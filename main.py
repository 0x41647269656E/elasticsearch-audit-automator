import argparse
import datetime
import json
import os
import select
import socket
import socketserver
import subprocess
import threading
import ssl
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import paramiko
import requests
from dotenv import load_dotenv


class ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ForwardHandler(socketserver.BaseRequestHandler):
    transport: paramiko.Transport
    remote_host: str
    remote_port: int

    def handle(self) -> None:
        try:
            chan = self.transport.open_channel(
                "direct-tcpip",
                (self.remote_host, self.remote_port),
                self.request.getpeername(),
            )
        except Exception as exc:  # pragma: no cover
            print(f"Tunnel channel open failed: {exc}")
            return

        if chan is None:
            print("Failed to open SSH channel")
            return

        try:
            while True:
                r, _, _ = select.select([self.request, chan], [], [])
                if self.request in r:
                    data = self.request.recv(1024)
                    if len(data) == 0:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if len(data) == 0:
                        break
                    self.request.send(data)
        finally:
            chan.close()
            self.request.close()


class SshTunnel:
    def __init__(
        self,
        ssh_host: str,
        ssh_port: int,
        ssh_username: str,
        ssh_password: Optional[str],
        ssh_key_path: Optional[str],
        remote_host: str,
        remote_port: int,
    ) -> None:
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_key_path = ssh_key_path
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.client: Optional[paramiko.SSHClient] = None
        self.server: Optional[ForwardServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.local_port: Optional[int] = None

    def __enter__(self) -> "SshTunnel":
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=self.ssh_host,
            port=self.ssh_port,
            username=self.ssh_username,
            password=self.ssh_password,
            key_filename=self.ssh_key_path or None,
        )
        transport = self.client.get_transport()
        if transport is None:
            raise RuntimeError("Unable to start SSH transport")

        handler = self._build_handler(transport)
        self.server = ForwardServer(("127.0.0.1", 0), handler)
        self.local_port = self.server.server_address[1]
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        return self

    def _build_handler(self, transport: paramiko.Transport):
        class Handler(ForwardHandler):
            transport = transport
            remote_host = self.remote_host
            remote_port = self.remote_port

        return Handler

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.client:
            self.client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automated Elasticsearch cluster audit")
    parser.add_argument("--commands", default="commands.json", help="Path to commands.json file")
    parser.add_argument("--host", help="Elasticsearch host")
    parser.add_argument("--port", type=int, help="Elasticsearch port")
    parser.add_argument("--scheme", choices=["http", "https"], help="Protocol to use")
    parser.add_argument("--username", help="Elasticsearch username")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--token", help="Elasticsearch bearer token")
    parser.add_argument("--client-name", help="Client name for audit folder")
    parser.add_argument("--cluster-name", help="Cluster name override")
    parser.add_argument("--verify-tls", choices=["true", "false"], help="Verify TLS certificates")
    parser.add_argument("--ssh-host", help="SSH jump host")
    parser.add_argument("--ssh-port", type=int, default=None, help="SSH port")
    parser.add_argument("--ssh-username", help="SSH username")
    parser.add_argument("--ssh-password", help="SSH password")
    parser.add_argument("--ssh-key-path", help="SSH private key path")
    return parser.parse_args()


def env_bool(value: Optional[str], default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).lower() in {"1", "true", "yes", "y"}


def load_configuration(args: argparse.Namespace) -> Dict[str, Any]:
    load_dotenv()
    config = {
        "host": args.host or os.getenv("ELASTIC_HOST", "localhost"),
        "port": args.port or int(os.getenv("ELASTIC_PORT", "9200")),
        "scheme": args.scheme or os.getenv("ELASTIC_SCHEME", "http"),
        "username": args.username or os.getenv("ELASTIC_USERNAME"),
        "password": args.password or os.getenv("ELASTIC_PASSWORD"),
        "token": args.token or os.getenv("ELASTIC_BEARER_TOKEN"),
        "client_name": args.client_name or os.getenv("CLIENT_NAME", "client"),
        "cluster_name": args.cluster_name or os.getenv("CLUSTER_NAME"),
        "verify_tls": env_bool(args.verify_tls or os.getenv("VERIFY_TLS", "true")),
        "ssh_host": args.ssh_host or os.getenv("SSH_HOST"),
        "ssh_port": args.ssh_port or int(os.getenv("SSH_PORT", "22")),
        "ssh_username": args.ssh_username or os.getenv("SSH_USERNAME"),
        "ssh_password": args.ssh_password or os.getenv("SSH_PASSWORD"),
        "ssh_key_path": args.ssh_key_path or os.getenv("SSH_KEY_PATH"),
    }
    return config


def load_commands(commands_path: str) -> Dict[str, Any]:
    with open(commands_path, "r", encoding="utf-8") as file:
        data = json.load(file)
    if data.get("version") != "1.0":
        raise ValueError("commands.json version must be 1.0")
    return data


def build_session(config: Dict[str, Any]) -> requests.Session:
    session = requests.Session()
    headers = {"Content-Type": "application/json"}
    if config.get("token"):
        headers["Authorization"] = f"Bearer {config['token']}"
    session.headers.update(headers)
    if config.get("username") and config.get("password"):
        session.auth = (config["username"], config["password"])
    return session


def build_base_url(config: Dict[str, Any], local_port: Optional[int] = None) -> str:
    scheme = config["scheme"]
    host = "127.0.0.1" if local_port else config["host"]
    port = local_port or config["port"]
    return f"{scheme}://{host}:{port}"


def ensure_data_dir() -> Path:
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir


def create_audit_dir(base_dir: Path, client: str, cluster: str, host: str) -> Path:
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
    cluster_part = cluster or host
    safe_cluster = cluster_part.replace("/", "-")
    name = f"{timestamp}-{client}-{safe_cluster}"
    audit_dir = base_dir / name
    audit_dir.mkdir(parents=True, exist_ok=True)
    return audit_dir


def execute_request(session: requests.Session, method: str, url: str, verify: bool) -> requests.Response:
    method = method.upper()
    response = session.request(method, url, verify=verify)
    return response


def save_output(audit_dir: Path, command_name: str, output_format: str, content: Any) -> None:
    output_path = audit_dir / f"{command_name}.{ 'json' if output_format == 'json' else 'txt'}"
    if output_format == "json":
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(content, file, indent=2)
    else:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(str(content))


def run_commands(
    session: requests.Session,
    base_url: str,
    commands: List[Dict[str, Any]],
    verify_tls: bool,
    audit_dir: Path,
) -> Dict[str, List[str]]:
    executed: List[str] = []
    failed: List[str] = []
    errors: List[str] = []

    for entry in commands:
        name = entry.get("name", "unnamed")
        command_str = entry.get("command", "")
        output_format = entry.get("output_format", "json").lower()
        if " " in command_str:
            method, path = command_str.split(" ", 1)
        else:
            method, path = "GET", command_str
        url = f"{base_url}{path}"
        print(f"Executing {name}: {method} {path}")
        try:
            response = execute_request(session, method, url, verify_tls)
            if response.ok:
                content = response.json() if output_format == "json" else response.text
                save_output(audit_dir, name, output_format, content)
                executed.append(name)
            else:
                failed.append(name)
                error_msg = f"Command {name} failed with status {response.status_code}: {response.text}"
                errors.append(error_msg)
                save_output(audit_dir, f"{name}-error", "text", error_msg)
        except Exception as exc:
            failed.append(name)
            error_msg = f"Command {name} raised exception: {exc}"
            errors.append(error_msg)
            save_output(audit_dir, f"{name}-error", "text", error_msg)

    if errors:
        with open(audit_dir / "errors.log", "w", encoding="utf-8") as log_file:
            log_file.write("\n".join(errors))

    return {"executed": executed, "failed": failed}


def decode_certificate(der_bytes: bytes) -> Dict[str, Any]:
    """Decode DER certificate bytes into a JSON-serializable dictionary."""
    pem = ssl.DER_cert_to_PEM_cert(der_bytes)
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        tmp.write(pem)
        tmp_path = tmp.name
    try:
        decoded = ssl._ssl._test_decode_cert(tmp_path)  # type: ignore[attr-defined]
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    san = decoded.get("subjectAltName", [])
    return {
        "subject": decoded.get("subject"),
        "issuer": decoded.get("issuer"),
        "not_before": decoded.get("notBefore"),
        "not_after": decoded.get("notAfter"),
        "subject_alt_names": san,
    }


def fetch_tls_chain(host: str, port: int, server_hostname: str, verify: bool) -> Dict[str, Any]:
    """Retrieve TLS chain information from a remote HTTPS endpoint."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                chain_ders: List[bytes]
                if hasattr(ssock, "getpeercertchain"):
                    chain_ders = ssock.getpeercertchain()  # type: ignore[attr-defined]
                else:
                    leaf = ssock.getpeercert(True)
                    chain_ders = [leaf] if leaf else []
    except Exception as exc:
        return {"status": "error", "error": str(exc), "chain": []}

    decoded_chain = [decode_certificate(cert) for cert in chain_ders]
    return {"status": "ok", "chain": decoded_chain}


def persist_tls_report(
    audit_dir: Path,
    config: Dict[str, Any],
    local_port: Optional[int] = None,
) -> Optional[str]:
    if config.get("scheme") != "https":
        return None
    connect_host = "127.0.0.1" if local_port else config["host"]
    connect_port = local_port or config["port"]
    tls_info = fetch_tls_chain(connect_host, connect_port, server_hostname=config["host"], verify=config["verify_tls"])
    report_path = audit_dir / "tls_report.json"
    with open(report_path, "w", encoding="utf-8") as file:
        json.dump(tls_info, file, indent=2)
    return str(report_path)


def collect_cluster_details(session: requests.Session, base_url: str, verify_tls: bool) -> Dict[str, Any]:
    details: Dict[str, Any] = {}
    try:
        health = execute_request(session, "GET", f"{base_url}/_cluster/health", verify_tls)
        if health.ok:
            payload = health.json()
            details["cluster_name"] = payload.get("cluster_name")
    except Exception:
        details["cluster_name"] = None

    try:
        nodes_info = execute_request(session, "GET", f"{base_url}/_nodes", verify_tls)
        if nodes_info.ok:
            info_payload = nodes_info.json()
            details["nodes_os"] = {
                node_id: {
                    "name": data.get("name"),
                    "os": data.get("os", {}).get("name"),
                    "version": data.get("version"),
                }
                for node_id, data in info_payload.get("nodes", {}).items()
            }
    except Exception:
        details["nodes_os"] = {}

    try:
        stats = execute_request(session, "GET", f"{base_url}/_nodes/stats", verify_tls)
        if stats.ok:
            stats_payload = stats.json()
            details["nodes_stats"] = {
                node_id: {
                    "name": data.get("name"),
                    "cpu_percent": data.get("os", {}).get("cpu", {}).get("percent"),
                    "mem_total_in_bytes": data.get("os", {}).get("mem", {}).get("total_in_bytes"),
                    "fs_total_in_bytes": sum(
                        fs.get("total_in_bytes", 0) for fs in data.get("fs", {}).get("data", [])
                    ),
                }
                for node_id, data in stats_payload.get("nodes", {}).items()
            }
    except Exception:
        details["nodes_stats"] = {}

    return details


def write_audit_info(
    audit_dir: Path,
    connection_method: str,
    client_name: str,
    cluster_name: str,
    commands_meta: Dict[str, Any],
    command_results: Dict[str, List[str]],
    node_details: Dict[str, Any],
    tls_report: Optional[str] = None,
) -> None:
    audit_info = {
        "connection_method": connection_method,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "cluster_name": cluster_name,
        "client_name": client_name,
        "commands_version": commands_meta.get("version"),
        "commands_executed": command_results["executed"],
        "commands_failed": command_results["failed"],
        "nodes_os": node_details.get("nodes_os", {}),
        "nodes_resources": node_details.get("nodes_stats", {}),
    }
    if tls_report:
        audit_info["tls_report"] = tls_report
    with open(audit_dir / "audit_infos.json", "w", encoding="utf-8") as file:
        json.dump(audit_info, file, indent=2)


def prompt_analysis(audit_path: Path) -> None:
    choice = input("Souhaitez-vous lancer le script d’analyse ? (Y/n) ").strip().lower()
    if choice in {"", "y", "yes"}:
        try:
            subprocess.run(["python", "analyse.py", str(audit_path)], check=True)
        except FileNotFoundError:
            print("analyse.py introuvable. Ajoutez-le avant d'exécuter l'analyse.")
        except subprocess.CalledProcessError as exc:
            print(f"Le script d'analyse a échoué: {exc}")
    else:
        print("Analyse ignorée. Les données d'audit sont prêtes.")


def main() -> None:
    args = parse_args()
    config = load_configuration(args)
    commands_meta = load_commands(args.commands)

    data_dir = ensure_data_dir()

    session = build_session(config)
    connection_method = "ssh" if config.get("ssh_host") else config["scheme"]
    base_url = build_base_url(config)

    if config.get("ssh_host"):
        if not config.get("ssh_username"):
            raise ValueError("SSH username is required when using SSH")
        with SshTunnel(
            ssh_host=config["ssh_host"],
            ssh_port=config["ssh_port"],
            ssh_username=config["ssh_username"],
            ssh_password=config.get("ssh_password"),
            ssh_key_path=config.get("ssh_key_path"),
            remote_host=config["host"],
            remote_port=config["port"],
        ) as tunnel:
            local_base_url = build_base_url(config, tunnel.local_port)
            node_details = collect_cluster_details(session, local_base_url, config["verify_tls"])
            cluster_name = config.get("cluster_name") or node_details.get("cluster_name") or config["host"]
            audit_dir = create_audit_dir(data_dir, config["client_name"], cluster_name, config["host"])
            tls_report = persist_tls_report(audit_dir, config, local_port=tunnel.local_port)
            results = run_commands(
                session,
                local_base_url,
                commands_meta.get("commands", []),
                config["verify_tls"],
                audit_dir,
            )
            write_audit_info(
                audit_dir,
                "SSH",
                config["client_name"],
                cluster_name,
                commands_meta,
                results,
                node_details,
                tls_report,
            )
            prompt_analysis(audit_dir)
    else:
        node_details = collect_cluster_details(session, base_url, config["verify_tls"])
        cluster_name = config.get("cluster_name") or node_details.get("cluster_name") or config["host"]
        audit_dir = create_audit_dir(data_dir, config["client_name"], cluster_name, config["host"])
        tls_report = persist_tls_report(audit_dir, config)
        results = run_commands(
            session,
            base_url,
            commands_meta.get("commands", []),
            config["verify_tls"],
            audit_dir,
        )
        write_audit_info(
            audit_dir,
            config["scheme"].upper(),
            config["client_name"],
            cluster_name,
            commands_meta,
            results,
            node_details,
            tls_report,
        )
        prompt_analysis(audit_dir)


if __name__ == "__main__":
    main()
