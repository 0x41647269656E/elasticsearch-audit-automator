import json
import logging
import os
import time
from typing import Iterable, List

from elasticsearch import Elasticsearch, helpers

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def get_major_version(client: Elasticsearch) -> int:
    info = client.info()
    version_str = info.get("version", {}).get("number", "0.0.0")
    major_str = version_str.split(".", 1)[0]
    try:
        return int(major_str)
    except ValueError:
        return 0

def select_audit_policy_path(client: Elasticsearch, overright_policy: str) -> str:
    """
    Select the appropriate audit policy file based on Elasticsearch major version.
    - ES 7.x  -> AUDIT_POLICY_PATH_7 
    - ES 8.x+ -> AUDIT_POLICY_PATH_8

    If AUDIT_POLICY env variable is defined, it override.
    """

    # Manual override has absolute priority
    if overright_policy:
        return overright_policy
    
    # Auto-detect cluster version
    major = get_major_version(client)

    if major >= 8:
        return "/app/audit_policies/audit_policy_8.json"
    return "/app/audit_policies/audit_policy_7.json"

def build_client(host: str, username: str, password: str, verify: bool, ca_cert: str | None) -> Elasticsearch:
    kwargs = {
        "hosts": [host],
    }
    if username and password:
        kwargs["basic_auth"] = (username, password)
    kwargs["verify_certs"] = verify
    if ca_cert:
        kwargs["ca_certs"] = ca_cert
    return Elasticsearch(**kwargs)

def wait_for_green(client: Elasticsearch, timeout: int = 600) -> None:
    start = time.time()
    while True:
        try:
            health = client.options(request_timeout=60, ignore_status=[400]).cluster.health()
            status = health.get("status")
            logger.info("Cluster health: %s", status)
            if status == "green":
                return
        except Exception as exc:  # noqa: BLE001
            logger.warning("Health check failed: %s", exc)
        if time.time() - start > timeout:
            raise TimeoutError("Cluster did not reach green status in time")
        time.sleep(10)

def ensure_user( client: Elasticsearch, username: str, password: str, roles: list[str]) -> None:
    try:
        existing = client.security.get_user(username=username)
        user_info = existing.get(username, {})
        current_roles = set(user_info.get("roles", []))
        if set(roles).issubset(current_roles):
            logger.info("User %s already exists with roles %s", username, roles)
            return

        logger.info("User %s exists; updating roles", username)
        updated_roles = sorted(current_roles | set(roles))
        client.security.put_user(
            username=username,
            body={
                "roles": updated_roles,
                "full_name": user_info.get("full_name", "Audit automation"),
                "email": user_info.get("email", "audit@example.com"),
            },
        )
        return
    except Exception:  # noqa: BLE001
        logger.info("Creating user %s", username)

    client.security.put_user(
        username=username,
        body={
            "password": password,
            "roles": roles,
            "full_name": "Audit automation",
            "email": "audit@example.com",
        },
    )

def ensure_role(client: Elasticsearch, role_name: str, role_body: dict) -> None:
    client.security.put_role(name=role_name, body=role_body)
    logger.info("Ensured role %s exists", role_name)

def load_audit_policy(path: str) -> tuple[str, dict]:
    with open(path, "r", encoding="utf-8") as file:
        policy = json.load(file)
    if "role_name" not in policy or "role" not in policy:
        raise ValueError("Audit policy must include role_name and role fields")
    return policy["role_name"], policy["role"]

def create_indices(client: Elasticsearch, index_prefix: str, count: int) -> List[str]:
    names = [f"{index_prefix}-{i:02d}" for i in range(1, count + 1)]
    options = client.options(request_timeout=60, ignore_status=[400])
    for name in names:
        try:
            options.indices.create(
                index=name,
                body={
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1,
                        "index.mapping.total_fields.limit": 20000,
                        "index.mapping.ignore_malformed": True,
                    },
                    "mappings": {
                        "dynamic": True,
                        "date_detection": False,
                    },
                },
            )
            logger.info("Ensured index %s exists", name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Index creation issue for %s: %s", name, exc)
    return names

def load_local_documents(path: str) -> List[dict]:
    """Load documents from a local JSON file (array or NDJSON)."""
    logger.info("Loading local dataset from %s", path)
    with open(path, "r", encoding="utf-8") as file:
        raw = file.read()
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass

    documents: List[dict] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            documents.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return documents

def generate_actions(documents: List[dict], indices: List[str]) -> Iterable[dict]:
    index_count = len(indices)
    for idx, doc in enumerate(documents):
        target_index = indices[idx % index_count]
        yield {
            "_index": target_index,
            "_source": doc,
        }

def bulk_ingest(client: Elasticsearch, documents: List[dict], indices: List[str], batch_size: int = 500, request_timeout: int = 120) -> None:
    if not documents:
        logger.warning("No documents found to ingest")
        return

    total = 0
    bulk_client = client.options(request_timeout=request_timeout)

    for ok, result in helpers.streaming_bulk(
        bulk_client,
        generate_actions(documents, indices),
        chunk_size=batch_size,
        max_retries=5,
        initial_backoff=2,
        max_backoff=30,
        raise_on_error=False,
        refresh="wait_for",
    ):
        total += 1
        if not ok:
            logger.warning("Bulk item error: %s", result)
        if total % (batch_size * 5) == 0:
            logger.info("Indexed %s documents so far", total)
    logger.info("Ingestion finished; total items processed: %s", total)

def main() -> None:
    scheme = os.getenv("ELASTIC_SCHEME", "http")
    host_name = os.getenv("ELASTIC_HOST", "localhost")
    port = os.getenv("ELASTIC_PORT", "9200")
    host = f"{scheme}://{host_name}:{port}"

    username = os.getenv("ELASTIC_USERNAME", "elastic")
    password = os.getenv("ELASTIC_PASSWORD", "changeme")
    target_username = os.getenv("TARGET_USERNAME", "audit-elasticsearch")
    target_password = os.getenv("TARGET_PASSWORD", "audit-me")
    index_prefix = os.getenv("TARGET_INDEX_PREFIX", "audit-demo")
    index_count = int(os.getenv("INDEX_COUNT", "10"))
    verify_certs = os.getenv("VERIFY_CERTS", "false").lower() == "true"
    ca_cert = os.getenv("CA_CERT_PATH")
    security_enabled = os.getenv("SECURITY_ENABLED", "true").lower() == "true"
    bulk_chunk_size = int(os.getenv("BULK_CHUNK_SIZE", "500"))
    bulk_request_timeout = int(os.getenv("BULK_REQUEST_TIMEOUT", "120"))
    data_file = os.getenv("DATA_FILE", "/app/dummy_data.json")
    audit_policy_path = os.getenv("AUDIT_POLICY_PATH", "")

    admin_client = build_client(host, username if security_enabled else "", password if security_enabled else "", verify_certs, ca_cert)
    wait_for_green(admin_client)

    if security_enabled:
        major = get_major_version(admin_client)
        logger.info("Detected Elasticsearch major version: %s", major)

        policy_path = select_audit_policy_path(admin_client, audit_policy_path)
        logger.info("Using audit policy file: %s", policy_path)

        role_name, role_body = load_audit_policy(policy_path)

        logger.info("Audit policy file loaded with role_name: %s", role_name)

        # roles = [role_name, "kibana_admin"], if you need to add build-in roles
        roles = [role_name]

        ensure_role(admin_client, role_name, role_body)
        ensure_user(admin_client, target_username, target_password, roles)

    ingest_client = admin_client
    indices = create_indices(ingest_client, index_prefix, index_count)
    documents = load_local_documents(data_file)
    bulk_ingest(ingest_client, documents, indices, batch_size=bulk_chunk_size, request_timeout=bulk_request_timeout)

    logger.info("Data load complete for indices: %s", ", ".join(indices))

if __name__ == "__main__":
    main()
