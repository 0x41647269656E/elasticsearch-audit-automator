import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import main


def _tmp_dir(case: unittest.TestCase) -> Path:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    return Path(tmp.name)


class RecordingSession:
    """Stands in for requests.Session and captures the call kwargs."""

    def __init__(self) -> None:
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return SimpleNamespace(ok=True, json=lambda: {}, text="", status_code=200)


class ExecuteRequestTimeoutTests(unittest.TestCase):
    def test_applies_a_timeout_so_a_wedged_node_cannot_hang_the_audit(self) -> None:
        session = RecordingSession()

        main.execute_request(session, "GET", "http://es:9200/_cluster/health", False)

        self.assertIsNotNone(
            session.calls[0].get("timeout"),
            "execute_request must pass a timeout to requests",
        )

    def test_uses_the_caller_supplied_timeout(self) -> None:
        session = RecordingSession()

        main.execute_request(session, "GET", "http://es:9200/", False, timeout=12)

        self.assertEqual(session.calls[0]["timeout"], 12)


class TimeoutPropagationTests(unittest.TestCase):
    def test_run_commands_forwards_the_configured_timeout(self) -> None:
        session = RecordingSession()
        commands = [{"name": "health", "command": "GET /_cluster/health", "output_format": "json"}]

        main.run_commands(
            session,
            "http://es:9200",
            commands,
            False,
            _tmp_dir(self),
            timeout=7,
        )

        self.assertEqual(session.calls[0]["timeout"], 7)


class TimeoutConfigurationTests(unittest.TestCase):
    def test_timeout_defaults_when_not_configured(self) -> None:
        args = SimpleNamespace(
            host="es", port=9200, scheme="http", username=None, password=None,
            token=None, client_name=None, cluster_typology=None, verify_tls=None,
            ca_cert=None, ssh_host=None, ssh_port=None, ssh_username=None,
            ssh_password=None, ssh_key_path=None, timeout=None,
        )

        config = main.load_configuration(args)

        self.assertEqual(config["timeout"], main.DEFAULT_REQUEST_TIMEOUT)

    def test_cli_timeout_overrides_the_default(self) -> None:
        args = SimpleNamespace(
            host="es", port=9200, scheme="http", username=None, password=None,
            token=None, client_name=None, cluster_typology=None, verify_tls=None,
            ca_cert=None, ssh_host=None, ssh_port=None, ssh_username=None,
            ssh_password=None, ssh_key_path=None, timeout=5,
        )

        config = main.load_configuration(args)

        self.assertEqual(config["timeout"], 5)


if __name__ == "__main__":
    unittest.main()
