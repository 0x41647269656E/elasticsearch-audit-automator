import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

import main


def tmp_dir(case: unittest.TestCase) -> Path:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    return Path(tmp.name)


META = {
    "node": "es01",
    "at": "2026-07-31T19:01:23.412000+00:00",
    "command": "GET /_cluster/health",
    "status": 200,
    "duration_ms": 42,
}


class SaveOutputMetadataTests(unittest.TestCase):
    def test_json_artefact_carries_audit_metadata_alongside_the_response(self) -> None:
        audit_dir = tmp_dir(self)

        main.save_output(audit_dir, "cluster_health", "json", {"status": "green"}, META)

        written = json.loads((audit_dir / "cluster_health.json").read_text(encoding="utf-8"))
        self.assertEqual(written["_audit"], META)
        self.assertEqual(written["_data"], {"status": "green"})

    def test_text_artefact_stays_byte_for_byte_the_elasticsearch_output(self) -> None:
        """A .txt must remain parseable by anything that reads _cat output."""
        audit_dir = tmp_dir(self)

        main.save_output(audit_dir, "shards_list", "text", "index shard\ndemo 0\n", META)

        self.assertEqual(
            (audit_dir / "shards_list.txt").read_text(encoding="utf-8"),
            "index shard\ndemo 0\n",
        )

    def test_text_artefact_gets_a_sidecar_holding_its_metadata(self) -> None:
        audit_dir = tmp_dir(self)

        main.save_output(audit_dir, "shards_list", "text", "index shard\n", META)

        sidecar = json.loads((audit_dir / "shards_list.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar, META)

    def test_without_metadata_the_json_artefact_is_the_bare_response(self) -> None:
        audit_dir = tmp_dir(self)

        main.save_output(audit_dir, "cluster_health", "json", {"status": "green"})

        written = json.loads((audit_dir / "cluster_health.json").read_text(encoding="utf-8"))
        self.assertEqual(written, {"status": "green"})
        self.assertFalse((audit_dir / "cluster_health.meta.json").exists())


class RecordingSession:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code

    def request(self, method, url, **kwargs):
        return SimpleNamespace(
            ok=self.status_code < 400,
            json=lambda: {"status": "green"},
            text="boom",
            status_code=self.status_code,
        )


class RunCommandsMetadataTests(unittest.TestCase):
    COMMANDS = [
        {"name": "cluster_health", "command": "GET /_cluster/health", "output_format": "json"}
    ]

    def test_records_when_each_command_ran_and_which_node_answered(self) -> None:
        audit_dir = tmp_dir(self)

        main.run_commands(
            RecordingSession(), "http://es:9200", self.COMMANDS, False, audit_dir,
            node_name="es01",
        )

        meta = json.loads((audit_dir / "cluster_health.json").read_text(encoding="utf-8"))["_audit"]
        self.assertEqual(meta["node"], "es01")
        self.assertEqual(meta["command"], "GET /_cluster/health")
        self.assertEqual(meta["status"], 200)
        self.assertIsInstance(meta["duration_ms"], int)
        self.assertTrue(meta["at"])

    def test_a_failed_command_still_records_its_status_and_timing(self) -> None:
        audit_dir = tmp_dir(self)

        main.run_commands(
            RecordingSession(status_code=403), "http://es:9200", self.COMMANDS, False, audit_dir,
            node_name="es01",
        )

        sidecar = json.loads(
            (audit_dir / "cluster_health-error.meta.json").read_text(encoding="utf-8")
        )
        self.assertEqual(sidecar["status"], 403)
        self.assertEqual(sidecar["node"], "es01")


class DetectNodeNameTests(unittest.TestCase):
    def test_reads_the_contacted_node_name_from_the_root_endpoint(self) -> None:
        def fake_request(_session, _method, url, *_args, **_kwargs):
            self.assertTrue(url.endswith("/"))
            return SimpleNamespace(ok=True, json=lambda: {"name": "es01", "cluster_name": "c"})

        with unittest.mock.patch.object(main, "execute_request", fake_request):
            self.assertEqual(main.detect_node_name(object(), "http://es:9200", False), "es01")

    def test_returns_none_rather_than_failing_the_audit(self) -> None:
        """The node name is a nicety; losing it must not abort a collection."""
        def fake_request(*_args, **_kwargs):
            raise RuntimeError("unreachable")

        with unittest.mock.patch.object(main, "execute_request", fake_request):
            self.assertIsNone(main.detect_node_name(object(), "http://es:9200", False))


if __name__ == "__main__":
    unittest.main()
