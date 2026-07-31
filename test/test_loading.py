import json
import tempfile
import unittest
from pathlib import Path

from audit_analysis import loading


def build_audit(case: unittest.TestCase, *, with_metadata: bool = True) -> Path:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    d = Path(tmp.name)

    meta = {
        "node": "es01",
        "at": "2026-07-31T19:01:23.412000+00:00",
        "command": "GET /_cluster/health",
        "status": 200,
        "duration_ms": 42,
    }
    health = {"status": "green"}
    (d / "cluster_health.json").write_text(
        json.dumps({"_audit": meta, "_data": health} if with_metadata else health),
        encoding="utf-8",
    )

    (d / "shards_list.txt").write_text("index shard\ndemo 0\n", encoding="utf-8")
    if with_metadata:
        (d / "shards_list.meta.json").write_text(
            json.dumps({**meta, "command": "GET /_cat/shards?v"}), encoding="utf-8"
        )

    (d / "security_users-error.txt").write_text(
        "Command security_users failed with status 403: denied", encoding="utf-8"
    )
    (d / "audit_infos.json").write_text(
        json.dumps(
            {
                "cluster_name": "audit-es8",
                "cluster_typology": "RECETTE",
                "client_name": "acme",
                "timestamp": "2026-07-31T19:01:20+00:00",
                "node_name": "es01" if with_metadata else None,
                "commands_executed": ["cluster_health", "shards_list"],
                "commands_failed": ["security_users"],
            }
        ),
        encoding="utf-8",
    )
    return d


class LoadAuditTests(unittest.TestCase):
    def test_unwraps_the_audit_envelope_and_exposes_the_elasticsearch_response(self) -> None:
        audit = loading.load_audit(build_audit(self))

        artefact = audit.artefacts["cluster_health"]
        self.assertEqual(artefact.data, {"status": "green"})
        self.assertEqual(artefact.metadata["node"], "es01")
        self.assertEqual(artefact.metadata["status"], 200)

    def test_pairs_a_text_artefact_with_its_sidecar(self) -> None:
        audit = loading.load_audit(build_audit(self))

        artefact = audit.artefacts["shards_list"]
        self.assertEqual(artefact.data, "index shard\ndemo 0\n")
        self.assertEqual(artefact.metadata["command"], "GET /_cat/shards?v")

    def test_collects_failures_with_their_message(self) -> None:
        audit = loading.load_audit(build_audit(self))

        self.assertIn("security_users", audit.failures)
        self.assertIn("403", audit.failures["security_users"])

    def test_error_files_are_not_mistaken_for_artefacts(self) -> None:
        audit = loading.load_audit(build_audit(self))

        self.assertNotIn("security_users-error", audit.artefacts)

    def test_reads_the_audit_context(self) -> None:
        audit = loading.load_audit(build_audit(self))

        self.assertEqual(audit.cluster_name, "audit-es8")
        self.assertEqual(audit.typology, "RECETTE")
        self.assertEqual(audit.node_name, "es01")


class LegacyAuditTests(unittest.TestCase):
    """A folder collected before per-command metadata existed must still work."""

    def test_reads_an_artefact_that_has_no_audit_envelope(self) -> None:
        audit = loading.load_audit(build_audit(self, with_metadata=False))

        self.assertEqual(audit.artefacts["cluster_health"].data, {"status": "green"})

    def test_falls_back_to_the_audit_wide_timestamp(self) -> None:
        audit = loading.load_audit(build_audit(self, with_metadata=False))

        artefact = audit.artefacts["cluster_health"]
        self.assertEqual(artefact.metadata["at"], "2026-07-31T19:01:20+00:00")
        self.assertIsNone(artefact.metadata["node"])

    def test_flags_the_folder_so_the_report_can_say_so(self) -> None:
        self.assertFalse(loading.load_audit(build_audit(self, with_metadata=False)).has_metadata)
        self.assertTrue(loading.load_audit(build_audit(self)).has_metadata)


if __name__ == "__main__":
    unittest.main()
