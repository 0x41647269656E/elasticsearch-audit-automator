import json
import tempfile
import unittest
from pathlib import Path

from audit_analysis import analysis, loading
from audit_analysis.model import Constat, Extrait, ResultatAxe

COMMANDS = {
    "version": "1.1",
    "restitution": {"langue": "fr", "consigne_globale": "Rédige en français."},
    "axes": {
        "resilience": {"titre": "Résilience", "reference": "https://x/resilience", "prompt": "Corrèle."},
        "securite": {"titre": "Sécurité", "reference": "https://x/securite", "prompt": "Contrôle."},
    },
    "commands": [
        {"name": "indices_settings", "command": "GET /_settings", "axes": ["resilience"],
         "prompt": "Relève number_of_replicas.", "output_format": "json"},
        {"name": "absente", "command": "GET /_absent", "axes": ["resilience"],
         "prompt": "…", "output_format": "json"},
        {"name": "security_users", "command": "GET /_security/user", "axes": ["securite"],
         "prompt": "Relève les comptes.", "output_format": "json"},
    ],
}


def audit_fixture(case: unittest.TestCase) -> loading.Audit:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    d = Path(tmp.name)
    meta = {"node": "es01", "at": "2026-07-31T19:01:23+00:00",
            "command": "GET /_settings", "status": 200, "duration_ms": 42}
    (d / "indices_settings.json").write_text(
        json.dumps({"_audit": meta,
                    "_data": {"idx": {"settings": {"index": {"number_of_replicas": "0"}}}}}),
        encoding="utf-8")
    (d / "security_users-error.txt").write_text(
        "Command security_users failed with status 403: denied", encoding="utf-8")
    (d / "audit_infos.json").write_text(
        json.dumps({"cluster_name": "c", "cluster_typology": "PRODUCTION",
                    "timestamp": "2026-07-31T19:01:20+00:00", "node_name": "es01"}),
        encoding="utf-8")
    return loading.load_audit(d)


class GroupingTests(unittest.TestCase):
    def test_builds_one_axis_per_declared_axis(self) -> None:
        axes = analysis.build_axes(COMMANDS, audit_fixture(self))

        self.assertEqual([a.cle for a in axes], ["resilience", "securite"])
        self.assertEqual(axes[0].titre, "Résilience")
        self.assertEqual(axes[0].reference, "https://x/resilience")

    def test_skips_commands_that_produced_no_artefact(self) -> None:
        axes = analysis.build_axes(COMMANDS, audit_fixture(self))

        self.assertEqual(axes[0].commandes, ["indices_settings"])

    def test_context_carries_the_failures_of_that_axis_only(self) -> None:
        audit = audit_fixture(self)
        axes = analysis.build_axes(COMMANDS, audit)

        self.assertEqual(analysis.axis_failures(axes[0], audit), {})
        self.assertIn("security_users", analysis.axis_failures(axes[1], audit))


class ExcerptVerificationTests(unittest.TestCase):
    """A finding may only rest on a fragment that really exists in the artefact."""

    def setUp(self) -> None:
        self.audit = audit_fixture(self)

    def _resultat(self, fragment: str) -> ResultatAxe:
        return ResultatAxe(constats=[Constat(
            constat="c", valeur_relevee="v", severite="MAJEUR", impact="i",
            remediation="r", reference="https://x",
            extraits=[Extrait(commande="indices_settings", fragment=fragment)])])

    def test_accepts_a_fragment_present_in_the_artefact(self) -> None:
        unverified = analysis.verify_excerpts(self._resultat('"number_of_replicas": "0"'), self.audit)

        self.assertEqual(unverified, [])

    def test_tolerates_whitespace_differences(self) -> None:
        unverified = analysis.verify_excerpts(self._resultat('"number_of_replicas":"0"'), self.audit)

        self.assertEqual(unverified, [])

    def test_reports_a_fragment_the_model_invented(self) -> None:
        unverified = analysis.verify_excerpts(self._resultat('"number_of_replicas": "3"'), self.audit)

        self.assertEqual(len(unverified), 1)
        self.assertIn("number_of_replicas", unverified[0])

    def test_reports_a_fragment_attributed_to_an_absent_command(self) -> None:
        resultat = ResultatAxe(constats=[Constat(
            constat="c", valeur_relevee="v", severite="MAJEUR", impact="i",
            remediation="r", reference="https://x",
            extraits=[Extrait(commande="jamais_collectee", fragment="x")])])

        self.assertEqual(len(analysis.verify_excerpts(resultat, self.audit)), 1)


class FakeCaller:
    """Stands in for the Anthropic client; records what it was asked."""

    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.calls = []

    def complete(self, system, user, schema):
        self.calls.append({"system": system, "user": user, "schema": schema})
        return self.outcome


class AxisAnalysisTests(unittest.TestCase):
    RESULT = {"constats": [{"constat": "7 index sans replica",
                            "valeur_relevee": '"number_of_replicas": "0"',
                            "severite": "CRITIQUE", "impact": "perte de données",
                            "remediation": "PUT …", "reference": "https://x/resilience",
                            "extraits": [{"commande": "indices_settings",
                                          "fragment": '"number_of_replicas": "0"'}]}],
              "angles_morts": []}

    def setUp(self) -> None:
        self.audit = audit_fixture(self)
        self.axe = analysis.build_axes(COMMANDS, self.audit)[0]

    def test_parses_a_structured_result_into_findings(self) -> None:
        caller = FakeCaller(analysis.ModelOutcome(data=self.RESULT))

        result = analysis.analyse_axis(caller, self.axe, self.audit, COMMANDS)

        self.assertEqual(len(result.constats), 1)
        self.assertEqual(result.constats[0].severite, "CRITIQUE")
        self.assertIsNone(result.erreur)

    def test_a_refusal_becomes_a_declared_gap_not_a_crash(self) -> None:
        caller = FakeCaller(analysis.ModelOutcome(refusal="cyber"))

        result = analysis.analyse_axis(caller, self.axe, self.audit, COMMANDS)

        self.assertIsNotNone(result.erreur)
        self.assertIn("refus", result.erreur.lower())
        self.assertEqual(result.constats, [])

    def test_an_api_error_becomes_a_declared_gap_not_a_crash(self) -> None:
        class Boom:
            def complete(self, *_a, **_k):
                raise RuntimeError("réseau indisponible")

        result = analysis.analyse_axis(Boom(), self.axe, self.audit, COMMANDS)

        self.assertIn("réseau indisponible", result.erreur)

    def test_sends_the_axis_prompt_and_the_command_prompts(self) -> None:
        caller = FakeCaller(analysis.ModelOutcome(data=self.RESULT))

        analysis.analyse_axis(caller, self.axe, self.audit, COMMANDS)

        user = caller.calls[0]["user"]
        self.assertIn("Corrèle.", user)
        self.assertIn("Relève number_of_replicas.", user)

    def test_stable_context_goes_in_the_system_prompt_for_caching(self) -> None:
        """The shared prefix must not vary per axis, or the cache never hits."""
        caller = FakeCaller(analysis.ModelOutcome(data=self.RESULT))
        axes = analysis.build_axes(COMMANDS, self.audit)

        for axe in axes:
            analysis.analyse_axis(caller, axe, self.audit, COMMANDS)

        self.assertEqual(caller.calls[0]["system"], caller.calls[1]["system"])
        self.assertIn("PRODUCTION", caller.calls[0]["system"])

    def test_flags_an_invented_excerpt_on_the_axis(self) -> None:
        invented = json.loads(json.dumps(self.RESULT))
        invented["constats"][0]["extraits"][0]["fragment"] = '"number_of_replicas": "9"'
        caller = FakeCaller(analysis.ModelOutcome(data=invented))

        result = analysis.analyse_axis(caller, self.axe, self.audit, COMMANDS)

        self.assertEqual(len(result.extraits_invérifiables), 1)


if __name__ == "__main__":
    unittest.main()
