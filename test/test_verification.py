import json
import tempfile
import unittest
from pathlib import Path

from audit_analysis import analysis, loading
from audit_analysis.model import AxeAnalyse, Constat, Extrait, ResultatAxe


def audit_fixture(case: unittest.TestCase) -> loading.Audit:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    d = Path(tmp.name)
    meta = {"node": "es01", "at": "2026-08-01T08:06:14+00:00",
            "command": "GET /_settings", "status": 200, "duration_ms": 4}
    (d / "indices_settings.json").write_text(
        json.dumps({"_audit": meta, "_data": {"idx": {"number_of_replicas": "0"}}}),
        encoding="utf-8")
    (d / "audit_infos.json").write_text(
        json.dumps({"cluster_name": "audit-es8", "cluster_typology": "PRODUCTION",
                    "timestamp": "2026-08-01T08:06:14+00:00", "node_name": "es01",
                    "nodes_resources": {"n1": {"name": "es01", "mem_total_in_bytes": 1073741824}}}),
        encoding="utf-8")
    return loading.load_audit(d)


def resultat(commande: str, fragment: str) -> ResultatAxe:
    return ResultatAxe(constats=[Constat(
        constat="c", valeur_relevee="v", severite="MAJEUR", impact="i",
        remediation="r", reference="https://x",
        extraits=[Extrait(commande=commande, fragment=fragment)])])


class AuditContextCitationTests(unittest.TestCase):
    """audit_infos.json est fourni au modèle dans le prompt système : le citer
    est légitime, et vérifiable."""

    def setUp(self) -> None:
        self.audit = audit_fixture(self)

    def test_accepts_a_real_fragment_of_the_audit_context(self) -> None:
        unverified = analysis.verify_excerpts(
            resultat("audit_infos", '"cluster_typology": "PRODUCTION"'), self.audit)

        self.assertEqual(unverified, [])

    def test_accepts_it_under_its_file_name_too(self) -> None:
        unverified = analysis.verify_excerpts(
            resultat("audit_infos.json", '"mem_total_in_bytes": 1073741824'), self.audit)

        self.assertEqual(unverified, [])

    def test_still_rejects_an_invented_fragment_of_the_context(self) -> None:
        unverified = analysis.verify_excerpts(
            resultat("audit_infos", '"cluster_typology": "DEV"'), self.audit)

        self.assertEqual(len(unverified), 1)

    def test_an_unknown_command_is_still_reported(self) -> None:
        unverified = analysis.verify_excerpts(resultat("jamais_collectee", "x"), self.audit)

        self.assertEqual(len(unverified), 1)


class ReferenceCheckTests(unittest.TestCase):
    """Le modèle affine parfois l'URL de l'axe — utile quand elle existe,
    inacceptable dans un livrable quand elle est inventée."""

    def _axe(self, *urls: str) -> AxeAnalyse:
        constats = [
            Constat(constat="c", valeur_relevee="v", severite="MINEUR", impact="i",
                    remediation="r", reference=u)
            for u in urls
        ]
        return AxeAnalyse(cle="a", titre="A", reference="https://ok/axe", commandes=[],
                          resultat=ResultatAxe(constats=constats))

    def test_flags_a_reference_that_does_not_resolve(self) -> None:
        axe = self._axe("https://ok/vrai", "https://ok/invente")

        analysis.verify_references([axe], checker=lambda u: "invente" not in u)

        self.assertEqual(axe.references_cassees, ["https://ok/invente"])

    def test_leaves_a_valid_reference_alone(self) -> None:
        axe = self._axe("https://ok/vrai")

        analysis.verify_references([axe], checker=lambda u: True)

        self.assertEqual(axe.references_cassees, [])

    def test_checks_each_distinct_url_once(self) -> None:
        axe = self._axe("https://ok/a", "https://ok/a", "https://ok/b")
        vues = []

        analysis.verify_references([axe], checker=lambda u: vues.append(u) or True)

        self.assertEqual(sorted(vues), ["https://ok/a", "https://ok/b"])

    def test_a_checker_failure_does_not_break_the_report(self) -> None:
        axe = self._axe("https://ok/a")

        def boom(_url):
            raise RuntimeError("réseau coupé")

        analysis.verify_references([axe], checker=boom)

        self.assertEqual(axe.references_cassees, [])


if __name__ == "__main__":
    unittest.main()
