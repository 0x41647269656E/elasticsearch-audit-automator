import json
import tempfile
import unittest
from pathlib import Path

from audit_analysis import loading, rendering
from audit_analysis.model import AxeAnalyse, Constat, Extrait, ResultatAxe


def audit_fixture(case: unittest.TestCase, big_artefact: bool = False) -> loading.Audit:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    d = Path(tmp.name)
    meta = {
        "node": "es01",
        "at": "2026-07-31T19:01:23.412000+00:00",
        "command": "GET /_settings",
        "status": 200,
        "duration_ms": 42,
    }
    payload = {"idx": {"settings": {"index": {"number_of_replicas": "0"}}}}
    if big_artefact:
        payload = {f"idx-{i}": {"settings": {"filler": "x" * 400}} for i in range(200)}
    (d / "indices_settings.json").write_text(
        json.dumps({"_audit": meta, "_data": payload}), encoding="utf-8"
    )
    (d / "audit_infos.json").write_text(
        json.dumps(
            {
                "cluster_name": "audit-es8",
                "cluster_typology": "PRODUCTION",
                "client_name": "acme",
                "timestamp": "2026-07-31T19:01:20+00:00",
                "node_name": "es01",
            }
        ),
        encoding="utf-8",
    )
    return loading.load_audit(d)


CONSTAT = Constat(
    constat="7 index sans replica",
    valeur_relevee="number_of_replicas: 0",
    severite="CRITIQUE",
    impact="Perte de données à la première défaillance de nœud",
    remediation='PUT /idx/_settings {"index.number_of_replicas": 1}',
    reference="https://www.elastic.co/docs/deploy-manage/production-guidance/availability-and-resilience",
    extraits=[Extrait(commande="indices_settings", fragment='"number_of_replicas":"0"')],
)


def axe(**kwargs) -> AxeAnalyse:
    base = dict(
        cle="resilience",
        titre="Conception pour la résilience",
        reference="https://www.elastic.co/docs/deploy-manage/production-guidance/availability-and-resilience",
        commandes=["indices_settings"],
        resultat=ResultatAxe(constats=[CONSTAT], angles_morts=[]),
    )
    base.update(kwargs)
    return AxeAnalyse(**base)


class ReportHeaderTests(unittest.TestCase):
    def test_names_the_cluster_and_its_typology(self) -> None:
        md = rendering.render_report(audit_fixture(self), [axe()])

        self.assertIn("audit-es8", md)
        self.assertIn("PRODUCTION", md)

    def test_summary_counts_findings_by_severity(self) -> None:
        md = rendering.render_report(audit_fixture(self), [axe()])

        summary = md.split("## Axe")[0]
        self.assertIn("CRITIQUE", summary)
        self.assertIn("Conception pour la résilience", summary)


class CommandBlockTests(unittest.TestCase):
    def test_states_node_timestamp_and_command_before_the_analysis(self) -> None:
        md = rendering.render_report(audit_fixture(self), [axe()])

        self.assertIn("es01", md)
        self.assertIn("2026-07-31T19:01:23.412000+00:00", md)
        self.assertIn("GET /_settings", md)

    def test_analysis_comes_after_the_command_block(self) -> None:
        md = rendering.render_report(audit_fixture(self), [axe()])

        self.assertLess(md.index("GET /_settings"), md.index("7 index sans replica"))

    def test_every_finding_field_reaches_the_report(self) -> None:
        md = rendering.render_report(audit_fixture(self), [axe()])

        for value in (
            CONSTAT.constat,
            CONSTAT.valeur_relevee,
            CONSTAT.severite,
            CONSTAT.impact,
            CONSTAT.remediation,
            CONSTAT.reference,
        ):
            self.assertIn(value, md)


class BlindSpotTests(unittest.TestCase):
    def test_declares_blind_spots_rather_than_staying_silent(self) -> None:
        result = ResultatAxe(constats=[], angles_morts=["Rôles non évalués : privilèges manquants"])

        md = rendering.render_report(audit_fixture(self), [axe(resultat=result)])

        self.assertIn("Rôles non évalués", md)

    def test_surfaces_an_axis_that_could_not_be_analysed(self) -> None:
        md = rendering.render_report(
            audit_fixture(self), [axe(resultat=None, erreur="refus du modèle")]
        )

        self.assertIn("refus du modèle", md)

    def test_states_which_artefacts_were_aggregated(self) -> None:
        md = rendering.render_report(
            audit_fixture(self), [axe(agregations=["indices_segments"])]
        )

        self.assertIn("indices_segments", md)
        self.assertIn("agrég", md.lower())

    def test_marks_an_excerpt_that_could_not_be_verified(self) -> None:
        md = rendering.render_report(
            audit_fixture(self), [axe(extraits_invérifiables=['"number_of_replicas":"0"'])]
        )

        self.assertIn("invérifiable", md.lower())

    def test_warns_when_the_folder_predates_per_command_metadata(self) -> None:
        audit = audit_fixture(self)
        audit.has_metadata = False

        md = rendering.render_report(audit, [axe()])

        self.assertIn("horodatage global", md.lower())


class AnnexTests(unittest.TestCase):
    def test_every_annex_link_resolves_to_a_real_anchor(self) -> None:
        """A slugified heading would not match the link; anchors must be explicit."""
        import re

        md = rendering.render_report(audit_fixture(self), [axe()])

        targets = set(re.findall(r"\]\(#([a-z0-9_-]+)\)", md))
        anchors = set(re.findall(r'<a id="([a-z0-9_-]+)">', md))
        self.assertTrue(targets)
        self.assertEqual(targets - anchors, set())

    def test_small_artefact_is_included_in_full(self) -> None:
        md = rendering.render_report(audit_fixture(self), [axe()])

        self.assertIn("number_of_replicas", md.split("## Annexe")[1])

    def test_large_artefact_is_referenced_rather_than_inlined(self) -> None:
        md = rendering.render_report(
            audit_fixture(self, big_artefact=True), [axe()], annex_threshold=1024
        )

        annex = md.split("## Annexe")[1]
        self.assertIn("indices_settings.json", annex)
        self.assertNotIn("filler", annex)


if __name__ == "__main__":
    unittest.main()
