import json
import tempfile
import unittest
from pathlib import Path

from audit_analysis import persistence, rendering
from audit_analysis.model import AxeAnalyse, Constat, Extrait, ResultatAxe, Usage
from test_rendering import audit_fixture

CONSTAT = Constat(
    constat="7 index sans replica",
    valeur_relevee='"number_of_replicas": "0"',
    severite="CRITIQUE",
    impact="Perte de données",
    remediation="PUT …",
    reference="https://x/resilience",
    extraits=[Extrait(commande="indices_settings", fragment='"number_of_replicas": "0"')],
)


def axes_fixture():
    return [
        AxeAnalyse(
            cle="resilience", titre="Résilience", reference="https://x/resilience",
            commandes=["indices_settings"], commandes_declarees=["indices_settings"],
            resultat=ResultatAxe(constats=[CONSTAT], angles_morts=["rôles non évalués"]),
            agregations=["indices_segments"],
            extraits_invérifiables=["indices_settings : inventé"],
            references_cassees=["https://x/mort"],
            usage=Usage(input_tokens=1000, output_tokens=2000, cache_read_input_tokens=50),
            duree_s=12.5,
        ),
        AxeAnalyse(cle="disque", titre="Disque", reference="https://x/disque",
                   commandes=[], erreur="refus du modèle"),
    ]


class RoundTripTests(unittest.TestCase):
    """Le rendu doit pouvoir être rejoué sans rappeler le modèle."""

    def setUp(self) -> None:
        self.restaures = persistence.load_axes(
            json.loads(json.dumps(persistence.dump_axes(axes_fixture())))
        )

    def test_restores_the_findings_intact(self) -> None:
        constat = self.restaures[0].constats[0]

        self.assertEqual(constat.constat, CONSTAT.constat)
        self.assertEqual(constat.severite, "CRITIQUE")
        self.assertEqual(constat.extraits[0].fragment, CONSTAT.extraits[0].fragment)

    def test_restores_what_the_report_must_declare(self) -> None:
        axe = self.restaures[0]

        self.assertEqual(axe.agregations, ["indices_segments"])
        self.assertEqual(axe.extraits_invérifiables, ["indices_settings : inventé"])
        self.assertEqual(axe.references_cassees, ["https://x/mort"])
        self.assertEqual(axe.resultat.angles_morts, ["rôles non évalués"])

    def test_restores_an_unevaluated_axis(self) -> None:
        self.assertEqual(self.restaures[1].erreur, "refus du modèle")
        self.assertIsNone(self.restaures[1].resultat)

    def test_restores_the_measured_usage(self) -> None:
        usage = self.restaures[0].usage

        self.assertEqual(usage.input_tokens, 1000)
        self.assertEqual(usage.output_tokens, 2000)
        self.assertEqual(usage.cache_read_input_tokens, 50)
        self.assertEqual(self.restaures[0].duree_s, 12.5)

    def test_rerendering_gives_byte_identical_markdown(self) -> None:
        audit = audit_fixture(self)

        depuis_origine = rendering.render_report(audit, axes_fixture())
        depuis_fichier = rendering.render_report(audit, self.restaures)

        self.assertEqual(depuis_origine, depuis_fichier)

    def test_uses_ascii_keys_so_the_file_stays_interoperable(self) -> None:
        payload = persistence.dump_axes(axes_fixture())

        for cle in payload[0]:
            with self.subTest(cle=cle):
                self.assertTrue(cle.isascii())


class PathTests(unittest.TestCase):
    def test_full_run_writes_the_canonical_name(self) -> None:
        sorties = persistence.output_paths("data/audit")

        self.assertEqual(sorties.rapport.name, "rapport.md")
        self.assertEqual(sorties.consommation.name, "consommation.json")
        self.assertEqual(sorties.constats.name, "constats.json")

    def test_a_replay_names_all_three_after_the_axis(self) -> None:
        sorties = persistence.output_paths("data/audit", axe="securite")

        for chemin in (sorties.rapport, sorties.consommation, sorties.constats):
            with self.subTest(chemin=chemin.name):
                self.assertIn("rejeu", chemin.name)
                self.assertIn("securite", chemin.name)


class WriteReadTests(unittest.TestCase):
    def test_written_file_can_be_read_back(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        chemin = Path(tmp.name) / "constats.json"

        persistence.write_axes(chemin, axes_fixture())
        restaures = persistence.read_axes(chemin)

        self.assertEqual(len(restaures), 2)
        self.assertEqual(restaures[0].constats[0].severite, "CRITIQUE")


if __name__ == "__main__":
    unittest.main()
