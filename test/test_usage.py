import re
import unittest

from audit_analysis import usage
from audit_analysis.model import AxeAnalyse, Usage


def axe(cle: str, **kw) -> AxeAnalyse:
    base = dict(cle=cle, titre=cle.title(), reference="https://x", commandes=[])
    base.update(kw)
    return AxeAnalyse(**base)


class CostTests(unittest.TestCase):
    def test_prices_input_and_output_at_the_model_rate(self) -> None:
        cout = usage.cost_usd(
            Usage(input_tokens=1_000_000, output_tokens=1_000_000), "claude-opus-5"
        )

        self.assertAlmostEqual(cout, 5.0 + 25.0, places=4)

    def test_cached_input_is_billed_far_below_fresh_input(self) -> None:
        frais = usage.cost_usd(Usage(input_tokens=1_000_000), "claude-opus-5")
        cache = usage.cost_usd(Usage(cache_read_input_tokens=1_000_000), "claude-opus-5")

        self.assertLess(cache, frais / 5)

    def test_thinking_is_billed_as_output(self) -> None:
        """Les jetons de raisonnement comptent dans output_tokens : c'est ce qui
        avait fait sous-estimer le coût du premier run."""
        sans = usage.cost_usd(Usage(input_tokens=100_000, output_tokens=4_000), "claude-opus-5")
        avec = usage.cost_usd(Usage(input_tokens=100_000, output_tokens=24_000), "claude-opus-5")

        self.assertGreater(avec, sans * 1.5)

    def test_an_unknown_model_yields_no_cost_rather_than_a_wrong_one(self) -> None:
        self.assertIsNone(usage.cost_usd(Usage(input_tokens=1_000), "modele-inconnu"))


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.axes = [
            axe("resilience", usage=Usage(input_tokens=198_024, output_tokens=6_000), duree_s=120.0),
            axe("securite", usage=Usage(input_tokens=18_495, output_tokens=2_000), duree_s=30.0),
            axe("disque", erreur="refus du modèle"),
        ]

    def test_records_each_axis_separately(self) -> None:
        rapport = usage.build_report("claude-opus-5", "high", self.axes, duree_s=200.0)

        self.assertEqual(rapport["axes"]["resilience"]["input_tokens"], 198_024)
        self.assertEqual(rapport["axes"]["securite"]["output_tokens"], 2_000)

    def test_totals_add_up(self) -> None:
        rapport = usage.build_report("claude-opus-5", "high", self.axes, duree_s=200.0)

        self.assertEqual(rapport["total"]["input_tokens"], 198_024 + 18_495)
        self.assertEqual(rapport["total"]["output_tokens"], 8_000)

    def test_reports_the_cost_it_actually_measured(self) -> None:
        rapport = usage.build_report("claude-opus-5", "high", self.axes, duree_s=200.0)

        attendu = (198_024 + 18_495) / 1e6 * 5 + 8_000 / 1e6 * 25
        self.assertAlmostEqual(rapport["total"]["cout_usd"], attendu, places=4)

    def test_an_unevaluated_axis_is_listed_without_being_counted(self) -> None:
        rapport = usage.build_report("claude-opus-5", "high", self.axes, duree_s=200.0)

        self.assertEqual(rapport["axes"]["disque"]["etat"], "non évalué")
        self.assertEqual(rapport["axes"]["disque"]["input_tokens"], 0)

    def test_keeps_the_model_and_effort_that_produced_it(self) -> None:
        rapport = usage.build_report("claude-opus-5", "high", self.axes, duree_s=200.0)

        self.assertEqual(rapport["modele"], "claude-opus-5")
        self.assertEqual(rapport["effort"], "high")
        self.assertEqual(rapport["duree_s"], 200.0)


class OutputNamingTests(unittest.TestCase):
    """Un rejeu ne doit jamais écraser le rapport complet."""

    def test_full_run_uses_the_canonical_names(self) -> None:
        rapport, conso = usage.output_paths("data/audit")

        self.assertEqual(rapport.name, "rapport.md")
        self.assertEqual(conso.name, "consommation.json")

    def test_a_replay_names_the_axis_it_replayed(self) -> None:
        rapport, conso = usage.output_paths("data/audit", axe="securite")

        self.assertIn("rejeu", rapport.name)
        self.assertIn("securite", rapport.name)
        self.assertTrue(rapport.name.endswith(".md"))
        self.assertIn("rejeu", conso.name)
        self.assertIn("securite", conso.name)

    def test_a_replay_is_timestamped_so_successive_ones_coexist(self) -> None:
        rapport, _ = usage.output_paths("data/audit", axe="securite")

        self.assertRegex(rapport.name, r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}")

    def test_a_replay_never_collides_with_the_full_report(self) -> None:
        complet, conso_complet = usage.output_paths("data/audit")
        rejeu, conso_rejeu = usage.output_paths("data/audit", axe="securite")

        self.assertNotEqual(complet, rejeu)
        self.assertNotEqual(conso_complet, conso_rejeu)


if __name__ == "__main__":
    unittest.main()
