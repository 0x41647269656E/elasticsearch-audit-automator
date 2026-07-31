import json
import tempfile
import unittest
from pathlib import Path

import main


def write_commands(case: unittest.TestCase, payload: dict) -> str:
    tmp = tempfile.TemporaryDirectory()
    case.addCleanup(tmp.cleanup)
    path = Path(tmp.name) / "commands.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


class LoadCommandsVersionTests(unittest.TestCase):
    def test_accepts_the_legacy_1_0_format(self) -> None:
        path = write_commands(self, {"version": "1.0", "commands": []})

        self.assertEqual(main.load_commands(path)["version"], "1.0")

    def test_accepts_1_1_with_analysis_axes(self) -> None:
        path = write_commands(
            self,
            {
                "version": "1.1",
                "axes": {"resilience": {"titre": "R", "reference": "u", "prompt": "p"}},
                "commands": [{"name": "c", "command": "GET /", "axes": ["resilience"]}],
            },
        )

        data = main.load_commands(path)

        self.assertEqual(data["version"], "1.1")
        self.assertIn("resilience", data["axes"])

    def test_rejects_an_unknown_version(self) -> None:
        path = write_commands(self, {"version": "2.0", "commands": []})

        with self.assertRaises(ValueError) as raised:
            main.load_commands(path)

        self.assertIn("2.0", str(raised.exception))


class RealCommandsFileTests(unittest.TestCase):
    """The shipped commands.json must satisfy its own contract."""

    def setUp(self) -> None:
        self.data = main.load_commands("commands.json")

    def test_every_command_declares_at_least_one_axis(self) -> None:
        orphans = [c["name"] for c in self.data["commands"] if not c.get("axes")]

        self.assertEqual(orphans, [])

    def test_every_declared_axis_exists(self) -> None:
        known = set(self.data["axes"])
        unknown = {a for c in self.data["commands"] for a in c.get("axes", [])} - known

        self.assertEqual(unknown, set())

    def test_every_axis_is_used_by_a_command(self) -> None:
        used = {a for c in self.data["commands"] for a in c.get("axes", [])}
        unused = set(self.data["axes"]) - used

        self.assertEqual(unused, set())

    def test_every_axis_carries_a_reference_and_a_prompt(self) -> None:
        for key, axis in self.data["axes"].items():
            with self.subTest(axis=key):
                self.assertTrue(axis.get("reference", "").startswith("https://"))
                self.assertTrue(axis.get("prompt"))
                self.assertTrue(axis.get("titre"))

    def test_command_names_and_paths_are_unique(self) -> None:
        names = [c["name"] for c in self.data["commands"]]
        paths = [c["command"] for c in self.data["commands"]]

        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(paths), len(set(paths)))


if __name__ == "__main__":
    unittest.main()
