import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import analyse


class DotenvTests(unittest.TestCase):
    """The spec says the key is read from .env; nothing else loads it for analyse.py."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.env_file = Path(tmp.name) / ".env"
        self.env_file.write_text("ANTHROPIC_API_KEY=sk-ant-depuis-le-fichier\n", encoding="utf-8")
        previous = os.environ.pop("ANTHROPIC_API_KEY", None)
        self.addCleanup(
            lambda: os.environ.__setitem__("ANTHROPIC_API_KEY", previous)
            if previous is not None
            else os.environ.pop("ANTHROPIC_API_KEY", None)
        )

    def test_reads_the_key_from_a_dotenv_file(self) -> None:
        analyse.load_credentials(self.env_file)

        self.assertEqual(os.environ.get("ANTHROPIC_API_KEY"), "sk-ant-depuis-le-fichier")

    def test_an_exported_key_wins_over_the_file(self) -> None:
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-de-l-environnement"

        analyse.load_credentials(self.env_file)

        self.assertEqual(os.environ["ANTHROPIC_API_KEY"], "sk-ant-de-l-environnement")

    def test_a_missing_file_is_not_an_error(self) -> None:
        analyse.load_credentials(Path("nexiste-pas/.env"))


if __name__ == "__main__":
    unittest.main()
