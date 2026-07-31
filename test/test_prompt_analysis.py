import unittest
from pathlib import Path
from unittest.mock import patch

import main

# Any file that really exists, so the prompt is actually reached.
EXISTING_SCRIPT = Path(main.__file__)


class PromptAnalysisNonInteractiveTests(unittest.TestCase):
    def test_does_not_crash_when_stdin_is_closed(self) -> None:
        """A cron/CI run has no stdin; the audit is already on disk by then."""
        with patch.object(main, "ANALYSE_SCRIPT", EXISTING_SCRIPT):
            with patch("builtins.input", side_effect=EOFError):
                with patch.object(main.subprocess, "run") as runner:
                    main.prompt_analysis(Path("data/some-audit"))

        runner.assert_not_called()

    def test_does_not_crash_when_the_user_interrupts(self) -> None:
        with patch.object(main, "ANALYSE_SCRIPT", EXISTING_SCRIPT):
            with patch("builtins.input", side_effect=KeyboardInterrupt):
                with patch.object(main.subprocess, "run") as runner:
                    main.prompt_analysis(Path("data/some-audit"))

        runner.assert_not_called()

    def test_runs_the_script_when_the_user_accepts(self) -> None:
        with patch.object(main, "ANALYSE_SCRIPT", EXISTING_SCRIPT):
            with patch("builtins.input", return_value=""):
                with patch.object(main.subprocess, "run") as runner:
                    main.prompt_analysis(Path("data/some-audit"))

        runner.assert_called_once()


class PromptAnalysisMissingScriptTests(unittest.TestCase):
    def test_reports_a_missing_analyse_script_clearly(self) -> None:
        """analyse.py absent must not surface as an opaque 'exit status 2'."""
        with patch.object(main, "ANALYSE_SCRIPT", Path("definitely-absent.py")):
            with patch.object(main.subprocess, "run") as runner:
                with patch("builtins.print") as printer:
                    main.prompt_analysis(Path("data/some-audit"))

        runner.assert_not_called()
        printed = " ".join(str(call.args[0]) for call in printer.call_args_list if call.args)
        self.assertIn("definitely-absent.py", printed)


if __name__ == "__main__":
    unittest.main()
