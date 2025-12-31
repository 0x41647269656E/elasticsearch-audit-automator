import unittest
from types import SimpleNamespace
from unittest.mock import patch

import main


def make_response(ok: bool, payload: dict) -> SimpleNamespace:
    return SimpleNamespace(ok=ok, json=lambda: payload)


class DetectClusterNameTests(unittest.TestCase):
    def test_returns_cluster_name_from_health(self) -> None:
        session = object()
        with patch.object(
            main,
            "execute_request",
            return_value=make_response(True, {"cluster_name": "prod-cluster"}),
        ) as mocked_request:
            result = main.detect_cluster_name(session, "http://localhost:9200", True)

        self.assertEqual(result, "prod-cluster")
        mocked_request.assert_called_once()

    def test_falls_back_to_root_when_health_fails(self) -> None:
        session = object()
        responses = [
            Exception("health down"),
            make_response(True, {"cluster_name": "fallback-cluster"}),
        ]

        def side_effect(*_args, **_kwargs):
            outcome = responses.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        with patch.object(main, "execute_request", side_effect=side_effect):
            result = main.detect_cluster_name(session, "http://localhost:9200", True)

        self.assertEqual(result, "fallback-cluster")


if __name__ == "__main__":
    unittest.main()
