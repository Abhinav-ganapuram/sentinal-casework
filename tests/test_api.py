import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from unittest.mock import patch
from sentinel_casework.api import create_app


class APITests(unittest.TestCase):
    
    def test_live_ai_investigation_is_saved(self):
        from sentinel_casework.demo_adapter import DemoDecider

        live_app = create_app(
            self.db_path,
            live_decider_factory=lambda: DemoDecider(),
        )

        with TestClient(live_app) as client:
            response = client.post(
                "/cases/CASE-001/investigate",
                json={"mode": "gemini"},
            )

        self.assertEqual(response.status_code, 200)

        result = response.json()

        self.assertEqual(
            result["execution_mode"],
            "gemini",
        )
        self.assertEqual(
            result["status"],
            "needs_review",
        )
        self.assertEqual(len(result["trace"]), 2)

        saved = self.client.get(
            f"/investigations/{result['investigation_id']}"
        )

        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json(), result)

    def test_gemini_requires_server_configuration(self):
        with patch.dict(
            "os.environ",
            {"GEMINI_API_KEY": ""},
        ):
            response = self.client.post(
                "/cases/CASE-001/investigate",
                json={"mode": "gemini"},
            )

        self.assertEqual(response.status_code, 503)

    def test_invalid_investigation_mode_is_rejected(self):
        response = self.client.post(
            "/cases/CASE-001/investigate",
            json={"mode": "unrestricted"},
        )

        self.assertEqual(response.status_code, 422)

    def test_invalid_ai_decision_is_saved_safely(self):
        def invalid_factory():
            def decide(context):
                return {
                    "tool": "delete_account",
                    "value": "unknown",
                    "reason": "Unsupported action",
                }

            return decide

        live_app = create_app(
            self.db_path,
            live_decider_factory=invalid_factory,
        )

        with TestClient(live_app) as client:
            response = client.post(
                "/cases/CASE-001/investigate",
                json={"mode": "gemini"},
            )

        self.assertEqual(response.status_code, 200)

        result = response.json()

        self.assertEqual(
            result["status"],
            "agent_error",
        )
        self.assertEqual(
            result["execution_mode"],
            "gemini",
        )
        self.assertTrue(result["findings"])
        self.assertEqual(result["trace"], [])
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

        self.db_path = Path(self.directory.name) / "test.db"
        self.client = TestClient(create_app(self.db_path))
        self.addCleanup(self.client.close)

    def test_lists_available_cases(self):
        response = self.client.get("/cases")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {case["case_id"] for case in response.json()},
            {"CASE-001", "CASE-002"},
        )

    def test_returns_case_evidence(self):
        response = self.client.get("/cases/CASE-001")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["events"]), 8)

    def test_runs_suspicious_demo_investigation(self):
        response = self.client.post("/cases/CASE-001/investigate")

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["execution_mode"], "demo")
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(
            [step["result_count"] for step in result["trace"]],
            [8, 7],
        )
        self.assertTrue(result["investigation_id"])
        self.assertTrue(result["created_at"])

    def test_benign_case_has_no_investigation_steps(self):
        response = self.client.post("/cases/CASE-002/investigate")

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "no_detection")
        self.assertEqual(result["trace"], [])

    def test_unknown_case_returns_404(self):
        for method, path in [
            ("get", "/cases/UNKNOWN"),
            ("post", "/cases/UNKNOWN/investigate"),
        ]:
            with self.subTest(method=method):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(
                    response.json()["detail"],
                    "Case not found",
                )

    def test_saved_investigation_survives_app_recreation(self):
        created = self.client.post(
            "/cases/CASE-001/investigate"
        )
        self.assertEqual(created.status_code, 200)
        original = created.json()

        with TestClient(create_app(self.db_path)) as restarted_client:
            response = restarted_client.get(
                f"/investigations/{original['investigation_id']}"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), original)

    def test_unknown_investigation_returns_404(self):
        response = self.client.get("/investigations/missing")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            response.json()["detail"],
            "Investigation not found",
        )


if __name__ == "__main__":
    unittest.main()