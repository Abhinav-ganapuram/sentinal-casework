import unittest

from fastapi.testclient import TestClient

from sentinel_casework.api import app


class APITests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
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


if __name__ == "__main__":
    unittest.main()