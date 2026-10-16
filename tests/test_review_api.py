import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from sentinel_casework.api import create_app


class ReviewAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

        self.db_path = Path(self.directory.name) / "test.db"
        self.client = TestClient(create_app(self.db_path))
        self.addCleanup(self.client.close)

        response = self.client.post("/cases/CASE-001/investigate")
        self.assertEqual(response.status_code, 200)
        self.original = response.json()
        self.run_id = self.original["investigation_id"]
        self.url = f"/investigations/{self.run_id}/reviews"

    def test_new_investigation_has_no_reviews(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_review_is_saved_and_original_result_is_preserved(self):
        response = self.client.post(
            self.url,
            json={
                "verdict": "needs_more_evidence",
                "notes": "  Check whether the role grant was authorized.  ",
            },
        )

        self.assertEqual(response.status_code, 201)
        review = response.json()
        self.assertEqual(review["investigation_id"], self.run_id)
        self.assertEqual(
            review["notes"],
            "Check whether the role grant was authorized.",
        )

        with TestClient(create_app(self.db_path)) as restarted:
            history = restarted.get(self.url)
            saved_run = restarted.get(f"/investigations/{self.run_id}")

        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json(), [review])
        self.assertEqual(saved_run.json(), self.original)

    def test_invalid_requests_are_rejected_without_saving(self):
        invalid_requests = [
            {"verdict": "unknown", "notes": "Some notes"},
            {"verdict": "benign", "notes": "   "},
            {"verdict": "suspicious"},
            {"verdict": "suspicious", "notes": "x" * 2001},
            {
                "verdict": "benign",
                "notes": "Reviewed.",
                "unexpected": "not allowed",
            },
        ]

        for payload in invalid_requests:
            with self.subTest(payload_keys=list(payload)):
                response = self.client.post(self.url, json=payload)
                self.assertEqual(response.status_code, 422)

        self.assertEqual(self.client.get(self.url).json(), [])

    def test_unknown_investigation_returns_404(self):
        url = "/investigations/missing/reviews"

        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

        response = self.client.post(
            url,
            json={
                "verdict": "suspicious",
                "notes": "Needs investigation.",
            },
        )
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()