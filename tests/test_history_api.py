import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from sentinel_casework.api import create_app


class HistoryAPITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

        db_path = Path(self.directory.name) / "test.db"
        self.client = TestClient(create_app(db_path))
        self.addCleanup(self.client.close)

    def create_run(self, case_id):
        response = self.client.post(f"/cases/{case_id}/investigate")
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_case_without_runs_has_empty_history(self):
        response = self.client.get("/cases/CASE-001/investigations")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_history_is_filtered_and_newest_first(self):
        # Identical timestamps also exercise the insertion-order tie-breaker.
        with patch("sentinel_casework.storage.datetime") as clock:
            clock.now.return_value.isoformat.return_value = (
                "2026-10-13T00:00:00+00:00"
            )
            first = self.create_run("CASE-001")
            self.create_run("CASE-002")
            latest = self.create_run("CASE-001")

        response = self.client.get("/cases/CASE-001/investigations")

        self.assertEqual(response.status_code, 200)
        history = response.json()

        self.assertEqual(
            [run["investigation_id"] for run in history],
            [latest["investigation_id"], first["investigation_id"]],
        )
        self.assertTrue(
            all(run["case_id"] == "CASE-001" for run in history)
        )
        self.assertEqual(history[0]["finding_count"], 1)
        self.assertEqual(history[0]["execution_mode"], "demo")
        self.assertNotIn("trace", history[0])

        saved = self.client.get(
            f"/investigations/{history[0]['investigation_id']}"
        )
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json(), latest)

    def test_history_is_limited_to_50_runs(self):
        for _ in range(51):
            self.create_run("CASE-002")

        response = self.client.get("/cases/CASE-002/investigations")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 50)

    def test_unknown_case_returns_404(self):
        response = self.client.get("/cases/UNKNOWN/investigations")

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()