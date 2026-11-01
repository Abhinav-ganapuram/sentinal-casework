
"""Tests for persistent Sysmon telemetry imports."""

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from sentinel_casework.api import create_app


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "telemetry_samples" / "sysmon_demo.json"


class TelemetryImportAPITests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

        self.db_path = (
            Path(self.temp.name) / "import_test.db"
        )

        self.client = TestClient(
            create_app(db_path=self.db_path)
        )

        self.sample_content = SAMPLE.read_text(
            encoding="utf-8"
        )

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def import_sample(self):
        return self.client.post(
            "/imports",
            json={
                "filename": "sysmon_demo.json",
                "content": self.sample_content,
            },
        )

    def test_imports_sysmon_events(self):
        response = self.import_sample()

        self.assertEqual(response.status_code, 201)

        data = response.json()

        self.assertTrue(
            data["case_id"].startswith("IMPORT-")
        )

        self.assertEqual(data["event_count"], 3)

    def test_imported_case_appears_in_library(self):
        created = self.import_sample().json()

        response = self.client.get("/cases")

        self.assertEqual(response.status_code, 200)

        case_ids = {
            item["case_id"]
            for item in response.json()
        }

        self.assertIn(
            created["case_id"],
            case_ids,
        )

        # Existing built-in cases must still be available.
        self.assertIn("CASE-001", case_ids)
        self.assertIn("CASE-006", case_ids)

    def test_imported_case_can_be_reopened(self):
        created = self.import_sample().json()

        response = self.client.get(
            f"/cases/{created['case_id']}"
        )

        self.assertEqual(response.status_code, 200)

        case = response.json()

        self.assertEqual(len(case["events"]), 3)
        self.assertEqual(
            case["source_type"],
            "sysmon_import",
        )

        self.assertEqual(
            case["events"][0]["source"],
            "sysmon",
        )

    def test_import_survives_app_restart(self):
        created = self.import_sample().json()

        # Simulate reopening the application against
        # the same SQLite database.
        with TestClient(
            create_app(db_path=self.db_path)
        ) as restarted_client:

            response = restarted_client.get(
                f"/cases/{created['case_id']}"
            )

            self.assertEqual(response.status_code, 200)

            self.assertEqual(
                response.json()["case_id"],
                created["case_id"],
            )

    def test_imported_case_supports_investigation(self):
        created = self.import_sample().json()

        response = self.client.post(
            f"/cases/{created['case_id']}/investigate",
            json={"mode": "demo"},
        )

        self.assertEqual(response.status_code, 200)

        result = response.json()

        # Endpoint detections are not implemented yet.
        self.assertEqual(
            result["status"],
            "no_detection",
        )

        self.assertEqual(result["findings"], [])
        self.assertIn("report", result)
        self.assertIn("investigation_id", result)

        history = self.client.get(
            f"/cases/{created['case_id']}/investigations"
        )

        self.assertEqual(history.status_code, 200)
        self.assertEqual(len(history.json()), 1)

    def test_rejects_malformed_json(self):
        response = self.client.post(
            "/imports",
            json={
                "filename": "bad.json",
                "content": "{not-valid-json",
            },
        )

        self.assertEqual(response.status_code, 422)

    def test_rejects_unsupported_file(self):
        response = self.client.post(
            "/imports",
            json={
                "filename": "events.evtx",
                "content": "fake binary data",
            },
        )

        self.assertEqual(response.status_code, 415)

    def test_rejects_path_in_filename(self):
        response = self.client.post(
            "/imports",
            json={
                "filename": "../events.json",
                "content": self.sample_content,
            },
        )

        self.assertEqual(response.status_code, 422)

    def test_rejects_oversized_content(self):
        response = self.client.post(
            "/imports",
            json={
                "filename": "large.json",
                "content": " " * (5 * 1024 * 1024 + 1),
            },
        )

        self.assertEqual(response.status_code, 413)

    def test_missing_case_returns_404(self):
        response = self.client.get(
            "/cases/IMPORT-DOESNOTEXIST"
        )

        self.assertEqual(response.status_code, 404)

    def test_import_list_endpoint(self):
        created = self.import_sample().json()

        response = self.client.get("/imports")

        self.assertEqual(response.status_code, 200)

        self.assertEqual(len(response.json()), 1)

        self.assertEqual(
            response.json()[0]["case_id"],
            created["case_id"],
        )


if __name__ == "__main__":
    unittest.main()