import tempfile
import unittest
from pathlib import Path

from sentinel_casework.storage import (
    get_investigation,
    save_investigation,
)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_path = Path(self.directory.name) / "data" / "test.db"

        self.result = {
            "case_id": "CASE-001",
            "status": "needs_review",
            "execution_mode": "demo",
            "findings": [{
                "rule_id": "DET-001",
                "evidence_ids": ["E003", "E004"],
            }],
            "trace": [{
                "tool": "get_ip_events",
                "query": "203.0.113.57",
                "result_count": 2,
                "event_ids": ["E003", "E004"],
                "reason": "Review source activity.",
            }],
        }

    def test_result_survives_database_reconnection(self):
        saved = save_investigation(self.result, self.db_path)

        loaded = get_investigation(
            saved["investigation_id"],
            self.db_path,
        )

        self.assertEqual(loaded, saved)
        self.assertEqual(loaded["result"], self.result)
        self.assertTrue(saved["created_at"].endswith("+00:00"))

    def test_repeated_runs_preserve_separate_results(self):
        first = save_investigation(self.result, self.db_path)

        second_result = {
            **self.result,
            "status": "step_limit",
        }
        second = save_investigation(second_result, self.db_path)

        self.assertNotEqual(
            first["investigation_id"],
            second["investigation_id"],
        )

        first_loaded = get_investigation(
            first["investigation_id"],
            self.db_path,
        )
        second_loaded = get_investigation(
            second["investigation_id"],
            self.db_path,
        )

        self.assertEqual(first_loaded["result"]["status"], "needs_review")
        self.assertEqual(second_loaded["result"]["status"], "step_limit")

    def test_unknown_id_returns_none(self):
        self.assertIsNone(
            get_investigation("missing-investigation", self.db_path)
        )


if __name__ == "__main__":
    unittest.main()