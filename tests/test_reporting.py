import json
import tempfile
import unittest
from pathlib import Path

from sentinel_casework.reporting import save_report


class ReportingTests(unittest.TestCase):
    def test_saves_complete_result_in_new_directory(self):
        result = {
            "case_id": "CASE-001",
            "status": "needs_review",
            "findings": [{"evidence_ids": ["E003", "E004"]}],
            "trace": [{
                "tool": "get_ip_events",
                "query": "203.0.113.57",
                "event_ids": ["E003", "E004"],
                "result_count": 2,
                "reason": "Review source activity.",
            }],
        }

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reports" / "case.json"

            save_report(result, path)

            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved, result)

    def test_existing_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.json"
            path.write_text("original report", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                save_report({"case_id": "CASE-002"}, path)

            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "original report",
            )


if __name__ == "__main__":
    unittest.main()