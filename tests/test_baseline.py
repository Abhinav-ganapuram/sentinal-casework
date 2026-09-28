import unittest
from pathlib import Path

from sentinel_casework.baseline import investigate_case
from sentinel_casework.cases import load_case


ROOT = Path(__file__).resolve().parent.parent


class BaselineTests(unittest.TestCase):
    def test_suspicious_case_records_two_lookups(self):
        case = load_case(ROOT / "cases" / "identity_compromise.json")

        result = investigate_case(case)

        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(
            [step["tool"] for step in result["trace"]],
            ["get_user_events", "get_ip_events"],
        )
        self.assertEqual(
            [step["result_count"] for step in result["trace"]],
            [8, 7],
        )

    def test_benign_case_needs_no_follow_up(self):
        case = load_case(ROOT / "cases" / "benign_mfa_retry.json")

        result = investigate_case(case)

        self.assertEqual(result["status"], "no_detection")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["trace"], [])


if __name__ == "__main__":
    unittest.main()