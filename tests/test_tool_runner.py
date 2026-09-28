import unittest

from sentinel_casework.cases import load_case
from sentinel_casework.tool_runner import run_lookup


class ToolRunnerTests(unittest.TestCase):
    def test_records_user_lookup(self):
        case = load_case()

        results, trace = run_lookup(
            case["events"], "get_user_events", case["subject"]
        )

        self.assertEqual(len(results), 8)
        self.assertEqual(trace["tool"], "get_user_events")
        self.assertEqual(trace["result_count"], 8)
        self.assertEqual(trace["event_ids"], [event["id"] for event in results])

    def test_rejects_unknown_tool(self):
        events = load_case()["events"]

        with self.assertRaisesRegex(ValueError, "Unknown investigation tool"):
            run_lookup(events, "delete_account", "mira.patel@example.test")


if __name__ == "__main__":
    unittest.main()