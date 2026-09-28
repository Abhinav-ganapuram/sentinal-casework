import copy
import unittest

from sentinel_casework.cases import load_case
from sentinel_casework.investigation import get_ip_events, get_user_events


class InvestigationTests(unittest.TestCase):
    def test_filters_user_without_changing_original_events(self):
        case = load_case()
        events = case["events"]

        other_user_event = copy.deepcopy(events[0])
        other_user_event["id"] = "OTHER-001"
        other_user_event["user"] = "someone.else@example.test"
        events.append(other_user_event)

        results = get_user_events(events, case["subject"])

        self.assertEqual(len(results), 8)
        self.assertNotIn("OTHER-001", [event["id"] for event in results])

        results[0]["details"]["device"] = "changed"
        self.assertEqual(events[0]["details"]["device"], "managed-laptop")
    def test_filters_mfa_events(self):
        case = load_case()

        results = get_user_events(
            case["events"], case["subject"], action="mfa_push"
        )

        self.assertEqual(
            [event["id"] for event in results],
            ["E003", "E004", "E005", "E006"],
        )
    def test_ip_lookup_finds_other_users_without_changing_evidence(self):
        case = load_case()
        events = case["events"]

        other_user_event = copy.deepcopy(events[0])
        other_user_event["id"] = "OTHER-002"
        other_user_event["user"] = "someone.else@example.test"
        other_user_event["details"]["ip"] = "203.0.113.57"
        events.append(other_user_event)

        results = get_ip_events(events, "203.0.113.57")

        self.assertEqual(len(results), 8)
        self.assertIn("OTHER-002", [event["id"] for event in results])

        results[0]["details"]["device"] = "changed"
        self.assertEqual(events[1]["details"]["device"], "new-browser")
        self.assertEqual(get_ip_events(events, ""), [])
if __name__ == "__main__":
    unittest.main()