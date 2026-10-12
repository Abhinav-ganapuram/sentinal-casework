import unittest
from unittest.mock import Mock

from sentinel_casework.agent import run_agent
from sentinel_casework.cases import CASE_PATH, load_case
from sentinel_casework.demo_adapter import DemoDecider


class DemoAdapterTests(unittest.TestCase):
    def test_suspicious_case_runs_two_lookups_and_finishes(self):
        result = run_agent(load_case(), DemoDecider(), max_steps=3)

        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(
            [step["tool"] for step in result["trace"]],
            ["get_user_events", "get_ip_events"],
        )
        self.assertEqual(
            [step["result_count"] for step in result["trace"]],
            [8, 7],
        )
        self.assertIn("Scripted demo", result["finish_reason"])

    def test_demo_respects_agent_step_limit(self):
        result = run_agent(load_case(), DemoDecider(), max_steps=1)

        self.assertEqual(result["status"], "step_limit")
        self.assertEqual(len(result["trace"]), 1)
        self.assertNotIn("finish_reason", result)

    def test_benign_case_skips_scripted_decisions(self):
        case = load_case(CASE_PATH.parent / "benign_mfa_retry.json")
        decider = Mock(wraps=DemoDecider())

        result = run_agent(case, decider, max_steps=3)

        self.assertEqual(result["status"], "no_detection")
        decider.assert_not_called()


if __name__ == "__main__":
    unittest.main()