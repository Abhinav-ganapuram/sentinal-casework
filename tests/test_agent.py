import unittest

from sentinel_casework.agent import run_agent, validate_decision
from sentinel_casework.cases import load_case

class AgentDecisionTests(unittest.TestCase):
    def test_accepts_approved_lookup(self):
        decision = validate_decision({
            "tool": "get_ip_events",
            "value": "203.0.113.57",
            "reason": "Check related activity",
        })
        self.assertEqual(decision["tool"], "get_ip_events")

    def test_rejects_unknown_or_malformed_tool(self):
        for tool in ("delete_account", ["get_ip_events"]):
            with self.subTest(tool=tool):
                with self.assertRaises(ValueError):
                    validate_decision({
                        "tool": tool,
                        "value": "203.0.113.57",
                        "reason": "Investigate",
                    })

    def test_rejects_lookup_without_value(self):
        with self.assertRaisesRegex(ValueError, "Lookup needs a value"):
            validate_decision({
                "tool": "get_user_events",
                "value": "",
                "reason": "Investigate",
            })

    def test_finish_does_not_need_a_lookup_value(self):
        decision = validate_decision({
            "tool": "finish",
            "reason": "Enough evidence collected",
        })
        self.assertEqual(decision["value"], "")
    def test_agent_uses_observations_and_finishes(self):
        case = load_case()
        choices = iter([
            {
                "tool": "get_user_events",
                "value": case["subject"],
                "reason": "Review account activity",
            },
            {
                "tool": "get_ip_events",
                "value": "203.0.113.57",
                "reason": "Check source IP",
            },
            {
                "tool": "finish",
                "reason": "Ready for analyst review",
            },
        ])
        observation_counts = []

        def decide(context):
            observation_counts.append(len(context["observations"]))
            return next(choices)

        result = run_agent(case, decide)

        self.assertEqual(observation_counts, [0, 1, 2])
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(
            [step["result_count"] for step in result["trace"]],
            [8, 7],
        )
        self.assertEqual(result["finish_reason"], "Ready for analyst review")

    def test_benign_case_does_not_call_decision_function(self):
        from pathlib import Path

        path = Path(__file__).resolve().parent.parent / "cases" / "benign_mfa_retry.json"
        case = load_case(path)

        def decide(context):
            raise AssertionError("No agent decision expected")

        self.assertEqual(run_agent(case, decide)["status"], "no_detection")

    def test_agent_stops_at_step_limit(self):
        case = load_case()

        def decide(context):
            return {
                "tool": "get_user_events",
                "value": case["subject"],
                "reason": "Check account",
            }

        result = run_agent(case, decide, max_steps=2)
        self.assertEqual(result["status"], "step_limit")
        self.assertEqual(len(result["trace"]), 2)

if __name__ == "__main__":
    unittest.main()