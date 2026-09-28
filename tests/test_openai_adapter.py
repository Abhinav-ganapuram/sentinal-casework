import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from sentinel_casework.openai_adapter import NextAction, OpenAIDecider


class OpenAIAdapterTests(unittest.TestCase):
    def test_returns_structured_decision_without_api_call(self):
        parse = Mock(return_value=SimpleNamespace(
            output_parsed=NextAction(
                tool="get_ip_events",
                value="203.0.113.57",
                reason="Check source IP",
            )
        ))
        fake_client = SimpleNamespace(responses=SimpleNamespace(parse=parse))
        decider = OpenAIDecider(client=fake_client)

        decision = decider({"case_id": "CASE-001", "observations": []})

        self.assertEqual(decision["tool"], "get_ip_events")
        self.assertEqual(decision["value"], "203.0.113.57")
        self.assertEqual(parse.call_args.kwargs["model"], "gpt-6-luna")
        self.assertIn(
            "CASE-001",
            parse.call_args.kwargs["input"][1]["content"],
        )

    def test_missing_model_decision_raises_error(self):
        parse = Mock(return_value=SimpleNamespace(output_parsed=None))
        fake_client = SimpleNamespace(responses=SimpleNamespace(parse=parse))

        with self.assertRaisesRegex(ValueError, "did not return a decision"):
            OpenAIDecider(client=fake_client)({"case_id": "CASE-001"})


if __name__ == "__main__":
    unittest.main()