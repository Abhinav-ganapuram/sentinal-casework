import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from pydantic import ValidationError

from sentinel_casework.gemini_adapter import GeminiDecider


class GeminiAdapterTests(unittest.TestCase):
    def make_decider(self, output_text):
        client = Mock()
        client.interactions.create.return_value = SimpleNamespace(
            output_text=output_text
        )
        return GeminiDecider(client=client)

    def test_returns_valid_lookup_decision(self):
        expected = {
            "tool": "get_ip_events",
            "value": "203.0.113.57",
            "reason": "Review activity from the source IP.",
        }
        decider = self.make_decider(json.dumps(expected))

        result = decider({
            "case_id": "CASE-001",
            "finding": {"source_ip": "203.0.113.57"},
            "observations": [],
        })

        self.assertEqual(result, expected)

    def test_rejects_unknown_tool(self):
        decider = self.make_decider(json.dumps({
            "tool": "delete_user",
            "value": "mira.patel@example.test",
            "reason": "Remove the account.",
        }))

        with self.assertRaises(ValidationError):
            decider({})

    def test_rejects_empty_response(self):
        decider = self.make_decider("")

        with self.assertRaisesRegex(ValueError, "Gemini returned no decision"):
            decider({})

    def test_rejects_invalid_json(self):
        decider = self.make_decider("Here is my investigation decision.")

        with self.assertRaises(ValidationError):
            decider({})


if __name__ == "__main__":
    unittest.main()