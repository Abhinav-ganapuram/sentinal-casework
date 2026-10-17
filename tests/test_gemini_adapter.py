
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from sentinel_casework.gemini_adapter import (
    GeminiDecider,
    GeminiProviderError,
)


class GeminiAdapterTests(unittest.TestCase):

    def make_decider(self, response_text):
        client = Mock()
        client.models.generate_content.return_value = (
            SimpleNamespace(text=response_text)
        )

        return GeminiDecider(
            client=client,
            model="gemini-3.8-flash",
        )

    def test_returns_valid_lookup_decision(self):
        expected = {
            "tool": "get_ip_events",
            "value": "203.0.113.57",
            "reason": "Review activity from source IP",
        }

        decider = self.make_decider(
            json.dumps(expected)
        )

        result = decider({
            "case_id": "CASE-001",
            "finding": {
                "source_ip": "203.0.113.57",
            },
            "observations": [],
        })

        self.assertEqual(result, expected)

        decider.client.models.generate_content.assert_called_once()

        call = (
            decider.client.models.generate_content.call_args
        )

        self.assertEqual(
            call.kwargs["model"],
            "gemini-3.8-flash",
        )

        self.assertEqual(
            call.kwargs["config"].response_mime_type,
            "application/json",
        )

    def test_rejects_unknown_tool(self):
        decider = self.make_decider(
            json.dumps({
                "tool": "delete_user",
                "value": "user@example.test",
                "reason": "Delete account",
            })
        )

        with self.assertRaisesRegex(
            ValueError,
            "invalid decision",
        ):
            decider({})

    def test_rejects_empty_response(self):
        decider = self.make_decider("")

        with self.assertRaisesRegex(
            ValueError,
            "Gemini returned no decision",
        ):
            decider({})

    def test_rejects_invalid_json(self):
        decider = self.make_decider(
            "Not a JSON response"
        )

        with self.assertRaisesRegex(
            ValueError,
            "invalid decision",
        ):
            decider({})

    def test_provider_failure_is_wrapped(self):
        client = Mock()

        client.models.generate_content.side_effect = (
            RuntimeError("Simulated provider failure")
        )

        decider = GeminiDecider(client=client)

        with self.assertRaises(GeminiProviderError):
            decider({"case_id": "CASE-001"})


if __name__ == "__main__":
    unittest.main()
