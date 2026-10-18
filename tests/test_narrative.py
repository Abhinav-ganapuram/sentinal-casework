
import json
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

from sentinel_casework.agent import run_agent
from sentinel_casework.cases import load_case
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.narrative import (
    GeminiNarrativeGenerator,
    NarrativeValidationError,
    validate_narrative,
)
from sentinel_casework.report_builder import build_incident_report


class NarrativeTests(unittest.TestCase):

    def setUp(self):
        case = load_case()
        result = run_agent(case, DemoDecider())

        self.report = build_incident_report(case, result)

        self.narrative = {
            "executive_summary": (
                "Suspicious identity activity detected."
            ),
            "observations": [
                {
                    "statement": (
                        "Authentication activity was observed."
                    ),
                    "event_ids": [
                        self.report["evidence_event_ids"][0]
                    ],
                }
            ],
            "implications": [
                "Potential account access risk"
            ],
            "uncertainties": [
                "Account compromise is unconfirmed"
            ],
            "next_steps": [
                "Verify account activity"
            ],
        }

    def test_accepts_valid_evidence_references(self):
        output = validate_narrative(
            self.narrative,
            self.report,
        )

        self.assertEqual(
            output["generation_method"],
            "gemini",
        )

        self.assertEqual(
            output["evidence_validation"],
            "event_ids_checked",
        )

        self.assertTrue(
            output["requires_human_review"]
        )

    def test_rejects_fabricated_event_ids(self):
        narrative = deepcopy(self.narrative)

        narrative["observations"][0]["event_ids"] = [
            "FAKE-EVENT"
        ]

        with self.assertRaisesRegex(
            NarrativeValidationError,
            "unknown evidence IDs",
        ):
            validate_narrative(
                narrative,
                self.report,
            )

    def test_rejects_missing_observation_citations(self):
        narrative = deepcopy(self.narrative)

        narrative["observations"][0]["event_ids"] = []

        with self.assertRaises(NarrativeValidationError):
            validate_narrative(
                narrative,
                self.report,
            )

    def test_rejects_unexpected_fields(self):
        narrative = deepcopy(self.narrative)

        narrative["unsupported_field"] = "unexpected"

        with self.assertRaises(NarrativeValidationError):
            validate_narrative(
                narrative,
                self.report,
            )

    def test_gemini_generator_returns_unvalidated_payload(self):
        client = Mock()

        client.models.generate_content.return_value = (
            SimpleNamespace(
                text=json.dumps(self.narrative)
            )
        )

        generator = GeminiNarrativeGenerator(
            client=client,
            model="gemini-3.8-flash",
        )

        generated = generator(self.report)

        self.assertEqual(
            generated,
            self.narrative,
        )

        validated = validate_narrative(
            generated,
            self.report,
        )

        self.assertEqual(
            validated["generation_method"],
            "gemini",
        )

        self.assertTrue(
            validated["requires_human_review"]
        )

        client.models.generate_content.assert_called_once()


if __name__ == "__main__":
    unittest.main()