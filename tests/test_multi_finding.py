
"""Tests for process lookups and multiple finding investigations."""

import unittest
from copy import deepcopy
from pathlib import Path

from sentinel_casework.agent import (
    run_agent,
    validate_investigation_step,
)
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.investigation import get_process_events
from sentinel_casework.report_builder import build_incident_report
from sentinel_casework.telemetry import (
    create_imported_case,
    load_sysmon_file,
)
from sentinel_casework.tool_runner import run_lookup


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "telemetry_samples"


class MultiFindingTests(unittest.TestCase):

    def setUp(self):
        self.encoded = load_sysmon_file(
            SAMPLES / "sysmon_suspicious_powershell.json"
        )
        self.office = load_sysmon_file(
            SAMPLES / "sysmon_office_powershell.json"
        )

        self.events = self.encoded + self.office

        self.case = create_imported_case(
            self.events,
            case_id="IMPORT-MULTI-TEST",
            title="Two suspicious PowerShell process chains",
        )

    def test_process_guid_lookup(self):
        guid = self.encoded[0]["details"]["process_guid"]

        result = get_process_events(
            self.events,
            guid,
        )

        self.assertEqual(len(result), 2)
        self.assertEqual(
            {item["action"] for item in result},
            {"process_created", "network_connection"},
        )

    def test_process_lookup_is_read_only(self):
        original = deepcopy(self.events)
        guid = self.encoded[0]["details"]["process_guid"]

        results, step = run_lookup(
            self.events,
            "get_process_events",
            guid,
        )

        self.assertEqual(step["result_count"], 2)
        self.assertEqual(
            len(step["event_ids"]),
            2,
        )

        results[0]["details"]["image"] = "changed"

        self.assertEqual(self.events, original)

    def test_valid_process_lookup_accepted(self):
        guid = self.office[0]["details"]["process_guid"]

        decision = validate_investigation_step(
            {
                "tool": "get_process_events",
                "value": guid,
                "reason": "Inspect associated process events",
            },
            self.events,
            [],
        )

        self.assertEqual(
            decision["tool"],
            "get_process_events",
        )

    def test_unknown_process_guid_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "not present in case evidence",
        ):
            validate_investigation_step(
                {
                    "tool": "get_process_events",
                    "value": "{invented-guid}",
                    "reason": "Inspect process",
                },
                self.events,
                [],
            )

    def test_duplicate_process_lookup_rejected(self):
        guid = self.encoded[0]["details"]["process_guid"]

        previous = [{
            "tool": "get_process_events",
            "query": guid,
            "event_ids": [],
        }]

        with self.assertRaisesRegex(
            ValueError,
            "Repeated investigation lookup",
        ):
            validate_investigation_step(
                {
                    "tool": "get_process_events",
                    "value": guid,
                    "reason": "Repeat lookup",
                },
                self.events,
                previous,
            )

    def test_demo_investigates_both_findings(self):
        result = run_agent(
            self.case,
            DemoDecider(),
        )

        rule_ids = {
            item["rule_id"]
            for item in result["findings"]
        }

        self.assertEqual(
            rule_ids,
            {"DET-002", "DET-003"},
        )

        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(
            result["investigated_finding_count"],
            2,
        )

        self.assertEqual(
            len(result["finding_investigations"]),
            2,
        )

        # Two lookups for each independently investigated finding.
        self.assertEqual(len(result["trace"]), 4)

        indices = [
            item["finding_index"]
            for item in result["trace"]
        ]

        self.assertEqual(indices, [0, 0, 1, 1])

    def test_process_lookup_per_finding(self):
        requested = []

        def process_decider(context):
            index = context["finding_index"]

            if not context["observations"]:
                guid = context["process_guids"][0]
                requested.append((index, guid))

                return {
                    "tool": "get_process_events",
                    "value": guid,
                    "reason": "Inspect the finding's process",
                }

            return {
                "tool": "finish",
                "value": "",
                "reason": "Process events reviewed",
            }

        result = run_agent(
            self.case,
            process_decider,
        )

        self.assertEqual(
            result["status"],
            "needs_review",
        )
        self.assertEqual(
            len(result["trace"]),
            2,
        )
        self.assertEqual(
            [step["tool"] for step in result["trace"]],
            ["get_process_events", "get_process_events"],
        )
        self.assertEqual(
            {index for index, _ in requested},
            {0, 1},
        )

    def test_failure_in_one_finding_preserves_other(self):
        def decide(context):
            if context["finding_index"] == 0:
                return {
                    "tool": "delete_account",
                    "value": "anything",
                    "reason": "Invalid action",
                }

            return {
                "tool": "finish",
                "value": "",
                "reason": "Reviewed second finding",
            }

        result = run_agent(self.case, decide)

        self.assertEqual(
            result["status"],
            "agent_error",
        )

        self.assertEqual(
            [item["status"] for item in result[
                "finding_investigations"
            ]],
            ["agent_error", "needs_review"],
        )

    def test_multi_finding_report_contains_both_chains(self):
        result = run_agent(
            self.case,
            DemoDecider(),
        )

        report = build_incident_report(
            self.case,
            result,
        )

        self.assertEqual(
            report["finding_count"],
            2,
        )
        self.assertEqual(
            len(report["timeline"]),
            4,
        )

        self.assertEqual(
            len(report["evidence_event_ids"]),
            4,
        )

    def test_old_single_finding_behavior_preserved(self):
        case = create_imported_case(
            self.encoded,
            case_id="IMPORT-SINGLE-TEST",
        )

        result = run_agent(
            case,
            DemoDecider(),
        )

        self.assertEqual(
            result["status"],
            "needs_review",
        )
        self.assertEqual(
            len(result["trace"]),
            2,
        )
        self.assertIn("finish_reason", result)


if __name__ == "__main__":
    unittest.main()