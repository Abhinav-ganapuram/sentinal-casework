
import unittest
from copy import deepcopy

from sentinel_casework.cases import load_case
from sentinel_casework.agent import run_agent
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.report_builder import build_incident_report


class IncidentReportTests(unittest.TestCase):

    def test_suspicious_case_report(self):
        case = load_case()
        result = run_agent(case, DemoDecider())

        report = build_incident_report(case, result)

        self.assertEqual(report["case_id"], "CASE-001")
        self.assertEqual(report["severity"], "high")
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["investigation_step_count"], 2)
        self.assertTrue(report["requires_human_review"])
        self.assertEqual(
            report["generation_method"],
            "deterministic",
        )
        self.assertTrue(report["timeline"])

    def test_report_references_real_events_only(self):
        case = load_case()
        result = run_agent(case, DemoDecider())

        report = build_incident_report(case, result)

        actual_ids = {
            event["id"] for event in case["events"]
        }

        self.assertTrue(
            set(report["evidence_event_ids"]).issubset(actual_ids)
        )

        timestamps = [
            event["timestamp"]
            for event in report["timeline"]
        ]

        self.assertEqual(timestamps, sorted(timestamps))

    def test_invalid_finding_evidence_is_rejected(self):
        case = load_case()
        result = deepcopy(run_agent(case, DemoDecider()))

        result["findings"][0]["evidence_ids"].append(
            "FAKE-EVENT"
        )

        with self.assertRaisesRegex(
            ValueError,
            "Unknown finding evidence",
        ):
            build_incident_report(case, result)

    def test_invalid_tool_evidence_is_rejected(self):
        case = load_case()
        result = deepcopy(run_agent(case, DemoDecider()))

        result["trace"][0]["event_ids"].append(
            "FAKE-EVENT"
        )

        with self.assertRaisesRegex(
            ValueError,
            "Unknown lookup evidence",
        ):
            build_incident_report(case, result)

    def test_benign_case_report(self):
        from sentinel_casework.api import CASE_FILES

        case = load_case(CASE_FILES["CASE-002"])
        result = run_agent(case, DemoDecider())

        report = build_incident_report(case, result)

        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["severity"], "none")
        self.assertEqual(report["timeline"], [])
        self.assertIn(
            "does not prove",
            report["summary"],
        )


if __name__ == "__main__":
    unittest.main()
