
"""Tests for Office-to-PowerShell endpoint detection."""

import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sentinel_casework.agent import run_agent
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.report_builder import build_incident_report
from sentinel_casework.telemetry import create_imported_case
from sentinel_casework.endpoint_detections import (
    detect_endpoint_threats,
    detect_office_powershell_network,
)
from sentinel_casework.telemetry import load_sysmon_file


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (
    ROOT / "telemetry_samples" / "sysmon_office_powershell.json"
)


class OfficeDetectionTests(unittest.TestCase):
    def test_office_detection_investigation_and_report(self):
        case = create_imported_case(
            self.events,
            case_id="IMPORT-OFFICE-TEST",
        )

        result = run_agent(case, DemoDecider())

        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["findings"][0]["rule_id"], "DET-003")
        self.assertEqual(len(result["trace"]), 2)

        report = build_incident_report(case, result)

        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(len(report["timeline"]), 2)
    def setUp(self):
        self.events = load_sysmon_file(SAMPLE)

    def test_detects_office_powershell_chain(self):
        findings = detect_office_powershell_network(
            self.events
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "DET-003")
        self.assertEqual(findings[0]["severity"], "high")

    def test_mitre_mapping(self):
        finding = detect_office_powershell_network(
            self.events
        )[0]

        ids = {
            item["technique_id"]
            for item in finding["mitre_techniques"]
        }

        self.assertEqual(
            ids,
            {"T1204.002", "T1059.001"},
        )

    def test_evidence_ids_exist(self):
        finding = detect_office_powershell_network(
            self.events
        )[0]

        known = {event["id"] for event in self.events}

        self.assertEqual(
            set(finding["evidence_ids"]),
            known,
        )

    def test_normal_office_activity_not_detected(self):
        events = deepcopy(self.events)

        events[0]["details"]["image"] = (
            r"C:\Program Files\Microsoft Office\WINWORD.EXE"
        )

        events[0]["details"]["parent_image"] = (
            r"C:\Windows\explorer.exe"
        )

        self.assertEqual(
            detect_office_powershell_network(events),
            [],
        )

    def test_powershell_from_explorer_not_detected(self):
        events = deepcopy(self.events)

        events[0]["details"]["parent_image"] = (
            r"C:\Windows\explorer.exe"
        )

        self.assertEqual(
            detect_office_powershell_network(events),
            [],
        )

    def test_different_process_not_detected(self):
        events = deepcopy(self.events)
        events[1]["details"]["process_guid"] = (
            "{unrelated-guid}"
        )

        self.assertEqual(
            detect_office_powershell_network(events),
            [],
        )

    def test_different_user_not_detected(self):
        events = deepcopy(self.events)
        events[1]["user"] = r"LAB\other-user"

        self.assertEqual(
            detect_office_powershell_network(events),
            [],
        )

    def test_outside_five_minute_window(self):
        events = deepcopy(self.events)

        events[1]["timestamp"] = (
            "2026-10-21T10:05:01Z"
        )

        self.assertEqual(
            detect_office_powershell_network(events),
            [],
        )

    def test_both_rules_remain_available(self):
        findings = detect_endpoint_threats(self.events)

        self.assertEqual(
            [item["rule_id"] for item in findings],
            ["DET-003"],
        )

    def test_encoded_powershell_still_works(self):
        path = (
            ROOT
            / "telemetry_samples"
            / "sysmon_suspicious_powershell.json"
        )

        events = load_sysmon_file(path)
        findings = detect_endpoint_threats(events)

        self.assertIn(
            "DET-002",
            [item["rule_id"] for item in findings],
        )


if __name__ == "__main__":
    unittest.main()