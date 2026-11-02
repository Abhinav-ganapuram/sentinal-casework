
"""Regression tests for Sysmon endpoint detection engineering."""

import unittest
from copy import deepcopy
from pathlib import Path

from sentinel_casework.agent import run_agent
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.endpoint_detections import (
    detect_endpoint_threats,
)
from sentinel_casework.report_builder import build_incident_report
from sentinel_casework.telemetry import (
    create_imported_case,
    load_sysmon_file,
)


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "telemetry_samples"


class EndpointDetectionTests(unittest.TestCase):

    def setUp(self):
        self.suspicious = load_sysmon_file(
            SAMPLES / "sysmon_suspicious_powershell.json"
        )

        self.benign = load_sysmon_file(
            SAMPLES / "sysmon_demo.json"
        )

    def test_suspicious_powershell_detected(self):
        findings = detect_endpoint_threats(
            self.suspicious
        )

        self.assertEqual(len(findings), 1)

        finding = findings[0]

        self.assertEqual(
            finding["rule_id"],
            "DET-002",
        )

        self.assertEqual(
            finding["severity"],
            "high",
        )

        self.assertEqual(
            finding["mitre_attack"]["technique_id"],
            "T1059.001",
        )

    def test_benign_powershell_not_detected(self):
        findings = detect_endpoint_threats(
            self.benign
        )

        self.assertEqual(findings, [])

    def test_evidence_references_actual_events(self):
        findings = detect_endpoint_threats(
            self.suspicious
        )

        known_ids = {
            event["id"]
            for event in self.suspicious
        }

        evidence_ids = set(
            findings[0]["evidence_ids"]
        )

        self.assertTrue(
            evidence_ids.issubset(known_ids)
        )

        self.assertEqual(len(evidence_ids), 2)

    def test_different_process_guid_not_detected(self):
        events = deepcopy(self.suspicious)

        events[1]["details"]["process_guid"] = (
            "{different-process-guid}"
        )

        self.assertEqual(
            detect_endpoint_threats(events),
            [],
        )

    def test_different_user_not_detected(self):
        events = deepcopy(self.suspicious)

        events[1]["user"] = "LAB\\another-user"

        self.assertEqual(
            detect_endpoint_threats(events),
            [],
        )

    def test_network_before_process_not_detected(self):
        events = deepcopy(self.suspicious)

        events[1]["timestamp"] = (
            "2026-10-20T10:59:59Z"
        )

        self.assertEqual(
            detect_endpoint_threats(events),
            [],
        )

    def test_network_after_window_not_detected(self):
        events = deepcopy(self.suspicious)

        events[1]["timestamp"] = (
            "2026-10-20T11:05:01Z"
        )

        self.assertEqual(
            detect_endpoint_threats(events),
            [],
        )

    def test_network_at_window_boundary_detected(self):
        events = deepcopy(self.suspicious)

        events[1]["timestamp"] = (
            "2026-10-20T11:05:00Z"
        )

        self.assertEqual(
            len(detect_endpoint_threats(events)),
            1,
        )

    def test_missing_source_ip_not_detected(self):
        events = deepcopy(self.suspicious)

        events[1]["details"].pop("source_ip", None)
        events[1]["details"].pop("ip", None)

        self.assertEqual(
            detect_endpoint_threats(events),
            [],
        )

    def test_normalized_events_supported_by_agent(self):
        case = create_imported_case(
            self.suspicious,
            case_id="IMPORT-TEST",
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
            result["findings"][0]["rule_id"],
            "DET-002",
        )

        self.assertEqual(
            len(result["trace"]),
            2,
        )

        report = build_incident_report(
            case,
            result,
        )

        self.assertEqual(
            report["finding_count"],
            1,
        )

        self.assertTrue(
            report["timeline"],
        )


if __name__ == "__main__":
    unittest.main()