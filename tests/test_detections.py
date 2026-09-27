"""Check that the rule finds the incident and rejects misleading event chains."""

import copy
import unittest
from pathlib import Path

from sentinel_casework.cases import load_case
from sentinel_casework.detections import detect_mfa_fatigue_and_privilege_change


ROOT = Path(__file__).resolve().parent.parent


class DetectionTests(unittest.TestCase):
    def test_incident_points_to_exact_evidence(self):
        events = load_case(ROOT / "cases" / "identity_compromise.json")["events"]
        findings = detect_mfa_fatigue_and_privilege_change(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence_ids"], ["E003", "E004", "E005", "E006", "E008"])

    def test_benign_retries_do_not_trigger(self):
        events = load_case(ROOT / "cases" / "benign_mfa_retry.json")["events"]
        self.assertEqual(detect_mfa_fatigue_and_privilege_change(events), [])

    def test_unrelated_ip_cannot_complete_chain(self):
        events = copy.deepcopy(load_case(ROOT / "cases" / "identity_compromise.json")["events"])
        next(e for e in events if e["id"] == "E008")["details"]["ip"] = "192.0.2.9"
        self.assertEqual(detect_mfa_fatigue_and_privilege_change(events), [])

    def test_grant_after_window_cannot_complete_chain(self):
        events = copy.deepcopy(load_case(ROOT / "cases" / "identity_compromise.json")["events"])
        next(e for e in events if e["id"] == "E008")["timestamp"] = "2026-09-20T09:30:00Z"
        self.assertEqual(detect_mfa_fatigue_and_privilege_change(events), [])

    def test_ordinary_role_does_not_count_as_privilege_change(self):
        events = copy.deepcopy(load_case(ROOT / "cases" / "identity_compromise.json")["events"])
        next(e for e in events if e["id"] == "E008")["details"]["role"] = "Reader"
        self.assertEqual(detect_mfa_fatigue_and_privilege_change(events), [])


if __name__ == "__main__":
    unittest.main()
