
"""Regression tests for evidence-backed SOC playbooks."""

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

from sentinel_casework.api import create_app
from sentinel_casework.cases import load_case
from sentinel_casework.detections import (
    detect_mfa_fatigue_and_privilege_change,
)
from sentinel_casework.endpoint_detections import (
    detect_endpoint_threats,
)
from sentinel_casework.playbooks import build_playbooks
from sentinel_casework.telemetry import (
    create_imported_case,
    load_sysmon_file,
)


ROOT = Path(__file__).resolve().parent.parent


def make_result(case, findings, trace=None):
    return {
        "case_id": case["case_id"],
        "status": (
            "needs_review" if findings else "no_detection"
        ),
        "findings": findings,
        "trace": trace or [],
    }


class PlaybookTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.identity = load_case()

        cls.encoded = load_sysmon_file(
            ROOT
            / "telemetry_samples"
            / "sysmon_suspicious_powershell.json"
        )

        cls.office = load_sysmon_file(
            ROOT
            / "telemetry_samples"
            / "sysmon_office_powershell.json"
        )

    def test_identity_playbook(self):
        findings = detect_mfa_fatigue_and_privilege_change(
            self.identity["events"]
        )

        output = build_playbooks(
            self.identity,
            make_result(self.identity, findings),
        )

        self.assertEqual(len(output), 1)
        self.assertEqual(output[0]["playbook_id"], "PB-001")
        self.assertEqual(
            output[0]["status"],
            "evidence_checked",
        )

        self.assertTrue(all(
            item["satisfied"]
            for item in output[0]["requirements"]
        ))

    def test_encoded_powershell_playbook(self):
        case = create_imported_case(
            self.encoded,
            case_id="IMPORT-PB-002",
        )

        findings = detect_endpoint_threats(case["events"])

        output = build_playbooks(
            case,
            make_result(case, findings),
        )

        self.assertEqual(len(output), 1)
        self.assertEqual(output[0]["playbook_id"], "PB-002")
        self.assertEqual(
            output[0]["status"],
            "evidence_checked",
        )

    def test_office_powershell_playbook(self):
        case = create_imported_case(
            self.office,
            case_id="IMPORT-PB-003",
        )

        findings = detect_endpoint_threats(case["events"])

        output = build_playbooks(
            case,
            make_result(case, findings),
        )

        self.assertEqual(len(output), 1)
        self.assertEqual(output[0]["playbook_id"], "PB-003")
        self.assertEqual(
            output[0]["status"],
            "evidence_checked",
        )

    def test_missing_evidence_is_visible(self):
        case = create_imported_case(
            self.office,
            case_id="IMPORT-PB-MISSING",
        )

        findings = deepcopy(
            detect_endpoint_threats(case["events"])
        )

        # Remove the network event from the cited evidence.
        findings[0]["evidence_ids"] = [
            self.office[0]["id"]
        ]

        output = build_playbooks(
            case,
            make_result(case, findings),
        )

        self.assertEqual(
            output[0]["status"],
            "evidence_incomplete",
        )

        self.assertFalse(all(
            item["satisfied"]
            for item in output[0]["requirements"]
        ))

    def test_unknown_evidence_rejected(self):
        findings = deepcopy(
            detect_mfa_fatigue_and_privilege_change(
                self.identity["events"]
            )
        )

        findings[0]["evidence_ids"].append(
            "INVENTED-EVENT-ID"
        )

        with self.assertRaisesRegex(
            ValueError,
            "unknown evidence",
        ):
            build_playbooks(
                self.identity,
                make_result(self.identity, findings),
            )

    def test_multi_finding_playbooks(self):
        events = self.encoded + self.office

        case = create_imported_case(
            events,
            case_id="IMPORT-PB-MULTI",
        )

        findings = detect_endpoint_threats(case["events"])

        output = build_playbooks(
            case,
            make_result(case, findings),
        )

        self.assertEqual(
            [item["playbook_id"] for item in output],
            ["PB-002", "PB-003"],
        )

    def test_lookups_are_scoped_to_finding(self):
        events = self.encoded + self.office

        case = create_imported_case(
            events,
            case_id="IMPORT-PB-LOOKUPS",
        )

        findings = detect_endpoint_threats(case["events"])

        trace = [
            {
                "tool": "get_process_events",
                "finding_index": 0,
            },
            {
                "tool": "get_user_events",
                "finding_index": 1,
            },
        ]

        output = build_playbooks(
            case,
            make_result(case, findings, trace),
        )

        first, second = output

        first_lookups = {
            item["tool"]: item["executed"]
            for item in first["lookups"]
        }

        second_lookups = {
            item["tool"]: item["executed"]
            for item in second["lookups"]
        }

        self.assertTrue(
            first_lookups["get_process_events"]
        )

        self.assertFalse(
            first_lookups["get_user_events"]
        )

        self.assertTrue(
            second_lookups["get_user_events"]
        )

        self.assertFalse(
            second_lookups["get_process_events"]
        )

    def test_no_findings_no_playbooks(self):
        result = make_result(self.identity, [])

        output = build_playbooks(
            self.identity,
            result,
        )

        self.assertEqual(output, [])

    def test_response_actions_are_never_executed(self):
        findings = detect_mfa_fatigue_and_privilege_change(
            self.identity["events"]
        )

        output = build_playbooks(
            self.identity,
            make_result(self.identity, findings),
        )

        for playbook in output:
            self.assertTrue(
                playbook["requires_human_review"]
            )

            self.assertFalse(
                playbook["response_actions_executed"]
            )

    def test_api_persists_playbooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "casework.sqlite3"

            app = create_app(db_path=db_path)

            with TestClient(app) as client:
                response = client.post(
                    "/cases/CASE-001/investigate",
                    json={"mode": "demo"},
                )

                self.assertEqual(
                    response.status_code,
                    200,
                    response.text,
                )

                result = response.json()

                self.assertEqual(
                    result["playbooks"][0]["playbook_id"],
                    "PB-001",
                )

                investigation_id = result["investigation_id"]

                saved_response = client.get(
                    f"/investigations/{investigation_id}"
                )

                self.assertEqual(
                    saved_response.status_code,
                    200,
                )

                saved = saved_response.json()

                self.assertEqual(
                    saved["playbooks"],
                    result["playbooks"],
                )


if __name__ == "__main__":
    unittest.main()