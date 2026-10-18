
"""Regression tests for synthetic SOC evaluation scenarios."""

import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from sentinel_casework.api import CASE_FILES, create_app
from sentinel_casework.cases import load_case
from sentinel_casework.detections import (
    detect_mfa_fatigue_and_privilege_change,
)
from sentinel_casework.metrics import evaluate_cases
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.agent import run_agent


EXPECTED_LABELS = {
    "CASE-001": "suspicious",
    "CASE-002": "benign",
    "CASE-003": "suspicious",
    "CASE-004": "suspicious",
    "CASE-005": "benign",
    "CASE-006": "benign",
}


class ScenarioTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cases = {
            case_id: load_case(path)
            for case_id, path in CASE_FILES.items()
        }

    def test_all_six_cases_are_registered(self):
        self.assertEqual(
            set(self.cases),
            set(EXPECTED_LABELS),
        )

    def test_case_ids_match_filenames_registry(self):
        for case_id, case in self.cases.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    case["case_id"],
                    case_id,
                )

    def test_each_case_has_expected_label(self):
        for case_id, case in self.cases.items():
            with self.subTest(case_id=case_id):
                self.assertEqual(
                    case["label"],
                    EXPECTED_LABELS[case_id],
                )

    def test_detection_matches_scenario_labels(self):
        for case_id, case in self.cases.items():
            with self.subTest(case_id=case_id):
                findings = (
                    detect_mfa_fatigue_and_privilege_change(
                        case["events"]
                    )
                )

                if case["label"] == "suspicious":
                    self.assertTrue(
                        findings,
                        f"Missing detection for {case_id}",
                    )
                else:
                    self.assertEqual(
                        findings,
                        [],
                        f"Unexpected detection for {case_id}",
                    )

    def test_evidence_ids_are_real(self):
        for case_id, case in self.cases.items():
            with self.subTest(case_id=case_id):
                valid_ids = {
                    event["id"]
                    for event in case["events"]
                }

                findings = (
                    detect_mfa_fatigue_and_privilege_change(
                        case["events"]
                    )
                )

                for finding in findings:
                    self.assertTrue(
                        set(finding["evidence_ids"])
                        <= valid_ids
                    )

                    self.assertEqual(
                        len(finding["evidence_ids"]),
                        len(set(finding["evidence_ids"])),
                    )

    def test_evaluation_confusion_matrix(self):
        result = evaluate_cases(
            list(self.cases.values())
        )

        self.assertEqual(result["case_count"], 6)

        self.assertEqual(
            result["confusion_matrix"],
            {
                "tp": 3,
                "fp": 0,
                "tn": 3,
                "fn": 0,
            },
        )

        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["f1_score"], 1.0)

    def test_demo_investigation_on_new_cases(self):
        for case_id in (
            "CASE-003",
            "CASE-004",
            "CASE-005",
            "CASE-006",
        ):
            with self.subTest(case_id=case_id):
                result = run_agent(
                    self.cases[case_id],
                    DemoDecider(),
                )

                if EXPECTED_LABELS[case_id] == "suspicious":
                    self.assertEqual(
                        result["status"],
                        "needs_review",
                    )
                    self.assertEqual(
                        len(result["trace"]),
                        2,
                    )
                else:
                    self.assertEqual(
                        result["status"],
                        "no_detection",
                    )
                    self.assertEqual(
                        result["trace"],
                        [],
                    )

    def test_new_cases_available_through_api(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "scenarios.db"

            with TestClient(create_app(db_path)) as client:
                response = client.get("/cases")

                self.assertEqual(
                    response.status_code,
                    200,
                )

                returned_ids = {
                    item["case_id"]
                    for item in response.json()
                }

                self.assertEqual(
                    returned_ids,
                    set(EXPECTED_LABELS),
                )

                for case_id in (
                    "CASE-003",
                    "CASE-004",
                    "CASE-005",
                    "CASE-006",
                ):
                    with self.subTest(case_id=case_id):
                        detail = client.get(
                            f"/cases/{case_id}"
                        )

                        self.assertEqual(
                            detail.status_code,
                            200,
                        )


if __name__ == "__main__":
    unittest.main()