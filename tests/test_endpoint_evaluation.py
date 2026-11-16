
"""Regression checks for offline detection-quality evaluation."""

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from sentinel_casework.endpoint_evaluation import (
    build_endpoint_scenarios,
    evaluate_endpoint_scenarios,
    run_endpoint_evaluation,
)


class EndpointEvaluationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenarios = build_endpoint_scenarios()

    def test_unique_scenarios_and_expected_coverage(self):
        names = [
            scenario["name"]
            for scenario in self.scenarios
        ]

        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 15)
        self.assertIn("combined_two_rules", names)

    def test_all_synthetic_labels_match_detections(self):
        result = evaluate_endpoint_scenarios(
            self.scenarios
        )

        self.assertEqual(
            result["scenario_count"],
            len(self.scenarios),
        )

        for rule in ("DET-002", "DET-003"):
            matrix = result["rules"][rule]["confusion_matrix"]

            self.assertEqual(matrix["fp"], 0)
            self.assertEqual(matrix["fn"], 0)
            self.assertGreater(matrix["tp"], 0)
            self.assertGreater(matrix["tn"], 0)

    def test_combined_scenario_detects_both_rules(self):
        result = evaluate_endpoint_scenarios(
            self.scenarios
        )

        item = next(
            row
            for row in result["details"]
            if row["scenario"] == "combined_two_rules"
        )

        self.assertEqual(
            item["detected_rules"],
            ["DET-002", "DET-003"],
        )

    def test_negative_scenarios_remain_negative(self):
        result = evaluate_endpoint_scenarios(
            self.scenarios
        )

        for row in result["details"]:
            if not row["expected_rules"]:
                self.assertEqual(
                    row["detected_rules"],
                    [],
                    row["scenario"],
                )

    def test_duplicate_scenario_rejected(self):
        scenarios = [
            deepcopy(self.scenarios[0]),
            deepcopy(self.scenarios[0]),
        ]

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate evaluation scenario",
        ):
            evaluate_endpoint_scenarios(scenarios)

    def test_duplicate_event_ids_rejected(self):
        scenario = deepcopy(self.scenarios[0])

        scenario["events"][1]["id"] = (
            scenario["events"][0]["id"]
        )

        with self.assertRaisesRegex(
            ValueError,
            "Duplicate event IDs",
        ):
            evaluate_endpoint_scenarios([scenario])

    def test_fabricated_evidence_rejected(self):
        scenario = deepcopy(self.scenarios[0])

        fake_finding = {
            "rule_id": "DET-002",
            "evidence_ids": ["NOT-A-REAL-EVENT"],
        }

        with patch(
            "sentinel_casework.endpoint_evaluation.detect_endpoint_threats",
            return_value=[fake_finding],
        ):
            with self.assertRaisesRegex(
                ValueError,
                "Invalid evidence references",
            ):
                evaluate_endpoint_scenarios([scenario])

    def test_unexpected_rule_label_rejected(self):
        scenario = deepcopy(self.scenarios[0])

        scenario["expected_rules"] = ["DET-999"]

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported or duplicate",
        ):
            evaluate_endpoint_scenarios([scenario])

    def test_report_is_saved_with_scope_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, path = run_endpoint_evaluation(
                Path(tmp) / "endpoint_evaluation.json"
            )

            self.assertTrue(path.exists())

            self.assertEqual(
                result["scenario_count"],
                len(self.scenarios),
            )

            self.assertIn(
                "real-world",
                result["limitations"],
            )


if __name__ == "__main__":
    unittest.main()