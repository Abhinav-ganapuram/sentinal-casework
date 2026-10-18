
import tempfile
import unittest
from pathlib import Path
from time import sleep

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinel_casework.cases import load_case
from sentinel_casework.metrics import (
    MeasuredDecider,
    evaluate_cases,
    run_measured_investigation,
)
from sentinel_casework.metrics_api import create_metrics_router
from sentinel_casework.storage import save_investigation


ROOT = Path(__file__).resolve().parent.parent


class MetricsTests(unittest.TestCase):

    def setUp(self):
        self.suspicious = load_case(
            ROOT / "cases" / "identity_compromise.json"
        )
        self.benign = load_case(
            ROOT / "cases" / "benign_mfa_retry.json"
        )

    def test_labeled_case_evaluation(self):
        result = evaluate_cases([
            self.suspicious,
            self.benign,
        ])

        matrix = result["confusion_matrix"]

        self.assertEqual(result["case_count"], 2)
        self.assertEqual(matrix["tp"], 1)
        self.assertEqual(matrix["tn"], 1)
        self.assertEqual(matrix["fp"], 0)
        self.assertEqual(matrix["fn"], 0)
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["f1_score"], 1.0)

    def test_duplicate_case_ids_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "Duplicate case ID"
        ):
            evaluate_cases([
                self.suspicious,
                self.suspicious,
            ])

    def test_invalid_label_rejected(self):
        case = dict(self.suspicious)
        case["label"] = "unknown"

        with self.assertRaisesRegex(
            ValueError, "needs a suspicious/benign label"
        ):
            evaluate_cases([case])

    def test_empty_evaluation(self):
        result = evaluate_cases([])

        self.assertEqual(result["case_count"], 0)
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])
        self.assertIsNone(result["f1_score"])

    def test_decider_tracks_calls_and_time(self):
        def decision(context):
            sleep(0.005)
            return {
                "tool": "finish",
                "value": "",
                "reason": "Complete",
            }

        measured = MeasuredDecider(decision)
        output = measured({"finding": {}})

        self.assertEqual(output["tool"], "finish")
        self.assertEqual(measured.calls, 1)
        self.assertGreater(measured.duration_seconds, 0)

    def test_measured_investigation(self):
        def finish(context):
            return {
                "tool": "finish",
                "value": "",
                "reason": "No additional lookup needed",
            }

        result = run_measured_investigation(
            self.suspicious,
            finish,
        )

        perf = result["performance"]

        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(perf["decision_count"], 1)
        self.assertEqual(perf["tool_lookup_count"], 0)
        self.assertGreaterEqual(
            perf["total_duration_ms"], 0
        )
        self.assertGreaterEqual(
            perf["decision_duration_ms"], 0
        )

    def test_no_detection_uses_no_ai_calls(self):
        calls = []

        def decision(context):
            calls.append(context)
            raise AssertionError(
                "Decider should not run for benign case"
            )

        result = run_measured_investigation(
            self.benign,
            decision,
        )

        self.assertEqual(result["status"], "no_detection")
        self.assertEqual(
            result["performance"]["decision_count"], 0
        )
        self.assertEqual(calls, [])

    def test_metrics_api_summarizes_saved_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "metrics.db"

            def finish(context):
                return {
                    "tool": "finish",
                    "value": "",
                    "reason": "Ready for analyst review",
                }

            result = run_measured_investigation(
                self.suspicious,
                finish,
            )
            result["execution_mode"] = "demo"

            save_investigation(result, db_path)

            app = FastAPI()
            app.include_router(
                create_metrics_router(db_path)
            )

            with TestClient(app) as client:
                response = client.get(
                    "/metrics/investigations"
                )

            self.assertEqual(response.status_code, 200)

            data = response.json()

            self.assertEqual(data["sample_size"], 1)
            self.assertEqual(
                data["overall"]["run_count"], 1
            )
            self.assertEqual(
                data["by_mode"]["demo"]["run_count"], 1
            )
            self.assertEqual(
                len(data["recent_investigations"]), 1
            )

    def test_legacy_investigations_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "metrics.db"

            save_investigation({
                "case_id": self.suspicious["case_id"],
                "status": "needs_review",
                "findings": [],
                "trace": [],
                "execution_mode": "demo",
            }, db_path)

            app = FastAPI()
            app.include_router(
                create_metrics_router(db_path)
            )

            with TestClient(app) as client:
                response = client.get(
                    "/metrics/investigations"
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.json()["sample_size"], 0
            )


if __name__ == "__main__":
    unittest.main()