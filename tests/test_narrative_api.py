
import tempfile
import unittest
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinel_casework.agent import run_agent
from sentinel_casework.cases import load_case
from sentinel_casework.demo_adapter import DemoDecider
from sentinel_casework.narrative_api import create_narrative_router
from sentinel_casework.report_builder import build_incident_report
from sentinel_casework.storage import save_investigation


class NarrativeAPITests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "narratives.db"

        # Create a real demo investigation.
        case = load_case()
        result = run_agent(case, DemoDecider())

        result["execution_mode"] = "demo"
        result["report"] = build_incident_report(
            case,
            result,
        )

        # Save the investigation to a temporary database.
        saved = save_investigation(
            result,
            self.db_path,
        )

        self.investigation_id = saved["investigation_id"]

        # Track how many times the AI generator is called.
        self.calls = 0

        # Mock Gemini generation to avoid API requests.
        def generator(report):
            self.calls += 1

            return {
                "executive_summary": (
                    "Suspicious authentication activity detected."
                ),
                "observations": [
                    {
                        "statement": (
                            "An authentication event was observed."
                        ),
                        "event_ids": [
                            report["evidence_event_ids"][0]
                        ],
                    }
                ],
                "implications": [
                    "Potential identity security risk"
                ],
                "uncertainties": [
                    "Account compromise remains unconfirmed"
                ],
                "next_steps": [
                    "Review the affected account activity"
                ],
            }

        # Create an isolated FastAPI application.
        app = FastAPI()

        app.include_router(
            create_narrative_router(
                self.db_path,
                generator_factory=lambda: generator,
            )
        )

        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        self.temp.cleanup()

    def test_generate_and_retrieve_narrative(self):
        url = (
            f"/investigations/"
            f"{self.investigation_id}/narrative"
        )

        # Generate the AI narrative.
        created = self.client.post(url)

        self.assertEqual(
            created.status_code,
            200,
        )

        created_data = created.json()

        self.assertIn(
            "narrative",
            created_data,
        )

        self.assertEqual(
            created_data["narrative"]["generation_method"],
            "gemini",
        )

        self.assertTrue(
            created_data["narrative"]["requires_human_review"]
        )

        # Retrieve the same narrative from storage.
        loaded = self.client.get(url)

        self.assertEqual(
            loaded.status_code,
            200,
        )

        self.assertEqual(
            created.json(),
            loaded.json(),
        )

        self.assertEqual(
            self.calls,
            1,
        )

    def test_repeated_generation_uses_saved_result(self):
        url = (
            f"/investigations/"
            f"{self.investigation_id}/narrative"
        )

        first = self.client.post(url)
        second = self.client.post(url)

        self.assertEqual(
            first.status_code,
            200,
        )

        self.assertEqual(
            second.status_code,
            200,
        )

        # Gemini should be called only once.
        self.assertEqual(
            self.calls,
            1,
        )

        self.assertEqual(
            first.json(),
            second.json(),
        )

    def test_unknown_investigation_returns_404(self):
        response = self.client.post(
            "/investigations/unknown/narrative"
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_invalid_ai_evidence_is_not_saved(self):

        # Mock a narrative containing a fabricated event ID.
        def bad_generator(report):
            return {
                "executive_summary": (
                    "Unverified activity was detected."
                ),
                "observations": [
                    {
                        "statement": (
                            "This event does not exist."
                        ),
                        "event_ids": [
                            "FAKE-EVENT"
                        ],
                    }
                ],
                "implications": [],
                "uncertainties": [],
                "next_steps": [],
            }

        app = FastAPI()

        app.include_router(
            create_narrative_router(
                self.db_path,
                generator_factory=lambda: bad_generator,
            )
        )

        url = (
            f"/investigations/"
            f"{self.investigation_id}/narrative"
        )

        with TestClient(app) as client:
            response = client.post(url)
            saved = client.get(url)

        # Invalid AI output must be rejected.
        self.assertEqual(
            response.status_code,
            422,
        )

        # Invalid output must not be persisted.
        self.assertEqual(
            saved.status_code,
            404,
        )


if __name__ == "__main__":
    unittest.main()
