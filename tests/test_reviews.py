import tempfile
import unittest
from pathlib import Path

from sentinel_casework.reviews import list_reviews, save_review
from sentinel_casework.storage import (
    get_investigation,
    save_investigation,
)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db_path = Path(self.directory.name) / "test.db"

        self.saved = save_investigation(
            {
                "case_id": "CASE-001",
                "status": "needs_review",
                "execution_mode": "demo",
                "findings": [],
                "trace": [],
            },
            self.db_path,
        )
        self.investigation_id = self.saved["investigation_id"]

    def test_review_persists_without_changing_investigation(self):
        review = save_review(
            self.investigation_id,
            "needs_more_evidence",
            "  Verify whether the role grant was authorized.  ",
            self.db_path,
        )

        self.assertEqual(
            list_reviews(self.investigation_id, self.db_path),
            [review],
        )
        self.assertEqual(
            review["notes"],
            "Verify whether the role grant was authorized.",
        )
        self.assertEqual(
            get_investigation(self.investigation_id, self.db_path),
            self.saved,
        )

    def test_later_review_preserves_earlier_review(self):
        first = save_review(
            self.investigation_id,
            "needs_more_evidence",
            "Awaiting change approval details.",
            self.db_path,
        )
        second = save_review(
            self.investigation_id,
            "benign",
            "The scenario's change record confirms authorization.",
            self.db_path,
        )

        self.assertNotEqual(first["review_id"], second["review_id"])
        self.assertEqual(
            list_reviews(self.investigation_id, self.db_path),
            [first, second],
        )

    def test_invalid_reviews_are_not_saved(self):
        invalid_inputs = [
            ("unknown", "Some notes"),
            ("suspicious", ""),
            ("benign", "   "),
            ("needs_more_evidence", "x" * 2001),
        ]

        for verdict, notes in invalid_inputs:
            with self.subTest(verdict=verdict, length=len(notes)):
                with self.assertRaises(ValueError):
                    save_review(
                        self.investigation_id,
                        verdict,
                        notes,
                        self.db_path,
                    )

        self.assertEqual(
            list_reviews(self.investigation_id, self.db_path),
            [],
        )

    def test_review_requires_existing_investigation(self):
        with self.assertRaises(LookupError):
            save_review(
                "missing-investigation",
                "suspicious",
                "This investigation does not exist.",
                self.db_path,
            )

    def test_reviews_are_scoped_to_one_investigation(self):
        save_review(
            self.investigation_id,
            "suspicious",
            "The activity requires further investigation.",
            self.db_path,
        )

        other = save_investigation(
            {
                "case_id": "CASE-002",
                "status": "no_detection",
                "execution_mode": "demo",
                "findings": [],
                "trace": [],
            },
            self.db_path,
        )

        self.assertEqual(
            list_reviews(other["investigation_id"], self.db_path),
            [],
        )


if __name__ == "__main__":
    unittest.main()