"""Store analyst reviews separately from investigation results."""

import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .storage import DEFAULT_DB_PATH, connect_database


ALLOWED_VERDICTS = {
    "suspicious",
    "benign",
    "needs_more_evidence",
}


def connect_reviews(db_path: Path) -> sqlite3.Connection:
    connection = connect_database(db_path)
    connection.execute("PRAGMA foreign_keys = ON")

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS reviews (
            review_id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            verdict TEXT NOT NULL CHECK (
                verdict IN ('suspicious', 'benign', 'needs_more_evidence')
            ),
            notes TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id)
                REFERENCES investigations(investigation_id)
        )
        """
    )
    connection.commit()

    return connection


def save_review(
    investigation_id: str,
    verdict: str,
    notes: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    """Append a review without modifying the saved investigation."""
    if verdict not in ALLOWED_VERDICTS:
        raise ValueError("Unsupported review verdict")

    if not isinstance(notes, str) or not notes.strip():
        raise ValueError("Review notes are required")

    notes = notes.strip()

    if len(notes) > 2000:
        raise ValueError("Review notes must be at most 2000 characters")

    review = {
        "review_id": str(uuid4()),
        "investigation_id": investigation_id,
        "verdict": verdict,
        "notes": notes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with closing(connect_reviews(db_path)) as connection:
        with connection:
            investigation = connection.execute(
                """
                SELECT investigation_id
                FROM investigations
                WHERE investigation_id = ?
                """,
                (investigation_id,),
            ).fetchone()

            if investigation is None:
                raise LookupError("Investigation not found")

            connection.execute(
                """
                INSERT INTO reviews (
                    review_id, investigation_id, verdict, notes, created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    review["review_id"],
                    review["investigation_id"],
                    review["verdict"],
                    review["notes"],
                    review["created_at"],
                ),
            )

    return review


def list_reviews(
    investigation_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict]:
    """Return reviews in chronological order."""
    with closing(connect_reviews(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT review_id, investigation_id, verdict, notes, created_at
            FROM reviews
            WHERE investigation_id = ?
            ORDER BY created_at ASC, rowid ASC
            """,
            (investigation_id,),
        ).fetchall()

    return [dict(row) for row in rows]