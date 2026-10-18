
"""Persist generated narratives without changing investigations."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from .storage import DEFAULT_DB_PATH, connect_database


def connect_narratives(db_path: Path):
    connection = connect_database(db_path)
    connection.execute("PRAGMA foreign_keys = ON")

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS narratives (
            investigation_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            narrative_json TEXT NOT NULL,
            FOREIGN KEY (investigation_id)
                REFERENCES investigations(investigation_id)
        )
        """
    )
    connection.commit()
    return connection


def get_narrative(
    investigation_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict | None:
    with closing(connect_narratives(db_path)) as connection:
        row = connection.execute(
            """
            SELECT investigation_id, created_at, narrative_json
            FROM narratives
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "investigation_id": row["investigation_id"],
        "created_at": row["created_at"],
        "narrative": json.loads(row["narrative_json"]),
    }


def save_narrative(
    investigation_id: str,
    narrative: dict,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    created_at = datetime.now(timezone.utc).isoformat()

    with closing(connect_narratives(db_path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO narratives (
                    investigation_id, created_at, narrative_json
                )
                VALUES (?, ?, ?)
                """,
                (
                    investigation_id,
                    created_at,
                    json.dumps(narrative, ensure_ascii=False),
                ),
            )

    # An existing narrative is preserved rather than overwritten.
    return get_narrative(investigation_id, db_path)
