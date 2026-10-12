"""Persist investigation results in a local SQLite database."""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "casework.db"


def connect_database(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
        """
    )
    connection.commit()

    return connection


def save_investigation(
    result: dict,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    """Save a new run and return its ID, timestamp, and result."""
    result_json = json.dumps(result, ensure_ascii=False)
    investigation_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    with closing(connect_database(db_path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO investigations (
                    investigation_id, case_id, created_at, result_json
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    result["case_id"],
                    created_at,
                    result_json,
                ),
            )

    return {
        "investigation_id": investigation_id,
        "created_at": created_at,
        "result": json.loads(result_json),
    }


def get_investigation(
    investigation_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict | None:
    """Load a saved run, or return None if the ID does not exist."""
    with closing(connect_database(db_path)) as connection:
        row = connection.execute(
            """
            SELECT investigation_id, created_at, result_json
            FROM investigations
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "investigation_id": row["investigation_id"],
        "created_at": row["created_at"],
        "result": json.loads(row["result_json"]),
    }
def list_investigations(
    case_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict]:
    """Return summaries of the latest 50 investigations for a case."""
    with closing(connect_database(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT investigation_id, case_id, created_at, result_json
            FROM investigations
            WHERE case_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 50
            """,
            (case_id,),
        ).fetchall()

    summaries = []

    for row in rows:
        result = json.loads(row["result_json"])
        summaries.append({
            "investigation_id": row["investigation_id"],
            "case_id": row["case_id"],
            "created_at": row["created_at"],
            "status": result["status"],
            "execution_mode": result["execution_mode"],
            "finding_count": len(result["findings"]),
        })

    return summaries