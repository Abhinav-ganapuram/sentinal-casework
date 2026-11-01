
"""Persistent storage for imported security telemetry cases."""

import json
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .storage import DEFAULT_DB_PATH, connect_database


def _connect_imports(db_path: Path):
    connection = connect_database(db_path)

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS imported_cases (
            case_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            filename TEXT NOT NULL,
            case_json TEXT NOT NULL
        )
        """
    )
    connection.commit()

    return connection


def save_imported_case(
    case: dict,
    filename: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    """Persist a new imported case with a generated case ID."""

    case_id = f"IMPORT-{uuid4().hex[:12].upper()}"
    created_at = datetime.now(timezone.utc).isoformat()

    stored_case = {
        **case,
        "case_id": case_id,
        "source_type": "sysmon_import",
        "created_at": created_at,
    }

    with closing(_connect_imports(db_path)) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO imported_cases (
                    case_id,
                    created_at,
                    filename,
                    case_json
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    case_id,
                    created_at,
                    filename,
                    json.dumps(
                        stored_case,
                        ensure_ascii=False,
                    ),
                ),
            )

    return stored_case


def get_imported_case(
    case_id: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict | None:
    """Retrieve an imported case by ID."""

    with closing(_connect_imports(db_path)) as connection:
        row = connection.execute(
            """
            SELECT case_json
            FROM imported_cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

    if row is None:
        return None

    return json.loads(row["case_json"])


def list_imported_cases(
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict]:
    """Return imported cases for the dashboard."""

    with closing(_connect_imports(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT case_id, filename, created_at, case_json
            FROM imported_cases
            ORDER BY created_at DESC, rowid DESC
            """
        ).fetchall()

    cases = []

    for row in rows:
        case = json.loads(row["case_json"])

        cases.append({
            "case_id": row["case_id"],
            "title": case["title"],
            "event_count": len(case["events"]),
            "source_type": "sysmon_import",
            "filename": row["filename"],
            "created_at": row["created_at"],
        })

    return cases