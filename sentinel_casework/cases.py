"""Load and validate synthetic cases before using them in an investigation."""

import json
from datetime import datetime
from pathlib import Path


CASE_PATH = Path(__file__).resolve().parent.parent / "cases" / "identity_compromise.json"
REQUIRED_EVENT_FIELDS = {"id", "timestamp", "source", "action", "outcome", "user", "details"}


def load_case(path: Path = CASE_PATH) -> dict:
    """Return a validated case with events sorted from oldest to newest."""
    case = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(case, dict) or not {"case_id", "title", "events"} <= case.keys():
        raise ValueError("Case must contain case_id, title, and events")
    if not isinstance(case["events"], list) or not case["events"]:
        raise ValueError("Case must contain at least one event")

    seen_ids = set()
    for event in case["events"]:
        if not isinstance(event, dict) or not REQUIRED_EVENT_FIELDS <= event.keys():
            raise ValueError("Every event must contain the required fields")
        if event["id"] in seen_ids:
            raise ValueError(f"Duplicate event ID: {event['id']}")
        seen_ids.add(event["id"])
        timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError(f"Timestamp needs a timezone: {event['id']}")

    case["events"].sort(key=lambda event: event["timestamp"])
    return case

