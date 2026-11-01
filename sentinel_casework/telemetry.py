
"""Normalize exported Sysmon JSON and JSONL security events."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_EVENTS = 5000

SUPPORTED_EVENTS = {
    1: "process_created",
    3: "network_connection",
    11: "file_created",
}


class TelemetryError(ValueError):
    """Invalid or unsupported telemetry input."""


def _utc_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise TelemetryError("Missing event timestamp")

    value = value.strip()

    # Sysmon UtcTime often uses a space instead of T,
    # with UTC implied by the field's definition.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as error:
        raise TelemetryError(
            "Invalid event timestamp"
        ) from error

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(
        timezone.utc
    ).isoformat().replace("+00:00", "Z")


def _event_data(record):
    if not isinstance(record, dict):
        raise TelemetryError("Each event must be an object")

    # Accept either flat exports or common EventData wrappers.
    event_data = record.get(
        "EventData",
        record.get("event_data", record),
    )

    if not isinstance(event_data, dict):
        raise TelemetryError("EventData must be an object")

    return event_data


def _event_id(record):
    system = record.get("System", {})
    if not isinstance(system, dict):
        raise TelemetryError("System must be an object")

    value = (
        record.get("EventID")
        or record.get("EventId")
        or record.get("event_id")
        or system.get("EventID")
    )

    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise TelemetryError(
            "Missing or invalid Sysmon EventID"
        ) from error


def normalize_sysmon_event(record, position=0):
    """Convert one Sysmon export into a Sentinel event."""

    if not isinstance(record, dict):
        raise TelemetryError("Each event must be an object")

    event_id = _event_id(record)

    if event_id not in SUPPORTED_EVENTS:
        raise TelemetryError(
            f"Unsupported Sysmon EventID: {event_id}"
        )

    data = _event_data(record)

    timestamp = _utc_timestamp(
        data.get("UtcTime")
        or record.get("timestamp")
        or record.get("TimeCreated")
    )

    user = data.get("User") or "unknown"
    if not isinstance(user, str):
        raise TelemetryError("User must be a string")

    image = data.get("Image")
    process_guid = data.get("ProcessGuid")

    if event_id in (1, 3, 11):
        if not isinstance(image, str) or not image:
            raise TelemetryError(
                f"Sysmon EventID {event_id} needs Image"
            )

    if event_id == 1:
        details = {
            "image": image,
            "command_line": data.get("CommandLine"),
            "parent_image": data.get("ParentImage"),
            "process_guid": process_guid,
            "process_id": data.get("ProcessId"),
        }

    elif event_id == 3:
        destination_ip = data.get("DestinationIp")

        if not destination_ip:
            raise TelemetryError(
                "Network event needs DestinationIp"
            )

        details = {
            "image": image,
            "process_guid": process_guid,
            "ip": data.get("SourceIp"),
            "source_ip": data.get("SourceIp"),
            "destination_ip": destination_ip,
            "destination_port": data.get(
                "DestinationPort"
            ),
            "protocol": data.get("Protocol"),
        }

    else:
        target = data.get("TargetFilename")

        if not isinstance(target, str) or not target:
            raise TelemetryError(
                "File creation event needs TargetFilename"
            )

        details = {
            "image": image,
            "process_guid": process_guid,
            "target_filename": target,
        }

    # Remove optional fields that have no value.
    details = {
        key: value
        for key, value in details.items()
        if value is not None
    }

    # Keep the original record for evidence provenance.
    details["sysmon_event_id"] = event_id
    details["raw_event"] = record

    canonical = json.dumps(
        record,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        f"{position}:{canonical}".encode("utf-8")
    ).hexdigest()[:16]

    return {
        "id": f"SYSMON-{digest}",
        "timestamp": timestamp,
        "source": "sysmon",
        "action": SUPPORTED_EVENTS[event_id],
        "outcome": "observed",
        "user": user,
        "details": details,
    }


def parse_sysmon_text(content, filename="events.json"):
    """Parse a JSON array or a JSONL export."""

    if not isinstance(content, str):
        raise TelemetryError("Input must be text")

    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        raise TelemetryError("Telemetry file exceeds 5 MB")

    if filename.lower().endswith(".jsonl"):
        try:
            records = [
                json.loads(line)
                for line in content.splitlines()
                if line.strip()
            ]
        except json.JSONDecodeError as error:
            raise TelemetryError(
                "Invalid JSONL record"
            ) from error

    elif filename.lower().endswith(".json"):
        try:
            records = json.loads(content)
        except json.JSONDecodeError as error:
            raise TelemetryError(
                "Invalid JSON input"
            ) from error

    else:
        raise TelemetryError(
            "Only .json and .jsonl exports are supported"
        )

    if not isinstance(records, list) or not records:
        raise TelemetryError(
            "Telemetry must contain a non-empty event list"
        )

    if len(records) > MAX_EVENTS:
        raise TelemetryError(
            f"Telemetry exceeds {MAX_EVENTS} events"
        )

    events = [
        normalize_sysmon_event(record, position)
        for position, record in enumerate(records)
    ]

    events.sort(key=lambda event: event["timestamp"])

    return events


def load_sysmon_file(path):
    """Read and normalize a local export file."""

    path = Path(path)

    if path.stat().st_size > MAX_FILE_BYTES:
        raise TelemetryError("Telemetry file exceeds 5 MB")

    content = path.read_text(encoding="utf-8")

    return parse_sysmon_text(
        content,
        filename=path.name,
    )


def create_imported_case(
    events,
    case_id="IMPORT-001",
    title="Imported Sysmon telemetry",
):
    """Create a case compatible with Sentinel's case model."""

    if not events:
        raise TelemetryError("Cannot create an empty case")

    ids = [event["id"] for event in events]
    if len(ids) != len(set(ids)):
        raise TelemetryError("Duplicate normalized event IDs")

    return {
        "case_id": case_id,
        "title": title,
        "subject": "imported-endpoint-telemetry",
        "scenario": "Imported Sysmon events",
        "label": "unlabeled",
        "events": events,
    }