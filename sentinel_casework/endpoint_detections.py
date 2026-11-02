
"""Deterministic endpoint detections from normalized Sysmon telemetry."""

import re
from datetime import datetime, timedelta


ENCODED_COMMAND = re.compile(
    r"(?i)(?:^|\s)-(?:encodedcommand|enc|e)(?=\s|:|$)"
)

POWERSHELL_EXECUTABLES = {
    "powershell.exe",
    "pwsh.exe",
}


def _timestamp(event):
    return datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )


def _is_powershell(event):
    image = event.get("details", {}).get("image", "")
    if not isinstance(image, str):
        return False

    executable = image.replace("/", "\\").split("\\")[-1].lower()
    return executable in POWERSHELL_EXECUTABLES


def detect_encoded_powershell_network(events):
    """
    Detect PowerShell encoded-command execution followed by
    a network connection from the same process within five minutes.

    This is a triage signal, not confirmed compromise.
    """

    findings = []
    ordered = sorted(events, key=_timestamp)

    processes = [
        event for event in ordered
        if event.get("source") == "sysmon"
        and event.get("action") == "process_created"
        and _is_powershell(event)
    ]

    connections = [
        event for event in ordered
        if event.get("source") == "sysmon"
        and event.get("action") == "network_connection"
    ]

    for process in processes:
        details = process["details"]
        command_line = details.get("command_line", "")

        if not isinstance(command_line, str):
            continue

        if not ENCODED_COMMAND.search(command_line):
            continue

        process_guid = details.get("process_guid")

        if not process_guid:
            continue

        created_at = _timestamp(process)

        matches = [
            connection
            for connection in connections
            if connection["details"].get("process_guid")
            == process_guid
            and connection.get("user") == process["user"]
            and created_at <= _timestamp(connection)
            <= created_at + timedelta(minutes=5)
            and connection["details"].get("destination_ip")
        ]

        if not matches:
            continue

        first_connection = matches[0]
        source_ip = (
            first_connection["details"].get("source_ip")
            or first_connection["details"].get("ip")
        )

        # Keep existing read-only IP lookups compatible.
        # The Demo agent needs an actual source IP in evidence.
        if not source_ip:
            continue

        evidence_ids = [
            process["id"],
            *[connection["id"] for connection in matches],
        ]

        findings.append({
            "rule_id": "DET-002",
            "title": (
                "Encoded PowerShell execution with network activity"
            ),
            "severity": "high",
            "user": process["user"],
            "source_ip": source_ip,
            "evidence_ids": evidence_ids,
            "mitre_attack": {
                "technique_id": "T1059.001",
                "technique": "PowerShell",
                "tactic": "Execution",
            },
            "reason": (
                "PowerShell started with an encoded-command "
                "option and the same process initiated network "
                "activity within five minutes. "
                "The activity requires analyst investigation."
            ),
        })

    return findings


def detect_endpoint_threats(events):
    """Run all configured endpoint detection rules."""
    findings = []
    findings.extend(
        detect_encoded_powershell_network(events)
    )
    return findings