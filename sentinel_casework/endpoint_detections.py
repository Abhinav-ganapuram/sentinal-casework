
"""Deterministic detection rules for normalized Sysmon events."""

import re
from datetime import datetime, timedelta


ENCODED_COMMAND = re.compile(
    r"(?i)(?:^|\s)-(?:encodedcommand|enc|e)(?=\s|:|$)"
)

POWERSHELL = {"powershell.exe", "pwsh.exe"}

OFFICE_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
}


def _timestamp(event):
    return datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )


def _executable(path):
    if not isinstance(path, str):
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()


def _is_powershell(event):
    return _executable(
        event.get("details", {}).get("image")
    ) in POWERSHELL


def _matching_connections(process, events):
    """Find outbound connections from the same process."""

    details = process.get("details", {})
    guid = details.get("process_guid")

    if not guid:
        return []

    start = _timestamp(process)
    end = start + timedelta(minutes=5)

    return [
        event
        for event in events
        if event.get("source") == "sysmon"
        and event.get("action") == "network_connection"
        and event.get("user") == process.get("user")
        and event.get("details", {}).get("process_guid") == guid
        and event.get("details", {}).get("destination_ip")
        and (
            event.get("details", {}).get("source_ip")
            or event.get("details", {}).get("ip")
        )
        and start <= _timestamp(event) <= end
    ]


def _make_finding(
    process,
    connections,
    rule_id,
    title,
    reason,
    techniques,
):
    connection = connections[0]
    details = connection["details"]

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": "high",
        "user": process["user"],
        "source_ip": (
            details.get("source_ip") or details.get("ip")
        ),
        "evidence_ids": [
            process["id"],
            *[event["id"] for event in connections],
        ],
        "mitre_attack": techniques[0],
        "mitre_techniques": techniques,
        "reason": reason,
    }


def detect_encoded_powershell_network(events):
    """DET-002: Encoded PowerShell followed by network activity."""

    findings = []
    ordered = sorted(events, key=_timestamp)

    for process in ordered:
        if (
            process.get("source") != "sysmon"
            or process.get("action") != "process_created"
            or not _is_powershell(process)
        ):
            continue

        command = process.get("details", {}).get(
            "command_line", ""
        )

        if (
            not isinstance(command, str)
            or not ENCODED_COMMAND.search(command)
        ):
            continue

        connections = _matching_connections(
            process, ordered
        )

        if connections:
            findings.append(
                _make_finding(
                    process,
                    connections,
                    "DET-002",
                    "Encoded PowerShell with network activity",
                    (
                        "A PowerShell process used an encoded-command "
                        "option and made a network connection within "
                        "five minutes. Investigate the command and "
                        "the destination before drawing conclusions."
                    ),
                    [{
                        "technique_id": "T1059.001",
                        "technique": "PowerShell",
                        "tactic": "Execution",
                    }],
                )
            )

    return findings


def detect_office_powershell_network(events):
    """
    DET-003: An Office process launches PowerShell, which then
    initiates a network connection within five minutes.

    This is suspicious behavior, not proof of compromise.
    """

    findings = []
    ordered = sorted(events, key=_timestamp)

    for process in ordered:
        if (
            process.get("source") != "sysmon"
            or process.get("action") != "process_created"
            or not _is_powershell(process)
        ):
            continue

        details = process.get("details", {})
        parent = _executable(details.get("parent_image"))

        if parent not in OFFICE_PARENTS:
            continue

        connections = _matching_connections(
            process, ordered
        )

        if not connections:
            continue

        findings.append(
            _make_finding(
                process,
                connections,
                "DET-003",
                "Office-spawned PowerShell with network activity",
                (
                    "A Microsoft Office process launched PowerShell, "
                    "and the same PowerShell process made a network "
                    "connection within five minutes. This can "
                    "indicate suspicious document-driven execution, "
                    "but requires analyst verification."
                ),
                [
                    {
                        "technique_id": "T1204.002",
                        "technique": "Malicious File",
                        "tactic": "Execution",
                    },
                    {
                        "technique_id": "T1059.001",
                        "technique": "PowerShell",
                        "tactic": "Execution",
                    },
                ],
            )
        )

    return findings


def detect_endpoint_threats(events):
    """Run all endpoint detection rules."""

    return (
        detect_encoded_powershell_network(events)
        + detect_office_powershell_network(events)
    )
