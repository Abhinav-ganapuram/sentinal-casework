
"""Deterministic, evidence-backed SOC investigation playbooks.

Playbooks inspect existing evidence and agent traces.
They do not execute endpoint commands or containment actions.
"""

import re
from datetime import datetime

from .detections import PRIVILEGED_ROLES
from .endpoint_detections import OFFICE_PARENTS, POWERSHELL


PLAYBOOKS = {
    "DET-001": {
        "id": "PB-001",
        "name": "Identity compromise investigation",
        "requirements": (
            ("mfa_denials", "At least three denied MFA pushes"),
            ("mfa_approval", "MFA approval after the denials"),
            ("privilege_grant", "Privileged role grant after approval"),
        ),
        "lookups": ("get_user_events", "get_ip_events"),
        "analyst_actions": (
            "Confirm MFA activity with the account owner using an independent channel.",
            "Check the privileged role assignment against an approved change.",
            "Review sign-in sessions and identity alerts before escalation.",
        ),
        "context_to_verify": (
            "Whether the account owner authorized the MFA approval",
            "Change approval for the privileged role",
            "Sign-in device and session context outside this case",
        ),
    },
    "DET-002": {
        "id": "PB-002",
        "name": "Encoded PowerShell investigation",
        "requirements": (
            ("encoded_powershell", "Encoded PowerShell command execution"),
            ("network_connection", "Same-process network connection within five minutes"),
        ),
        "lookups": (
            "get_process_events",
            "get_user_events",
            "get_ip_events",
        ),
        "analyst_actions": (
            "Inspect and safely decode the command without executing it.",
            "Review the process tree and related network events.",
            "Verify command purpose and network destination ownership.",
        ),
        "context_to_verify": (
            "Intent of the encoded command",
            "Destination reputation and ownership",
            "Complete endpoint process tree",
        ),
    },
    "DET-003": {
        "id": "PB-003",
        "name": "Office-to-PowerShell investigation",
        "requirements": (
            ("office_parent", "Microsoft Office parent launched PowerShell"),
            ("network_connection", "Same-process network connection within five minutes"),
        ),
        "lookups": (
            "get_process_events",
            "get_user_events",
            "get_ip_events",
        ),
        "analyst_actions": (
            "Verify the Office parent-child process relationship.",
            "Inspect PowerShell arguments and related process activity.",
            "Review document provenance and authorized automation context.",
        ),
        "context_to_verify": (
            "Document provenance and user interaction",
            "Script or document reputation",
            "Complete endpoint process tree",
        ),
    },
}


ENCODED_OPTION = re.compile(
    r"(?i)(?:^|\s)-(?:encodedcommand|enc|e)(?=\s|:|$)"
)


def _timestamp(event):
    """Parse a normalized event timestamp."""

    return datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )


def _executable(path):
    """Extract an executable name from a Windows path."""

    return (
        str(path or "")
        .replace("/", "\\")
        .split("\\")[-1]
        .lower()
    )


def _requirements(rule_id, evidence):
    """Validate behavioral requirements using cited source events."""

    if rule_id == "DET-001":
        approvals = [
            e for e in evidence
            if e["action"] == "mfa_push"
            and e["outcome"] == "approved"
        ]

        denials = [
            e for e in evidence
            if e["action"] == "mfa_push"
            and e["outcome"] == "denied"
        ]

        grants = [
            e for e in evidence
            if e["action"] == "role_granted"
            and e["outcome"] == "success"
            and e.get("details", {}).get("role") in PRIVILEGED_ROLES
        ]

        valid_denials = False
        valid_approvals = False
        valid_grants = False

        for approval in approvals:
            ip = approval.get("details", {}).get("ip")

            if not ip:
                continue

            matching_denials = [
                e for e in denials
                if e["user"] == approval["user"]
                and e.get("details", {}).get("ip") == ip
                and 0 < (
                    _timestamp(approval) - _timestamp(e)
                ).total_seconds() <= 300
            ]

            if len(matching_denials) >= 3:
                valid_denials = True
                valid_approvals = True

                if any(
                    e["user"] == approval["user"]
                    and e.get("details", {}).get("ip") == ip
                    and 0 < (
                        _timestamp(e) - _timestamp(approval)
                    ).total_seconds() <= 600
                    for e in grants
                ):
                    valid_grants = True

        return {
            "mfa_denials": valid_denials,
            "mfa_approval": valid_approvals,
            "privilege_grant": valid_grants,
        }

    processes = [
        e for e in evidence
        if e.get("source") == "sysmon"
        and e["action"] == "process_created"
        and _executable(
            e.get("details", {}).get("image")
        ) in POWERSHELL
    ]

    connections = [
        e for e in evidence
        if e.get("source") == "sysmon"
        and e["action"] == "network_connection"
    ]

    valid_pairs = []

    for process in processes:
        guid = process.get("details", {}).get("process_guid")

        if not guid:
            continue

        for connection in connections:
            details = connection.get("details", {})

            if (
                connection.get("user") == process.get("user")
                and details.get("process_guid") == guid
                and details.get("destination_ip")
                and (
                    details.get("source_ip")
                    or details.get("ip")
                )
                and 0 <= (
                    _timestamp(connection) - _timestamp(process)
                ).total_seconds() <= 300
            ):
                valid_pairs.append((process, connection))

    if rule_id == "DET-002":
        return {
            "encoded_powershell": any(
                ENCODED_OPTION.search(
                    str(
                        process["details"].get(
                            "command_line", ""
                        )
                    )
                )
                for process, _ in valid_pairs
            ),
            "network_connection": bool(valid_pairs),
        }

    return {
        "office_parent": any(
            _executable(
                process["details"].get("parent_image")
            ) in OFFICE_PARENTS
            for process, _ in valid_pairs
        ),
        "network_connection": bool(valid_pairs),
    }


def build_playbooks(case: dict, result: dict) -> list[dict]:
    """Build advisory playbooks for supported investigation findings."""

    events = case["events"]
    by_id = {event["id"]: event for event in events}

    if len(by_id) != len(events):
        raise ValueError("Duplicate source event IDs")

    findings = result.get("findings", [])
    trace = result.get("trace", [])
    outcomes = result.get("finding_investigations", [])

    output = []

    for index, finding in enumerate(findings):
        rule_id = finding.get("rule_id")
        template = PLAYBOOKS.get(rule_id)

        if template is None:
            continue

        evidence_ids = finding.get("evidence_ids", [])

        if (
            not isinstance(evidence_ids, list)
            or any(
                event_id not in by_id
                for event_id in evidence_ids
            )
        ):
            raise ValueError(
                "Playbook finding references unknown evidence"
            )

        cited_events = [
            by_id[event_id]
            for event_id in dict.fromkeys(evidence_ids)
        ]

        checks = _requirements(rule_id, cited_events)

        requirements = [
            {
                "key": key,
                "label": label,
                "satisfied": checks[key],
            }
            for key, label in template["requirements"]
        ]

        # Multi-finding traces are scoped by finding_index.
        # Legacy single-finding traces may omit that field.
        related_steps = [
            step for step in trace
            if step.get("finding_index", 0) == index
            and (
                len(findings) == 1
                or "finding_index" in step
            )
        ]

        lookups = [
            {
                "tool": tool,
                "executed": any(
                    step.get("tool") == tool
                    for step in related_steps
                ),
            }
            for tool in template["lookups"]
        ]

        finding_status = (
            outcomes[index].get("status", result.get("status"))
            if index < len(outcomes)
            else result.get("status")
        )

        all_evidence_present = all(
            item["satisfied"]
            for item in requirements
        )

        output.append({
            "playbook_id": template["id"],
            "rule_id": rule_id,
            "finding_index": index,
            "name": template["name"],
            "status": (
                "evidence_checked"
                if all_evidence_present
                else "evidence_incomplete"
            ),
            "investigation_status": finding_status,
            "requirements": requirements,
            "lookups": lookups,
            "evidence_event_ids": list(
                dict.fromkeys(evidence_ids)
            ),
            "analyst_actions": list(
                template["analyst_actions"]
            ),
            "context_to_verify": list(
                template["context_to_verify"]
            ),
            "requires_human_review": True,
            "response_actions_executed": False,
        })

    return output