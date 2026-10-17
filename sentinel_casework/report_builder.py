
"""Build evidence-grounded SOC incident reports."""

from datetime import datetime


def build_incident_report(case: dict, result: dict) -> dict:
    """Create a report referencing only real source events."""

    events = case["events"]
    event_by_id = {event["id"]: event for event in events}

    if len(event_by_id) != len(events):
        raise ValueError("Duplicate event IDs in case")

    findings = result["findings"]
    trace = result["trace"]

    referenced_ids = set()

    for finding in findings:
        for event_id in finding["evidence_ids"]:
            if event_id not in event_by_id:
                raise ValueError(
                    f"Unknown finding evidence: {event_id}"
                )
            referenced_ids.add(event_id)

    for step in trace:
        for event_id in step["event_ids"]:
            if event_id not in event_by_id:
                raise ValueError(
                    f"Unknown lookup evidence: {event_id}"
                )
            referenced_ids.add(event_id)

    timeline = []

    for event in events:
        if event["id"] not in referenced_ids:
            continue

        timeline.append({
            "event_id": event["id"],
            "timestamp": event["timestamp"],
            "user": event["user"],
            "action": event["action"],
            "outcome": event["outcome"],
            "source": event["source"],
            "source_ip": event["details"].get("ip"),
        })

    timeline.sort(
        key=lambda event: datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
    )

    status = result["status"]

    if not findings:
        summary = (
            "No configured detection rule matched this case. "
            "This does not prove that the activity is benign."
        )
        severity = "none"
    else:
        severity_order = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        severity = max(
            (finding["severity"] for finding in findings),
            key=lambda value: severity_order.get(value, 0),
        )

        summary = " ".join(
            f"{finding['title']}: {finding['reason']}"
            for finding in findings
        )

    recommendations = []

    if findings:
        recommendations = [
            "Verify the affected identity and authentication activity.",
            "Review the source IP and associated sessions.",
            "Confirm whether any privileged role changes were authorized.",
            "Escalate suspicious findings for analyst review.",
        ]

    limitations = [
        "The report uses only events available in this case.",
        "A detection finding is not proof of compromise.",
        "Recommended actions are not automatically executed.",
    ]

    if status == "agent_error":
        limitations.append(
            "The AI investigation stopped before completing."
        )
    elif status == "step_limit":
        limitations.append(
            "The investigation reached its configured step limit."
        )

    return {
        "case_id": case["case_id"],
        "title": case["title"],
        "status": status,
        "severity": severity,
        "summary": summary,
        "finding_count": len(findings),
        "investigation_step_count": len(trace),
        "evidence_event_ids": [
            event["event_id"] for event in timeline
        ],
        "timeline": timeline,
        "recommendations": recommendations,
        "limitations": limitations,
        "generation_method": "deterministic",
        "requires_human_review": True,
    }