"""A fixed investigation sequence used as a baseline for the agent."""

from .detections import detect_mfa_fatigue_and_privilege_change
from .tool_runner import run_lookup


def investigate_case(case: dict) -> dict:
    """Detect findings and record follow-up lookups."""
    events = case["events"]
    findings = detect_mfa_fatigue_and_privilege_change(events)
    trace = []

    for finding in findings:
        _, user_step = run_lookup(
            events, "get_user_events", finding["user"]
        )
        user_step["purpose"] = "Review activity by the affected user"
        trace.append(user_step)

        _, ip_step = run_lookup(
            events, "get_ip_events", finding["source_ip"]
        )
        ip_step["purpose"] = "Check other activity from the source IP"
        trace.append(ip_step)

    return {
        "case_id": case["case_id"],
        "status": "needs_review" if findings else "no_detection",
        "findings": findings,
        "trace": trace,
    }