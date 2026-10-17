"""Validate an agent's proposed next step before executing it."""

from .tool_runner import TOOLS


def validate_decision(decision: dict) -> dict:
    """Accept an approved lookup or a decision to finish."""
    if not isinstance(decision, dict):
        raise ValueError("Decision must be an object")

    tool = decision.get("tool")
    value = decision.get("value")
    reason = decision.get("reason")

    if not isinstance(tool, str) or tool not in {*TOOLS, "finish"}:
        raise ValueError(f"Tool is not allowed: {tool}")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Decision needs a reason")
    if tool != "finish" and (not isinstance(value, str) or not value.strip()):
        raise ValueError("Lookup needs a value")

    return {
        "tool": tool,
        "value": value if tool != "finish" else "",
        "reason": reason.strip(),
    }

def validate_investigation_step(
    decision: dict,
    events: list[dict],
    trace: list[dict],
) -> dict:
    """Validate a proposed lookup against available evidence and history."""
    decision = validate_decision(decision)

    if decision["tool"] == "finish":
        return decision

    tool = decision["tool"]
    value = decision["value"].strip()

    if tool == "get_user_events":
        allowed_values = {
            event["user"] for event in events
        }
    elif tool == "get_ip_events":
        allowed_values = {
            event["details"].get("ip")
            for event in events
            if event["details"].get("ip")
        }
    else:
        raise ValueError("Unsupported investigation tool")

    if value not in allowed_values:
        raise ValueError(
            f"Lookup identifier is not present in case evidence: {value}"
        )

    if any(
        step["tool"] == tool and step["query"] == value
        for step in trace
    ):
        raise ValueError(
            f"Repeated investigation lookup: {tool}({value})"
        )

    return {
        **decision,
        "value": value,
    }


def run_agent(case: dict, decide, max_steps: int = 3) -> dict:
    """Investigate a case with bounded, validated agent decisions."""
    from .detections import detect_mfa_fatigue_and_privilege_change
    from .tool_runner import run_lookup

    if not isinstance(max_steps, int) or isinstance(max_steps, bool) or max_steps < 1:
        raise ValueError("max_steps must be a positive integer")

    events = case["events"]
    findings = detect_mfa_fatigue_and_privilege_change(events)
    trace = []
    observations = []

    if not findings:
        return {
            "case_id": case["case_id"],
            "status": "no_detection",
            "findings": [],
            "trace": [],
        }

    for step_number in range(1, max_steps + 1):
        context = {
            "case_id": case["case_id"],
            "finding": findings[0],
            "observations": observations,
        }

        try:
            proposed_decision = decide(context)

            decision = validate_investigation_step(
                proposed_decision,
                events,
                trace,
            )

        except ValueError as error:
            return {
                "case_id": case["case_id"],
                "status": "agent_error",
                "findings": findings,
                "trace": trace,
                "error": {
                    "type": "invalid_decision",
                    "message": str(error),
                    "step": step_number,
                },
            }

        if decision["tool"] == "finish":
            return {
                "case_id": case["case_id"],
                "status": "needs_review",
                "findings": findings,
                "trace": trace,
                "finish_reason": decision["reason"],
            }

        results, step = run_lookup(
            events,
            decision["tool"],
            decision["value"],
        )

        step["reason"] = decision["reason"]
        trace.append(step)

        observations.append({
            "tool": decision["tool"],
            "events": results,
        })

    return {
        "case_id": case["case_id"],
        "status": "step_limit",
        "findings": findings,
        "trace": trace,
    }
