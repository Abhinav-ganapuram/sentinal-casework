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
def run_agent(case: dict, decide, max_steps: int = 3) -> dict:
    """Investigate a detected case using bounded, validated tool choices."""
    from .detections import detect_mfa_fatigue_and_privilege_change
    from .tool_runner import run_lookup

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

    for _ in range(max_steps):
        context = {
            "case_id": case["case_id"],
            "finding": findings[0],
            "observations": observations,
        }
        decision = validate_decision(decide(context))

        if decision["tool"] == "finish":
            return {
                "case_id": case["case_id"],
                "status": "needs_review",
                "findings": findings,
                "trace": trace,
                "finish_reason": decision["reason"],
            }

        results, step = run_lookup(
            events, decision["tool"], decision["value"]
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