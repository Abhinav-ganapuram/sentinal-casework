
"""Bounded, evidence-validated investigation agent."""

from .tool_runner import TOOLS


MAX_FINDINGS_PER_RUN = 10


def validate_decision(decision: dict) -> dict:
    """Validate the proposed action against the tool allowlist."""

    if not isinstance(decision, dict):
        raise ValueError("Decision must be an object")

    tool = decision.get("tool")
    value = decision.get("value")
    reason = decision.get("reason")

    if not isinstance(tool, str) or tool not in {
        *TOOLS,
        "finish",
    }:
        raise ValueError(f"Tool is not allowed: {tool}")

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Decision needs a reason")

    if tool != "finish" and (
        not isinstance(value, str) or not value.strip()
    ):
        raise ValueError("Lookup needs a value")

    return {
        "tool": tool,
        "value": value.strip() if tool != "finish" else "",
        "reason": reason.strip(),
    }


def validate_investigation_step(
    decision: dict,
    events: list[dict],
    trace: list[dict],
) -> dict:
    """Validate identifiers and reject repeated lookups."""

    decision = validate_decision(decision)

    if decision["tool"] == "finish":
        return decision

    tool = decision["tool"]
    value = decision["value"]

    if tool == "get_user_events":
        allowed_values = {
            event["user"]
            for event in events
        }

    elif tool == "get_ip_events":
        allowed_values = {
            ip
            for event in events
            for ip in (
                event["details"].get("ip"),
                event["details"].get("source_ip"),
            )
            if isinstance(ip, str) and ip
        }

    elif tool == "get_process_events":
        allowed_values = {
            event.get("details", {}).get("process_guid")
            for event in events
            if event.get("source") == "sysmon"
            and event.get("details", {}).get("process_guid")
        }

    else:
        raise ValueError("Unsupported investigation tool")

    if value not in allowed_values:
        raise ValueError(
            "Lookup identifier is not present in case evidence: "
            f"{value}"
        )

    if any(
        step["tool"] == tool
        and step["query"] == value
        for step in trace
    ):
        raise ValueError(
            f"Repeated investigation lookup: {tool}({value})"
        )

    return decision


def _finding_process_guids(
    finding: dict,
    events: list[dict],
) -> list[str]:
    """Identify process GUIDs referenced by this finding."""

    evidence_ids = set(finding.get("evidence_ids", []))

    return sorted({
        event["details"]["process_guid"]
        for event in events
        if event["id"] in evidence_ids
        and event.get("source") == "sysmon"
        and event.get("details", {}).get("process_guid")
    })


def _investigate_finding(
    case_id: str,
    finding: dict,
    finding_index: int,
    finding_count: int,
    events: list[dict],
    decide,
    max_steps: int,
) -> dict:
    """Investigate one finding with its own bounded decision loop."""

    from .tool_runner import run_lookup

    trace = []
    observations = []

    for step_number in range(1, max_steps + 1):
        context = {
            "case_id": case_id,
            "finding": finding,
            "finding_index": finding_index,
            "finding_count": finding_count,
            "process_guids": _finding_process_guids(
                finding, events
            ),
            "observations": observations,
        }

        try:
            proposed = decide(context)

            decision = validate_investigation_step(
                proposed,
                events,
                trace,
            )

        except ValueError as error:
            return {
                "status": "agent_error",
                "trace": trace,
                "error": {
                    "type": "invalid_decision",
                    "message": str(error),
                    "step": step_number,
                },
            }

        if decision["tool"] == "finish":
            return {
                "status": "needs_review",
                "trace": trace,
                "finish_reason": decision["reason"],
            }

        results, step = run_lookup(
            events,
            decision["tool"],
            decision["value"],
        )

        step["reason"] = decision["reason"]
        step["finding_index"] = finding_index
        step["rule_id"] = finding.get("rule_id")

        trace.append(step)

        observations.append({
            "tool": decision["tool"],
            "query": decision["value"],
            "events": results,
        })

    return {
        "status": "step_limit",
        "trace": trace,
    }


def run_agent(
    case: dict,
    decide,
    max_steps: int = 3,
) -> dict:
    """Investigate all detected findings within bounded limits."""

    from .detections import (
        detect_mfa_fatigue_and_privilege_change,
    )
    from .endpoint_detections import detect_endpoint_threats

    if (
        not isinstance(max_steps, int)
        or isinstance(max_steps, bool)
        or max_steps < 1
    ):
        raise ValueError(
            "max_steps must be a positive integer"
        )

    events = case["events"]

    findings = (
        detect_mfa_fatigue_and_privilege_change(events)
        + detect_endpoint_threats(events)
    )

    if not findings:
        return {
            "case_id": case["case_id"],
            "status": "no_detection",
            "findings": [],
            "trace": [],
            "finding_investigations": [],
            "investigated_finding_count": 0,
            "uninvestigated_finding_count": 0,
        }

    combined_trace = []
    finding_investigations = []

    selected_findings = findings[:MAX_FINDINGS_PER_RUN]

    for index, finding in enumerate(selected_findings):
        outcome = _investigate_finding(
            case_id=case["case_id"],
            finding=finding,
            finding_index=index,
            finding_count=len(findings),
            events=events,
            decide=decide,
            max_steps=max_steps,
        )

        combined_trace.extend(outcome["trace"])

        record = {
            "finding_index": index,
            "rule_id": finding.get("rule_id"),
            "status": outcome["status"],
            "trace_step_count": len(outcome["trace"]),
        }

        if "finish_reason" in outcome:
            record["finish_reason"] = outcome["finish_reason"]

        if "error" in outcome:
            record["error"] = outcome["error"]

        finding_investigations.append(record)

    uninvestigated_count = (
        len(findings) - len(selected_findings)
    )

    statuses = {
        item["status"]
        for item in finding_investigations
    }

    if "agent_error" in statuses:
        overall_status = "agent_error"
    elif "step_limit" in statuses or uninvestigated_count:
        overall_status = "step_limit"
    else:
        overall_status = "needs_review"

    result = {
        "case_id": case["case_id"],
        "status": overall_status,
        "findings": findings,
        "trace": combined_trace,
        "finding_investigations": finding_investigations,
        "investigated_finding_count": len(
            selected_findings
        ),
        "uninvestigated_finding_count": uninvestigated_count,
    }

    # Maintain the existing single-finding result contract.
    if len(findings) == 1:
        only = finding_investigations[0]

        if "finish_reason" in only:
            result["finish_reason"] = only["finish_reason"]

        if "error" in only:
            result["error"] = only["error"]

    return result