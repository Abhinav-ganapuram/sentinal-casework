
"""Execute allowlisted, read-only SOC investigation tools."""

from .investigation import (
    get_user_events,
    get_ip_events,
    get_process_events,
)


# Only these read-only investigation tools are permitted.
TOOLS = {
    "get_user_events": get_user_events,
    "get_ip_events": get_ip_events,
    "get_process_events": get_process_events,
}


def run_lookup(
    events: list[dict],
    tool_name: str,
    value: str,
) -> tuple[list[dict], dict]:
    """
    Execute an approved lookup and return its observations
    together with an evidence-backed trace entry.
    """

    if tool_name not in TOOLS:
        raise ValueError(
            f"Unknown investigation tool: {tool_name}"
        )

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "Lookup value must be a non-empty string"
        )

    results = TOOLS[tool_name](
        events,
        value,
    )

    trace = {
        "tool": tool_name,
        "query": value,
        "result_count": len(results),
        "event_ids": [
            event["id"]
            for event in results
        ],
    }

    return results, trace