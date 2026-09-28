"""Run approved investigation tools and record their results."""

from .investigation import get_ip_events, get_user_events


TOOLS = {
    "get_user_events": get_user_events,
    "get_ip_events": get_ip_events,
}


def run_lookup(
    events: list[dict], tool_name: str, value: str
) -> tuple[list[dict], dict]:
    """Run an allowed lookup and return its events and trace entry."""
    if tool_name not in TOOLS:
        raise ValueError(f"Unknown investigation tool: {tool_name}")

    results = TOOLS[tool_name](events, value)
    trace = {
        "tool": tool_name,
        "query": value,
        "result_count": len(results),
        "event_ids": [event["id"] for event in results],
    }
    return results, trace