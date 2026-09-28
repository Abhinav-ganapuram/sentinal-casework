"""Read-only tools for investigating a case."""

from copy import deepcopy


def get_user_events(
    events: list[dict], user: str, action: str | None = None
) -> list[dict]:
    """Return a user's events, optionally limited to one action."""
    matches = [
        event
        for event in events
        if event["user"] == user
        and (action is None or event["action"] == action)
    ]
    return deepcopy(matches)

def get_ip_events(events: list[dict], ip: str) -> list[dict]:
    """Return events from one source IP without changing the case."""
    if not ip:
        return []

    matches = [
        event for event in events
        if event["details"].get("ip") == ip
    ]
    return deepcopy(matches)