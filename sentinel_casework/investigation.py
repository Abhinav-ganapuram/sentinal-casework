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