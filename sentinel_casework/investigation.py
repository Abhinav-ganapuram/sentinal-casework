
"""Read-only evidence lookup tools for SOC investigations."""

from copy import deepcopy


def get_user_events(
    events: list[dict],
    user: str,
    action: str | None = None,
) -> list[dict]:
    """Return events for a user, optionally filtered by action."""

    return deepcopy([
        event
        for event in events
        if event["user"] == user
        and (action is None or event["action"] == action)
    ])


def get_ip_events(
    events: list[dict],
    ip: str,
) -> list[dict]:
    """Find events associated with a source IP."""

    if not ip:
        return []

    return deepcopy([
        event
        for event in events
        if event["details"].get("ip") == ip
        or event["details"].get("source_ip") == ip
    ])


def get_process_events(
    events: list[dict],
    process_guid: str,
) -> list[dict]:
    """Find Sysmon events belonging to one process GUID."""

    if not process_guid:
        return []

    return deepcopy([
        event
        for event in events
        if event.get("source") == "sysmon"
        and event.get("details", {}).get("process_guid")
        == process_guid
    ])