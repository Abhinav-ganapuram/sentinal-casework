"""Deterministic detections; each finding points to the events that caused it."""

from datetime import datetime, timedelta

PRIVILEGED_ROLES = {"SecurityAdministrator", "GlobalAdministrator"}


def _time(event: dict) -> datetime:
    return datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))


def detect_mfa_fatigue_and_privilege_change(events: list[dict]) -> list[dict]:
    """Find 3+ denied pushes, approval, then role grant for one user and IP.

    Denials must occur within five minutes before the approval. The grant must
    follow the approval within ten minutes. All matching events must have the
    same user and IP. This is a triage signal, not proof of compromise.
    """
    findings = []
    ordered = sorted(events, key=_time)
    approvals = [e for e in ordered if e["action"] == "mfa_push" and e["outcome"] == "approved"]

    for approval in approvals:
        approved_at = _time(approval)
        ip = approval["details"].get("ip")
        if not ip:
            continue
        denials = [
            e for e in ordered
            if e["action"] == "mfa_push"
            and e["outcome"] == "denied"
            and e["user"] == approval["user"]
            and e["details"].get("ip") == ip
            and approved_at - timedelta(minutes=5) <= _time(e) < approved_at
        ]
        if len(denials) < 3:
            continue

        grants = [
            e for e in ordered
            if e["action"] == "role_granted"
            and e["outcome"] == "success"
            and e["details"].get("role") in PRIVILEGED_ROLES
            and e["user"] == approval["user"]
            and e["details"].get("ip") == ip
            and approved_at < _time(e) <= approved_at + timedelta(minutes=10)
        ]
        for grant in grants:
            findings.append({
                "rule_id": "DET-001",
                "title": "MFA fatigue followed by privilege change",
                "severity": "high",
                "user": approval["user"],
                "source_ip": ip,
                "evidence_ids": [e["id"] for e in denials] + [approval["id"], grant["id"]],
                "reason": (
                    f"{len(denials)} denied MFA pushes preceded an approval from the same "
                    "user and IP; a privileged role was granted within 10 minutes."
                ),
            })
    return findings
