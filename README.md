# Sentinel Casework

An evidence-first, agent-assisted SOC investigation console. This repository is
built in small working steps. It now has two replayable identity cases and an
evidence-backed detection rule. It runs with Python's standard library and no VM.

## Replay the cases

Requirements: Python 3.10 or newer.

```bash
python -m sentinel_casework.cli
python -m sentinel_casework.cli --case cases/benign_mfa_retry.json
python -m unittest discover -s tests -v
```

On Windows, replace `python` with `py` if needed. Run commands from the
repository root. The first case produces one high-severity finding; the benign
case produces zero findings. No API key, cloud account, or package installation
is needed.

## What the case represents

`cases/identity_compromise.json` contains fictional security events for one
identity. `cases/benign_mfa_retry.json` contains denied prompts without an
approval or privilege change. `sentinel_casework/detections.py` requires at
least three MFA denials from the same user and IP within five minutes before
an approval, followed by a role grant within ten minutes from that same user
and IP. Privileged roles are explicitly listed in the rule. Each finding cites
exact event IDs. The `label` in case fixtures is
for evaluation; the rule never reads it. A finding warrants analyst review
and does not establish malicious intent by itself.

## Planned build stages

1. Replayable case and validated event loader (complete).
2. Detection rule and a benign comparison case (complete).
3. Read-only investigation tools and an agent with a recorded tool trace.
4. Analyst approval and simulated response actions.
5. Web case queue, timeline, evidence view, and report.
6. Evaluation, documentation, and demo video.

All events in this repo are synthetic. Do not add employer data, internal rules,
credentials, or private incident information.
