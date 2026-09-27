# Sentinel Casework

An evidence-first, agent-assisted SOC investigation console. This repository is
built in small working steps. The first step is a replayable, synthetic identity
security case that runs with Python's standard library and requires no VM.

## Step 1: replay an incident

Requirements: Python 3.10 or newer.

```bash
python -m sentinel_casework.cli
```

On Windows, `py -m sentinel_casework.cli` works if `python` is unavailable.
Run the command from the repository root. You should see a case summary and a
chronological event timeline. No API key, cloud account, or package installation
is needed at this stage.

## What the case represents

`cases/identity_compromise.json` contains fictional security events for a
single identity. Repeated MFA denials, a successful approval, and a subsequent
privilege change form the starting point for our investigation. An event alone
does not establish malicious intent: later steps will add detections, evidence
collection, analyst review, and a safe simulated response.

## Planned build stages

1. Replayable case and validated event loader (current step).
2. Detection rules and a benign comparison case.
3. Read-only investigation tools and an agent with a recorded tool trace.
4. Analyst approval and simulated response actions.
5. Web case queue, timeline, evidence view, and report.
6. Evaluation, documentation, and demo video.

All events in this repo are synthetic. Do not add employer data, internal rules,
credentials, or private incident information.

