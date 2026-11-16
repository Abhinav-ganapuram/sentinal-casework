
# Sentinel Casework — Five-Minute Technical Demo

## Objective

Show how Sentinel correlates identity and endpoint telemetry,
investigates findings with bounded read-only tools, validates
evidence, and supports human review.

Demo mode is preferred. No Gemini API key is required.

## Before the demo

From the project root, start FastAPI:

```powershell
python -m uvicorn sentinel_casework.api:app --reload --port 8000
```

From a second terminal:

```powershell
cd frontend
npm run dev
```

Open http://localhost:5173.

Make sure the following fixtures are available:

- telemetry_samples/sysmon_suspicious_powershell.json
- telemetry_samples/sysmon_office_powershell.json

## 0:00–0:45 — Explain the problem

SOC analysts need to correlate events, investigate suspicious
activity, and produce trustworthy incident evidence.

Sentinel demonstrates a local-first workflow combining
detection engineering, AI-assisted decisions, and human oversight.

## 0:45–1:30 — Demonstrate an identity finding

Open CASE-001.

Show the MFA denial sequence, subsequent approval, and
privileged role grant.

Explain how DET-001 uses user, IP, and timing correlation,
rather than searching for isolated suspicious keywords.

Run a Demo investigation.

## 1:30–2:30 — Demonstrate endpoint investigation

Import sysmon_office_powershell.json.

Run a new Demo investigation.

Show:

- DET-003: Office-spawned PowerShell with network activity
- MITRE ATT&CK technique mapping
- Source evidence IDs
- Correlated process creation and network connection
- Investigation tool trace

Explain that process GUID correlation is stronger than matching
only a username or a PowerShell executable name.

## 2:30–3:15 — Show playbooks and human oversight

Open the SOC investigation playbook.

Explain the difference between:

- Required source evidence
- Lookups actually performed
- Recommended analyst follow-up
- Context not independently verified

Show that the system doesn't automatically perform containment.

## 3:15–4:00 — Demonstrate persistence and reporting

Open the incident report and evidence timeline.

Reopen the saved investigation from history.

Explain that findings, tool decisions, analyst reviews, and
AI-generated narratives serve different purposes.

## 4:00–4:40 — Show engineering quality

From the project root run:

```powershell
python -m unittest discover -s tests -v
python -m sentinel_casework.evaluate
python -m sentinel_casework.endpoint_evaluation
```

Show the GitHub Actions workflow.

Explain that the evaluations use synthetic labeled fixtures,
so their metrics are regression-test results rather than
estimates of production detection performance.

## 4:40–5:00 — Explain tradeoffs

Highlight the security boundaries:

- Evidence-grounded read-only lookups
- Bounded agent execution
- Human review
- No automatic containment
- No production authentication or RBAC

## Optional extended demo

Import a combined Sysmon sample containing both DET-002 and
DET-003 behavior.

Show that both findings can be investigated independently and
retain their own tool traces and playbook requirements.

If Gemini is configured, demonstrate a separate Gemini run.
Do not depend on live model access for the primary demo.

## Interview closing statement

"Sentinel Casework demonstrates how I approach security
automation: deterministic detection, evidence-grounded
investigation, restricted AI tool use, automated regression
testing, and human-controlled incident decisions."