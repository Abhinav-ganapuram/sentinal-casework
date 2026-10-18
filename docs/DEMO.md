
# Sentinel Casework — Interview Demonstration

## Objective

Demonstrate an evidence-first SOC investigation, including
detection engineering, AI-assisted investigation, validated reports,
human review, and evaluation.

Target walkthrough: approximately 7–10 minutes.

## 1. Introduce the problem

SOC analysts investigate multiple alerts across identity and audit
systems. Events need to be correlated, evidence must remain
traceable, and investigation outcomes must be reviewed.

Sentinel explores how bounded AI tool selection can assist this
workflow without giving an AI agent autonomous response authority.

## 2. Demonstrate detection

Open CASE-001.

Show the sequence:

- Repeated MFA denials
- Successful MFA approval
- Privileged role assignment
- Detection finding referencing actual event IDs

Explain the role of temporal correlation and shared user/IP context.

## 3. Demonstrate automated investigation

Select Demo mode.

Run the investigation and show:

- Individual tool requests
- Returned events
- Decision trace
- Investigation status

Explain why investigation tools are read-only and validated.

## 4. Demonstrate AI functionality

If Gemini access is available, select Gemini mode on a new run.

Explain that Gemini selects the next bounded lookup and receives
the observations returned by Python.

Explain that Gemini does not directly query a database or perform
account containment.

If Gemini is unavailable, show a previously saved Gemini
investigation and explain the same workflow.

## 5. Show evidence-grounded reports

Open the deterministic incident report.

Highlight:

- Event IDs
- Chronological evidence timeline
- Detection summary
- Uncertainty and limitations
- Recommended analyst investigation actions

Explain that the report builder rejects non-existent evidence IDs.

## 6. Show AI narrative

Open a saved AI narrative or generate one if available.

Highlight:

- Executive summary
- Evidence-cited observations
- Potential security implications
- Missing evidence and uncertainty
- Recommended next steps

Explain that citation existence is checked, but full factual
correctness still requires analyst review.

## 7. Demonstrate human review

Submit an analyst verdict and notes.

Reopen the saved investigation and show that the review persists
without modifying the original investigation result.

Explain why human verdicts and AI outputs are separate records.

## 8. Demonstrate evaluation

Run:

    python -m sentinel_casework.evaluate

Show the confusion matrix, precision, recall, and F1 score.

Explain the difference between a regression test dataset and an
independent production evaluation dataset.

## 9. Demonstrate performance metrics

Open the performance dashboard.

Compare:

- Demo and Gemini execution modes
- Investigation duration
- Decision-provider duration
- Number of decisions
- Number of tool lookups

Explain the latency cost of sequential model calls.

## 10. Discuss limitations and next steps

Acknowledge:

- Synthetic telemetry only
- Limited detection coverage
- No authenticated analyst identities
- No automated containment
- Need for broader evaluation datasets
- Need for production security hardening

## Closing statement

Sentinel Casework combines detection engineering, evidence validation,
AI-assisted tool orchestration, persistent investigation history,
human review, and measurable evaluation.

Its central design choice is keeping AI useful without treating
AI-generated decisions as verified security facts.