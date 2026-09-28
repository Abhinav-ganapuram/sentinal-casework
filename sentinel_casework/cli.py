"""Replay a case and show its evidence-backed detection findings."""

import argparse
from pathlib import Path

from .cases import CASE_PATH, load_case
from .baseline import investigate_case

def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a synthetic SOC case")
    parser.add_argument("--case", type=Path, default=CASE_PATH, help="Path to a case JSON file")
    args = parser.parse_args()
    case = load_case(args.case)
    print(f"{case['case_id']} | {case['title']}")
    print(f"Subject: {case['subject']} | Events: {len(case['events'])}")
    print("\nTimeline (UTC)")
    for event in case["events"]:
        details = event["details"]
        context = details.get("location") or details.get("role") or details.get("device") or ""
        print(
            f"{event['timestamp']}  {event['id']}  "
            f"{event['action']:<24} {event['outcome']:<8} {context}"
        )

    result = investigate_case(case)
    findings = result["findings"]
    print(f"\nDetection findings: {len(findings)}")
    for finding in findings:
        print(f"{finding['rule_id']} | {finding['severity'].upper()} | {finding['title']}")
        print(f"  Evidence: {', '.join(finding['evidence_ids'])}")
        print(f"  Why: {finding['reason']}")
    
    print(f"\nInvestigation status: {result['status']}")
    for step in result["trace"]:
        print(f"  {step['purpose']}")
        print(f"    Tool: {step['tool']} | Query: {step['query']}")
        print(f"    Events: {', '.join(step['event_ids'])}")

if __name__ == "__main__":
    main()
