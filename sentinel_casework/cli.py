"""Print the first investigation case without external dependencies."""

from .cases import load_case


def main() -> None:
    case = load_case()
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


if __name__ == "__main__":
    main()

