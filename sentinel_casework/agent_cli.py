"""Run a read-only investigation using Gemini."""

import argparse
import getpass
import sys
from pathlib import Path
from .reporting import save_report
from google import genai
from google.genai import errors
from .demo_adapter import DemoDecider
from .agent import run_agent
from .cases import CASE_PATH, load_case
from .gemini_adapter import GeminiDecider


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Investigate a synthetic SOC case with Gemini"
    )
    parser.add_argument("--case", type=Path, default=CASE_PATH)
    parser.add_argument("--model", default="gemini-3.8-flash")
    parser.add_argument(
        "--output",
        type=Path,
        help="Save the investigation result to a new JSON file",
    )
    parser.add_argument(
        "--mode",
        choices=["live", "demo"],
        default="live",
        help="Use live Gemini decisions or an offline scripted demo",
    )
    args = parser.parse_args()

    client = None
    decider = None

    def decide(context):
        nonlocal client, decider

        if decider is None:
            key = getpass.getpass("Paste Gemini key (hidden): ").strip()
            if not key:
                raise ValueError("A Gemini API key is required.")

            client = genai.Client(api_key=key)
            decider = GeminiDecider(client=client, model=args.model)

        return decider(context)

    try:
        case = load_case(args.case)
        decision_function = DemoDecider() if args.mode == "demo" else decide
        result = run_agent(case, decision_function, max_steps=3)
        result["execution_mode"] = args.mode
        
        if args.output is not None:
            save_report(result, args.output)
    except errors.APIError as error:
        print(f"Gemini API error: {error.code}", file=sys.stderr)
        print(
            "Check your API key, model access, and quota in Google AI Studio.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, OSError) as error:
        print(f"Investigation failed: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nInvestigation cancelled.", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()
    if args.mode == "demo":
        print("Mode: DEMO — scripted decisions; no model calls")
    else:
        print("Mode: LIVE — Gemini decisions when investigation is needed")
    print(f"{result['case_id']} | {result['status']}")

    for number, step in enumerate(result["trace"], start=1):
        print(f"{number}. {step['tool']}({step['query']})")
        print(f"   Reason: {step['reason']}")
        print(f"   Events: {', '.join(step['event_ids'])}")

    if "finish_reason" in result:
        print(f"Finished: {result['finish_reason']}")

    if result["status"] == "step_limit":
        print("Step limit reached. Human review is still required.")

    if args.output is not None:
        print(f"Report saved: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())