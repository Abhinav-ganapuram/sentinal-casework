"""Run a read-only investigation using Gemini."""

import argparse
import getpass
import sys
from pathlib import Path

from google import genai
from google.genai import errors

from .agent import run_agent
from .cases import CASE_PATH, load_case
from .gemini_adapter import GeminiDecider


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Investigate a synthetic SOC case with Gemini"
    )
    parser.add_argument("--case", type=Path, default=CASE_PATH)
    parser.add_argument("--model", default="gemini-3.8-flash")
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
        result = run_agent(case, decide, max_steps=3)
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

    print(f"{result['case_id']} | {result['status']}")

    for number, step in enumerate(result["trace"], start=1):
        print(f"{number}. {step['tool']}({step['query']})")
        print(f"   Reason: {step['reason']}")
        print(f"   Events: {', '.join(step['event_ids'])}")

    if "finish_reason" in result:
        print(f"Finished: {result['finish_reason']}")

    if result["status"] == "step_limit":
        print("Step limit reached. Human review is still required.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())