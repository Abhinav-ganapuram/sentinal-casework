
"""Evaluate Sentinel's detection rule on labeled cases."""

import json
from pathlib import Path

from .cases import load_case
from .metrics import evaluate_cases


ROOT = Path(__file__).resolve().parent.parent
CASE_DIRECTORY = ROOT / "cases"
OUTPUT_DIRECTORY = ROOT / "data"


def run_evaluation():
    cases = []

    for path in sorted(CASE_DIRECTORY.glob("*.json")):
        case = load_case(path)

        # Only explicitly labeled cases are evaluation examples.
        if case.get("label") in {"suspicious", "benign"}:
            cases.append(case)

    if not cases:
        raise ValueError("No labeled evaluation cases found")

    result = evaluate_cases(cases)

    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path = OUTPUT_DIRECTORY / "evaluation.json"

    output_path.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8",
    )

    return result, output_path


def main():
    result, path = run_evaluation()

    print("\nSENTINEL CASEWORK — DETECTION EVALUATION")
    print("=" * 48)

    print(f"Cases evaluated : {result['case_count']}")

    matrix = result["confusion_matrix"]

    print(f"True positives  : {matrix['tp']}")
    print(f"False positives : {matrix['fp']}")
    print(f"True negatives  : {matrix['tn']}")
    print(f"False negatives : {matrix['fn']}")

    def display_score(value):
        return "N/A" if value is None else f"{value:.2%}"

    print(f"Precision       : {display_score(result['precision'])}")
    print(f"Recall          : {display_score(result['recall'])}")
    print(f"F1 score        : {display_score(result['f1_score'])}")
    print(f"Accuracy        : {display_score(result['accuracy'])}")

    print("\nCase results:")

    for item in result["details"]:
        print(
            f"  {item['case_id']}: "
            f"{item['actual_label']} -> "
            f"{item['predicted_label']} "
            f"({item['outcome']})"
        )

    print(f"\nSaved report: {path}")
    print(
        "Note: results describe the synthetic test set, "
        "not real-world detection performance."
    )


if __name__ == "__main__":
    main()