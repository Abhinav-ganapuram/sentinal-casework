
"""Investigation timing and labeled detection evaluation."""

from collections import Counter
from time import perf_counter

from .detections import detect_mfa_fatigue_and_privilege_change


class MeasuredDecider:
    """Count and time decisions without changing agent behavior."""

    def __init__(self, decider):
        self.decider = decider
        self.calls = 0
        self.duration_seconds = 0.0

    def __call__(self, context):
        start = perf_counter()
        self.calls += 1

        try:
            return self.decider(context)
        finally:
            self.duration_seconds += perf_counter() - start


def run_measured_investigation(case, decider, max_steps=3):
    """Run the agent and attach performance measurements."""

    from .agent import run_agent

    measured = MeasuredDecider(decider)
    start = perf_counter()

    result = run_agent(
        case,
        measured,
        max_steps=max_steps,
    )

    total_seconds = perf_counter() - start

    result["performance"] = {
        "total_duration_ms": round(
            total_seconds * 1000, 2
        ),
        "decision_duration_ms": round(
            measured.duration_seconds * 1000, 2
        ),
        "non_decision_duration_ms": round(
            max(0.0, total_seconds - measured.duration_seconds)
            * 1000,
            2,
        ),
        "decision_count": measured.calls,
        "tool_lookup_count": len(result["trace"]),
    }

    return result


def evaluate_cases(cases):
    """Compare deterministic detections to labeled case fixtures."""

    matrix = Counter({
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
    })

    details = []
    seen_ids = set()

    for case in cases:
        case_id = case["case_id"]

        if case_id in seen_ids:
            raise ValueError(f"Duplicate case ID: {case_id}")
        seen_ids.add(case_id)

        label = case.get("label")

        if label not in {"suspicious", "benign"}:
            raise ValueError(
                f"Case {case_id} needs a suspicious/benign label"
            )

        findings = detect_mfa_fatigue_and_privilege_change(
            case["events"]
        )

        actual_positive = label == "suspicious"
        predicted_positive = len(findings) > 0

        if actual_positive and predicted_positive:
            outcome = "tp"
        elif not actual_positive and predicted_positive:
            outcome = "fp"
        elif actual_positive and not predicted_positive:
            outcome = "fn"
        else:
            outcome = "tn"

        matrix[outcome] += 1

        details.append({
            "case_id": case_id,
            "actual_label": label,
            "predicted_label": (
                "suspicious" if predicted_positive else "benign"
            ),
            "finding_count": len(findings),
            "outcome": outcome.upper(),
        })

    tp = matrix["tp"]
    fp = matrix["fp"]
    tn = matrix["tn"]
    fn = matrix["fn"]

    count = tp + fp + tn + fn

    def ratio(numerator, denominator):
        if denominator == 0:
            return None
        return round(numerator / denominator, 4)

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)

    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = round(
            2 * precision * recall / (precision + recall),
            4,
        )

    return {
        "case_count": count,
        "confusion_matrix": dict(matrix),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": ratio(tp + tn, count),
        "details": details,
        "evaluation_scope": "labeled_synthetic_cases",
    }