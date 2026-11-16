
"""Offline evaluation of endpoint detections on synthetic scenarios.

Expected labels are hand-constructed test expectations,
not independently verified real-world incident labels.
"""

import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .endpoint_detections import detect_endpoint_threats
from .telemetry import load_sysmon_file


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "telemetry_samples"
RULE_IDS = ("DET-002", "DET-003")


def _shift(timestamp, minutes):
    """Move a UTC timestamp by a specified number of minutes."""

    parsed = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    return (
        (parsed + timedelta(minutes=minutes))
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _scenario(name, source, expected, change=None):
    """Copy source evidence and apply one controlled modification."""

    events = deepcopy(source)

    if change is not None:
        change(events)

    return {
        "name": name,
        "events": events,
        "expected_rules": sorted(expected),
    }


def build_endpoint_scenarios(sample_dir=SAMPLES):
    """Generate suspicious cases and benign near-miss scenarios."""

    sample_dir = Path(sample_dir)

    encoded = load_sysmon_file(
        sample_dir / "sysmon_suspicious_powershell.json"
    )

    office = load_sysmon_file(
        sample_dir / "sysmon_office_powershell.json"
    )

    def change_network(field, value):
        def mutate(events):
            events[1]["details"][field] = value
        return mutate

    def change_process(field, value):
        def mutate(events):
            events[0]["details"][field] = value
        return mutate

    def change_network_user(events):
        events[1]["user"] = "LAB\\other_user"

    def remove_source_address(events):
        events[1]["details"]["source_ip"] = None
        events[1]["details"]["ip"] = None

    def move_connection(minutes):
        def mutate(events):
            events[1]["timestamp"] = _shift(
                events[0]["timestamp"],
                minutes,
            )
        return mutate

    scenarios = [
        _scenario(
            "encoded_positive",
            encoded,
            {"DET-002"},
        ),
        _scenario(
            "encoded_no_flag",
            encoded,
            set(),
            change_process(
                "command_line",
                "powershell.exe -NoProfile Get-Date",
            ),
        ),
        _scenario(
            "encoded_other_process",
            encoded,
            set(),
            change_network(
                "process_guid",
                "{different-process-guid}",
            ),
        ),
        _scenario(
            "encoded_other_user",
            encoded,
            set(),
            change_network_user,
        ),
        _scenario(
            "encoded_network_before_process",
            encoded,
            set(),
            move_connection(-1),
        ),
        _scenario(
            "encoded_network_after_window",
            encoded,
            set(),
            move_connection(5 + 1 / 60),
        ),
        _scenario(
            "encoded_at_five_minutes",
            encoded,
            {"DET-002"},
            move_connection(5),
        ),
        _scenario(
            "encoded_missing_source_ip",
            encoded,
            set(),
            remove_source_address,
        ),
        _scenario(
            "office_positive",
            office,
            {"DET-003"},
        ),
        _scenario(
            "office_non_office_parent",
            office,
            set(),
            change_process(
                "parent_image",
                "C:\\Windows\\explorer.exe",
            ),
        ),
        _scenario(
            "office_other_process",
            office,
            set(),
            change_network(
                "process_guid",
                "{different-process-guid}",
            ),
        ),
        _scenario(
            "office_other_user",
            office,
            set(),
            change_network_user,
        ),
        _scenario(
            "office_network_before_process",
            office,
            set(),
            move_connection(-1),
        ),
        _scenario(
            "office_network_after_window",
            office,
            set(),
            move_connection(5 + 1 / 60),
        ),
        _scenario(
            "office_at_five_minutes",
            office,
            {"DET-003"},
            move_connection(5),
        ),
        _scenario(
            "office_missing_source_ip",
            office,
            set(),
            remove_source_address,
        ),
        _scenario(
            "combined_two_rules",
            encoded + office,
            {"DET-002", "DET-003"},
        ),
    ]

    names = [case["name"] for case in scenarios]

    if len(names) != len(set(names)):
        raise ValueError(
            "Duplicate evaluation scenario names"
        )

    return scenarios


def _scores(matrix):
    """Calculate classification metrics for one detection rule."""

    tp, fp, tn, fn = (
        matrix[key]
        for key in ("tp", "fp", "tn", "fn")
    )

    def ratio(numerator, denominator):
        return (
            round(numerator / denominator, 4)
            if denominator
            else None
        )

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
        "confusion_matrix": dict(matrix),
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "accuracy": ratio(
            tp + tn,
            tp + fp + tn + fn,
        ),
    }


def evaluate_endpoint_scenarios(scenarios):
    """Evaluate rule matches and validate finding provenance."""

    per_rule = {
        rule: Counter({
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
        })
        for rule in RULE_IDS
    }

    details = []
    names = set()

    for scenario in scenarios:
        name = scenario["name"]

        if name in names:
            raise ValueError(
                f"Duplicate evaluation scenario: {name}"
            )

        names.add(name)

        events = scenario["events"]

        event_ids = [
            event["id"]
            for event in events
        ]

        if len(event_ids) != len(set(event_ids)):
            raise ValueError(
                f"Duplicate event IDs in {name}"
            )

        expected_list = scenario["expected_rules"]
        expected = set(expected_list)

        if (
            len(expected) != len(expected_list)
            or not expected.issubset(RULE_IDS)
        ):
            raise ValueError(
                f"Unsupported or duplicate expected rules in {name}"
            )

        findings = detect_endpoint_threats(events)
        predicted = set()

        for finding in findings:
            rule_id = finding["rule_id"]
            evidence = finding.get("evidence_ids")

            if rule_id not in RULE_IDS:
                raise ValueError(
                    f"Unknown detected rule: {rule_id}"
                )

            if (
                not isinstance(evidence, list)
                or not evidence
                or len(evidence) != len(set(evidence))
                or not set(evidence).issubset(event_ids)
            ):
                raise ValueError(
                    f"Invalid evidence references in {name}: {rule_id}"
                )

            predicted.add(rule_id)

        outcomes = {}

        for rule in RULE_IDS:
            if rule in expected and rule in predicted:
                outcome = "tp"
            elif rule not in expected and rule in predicted:
                outcome = "fp"
            elif rule in expected and rule not in predicted:
                outcome = "fn"
            else:
                outcome = "tn"

            per_rule[rule][outcome] += 1
            outcomes[rule] = outcome.upper()

        details.append({
            "scenario": name,
            "expected_rules": sorted(expected),
            "detected_rules": sorted(predicted),
            "outcomes": outcomes,
            "finding_count": len(findings),
        })

    return {
        "evaluation_scope": "synthetic_sysmon_regression_scenarios",
        "scenario_count": len(details),
        "rules": {
            rule: _scores(per_rule[rule])
            for rule in RULE_IDS
        },
        "details": details,
        "limitations": (
            "These hand-constructed cases test rule behavior, "
            "not real-world false-positive rates or "
            "detection effectiveness."
        ),
    }


def run_endpoint_evaluation(output_path=None):
    """Run the benchmark and persist its JSON report."""

    result = evaluate_endpoint_scenarios(
        build_endpoint_scenarios()
    )

    if output_path is None:
        output_path = (
            ROOT / "data" / "endpoint_evaluation.json"
        )

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )

    return result, output_path


def main():
    result, path = run_endpoint_evaluation()

    print(
        f"Evaluated {result['scenario_count']} "
        "synthetic endpoint scenarios"
    )

    for rule, metrics in result["rules"].items():
        print(
            f"{rule}: {metrics['confusion_matrix']} "
            f"precision={metrics['precision']} "
            f"recall={metrics['recall']}"
        )

    print(f"Report: {path}")
    print(result["limitations"])


if __name__ == "__main__":
    main()