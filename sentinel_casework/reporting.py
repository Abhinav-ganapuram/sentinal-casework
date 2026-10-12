"""Save investigation results as JSON reports."""

import json
from pathlib import Path


def save_report(result: dict, output_path: Path) -> None:
    """Create a report without overwriting an existing file."""
    content = json.dumps(result, indent=2, ensure_ascii=False)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("x", encoding="utf-8") as report:
        report.write(content + "\n")