
"""API endpoint for investigation performance analytics."""

import json
from contextlib import closing
from pathlib import Path

from fastapi import APIRouter

from .storage import connect_database


def create_metrics_router(db_path: Path) -> APIRouter:
    router = APIRouter(
        prefix="/metrics",
        tags=["Evaluation and performance"],
    )

    @router.get("/investigations")
    def investigation_metrics():
        with closing(connect_database(db_path)) as connection:
            rows = connection.execute(
                """
                SELECT investigation_id, case_id,
                       created_at, result_json
                FROM investigations
                ORDER BY created_at DESC, rowid DESC
                LIMIT 500
                """
            ).fetchall()

        results = []
        for row in rows:
            result = json.loads(row["result_json"])
            perf = result.get("performance")

            if not isinstance(perf, dict):
                continue

            results.append({
                "investigation_id": row["investigation_id"],
                "case_id": row["case_id"],
                "created_at": row["created_at"],
                "mode": result.get(
                    "execution_mode", "unknown"
                ),
                "status": result.get(
                    "status", "unknown"
                ),
                **perf,
            })

        def summarize(items):
            durations = sorted(
                item["total_duration_ms"]
                for item in items
            )

            count = len(durations)

            if not count:
                return {
                    "run_count": 0,
                    "average_duration_ms": None,
                    "p95_duration_ms": None,
                    "average_decision_count": None,
                    "average_tool_lookups": None,
                }

            rank = max(
                0,
                (95 * count + 99) // 100 - 1,
            )

            return {
                "run_count": count,
                "average_duration_ms": round(
                    sum(durations) / count, 2
                ),
                "p95_duration_ms": durations[rank],
                "average_decision_count": round(
                    sum(x["decision_count"] for x in items)
                    / count,
                    2,
                ),
                "average_tool_lookups": round(
                    sum(x["tool_lookup_count"] for x in items)
                    / count,
                    2,
                ),
            }

        modes = sorted({
            item["mode"] for item in results
        })

        return {
            "sample_size": len(results),
            "sample_limit": 500,
            "overall": summarize(results),
            "by_mode": {
                mode: summarize([
                    item for item in results
                    if item["mode"] == mode
                ])
                for mode in modes
            },
            "recent_investigations": results[:20],
        }

    return router