"""Local API for synthetic SOC case investigations."""

from pathlib import Path

from fastapi import FastAPI, HTTPException

from .agent import run_agent
from .cases import CASE_PATH, load_case
from .demo_adapter import DemoDecider
from .storage import (
    DEFAULT_DB_PATH,
    get_investigation,
    list_investigations,
    save_investigation,
)


CASE_FILES = {
    "CASE-001": CASE_PATH,
    "CASE-002": CASE_PATH.parent / "benign_mfa_retry.json",
}


def get_case(case_id: str) -> dict:
    path = CASE_FILES.get(case_id)

    if path is None:
        raise HTTPException(status_code=404, detail="Case not found")

    return load_case(path)


def create_app(db_path: Path = DEFAULT_DB_PATH) -> FastAPI:
    application = FastAPI(
        title="Sentinel Casework",
        description="Synthetic SOC investigations — offline demo API",
        version="0.2.0",
    )

    @application.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @application.get("/cases")
    def list_cases() -> list[dict]:
        cases = []

        for case_id in CASE_FILES:
            case = get_case(case_id)
            cases.append({
                "case_id": case["case_id"],
                "title": case["title"],
                "event_count": len(case["events"]),
            })

        return cases

    @application.get("/cases/{case_id}")
    def case_detail(case_id: str) -> dict:
        return get_case(case_id)

    @application.get("/cases/{case_id}/investigations")
    def case_history(case_id: str) -> list[dict]:
        get_case(case_id)
        return list_investigations(case_id, db_path)

    @application.post("/cases/{case_id}/investigate")
    def investigate(case_id: str) -> dict:
        case = get_case(case_id)
        result = run_agent(case, DemoDecider(), max_steps=3)
        result["execution_mode"] = "demo"

        saved = save_investigation(result, db_path)

        return {
            **saved["result"],
            "investigation_id": saved["investigation_id"],
            "created_at": saved["created_at"],
        }

    @application.get("/investigations/{investigation_id}")
    def investigation_detail(investigation_id: str) -> dict:
        saved = get_investigation(investigation_id, db_path)

        if saved is None:
            raise HTTPException(
                status_code=404,
                detail="Investigation not found",
            )

        return {
            **saved["result"],
            "investigation_id": saved["investigation_id"],
            "created_at": saved["created_at"],
        }

    return application


app = create_app()