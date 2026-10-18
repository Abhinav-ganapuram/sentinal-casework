
"""Local API for synthetic SOC case investigations."""

import os
from pathlib import Path
from .metrics_api import create_metrics_router
from .metrics import run_measured_investigation
from typing import Callable, Literal
from .narrative_api import create_narrative_router
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict
from .report_builder import build_incident_report
from .agent import run_agent
from .cases import CASE_PATH, load_case
from .demo_adapter import DemoDecider
from .gemini_adapter import (
    GeminiDecider,
    GeminiProviderError,
)
from .review_api import create_review_router
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


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["demo", "gemini"] = "demo"


def get_case(case_id: str) -> dict:
    path = CASE_FILES.get(case_id)

    if path is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found",
        )

    return load_case(path)


def create_live_decider():
    if not (
        os.getenv("GEMINI_API_KEY")
        or os.getenv("GOOGLE_API_KEY")
    ):
        raise HTTPException(
            status_code=503,
            detail="Gemini API key is not configured on the server",
        )

    return GeminiDecider(
        model=os.getenv(
            "SENTINEL_GEMINI_MODEL",
            "gemini-3.8-flash",
        )
    )


def create_app(
    db_path: Path = DEFAULT_DB_PATH,
    live_decider_factory: Callable | None = None,
) -> FastAPI:

    application = FastAPI(
        title="Sentinel Casework",
        description="Evidence-backed SOC investigation API",
        version="0.3.0",
    )

    factory = (
        live_decider_factory
        if live_decider_factory is not None
        else create_live_decider
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
    def investigate(
        case_id: str,
        request: InvestigationRequest | None = None,
    ) -> dict:

        case = get_case(case_id)

        selected_mode = (
            request.mode
            if request is not None
            else "demo"
        )

        if selected_mode == "demo":
            decider = DemoDecider()
        else:
            decider = factory()

        try:
            result = run_measured_investigation(
            case,
            decider,
            max_steps=3,
            )
        except GeminiProviderError as error:
            raise HTTPException(
                status_code=502,
                detail="Gemini provider request failed. Check model access, API quota, and backend logs.",
            ) from error

        result["execution_mode"] = selected_mode
        result["report"] = build_incident_report(case, result)
        saved = save_investigation(
            result,
            db_path,
        )

        return {
            **saved["result"],
            "investigation_id": saved["investigation_id"],
            "created_at": saved["created_at"],
        }

    @application.get("/investigations/{investigation_id}")
    def investigation_detail(investigation_id: str) -> dict:
        saved = get_investigation(
            investigation_id,
            db_path,
        )

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

    application.include_router(
        create_review_router(db_path)
    )
    application.include_router(
    create_narrative_router(db_path)
    )

    application.include_router(
    create_metrics_router(db_path)
    )
    
    return application


app = create_app()
