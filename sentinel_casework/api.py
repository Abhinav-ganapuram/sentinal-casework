
"""Sentinel Casework API for evidence-backed SOC investigations."""

import os
from pathlib import Path
from typing import Callable, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from .cases import CASE_PATH, load_case
from .demo_adapter import DemoDecider
from .gemini_adapter import (
    GeminiDecider,
    GeminiProviderError,
)
from .import_api import create_import_router
from .import_storage import (
    get_imported_case,
    list_imported_cases,
)
from .metrics import run_measured_investigation
from .metrics_api import create_metrics_router
from .narrative_api import create_narrative_router
from .report_builder import build_incident_report
from .review_api import create_review_router
from .storage import (
    DEFAULT_DB_PATH,
    get_investigation,
    list_investigations,
    save_investigation,
)


# Existing built-in synthetic cases
CASE_FILES = {
    "CASE-001": CASE_PATH,
    "CASE-002": CASE_PATH.parent / "benign_mfa_retry.json",
    "CASE-003": CASE_PATH.parent / "mfa_global_admin.json",
    "CASE-004": CASE_PATH.parent / "mfa_threshold_attack.json",
    "CASE-005": CASE_PATH.parent / "benign_cross_ip.json",
    "CASE-006": CASE_PATH.parent / "benign_delayed_grant.json",
}


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["demo", "gemini"] = "demo"


def get_case(case_id: str) -> dict:
    """Load a predefined synthetic case."""

    path = CASE_FILES.get(case_id)

    if path is None:
        raise HTTPException(
            status_code=404,
            detail="Case not found",
        )

    return load_case(path)


def create_live_decider():
    """Create the Gemini decision provider."""

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
    """Create the Sentinel Casework API application."""

    application = FastAPI(
        title="Sentinel Casework",
        description=(
            "Evidence-backed SOC investigation and "
            "security telemetry ingestion API"
        ),
        version="0.4.0",
    )

    factory = (
        live_decider_factory
        if live_decider_factory is not None
        else create_live_decider
    )

    # -------------------------------------------------------
    # Case resolution
    # -------------------------------------------------------

    def resolve_case(case_id: str) -> dict:
        """
        Resolve both built-in and imported cases.

        Built-in cases come from JSON fixtures.
        Imported cases are stored persistently in SQLite.
        """

        if case_id in CASE_FILES:
            return get_case(case_id)

        imported = get_imported_case(
            case_id,
            db_path,
        )

        if imported is not None:
            return imported

        raise HTTPException(
            status_code=404,
            detail="Case not found",
        )

    # -------------------------------------------------------
    # Health check
    # -------------------------------------------------------

    @application.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    # -------------------------------------------------------
    # Case library
    # -------------------------------------------------------

    @application.get("/cases")
    def list_cases() -> list[dict]:
        """
        List built-in synthetic cases and imported Sysmon cases.
        """

        cases = []

        for case_id in CASE_FILES:
            case = get_case(case_id)

            cases.append({
                "case_id": case["case_id"],
                "title": case["title"],
                "event_count": len(case["events"]),
                "source_type": "synthetic",
            })

        # Add persistent imported cases.
        cases.extend(
            list_imported_cases(db_path)
        )

        return cases

    @application.get("/cases/{case_id}")
    def case_detail(case_id: str) -> dict:
        """Retrieve a built-in or imported case."""

        return resolve_case(case_id)

    # -------------------------------------------------------
    # Investigation history
    # -------------------------------------------------------

    @application.get("/cases/{case_id}/investigations")
    def case_history(case_id: str) -> list[dict]:
        """
        Return saved investigations for an existing case.
        """

        # Validate that the requested case exists.
        resolve_case(case_id)

        return list_investigations(
            case_id,
            db_path,
        )

    # -------------------------------------------------------
    # Investigation execution
    # -------------------------------------------------------

    @application.post("/cases/{case_id}/investigate")
    def investigate(
        case_id: str,
        request: InvestigationRequest | None = None,
    ) -> dict:
        """
        Run a Demo or Gemini investigation.

        Supports both built-in synthetic cases and imported
        Sysmon telemetry cases.
        """

        case = resolve_case(case_id)

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
                detail=(
                    "Gemini provider request failed. "
                    "Check model access, API quota, "
                    "and backend logs."
                ),
            ) from error

        # Record which investigation mode was used.
        result["execution_mode"] = selected_mode

        # Generate an evidence-backed incident report.
        result["report"] = build_incident_report(
            case,
            result,
        )

        # Persist investigation, report, and performance metrics.
        saved = save_investigation(
            result,
            db_path,
        )

        return {
            **saved["result"],
            "investigation_id": saved["investigation_id"],
            "created_at": saved["created_at"],
        }

    # -------------------------------------------------------
    # Saved investigation details
    # -------------------------------------------------------

    @application.get("/investigations/{investigation_id}")
    def investigation_detail(
        investigation_id: str,
    ) -> dict:
        """Retrieve a previously saved investigation."""

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

    # -------------------------------------------------------
    # Modular feature routers
    # -------------------------------------------------------

    # Persistent analyst review and verdict history
    application.include_router(
        create_review_router(db_path)
    )

    # Evidence-validated Gemini incident narratives
    application.include_router(
        create_narrative_router(db_path)
    )

    # Investigation performance and evaluation analytics
    application.include_router(
        create_metrics_router(db_path)
    )

    # NEW: Sysmon JSON / JSONL telemetry ingestion
    application.include_router(
        create_import_router(db_path)
    )

    return application


# Entry point for Uvicorn.
app = create_app()