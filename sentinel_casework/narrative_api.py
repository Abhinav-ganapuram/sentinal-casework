
"""API endpoints for saved, evidence-validated AI narratives."""

import os
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, HTTPException

from .gemini_adapter import GeminiProviderError
from .narrative import (
    GeminiNarrativeGenerator,
    NarrativeValidationError,
    validate_narrative,
)
from .narrative_storage import get_narrative, save_narrative
from .storage import get_investigation


def create_narrative_router(
    db_path: Path,
    generator_factory: Callable | None = None,
) -> APIRouter:
    router = APIRouter(
        prefix="/investigations",
        tags=["AI narratives"],
    )

    def get_saved_investigation(investigation_id):
        saved = get_investigation(investigation_id, db_path)
        if saved is None:
            raise HTTPException(
                status_code=404,
                detail="Investigation not found",
            )
        return saved

    def make_generator():
        if generator_factory is not None:
            return generator_factory()

        if not (
            os.getenv("GEMINI_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
        ):
            raise HTTPException(
                status_code=503,
                detail="Gemini API key is not configured",
            )

        return GeminiNarrativeGenerator()

    @router.get("/{investigation_id}/narrative")
    def narrative_detail(investigation_id: str):
        get_saved_investigation(investigation_id)

        result = get_narrative(investigation_id, db_path)

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="Narrative not generated yet",
            )

        return result

    @router.post("/{investigation_id}/narrative")
    def generate_narrative(investigation_id: str):
        saved = get_saved_investigation(investigation_id)

        existing = get_narrative(investigation_id, db_path)
        if existing is not None:
            return existing

        report = saved["result"].get("report")

        if not report:
            raise HTTPException(
                status_code=409,
                detail="Investigation has no evidence report",
            )

        if not report.get("evidence_event_ids"):
            raise HTTPException(
                status_code=409,
                detail="No referenced evidence is available",
            )

        generator = make_generator()

        try:
            narrative = generator(report)
            narrative = validate_narrative(narrative, report)
        except GeminiProviderError as error:
            raise HTTPException(
                status_code=502,
                detail="Gemini narrative request failed",
            ) from error
        except NarrativeValidationError as error:
            raise HTTPException(
                status_code=422,
                detail=str(error),
            ) from error

        return save_narrative(
            investigation_id,
            narrative,
            db_path,
        )

    return router
