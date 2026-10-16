"""API routes for analyst reviews."""

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .reviews import list_reviews, save_review
from .storage import get_investigation


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal["suspicious", "benign", "needs_more_evidence"]
    notes: str = Field(min_length=1, max_length=2000)

    @field_validator("notes")
    @classmethod
    def validate_notes(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Review notes are required")

        return value


def create_review_router(db_path: Path) -> APIRouter:
    router = APIRouter(
        prefix="/investigations",
        tags=["Analyst reviews"],
    )

    @router.get("/{investigation_id}/reviews")
    def review_history(investigation_id: str) -> list[dict]:
        if get_investigation(investigation_id, db_path) is None:
            raise HTTPException(
                status_code=404,
                detail="Investigation not found",
            )

        return list_reviews(investigation_id, db_path)

    @router.post("/{investigation_id}/reviews", status_code=201)
    def submit_review(
        investigation_id: str,
        request: ReviewRequest,
    ) -> dict:
        try:
            return save_review(
                investigation_id,
                request.verdict,
                request.notes,
                db_path,
            )
        except LookupError as error:
            raise HTTPException(
                status_code=404,
                detail="Investigation not found",
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=422,
                detail=str(error),
            ) from error

    return router