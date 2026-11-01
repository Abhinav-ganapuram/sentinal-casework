
"""FastAPI routes for importing exported Sysmon telemetry."""

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .import_storage import (
    list_imported_cases,
    save_imported_case,
)
from .telemetry import (
    TelemetryError,
    create_imported_case,
    parse_sysmon_text,
    MAX_FILE_BYTES,
)


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1)


def create_import_router(db_path: Path) -> APIRouter:
    router = APIRouter(
        prefix="/imports",
        tags=["Telemetry ingestion"],
    )

    @router.post("", status_code=201)
    def import_telemetry(request: ImportRequest):
        filename = request.filename.strip()

        # Accept only simple filenames, never local paths.
        if (
            not filename
            or "/" in filename
            or "\\" in filename
            or filename in {".", ".."}
        ):
            raise HTTPException(
                status_code=422,
                detail="Invalid filename",
            )

        if not filename.lower().endswith(
            (".json", ".jsonl")
        ):
            raise HTTPException(
                status_code=415,
                detail="Only JSON and JSONL files are supported",
            )

        if (
            len(request.content.encode("utf-8"))
            > MAX_FILE_BYTES
        ):
            raise HTTPException(
                status_code=413,
                detail="Telemetry exceeds 5 MB",
            )

        try:
            events = parse_sysmon_text(
                request.content,
                filename=filename,
            )

            case = create_imported_case(
                events,
                title=f"Sysmon Import: {filename}",
            )

        except TelemetryError as error:
            raise HTTPException(
                status_code=422,
                detail=str(error),
            ) from error

        saved = save_imported_case(
            case,
            filename,
            db_path,
        )

        return {
            "case_id": saved["case_id"],
            "title": saved["title"],
            "event_count": len(saved["events"]),
            "source_type": saved["source_type"],
            "created_at": saved["created_at"],
        }

    @router.get("")
    def imported_cases():
        return list_imported_cases(db_path)

    return router