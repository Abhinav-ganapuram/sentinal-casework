"""Local API for synthetic SOC case investigations."""

from fastapi import FastAPI, HTTPException

from .agent import run_agent
from .cases import CASE_PATH, load_case
from .demo_adapter import DemoDecider


app = FastAPI(
    title="Sentinel Casework",
    description="Synthetic SOC investigations — offline demo API",
    version="0.1.0",
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/cases")
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


@app.get("/cases/{case_id}")
def case_detail(case_id: str) -> dict:
    return get_case(case_id)


@app.post("/cases/{case_id}/investigate")
def investigate(case_id: str) -> dict:
    case = get_case(case_id)
    result = run_agent(case, DemoDecider(), max_steps=3)
    result["execution_mode"] = "demo"
    return result