from __future__ import annotations

from fastapi import FastAPI, HTTPException
from vls import VlsRegistry

from .agent import RegistryScoringAgent
from .schemas import ScoreRequest, ScoreResponse

app = FastAPI(title="Scoring Agent API", version="1.0.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/score", response_model=ScoreResponse)
def score_findings(request: ScoreRequest) -> ScoreResponse:
    try:
        registry = VlsRegistry(request.vulnerabilities)
        scorer = RegistryScoringAgent(request.topology, request.service_name)
        scorer.score_registry(registry, request.target_dir)
        return ScoreResponse(vulnerabilities=registry.all())
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def main() -> None:
    import uvicorn

    uvicorn.run("scoring_agent.app:app", host="0.0.0.0", port=8000)
