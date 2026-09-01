FROM python:3.14-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
COPY apps/sandbox_supervisor/src ./src

COPY packages/vls ./packages/vls
COPY packages/sandboxdAPI ./packages/sandboxdAPI
COPY apps/data_enricher ./apps/data_enricher
COPY apps/scoring_agent ./apps/scoring_agent
COPY apps/orchestrator ./apps/orchestrator

RUN uv pip install --system \
    fastapi \
    httpx \
    aiofiles \
    pydantic \
    uvicorn \
    semgrep

RUN uv pip install --system \
    ./packages/vls \
    ./packages/sandboxdAPI \
    ./apps/data_enricher \
    ./apps/scoring_agent \
    ./apps/orchestrator


ENV PYTHONPATH=/app/src

CMD ["uvicorn", "sandbox_supervisor.main:app", "--host", "0.0.0.0", "--port", "8000"]
