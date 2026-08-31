FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim

WORKDIR /workspace

COPY pyproject.toml uv.lock ./
COPY apps/scoring_agent ./apps/scoring_agent
COPY packages/vls ./packages/vls

RUN uv sync --frozen --package scoring-agent --no-dev

EXPOSE 8000

CMD ["/workspace/.venv/bin/uvicorn", "scoring_agent.app:app", "--host", "0.0.0.0", "--port", "8000"]
