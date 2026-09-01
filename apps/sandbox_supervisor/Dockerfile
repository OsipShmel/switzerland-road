FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
COPY apps/sandbox_supervisor/src ./src

# На этом этапе vls лучше установить из локального packages/vls,
# а не надеяться на внешний PyPI-пакет.
COPY packages/vls ./packages/vls
COPY packages/sandboxdAPI ./packages/sandboxdAPI

RUN uv pip install --system \
    fastapi \
    httpx \
    aiofiles \
    pydantic \
    uvicorn

RUN uv pip install --system ./packages/vls ./packages/sandboxdAPI


ENV PYTHONPATH=/app/src

CMD ["uvicorn", "sandbox_supervisor.main:app", "--host", "0.0.0.0", "--port", "8000"]