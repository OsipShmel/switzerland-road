FROM python:3.14-alpine

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    pydantic \
    httpx

WORKDIR /srv

COPY packages/vls/src /opt/vls
COPY packages/sandboxdAPI/src /opt/sandboxdapi
COPY apps/sandboxd/src /opt/sandboxd

COPY apps/sandboxd/tests/gateway/main.py /srv/main.py

ENV PYTHONPATH=/opt/sandboxd:/opt/vls:/opt/sandboxdapi

EXPOSE 9000

CMD ["python3", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"]