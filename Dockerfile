FROM docker:dind

# RUN apk add --no-cache python3 bash git curl
RUN apk add --no-cache python3 bash git curl socat

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY . .

RUN uv sync --frozen

ENV PYTHONPATH=/app/apps/sandboxd/src

COPY apps/sandboxd/docker-entrypoint.sh /usr/local/bin/sandboxd-entrypoint
RUN chmod +x /usr/local/bin/sandboxd-entrypoint

ENTRYPOINT ["sandboxd-entrypoint"]

CMD ["uv", "run", "--package", "sandboxd", "python", "-m", "sandboxd.main"]