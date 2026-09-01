# sandbox-supervisor

Supervisor service packaged with `uv`.

## Development

```bash
uv sync
uv run uvicorn sandbox_supervisor.main:app --host 0.0.0.0 --port 8000
```
