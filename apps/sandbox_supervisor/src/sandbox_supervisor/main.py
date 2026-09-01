from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .VLSManager import router as vls_router
from .sandbox_io_manager import router as sandbox_router
from .security_gate import router as security_gate_router
from .supervisor import router as supervisor_router

app = FastAPI(title="Sandbox Manager API")


def _frontend_origins() -> list[str]:
    configured = os.getenv(
        "FRONTEND_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173",
    )
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def _frontend_origin_regex() -> str:
    return os.getenv(
        "FRONTEND_ORIGIN_REGEX",
        r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=_frontend_origins(),
    allow_origin_regex=_frontend_origin_regex(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(vls_router)          # /api/vls/*
app.include_router(supervisor_router)   # /api/supervisor/*
app.include_router(security_gate_router)  # /api/security-gate/*
app.include_router(sandbox_router)      # /sandbox/*

@app.get("/")
async def root():
    return {
        "message": "Sandbox Manager API",
        "endpoints": {
            "vls": "/api/vls/*",
            "vlsregisry": "/api/vlsregistry",
            "supervisor": "/api/supervisor/*",
            "security_gate": "/api/security-gate/*",
            "sandbox": "/sandbox/*",
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
