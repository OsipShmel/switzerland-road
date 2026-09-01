from __future__ import annotations

from fastapi import FastAPI
from .VLSManager import router as vls_router
from .supervisor import router as supervisor_router
from .sandbox_io_manager import router as sandbox_router

app = FastAPI(title="Sandbox Manager API")

app.include_router(vls_router)          # /api/vls/*
app.include_router(supervisor_router)   # /api/supervisor/*
app.include_router(sandbox_router)      # /sandbox/*

@app.get("/")
async def root():
    return {
        "message": "Sandbox Manager API",
        "endpoints": {
            "vls": "/api/vls/*",
            "vlsregisry": "/api/vlsregistry",
            "supervisor": "/api/supervisor/*",
            "sandbox": "/sandbox/*",
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
