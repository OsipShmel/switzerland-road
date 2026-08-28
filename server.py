import asyncio
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any

# берем граф, RAG и память из main.py
from main import pentest_graph, load_skill_rag, CheckSessionState

app = FastAPI(
    title="Pentest Agent Core API",
    description="REST API для управления ИИ-агентом верификации (Пауза/Возобновление)",
    version="1.0.0"
)

active_sessions: Dict[str, Dict[str, Any]] = {}


class StartSessionRequest(BaseModel):
    id: str = Field(description="ID уязвимости от сканера")
    type: str = Field(
        description="Тип уязвимости (SQL Injection, Path Traversal, Cross-Site Scripting)")
    target_url: str = Field(description="URL сайта для атаки")
    parameter: str = Field(description="HTTP-параметр")


@app.post("/api/v1/agent/start")
async def start_pentest_session(request: StartSessionRequest, background_tasks: BackgroundTasks):
    vuln_id = request.id
    if vuln_id in active_sessions and active_sessions[vuln_id]["status"] == "running":
        raise HTTPException(status_code=400, detail="Сессия уже выполняется.")

    clean_initial_state = CheckSessionState(
        vulnerability_info=request.model_dump(),
        skill_content=load_skill_rag(request.type),
        chat_history=[], used_payloads_hashes=[], last_ai_decision={}, final_report={}, error_retry_count=0
    )
    config = {"configurable": {"thread_id": vuln_id}, "recursion_limit": 10}
    active_sessions[vuln_id] = {
        "status": "running", "config": config, "result": None}

    async def run_agent_workflow():
        try:
            result = await pentest_graph.ainvoke(clean_initial_state, config=config)
            if "final_report" in result and result["final_report"]:
                active_sessions[vuln_id]["status"] = "completed"
                active_sessions[vuln_id]["result"] = result["final_report"]
            else:
                active_sessions[vuln_id]["status"] = "paused"
        except Exception as e:
            active_sessions[vuln_id]["status"] = "failed"
            active_sessions[vuln_id]["result"] = {"error": str(e)}

    background_tasks.add_task(run_agent_workflow)
    return {"vulnerability_id": vuln_id, "status": "started"}


@app.post("/api/v1/agent/resume/{vuln_id}")
async def resume_pentest_session(vuln_id: str, background_tasks: BackgroundTasks):
    if vuln_id not in active_sessions or active_sessions[vuln_id]["status"] != "paused":
        raise HTTPException(
            status_code=400, detail="Невозможно возобновить поток.")

    active_sessions[vuln_id]["status"] = "running"
    config = active_sessions[vuln_id]["config"]

    async def resume_agent_workflow():
        try:
            result = await pentest_graph.ainvoke(None, config=config)
            active_sessions[vuln_id]["status"] = "completed"
            active_sessions[vuln_id]["result"] = result["final_report"]
        except Exception as e:
            active_sessions[vuln_id]["status"] = "failed"
            active_sessions[vuln_id]["result"] = {"error": str(e)}

    background_tasks.add_task(resume_agent_workflow)
    return {"vulnerability_id": vuln_id, "status": "resumed"}


@app.get("/api/v1/agent/status/{vuln_id}")
async def get_session_status(vuln_id: str):
    if vuln_id not in active_sessions:
        raise HTTPException(status_code=404, detail="Не найдено.")
    return active_sessions[vuln_id]
