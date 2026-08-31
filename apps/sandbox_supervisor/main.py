from __future__ import annotations

import asyncio
import httpx
from fastapi import FastAPI, Request, BackgroundTasks

from VLSManager import vls_manager_instance
from supervisor import Supervisor
from supervisor_shell import SupervisorShell


#дерьмонстрационная поеба

app = FastAPI()

def get_vls_manager():
    return vls_manager_instance
    
@app.post("/log-vls")    
async def receive_vls_registry(
        request: Request,
        background_tasks: BackgroundTasks
):
    raw_resp = await request.body()
    background_tasks.add_task(vls_manager_instance._process_json, raw_resp)
    return {"is_success": True}    


async def main():
    async with httpx.AsyncClient() as client:
        supervisor = Supervisor(client=client)
        shell = SupervisorShell(supervisor=supervisor)
        await asyncio.gather(shell.run())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Приложение остановлено.")
