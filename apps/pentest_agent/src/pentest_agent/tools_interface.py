import json
import httpx
from typing import Dict, Any
import os

# Если запускаем в Docker Compose, URL подтянется из ENV, иначе дефолт на localhost
SANDBOXD_URL = os.getenv("SANDBOXD_URL", "http://localhost:8080/api/v1")


async def log_to_sandbox(level: str, event: str, message: str, metadata: Dict[str, Any] = None):
    """Метод append-only логирования."""
    log_entry = {
        "level": level,
        "event": event,
        "message": message,
        "metadata": metadata or {}
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(f"{SANDBOXD_URL}/log", json=log_entry, timeout=1.0)
    except Exception:
        # Fail-safe для логов: если один пакет потерялся, агент не падает
        print(
            f"[📡 SandboxD Offline] LOG: {json.dumps(log_entry, ensure_ascii=False)}")


async def execute_ib_tool(action: str, payload: str, vulnerability_info: Dict[str, Any]) -> str:
    """
    УНИВЕРСАЛЬНЫЙ ИНТЕРФЕЙС ИБ-ИНСТРУМЕНТОВ (Модуль Никиты).
    Полностью вычищен от Juice Shop. Работает с ЛЮБЫМ сайтом/целью из контекста.
    """
    target_url = vulnerability_info.get("target_url")
    parameter = vulnerability_info.get("parameter")

    # (level: info, event: tool_start)
    await log_to_sandbox(
        level="info",
        event="tool_start",
        message=f"Starting tool {action} against endpoint {target_url}",
        metadata={"tool": action, "target": target_url, "param": parameter}
    )

    try:
        # ======================================================================
        #  ТОЧКА ПОДКЛЮЧЕНИЯ tools'ов
        # ======================================================================

        async with httpx.AsyncClient() as client:
            params = {parameter: payload}
            response = await client.get(target_url, params=params, timeout=5.0)
            tool_output = f"HTTP {response.status_code}. Response Preview: {response.text[:200]}"

        # ======================================================================

        # Успешное окончание (level: debug, event: tool_result)
        await log_to_sandbox(
            level="debug",
            event="tool_result",
            message=f"Tool {action} finished successfully",
            metadata={"tool": action, "result": tool_output, "exit_code": 0}
        )
        return tool_output

    except Exception as e:
        error_msg = f"Критическая ошибка сети при сканировании цели {target_url}: {str(e)}"
        # Ошибка (level: error, event: tool_error)
        await log_to_sandbox(level="error", event="tool_error", message=error_msg)
        return f"HTTP 0: Connection Failed. {error_msg}"
