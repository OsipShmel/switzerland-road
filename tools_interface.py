from port_scan import port_scan
from endpoint_discovery import endpoint_discovery
from http_request import http_request
from cookie_check import cookie_check
from response_compare import response_compare
from config import SANDBOXD_GATEWAY_URL, TARGET_URL
import json
import sys
from pathlib import Path
from typing import Dict, Any

sys.path.append(str(Path(__file__).parent.absolute()))


async def log_to_sandbox(level: str, event: str, message: str, metadata: Dict[str, Any] = None) -> None:
    valid_level = level if level in [
        "model", "debug", "info", "warning", "error"] else "error"
    log_entry = {
        "level": valid_level,
        "event": event,
        "message": message,
        "metadata": metadata or {},
        "context": None
    }
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            await client.post(f"{SANDBOXD_GATEWAY_URL}/log", json=log_entry, timeout=2.0)
    except Exception:
        print(
            f"[📡 SandboxD Offline] LOG: {json.dumps(log_entry, ensure_ascii=False)}")


async def execute_ib_tool(action: str, payload: str, vulnerability_info: Dict[str, Any]) -> str:
    trace_id = vulnerability_info.get("trace_id", "")

    vls_info = {
        "target_url": TARGET_URL,
        "allowed_ports": [80, 443, 3000, 8080]
    }

    await log_to_sandbox(
        level="info",
        event="tool_start",
        message=f"ИИ активировал инструмент '{action}' для проверки уязвимости.",
        metadata={"action": action, "payload": payload, "trace_id": trace_id}
    )

    try:
        if action == "port_scan":
            args = {"ports": vls_info["allowed_ports"]}
            result = await port_scan(vls_info, args)

        elif action == "endpoint_discovery":
            args = {
                "max_pages": vulnerability_info.get("max_pages", 10),
                "max_depth": vulnerability_info.get("max_depth", 2),
                "concurrency": vulnerability_info.get("concurrency", 5)
            }
            result = await endpoint_discovery(vls_info, args)

        elif action == "http_request" or action in ["sqli_check", "xss_check", "path_traversal_check"]:
            param = vulnerability_info.get("parameter", "q")
            args = {
                "method": "GET",
                "params": {param: payload},
                "headers": {"x-vls-trace-id": trace_id} if trace_id else {}
            }
            result = await http_request(vls_info, args)

        elif action == "cookie_check":
            args = {"set_cookie_headers": vulnerability_info.get(
                "captured_cookies", [])}
            result = await cookie_check(vls_info, args)

        elif action == "response_compare":
            args = {
                "baseline": vulnerability_info.get("baseline_response", {}),
                "attack": vulnerability_info.get("attack_response", {}),
                "payload": payload,
                "normalize_dynamic": True
            }
            result = await response_compare(args)

        else:
            result = {
                "success": False, "error": f"Инструмент '{action}' не найден в арсенале агента."}

        await log_to_sandbox(
            level="debug",
            event="tool_result",
            message=f"Инструмент '{action}' успешно завершил работу.",
            metadata={"action": action, "exit_code": 0}
        )

        return json.dumps(result, ensure_ascii=False)

    except Exception as e:
        error_msg = f"Критический сбой внутри модуля инструмента '{action}': {str(e)}"
        await log_to_sandbox(level="error", event="tool_error", message=error_msg)
        return json.dumps({"success": False, "error": error_msg}, ensure_ascii=False)
