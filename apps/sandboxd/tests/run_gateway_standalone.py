"""
Запуск agent-gateway отдельно от sandboxd, без докера и без SandboxOrchestrator —
только для ручного/curl-тестирования HTTP-контракта.

    uv run python dev/run_gateway_standalone.py

Слушает 127.0.0.1:9000, сидирует пару тестовых VLS, чтобы start_check_session
было с чем работать.
"""
from __future__ import annotations

from pathlib import Path

import uvicorn

from sandboxd.api.app import create_agent_gateway_app
from sandboxd.api.agent_gateway.state import GatewayState
from vls import VLS, VlsRegistry, SastBlock


def _seed_registry() -> VlsRegistry:
    return VlsRegistry([
        VLS(
            id="vls-001",
            title="Reflected XSS in search",
            sast=SastBlock(rule_id="js.xss.reflected", file_path="routes/search.ts", line=42, score=7.5),
        ),
        VLS(
            id="vls-002",
            title="SQL injection in login",
            sast=SastBlock(rule_id="js.sqli.basic", file_path="routes/login.ts", line=17, score=9.0),
        ),
    ])


def main() -> None:
    logs_dir = Path(__file__).parent / ".gateway_logs"
    gateway_state = GatewayState(logs_dir=logs_dir)
    gateway_state.load_vulnerabilities(_seed_registry())

    app = create_agent_gateway_app(gateway_state)
    uvicorn.run(app, host="127.0.0.1", port=9000, log_level="info")


if __name__ == "__main__":
    main()
