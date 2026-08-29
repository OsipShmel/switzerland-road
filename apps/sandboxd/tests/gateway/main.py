from pathlib import Path

from sandboxd.api.app import create_agent_gateway_app
from sandboxd.api.agent_gateway.state import GatewayState

from vls import VLS, VlsRegistry, SastBlock


def _seed_registry() -> VlsRegistry:
    return VlsRegistry([
        VLS(
            id="vls-001",
            title="Reflected XSS in search",
            sast=SastBlock(
                rule_id="js.xss.reflected",
                file_path="routes/search.ts",
                line=42,
                score=7.5,
            ),
        ),

        VLS(
            id="vls-002",
            title="SQL injection in login",
            sast=SastBlock(
                rule_id="js.sqli.basic",
                file_path="routes/login.ts",
                line=17,
                score=9.0,
            ),
        ),
    ])


logs_dir = Path("/logs")

gateway_state = GatewayState(
    logs_dir=logs_dir,
)

gateway_state.load_vulnerabilities(
    _seed_registry()
)

app = create_agent_gateway_app(
    gateway_state
)