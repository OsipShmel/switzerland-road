from pathlib import Path

from sandboxd.api.app import create_agent_gateway_app
from sandboxd.api.agent_gateway.state import GatewayState

logs_dir = Path("/logs")

gateway_state = GatewayState(
    logs_dir=logs_dir,
)

app = create_agent_gateway_app(
    gateway_state
)
