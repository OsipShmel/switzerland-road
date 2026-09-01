from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI

from sandboxd.api.agent_gateway.routes.errors import sandboxd_api_error_handler
from sandboxd.api.agent_gateway.routes import check_session, flag, agent_log
from sandboxd.api.agent_gateway.state import GatewayState
from sandboxdapi.errors import SandboxdApiError


def create_agent_gateway_app(gateway_state: GatewayState) -> FastAPI:

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        gateway_state.bind_event_loop(asyncio.get_running_loop())
        await gateway_state.load_current_registry()
        yield

    app = FastAPI(
        title="sandbox-daemon agent gateway",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.gateway_state = gateway_state

    app.add_exception_handler(
        SandboxdApiError,
        sandboxd_api_error_handler,
    )
    app.include_router(check_session.router)
    app.include_router(flag.router)
    app.include_router(agent_log.router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
