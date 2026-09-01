from __future__ import annotations

import asyncio

import uvicorn

from sandboxd.api.supervisor_gateway.app import SandboxControlService, create_sandbox_control_app
from sandboxd.config.settings import settings


async def _serve(app) -> None:
    socket_path = settings.control_socket
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()

    tcp_config = uvicorn.Config(
        app,
        host=settings.supervisor_api_host,
        port=settings.supervisor_api_port,
        log_level="info",
    )
    uds_config = uvicorn.Config(app, uds=str(socket_path), log_level="info")
    tcp_server = uvicorn.Server(tcp_config)
    uds_server = uvicorn.Server(uds_config)

    try:
        await asyncio.gather(tcp_server.serve(), uds_server.serve())
    finally:
        if socket_path.exists():
            socket_path.unlink()


def main() -> None:
    service = SandboxControlService(settings)
    app = create_sandbox_control_app(service)
    asyncio.run(_serve(app))


if __name__ == "__main__":
    main()
