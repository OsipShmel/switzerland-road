from __future__ import annotations

from docker.models.containers import Container

# Да, чатгпт принциально не может в рефакторинг
def get_ip(container: Container, network: str) -> str:
    """Return a container IPv4 address on a named Docker network."""
    container.reload()
    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    data = networks.get(network)
    if data is None:
        raise RuntimeError(
            f"container '{container.name}' is not attached to network '{network}'. "
            f"attached: {list(networks)}"
        )

    address = data.get("IPAddress")
    if not address:
        raise RuntimeError(
            f"container '{container.name}' has no IP yet on network '{network}'"
        )
    return address
