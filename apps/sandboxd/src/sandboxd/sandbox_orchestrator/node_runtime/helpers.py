
from __future__ import annotations
from docker.models.containers import Container


# TODO! мне кажется я чем то не тем занимаюсь, не здоровая архитектура выходит вообще
# все под рефакторинг.
def get_ip(container: Container, network: str) -> str:
    container.reload()
    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})

    data = networks.get(network)
    if data is None:
        raise RuntimeError(
            f"container '{container.name}' is not attached to network '{network}'. "
            f"attached: {list(networks.keys())}"
        )

    ip_address = data.get("IPAddress")
    if not ip_address:
        raise RuntimeError(
            f"container '{container.name}' has no IP yet on network '{network}'"
        )

    return ip_address