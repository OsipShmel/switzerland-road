#!/bin/sh
set -eu

echo "[sandboxd] starting inner Docker daemon..."

dockerd \
    --host=unix:///var/run/docker.sock \
    > /var/log/dockerd.log 2>&1 &

DOCKERD_PID=$!

cleanup() {
    echo "[sandboxd] stopping inner Docker daemon..."

    kill "$DOCKERD_PID" 2>/dev/null || true
    wait "$DOCKERD_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

echo "[sandboxd] waiting for inner Docker daemon..."

for i in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then
        echo "[sandboxd] Docker daemon is ready"
        break
    fi

    if ! kill -0 "$DOCKERD_PID" 2>/dev/null; then
        echo "[sandboxd] dockerd died"
        cat /var/log/dockerd.log
        exit 1
    fi

    sleep 1
done

if ! docker info >/dev/null 2>&1; then
    echo "[sandboxd] Docker daemon did not become ready"
    cat /var/log/dockerd.log
    exit 1
fi

echo "[sandboxd] Docker daemon ready"

echo "[sandboxd] applying 100ms delay to eth0..."
tc qdisc add dev eth0 root netem delay 100ms


exec "$@"