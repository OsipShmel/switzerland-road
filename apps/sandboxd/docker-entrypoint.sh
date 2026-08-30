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

echo "[sandboxd] configuring intelligent network bridges..."

# 1. Запускаем socat в L1 на 0.0.0.0. Он поймает пакет с любого внутреннего интерфейса.
# Вычисляем IP Мака (L0) динамически через шлюз интерфейса eth0
MAC_HOST_IP=$(ip route show | grep default | awk '{print $3}')
echo "[sandboxd] detected L0 Mac IP: $MAC_HOST_IP"

socat TCP-LISTEN:11434,fork,reuseaddr TCP:${MAC_HOST_IP}:11434 &

# 2. Магия DNS для DinD:
# Чтобы не хардкодить IP моста, мы перехватим вызовы запуска L2 контейнеров.
# Но можно сделать проще: создаем глобальный алиас или используем встроенный DNS dockerd.
# Самый дубовый и рабочий способ в DinD — пропатчить дефолтный docker run, чтобы он подкидывал правильный IP шлюза.
# Но так как ваш оркестратор вызывает Docker API напрямую через сокет, мы просто добавим правило iptables в L1,
# которое перенаправит ВСЕ пакеты на порт 11434, куда бы L2 их ни слал локально!

iptables -t nat -A PREROUTING -p tcp --dport 11434 -j REDIRECT --to-ports 11434

# Способ 1: Если нужно замедлить весь трафик DinD-контейнера наружу (Самый надежный)
echo "[sandboxd] applying 100ms delay to eth0..."
tc qdisc add dev eth0 root netem delay 100ms

# Способ 2 (Альтернативный): Если нужно замедлить только дефолтную Docker-сеть внутри DinD
# echo "[sandboxd] applying 100ms delay to docker0..."
# tc qdisc add dev docker0 root netem delay 100ms

# Способ 3 (Исправление вашей логики): Если вы всё же ищете br-, добавляем '|| true'
# TARGET_BRIDGE=$(ip route show | grep "172.19.0" | awk '{print $3}' | grep br- || true)
# if [ -n "$TARGET_BRIDGE" ]; then
#     echo "[sandboxd] applying 100ms delay to bridge: $TARGET_BRIDGE"
#     tc qdisc add dev "$TARGET_BRIDGE" root netem delay 100ms
# else
#     echo "[sandboxd] WARNING: Target bridge network not found, skipping tc configuration"
# fi

exec "$@"