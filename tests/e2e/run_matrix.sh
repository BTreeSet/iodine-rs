#!/usr/bin/env bash
set -euo pipefail

if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  COMPOSE=(docker compose)
fi
PASS="testpass"
SERVER_IP="172.20.0.10"
TUN_SERVER_IP="10.0.0.1"
DOMAIN="testdomain.com"
STARTUP_WAIT_SECONDS="2"

cleanup() {
  docker exec server sh -c '[ -f /tmp/e2e_server.pid ] && kill "$(cat /tmp/e2e_server.pid)" >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
  docker exec client sh -c '[ -f /tmp/e2e_client.pid ] && kill "$(cat /tmp/e2e_client.pid)" >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
  docker exec server rm -f /tmp/e2e_server.pid /tmp/e2e_server.log >/dev/null 2>&1 || true
  docker exec client rm -f /tmp/e2e_client.pid /tmp/e2e_client.log >/dev/null 2>&1 || true
  "${COMPOSE[@]}" down >/dev/null 2>&1 || true
}

wait_for_tun() {
  local container="$1"
  for _ in $(seq 1 20); do
    if docker exec "${container}" sh -c "ip -o link show | grep -Eq ' (iodine[0-9]*|dns[0-9]*):'" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_ping_proof() {
  docker exec client ping -c 3 "$TUN_SERVER_IP" >/dev/null
}

run_stress_ping() {
  docker exec client ping -c 3 -s 1400 "$TUN_SERVER_IP" >/dev/null
}

print_logs() {
  echo "=== server log ==="
  docker exec server sh -c 'cat /tmp/e2e_server.log 2>/dev/null || true' || true
  echo "=== client log ==="
  docker exec client sh -c 'cat /tmp/e2e_client.log 2>/dev/null || true' || true
}

assert_tunnel() {
  if ! wait_for_tun client; then
    print_logs
    return 1
  fi
}

assert_ping() {
  local mode="$1"
  if [[ "$mode" == "stress" ]]; then
    run_stress_ping || {
      print_logs
      return 1
    }
  else
    run_ping_proof || {
      print_logs
      return 1
    }
  fi
}

trap cleanup EXIT

"${COMPOSE[@]}" up -d --build

# Test 1: Rust Server -> C Client
docker exec server sh -c "iodine-server --bind-addr 0.0.0.0:53 --tun-ip ${TUN_SERVER_IP} --topdomain ${DOMAIN} >/tmp/e2e_server.log 2>&1 & echo \$! >/tmp/e2e_server.pid"
sleep "${STARTUP_WAIT_SECONDS}"
docker exec client sh -c "iodine -P ${PASS} ${SERVER_IP} ${DOMAIN} >/tmp/e2e_client.log 2>&1 & echo \$! >/tmp/e2e_client.pid"
assert_tunnel
assert_ping normal
cleanup
"${COMPOSE[@]}" up -d

# Test 2: C Server -> Rust Client
docker exec server sh -c "iodined -c -P ${PASS} ${TUN_SERVER_IP} ${DOMAIN} >/tmp/e2e_server.log 2>&1 & echo \$! >/tmp/e2e_server.pid"
sleep "${STARTUP_WAIT_SECONDS}"
docker exec client sh -c "iodine-client --nameserver ${SERVER_IP}:53 --topdomain ${DOMAIN} >/tmp/e2e_client.log 2>&1 & echo \$! >/tmp/e2e_client.pid"
assert_tunnel
assert_ping normal
cleanup
"${COMPOSE[@]}" up -d

# Test 3: Rust Server -> Rust Client (fragmentation stress)
docker exec server sh -c "iodine-server --bind-addr 0.0.0.0:53 --tun-ip ${TUN_SERVER_IP} --topdomain ${DOMAIN} >/tmp/e2e_server.log 2>&1 & echo \$! >/tmp/e2e_server.pid"
sleep "${STARTUP_WAIT_SECONDS}"
docker exec client sh -c "iodine-client --nameserver ${SERVER_IP}:53 --topdomain ${DOMAIN} >/tmp/e2e_client.log 2>&1 & echo \$! >/tmp/e2e_client.pid"
assert_tunnel
assert_ping stress
