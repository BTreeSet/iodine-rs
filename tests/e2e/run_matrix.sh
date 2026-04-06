#!/usr/bin/env bash
set -euo pipefail

COMPOSE="docker-compose"
PASS="testpass"
SERVER_IP="172.20.0.10"
TUN_SERVER_IP="10.0.0.1"
DOMAIN="testdomain.com"

cleanup() {
  docker exec server pkill -f "iodine-server|iodined" >/dev/null 2>&1 || true
  docker exec client pkill -f "iodine-client|iodine " >/dev/null 2>&1 || true
  ${COMPOSE} down >/dev/null 2>&1 || true
}

wait_for_tun() {
  local container="$1"
  for _ in $(seq 1 20); do
    if docker exec "${container}" ip link show iodine0 >/dev/null 2>&1; then
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

trap cleanup EXIT

${COMPOSE} up -d

# Test 1: Rust Server -> C Client
docker exec server sh -lc "iodine-server --bind-addr 0.0.0.0:53 --tun-ip ${TUN_SERVER_IP} --topdomain ${DOMAIN}" >/tmp/iodine-server.log 2>&1 &
sleep 2
docker exec client sh -lc "iodine -P ${PASS} ${SERVER_IP} ${DOMAIN}" >/tmp/iodine-c-client.log 2>&1 &
wait_for_tun client
run_ping_proof
cleanup
${COMPOSE} up -d

# Test 2: C Server -> Rust Client
docker exec server sh -lc "iodined -c -P ${PASS} ${TUN_SERVER_IP} ${DOMAIN}" >/tmp/iodined.log 2>&1 &
sleep 2
docker exec client sh -lc "iodine-client --nameserver ${SERVER_IP}:53 --topdomain ${DOMAIN}" >/tmp/iodine-rust-client.log 2>&1 &
wait_for_tun client
run_ping_proof
cleanup
${COMPOSE} up -d

# Test 3: Rust Server -> Rust Client (fragmentation stress)
docker exec server sh -lc "iodine-server --bind-addr 0.0.0.0:53 --tun-ip ${TUN_SERVER_IP} --topdomain ${DOMAIN}" >/tmp/iodine-server-stress.log 2>&1 &
sleep 2
docker exec client sh -lc "iodine-client --nameserver ${SERVER_IP}:53 --topdomain ${DOMAIN}" >/tmp/iodine-rust-client-stress.log 2>&1 &
wait_for_tun client
run_stress_ping
