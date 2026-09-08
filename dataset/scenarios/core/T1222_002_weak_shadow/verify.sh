#!/bin/bash
# Differential verification for T1222_002_weak_shadow
set -e
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_NAME="$(basename "$SCENARIO_DIR")"
SCENARIO_LOWER=$(echo "$SCENARIO_NAME" | tr '[:upper:]' '[:lower:]')
VULN_IMAGE="privesc-${SCENARIO_LOWER}-vuln"
FIXED_IMAGE="privesc-${SCENARIO_LOWER}-fixed"

echo "=== Verifying scenario: ${SCENARIO_NAME} ==="

echo "[L1] Building images..."
docker build -t "$VULN_IMAGE" -f "$SCENARIO_DIR/Dockerfile" "$SCENARIO_DIR" > /dev/null 2>&1
docker build -t "$FIXED_IMAGE" -f "$SCENARIO_DIR/Dockerfile.fixed" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] PASS"

echo "[L2] Testing vulnerable image..."
VULN_CONTAINER=$(docker run -d "$VULN_IMAGE")
sleep 2
VULN_PERMS=$(docker exec "$VULN_CONTAINER" stat -c '%a' /etc/shadow)
docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1
if [ "$VULN_PERMS" != "666" ]; then
    echo "[L2] FAIL: /etc/shadow perms=$VULN_PERMS (expected 666)"
    exit 1
fi
echo "[L2] PASS: vuln /etc/shadow=666"

echo "[L2] Testing fixed image..."
FIXED_CONTAINER=$(docker run -d "$FIXED_IMAGE")
sleep 2
FIXED_PERMS=$(docker exec "$FIXED_CONTAINER" stat -c '%a' /etc/shadow)
docker rm -f "$FIXED_CONTAINER" > /dev/null 2>&1
if [ "$FIXED_PERMS" != "640" ]; then
    echo "[L2] FAIL: fixed /etc/shadow perms=$FIXED_PERMS (expected 640)"
    exit 1
fi
echo "[L2] PASS: fixed /etc/shadow=640"

docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true
echo "=== VERIFIED: ${SCENARIO_NAME} ==="
exit 0
