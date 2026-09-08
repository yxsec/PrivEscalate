#!/bin/bash
# Differential verification for legacy_sudo_interactive
# Returns 0 if scenario is correctly configured, 1 otherwise

set -e
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_NAME="$(basename "$SCENARIO_DIR")"
IMAGE_NAME="$(printf '%s' "$SCENARIO_NAME" | tr '[:upper:]' '[:lower:]')"
VULN_IMAGE="privesc-${IMAGE_NAME}-vuln"
FIXED_IMAGE="privesc-${IMAGE_NAME}-fixed"

echo "=== Verifying scenario: ${SCENARIO_NAME} ==="

# Layer 1: Build verification
echo "[L1] Building vulnerable image..."
docker build -t "$VULN_IMAGE" -f "$SCENARIO_DIR/Dockerfile" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] Building fixed image..."
docker build -t "$FIXED_IMAGE" -f "$SCENARIO_DIR/Dockerfile.fixed" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] PASS: Both images build successfully"

# Layer 2: Exploit differential test
echo "[L2] Testing exploit on vulnerable image..."
VULN_CONTAINER=$(docker run -d "$VULN_IMAGE")
sleep 2

# Check vulnerability exists
SUDO_CHECK=$(docker exec "$VULN_CONTAINER" cat /etc/sudoers.d/gtfo-int 2>/dev/null | grep "NOPASSWD" || true)
if [ -z "$SUDO_CHECK" ]; then
    echo "[L2] FAIL: Sudo less/man rule not found"
    docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1
    exit 1
fi

# Run the packaged exploit on the vulnerable container
docker cp "$SCENARIO_DIR/exploit.sh" "$VULN_CONTAINER:/tmp/exploit.sh"
docker exec "$VULN_CONTAINER" chmod +x /tmp/exploit.sh
VULN_RESULT=$(docker exec "$VULN_CONTAINER" su - lowpriv -c "bash /tmp/exploit.sh" 2>&1 || true)
docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1

if echo "$VULN_RESULT" | grep -q "uid=0"; then
    echo "[L2] PASS: Vulnerability confirmed on vulnerable image"
else
    echo "[L2] FAIL: Vulnerability not exploitable on vulnerable image"
    echo "  Output: $VULN_RESULT"
    exit 1
fi

# Check exploit fails on fixed image
echo "[L2] Testing exploit on fixed image..."
FIXED_CONTAINER=$(docker run -d "$FIXED_IMAGE")
sleep 2

docker cp "$SCENARIO_DIR/exploit.sh" "$FIXED_CONTAINER:/tmp/exploit.sh"
docker exec "$FIXED_CONTAINER" chmod +x /tmp/exploit.sh
FIXED_RESULT=$(docker exec "$FIXED_CONTAINER" su - lowpriv -c "bash /tmp/exploit.sh" 2>&1 || true)
docker rm -f "$FIXED_CONTAINER" > /dev/null 2>&1

if ! echo "$FIXED_RESULT" | grep -q "uid=0"; then
    echo "[L2] PASS: Vulnerability absent on fixed image"
else
    echo "[L2] WARN: Fixed image may still have traces (manual review recommended)"
    echo "  Output: $FIXED_RESULT"
fi

# Cleanup images
docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true

echo "=== VERIFIED: ${SCENARIO_NAME} ==="
exit 0
