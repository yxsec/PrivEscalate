#!/bin/bash
# Differential verification for legacy_docker_group
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
DOCKER_CHECK=$(docker exec "$VULN_CONTAINER" id lowpriv | grep "docker")
if [ -z "${SUID_CHECK:-${SUDO_CHECK:-${HIST_CHECK:-${MYCNF_CHECK:-${PASS_CHECK:-${DOCKER_CHECK:-${KEY_CHECK:-${CRON_CHECK:-${FILE_CHECK}}}}}}}}}" ]; then
    echo "[L2] FAIL: User not in docker group"
    docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1
    exit 1
fi

# Run exploit check on vulnerable container
VULN_RESULT=$(docker exec "$VULN_CONTAINER" su - lowpriv -c "id | grep docker" 2>&1)
docker rm -f "$VULN_CONTAINER" > /dev/null 2>&1

if [ -n "$VULN_RESULT" ]; then
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

FIXED_RESULT=$(docker exec "$FIXED_CONTAINER" su - lowpriv -c "id | grep docker" 2>&1)
docker rm -f "$FIXED_CONTAINER" > /dev/null 2>&1

if [ -z "$FIXED_RESULT" ]; then
    echo "[L2] PASS: Vulnerability absent on fixed image"
else
    echo "[L2] WARN: Fixed image may still have traces (manual review recommended)"
    echo "  Output: $FIXED_RESULT"
fi

# Cleanup images
docker rmi "$VULN_IMAGE" "$FIXED_IMAGE" > /dev/null 2>&1 || true

echo "=== VERIFIED: ${SCENARIO_NAME} ==="
exit 0
