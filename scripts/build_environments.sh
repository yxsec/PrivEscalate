#!/bin/bash
# Build all PrivEscalate environment Dockerfiles.
# Usage: bash scripts/build_environments.sh [--fixed]

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCENARIOS_DIR="$PROJECT_DIR/dataset/scenarios"

BUILD_FIXED=false
if [[ "$1" == "--fixed" ]]; then
    BUILD_FIXED=true
fi

TOTAL=0
PASSED=0
FAILED=0

echo "=== PrivEscalate: Building all scenarios ==="
echo ""

for scenario_dir in "$SCENARIOS_DIR"/core/*/; do
    scenario_name=$(basename "$scenario_dir")
    image_name=$(printf '%s' "$scenario_name" | tr '[:upper:]' '[:lower:]')
    TOTAL=$((TOTAL + 1))

    # Build vulnerable version
    echo -n "[$TOTAL] $scenario_name (vuln)... "
    if docker build -t "privesc-$image_name-vuln" -f "$scenario_dir/Dockerfile" "$scenario_dir" > /dev/null 2>&1; then
        echo "OK"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi

    # Optionally build fixed version
    if $BUILD_FIXED && [ -f "$scenario_dir/Dockerfile.fixed" ]; then
        echo -n "[$TOTAL] $scenario_name (fixed)... "
        if docker build -t "privesc-$image_name-fixed" -f "$scenario_dir/Dockerfile.fixed" "$scenario_dir" > /dev/null 2>&1; then
            echo "OK"
        else
            echo "FAIL"
        fi
    fi
done

# Also build variants
for scenario_dir in "$SCENARIOS_DIR"/variants/*/; do
    [ -d "$scenario_dir" ] || continue
    scenario_name=$(basename "$scenario_dir")
    image_name=$(printf '%s' "$scenario_name" | tr '[:upper:]' '[:lower:]')
    TOTAL=$((TOTAL + 1))

    echo -n "[$TOTAL] $scenario_name (variant)... "
    if docker build -t "privesc-$image_name-vuln" -f "$scenario_dir/Dockerfile" "$scenario_dir" > /dev/null 2>&1; then
        echo "OK"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "=== Build Summary ==="
echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED"
echo "Pass Rate: $(( PASSED * 100 / TOTAL ))%"

exit $FAILED
