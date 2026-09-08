#!/bin/bash
# Run verify.sh for all PrivEscalate environments.
# Usage: bash scripts/verify_environments.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCENARIOS_DIR="$PROJECT_DIR/dataset/scenarios"

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

echo "=== PrivEscalate: Verifying all scenarios ==="
echo ""

for partition in core variants; do
    for scenario_dir in "$SCENARIOS_DIR"/"$partition"/*/; do
        [ -d "$scenario_dir" ] || continue
        scenario_name=$(basename "$scenario_dir")
        TOTAL=$((TOTAL + 1))

        if [ ! -f "$scenario_dir/verify.sh" ]; then
            echo "[$TOTAL] $scenario_name: SKIP (no verify.sh)"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        echo -n "[$TOTAL] $scenario_name: "
        if bash "$scenario_dir/verify.sh" > /dev/null 2>&1; then
            echo "PASS"
            PASSED=$((PASSED + 1))
        else
            echo "FAIL"
            FAILED=$((FAILED + 1))
        fi
    done
done

echo ""
echo "=== Verification Summary ==="
echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED | Skipped: $SKIPPED"

if [ $TOTAL -gt 0 ]; then
    echo "Pass Rate: $(( PASSED * 100 / TOTAL ))%"
fi

exit $FAILED
