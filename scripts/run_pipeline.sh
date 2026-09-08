#!/bin/bash
# Full PrivEscalate construction pipeline.
# Usage: bash scripts/run_pipeline.sh
#
# Prerequisites:
#   export OPENAI_API_KEY="sk-xxx"    # or ANTHROPIC_API_KEY
#   Docker running
#
# Stages:
#   Phase A: generate templates (DataIngester + LLM classification)
#   Phase B: generate environments (Scaffolder + Exploiter + Verifier) --
#            supports multi-process parallelism
#
# Parallelism:
#   PRIVESC_PARALLEL=3  bash scripts/run_pipeline.sh   # 3 workers (default)
#   PRIVESC_PARALLEL=1  bash scripts/run_pipeline.sh   # serial
#   PRIVESC_PARALLEL=5  bash scripts/run_pipeline.sh   # 5 workers

set -e
# Resolve project root (works with both bash and source)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR/.."
PROJECT_ROOT=$(pwd)

# Load .env if present
if [ -f ".env" ]; then
    echo "[loading .env]"
    source .env
fi

echo "================================================"
echo "PrivEscalate Pipeline"
echo "Project: $PROJECT_ROOT"
echo "================================================"

# Dependency check
echo ""
echo "[dependency check]"
# Detect python -- prefer conda python over system python
if [ -n "$PYTHON" ]; then
    :  # User specified
elif [ -x "$HOME/miniconda3/bin/python3" ]; then
    PYTHON="$HOME/miniconda3/bin/python3"
elif [ -x "$HOME/anaconda3/bin/python3" ]; then
    PYTHON="$HOME/anaconda3/bin/python3"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    PYTHON="python"
fi

if $PYTHON -c "import anthropic" 2>/dev/null; then
    echo "  anthropic OK ($(command -v $PYTHON))"
elif $PYTHON -c "import openai" 2>/dev/null; then
    echo "  openai OK ($(command -v $PYTHON))"
else
    echo "  ERROR: install openai or anthropic (pip install openai anthropic)"
    echo "  current python: $(command -v $PYTHON) ($(${PYTHON} --version 2>&1))"
    echo "  hint: try 'conda activate base && bash scripts/run_pipeline.sh'"
    echo "  or:   PYTHON=/path/to/python3 bash scripts/run_pipeline.sh"
    exit 1
fi
docker info > /dev/null 2>&1 && echo "  Docker OK" || { echo "  ERROR: Docker not running"; exit 1; }

# API key check
if [ -z "$OPENAI_API_KEY" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "  ERROR: set OPENAI_API_KEY or ANTHROPIC_API_KEY (or configure .env)"
    exit 1
fi

# Prefer PRIVESC_LLM_PROVIDER/MODEL from .env when present
PROVIDER="${PRIVESC_LLM_PROVIDER:-}"
MODEL="${PRIVESC_LLM_MODEL:-}"

if [ -z "$PROVIDER" ]; then
    if [ -n "$ANTHROPIC_API_KEY" ]; then
        PROVIDER="anthropic"
        MODEL="${MODEL:-claude-opus-4-6}"
    elif [ -n "$OPENAI_API_KEY" ]; then
        PROVIDER="openai"
        MODEL="${MODEL:-gpt-4o}"
    fi
fi

echo "  Provider: $PROVIDER ($MODEL)"
if [ -n "$ANTHROPIC_BASE_URL" ]; then
    echo "  Base URL: $ANTHROPIC_BASE_URL"
fi

LOG_DIR="logs/pipeline"
mkdir -p "$LOG_DIR"

echo ""
echo "================================================"
echo "Phase 0: data index sanity check"
echo "================================================"
$PYTHON scripts/build_all_indices.py --verify 2>&1 | tail -5

echo ""
echo "================================================"
echo "Phase 1: legacy scenario migration"
echo "================================================"
LEGACY_COUNT=$(find dataset/scenarios/core -maxdepth 1 -type d -name "legacy_*" 2>/dev/null | wc -l | tr -d ' ')
echo "  legacy scenarios: $LEGACY_COUNT / 13"
if [ "$LEGACY_COUNT" -lt 13 ]; then
    echo "  running migrate_legacy.py..."
    $PYTHON scripts/migrate_legacy.py
fi

echo ""
echo "================================================"
echo "Phase A: generate templates (discover + LLM classify)"
echo "================================================"
echo "  This step:"
echo "  - GTFOBins: discover exploitable binaries, LLM fine-grained classification"
echo "  - ExploitDB: LLM feasibility tier (L1-L4)"
echo "  - writes one params.json per template under dataset/templates/"
echo "  - does NOT start Docker or generate Dockerfile/exploit"
echo "  - existing templates are skipped (resume-safe)"
echo "  - estimated time: ~40-60 min (enrichment + classification)"
echo ""
EXISTING_TEMPLATES=$(find dataset/templates -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
echo "  current templates: $EXISTING_TEMPLATES"
echo "  expected new:      ~$((1065 - EXISTING_TEMPLATES)) templates (skip if <= 0)"
echo ""
echo "  Continue? (Ctrl+C to cancel, Enter to proceed)"
read -r

# Run DataIngester (discover only, no build)
$PYTHON generate.py \
    --auto-discover all \
    --provider "$PROVIDER" \
    --model "$MODEL" \
    --max-scenarios 0 \
    2>&1 | tee "$LOG_DIR/pipeline_phase_a.log"

NEW_TEMPLATES=$(find dataset/templates -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
echo ""
echo "Phase A complete:"
echo "  templates: $EXISTING_TEMPLATES -> $NEW_TEMPLATES (added $((NEW_TEMPLATES - EXISTING_TEMPLATES)))"
$PYTHON generate.py --show-progress

echo ""
echo "================================================"
echo "Phase B: generate environments (Scaffolder + Exploiter + Verifier)"
echo "================================================"

# Count pending / verified / failed templates
PENDING=$($PYTHON -c "
import json, os
p=v=f=0
for d in os.listdir('dataset/templates'):
    pf = os.path.join('dataset/templates', d, 'params.json')
    if os.path.exists(pf):
        s = json.load(open(pf)).get('status','pending')
        if s == 'verified': v += 1
        elif s == 'failed': f += 1
        else: p += 1
print(f'{p}')
" 2>/dev/null)
VERIFIED=$($PYTHON -c "
import json, os
v=0
for d in os.listdir('dataset/templates'):
    pf = os.path.join('dataset/templates', d, 'params.json')
    if os.path.exists(pf) and json.load(open(pf)).get('status','') == 'verified': v += 1
print(f'{v}')
" 2>/dev/null)
FAILED_T=$($PYTHON -c "
import json, os
f=0
for d in os.listdir('dataset/templates'):
    pf = os.path.join('dataset/templates', d, 'params.json')
    if os.path.exists(pf) and json.load(open(pf)).get('status','') == 'failed': f += 1
print(f'{f}')
" 2>/dev/null)

PARALLEL=${PRIVESC_PARALLEL:-3}

echo "  This step:"
echo "  - generates Dockerfile + exploit.sh per template"
echo "  - triple verification (Build + Exploit Diff + Consistency)"
echo "  - checkpointed; resume-safe on interruption"
echo "  - parallel workers: $PARALLEL"
echo ""
echo "  pending:   ${PENDING:-?}"
echo "  done:      ${VERIFIED:-0} verified / ${FAILED_T:-0} failed"
echo "  per item:  ~1-3 min (LLM + Docker)"
echo "  total:     ~$((${PENDING:-0} * 2 / 60 / PARALLEL)) hours (${PARALLEL}x parallel)"
echo ""
echo "  Continue? (Ctrl+C to cancel, Enter to proceed)"
read -r

if [ "$PARALLEL" -le 1 ]; then
    # ---------- serial mode ----------
    $PYTHON generate.py \
        --all \
        --provider "$PROVIDER" \
        --model "$MODEL" \
        --report "$LOG_DIR/build_report.json" \
        2>&1 | tee "$LOG_DIR/pipeline_phase_b.log"
else
    # ---------- parallel mode: each worker handles 1/N of the templates ----------
    echo ""
    echo "  starting $PARALLEL parallel workers..."
    echo "  logs: $LOG_DIR/pipeline_phase_b_shard_*.log"
    echo ""

    PIDS=()
    # Auto-terminate all workers on Ctrl+C / abnormal exit
    cleanup_workers() {
        echo ""
        echo "  interrupt received, terminating all workers..."
        for pid in "${PIDS[@]}"; do
            kill "$pid" 2>/dev/null
        done
        wait 2>/dev/null
        echo "  all workers terminated"
        exit 1
    }
    trap cleanup_workers INT TERM

    for ((i=0; i<PARALLEL; i++)); do
        $PYTHON generate.py \
            --all \
            --provider "$PROVIDER" \
            --model "$MODEL" \
            --shard "$i/$PARALLEL" \
            --report "$LOG_DIR/build_report_shard_${i}.json" \
            > "$LOG_DIR/pipeline_phase_b_shard_${i}.log" 2>&1 &
        PIDS+=($!)
        echo "  Worker $i/$PARALLEL started (PID $!)"
    done

    echo ""
    echo "  waiting for all workers... (tail -f $LOG_DIR/pipeline_phase_b_shard_*.log to monitor)"
    echo ""

    # Wait for all workers, count failures
    FAIL_COUNT=0
    for ((i=0; i<PARALLEL; i++)); do
        if wait "${PIDS[$i]}"; then
            echo "  Worker $i/$PARALLEL done"
        else
            EXIT_CODE=$?
            echo "  Worker $i/$PARALLEL failed (exit=$EXIT_CODE), see log: $LOG_DIR/pipeline_phase_b_shard_${i}.log"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    done

    # Merge per-shard reports
    $PYTHON -c "
import json, glob, sys, os
LOG_DIR = os.environ.get('LOG_DIR', 'logs/pipeline')
merged = []
for f in sorted(glob.glob(f'{LOG_DIR}/build_report_shard_*.json')):
    try:
        data = json.load(open(f))
        if isinstance(data, list):
            merged.extend(data)
        elif isinstance(data, dict):
            merged.append(data)
    except Exception as e:
        print(f'  Warning: failed to read {f}: {e}', file=sys.stderr)
with open(f'{LOG_DIR}/build_report.json', 'w') as out:
    json.dump(merged, out, indent=2)
print(f'  merged report: {len(merged)} entries -> {LOG_DIR}/build_report.json')
" 2>&1

    if [ "$FAIL_COUNT" -gt 0 ]; then
        echo ""
        echo "  WARNING: $FAIL_COUNT/$PARALLEL worker(s) failed"
        echo "  re-run with PRIVESC_PARALLEL=1 to retry the failed shards (checkpoint resume)"
    fi
fi

echo ""
echo "================================================"
echo "Final stats"
echo "================================================"
$PYTHON generate.py --show-progress
echo ""
CORE_COUNT=$(find dataset/scenarios/core -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
VARIANT_COUNT=$(find dataset/scenarios/variants -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
echo "Core scenarios:    $CORE_COUNT"
echo "Variant scenarios: $VARIANT_COUNT"
echo "Total:             $((CORE_COUNT + VARIANT_COUNT))"

echo ""
echo "================================================"
echo "LLM usage stats"
echo "================================================"
$PYTHON -c "
import json
from pathlib import Path
conv_log = Path('logs/conversations.jsonl')
if not conv_log.exists():
    print('  No conversation log found')
else:
    total_calls = 0
    with open(conv_log) as f:
        for line in f:
            total_calls += 1
    last = None
    with open(conv_log) as f:
        for line in f:
            last = json.loads(line)
    if last:
        tokens = last.get('tokens', {})
        inp = tokens.get('input', 0)
        out = tokens.get('output', 0)
        print(f'  Total LLM calls:    {total_calls}')
        print(f'  Input tokens:       {inp:,}')
        print(f'  Output tokens:      {out:,}')
        model = last.get('model', '')
        pricing = {
            'gpt-4o': (2.50, 10.00),
            'claude-opus-4-6': (15.00, 75.00),
            'claude-sonnet-4-5-20250929': (3.00, 15.00),
        }
        p = pricing.get(model, (5.0, 15.0))
        cost = inp/1e6*p[0] + out/1e6*p[1]
        print(f'  Estimated cost:     \${cost:.2f}')
        print(f'  Conversation log:   {conv_log}')
" 2>&1

echo ""
echo "Log files:"
echo "  Pipeline log A:    $LOG_DIR/pipeline_phase_a.log"
echo "  Pipeline log B:    $LOG_DIR/pipeline_phase_b.log"
echo "  LLM conversations: logs/conversations.jsonl"
echo "  Build report:      $LOG_DIR/build_report.json"
echo ""
echo "Next: $PYTHON scripts/run_experiments.py --parallel 3 --dry-run"
