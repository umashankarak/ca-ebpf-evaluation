#!/bin/bash
# =============================================================
# CA-eBPF Experiment — Step 5: Collect Data + Export CSV
# =============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COLLECT_DIR="$PROJECT_DIR/collect"
RAW_DIR="$COLLECT_DIR/raw"
OUTPUT_DIR="$COLLECT_DIR/output"
NAMESPACE="production"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)] $1${NC}"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] $1${NC}"; }

log "=== CA-eBPF Experiment: Step 5 — Export Data ==="
mkdir -p "$OUTPUT_DIR"

# ---- Ensure Tetragon stream is stopped ----
log "Stopping any active Tetragon streams..."
kill "$(cat "$RAW_DIR/tetragon_stream.pid" 2>/dev/null || echo 0)" 2>/dev/null || true

# ---- Collect any remaining service logs ----
log "Collecting final service logs from all pods..."
for SVC in order-service payment-service user-profile-service admin-service; do
    DEST="$RAW_DIR/${SVC}_logs.jsonl"
    log "  Collecting $SVC logs..."
    kubectl logs -n "$NAMESPACE" \
        -l "app=$SVC" \
        --since=3h \
        2>/dev/null >> "$DEST" || warn "Could not collect $SVC logs"
done

# ---- Collect Tetragon events if not already done ----
if [ ! -s "$RAW_DIR/tetragon_events.jsonl" ]; then
    warn "tetragon_events.jsonl is empty — collecting now..."
    TETRAGON_POD=$(kubectl get pods -n kube-system \
        -l app.kubernetes.io/name=tetragon \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "$TETRAGON_POD" ]; then
        log "Pulling buffered Tetragon events..."
        kubectl exec -n kube-system "$TETRAGON_POD" -c tetragon -- \
            tetra getevents -o json --namespace "$NAMESPACE" \
            --timeout 30s \
            > "$RAW_DIR/tetragon_events.jsonl" 2>/dev/null || true
    fi
fi

# ---- Collect K8s audit events ----
log "Collecting Kubernetes events..."
kubectl get events -n "$NAMESPACE" \
    --sort-by='.lastTimestamp' \
    -o json > "$RAW_DIR/k8s_events.json" 2>/dev/null || true

# ---- Copy raw data summary ----
log "Raw data summary:"
for f in "$RAW_DIR"/*.jsonl "$RAW_DIR"/*.json; do
    [ -f "$f" ] && echo "  $(basename $f): $(wc -l < "$f" 2>/dev/null || echo 0) lines / $(du -h "$f" | cut -f1)"
done

# ---- Copy all raw files to output for MDPI upload ----
cp "$RAW_DIR"/*.jsonl "$OUTPUT_DIR/" 2>/dev/null || true
cp "$RAW_DIR"/*.json  "$OUTPUT_DIR/" 2>/dev/null || true

# ---- Run telemetry processing ----
log "Running telemetry processing pipeline..."
python3 "$COLLECT_DIR/process_telemetry.py" \
    --raw-dir "$RAW_DIR" \
    --output-dir "$OUTPUT_DIR"

# ---- Verify output ----
CSV_PATH="$OUTPUT_DIR/real_cluster_dataset.csv"
if [ -f "$CSV_PATH" ] && [ -s "$CSV_PATH" ]; then
    ROWS=$(wc -l < "$CSV_PATH")
    log "✓ real_cluster_dataset.csv: $((ROWS-1)) records"

    log "Dataset preview (first 3 rows):"
    head -4 "$CSV_PATH" | column -t -s, 2>/dev/null || head -4 "$CSV_PATH"

    log ""
    log "Event type distribution:"
    python3 -c "
import csv, collections
with open('$CSV_PATH') as f:
    rows = list(csv.DictReader(f))
counts = collections.Counter(r['event_type'] for r in rows)
total = len(rows)
for et, n in sorted(counts.items()):
    print(f'  {et:<20}: {n:>6} ({n/total*100:.1f}%)')
print(f'  {\"TOTAL\":<20}: {total:>6}')
"
else
    warn "real_cluster_dataset.csv not generated or empty"
    warn "Check raw data files in $RAW_DIR"
fi

# ---- Generate kernel/system info for provenance ----
log "Collecting system provenance information..."
python3 -c "
import json, subprocess, platform, datetime

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, timeout=5).strip()
    except:
        return 'unavailable'

info = {
    'generated_at':    datetime.datetime.utcnow().isoformat() + 'Z',
    'kernel_version':  platform.uname().release,
    'os':              platform.uname().system + ' ' + platform.uname().version[:80],
    'architecture':    platform.uname().machine,
    'kind_version':    run('kind --version'),
    'kubectl_version': run('kubectl version --client --short 2>/dev/null || kubectl version --client'),
    'tetragon_helm':   run('helm list -n kube-system --filter tetragon -o json 2>/dev/null | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d[0][\\\"app_version\\\"] if d else \\\"unknown\\\")\" 2>/dev/null'),
    'cluster_nodes':   run('kubectl get nodes -o jsonpath=\"{range .items[*]}{.metadata.name} {.status.nodeInfo.kernelVersion}\\n{end}\"'),
    'ebpf_supported':  run('ls /sys/fs/bpf 2>/dev/null && echo yes || echo no'),
}

with open('$OUTPUT_DIR/system_provenance.json', 'w') as f:
    json.dump(info, f, indent=2)
print(json.dumps(info, indent=2))
" 2>/dev/null || warn "Could not collect full system info"

# ---- Final output listing ----
log ""
log "=== Output Files (upload all to MDPI) ==="
ls -lh "$OUTPUT_DIR/" 2>/dev/null

log ""
log "=== Step 5 Complete ==="
log "Files for MDPI upload are in: $OUTPUT_DIR/"
log ""
log "Critical files:"
log "  real_cluster_dataset.csv   — Upload as Supplementary S1-real"
log "  tetragon_events.jsonl      — Raw eBPF kernel events (proof)"
log "  *_logs.jsonl               — Raw service logs (proof)"
log "  processing_report.json     — Full provenance report"
log "  system_provenance.json     — Kernel/cluster version info"
log ""
log "These files prove all data came from a real Kubernetes cluster"
log "running Cilium Tetragon eBPF instrumentation on EC2."
