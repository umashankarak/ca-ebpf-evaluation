"""
CA-eBPF Experiment — Telemetry Processing Pipeline
Transforms raw Tetragon eBPF events + service logs → feature CSV

Input files (collect/raw/):
  tetragon_events.jsonl   Raw Tetragon kernel events (process_exec, network kprobes)
  order-service_logs.jsonl
  payment-service_logs.jsonl
  user-profile-service_logs.jsonl
  admin-service_logs.jsonl
  phase2_attack_log.json  Obvious attack ground truth timestamps
  phase3_attack_log.json  Stealth attack ground truth timestamps
  experiment_meta.json    Phase start/end timestamps

Output (collect/output/):
  real_cluster_dataset.csv   Final feature CSV — upload to MDPI as S1-real
  real_cluster_metrics.csv   Per-approach evaluation metrics
  processing_report.json     Full provenance report
"""

import os, sys, json, glob, argparse
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from dateutil import parser as dateparser
import pandas as pd
import numpy as np

RAW_DIR    = os.path.join(os.path.dirname(__file__), 'raw')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output')

NORMAL_BINARIES = {
    '/usr/local/bin/python3', '/usr/local/bin/python',
    '/usr/bin/python3', '/usr/bin/python',
    '/bin/gunicorn', '/usr/local/bin/gunicorn',
    '/usr/bin/curl',    # health checks only
}

ANOMALOUS_BINARIES = {
    '/bin/sh', '/bin/bash', '/bin/dash', '/usr/bin/sh',
    '/usr/bin/wget', '/bin/nc', '/usr/bin/ncat',
    '/usr/bin/perl', '/usr/bin/ruby',
    '/usr/bin/id', '/usr/bin/whoami',
}

EXPECTED_CALL_CHAINS = {
    'order-service':       {'payment-service'},
    'payment-service':     {'user-profile-service'},
    'user-profile-service': set(),
    'admin-service':       set(),
    'traffic-generator':   {'order-service'},
}


def parse_ts(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp to UTC datetime."""
    try:
        dt = dateparser.parse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def load_jsonl(path: str) -> list:
    events = []
    if not os.path.exists(path):
        return events
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def load_attack_log(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get('attacks', [])


def load_experiment_meta(path: str) -> dict:
    meta = {}
    if not os.path.exists(path):
        return meta
    with open(path) as f:
        for line in f:
            try:
                meta.update(json.loads(line))
            except Exception:
                pass
    return meta


# ============================================================
# STEP 1: Parse Tetragon Events
# ============================================================

def parse_tetragon_events(events: list) -> dict:
    """
    Parse Tetragon JSON events into structured feature maps.
    Returns:
      process_execs[pod_name] = list of {timestamp, binary, anomalous}
      network_events[pod_name] = list of {timestamp, src_ip, dst_ip, dport, direction}
    """
    process_execs  = defaultdict(list)
    network_events = defaultdict(list)

    for ev in events:
        try:
            ts_str = ev.get('time', '')
            ts     = parse_ts(ts_str) if ts_str else None

            # --- Process execution events ---
            if 'process_exec' in ev:
                proc  = ev['process_exec'].get('process', {})
                pod   = proc.get('pod', {})
                pod_name   = pod.get('name', '')
                namespace  = pod.get('namespace', '')
                binary     = proc.get('binary', '')
                arguments  = proc.get('arguments', '')

                if namespace == 'production' and pod_name and ts:
                    is_anomalous = any(binary.startswith(ab) for ab in ANOMALOUS_BINARIES)
                    is_expected  = any(binary.startswith(nb) for nb in NORMAL_BINARIES)
                    process_execs[pod_name].append({
                        'timestamp':   ts,
                        'binary':      binary,
                        'arguments':   arguments,
                        'anomalous':   is_anomalous,
                        'expected':    is_expected,
                    })

            # --- Network/kprobe events ---
            if 'process_kprobe' in ev:
                kp   = ev['process_kprobe']
                proc = kp.get('process', {})
                pod  = proc.get('pod', {})
                pod_name  = pod.get('name', '')
                namespace = pod.get('namespace', '')
                fn        = kp.get('function_name', '')

                if namespace == 'production' and pod_name and ts:
                    args = kp.get('args', [])
                    sock_info = {}
                    for arg in args:
                        if 'sock_arg' in arg:
                            sock_info = arg['sock_arg']
                            break

                    network_events[pod_name].append({
                        'timestamp':  ts,
                        'function':   fn,
                        'src_ip':     sock_info.get('saddr', ''),
                        'dst_ip':     sock_info.get('daddr', ''),
                        'sport':      sock_info.get('sport', 0),
                        'dport':      sock_info.get('dport', 0),
                    })

        except Exception:
            continue

    return dict(process_execs), dict(network_events)


# ============================================================
# STEP 2: Parse Service Logs
# ============================================================

def parse_service_logs(raw_dir: str) -> list:
    """Parse structured JSON service logs from all pods."""
    log_events = []
    services = ['order-service', 'payment-service', 'user-profile-service', 'admin-service']

    for svc in services:
        log_path = os.path.join(raw_dir, f'{svc}_logs.jsonl')
        raw_logs = load_jsonl(log_path)

        for entry in raw_logs:
            try:
                ts_str    = entry.get('timestamp', '')
                if not ts_str:
                    continue
                ts        = parse_ts(ts_str)
                event_type= entry.get('event_type', '')
                pod       = entry.get('pod', '')
                namespace = entry.get('namespace', 'production')
                caller    = entry.get('caller_service', entry.get('service', ''))

                log_events.append({
                    'timestamp':        ts,
                    'service':          entry.get('service', svc),
                    'pod':              pod,
                    'namespace':        namespace,
                    'event_type':       event_type,
                    'message':          entry.get('message', ''),
                    'caller_service':   entry.get('caller_service', ''),
                    'identity_valid':   entry.get('identity_valid', True),
                    'trace_id':         entry.get('trace_id', ''),
                    'trace_path':       entry.get('trace_path', ''),
                    'latency_ms':       entry.get('latency_ms', 0.0),
                    'status_code':      entry.get('status_code', 200),
                    'remote_addr':      entry.get('remote_addr', ''),
                    'namespace_violation': event_type in ('trust_boundary_violation', 'cross_namespace_violation'),
                    'identity_violation':  event_type == 'identity_violation',
                })
            except Exception:
                continue

    log_events.sort(key=lambda x: x['timestamp'])
    return log_events


# ============================================================
# STEP 3: Load Attack Ground Truth
# ============================================================

def load_all_attack_windows(raw_dir: str) -> list:
    """Load all attack timestamp windows from phase 2 and 3 logs."""
    windows = []
    for fname in ['phase2_attack_log.json', 'phase3_attack_log.json']:
        path = os.path.join(raw_dir, fname)
        attacks = load_attack_log(path)
        for atk in attacks:
            try:
                windows.append({
                    'start':    parse_ts(atk['start_ts']),
                    'end':      parse_ts(atk['end_ts']),
                    'category': atk['attack_category'],  # OBVIOUS_ATTACK or STEALTH_ATTACK
                    'type':     atk['attack_type'],
                })
            except Exception:
                continue
    return windows


def classify_by_timestamp(ts: datetime, attack_windows: list) -> tuple:
    """Return (label, event_type) for a given timestamp."""
    for window in attack_windows:
        if window['start'] <= ts <= window['end']:
            cat = window['category']
            return (1, cat)
    return (0, 'BENIGN')


# ============================================================
# STEP 4: Build Feature Vectors
# ============================================================

WINDOW_SECONDS = 10  # Group events into 10-second windows

def compute_invocation_frequency(log_events: list, pod: str, window_start: datetime,
                                  window_end: datetime) -> float:
    """Count requests per second for a pod in a time window."""
    count = sum(1 for e in log_events
                if e['pod'] == pod
                and window_start <= e['timestamp'] <= window_end
                and e['event_type'] in ('request_received', 'request_processed'))
    duration = (window_end - window_start).total_seconds()
    return round(count / duration, 3) if duration > 0 else 0.0


def compute_connection_score(log_events: list, pod: str, window_start: datetime,
                              window_end: datetime) -> float:
    """
    Compute connection stability score (0-1) based on success/failure ratio
    and latency stability.
    """
    window_events = [e for e in log_events
                     if e['pod'] == pod
                     and window_start <= e['timestamp'] <= window_end]

    if not window_events:
        return 0.75  # default neutral score

    success_count = sum(1 for e in window_events
                        if e.get('status_code', 200) in (200, 201, 202))
    total = len(window_events)
    if total == 0:
        return 0.75

    success_rate  = success_count / total
    latencies     = [e['latency_ms'] for e in window_events if e.get('latency_ms', 0) > 0]
    latency_score = 1.0
    if latencies:
        mean_lat = np.mean(latencies)
        # Penalise if mean latency > 200ms (abnormal for local cluster)
        latency_score = max(0.0, 1.0 - (mean_lat - 200) / 2000) if mean_lat > 200 else 1.0

    return round(min(1.0, success_rate * 0.7 + latency_score * 0.3), 4)


def check_trace_path_consistent(log_events: list, pod: str, window_start: datetime,
                                  window_end: datetime) -> bool:
    """
    Check if trace paths in this window match expected service call chains.
    Returns False if unexpected direct calls are detected.
    """
    window_events = [e for e in log_events
                     if e['pod'] == pod
                     and window_start <= e['timestamp'] <= window_end
                     and e.get('trace_path')]

    for ev in window_events:
        path   = ev.get('trace_path', '')
        caller = ev.get('caller_service', '')
        svc    = ev.get('service', '')

        # Check if caller is in the expected callers for this service
        expected_callers_for = {
            'payment-service':      {'order-service'},
            'user-profile-service': {'payment-service'},
            'admin-service':        {'admin-client', 'admin-operator'},
        }

        if svc in expected_callers_for and caller:
            if caller not in expected_callers_for[svc] and caller != 'traffic-generator':
                return False  # Unexpected call chain

    return True


def check_namespace_violation(log_events: list, pod: str, window_start: datetime,
                                window_end: datetime) -> bool:
    """Detect namespace violation events in this window."""
    return any(e for e in log_events
               if e['pod'] == pod
               and window_start <= e['timestamp'] <= window_end
               and (e.get('namespace_violation') or e.get('identity_violation')))


def check_process_anomaly(process_execs: dict, pod: str, window_start: datetime,
                           window_end: datetime) -> bool:
    """Detect anomalous process executions (shells, tools) in this window."""
    execs = process_execs.get(pod, [])
    return any(e for e in execs
               if window_start <= e['timestamp'] <= window_end
               and e.get('anomalous'))


def check_runtime_anomaly(log_events: list, process_execs: dict, pod: str,
                           window_start: datetime, window_end: datetime) -> bool:
    """Combined runtime anomaly check."""
    freq = compute_invocation_frequency(log_events, pod, window_start, window_end)
    has_process_anomaly = check_process_anomaly(process_execs, pod, window_start, window_end)
    has_ns_violation    = check_namespace_violation(log_events, pod, window_start, window_end)
    freq_anomaly        = freq > 8.5
    return has_process_anomaly or has_ns_violation or freq_anomaly


def get_identity_valid(log_events: list, pod: str, window_start: datetime,
                        window_end: datetime) -> bool:
    """
    Check identity validity from service logs.
    Any identity_violation event in this window → False.
    """
    violations = [e for e in log_events
                  if e['pod'] == pod
                  and window_start <= e['timestamp'] <= window_end
                  and not e.get('identity_valid', True)]
    return len(violations) == 0


def get_representative_log_message(log_events: list, pod: str,
                                    window_start: datetime, window_end: datetime,
                                    label: int) -> str:
    """Return a representative log message for this event window."""
    window_events = sorted(
        [e for e in log_events
         if e['pod'] == pod
         and window_start <= e['timestamp'] <= window_end],
        key=lambda x: x['timestamp']
    )
    if not window_events:
        return 'No log events in window'

    if label == 1:
        # For attacks, prefer violation/error messages
        for ev in window_events:
            if ev.get('event_type') in ('identity_violation', 'trust_boundary_violation',
                                         'admin_access_attempt', 'downstream_call_failed'):
                return ev.get('message', '')

    # For benign or fallback, return most recent message
    return window_events[-1].get('message', 'Service request processed successfully')


# ============================================================
# STEP 5: Compute Trust Score
# ============================================================

DEFAULT_WEIGHTS = {'wi': 0.30, 'wb': 0.20, 'wn': 0.20, 'wp': 0.15, 'wt': 0.15}


def compute_trust_score(identity_valid, connection_score, invocation_freq,
                         process_anomaly, trace_consistent,
                         runtime_anomaly, namespace_violation, weights=None):
    """Compute Ts from real feature values (same formula as evaluation)."""
    if weights is None:
        weights = DEFAULT_WEIGHTS

    Iv = 1.0 if identity_valid else 0.0
    if namespace_violation:
        Iv = max(0.0, Iv - 0.50)

    Bc = connection_score

    freq_norm = 1.0 - min(1.0, max(0.0, (invocation_freq - 6.0) / 54.0))
    Nt = 0.6 * min(1.0, max(0.0, 1.0 - invocation_freq / 50.0)) + 0.4 * freq_norm

    Pc = 0.0 if process_anomaly else 1.0
    Tr = 1.0 if trace_consistent else 0.0

    Ra = 0.0
    if runtime_anomaly:    Ra += 0.20
    if process_anomaly:    Ra += 0.15
    if namespace_violation:Ra += 0.15
    if not trace_consistent: Ra += 0.10
    if invocation_freq > 8.5: Ra += 0.10

    Ts = (weights['wi'] * Iv + weights['wb'] * Bc +
          weights['wn'] * Nt + weights['wp'] * Pc +
          weights['wt'] * Tr) - Ra

    return round(float(np.clip(Ts, 0.0, 1.0)), 6)


# ============================================================
# STEP 6: Main Processing Pipeline
# ============================================================

def process(raw_dir: str, output_dir: str, verbose: bool = True):
    os.makedirs(output_dir, exist_ok=True)

    def log(msg):
        if verbose:
            print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)

    log("Loading raw data files...")

    # Tetragon events
    tetragon_path  = os.path.join(raw_dir, 'tetragon_events.jsonl')
    tetragon_raw   = load_jsonl(tetragon_path)
    log(f"  Loaded {len(tetragon_raw):,} Tetragon events from {tetragon_path}")

    process_execs, network_events = parse_tetragon_events(tetragon_raw)
    log(f"  Parsed: {sum(len(v) for v in process_execs.values()):,} process exec events")
    log(f"  Parsed: {sum(len(v) for v in network_events.values()):,} network kprobe events")

    # Service logs
    log_events = parse_service_logs(raw_dir)
    log(f"  Loaded {len(log_events):,} service log events")

    # Attack ground truth
    attack_windows = load_all_attack_windows(raw_dir)
    obvious_windows = [w for w in attack_windows if w['category'] == 'OBVIOUS_ATTACK']
    stealth_windows = [w for w in attack_windows if w['category'] == 'STEALTH_ATTACK']
    log(f"  Attack windows: {len(obvious_windows)} obvious, {len(stealth_windows)} stealth")

    # Experiment metadata
    meta = load_experiment_meta(os.path.join(raw_dir, 'experiment_meta.json'))
    log(f"  Experiment metadata: {list(meta.keys())}")

    # Determine time range
    all_timestamps = [e['timestamp'] for e in log_events]
    if not all_timestamps:
        log("ERROR: No service log events found. Check that services are running.")
        sys.exit(1)

    exp_start = min(all_timestamps)
    exp_end   = max(all_timestamps)
    log(f"  Time range: {exp_start.isoformat()} → {exp_end.isoformat()}")

    # Get all unique pods
    pods = list({e['pod'] for e in log_events if e['pod']})
    log(f"  Pods: {pods}")

    # Build feature vectors over time windows
    log("\nBuilding feature vectors (10-second windows per pod)...")

    records = []
    event_id = 0

    current = exp_start
    while current < exp_end:
        window_start = current
        window_end   = current + timedelta(seconds=WINDOW_SECONDS)

        for pod in pods:
            # Only create a record if there was activity in this window
            window_log_events = [e for e in log_events
                                  if e['pod'] == pod
                                  and window_start <= e['timestamp'] <= window_end]
            if not window_log_events:
                current = window_end
                continue

            # Compute features from real telemetry
            identity_valid   = get_identity_valid(log_events, pod, window_start, window_end)
            runtime_anomaly  = check_runtime_anomaly(log_events, process_execs, pod,
                                                      window_start, window_end)
            trace_consistent = check_trace_path_consistent(log_events, pod, window_start, window_end)
            invocation_freq  = compute_invocation_frequency(log_events, pod, window_start, window_end)
            ns_violation     = check_namespace_violation(log_events, pod, window_start, window_end)
            process_anomaly  = check_process_anomaly(process_execs, pod, window_start, window_end)
            connection_score = compute_connection_score(log_events, pod, window_start, window_end)

            # Determine ground truth label
            window_mid    = window_start + timedelta(seconds=WINDOW_SECONDS / 2)
            label, etype  = classify_by_timestamp(window_mid, attack_windows)

            # Compute trust score
            trust_score = compute_trust_score(
                identity_valid, connection_score, invocation_freq,
                process_anomaly, trace_consistent,
                runtime_anomaly, ns_violation
            )

            log_message = get_representative_log_message(
                log_events, pod, window_start, window_end, label
            )

            records.append({
                'event_id':               event_id,
                'timestamp':              window_mid.isoformat(),
                'pod':                    pod,
                'log_message':            log_message,
                'trust_score':            trust_score,
                'identity_valid':         identity_valid,
                'runtime_anomaly':        runtime_anomaly,
                'trace_path_consistent':  trace_consistent,
                'invocation_frequency':   invocation_freq,
                'namespace_violation':    ns_violation,
                'process_anomaly':        process_anomaly,
                'connection_score':       round(connection_score, 6),
                'ground_truth_label':     label,
                'event_type':             etype,
                # Provenance
                'data_source':            'real_kubernetes_cluster',
                'tetragon_events_in_window': len([
                    e for execs in process_execs.values()
                    for e in execs
                    if window_start <= e['timestamp'] <= window_end
                ]),
                'service_log_events_in_window': len(window_log_events),
            })
            event_id += 1

        current = window_end

    log(f"\nGenerated {len(records):,} feature records")

    if not records:
        log("WARNING: No records generated. Check raw data collection.")
        return None

    df = pd.DataFrame(records)

    # Summary
    n_benign  = (df['event_type'] == 'BENIGN').sum()
    n_obvious = (df['event_type'] == 'OBVIOUS_ATTACK').sum()
    n_stealth = (df['event_type'] == 'STEALTH_ATTACK').sum()
    total     = len(df)

    log(f"\nDataset composition:")
    log(f"  BENIGN:         {n_benign:>6} ({n_benign/total*100:.1f}%)")
    log(f"  OBVIOUS_ATTACK: {n_obvious:>6} ({n_obvious/total*100:.1f}%)")
    log(f"  STEALTH_ATTACK: {n_stealth:>6} ({n_stealth/total*100:.1f}%)")
    log(f"  TOTAL:          {total:>6}")

    # Save outputs
    csv_path = os.path.join(output_dir, 'real_cluster_dataset.csv')
    df.to_csv(csv_path, index=False)
    log(f"\nSaved: {csv_path}  ({os.path.getsize(csv_path)//1024} KB)")

    # Processing provenance report
    report = {
        'generated_at':          datetime.now(timezone.utc).isoformat(),
        'data_source':           'real_kubernetes_cluster_kind_on_ec2',
        'kernel_version':        os.popen('uname -r').read().strip(),
        'telemetry_engine':      'cilium_tetragon',
        'experiment_start':      exp_start.isoformat(),
        'experiment_end':        exp_end.isoformat(),
        'total_tetragon_events': len(tetragon_raw),
        'total_service_log_events': len(log_events),
        'total_attack_windows':  len(attack_windows),
        'window_size_seconds':   WINDOW_SECONDS,
        'pods_observed':         pods,
        'total_records':         total,
        'benign_records':        int(n_benign),
        'obvious_attack_records':int(n_obvious),
        'stealth_attack_records':int(n_stealth),
        'trust_score_weights':   DEFAULT_WEIGHTS,
        'trust_score_threshold': 0.65,
        'feature_columns':       [c for c in df.columns if c not in
                                  ('event_id','timestamp','pod','log_message',
                                   'data_source','tetragon_events_in_window',
                                   'service_log_events_in_window')],
    }

    report_path = os.path.join(output_dir, 'processing_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    log(f"Saved: {report_path}")

    log("\n=== Processing Complete ===")
    log(f"Upload to MDPI: {csv_path}")
    return df


def main():
    parser = argparse.ArgumentParser(description='CA-eBPF Telemetry Processor')
    parser.add_argument('--raw-dir',    default=RAW_DIR,    help='Raw data directory')
    parser.add_argument('--output-dir', default=OUTPUT_DIR, help='Output directory')
    parser.add_argument('--quiet',      action='store_true')
    args = parser.parse_args()

    process(args.raw_dir, args.output_dir, verbose=not args.quiet)


if __name__ == '__main__':
    main()
