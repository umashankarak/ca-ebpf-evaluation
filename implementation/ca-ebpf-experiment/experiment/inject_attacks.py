"""
CA-eBPF Experiment — Attack Injector
Injects realistic OBVIOUS and STEALTH attack scenarios against the microservices.
All injection timestamps are logged to attack_timestamps.json for ground truth labeling.
"""

import os, sys, json, time, uuid, random, subprocess, argparse
from datetime import datetime, timezone
import requests

ORDER_URL        = os.getenv('ORDER_SERVICE_URL',        'http://order-service:5000')
PAYMENT_URL      = os.getenv('PAYMENT_SERVICE_URL',      'http://payment-service:5001')
USER_PROFILE_URL = os.getenv('USER_PROFILE_SERVICE_URL', 'http://user-profile-service:5002')
ADMIN_URL        = os.getenv('ADMIN_SERVICE_URL',        'http://admin-service:5003')

REQUEST_TIMEOUT  = 5
ATTACK_LOG       = []


def ts():
    return datetime.now(timezone.utc).isoformat()


def log(msg, **kwargs):
    entry = {'timestamp': ts(), 'component': 'attack-injector', 'message': msg, **kwargs}
    print(json.dumps(entry), flush=True)
    return entry


def record_attack(attack_type, attack_category, start_ts, end_ts, **kwargs):
    """Record attack window for ground truth labeling."""
    record = {
        'attack_type':     attack_type,
        'attack_category': attack_category,  # OBVIOUS_ATTACK or STEALTH_ATTACK
        'start_ts':        start_ts,
        'end_ts':          end_ts,
        **kwargs
    }
    ATTACK_LOG.append(record)
    return record


# ============================================================
# OBVIOUS ATTACKS — clear indicators in logs and telemetry
# ============================================================

def attack_token_replay(session):
    """Obvious: Replay an already-used or invalid JWT token."""
    start = ts()
    trace_id = str(uuid.uuid4())[:16]
    log('OBVIOUS_ATTACK: Token replay', attack='token_replay', trace_id=trace_id)

    # Send requests with explicitly invalid/replayed tokens
    invalid_tokens = [
        'REPLAYED_TOKEN_8821',
        'eyJhbGciOiJSUzI1NiJ9.INVALID_PAYLOAD.INVALID_SIG',
        '',           # empty token
        'null',
        'Bearer EXPIRED_TOKEN_2023',
    ]
    for token in invalid_tokens:
        try:
            session.post(f'{ORDER_URL}/order',
                json={'order_id': str(uuid.uuid4())[:8], 'amount': 9999},
                headers={'X-Caller-Service': 'unknown-attacker',
                         'X-Service-Token': token,
                         'X-Trace-Id': trace_id},
                timeout=REQUEST_TIMEOUT)
        except Exception:
            pass
        time.sleep(0.1)

    record_attack('token_replay', 'OBVIOUS_ATTACK', start, ts(),
                  target='order-service', token_type='invalid/replayed')


def attack_unknown_identity(session):
    """Obvious: Requests from completely unknown service identity."""
    start = ts()
    log('OBVIOUS_ATTACK: Unknown service identity')

    unknown_services = ['external-scanner', 'rogue-service', 'pentest-tool',
                        'unknown', 'lateral-movement-bot']
    for svc in unknown_services:
        trace_id = str(uuid.uuid4())[:16]
        for url, port in [(ORDER_URL, 5000), (PAYMENT_URL, 5001)]:
            try:
                session.post(f'{url}/{"order" if port==5000 else "payment"}',
                    json={'order_id': 'ATTACK', 'amount': 0},
                    headers={'X-Caller-Service': svc,
                             'X-Service-Token': 'UNKNOWN',
                             'X-Trace-Id': trace_id},
                    timeout=REQUEST_TIMEOUT)
            except Exception:
                pass
        time.sleep(0.2)

    record_attack('unknown_identity', 'OBVIOUS_ATTACK', start, ts(),
                  target='multiple', identities=unknown_services)


def attack_privilege_escalation_via_exec(namespace='production'):
    """Obvious: Attempt to spawn a shell inside a service pod (privilege escalation)."""
    start = ts()
    log('OBVIOUS_ATTACK: Privilege escalation via kubectl exec')

    try:
        # Get a payment-service pod
        result = subprocess.run(
            ['kubectl', 'get', 'pods', '-n', namespace,
             '-l', 'app=payment-service',
             '-o', 'jsonpath={.items[0].metadata.name}'],
            capture_output=True, text=True, timeout=10
        )
        pod_name = result.stdout.strip()

        if pod_name:
            # Execute unexpected commands inside the pod (triggers process_exec Tetragon event)
            attack_commands = [
                ['kubectl', 'exec', pod_name, '-n', namespace, '--',
                 'sh', '-c', 'id && whoami && uname -a'],
                ['kubectl', 'exec', pod_name, '-n', namespace, '--',
                 'sh', '-c', 'cat /etc/passwd | head -5'],
                ['kubectl', 'exec', pod_name, '-n', namespace, '--',
                 'sh', '-c', 'env | grep -i secret || true'],
            ]
            for cmd in attack_commands:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=5)
                    log(f'Executed: {" ".join(cmd[-3:])}',
                        pod=pod_name, attack_type='process_spawn')
                except Exception:
                    pass
                time.sleep(0.5)
    except Exception as e:
        log(f'Privilege escalation attempt: {e}')

    record_attack('privilege_escalation', 'OBVIOUS_ATTACK', start, ts(),
                  method='kubectl_exec', target_service='payment-service')


def attack_cross_namespace(session):
    """Obvious: Access from a pod claiming to be from a different namespace."""
    start = ts()
    log('OBVIOUS_ATTACK: Cross-namespace identity violation')

    for _ in range(10):
        trace_id = str(uuid.uuid4())[:16]
        try:
            # Claim to be from a different namespace
            session.post(f'{PAYMENT_URL}/payment',
                json={'order_id': 'CROSS_NS', 'amount': 1},
                headers={'X-Caller-Service': 'attacker-ns/order-service',
                         'X-Service-Token': 'CROSS_NAMESPACE_TOKEN',
                         'X-Namespace': 'attacker-namespace',
                         'X-Trace-Id': trace_id},
                timeout=REQUEST_TIMEOUT)
        except Exception:
            pass
        time.sleep(0.3)

    record_attack('cross_namespace', 'OBVIOUS_ATTACK', start, ts(),
                  target='payment-service', claimed_namespace='attacker-namespace')


def attack_admin_direct_access(session):
    """Obvious: Direct access to admin service from non-admin service."""
    start = ts()
    log('OBVIOUS_ATTACK: Unauthorised admin service access')

    attacking_services = ['order-service', 'payment-service', 'user-profile-service']
    for svc in attacking_services:
        trace_id = str(uuid.uuid4())[:16]
        try:
            # Direct access to admin endpoint violates trust boundary
            session.get(f'{ADMIN_URL}/admin/stats',
                headers={'X-Caller-Service': svc,
                         'X-Service-Token': 'STOLEN_TOKEN',
                         'X-Trace-Id': trace_id},
                timeout=REQUEST_TIMEOUT)
            session.get(f'{ADMIN_URL}/admin/config',
                headers={'X-Caller-Service': svc,
                         'X-Service-Token': 'STOLEN_TOKEN',
                         'X-Trace-Id': trace_id},
                timeout=REQUEST_TIMEOUT)
        except Exception:
            pass
        time.sleep(0.2)

    record_attack('admin_direct_access', 'OBVIOUS_ATTACK', start, ts(),
                  target='admin-service', attackers=attacking_services)


def attack_burst_flood(session):
    """Obvious: High-frequency burst attack (abnormal invocation frequency)."""
    start = ts()
    log('OBVIOUS_ATTACK: Burst flood (high invocation frequency)')

    trace_id = str(uuid.uuid4())[:16]
    burst_count = 60  # 60 requests in quick succession

    for i in range(burst_count):
        try:
            session.post(f'{PAYMENT_URL}/payment',
                json={'order_id': f'FLOOD_{i}', 'amount': 1},
                headers={'X-Caller-Service': 'flood-bot',
                         'X-Service-Token': 'FLOOD_TOKEN',
                         'X-Trace-Id': trace_id},
                timeout=2)
        except Exception:
            pass
        time.sleep(0.02)  # ~50 rps

    record_attack('burst_flood', 'OBVIOUS_ATTACK', start, ts(),
                  target='payment-service', burst_count=burst_count, approx_rps=50)


# ============================================================
# STEALTH ATTACKS — deliberately mimic legitimate traffic
# ============================================================

def stealth_slow_credential_abuse(session):
    """
    Stealth: Slow, low-frequency abuse of a valid-looking but stolen credential.
    Mimics normal traffic pattern but accesses wrong resources.
    """
    start = ts()
    log('STEALTH_ATTACK: Slow credential abuse')

    # Use a token that looks valid but belongs to wrong service
    for i in range(15):
        trace_id = str(uuid.uuid4())[:16]
        try:
            # Looks like payment-service but accessing admin (subtle boundary crossing)
            session.get(f'{ADMIN_URL}/admin/stats',
                headers={'X-Caller-Service': 'payment-service',   # valid-looking identity
                         'X-Service-Token':  'valid-looking-token-789',
                         'X-Trace-Id':       trace_id},
                timeout=REQUEST_TIMEOUT)
        except Exception:
            pass
        time.sleep(random.uniform(3.0, 7.0))  # slow, mimics normal pace

    record_attack('slow_credential_abuse', 'STEALTH_ATTACK', start, ts(),
                  target='admin-service', method='slow_rate_valid_identity')


def stealth_trace_path_anomaly(session):
    """
    Stealth: Correct identity but wrong call chain (unexpected trace path).
    E.g., order-service directly calling user-profile (should go via payment).
    """
    start = ts()
    log('STEALTH_ATTACK: Trace path anomaly (unexpected call chain)')

    for i in range(20):
        trace_id = str(uuid.uuid4())[:16]
        try:
            # order-service should NOT call user-profile directly
            session.get(
                f'{USER_PROFILE_URL}/profile/victim_user_{i}',
                headers={
                    'X-Caller-Service': 'order-service',     # valid identity
                    'X-Service-Token':  'traffic-generator', # valid-looking token
                    'X-Trace-Id':       trace_id,
                    # No intermediate payment-service span = broken trace chain
                },
                timeout=REQUEST_TIMEOUT
            )
        except Exception:
            pass
        time.sleep(random.uniform(2.0, 5.0))

    record_attack('trace_path_anomaly', 'STEALTH_ATTACK', start, ts(),
                  target='user-profile-service',
                  anomaly='direct_call_bypassing_payment_service')


def stealth_low_frequency_data_exfil(session):
    """
    Stealth: Low-frequency enumeration of user profiles.
    Frequency within normal range but pattern is anomalous.
    """
    start = ts()
    log('STEALTH_ATTACK: Low-frequency profile enumeration')

    for i in range(25):
        trace_id = str(uuid.uuid4())[:16]
        try:
            # Payment-service identity calling user-profile — looks valid
            # but it's enumerating sequential user IDs (abnormal pattern)
            user_id = f'user_{1000 + i:04d}'  # sequential enumeration
            session.get(
                f'{USER_PROFILE_URL}/profile/{user_id}',
                headers={
                    'X-Caller-Service': 'payment-service',  # correct identity
                    'X-Service-Token':  'traffic-generator',
                    'X-Trace-Id':       trace_id,
                },
                timeout=REQUEST_TIMEOUT
            )
        except Exception:
            pass
        time.sleep(random.uniform(1.5, 4.0))

    record_attack('low_freq_enumeration', 'STEALTH_ATTACK', start, ts(),
                  target='user-profile-service',
                  method='sequential_id_enumeration',
                  count=25, rate_rps_approx=0.4)


def stealth_intermittent_namespace_probe(session):
    """
    Stealth: Intermittent probing with mostly-valid requests mixed with violations.
    Hard to detect because attack requests are rare among normal traffic.
    """
    start = ts()
    log('STEALTH_ATTACK: Intermittent namespace probe')

    for i in range(20):
        trace_id = str(uuid.uuid4())[:16]
        is_attack_req = (i % 5 == 0)  # 1 in 5 requests is an attack

        if is_attack_req:
            # Probe admin with valid-looking service token
            try:
                session.get(f'{ADMIN_URL}/admin/stats',
                    headers={'X-Caller-Service': 'order-service',
                             'X-Service-Token':  'traffic-generator',
                             'X-Trace-Id':       trace_id},
                    timeout=REQUEST_TIMEOUT)
            except Exception:
                pass
        else:
            # Legitimate-looking request to maintain cover
            try:
                session.post(f'{ORDER_URL}/order',
                    json={'order_id': str(uuid.uuid4())[:8], 'amount': 50.0},
                    headers={'X-Caller-Service': 'traffic-generator',
                             'X-Service-Token':  'traffic-generator',
                             'X-Trace-Id':       trace_id},
                    timeout=REQUEST_TIMEOUT)
            except Exception:
                pass

        time.sleep(random.uniform(2.0, 6.0))

    record_attack('intermittent_probe', 'STEALTH_ATTACK', start, ts(),
                  target='admin-service', attack_ratio='1:5',
                  description='attacks_mixed_with_legitimate_traffic')


def stealth_identity_mimicry(session):
    """
    Stealth: Attacker knows valid service name and uses it with a slightly-off token.
    Identity claim looks valid but behavioral patterns deviate subtly.
    """
    start = ts()
    log('STEALTH_ATTACK: Identity mimicry with subtle behavioral deviation')

    for i in range(20):
        trace_id = str(uuid.uuid4())[:16]
        try:
            # Correct service name, slightly wrong token format
            # Unusual: accessing payment directly with profile data
            session.post(
                f'{PAYMENT_URL}/payment',
                json={
                    'order_id':   f'MIMIC_{i:04d}',
                    'amount':     random.uniform(10, 100),    # normal-looking amount
                    'user_id':    f'admin_user_{i}',          # subtle anomaly
                    'extra_flag': 'exfiltrate_profile_data',  # unusual payload field
                },
                headers={
                    'X-Caller-Service': 'order-service',   # valid name
                    'X-Service-Token':  'order-svc-token',  # plausible token
                    'X-Trace-Id':       trace_id,
                },
                timeout=REQUEST_TIMEOUT
            )
        except Exception:
            pass
        time.sleep(random.uniform(1.0, 3.5))

    record_attack('identity_mimicry', 'STEALTH_ATTACK', start, ts(),
                  target='payment-service',
                  method='valid_name_deviant_behavior')


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='CA-eBPF Attack Injector')
    parser.add_argument('--mode', choices=['obvious', 'stealth', 'both'],
                        default='both', help='Attack mode')
    parser.add_argument('--output', type=str,
                        default='attack_timestamps.json',
                        help='Output file for attack timestamps (ground truth)')
    parser.add_argument('--namespace', type=str, default='production')
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({'Content-Type': 'application/json'})

    log('=== CA-eBPF Attack Injector Starting ===',
        mode=args.mode, namespace=args.namespace)

    if args.mode in ('obvious', 'both'):
        log('--- Phase: OBVIOUS ATTACKS ---')
        attack_token_replay(session);              time.sleep(2)
        attack_unknown_identity(session);          time.sleep(2)
        attack_cross_namespace(session);           time.sleep(2)
        attack_admin_direct_access(session);       time.sleep(2)
        attack_burst_flood(session);               time.sleep(2)
        attack_privilege_escalation_via_exec(args.namespace); time.sleep(5)
        log('Obvious attacks complete', count=len(ATTACK_LOG))

    if args.mode in ('stealth', 'both'):
        log('--- Phase: STEALTH ATTACKS ---')
        stealth_slow_credential_abuse(session);         time.sleep(3)
        stealth_trace_path_anomaly(session);            time.sleep(3)
        stealth_low_frequency_data_exfil(session);      time.sleep(3)
        stealth_intermittent_namespace_probe(session);  time.sleep(3)
        stealth_identity_mimicry(session);              time.sleep(3)
        log('Stealth attacks complete', count=len(ATTACK_LOG))

    # Save ground truth attack log
    with open(args.output, 'w') as f:
        json.dump({
            'generated_at':    ts(),
            'total_attacks':   len(ATTACK_LOG),
            'obvious_count':   sum(1 for a in ATTACK_LOG if a['attack_category'] == 'OBVIOUS_ATTACK'),
            'stealth_count':   sum(1 for a in ATTACK_LOG if a['attack_category'] == 'STEALTH_ATTACK'),
            'attacks':         ATTACK_LOG,
        }, f, indent=2)

    log('Attack log saved', output=args.output, total=len(ATTACK_LOG))
    print(f"\nAttack timestamps saved to: {args.output}", flush=True)


if __name__ == '__main__':
    main()
