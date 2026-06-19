"""
CA-eBPF Experiment — Normal Traffic Generator
Sends realistic east-west microservice traffic to generate BENIGN events.
Runs from inside the cluster (kubectl exec) or via port-forward.
"""

import os, sys, json, time, uuid, random, argparse, signal
from datetime import datetime, timezone
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---- Configuration ----
ORDER_URL       = os.getenv('ORDER_SERVICE_URL',        'http://order-service:5000')
PAYMENT_URL     = os.getenv('PAYMENT_SERVICE_URL',      'http://payment-service:5001')
USER_PROFILE_URL= os.getenv('USER_PROFILE_SERVICE_URL', 'http://user-profile-service:5002')
ADMIN_URL       = os.getenv('ADMIN_SERVICE_URL',        'http://admin-service:5003')

# Service identity for traffic generator (legitimate caller)
CALLER_TOKEN = 'traffic-generator'
CALLER_NAME  = 'traffic-generator'

# Traffic parameters
NORMAL_RPS       = 2.5    # Average requests per second (normal)
NORMAL_RPS_STD   = 0.5    # Jitter
REQUEST_TIMEOUT  = 5      # seconds

running = True

def signal_handler(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def get_session():
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session


def log(msg, **kwargs):
    print(json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'component': 'traffic-generator',
        'message': msg,
        **kwargs
    }), flush=True)


def make_order_request(session, trace_id=None):
    """Standard order → payment → user-profile chain (normal expected path)."""
    trace_id = trace_id or str(uuid.uuid4())[:16]
    order_id = str(uuid.uuid4())[:8]
    amount   = round(random.uniform(10.0, 500.0), 2)

    try:
        resp = session.post(
            f'{ORDER_URL}/order',
            json={'order_id': order_id, 'amount': amount, 'user_id': f'user_{order_id}'},
            headers={
                'X-Caller-Service': CALLER_NAME,
                'X-Service-Token':  CALLER_TOKEN,
                'X-Trace-Id':       trace_id,
            },
            timeout=REQUEST_TIMEOUT
        )
        return {'success': resp.status_code == 200, 'trace_id': trace_id,
                'status': resp.status_code, 'flow': 'order->payment->user-profile'}
    except Exception as e:
        return {'success': False, 'error': str(e), 'trace_id': trace_id}


def make_health_check(session):
    """Periodic health checks — normal operational traffic."""
    endpoints = [
        (ORDER_URL,        5000, 'order-service'),
        (PAYMENT_URL,      5001, 'payment-service'),
        (USER_PROFILE_URL, 5002, 'user-profile-service'),
    ]
    svc_url, _, svc_name = random.choice(endpoints)
    try:
        resp = session.get(f'{svc_url}/health', timeout=REQUEST_TIMEOUT)
        return {'success': resp.status_code == 200, 'flow': f'health-check->{svc_name}'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def make_direct_payment_request(session, trace_id=None):
    """Direct payment call — simulates legitimate batch processing."""
    trace_id = trace_id or str(uuid.uuid4())[:16]
    try:
        resp = session.post(
            f'{PAYMENT_URL}/payment',
            json={'order_id': str(uuid.uuid4())[:8], 'amount': 99.99,
                  'user_id': 'user_batch01'},
            headers={
                'X-Caller-Service': 'order-service',  # legitimate caller identity
                'X-Service-Token':  CALLER_TOKEN,
                'X-Trace-Id':       trace_id,
            },
            timeout=REQUEST_TIMEOUT
        )
        return {'success': resp.status_code in [200, 403], 'trace_id': trace_id,
                'flow': 'direct-payment'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


REQUEST_TYPES = [
    (0.70, make_order_request),         # 70% full order flow
    (0.20, make_health_check),          # 20% health checks
    (0.10, make_direct_payment_request) # 10% direct payment
]


def main():
    parser = argparse.ArgumentParser(description='CA-eBPF Normal Traffic Generator')
    parser.add_argument('--duration', type=int, default=1200,
                        help='Duration in seconds (default: 1200 = 20 min)')
    parser.add_argument('--rps', type=float, default=NORMAL_RPS,
                        help='Target requests per second (default: 2.5)')
    parser.add_argument('--output', type=str, default=None,
                        help='JSON output file for request log')
    args = parser.parse_args()

    session   = get_session()
    start     = time.monotonic()
    total_req = 0
    success   = 0
    log_entries = []

    log('Traffic generator starting',
        duration_s=args.duration, target_rps=args.rps,
        start_time=datetime.now(timezone.utc).isoformat())

    while running and (time.monotonic() - start) < args.duration:
        # Select request type
        rand = random.random()
        cumulative = 0.0
        req_fn = make_order_request
        for prob, fn in REQUEST_TYPES:
            cumulative += prob
            if rand <= cumulative:
                req_fn = fn
                break

        trace_id = str(uuid.uuid4())[:16]
        t0       = time.monotonic()
        result   = req_fn(session, trace_id) if req_fn != make_health_check else req_fn(session)
        elapsed  = (time.monotonic() - t0) * 1000

        total_req += 1
        if result.get('success'):
            success += 1

        entry = {
            'timestamp':  datetime.now(timezone.utc).isoformat(),
            'event_type': 'BENIGN',
            'flow':       result.get('flow', 'unknown'),
            'trace_id':   result.get('trace_id', trace_id),
            'success':    result.get('success', False),
            'latency_ms': round(elapsed, 2),
            'req_number': total_req,
        }
        log_entries.append(entry)

        if total_req % 50 == 0:
            elapsed_total = time.monotonic() - start
            log(f'Progress: {total_req} requests, '
                f'{success/total_req*100:.1f}% success, '
                f'{total_req/elapsed_total:.1f} rps',
                elapsed_s=round(elapsed_total, 1))

        # Rate limiting
        sleep_time = max(0, (1.0 / args.rps) - (elapsed / 1000))
        sleep_time += random.gauss(0, 0.05)   # add natural jitter
        if sleep_time > 0:
            time.sleep(sleep_time)

    log('Traffic generator complete',
        total_requests=total_req,
        successful=success,
        success_rate=round(success/total_req*100, 1) if total_req else 0,
        duration_s=round(time.monotonic() - start, 1))

    if args.output and log_entries:
        with open(args.output, 'w') as f:
            for entry in log_entries:
                f.write(json.dumps(entry) + '\n')
        print(f"Request log saved: {args.output}", flush=True)


if __name__ == '__main__':
    main()
