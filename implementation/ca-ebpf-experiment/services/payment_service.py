"""
Payment Service — CA-eBPF Experiment
Processes payment requests from order-service.
Calls user-profile-service for account validation.
"""

import os, sys, json, time, uuid, logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    provider = TracerProvider(resource=Resource.create({"service.name": "payment-service"}))
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT','http://localhost:4317'),insecure=True)
    ))
    trace.set_tracer_provider(provider)
except Exception:
    pass

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)
RequestsInstrumentor().instrument()

SERVICE_NAME          = os.getenv('SERVICE_NAME', 'payment-service')
SERVICE_PORT          = int(os.getenv('SERVICE_PORT', '5001'))
USER_PROFILE_URL      = os.getenv('USER_PROFILE_SERVICE_URL', 'http://user-profile-service:5002')
POD_NAME              = os.getenv('POD_NAME', 'unknown')
POD_NAMESPACE         = os.getenv('POD_NAMESPACE', 'production')
NODE_NAME             = os.getenv('NODE_NAME', 'unknown')

SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'
try:
    with open(SA_TOKEN_PATH) as f:
        SA_TOKEN = f.read().strip()
    SA_TOKEN_AVAILABLE = True
except Exception:
    SA_TOKEN = 'dev-token-payment-service'
    SA_TOKEN_AVAILABLE = False

VALID_CALLERS = {'order-service'}

logging.basicConfig(level=logging.INFO, stream=sys.stdout)


def log_event(event_type, message, **kwargs):
    entry = {
        'timestamp':    datetime.now(timezone.utc).isoformat(),
        'service':      SERVICE_NAME,
        'pod':          POD_NAME,
        'namespace':    POD_NAMESPACE,
        'node':         NODE_NAME,
        'event_type':   event_type,
        'message':      message,
        **kwargs
    }
    print(json.dumps(entry), flush=True)


def validate_caller(caller_service, caller_token):
    return caller_service in VALID_CALLERS and bool(caller_token)


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': SERVICE_NAME,
                    'pod': POD_NAME, 'timestamp': datetime.now(timezone.utc).isoformat()})


@app.route('/payment', methods=['POST'])
def process_payment():
    start_time  = time.monotonic()
    request_id  = str(uuid.uuid4())[:8]
    data        = request.get_json(silent=True) or {}

    caller_service = request.headers.get('X-Caller-Service', 'unknown')
    caller_token   = request.headers.get('X-Service-Token', '')
    trace_id       = request.headers.get('X-Trace-Id', str(uuid.uuid4())[:16])
    order_id       = data.get('order_id', 'unknown')
    amount         = data.get('amount', 0)

    identity_valid = validate_caller(caller_service, caller_token)

    log_event('request_received', 'Payment request received',
              request_id=request_id, order_id=order_id, amount=amount,
              caller_service=caller_service, identity_valid=identity_valid,
              trace_id=trace_id, remote_addr=request.remote_addr)

    if not identity_valid:
        log_event('identity_violation', 'Unauthorized caller rejected',
                  request_id=request_id, caller_service=caller_service,
                  identity_valid=False, trace_id=trace_id)
        return jsonify({'error': 'Unauthorized caller'}), 403

    # Call user-profile-service
    try:
        user_id = data.get('user_id', f'user_{order_id}')
        ds_start = time.monotonic()
        resp = requests.get(
            f'{USER_PROFILE_URL}/profile/{user_id}',
            headers={
                'X-Caller-Service': SERVICE_NAME,
                'X-Service-Token':  SA_TOKEN[:32] if SA_TOKEN_AVAILABLE else SERVICE_NAME,
                'X-Trace-Id':       trace_id,
            },
            timeout=5
        )
        ds_latency = (time.monotonic() - ds_start) * 1000

        log_event('downstream_call_success', 'User profile lookup completed',
                  request_id=request_id, destination='user-profile-service',
                  latency_ms=round(ds_latency, 2), status_code=resp.status_code,
                  trace_id=trace_id,
                  trace_path='order-service->payment-service->user-profile-service')

        total_latency = (time.monotonic() - start_time) * 1000
        return jsonify({
            'order_id':   order_id,
            'amount':     amount,
            'status':     'approved',
            'service':    SERVICE_NAME,
            'latency_ms': round(total_latency, 2),
            'trace_id':   trace_id,
        })

    except requests.exceptions.RequestException as e:
        log_event('downstream_call_failed', f'User profile call failed: {str(e)}',
                  request_id=request_id, destination='user-profile-service',
                  error=str(e), trace_id=trace_id)
        return jsonify({'error': 'Upstream failure', 'detail': str(e)}), 502


if __name__ == '__main__':
    log_event('service_start', f'{SERVICE_NAME} starting', port=SERVICE_PORT)
    app.run(host='0.0.0.0', port=SERVICE_PORT, threaded=True)
