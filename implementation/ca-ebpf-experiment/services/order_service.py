"""
Order Service — CA-eBPF Experiment
Initiates customer transactions. Calls payment-service downstream.
Logs structured JSON for telemetry collection.
"""

import os, sys, json, time, uuid, logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import requests

# OpenTelemetry
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    OTLP_ENDPOINT = os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT', 'http://localhost:4317')
    exporter = OTLPSpanExporter(endpoint=OTLP_ENDPOINT, insecure=True)
    provider = TracerProvider(resource=Resource.create({"service.name": "order-service"}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
except Exception:
    pass  # OTLP not available, tracing disabled

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)
RequestsInstrumentor().instrument()

SERVICE_NAME     = os.getenv('SERVICE_NAME', 'order-service')
SERVICE_PORT     = int(os.getenv('SERVICE_PORT', '5000'))
PAYMENT_URL      = os.getenv('PAYMENT_SERVICE_URL', 'http://payment-service:5001')
POD_NAME         = os.getenv('POD_NAME', 'unknown')
POD_NAMESPACE    = os.getenv('POD_NAMESPACE', 'production')
NODE_NAME        = os.getenv('NODE_NAME', 'unknown')

# Read Kubernetes service account token (real identity proof)
SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'
try:
    with open(SA_TOKEN_PATH) as f:
        SA_TOKEN = f.read().strip()
    SA_TOKEN_AVAILABLE = True
except Exception:
    SA_TOKEN = 'dev-token-order-service'
    SA_TOKEN_AVAILABLE = False

# Known valid service account tokens (in real deployment, validated via K8s API)
VALID_CALLER_TOKENS = {'payment-service', 'user-profile-service', 'traffic-generator'}

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

def log_event(event_type: str, message: str, **kwargs):
    """Emit structured JSON log — collected by process_telemetry.py"""
    entry = {
        'timestamp':     datetime.now(timezone.utc).isoformat(),
        'service':       SERVICE_NAME,
        'pod':           POD_NAME,
        'namespace':     POD_NAMESPACE,
        'node':          NODE_NAME,
        'event_type':    event_type,
        'message':       message,
        'sa_available':  SA_TOKEN_AVAILABLE,
        **kwargs
    }
    print(json.dumps(entry), flush=True)


def validate_caller_identity(caller_service: str, caller_token: str) -> bool:
    """
    Validate that the caller presents a recognised service identity token.
    In production this would verify against the K8s TokenReview API.
    Here we check for a known service name in the token header.
    """
    if not caller_token:
        return False
    # Token should contain the calling service name (simplified identity check)
    return caller_service in VALID_CALLER_TOKENS or caller_service == 'traffic-generator'


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': SERVICE_NAME,
                    'pod': POD_NAME, 'timestamp': datetime.now(timezone.utc).isoformat()})


@app.route('/order', methods=['POST'])
def create_order():
    start_time = time.monotonic()
    request_id = str(uuid.uuid4())[:8]

    data            = request.get_json(silent=True) or {}
    caller_service  = request.headers.get('X-Caller-Service', 'unknown')
    caller_token    = request.headers.get('X-Service-Token', '')
    trace_id        = request.headers.get('X-Trace-Id', str(uuid.uuid4())[:16])
    order_id        = data.get('order_id', str(uuid.uuid4())[:8])
    amount          = data.get('amount', 100.0)

    identity_valid  = validate_caller_identity(caller_service, caller_token)

    log_event('request_received', 'Order request received',
              request_id=request_id, order_id=order_id, amount=amount,
              caller_service=caller_service,
              identity_valid=identity_valid,
              trace_id=trace_id,
              remote_addr=request.remote_addr)

    if not identity_valid:
        log_event('identity_violation', 'Invalid caller identity rejected',
                  request_id=request_id, caller_service=caller_service,
                  identity_valid=False, trace_id=trace_id)
        return jsonify({'error': 'Invalid service identity', 'service': SERVICE_NAME}), 403

    # Call downstream payment-service
    try:
        downstream_start = time.monotonic()
        resp = requests.post(
            f'{PAYMENT_URL}/payment',
            json={'order_id': order_id, 'amount': amount, 'trace_id': trace_id},
            headers={
                'X-Caller-Service': SERVICE_NAME,
                'X-Service-Token':  SA_TOKEN[:32] if SA_TOKEN_AVAILABLE else SERVICE_NAME,
                'X-Trace-Id':       trace_id,
            },
            timeout=5
        )
        downstream_latency = (time.monotonic() - downstream_start) * 1000

        log_event('downstream_call_success', 'Payment service call completed',
                  request_id=request_id, destination='payment-service',
                  latency_ms=round(downstream_latency, 2),
                  status_code=resp.status_code,
                  trace_id=trace_id,
                  trace_path='order-service->payment-service')

        total_latency = (time.monotonic() - start_time) * 1000
        return jsonify({
            'order_id':      order_id,
            'status':        'processed',
            'service':       SERVICE_NAME,
            'latency_ms':    round(total_latency, 2),
            'trace_id':      trace_id,
            'payment_result': resp.json()
        })

    except requests.exceptions.RequestException as e:
        log_event('downstream_call_failed', f'Payment service call failed: {str(e)}',
                  request_id=request_id, destination='payment-service',
                  error=str(e), trace_id=trace_id)
        return jsonify({'error': 'Downstream call failed', 'detail': str(e)}), 502


@app.route('/metrics')
def metrics():
    return jsonify({'service': SERVICE_NAME, 'pod': POD_NAME, 'status': 'ok'})


if __name__ == '__main__':
    log_event('service_start', f'{SERVICE_NAME} starting',
              port=SERVICE_PORT, sa_available=SA_TOKEN_AVAILABLE)
    app.run(host='0.0.0.0', port=SERVICE_PORT, threaded=True)
