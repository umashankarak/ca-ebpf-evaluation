"""
User Profile Service — CA-eBPF Experiment
Returns customer profile data. Accepts calls only from payment-service.
"""

import os, sys, json, time, uuid, logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify

from opentelemetry.instrumentation.flask import FlaskInstrumentor
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    provider = TracerProvider(resource=Resource.create({"service.name": "user-profile-service"}))
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT','http://localhost:4317'),insecure=True)
    ))
    trace.set_tracer_provider(provider)
except Exception:
    pass

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

SERVICE_NAME   = os.getenv('SERVICE_NAME', 'user-profile-service')
SERVICE_PORT   = int(os.getenv('SERVICE_PORT', '5002'))
POD_NAME       = os.getenv('POD_NAME', 'unknown')
POD_NAMESPACE  = os.getenv('POD_NAMESPACE', 'production')
NODE_NAME      = os.getenv('NODE_NAME', 'unknown')

VALID_CALLERS = {'payment-service'}

logging.basicConfig(level=logging.INFO, stream=sys.stdout)


def log_event(event_type, message, **kwargs):
    print(json.dumps({
        'timestamp':   datetime.now(timezone.utc).isoformat(),
        'service':     SERVICE_NAME,
        'pod':         POD_NAME,
        'namespace':   POD_NAMESPACE,
        'node':        NODE_NAME,
        'event_type':  event_type,
        'message':     message,
        **kwargs
    }), flush=True)


def validate_caller(caller_service, caller_token):
    return caller_service in VALID_CALLERS and bool(caller_token)


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': SERVICE_NAME,
                    'pod': POD_NAME, 'timestamp': datetime.now(timezone.utc).isoformat()})


@app.route('/profile/<user_id>', methods=['GET'])
def get_profile(user_id):
    start_time     = time.monotonic()
    caller_service = request.headers.get('X-Caller-Service', 'unknown')
    caller_token   = request.headers.get('X-Service-Token', '')
    trace_id       = request.headers.get('X-Trace-Id', str(uuid.uuid4())[:16])

    identity_valid = validate_caller(caller_service, caller_token)

    log_event('request_received', 'Profile lookup request received',
              user_id=user_id, caller_service=caller_service,
              identity_valid=identity_valid, trace_id=trace_id,
              remote_addr=request.remote_addr)

    if not identity_valid:
        log_event('identity_violation', 'Unauthorized caller rejected',
                  caller_service=caller_service, identity_valid=False,
                  trace_id=trace_id)
        return jsonify({'error': 'Unauthorized caller'}), 403

    latency = (time.monotonic() - start_time) * 1000
    log_event('request_processed', 'Profile lookup completed',
              user_id=user_id, latency_ms=round(latency, 2),
              trace_id=trace_id,
              trace_path='order-service->payment-service->user-profile-service')

    return jsonify({
        'user_id':   user_id,
        'name':      f'User {user_id}',
        'status':    'active',
        'service':   SERVICE_NAME,
        'trace_id':  trace_id,
    })


if __name__ == '__main__':
    log_event('service_start', f'{SERVICE_NAME} starting', port=SERVICE_PORT)
    app.run(host='0.0.0.0', port=SERVICE_PORT, threaded=True)
