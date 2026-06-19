"""
Admin Service — CA-eBPF Experiment
Privileged management service. High-value trust boundary target.
Should ONLY be accessed by explicitly authorised admin clients.
Any access from order/payment/user-profile services is a trust boundary violation.
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
    provider = TracerProvider(resource=Resource.create({"service.name": "admin-service"}))
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=os.getenv('OTEL_EXPORTER_OTLP_ENDPOINT','http://localhost:4317'),insecure=True)
    ))
    trace.set_tracer_provider(provider)
except Exception:
    pass

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

SERVICE_NAME   = os.getenv('SERVICE_NAME', 'admin-service')
SERVICE_PORT   = int(os.getenv('SERVICE_PORT', '5003'))
POD_NAME       = os.getenv('POD_NAME', 'unknown')
POD_NAMESPACE  = os.getenv('POD_NAMESPACE', 'production')
NODE_NAME      = os.getenv('NODE_NAME', 'unknown')

# Only admin-client role should access this service
VALID_CALLERS      = {'admin-client', 'admin-operator'}
UNAUTHORISED_CALLERS = {'order-service', 'payment-service', 'user-profile-service'}

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


@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'service': SERVICE_NAME,
                    'pod': POD_NAME, 'timestamp': datetime.now(timezone.utc).isoformat()})


@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    caller_service = request.headers.get('X-Caller-Service', 'unknown')
    caller_token   = request.headers.get('X-Service-Token', '')
    trace_id       = request.headers.get('X-Trace-Id', str(uuid.uuid4())[:16])

    # Detect cross-boundary access from non-admin services
    is_unauthorised_caller = caller_service in UNAUTHORISED_CALLERS
    identity_valid = caller_service in VALID_CALLERS and bool(caller_token)

    log_event('admin_access_attempt', 'Admin endpoint access attempt',
              caller_service=caller_service,
              identity_valid=identity_valid,
              unauthorised_cross_boundary=is_unauthorised_caller,
              trace_id=trace_id,
              remote_addr=request.remote_addr)

    if is_unauthorised_caller:
        log_event('trust_boundary_violation',
                  f'VIOLATION: {caller_service} attempted admin access — cross-boundary violation',
                  caller_service=caller_service, identity_valid=False,
                  violation_type='cross_service_boundary', trace_id=trace_id)
        return jsonify({'error': 'Access denied — trust boundary violation'}), 403

    if not identity_valid:
        log_event('identity_violation', 'Invalid identity for admin access',
                  caller_service=caller_service, identity_valid=False, trace_id=trace_id)
        return jsonify({'error': 'Unauthorized'}), 401

    log_event('admin_access_granted', 'Admin stats returned to authorised caller',
              caller_service=caller_service, trace_id=trace_id)

    return jsonify({
        'service':    SERVICE_NAME,
        'stats':      {'active_orders': 42, 'processed_payments': 128, 'uptime_s': int(time.time() % 86400)},
        'trace_id':   trace_id,
    })


@app.route('/admin/config', methods=['GET'])
def admin_config():
    caller_service = request.headers.get('X-Caller-Service', 'unknown')
    caller_token   = request.headers.get('X-Service-Token', '')
    trace_id       = request.headers.get('X-Trace-Id', str(uuid.uuid4())[:16])

    is_unauthorised = caller_service in UNAUTHORISED_CALLERS
    identity_valid  = caller_service in VALID_CALLERS and bool(caller_token)

    log_event('admin_config_attempt', 'Admin config access attempt',
              caller_service=caller_service, identity_valid=identity_valid,
              unauthorised_cross_boundary=is_unauthorised, trace_id=trace_id)

    if is_unauthorised or not identity_valid:
        log_event('trust_boundary_violation',
                  f'VIOLATION: {caller_service} attempted config access',
                  caller_service=caller_service, violation_type='config_access', trace_id=trace_id)
        return jsonify({'error': 'Forbidden'}), 403

    return jsonify({'config': 'restricted', 'service': SERVICE_NAME, 'trace_id': trace_id})


if __name__ == '__main__':
    log_event('service_start', f'{SERVICE_NAME} starting — privileged service',
              port=SERVICE_PORT)
    app.run(host='0.0.0.0', port=SERVICE_PORT, threaded=True)
