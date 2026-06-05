const fs = require('fs');

const events = [];

function randomChoice(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomInt(min, max) {
  return Math.floor(
    Math.random() * (max - min + 1)
  ) + min;
}

const services = [
  'AuthService',
  'OrderService',
  'BillingService',
  'NotificationService'
];

const benignMessages = [
  'User authenticated',
  'Order created',
  'Billing completed',
  'Notification sent'
];

const suspiciousMessages = [
  'Unauthorized token reuse',
  'Replay attack on billing',
  'InvalidPayload detected',
  'UnknownEventSource received'
];

let id = 1;

//
// BENIGN EVENTS
//

for (let i = 0; i < 1000; i++) {

  const suspiciousBenign =
    Math.random() < 0.08; // 8%

  events.push({
    request_id: `REQ-${id++}`,

    timestamp: Date.now(),

    service: randomChoice(services),

    message: suspiciousBenign
      ? randomChoice([
          'Replay completed successfully',
          'Payload validated successfully'
        ])
      : randomChoice(benignMessages),

    status: suspiciousBenign
      ? randomChoice(['warning', 'success'])
      : 'success',

    trust_score: +(
      Math.random() * 0.45 + 0.55
    ).toFixed(2),

    identity_valid: true,

    runtime_anomaly:
      Math.random() < 0.05,

    trace_violation:
      Math.random() < 0.03,

    invocation_count:
      suspiciousBenign
        ? randomInt(5, 10)
        : randomInt(1, 4),

    trace_path:
      suspiciousBenign
        ? 'API->Auth->Billing->Billing'
        : 'API->Auth->Order->Billing',

    label: 'BENIGN'
  });
} 

//
// OBVIOUS ATTACKS
//

for (let i = 0; i < 200; i++) {

  events.push({
    request_id: `REQ-${id++}`,

    timestamp: Date.now(),

    service: randomChoice(services),

    message:
      randomChoice(suspiciousMessages),

    status:
      randomChoice(['error', 'warning']),

    trust_score: +(
      Math.random() * 0.45
    ).toFixed(2),

    identity_valid:
      Math.random() < 0.85
        ? false
        : true,

    runtime_anomaly:
      Math.random() < 0.90,

    trace_violation:
      Math.random() < 0.90,

    invocation_count:
      randomInt(8, 20),

    trace_path:
      'API->UnknownService->Billing',

    label: 'ATTACK'
  });
}

//
// STEALTH ATTACKS
//

for (let i = 0; i < 100; i++) {

  events.push({
    request_id: `REQ-${id++}`,

    timestamp: Date.now(),

    service: randomChoice(services),

    message:
      randomChoice([
        'Billing completed',
        'Order created',
        'Notification sent'
      ]),

    status:
      randomChoice([
        'success',
        'warning'
      ]),


    trust_score:
  +(Math.random() * 0.35 + 0.50).toFixed(2),

    identity_valid:
      Math.random() < 0.30
        ? false
        : true,

    runtime_anomaly:
      Math.random() < 0.55,

    trace_violation:
      Math.random() < 0.55,

    invocation_count:
      randomInt(3, 12),

    trace_path:
      Math.random() < 0.50
        ? 'API->Auth->Billing->Billing'
        : 'API->Auth->Order->Billing',

    label: 'ATTACK'
  });
}

fs.writeFileSync(
  'events.json',
  JSON.stringify(events, null, 2)
);

console.log(
  `Generated ${events.length} events`
);