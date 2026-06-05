const fs = require('fs');

const events =
  JSON.parse(
    fs.readFileSync('events.json')
  );

const results = [];

events.forEach(event => {

  let score = 0;

  if (event.trust_score < 0.60)
    score += 2;

  if (!event.identity_valid)
    score += 2;

  if (event.runtime_anomaly)
    score += 1;

  if (event.trace_violation)
    score += 1;

  if (event.invocation_count > 7)
    score += 1;

  const prediction =
    score >= 3
      ? 'ATTACK'
      : 'BENIGN';

  results.push({
    actual: event.label,
    predicted: prediction
  });
});

fs.writeFileSync(
  'caebpf_results.json',
  JSON.stringify(results, null, 2)
);

console.log('CA-eBPF detector complete');