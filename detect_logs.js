const fs = require('fs');

const events =
  JSON.parse(
    fs.readFileSync('events.json')
  );

const suspiciousKeywords = [
  'Unauthorized',
  'Replay',
  'InvalidPayload',
  'UnknownEventSource'
];

const results = [];

events.forEach(event => {

  let prediction = 'BENIGN';

  for (const keyword of suspiciousKeywords) {

    if (event.message.includes(keyword)) {
      prediction = 'ATTACK';
      break;
    }
  }

  results.push({
    actual: event.label,
    predicted: prediction
  });
});

fs.writeFileSync(
  'logs_results.json',
  JSON.stringify(results, null, 2)
);

console.log('Logs detector complete');