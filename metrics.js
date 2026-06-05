const fs = require('fs');

const file =
  process.argv[2];

const results =
  JSON.parse(
    fs.readFileSync(file)
  );

let TP = 0;
let FP = 0;
let TN = 0;
let FN = 0;

results.forEach(r => {

  if (
    r.actual === 'ATTACK' &&
    r.predicted === 'ATTACK'
  ) TP++;

  else if (
    r.actual === 'BENIGN' &&
    r.predicted === 'ATTACK'
  ) FP++;

  else if (
    r.actual === 'BENIGN' &&
    r.predicted === 'BENIGN'
  ) TN++;

  else FN++;
});

const accuracy =
  (TP + TN) /
  (TP + FP + TN + FN);

const precision =
  TP / (TP + FP);

const recall =
  TP / (TP + FN);

const f1 =
  2 * precision * recall /
  (precision + recall);

console.log('\nRESULTS\n');

console.log({ TP, FP, TN, FN });

console.log(
  'Accuracy:',
  (accuracy * 100).toFixed(2) + '%'
);

console.log(
  'Precision:',
  (precision * 100).toFixed(2) + '%'
);

console.log(
  'Recall:',
  (recall * 100).toFixed(2) + '%'
);

console.log(
  'F1:',
  (f1 * 100).toFixed(2) + '%'
);