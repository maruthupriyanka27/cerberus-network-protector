// Proves the exported model gives the same answers in Node as scikit-learn did.
// Usage: node ml/verify-parity.js   (after train_export.py has run)
const fs = require('fs');
const path = require('path');
const model = JSON.parse(fs.readFileSync(path.join(__dirname, 'model.json'), 'utf8'));
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'parity_check.json'), 'utf8'));

function walk(x) {
  let prob = 0; const contrib = new Array(x.length).fill(0);
  for (const t of model.trees) {
    let n = 0;
    while (t.l[n] !== -1) { const nx = x[t.f[n]] <= t.t[n] ? t.l[n] : t.r[n]; contrib[t.f[n]] += t.v[nx] - t.v[n]; n = nx; }
    prob += t.v[n];
  }
  const k = model.trees.length;
  return { prob: prob / k, contrib: contrib.map((c) => c / k) };
}

let worst = 0, worstSum = 0;
fixture.x.forEach((x, i) => {
  const { prob, contrib } = walk(x);
  worst = Math.max(worst, Math.abs(prob - fixture.prob[i]));
  worstSum = Math.max(worstSum, Math.abs(model.bias + contrib.reduce((a, b) => a + b, 0) - prob));
});
console.log(`rows checked: ${fixture.x.length}`);
console.log(`max |node prob - sklearn prob|          = ${worst.toExponential(2)}  (rounding of exported leaf values)`);
console.log(`max |bias + sum(contributions) - prob|  = ${worstSum.toExponential(2)}  (attribution adds up)`);
process.exit(worst < 5e-3 && worstSum < 5e-3 ? 0 : 1);
