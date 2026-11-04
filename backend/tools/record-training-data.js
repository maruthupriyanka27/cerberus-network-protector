/**
 * Generates labelled windows for the ML model from THIS proxy's own traffic.
 *   node tools/record-training-data.js benign|attack  <outfile.jsonl>  [clients=40] [secs=25]
 * Start the proxy first with:
 *   ALLOW_SIM_IDS=1 ML_RECORD=<outfile> ML_RECORD_LABEL=<benign|attack> node proxy-server.js
 * Every simulated visitor has its own id, so the trainer can split by client.
 */
const { makeClient, BENIGN, ATTACK, CHROME, pick, sleep } = require('./traffic-profiles');
(async () => {
  const label = process.argv[2];
  const clients = Number(process.argv[4] || 40), secs = Number(process.argv[5] || 25);
  const set = label === 'attack' ? ATTACK : BENIGN;
  const names = Object.keys(set);
  const jobs = [];
  for (let i = 0; i < clients; i++) {
    const name = names[i % names.length];
    const c = makeClient({ id: `${label}-${name}-${i}-${Math.random().toString(36).slice(2, 6)}`, ua: name === 'slowBot' ? 'python-requests/2.31' : pick(CHROME), keepAlive: name !== 'noKeepAlive', maxSockets: name === 'noKeepAlive' ? 50 : 6 });
    jobs.push((async () => { await sleep(Math.random() * 3000); await set[name](c, secs * (0.6 + Math.random() * 0.8)); c.destroy(); })());
  }
  await Promise.all(jobs);
  console.log('done', label, clients, 'visitors');
})();
