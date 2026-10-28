/**
 * TCP-layer self-test. Start with TCP_MONITOR on (the default) first:
 *   node demo-app-server.js          (terminal 1)
 *   node proxy-server.js             (terminal 2)
 * then: node tools/selftest-tcp.js
 */
const { execFileSync } = require('child_process');
const path = require('path');
(async () => {
  console.log('1. TCP connection flood -> this IP gets banned, HTTP for it goes down too');
  execFileSync('node', [path.join(__dirname, '..', 'attack-sim', 'tcp-flood-sim.js'), '--count', '60'], { stdio: 'inherit' });
  await new Promise((r) => setTimeout(r, 500));
  const vis = await (await fetch('http://localhost:9000/_console/api/visitors')).json();
  const me = vis.visitors.find((v) => v.ip === '127.0.0.1');
  console.log('  visitor state:', me ? `${me.status} (source: ${me.blockSource})` : 'NOT FOUND');
  console.log(me && me.blocked && me.blockSource === 'tcp' ? '  OK   TCP ban reflected as an HTTP block' : '  FAIL expected blocked + blockSource=tcp');

  let httpDown = false;
  try { await fetch('http://localhost:8080/', { signal: AbortSignal.timeout(1000) }); } catch (e) { httpDown = true; }
  console.log(httpDown ? '  OK   HTTP for this IP is unreachable (site invisible)' : '  FAIL HTTP still reachable');

  console.log('2. Admin unblock immediately restores access');
  await fetch('http://localhost:9000/_console/api/unblock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: '127.0.0.1' }) });
  const r = await fetch('http://localhost:8080/');
  console.log(r.status === 200 ? '  OK   unblocked, site visible again' : `  FAIL status ${r.status}`);
})();
