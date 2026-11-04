/**
 * End-to-end self-test. Starts nothing itself — start the two servers first:
 *   TCP_MONITOR=off node demo-app-server.js        (terminal 1)
 *   TCP_MONITOR=off node proxy-server.js           (terminal 2, same machine is fine for this test)
 * then:  node tools/selftest.js
 * (TCP_MONITOR is off here because this test checks the HTTP/ML layer; run
 * tools/selftest-tcp.js separately for the TCP layer, which needs it ON.)
 */
const { makeClient, BENIGN, ATTACK, CHROME } = require('./traffic-profiles');
const assert = require('assert');
let pass = 0, fail = 0;
function check(name, cond, detail) {
  if (cond) { pass++; console.log('  OK  ', name); }
  else { fail++; console.log('  FAIL', name, detail || ''); }
}

(async () => {
  console.log('1. Legitimate traffic stays allowed');
  for (const [name, fn] of Object.entries(BENIGN)) {
    const c = makeClient({ ua: CHROME[0] });
    await fn(c, 10);
    const blocked = (c.stats.tiers.block || 0) > 0;
    check(`  ${name}: never blocked`, !blocked, JSON.stringify(c.stats.tiers));
    c.destroy();
  }

  console.log('2. Attack traffic gets blocked quickly');
  for (const [name, fn] of Object.entries(ATTACK)) {
    const c = makeClient({ ua: name === 'slowBot' ? 'python-requests/2.31' : CHROME[0] });
    await fn(c, 6);
    check(`  ${name}: reached block tier`, (c.stats.tiers.block || 0) > 0, JSON.stringify(c.stats.tiers));
    check(`  ${name}: blocked within 15 requests`, c.stats.firstBlockAt && c.stats.firstBlockAt.req <= 15, JSON.stringify(c.stats.firstBlockAt));
    c.destroy();
  }

  console.log('3. Block is a fixed sentence (does not reset on continued traffic)');
  {
    const c = makeClient({ ua: CHROME[0] });
    await ATTACK.sameUrlFlood(c, 3);
    const r1 = await fetch('http://localhost:8080/', { headers: { 'User-Agent': CHROME[0] } });
    const until1 = r1.headers.get('x-block-until');
    await new Promise((r) => setTimeout(r, 500));
    const r2 = await fetch('http://localhost:8080/', { headers: { 'User-Agent': CHROME[0] } });
    const until2 = r2.headers.get('x-block-until');
    check('  blockedUntil unchanged by extra traffic', until1 && until1 === until2, `${until1} vs ${until2}`);
    c.destroy();
  }

  console.log('Done.', pass, 'passed,', fail, 'failed.');
  process.exit(fail ? 1 : 0);
})();
