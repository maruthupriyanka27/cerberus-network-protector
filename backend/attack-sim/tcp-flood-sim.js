/**
 * TCP connection-flood simulator.
 *
 * This is NOT the browser-based Attack Simulator (simulator.html) — that
 * one sends HTTP requests with fetch(), which is an application-layer
 * (L7) test and can't open raw sockets or open them faster than a real
 * page load would. To actually exercise backend/lib/tcp-monitor.js's
 * flood detection, you need something opening many raw TCP connections
 * to the proxy very fast, from one script. That's what this is.
 *
 * What it does: opens a burst of plain `net.Socket` connections to the
 * proxy (default localhost:8080) back-to-back, all from this one process
 * (so they all share this machine's IP — exactly what the flood detector
 * keys on). It does NOT send any HTTP data; just opens connections.
 *
 * Usage:
 *   node attack-sim/tcp-flood-sim.js
 *   node attack-sim/tcp-flood-sim.js --count 50 --host localhost --port 8080
 *
 * What you should see:
 *   - In this terminal: most connections get closed immediately by the
 *     server (ECONNRESET / "socket hang up") — that's tcp-monitor.js
 *     calling socket.destroy() on them.
 *   - On the dashboard: the "Closed at TCP layer" KPI climbing, with
 *     "flood:" in its breakdown — pushed over the same WebSocket the
 *     HTTP decisions use, via { type: 'tcp', kind: 'flood', ... }.
 */

const net = require('net');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : fallback;
}

const HOST = arg('host', 'localhost');
const PORT = Number(arg('port', 8080));
const COUNT = Number(arg('count', 50));

console.log(`Opening ${COUNT} raw TCP connections to ${HOST}:${PORT} as fast as possible...`);

let opened = 0, closed = 0, errored = 0;

for (let i = 0; i < COUNT; i++) {
  const socket = net.createConnection({ host: HOST, port: PORT }, () => {
    opened++;
  });
  socket.on('error', () => { errored++; });
  socket.on('close', () => {
    closed++;
    if (opened + errored >= COUNT && closed >= opened) {
      console.log(`Done. opened=${opened} errored=${errored} closed=${closed}`);
      console.log('Check the dashboard\'s "Closed at TCP layer" KPI — it should have jumped.');
    }
  });
}
