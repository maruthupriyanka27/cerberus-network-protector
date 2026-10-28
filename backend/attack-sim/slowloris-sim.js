/**
 * Slowloris-style slow-connection simulator.
 *
 * Classic Slowloris: open a connection, send an HTTP request VERY slowly
 * (a header or two, then wait, then another header...) so the connection
 * never completes but also never looks "idle" enough to trip a generic
 * timeout — tying up a server slot indefinitely. This script approximates
 * that by opening connections and then sending nothing at all for longer
 * than tcp-monitor.js's SLOW_DATA_TIMEOUT_MS (4s), which is exactly the
 * pattern that check exists to catch: a connection that never sends its
 * first byte in a reasonable time.
 *
 * Usage:
 *   node attack-sim/slowloris-sim.js
 *   node attack-sim/slowloris-sim.js --count 20 --host localhost --port 8080
 *
 * What you should see:
 *   - In this terminal: each socket logs "opened", then ~4s later
 *     "closed by server" as tcp-monitor.js destroys it for staying silent.
 *   - On the dashboard: "Closed at TCP layer" climbing with
 *     "slowloris:" in its breakdown.
 */

const net = require('net');

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : fallback;
}

const HOST = arg('host', 'localhost');
const PORT = Number(arg('port', 8080));
const COUNT = Number(arg('count', 20));

console.log(`Opening ${COUNT} connections to ${HOST}:${PORT} and sending nothing (classic Slowloris pattern)...`);

for (let i = 0; i < COUNT; i++) {
  const id = i + 1;
  const socket = net.createConnection({ host: HOST, port: PORT }, () => {
    console.log(`[conn ${id}] opened — sending nothing, waiting...`);
  });
  socket.on('close', () => console.log(`[conn ${id}] closed by server`));
  socket.on('error', (err) => console.log(`[conn ${id}] error: ${err.code || err.message}`));
  // Deliberately never write anything — that's the attack.
}
