// One process for hosted deployments (Render etc.): the protected Northbank
// app listens on an internal port, the proxy on the platform's public PORT.
process.env.DEMO_PORT = process.env.DEMO_PORT || '3000';
process.env.DEMO_TARGET = process.env.DEMO_TARGET || `http://127.0.0.1:${process.env.DEMO_PORT}`;
process.env.SINGLE_PORT = process.env.SINGLE_PORT || '1';
require('./demo-app-server');
require('./proxy-server');
