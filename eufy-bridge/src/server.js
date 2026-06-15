const express = require('express');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const { WebSocketServer } = require('ws');
const { EufySecurity } = require('eufy-security-client');

const DATA_DIR = process.env.EUFY_DATA_DIR || '/data';
const OPTIONS_FILE = path.join(DATA_DIR, 'options.json');
const TOKEN_FILE = path.join(DATA_DIR, 'bridge_token');

function loadPort() {
  try {
    return JSON.parse(fs.readFileSync(OPTIONS_FILE, 'utf8')).port || 8787;
  } catch {
    return Number(process.env.PORT) || 8787;
  }
}

function loadOrCreateToken() {
  try {
    const t = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    if (t) return t;
  } catch {}
  const t = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, t, { mode: 0o600 });
  return t;
}

const PORT = loadPort();
const BRIDGE_TOKEN = loadOrCreateToken();

let api = null;
let initPromise = null;
let lastError = null;
let pushConnected = false;

// WebSocket client set — populated dopo lo start del wsServer in fondo al file
const wsClients = new Set();
function broadcast(message) {
  if (wsClients.size === 0) return;
  const payload = JSON.stringify(message);
  for (const ws of wsClients) {
    try { ws.send(payload); }
    catch (e) { console.error('WS send failed:', e.message); }
  }
}

function attachEufyListeners(instance) {
  // Property changes: l'unico che ci interessa oggi è "enabled" (privacy).
  // Invertiamo la semantica per esporre privacyEnabled come boolean naturale.
  instance.on('device property changed', (device, name, value) => {
    if (name === 'enabled' && typeof value === 'boolean') {
      broadcast({
        type: 'privacy_changed',
        serial: device.getSerial(),
        privacyEnabled: !value,
      });
    } else if (name === 'battery' && typeof value === 'number') {
      broadcast({
        type: 'battery_changed',
        serial: device.getSerial(),
        batteryValue: value,
      });
    }
  });

  // Devices added/removed: la lista è cambiata, il client farà un refresh REST.
  instance.on('device added', (device) => {
    broadcast({ type: 'devices_changed', reason: 'added', serial: device.getSerial() });
  });
  instance.on('device removed', (device) => {
    broadcast({ type: 'devices_changed', reason: 'removed', serial: device.getSerial() });
  });

  // Health del bridge verso Eufy.
  instance.on('push connect', () => {
    pushConnected = true;
    broadcast({ type: 'bridge_status', cloudConnected: instance.isConnected(), pushConnected });
  });
  instance.on('push close', () => {
    pushConnected = false;
    broadcast({ type: 'bridge_status', cloudConnected: instance.isConnected(), pushConnected });
  });
  instance.on('connect', () => {
    broadcast({ type: 'bridge_status', cloudConnected: true, pushConnected });
  });
  instance.on('close', () => {
    broadcast({ type: 'bridge_status', cloudConnected: false, pushConnected });
  });
}

async function initEufy({ email, password, country, language }) {
  if (api && api.isConnected()) return;
  const config = {
    username: email,
    password,
    country: country || 'IT',
    language: language || 'it',
    persistentDir: DATA_DIR,
    pollingIntervalMinutes: 10,
    eventDurationSeconds: 10,
  };
  const instance = await EufySecurity.initialize(config);
  instance.getApi().on('connect', async () => {
    try { await instance.refreshCloudData(); }
    catch (e) { console.error('refreshCloudData failed:', e.message); }
  });
  attachEufyListeners(instance);
  await instance.connect();
  await new Promise(r => setTimeout(r, 3000));
  if (!instance.isConnected()) {
    try { instance.close(); } catch {}
    throw new Error('AUTH_FAILED');
  }
  api = instance;
}

async function snapshot() {
  const devices = await api.getDevices();
  return devices.map(d => {
    const out = {
      serial: d.getSerial(),
      name: d.getName(),
      stationSerial: null,
      model: null,
      online: null,
      privacyEnabled: null,
      batteryValue: null,
    };
    try { out.model = d.getModel(); } catch {}
    try { out.stationSerial = d.getStationSerial(); } catch {}
    try { if (typeof d.isOnline === 'function') out.online = d.isOnline(); } catch {}
    try {
      if (d.hasProperty && d.hasProperty('enabled')) {
        const enabled = d.isEnabled();
        if (typeof enabled === 'boolean') out.privacyEnabled = !enabled;
      }
    } catch {}
    try {
      if (typeof d.getBatteryValue === 'function') {
        const v = d.getBatteryValue();
        if (typeof v === 'number') out.batteryValue = v;
      }
    } catch {}
    return out;
  });
}

const app = express();
app.use(express.json());

// Auth middleware: everything except /healthz needs the bridge token
app.use((req, res, next) => {
  if (req.path === '/healthz') return next();
  if (req.header('x-bridge-token') !== BRIDGE_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
});

app.get('/healthz', (req, res) => {
  const connected = !!(api && api.isConnected());
  res.json({
    connected,
    lastError,
    initialised: !!api,
  });
});

app.post('/init', async (req, res) => {
  const { email, password, country, language } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password required' });
  }
  if (api && api.isConnected()) {
    return res.json({ ok: true, alreadyConnected: true });
  }
  if (initPromise) {
    try { await initPromise; return res.json({ ok: true, alreadyConnected: true }); }
    catch (e) { return res.status(409).json({ error: e.message, code: classifyError(e.message) }); }
  }
  initPromise = initEufy({ email, password, country, language }).finally(() => {
    initPromise = null;
  });
  try {
    await initPromise;
    lastError = null;
    res.json({ ok: true });
  } catch (e) {
    lastError = e.message;
    res.status(409).json({ error: e.message, code: classifyError(e.message) });
  }
});

function classifyError(msg) {
  if (/captcha/i.test(msg)) return 'CAPTCHA';
  if (/2fa|otp|verification/i.test(msg)) return '2FA';
  if (/auth/i.test(msg)) return 'AUTH_FAILED';
  return 'UNKNOWN';
}

app.get('/cameras', async (req, res) => {
  if (!api) return res.status(503).json({ error: 'not initialised' });
  try {
    res.json(await snapshot());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/cameras/:serial', async (req, res) => {
  if (!api) return res.status(503).json({ error: 'not initialised' });
  try {
    const cam = (await snapshot()).find(c => c.serial === req.params.serial);
    if (!cam) return res.status(404).json({ error: 'not found' });
    res.json(cam);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/cameras/:serial/privacy', async (req, res) => {
  if (!api) return res.status(503).json({ error: 'not initialised' });
  const { enabled } = req.body || {};
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'enabled must be boolean' });
  }
  try {
    const device = await api.getDevice(req.params.serial);
    const station = await api.getStation(device.getStationSerial());
    // privacyEnabled=true → camera deve essere disabilitata; vice versa
    station.enableDevice(device, !enabled);
    res.json({ ok: true });
  } catch (e) {
    const code = /not supported/i.test(e.message) ? 'NOT_SUPPORTED' :
                 /not found/i.test(e.message) ? 'NOT_FOUND' : 'ERROR';
    res.status(code === 'NOT_FOUND' ? 404 : code === 'NOT_SUPPORTED' ? 501 : 500)
       .json({ error: e.message, code });
  }
});

// Diagnose: raw-property diff between two devices (per identificare property ID
// privacy su modelli nuovi — riproduce checkStatus.js)
app.get('/diagnose/:a/:b', async (req, res) => {
  if (!api) return res.status(503).json({ error: 'not initialised' });
  try {
    const dA = await api.getDevice(req.params.a);
    const dB = await api.getDevice(req.params.b);
    const rawA = dA.rawProperties || {};
    const rawB = dB.rawProperties || {};
    const keys = new Set([...Object.keys(rawA), ...Object.keys(rawB)]);
    const differences = [];
    keys.forEach(k => {
      const oA = rawA[k]; const oB = rawB[k];
      if (oA && oB && oA.value !== oB.value) {
        differences.push({ propertyId: k, valueA: oA.value, valueB: oB.value });
      }
    });
    res.json({ a: dA.getSerial(), b: dB.getSerial(), differences });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function shutdown(signal) {
  console.log(`Received ${signal}, shutting down`);
  try { if (api) api.close(); } catch {}
  for (const ws of wsClients) {
    try { ws.close(); } catch {}
  }
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// http.Server condiviso tra Express e WebSocket per restare su un'unica porta.
const server = http.createServer(app);

// WebSocket server con upgrade manuale per validare il token prima di handshake.
// Il token può arrivare via header X-Bridge-Token (preferito) o querystring ?token=.
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const parsed = url.parse(req.url, true);
  if (parsed.pathname !== '/events') {
    socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
    socket.destroy();
    return;
  }
  const headerToken = req.headers['x-bridge-token'];
  const queryToken = parsed.query.token;
  if (headerToken !== BRIDGE_TOKEN && queryToken !== BRIDGE_TOKEN) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  wsClients.add(ws);
  console.log(`WS client connected (total: ${wsClients.size})`);
  // Hello immediato così il client capisce subito lo stato di salute.
  try {
    ws.send(JSON.stringify({
      type: 'bridge_status',
      cloudConnected: !!(api && api.isConnected()),
      pushConnected,
    }));
  } catch {}
  ws.on('close', () => {
    wsClients.delete(ws);
    console.log(`WS client disconnected (total: ${wsClients.size})`);
  });
  ws.on('error', (err) => {
    console.error('WS error:', err.message);
    wsClients.delete(ws);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Eufy bridge listening on 0.0.0.0:${PORT}`);
  console.log(`WebSocket /events ready`);
  console.log(`Bridge token written to ${TOKEN_FILE}`);
});
