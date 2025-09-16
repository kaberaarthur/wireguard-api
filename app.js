// app.js - WireGuard API
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());

// ------------- CONFIG - replace these ----------------
const PUBLIC_IP = process.env.PUBLIC_IP || 'YOUR_DROPLET_PUBLIC_IP'; // or set via env
const SERVER_PUBLIC_KEY = process.env.SERVER_PUBLIC_KEY || 'YOUR_SERVER_PUBLIC_KEY';
const WG_INTERFACE = process.env.WG_INTERFACE || 'wg0';
const START_PORT = parseInt(process.env.START_PORT || '3001', 10);
const PORT_POOL_END = parseInt(process.env.PORT_POOL_END || '3100', 10); // inclusive
const TARGET_PORT = parseInt(process.env.TARGET_PORT || '8291', 10); // e.g., Winbox
const LISTEN_PORT = parseInt(process.env.LISTEN_PORT || '51820', 10); // wg server listen port
const API_TOKEN = process.env.API_TOKEN || 'change_this_to_a_secret_token';
// path to wireguard keys/dir
const WG_DIR = '/etc/wireguard';
const DB_PATH = path.join(__dirname, 'ports.db');
// -----------------------------------------------------

// helper to run shell commands (sync - simple)
function run(cmd) {
  console.log('RUN:', cmd);
  return execSync(cmd, { encoding: 'utf8' }).trim();
}

// create DB if not exists
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS assignments (
    port INTEGER PRIMARY KEY,
    client_ip TEXT,
    client_pubkey TEXT,
    client_privkey TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// helper: find first free port in pool
function findFreePort(callback) {
  db.all('SELECT port FROM assignments', (err, rows) => {
    if (err) return callback(err);
    const used = new Set(rows.map(r => r.port));
    for (let p = START_PORT; p <= PORT_POOL_END; p++) {
      if (!used.has(p)) return callback(null, p);
    }
    return callback(new Error('No free ports available'));
  });
}

// helper: compute IP for a given port index (10.0.0.X)
function ipForPort(port) {
  // map START_PORT -> 10.0.0.2, START_PORT+1 -> 10.0.0.3, ...
  const index = port - START_PORT + 2; // 2..n
  return `10.0.0.${index}`;
}

// helper: generate WireGuard keypair
function genKeypair() {
  const priv = run(`wg genkey`);
  const pub = run(`echo "${priv}" | wg pubkey`);
  return { priv: priv.trim(), pub: pub.trim() };
}

// helper: add peer to wg0 (sudo)
function addWgPeer(clientPub, clientIp) {
  // allowed-ips is the client's tunnel IP
  const cmd = `sudo wg set ${WG_INTERFACE} peer ${clientPub} allowed-ips ${clientIp}/32`;
  return run(cmd);
}

// helper: remove peer by pubkey
function removeWgPeer(clientPub) {
  const cmd = `sudo wg set ${WG_INTERFACE} peer ${clientPub} remove`;
  return run(cmd);
}

// helpers to add and delete iptables rules with a comment tag
function addIptablesRules(publicPort, clientIp) {
  // use comment to identify rules
  const comment = `wg-api-port-${publicPort}`;
  const dnat = `sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport ${publicPort} -m comment --comment "${comment}" -j DNAT --to-destination ${clientIp}:${TARGET_PORT}`;
  const forward = `sudo iptables -A FORWARD -d ${clientIp} -p tcp --dport ${TARGET_PORT} -m comment --comment "${comment}" -j ACCEPT`;
  run(dnat);
  run(forward);
  run('sudo netfilter-persistent save');
}

function deleteIptablesRules(publicPort, clientIp) {
  const comment = `wg-api-port-${publicPort}`;
  // Try to delete matching rules by matching comment (we construct exact commands to delete).
  // Delete PREROUTING DNAT rule:
  const dnat = `sudo iptables -t nat -D PREROUTING -i eth0 -p tcp --dport ${publicPort} -m comment --comment "${comment}" -j DNAT --to-destination ${clientIp}:${TARGET_PORT}`;
  const forward = `sudo iptables -D FORWARD -d ${clientIp} -p tcp --dport ${TARGET_PORT} -m comment --comment "${comment}" -j ACCEPT`;
  try { run(dnat); } catch (e) { console.warn('DNAT delete may have failed or rule not found'); }
  try { run(forward); } catch (e) { console.warn('FORWARD delete may have failed or rule not found'); }
  run('sudo netfilter-persistent save');
}

// API middleware: token auth (simple)
function checkToken(req, res, next) {
  const token = req.query.token || req.headers['x-api-token'] || (req.body && req.body.token);
  if (!token || token !== API_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/', (req, res) => {
  res.send('WireGuard API is running. Use /create, /remove, /list endpoints with token.');
});

/**
 * POST /create
 * body: { router_name?: string }
 * returns .rsc file content as text
 */
app.post('/create', checkToken, async (req, res) => {
  try {
    // pick a free public port
    const port = await new Promise((resolve, reject) => {
      findFreePort((err, p) => err ? reject(err) : resolve(p));
    });

    const clientIp = ipForPort(port);
    // generate keys
    const keys = genKeypair(); // {priv, pub}

    // add peer to wg
    addWgPeer(keys.pub, clientIp);

    // add iptables rules to forward PUBLIC_IP:port -> clientIp:TARGET_PORT
    addIptablesRules(port, clientIp);

    // persist assignment in DB
    db.run('INSERT INTO assignments (port, client_ip, client_pubkey, client_privkey) VALUES (?, ?, ?, ?)',
      [port, clientIp, keys.pub, keys.priv], (err) => {
        if (err) {
          // rollback: remove wg peer and iptables
          try { removeWgPeer(keys.pub); deleteIptablesRules(port, clientIp); } catch(e){/*ignore*/ }
          return res.status(500).json({ error: 'DB insert error', detail: err.message });
        }

        // Build RouterOS .rsc file
        const rsc = generateRouterOsRsc({
          port,
          clientPriv: keys.priv,
          clientPub: keys.pub,
          clientIp,
          serverPub: SERVER_PUBLIC_KEY,
          serverEndpoint: `${PUBLIC_IP}:${LISTEN_PORT}`
        });

        res.setHeader('Content-Disposition', `attachment; filename="mikrotik-wg-${port}.rsc"`);
        res.setHeader('Content-Type', 'text/plain');
        res.send(rsc);
      });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /remove
 * body: { port: 3001, token: ... }
 * Removes assignment: wg peer removal, iptables cleanup, db delete.
 */
app.post('/remove', checkToken, (req, res) => {
  const port = parseInt(req.body.port, 10);
  if (!port) return res.status(400).json({ error: 'port required' });

  db.get('SELECT * FROM assignments WHERE port = ?', [port], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'not found' });

    try {
      // remove wireguard peer
      removeWgPeer(row.client_pubkey);
      // remove iptables
      deleteIptablesRules(port, row.client_ip);
      // remove DB row
      db.run('DELETE FROM assignments WHERE port = ?', [port], (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        return res.json({ ok: true, removed: port });
      });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });
});

/**
 * GET /list?token=...
 * list current assignments
 */
app.get('/list', checkToken, (req, res) => {
  db.all('SELECT port, client_ip, client_pubkey, created_at FROM assignments ORDER BY port', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

function generateRouterOsRsc({ port, clientPriv, clientPub, clientIp, serverPub, serverEndpoint }) {
  // We configure the MikroTik WireGuard client. Note we set persistent-keepalive to 25.
  // Also we do not force full 0.0.0.0/0 routing by default (commented), but you can uncomment if you want to route everything.
  return `
# RouterOS script created by wireguard-api
/interface wireguard
add name=wg-${port} private-key="${clientPriv}" listen-port=0

/ip address
add address=${clientIp}/32 interface=wg-${port}

# add server as peer
/interface wireguard peers
add interface=wg-${port} public-key="${serverPub}" endpoint-address=${PUBLIC_IP} endpoint-port=${LISTEN_PORT} persistent-keepalive=25 allowed-address=10.0.0.1/32

# Optional: route all traffic through the tunnel
# /ip route add dst-address=0.0.0.0/0 gateway=10.0.0.1
`;
}

// start server
const HTTP_PORT = process.env.HTTP_PORT || 3000;
app.listen(HTTP_PORT, () => {
  console.log(`WireGuard API listening on 0.0.0.0:${HTTP_PORT}`);
  console.log(`Use token via ?token=... or header X-API-TOKEN`);
});
