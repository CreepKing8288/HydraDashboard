const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT;
const MONGODB_URI =
  process.env.MONGODB_URI;
const DB_NAME = 'hydrakeysys';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const sessions = new Map();
const loginAttempts = new Map();

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function scryptHash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + scryptHash(password, salt);
}

function verifyPassword(password, stored) {
  const parts = String(stored || '').split(':');
  if (parts.length !== 2) return false;
  const calc = Buffer.from(scryptHash(password, parts[0]), 'hex');
  const orig = Buffer.from(parts[1], 'hex');
  return calc.length === orig.length && crypto.timingSafeEqual(calc, orig);
}

function getLock(ip) {
  const now = Date.now();
  const lock = loginAttempts.get(ip);
  if (!lock || now > lock.resetAt) {
    const fresh = { count: 0, resetAt: now + 15 * 60 * 1000 };
    loginAttempts.set(ip, fresh);
    return fresh;
  }
  return lock;
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.query.token;
  const session = token ? sessions.get(token) : null;
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'Not authorized.' });
  }
  req.admin = session.username;
  req.token = token;
  next();
}

function makeKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () =>
    Array.from(crypto.randomBytes(4))
      .map((b) => chars[b % chars.length])
      .join('');
  return 'HS-' + seg() + '-' + seg() + '-' + seg();
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const ip = req.ip || 'unknown';
  const lock = getLock(ip);
  if (lock.count >= 5) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }

  const admins = db.collection('admins');
  const admin = await admins.findOne({ username: String(username || '').trim() });
  if (!admin || !verifyPassword(String(password || ''), admin.passwordHash)) {
    lock.count++;
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  loginAttempts.delete(ip);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: admin.username, expires: Date.now() + SESSION_TTL_MS });
  res.json({ token, username: admin.username });
});

app.post('/api/logout', auth, (req, res) => {
  sessions.delete(req.token);
  res.json({ ok: true });
});

app.post('/api/password', auth, async (req, res) => {
  const { current, next } = req.body || {};
  const admins = db.collection('admins');
  const admin = await admins.findOne({ username: req.admin });
  if (!admin || !verifyPassword(String(current || ''), admin.passwordHash)) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }
  const pw = String(next || '');
  if (pw.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters.' });
  }
  await admins.updateOne({ _id: admin._id }, { $set: { passwordHash: hashPassword(pw) } });
  res.json({ ok: true });
});

app.get('/api/keys', auth, async (req, res) => {
  const keys = await db.collection('keys').find({}).project({ _id: 0 }).sort({ createdAt: -1 }).toArray();
  res.json({ keys });
});

app.post('/api/keys', auth, async (req, res) => {
  const { key, expiration, note } = req.body || {};
  const k = String(key || '').trim() || makeKey();
  const exists = await db.collection('keys').findOne({ key: k });
  if (exists) return res.status(409).json({ error: 'Key already exists.' });

  const doc = { key: k, expiration: null, ip: '', note: String(note || '').trim(), createdAt: new Date() };
  if (expiration) {
    const d = new Date(expiration);
    if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid expiration date.' });
    doc.expiration = d;
  }
  await db.collection('keys').insertOne(doc);
  res.json({ ok: true, key: doc.key });
});

app.patch('/api/keys/:key', auth, async (req, res) => {
  const { expiration, ip, note } = req.body || {};
  const set = {};
  if (Object.prototype.hasOwnProperty.call(req.body, 'expiration')) {
    if (expiration) {
      const d = new Date(expiration);
      if (isNaN(d.getTime())) return res.status(400).json({ error: 'Invalid expiration date.' });
      set.expiration = d;
    } else {
      set.expiration = null;
    }
  }
  if (Object.prototype.hasOwnProperty.call(req.body, 'ip')) set.ip = String(ip || '');
  if (Object.prototype.hasOwnProperty.call(req.body, 'note')) set.note = String(note || '');

  const result = await db.collection('keys').updateOne({ key: String(req.params.key) }, { $set: set });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Key not found.' });
  res.json({ ok: true });
});

app.delete('/api/keys/:key', auth, async (req, res) => {
  const result = await db.collection('keys').deleteOne({ key: String(req.params.key) });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Key not found.' });
  res.json({ ok: true });
});

app.get('/download', (req, res) => {
  const file = path.join(__dirname, 'public', 'download', 'Hydra Sploits.exe');
  if (fs.existsSync(file)) return res.download(file, 'Hydra Sploits.exe');
  res.status(404).send('The build has not been uploaded yet.');
});

async function ensureAdmin() {
  const admins = db.collection('admins');
  const count = await admins.countDocuments({});
  if (count === 0) {
    await admins.insertOne({
      username: 'admin',
      passwordHash: hashPassword('admin'),
      createdAt: new Date(),
    });
    console.log('Default admin created: admin / admin  (CHANGE THIS)');
  }
}

let db;
function srvHost() {
  const match = String(MONGODB_URI).match(/@([^/]+)/);
  return match ? match[1] : null;
}

function ensureDns() {
  return new Promise((resolve) => {
    const host = srvHost();
    if (!host) return resolve();
    dns.resolveSrv('_mongodb._tcp.' + host, (err) => {
      if (err && err.code === 'ECONNREFUSED') {
        try {
          dns.setServers(['8.8.8.8', '1.1.1.1']);
          console.log('Default DNS resolver refused SRV queries; using public resolvers.');
        } catch (e) {
          /* ignore */
        }
      }
      resolve();
    });
  });
}

async function start() {
  await ensureDns();
  const client = new MongoClient(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  db = client.db(DB_NAME);
  await ensureAdmin();
  app.listen(PORT, () => console.log('Hydra dashboard running on port ' + PORT));
}

start().catch((err) => {
  console.error('Failed to connect to MongoDB:', err.message);
  process.exit(1);
});
