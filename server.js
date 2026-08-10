const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns');
const { MongoClient, ObjectId } = require('mongodb');

const PORT = process.env.PORT;
const MONGODB_URI =
  process.env.MONGODB_URI;
const DB_NAME = 'hydrakeysys';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const DISCORD_WEBHOOK_URL =
  process.env.DISCORD_WEBHOOK_URL;

const sessions = new Map();
const loginAttempts = new Map();
const subRequests = new Map();

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

function getSubLock(ip) {
  const now = Date.now();
  const lock = subRequests.get(ip);
  if (!lock || now > lock.resetAt) {
    const fresh = { count: 0, firstAt: now, resetAt: now + 5 * 60 * 60 * 1000 };
    subRequests.set(ip, fresh);
    return fresh;
  }
  return lock;
}

async function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : req.query.token;
  const session = token ? sessions.get(token) : null;
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'Not authorized.' });
  }
  const admin = await db.collection('admins').findOne({ username: session.username });
  if (!admin) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Not authorized.' });
  }
  req.admin = admin.username;
  req.role = admin.role === 'admin' ? 'admin' : 'owner';
  req.permissions = admin.permissions || [];
  req.token = token;
  next();
}

function hasPerm(req, perm) {
  return req.role === 'owner' || req.permissions.includes('*') || req.permissions.includes(perm);
}

function requirePerm(perm) {
  return (req, res, next) => {
    if (hasPerm(req, perm)) return next();
    return res.status(403).json({ error: 'You do not have permission to do this.' });
  };
}

function requireOwner(req, res, next) {
  if (req.role === 'owner') return next();
  return res.status(403).json({ error: 'Owner access required.' });
}

function makeKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () =>
    Array.from(crypto.randomBytes(4))
      .map((b) => chars[b % chars.length])
      .join('');
  return 'HS-' + seg() + '-' + seg() + '-' + seg();
}

function makeRequestId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const seg = () =>
    Array.from(crypto.randomBytes(4))
      .map((b) => chars[b % chars.length])
      .join('');
  return 'SR-' + seg() + '-' + seg() + '-' + seg();
}

async function sendSubscriptionWebhook(info) {
  try {
    await fetch(DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'Hydra Key System',
        embeds: [
          {
            title: 'New Subscription Request',
            color: 0x5865f2,
            fields: [
              { name: 'Plan', value: info.plan, inline: true },
              { name: 'Discord', value: info.discord, inline: true },
              { name: 'Request ID', value: info.requestId, inline: true },
              { name: 'Note', value: info.note || '\u2014' },
            ],
            timestamp: new Date().toISOString(),
          },
        ],
      }),
    });
  } catch (e) {
    console.error('Webhook failed:', e.message);
  }
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

app.get('/api/me', auth, (req, res) => {
  res.json({ username: req.admin, role: req.role, permissions: req.permissions });
});

app.get('/api/admins', auth, requireOwner, async (req, res) => {
  const docs = await db
    .collection('admins')
    .find({})
    .project({ username: 1, role: 1, permissions: 1, createdAt: 1 })
    .toArray();
  const admins = docs.map((a) => ({
    username: a.username,
    role: a.role === 'admin' ? 'admin' : 'owner',
    permissions: Array.isArray(a.permissions) ? a.permissions : [],
    createdAt: a.createdAt,
  }));
  res.json({ admins });
});

app.post('/api/admins', auth, requireOwner, async (req, res) => {
  const { username, password, permissions } = req.body || {};
  const u = String(username || '').trim();
  const pw = String(password || '');
  if (!u) return res.status(400).json({ error: 'Username is required.' });
  if (pw.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });

  const existing = await db.collection('admins').findOne({ username: u });
  if (existing) return res.status(409).json({ error: 'Username already exists.' });

  const doc = {
    username: u,
    passwordHash: hashPassword(pw),
    role: 'admin',
    permissions: Array.isArray(permissions) ? permissions.map(String) : [],
    createdAt: new Date(),
  };
  await db.collection('admins').insertOne(doc);
  res.json({ ok: true });
});

app.patch('/api/admins/:username', auth, requireOwner, async (req, res) => {
  const target = await db.collection('admins').findOne({ username: String(req.params.username) });
  if (!target) return res.status(404).json({ error: 'Admin not found.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'Cannot modify the owner account.' });

  const set = {};
  if (Object.prototype.hasOwnProperty.call(req.body, 'permissions')) {
    set.permissions = Array.isArray(req.body.permissions) ? req.body.permissions.map(String) : [];
  }
  if (Object.prototype.hasOwnProperty.call(req.body, 'password')) {
    const pw = String(req.body.password || '');
    if (pw.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters.' });
    set.passwordHash = hashPassword(pw);
  }
  await db.collection('admins').updateOne({ _id: target._id }, { $set: set });
  res.json({ ok: true });
});

app.delete('/api/admins/:username', auth, requireOwner, async (req, res) => {
  const u = String(req.params.username);
  if (u === req.admin) return res.status(400).json({ error: 'You cannot delete your own account.' });
  const target = await db.collection('admins').findOne({ username: u });
  if (!target) return res.status(404).json({ error: 'Admin not found.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'Cannot delete the owner account.' });

  await db.collection('admins').deleteOne({ _id: target._id });
  sessions.forEach((s, t) => {
    if (s.username === u) sessions.delete(t);
  });
  res.json({ ok: true });
});

app.post('/api/password', auth, requirePerm('security.password'), async (req, res) => {
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

app.get('/api/keys', auth, requirePerm('tab.keys'), async (req, res) => {
  const keys = await db.collection('keys').find({}).project({ _id: 0 }).sort({ createdAt: -1 }).toArray();
  res.json({ keys });
});

app.post('/api/keys', auth, requirePerm('keys.create'), async (req, res) => {
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
  if (
    (Object.prototype.hasOwnProperty.call(req.body, 'expiration') || Object.prototype.hasOwnProperty.call(req.body, 'note')) &&
    !hasPerm(req, 'keys.extend')
  ) {
    return res.status(403).json({ error: 'You do not have permission to do this.' });
  }
  if (Object.prototype.hasOwnProperty.call(req.body, 'ip') && !hasPerm(req, 'keys.clearip')) {
    return res.status(403).json({ error: 'You do not have permission to do this.' });
  }

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

app.delete('/api/keys/:key', auth, requirePerm('keys.delete'), async (req, res) => {
  const result = await db.collection('keys').deleteOne({ key: String(req.params.key) });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Key not found.' });
  res.json({ ok: true });
});

app.get('/api/public/plans', async (req, res) => {
  const plans = await db
    .collection('plans')
    .find({ active: true })
    .project({ _id: 1, name: 1, price: 1, duration: 1, description: 1 })
    .sort({ createdAt: 1 })
    .toArray();
  res.json({ plans });
});

app.get('/api/plans', auth, requirePerm('tab.subscriptions'), async (req, res) => {
  const plans = await db.collection('plans').find({}).sort({ createdAt: 1 }).toArray();
  res.json({ plans });
});

app.post('/api/plans', auth, requirePerm('plans.manage'), async (req, res) => {
  const { name, price, duration, description, active } = req.body || {};
  const n = String(name || '').trim();
  if (!n) return res.status(400).json({ error: 'Plan name is required.' });

  const doc = {
    name: n,
    price: String(price || ''),
    duration: Number(duration) > 0 ? Number(duration) : 0,
    description: String(description || '').trim(),
    active: active !== false,
    createdAt: new Date(),
  };
  await db.collection('plans').insertOne(doc);
  res.json({ ok: true, plan: doc });
});

app.patch('/api/plans/:id', auth, requirePerm('plans.manage'), async (req, res) => {
  let id;
  try {
    id = new ObjectId(req.params.id);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid plan id.' });
  }
  const { name, price, duration, description, active } = req.body || {};
  const set = {};
  if (Object.prototype.hasOwnProperty.call(req.body, 'name')) set.name = String(name || '').trim() || 'Untitled plan';
  if (Object.prototype.hasOwnProperty.call(req.body, 'price')) set.price = String(price || '');
  if (Object.prototype.hasOwnProperty.call(req.body, 'duration')) set.duration = Number(duration) > 0 ? Number(duration) : 0;
  if (Object.prototype.hasOwnProperty.call(req.body, 'description')) set.description = String(description || '').trim();
  if (Object.prototype.hasOwnProperty.call(req.body, 'active')) set.active = !!active;

  const result = await db.collection('plans').updateOne({ _id: id }, { $set: set });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Plan not found.' });
  res.json({ ok: true });
});

app.delete('/api/plans/:id', auth, requirePerm('plans.manage'), async (req, res) => {
  let id;
  try {
    id = new ObjectId(req.params.id);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid plan id.' });
  }
  const result = await db.collection('plans').deleteOne({ _id: id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Plan not found.' });
  res.json({ ok: true });
});

app.get('/api/subscriptions', auth, requirePerm('tab.subscriptions'), async (req, res) => {
  const subs = await db
    .collection('subscriptions')
    .find({})
    .sort({ createdAt: -1 })
    .toArray();
  res.json({ subscriptions: subs });
});

app.post('/api/subscriptions', async (req, res) => {
  const { planId, discord, note } = req.body || {};
  const d = String(discord || '').trim();
  if (!d) return res.status(400).json({ error: 'Discord user/tag is required.' });

  const ip = req.ip || 'unknown';
  const lock = getSubLock(ip);
  if (lock.count >= 3) {
    const mins = Math.max(1, Math.ceil((lock.resetAt - Date.now()) / 60000));
    if (mins >= 60) {
      const hours = Math.max(1, Math.ceil(mins / 60));
      return res.status(429).json({ error: 'Too many requests. Try again in about ' + hours + ' hour' + (hours === 1 ? '' : 's') + '.' });
    }
    return res.status(429).json({ error: 'Too many requests. Try again in about ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.' });
  }

  let plan;
  if (planId) {
    try {
      plan = await db.collection('plans').findOne({ _id: new ObjectId(planId), active: true });
    } catch (e) {
      return res.status(400).json({ error: 'Invalid plan.' });
    }
  }
  if (!plan) return res.status(400).json({ error: 'Plan not found.' });

  const doc = {
    requestId: makeRequestId(),
    planId: plan._id,
    plan: plan.name,
    discord: d,
    note: String(note || '').trim(),
    fulfilled: false,
    createdAt: new Date(),
  };
  await db.collection('subscriptions').insertOne(doc);
  lock.count++;
  sendSubscriptionWebhook({ plan: doc.plan, discord: doc.discord, note: doc.note, requestId: doc.requestId });
  res.json({ ok: true, requestId: doc.requestId });
});

app.patch('/api/subscriptions/:id', auth, requirePerm('subs.fulfill'), async (req, res) => {
  let id;
  try {
    id = new ObjectId(req.params.id);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid subscription id.' });
  }
  const { fulfilled } = req.body || {};
  const set = {};
  if (Object.prototype.hasOwnProperty.call(req.body, 'fulfilled')) set.fulfilled = !!fulfilled;
  if (Object.prototype.hasOwnProperty.call(req.body, 'note')) set.note = String(req.body.note || '');

  const result = await db.collection('subscriptions').updateOne({ _id: id }, { $set: set });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Subscription not found.' });
  res.json({ ok: true });
});

app.delete('/api/subscriptions/:id', auth, requirePerm('subs.delete'), async (req, res) => {
  let id;
  try {
    id = new ObjectId(req.params.id);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid subscription id.' });
  }
  const result = await db.collection('subscriptions').deleteOne({ _id: id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Subscription not found.' });
  res.json({ ok: true });
});

app.get('/api/settings/download', auth, async (req, res) => {
  const doc = await db.collection('settings').findOne({ key: 'downloadUrl' });
  res.json({ url: doc ? doc.value : '' });
});

app.patch('/api/settings/download', auth, requireOwner, async (req, res) => {
  const url = String((req.body || {}).url || '').trim();
  await db.collection('settings').updateOne({ key: 'downloadUrl' }, { $set: { value: url } }, { upsert: true });
  res.json({ ok: true, url });
});

app.get('/download', async (req, res) => {
  const doc = await db.collection('settings').findOne({ key: 'downloadUrl' });
  if (doc && doc.value) return res.redirect(doc.value);
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
      role: 'owner',
      permissions: [],
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
