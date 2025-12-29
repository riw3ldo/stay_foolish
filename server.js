import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import Database from 'better-sqlite3';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import QRCode from 'qrcode';
import crypto from 'crypto';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*'
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const MESSAGE_MAX_LENGTH = parseInt(process.env.MESSAGE_MAX_LENGTH || '200', 10);
const MESSAGE_COOLDOWN_MS = parseInt(process.env.MESSAGE_COOLDOWN_MS || '5000', 10);
const STAFF_ROLES = ['superadmin', 'admin', 'moderator'];

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

const db = new Database('data.db');

const cooldowns = new Map();
const badWords = ['bodoh', 'kasar', 'jelek'];

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS staff (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      nickname TEXT NOT NULL,
      event_code TEXT NOT NULL,
      table_ref TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER NOT NULL,
      text TEXT NOT NULL,
      status TEXT NOT NULL,
      hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      approved_by INTEGER,
      approved_at TEXT,
      ip_hash TEXT,
      FOREIGN KEY(session_id) REFERENCES sessions(id),
      FOREIGN KEY(approved_by) REFERENCES staff(id)
    );
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      brand_title TEXT,
      brand_subtitle TEXT,
      logo_url TEXT,
      bg_url TEXT,
      video_url TEXT,
      performer_url TEXT,
      performer_visible INTEGER DEFAULT 0,
      auto_accept INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor TEXT,
      action TEXT,
      details TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const staffCount = db.prepare('SELECT COUNT(*) as count FROM staff').get();
  if (staffCount.count === 0) {
    seedStaff();
  }

  const settingsCount = db.prepare('SELECT COUNT(*) as count FROM settings').get();
  if (settingsCount.count === 0) {
    db.prepare(
      `INSERT INTO settings (id, brand_title, brand_subtitle, logo_url, bg_url, video_url, performer_url, performer_visible, auto_accept)
       VALUES (1, 'POINT Pool & Lounge', 'Live Wall', '', '', '', '', 0, 0)`
    ).run();
  }
}

function seedStaff() {
  const users = [
    { username: 'superadmin', password: 'superadmin', role: 'superadmin' },
    { username: 'admin', password: 'admin', role: 'admin' },
    { username: 'moderator', password: 'moderator', role: 'moderator' }
  ];
  const stmt = db.prepare('INSERT INTO staff (username, password, role) VALUES (?, ?, ?)');
  users.forEach((user) => {
    const hashed = bcrypt.hashSync(user.password, 10);
    stmt.run(user.username, hashed, user.role);
  });
}

function emitSettingsUpdate(settings) {
  io.emit('settings:update', settings);
}

function emitMessageApproved(message) {
  io.emit('message:approved', message);
}

function getSettings() {
  const row = db.prepare('SELECT * FROM settings WHERE id = 1').get();
  return {
    brand: {
      title: row.brand_title || '',
      subtitle: row.brand_subtitle || ''
    },
    assets: {
      logo_url: row.logo_url || '',
      bg_url: row.bg_url || '',
      video_url: row.video_url || '',
      performer_url: row.performer_url || ''
    },
    performer_visible: Boolean(row.performer_visible),
    auto_accept: Boolean(row.auto_accept)
  };
}

function saveSettings(payload) {
  const current = getSettings();
  const merged = {
    brand_title: payload.brand?.title ?? current.brand.title,
    brand_subtitle: payload.brand?.subtitle ?? current.brand.subtitle,
    logo_url: payload.assets?.logo_url ?? current.assets.logo_url,
    bg_url: payload.assets?.bg_url ?? current.assets.bg_url,
    video_url: payload.assets?.video_url ?? current.assets.video_url,
    performer_url: payload.assets?.performer_url ?? current.assets.performer_url,
    performer_visible:
      payload.performer_visible !== undefined ? Number(payload.performer_visible) : Number(current.performer_visible),
    auto_accept: payload.auto_accept !== undefined ? Number(payload.auto_accept) : Number(current.auto_accept)
  };

  db.prepare(
    `UPDATE settings SET
      brand_title = ?,
      brand_subtitle = ?,
      logo_url = ?,
      bg_url = ?,
      video_url = ?,
      performer_url = ?,
      performer_visible = ?,
      auto_accept = ?
    WHERE id = 1`
  ).run(
    merged.brand_title,
    merged.brand_subtitle,
    merged.logo_url,
    merged.bg_url,
    merged.video_url,
    merged.performer_url,
    merged.performer_visible,
    merged.auto_accept
  );
  return getSettings();
}

function addAudit(actor, action, details = '') {
  db.prepare('INSERT INTO audit_logs (actor, action, details) VALUES (?, ?, ?)').run(actor, action, details);
}

function hashText(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(ip || 'unknown').digest('hex');
}

function requireAuth(roles = []) {
  return (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Missing token' });
    }
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

function moderateText(text) {
  let sanitized = text;
  badWords.forEach((word) => {
    const regex = new RegExp(word, 'gi');
    sanitized = sanitized.replace(regex, '*'.repeat(word.length));
  });
  return sanitized;
}

function enforceCooldown(sessionToken) {
  const now = Date.now();
  const last = cooldowns.get(sessionToken) || 0;
  if (now - last < MESSAGE_COOLDOWN_MS) {
    return false;
  }
  cooldowns.set(sessionToken, now);
  return true;
}

initDb();

app.use('/api/public', publicLimiter);
app.use(express.static('public'));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  const user = db.prepare('SELECT * FROM staff WHERE username = ? AND active = 1').get(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  addAudit(user.username, 'login', user.role);
  res.json({ token, role: user.role, username: user.username });
});

app.get('/api/admin/staff', requireAuth(['superadmin']), (req, res) => {
  const staff = db
    .prepare('SELECT id, username, role, active FROM staff ORDER BY role ASC, username ASC')
    .all()
    .map((row) => ({ ...row, active: Boolean(row.active) }));
  res.json(staff);
});

app.post('/api/admin/staff', requireAuth(['superadmin']), (req, res) => {
  const { username, password, role, active = true } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  if (!STAFF_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const exists = db.prepare('SELECT id FROM staff WHERE username = ?').get(username);
  if (exists) {
    return res.status(409).json({ error: 'Username already exists' });
  }
  const hashed = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO staff (username, password, role, active) VALUES (?, ?, ?, ?)').run(
    username,
    hashed,
    role,
    active ? 1 : 0
  );
  addAudit(req.user.username, 'staff:create', `${username} (${role})`);
  res.json({ id: db.prepare('SELECT last_insert_rowid() as id').get().id, username, role, active: Boolean(active) });
});

app.put('/api/admin/staff/:id', requireAuth(['superadmin']), (req, res) => {
  const { id } = req.params;
  const { role, active, password } = req.body;
  const staff = db.prepare('SELECT * FROM staff WHERE id = ?').get(id);
  if (!staff) {
    return res.status(404).json({ error: 'Staff not found' });
  }
  if (role && !STAFF_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  const updates = { role: staff.role, active: staff.active, password: staff.password };
  if (role) updates.role = role;
  if (active !== undefined) updates.active = active ? 1 : 0;
  if (password) updates.password = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE staff SET role = ?, active = ?, password = ? WHERE id = ?').run(
    updates.role,
    updates.active,
    updates.password,
    id
  );
  addAudit(req.user.username, 'staff:update', `${staff.username} -> ${updates.role}/${updates.active}`);
  res.json({ id: staff.id, username: staff.username, role: updates.role, active: Boolean(updates.active) });
});

app.post('/api/public/session', (req, res) => {
  const { event_code, nickname, table_ref, disclaimer } = req.body;
  if (!event_code || !nickname || !disclaimer) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const token = uuidv4();
  const stmt = db.prepare('INSERT INTO sessions (token, nickname, event_code, table_ref) VALUES (?, ?, ?, ?)');
  stmt.run(token, nickname.trim(), event_code.trim(), table_ref?.trim() || null);
  res.json({ token });
});

app.post('/api/public/message', (req, res) => {
  const sessionToken = req.headers['x-session'];
  const { text } = req.body;
  if (!sessionToken) {
    return res.status(401).json({ error: 'Missing session token' });
  }
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Message required' });
  }
  if (text.length > MESSAGE_MAX_LENGTH) {
    return res.status(400).json({ error: 'Message too long' });
  }
  if (!enforceCooldown(sessionToken)) {
    return res.status(429).json({ error: 'Cooldown active' });
  }
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(sessionToken);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }
  const messageHash = hashText(text.toLowerCase());
  const duplicate = db.prepare('SELECT id FROM messages WHERE session_id = ? AND hash = ?').get(session.id, messageHash);
  if (duplicate) {
    return res.status(429).json({ error: 'Duplicate detected' });
  }
  const settings = getSettings();
  const status = settings.auto_accept ? 'approved' : 'pending';
  const sanitized = moderateText(text.trim());
  const result = db
    .prepare('INSERT INTO messages (session_id, text, status, hash, ip_hash) VALUES (?, ?, ?, ?, ?)')
    .run(session.id, sanitized, status, messageHash, hashIp(req.ip));
  const message = {
    id: result.lastInsertRowid,
    text: sanitized,
    status,
    nickname: session.nickname,
    created_at: new Date().toISOString(),
    session_id: session.id
  };
  addAudit(session.nickname, 'message:create', status);
  if (status === 'approved') {
    emitMessageApproved({ ...message, approved_by: 'auto', approved_at: message.created_at });
  }
  res.json({ status });
});

app.get('/api/screen/messages', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '10', 10), 50);
  const rows = db
    .prepare(
      `SELECT messages.id, messages.text, messages.created_at, sessions.nickname
       FROM messages
       JOIN sessions ON messages.session_id = sessions.id
       WHERE messages.status = 'approved'
       ORDER BY messages.created_at DESC
       LIMIT ?`
    )
    .all(limit);
  res.json(rows);
});

app.get('/api/mod/messages', requireAuth(['moderator', 'admin', 'superadmin']), (req, res) => {
  const status = req.query.status || 'pending';
  const limit = Math.min(parseInt(req.query.limit || '20', 10), 100);
  const rows = db
    .prepare(
      `SELECT messages.id, messages.text, messages.status, messages.created_at, sessions.nickname
       FROM messages
       JOIN sessions ON messages.session_id = sessions.id
       WHERE messages.status = ?
       ORDER BY messages.created_at ASC
       LIMIT ?`
    )
    .all(status, limit);
  res.json(rows);
});

app.post('/api/mod/messages/:id/approve', requireAuth(['moderator', 'admin', 'superadmin']), (req, res) => {
  const { id } = req.params;
  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
  if (!message) {
    return res.status(404).json({ error: 'Message not found' });
  }
  const now = new Date().toISOString();
  db.prepare('UPDATE messages SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?').run(
    'approved',
    req.user.id,
    now,
    id
  );
  const payload = {
    id: message.id,
    text: message.text,
    status: 'approved',
    nickname: db.prepare('SELECT nickname FROM sessions WHERE id = ?').get(message.session_id).nickname,
    approved_by: req.user.username,
    approved_at: now
  };
  emitMessageApproved(payload);
  addAudit(req.user.username, 'message:approve', `id=${id}`);
  res.json({ ok: true });
});

app.post('/api/mod/messages/:id/reject', requireAuth(['moderator', 'admin', 'superadmin']), (req, res) => {
  const { id } = req.params;
  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
  if (!message) {
    return res.status(404).json({ error: 'Message not found' });
  }
  db.prepare('UPDATE messages SET status = ? WHERE id = ?').run('rejected', id);
  addAudit(req.user.username, 'message:reject', `id=${id}`);
  res.json({ ok: true });
});

app.get('/api/settings', (req, res) => {
  res.json(getSettings());
});

app.post('/api/settings', requireAuth(['admin', 'superadmin']), (req, res) => {
  const updated = saveSettings(req.body);
  emitSettingsUpdate(updated);
  addAudit(req.user.username, 'settings:update');
  res.json(updated);
});

app.put('/api/settings', requireAuth(['admin', 'superadmin']), (req, res) => {
  const updated = saveSettings(req.body);
  emitSettingsUpdate(updated);
  addAudit(req.user.username, 'settings:update');
  res.json(updated);
});

app.get('/api/admin/qrcodes', requireAuth(['admin', 'superadmin']), async (req, res) => {
  const { event_code = 'POINT', table_ref = '' } = req.query;
  const loginUrl = `${req.protocol}://${req.get('host')}/guest/login.html?event=${encodeURIComponent(
    event_code
  )}&table=${encodeURIComponent(table_ref)}`;
  try {
    const dataUrl = await QRCode.toDataURL(loginUrl);
    addAudit(req.user.username, 'qrcode:generate', loginUrl);
    res.json({ url: loginUrl, qrcode: dataUrl });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate QR' });
  }
});

app.get('/api/admin/audit', requireAuth(['admin', 'superadmin']), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const rows = db.prepare('SELECT actor, action, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT ?').all(limit);
  res.json(rows);
});

app.get('*', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`POINT Live Wall server running on port ${PORT}`);
});
