// backend/server.js  (ESM)
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import path from 'path';
import fs from 'fs';
import sqlite3pkg from 'sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const sqlite3 = sqlite3pkg.verbose();
const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));

const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');
});

function run(sql, params = []) { return new Promise((resolve, reject) => {
  db.run(sql, params, function (err) { if (err) reject(err); else resolve(this); });
});}
function get(sql, params = []) { return new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
});}
function all(sql, params = []) { return new Promise((resolve, reject) => {
  db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});}

async function init() {
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, must_change_password INTEGER DEFAULT 1, name TEXT DEFAULT '')`);
  await run(`CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS teams (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', color TEXT DEFAULT '', department_id INTEGER, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (department_id) REFERENCES departments(id))`);
  await run(`CREATE TABLE IF NOT EXISTS break_types (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '', status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, name TEXT NOT NULL, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, department_id INTEGER, team_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (department_id) REFERENCES departments(id), FOREIGN KEY (team_id) REFERENCES teams(id))`);
  await run(`CREATE TABLE IF NOT EXISTS breaks (id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL, break_type_id INTEGER NOT NULL, start_time TEXT NOT NULL, end_time TEXT, duration INTEGER, FOREIGN KEY (employee_id) REFERENCES employees(id), FOREIGN KEY (break_type_id) REFERENCES break_types(id))`);

  let admin = await get(`SELECT * FROM users WHERE username = 'admin'`);
  if (!admin) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await run(`INSERT INTO users (username, password, must_change_password, name) VALUES (?,?,1,?)`, ['admin', hashed, 'Admin']);
    admin = await get(`SELECT * FROM users WHERE username = 'admin'`);
    console.log('Seeded admin / admin123');
  }
  const emp = await get(`SELECT id FROM employees WHERE user_id = ?`, [admin.id]);
  if (!emp) await run(`INSERT INTO employees (user_id, name, status) VALUES (?, ?, 'Active')`, [admin.id, 'Admin']);
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : '';
    const payload = jwt.verify(t, JWT_SECRET);
    req.user = payload; next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}
function parseIso(s) { if (!s) return null; const d = new Date(s); return isNaN(d) ? null : d.toISOString(); }

app.get('/api/health', async (_req, res) => {
  try { const row = await get('SELECT 1 ok'); res.json({ status:'ok', db: row?.ok===1?'ok':'unknown', version:'0.9.0' }); }
  catch { res.status(500).json({ status:'error', db:'down' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
    const user = await get(`SELECT * FROM users WHERE username = ?`, [username]);
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, must_change_password: !!user.must_change_password });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password || new_password.length < 8) return res.status(400).json({ error: 'Invalid payload' });
    const user = await get(`SELECT * FROM users WHERE id = ?`, [req.user.id]);
    if (!user || !bcrypt.compareSync(current_password, user.password)) return res.status(400).json({ error: 'Current password incorrect' });
    const hashed = bcrypt.hashSync(new_password, 10);
    await run(`UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?`, [hashed, req.user.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/departments', auth, async (_req, res) => { try { res.json(await all(`SELECT * FROM departments ORDER BY id ASC`)); } catch { res.status(500).json({ error: 'Database error' }); }});
app.post('/api/departments', auth, async (req, res) => {
  const { name, description } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    const r = await run(`INSERT INTO departments (name, description, status) VALUES (?,?, 'Active')`, [name.trim(), String(description || '')]);
    res.status(201).json({ id: r.lastID, name: name.trim(), description: String(description || ''), status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Department already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/teams', auth, async (req, res) => {
  const { name, description, color } = req.body || {}; let { department_id } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    if (!department_id) {
      const dep = await get(`SELECT id FROM departments WHERE status='Active' ORDER BY id ASC LIMIT 1`);
      if (!dep) return res.status(400).json({ error: 'No departments. Create one first or provide department_id.' });
      department_id = dep.id;
    }
    const r = await run(`INSERT INTO teams (name, description, color, department_id, status) VALUES (?,?,?,?, 'Active')`,
      [name.trim(), String(description || ''), String(color || ''), department_id]);
    res.status(201).json({ id: r.lastID, name: name.trim(), description: String(description || ''), color: String(color || ''), department_id, status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Team already exists' });
    if (String(e).includes('FOREIGN KEY')) return res.status(400).json({ error: 'Invalid department_id' });
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/break-types', auth, async (_req, res) => { try { res.json(await all(`SELECT * FROM break_types WHERE status='Active' ORDER BY id ASC`)); } catch { res.status(500).json({ error: 'Database error' }); }});
app.post('/api/break-types', auth, async (req, res) => {
  const { name, color } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    const r = await run(`INSERT INTO break_types (name, color, status) VALUES (?, ?, 'Active')`, [name.trim(), String(color || '')]);
    res.status(201).json({ id: r.lastID, name: name.trim(), color: String(color || ''), status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Break type already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/breaks/start', auth, async (req, res) => {
  const { break_type_id } = req.body || {};
  if (!break_type_id) return res.status(400).json({ error: 'break_type_id is required' });
  try {
    const bt = await get(`SELECT id FROM break_types WHERE id = ? AND status='Active'`, [break_type_id]);
    if (!bt) return res.status(400).json({ error: 'Invalid break type' });
    let emp = await get(`SELECT id, name FROM employees WHERE user_id = ?`, [req.user.id]);
    if (!emp) {
      const user = await get(`SELECT username FROM users WHERE id = ?`, [req.user.id]);
      const name = (user?.username || `User${req.user.id}`);
      const r = await run(`INSERT INTO employees (user_id, name, status) VALUES (?, ?, 'Active')`, [req.user.id, name]);
      emp = { id: r.lastID, name };
    }
    const start = new Date().toISOString();
    const r = await run(`INSERT INTO breaks (employee_id, break_type_id, start_time) VALUES (?, ?, ?)`,
      [emp.id, break_type_id, start]);
    res.status(201).json({ id: r.lastID, start_time: start });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/breaks/stop', auth, async (_req, res) => {
  try {
    const emp = await get(`SELECT id FROM employees WHERE user_id = ?`, [req.user.id]);
    if (!emp) return res.status(400).json({ error: 'No employee found' });
    const br = await get(`SELECT * FROM breaks WHERE employee_id = ? AND end_time IS NULL ORDER BY id DESC LIMIT 1`, [emp.id]);
    if (!br) return res.status(400).json({ error: 'No active break' });
    const end = new Date();
    const duration = Math.max(0, Math.round((end - new Date(br.start_time)) / 60000));
    await run(`UPDATE breaks SET end_time = ?, duration = ? WHERE id = ?`, [end.toISOString(), duration, br.id]);
    res.json({ success: true, duration });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/employees', auth, async (_req, res) => { try { res.json(await all(`SELECT * FROM employees ORDER BY id ASC`)); } catch (e) { console.error(e); res.status(500).json({ error: 'Database error' }); }});
app.post('/api/employees', auth, async (req, res) => {
  try {
    const { user_id, name, department_id, team_id, status } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: 'name required' });
    if (user_id) { const u = await get(`SELECT id FROM users WHERE id = ?`, [user_id]); if (!u) return res.status(400).json({ error: 'invalid user_id' }); }
    if (department_id) { const d = await get(`SELECT id FROM departments WHERE id = ?`, [department_id]); if (!d) return res.status(400).json({ error: 'invalid department_id' }); }
    if (team_id) { const t = await get(`SELECT id FROM teams WHERE id = ?`, [team_id]); if (!t) return res.status(400).json({ error: 'invalid team_id' }); }
    const r = await run(`INSERT INTO employees (user_id, name, department_id, team_id, status) VALUES (?, ?, ?, ?, ?)`,
      [user_id || null, name.trim(), department_id || null, team_id || null, status || 'Active']);
    res.status(201).json({ id: r.lastID, name: name.trim(), user_id: user_id || null, department_id: department_id || null, team_id: team_id || null, status: status || 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE') && String(e).includes('user_id')) return res.status(409).json({ error: 'employee for this user already exists' });
    console.error(e); res.status(500).json({ error: 'Server error' });
  }
});
app.put('/api/employees/:id', auth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { name, department_id, team_id, status, user_id } = req.body || {};
    const fields = [], vals = [];
    if (name !== undefined) { fields.push('name = ?'); vals.push(String(name || '')); }
    if (department_id !== undefined) { fields.push('department_id = ?'); vals.push(department_id || null); }
    if (team_id !== undefined) { fields.push('team_id = ?'); vals.push(team_id || null); }
    if (status !== undefined) { fields.push('status = ?'); vals.push(String(status || 'Active')); }
    if (user_id !== undefined) { fields.push('user_id = ?'); vals.push(user_id || null); }
    if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
    vals.push(id);
    const r = await run(`UPDATE employees SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ success: true, changes: r.changes });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

const publicDir = path.resolve(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir, { index: 'index.html', maxAge: '15m' }));
  app.get(/^\/(?!api).*/, (_req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
  });
} else {
  console.warn('Static UI directory not found:', publicDir);
}

process.on('unhandledRejection', err => { console.error('unhandledRejection:', err); process.exit(1); });
process.on('uncaughtException', err => { console.error('uncaughtException:', err); process.exit(1); });

init().then(() => {
  app.listen(PORT, HOST, () => console.log(`Backend running on http://${HOST}:${PORT}`));
});
