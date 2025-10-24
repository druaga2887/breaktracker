const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

// --- SQLite helpers ---
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

// --- bootstrap schema & seed admin ---
async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      must_change_password INTEGER DEFAULT 1
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS departments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT DEFAULT '',
      status TEXT DEFAULT 'Active',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS teams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      description TEXT DEFAULT '',
      color TEXT DEFAULT '',
      department_id INTEGER,
      status TEXT DEFAULT 'Active',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (department_id) REFERENCES departments(id)
    )
  `);

  const admin = await get(`SELECT id FROM users WHERE username = 'admin'`);
  if (!admin) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await run(
      `INSERT INTO users (username, password, must_change_password) VALUES (?,?,1)`,
      ['admin', hashed]
    );
    console.log('Seeded admin / admin123');
  }
}

// --- small utils ---
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : '';
    const payload = jwt.verify(t, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// --- routes ---
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.3.0' });
});

// auth
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
    const user = await get(`SELECT * FROM users WHERE username = ?`, [username]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, must_change_password: !!user.must_change_password });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password || new_password.length < 8)
      return res.status(400).json({ error: 'Invalid payload' });
    const user = await get(`SELECT * FROM users WHERE id = ?`, [req.user.id]);
    if (!user || !bcrypt.compareSync(current_password, user.password))
      return res.status(400).json({ error: 'Current password incorrect' });
    const hashed = bcrypt.hashSync(new_password, 10);
    await run(`UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?`, [hashed, req.user.id]);
    res.json({ success: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// departments
app.get('/api/departments', auth, async (_req, res) => {
  try { res.json(await all(`SELECT * FROM departments ORDER BY id ASC`)); }
  catch { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/departments', auth, async (req, res) => {
  const { name, description } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    const r = await run(`INSERT INTO departments (name, description, status) VALUES (?,?, 'Active')`,
                        [name.trim(), String(description || '')]);
    return res.status(201).json({ id: r.lastID, name: name.trim(), description: String(description || ''), status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Department already exists' });
    return res.status(500).json({ error: 'Database error' });
  }
});

// teams (auto-pick first department if not provided)
app.post('/api/teams', auth, async (req, res) => {
  const { name, description, color } = req.body || {};
  let { department_id } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

  try {
    if (!department_id) {
      const dep = await get(`SELECT id FROM departments WHERE status='Active' ORDER BY id ASC LIMIT 1`);
      if (!dep) return res.status(400).json({ error: 'No departments. Create one first or provide department_id.' });
      department_id = dep.id;
    }
    const r = await run(
      `INSERT INTO teams (name, description, color, department_id, status) VALUES (?,?,?,?, 'Active')`,
      [name.trim(), String(description || ''), String(color || ''), department_id]
    );
    return res.status(201).json({ id: r.lastID, name: name.trim(), description: String(description || ''), color: String(color || ''), department_id, status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Team already exists' });
    if (String(e).includes('FOREIGN KEY')) return res.status(400).json({ error: 'Invalid department_id' });
    return res.status(500).json({ error: 'Database error' });
  }
});

// --- start ---
init().then(() => {
  app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
});
