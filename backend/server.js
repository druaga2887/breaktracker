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

// --- SQLite setup ---
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

// create schema + seed admin
async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      must_change_password INTEGER DEFAULT 1
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

// --- routes ---
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.2.0' });
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const user = await get(`SELECT * FROM users WHERE username = ?`, [username]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = bcrypt.compareSync(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, must_change_password: !!user.must_change_password });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

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
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- start ---
init().then(() => {
  app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
});
