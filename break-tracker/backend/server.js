
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.set('trust proxy', true);

app.use(express.json({ limit: '1mb' }));
app.use(cors());
app.use(morgan('tiny'));

// ===== HARD ALIASES: fix common frontend typos before routing =====
app.use((req, res, next) => {
  if (!req.path || !req.path.toLowerCase().startsWith('/api/')) return next();

  const hardAliases = {
    '/api/departmentss': '/api/departments',
    '/api/teamss': '/api/teams',
    '/api/employeess': '/api/employees',
    '/api/userss': '/api/users',
    '/api/break-typess': '/api/break-types',
    '/api/breaktypess': '/api/break-types',
    '/api/breaktypes': '/api/break-types',
    '/api/break_types': '/api/break-types',
    '/api/breaktype': '/api/break-types',
    '/api/breakss': '/api/breaks'
  };

  const low = req.path.toLowerCase();
  for (const bad in hardAliases) {
    if (low === bad || low.startsWith(bad + '/')) {
      const targetBase = hardAliases[bad];
      const suffix = req.path.substring(bad.length);
      const qs = req.originalUrl.substring(req.path.length);
      const target = targetBase + suffix + qs;
      console.warn('HARD ALIAS:', req.originalUrl, '->', target);
      req.url = target;
      break;
    }
  }
  next();
});
// ===== END HARD ALIASES =====

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

// --- SQLite setup
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(DB_PATH);

function run(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}
function get(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function(err, row) {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function(err, rows) {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function initSchema() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    role TEXT DEFAULT 'Admin',
    status TEXT DEFAULT 'Active',
    must_change_password INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  await run(`CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'Active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  await run(`CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    color TEXT DEFAULT '',
    department_id INTEGER,
    status TEXT DEFAULT 'Active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(department_id) REFERENCES departments(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS break_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    color TEXT DEFAULT '',
    status TEXT DEFAULT 'Active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  await run(`CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    user_id INTEGER,
    team_id INTEGER,
    department_id INTEGER,
    status TEXT DEFAULT 'Active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(team_id) REFERENCES teams(id),
    FOREIGN KEY(department_id) REFERENCES departments(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS breaks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    employee_name TEXT NOT NULL,
    break_type_id INTEGER NOT NULL,
    break_type_name TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    duration INTEGER,
    FOREIGN KEY(employee_id) REFERENCES employees(id),
    FOREIGN KEY(break_type_id) REFERENCES break_types(id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    action TEXT,
    details TEXT
  )`);
}

async function createDefaultAdmin() {
  const row = await get(`SELECT id FROM users WHERE username = ?`, ['admin']);
  if (!row) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await run(
      `INSERT INTO users (username, password, name, email, role, status, must_change_password)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ['admin', hashed, 'System Administrator', 'admin@company.com', 'Admin', 'Active', 1]
    );
    console.log('Seeded default admin (admin / admin123, must change password).');
  }
}

function addLog(req, action, details) {
  const uid = (req.user && req.user.id) || null;
  run(`INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)`,
      [uid, action, details || '']).catch(()=>{});
}

// --- Auth helpers
async function authenticateUser(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await get(`SELECT id, username, role, status, must_change_password FROM users WHERE id = ?`, [payload.id]);
    if (!user || user.status !== 'Active') return res.status(401).json({ error: 'Invalid user' });
    req.user = user;
    const allowedWhileMustChange = ['/api/auth/change-password', '/api/health', '/api/auth/login'];
    if (user.must_change_password && !allowedWhileMustChange.includes(req.path)) {
      return res.status(403).json({ error: 'Password change required' });
    }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function checkPermission(requiredRole) {
  const rank = { 'Admin': 3, 'Manager': 2, 'Employee': 1 };
  return (req, res, next) => {
    const userRole = (req.user && req.user.role) || 'Employee';
    if (rank[userRole] >= rank[requiredRole]) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// --- Health
app.get('/api/health', async (req, res) => {
  res.json({ ok: true, version: 'starter-1.0.0' });
});

// --- Auth
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = await get(`SELECT * FROM users WHERE username = ?`, [username]);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, must_change_password: user.must_change_password } });
});

app.post('/api/auth/change-password', authenticateUser, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const user = await get(`SELECT * FROM users WHERE id = ?`, [req.user.id]);
  if (!user) return res.status(500).json({ error: 'Database error' });
  if (!current_password || !bcrypt.compareSync(current_password, user.password)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const hashed = bcrypt.hashSync(new_password, 10);
  await run(`UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?`, [hashed, req.user.id]);
  addLog(req, 'Password Changed', `User ${user.username} changed password`);
  res.json({ success: true });
});

// --- Departments CRUD
app.get('/api/departments', authenticateUser, async (req, res) => {
  try {
    const rows = await all(`SELECT id, name, description, status, created_at FROM departments ORDER BY name ASC`);
    res.json(rows || []);
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/departments', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const { name, description } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    const r = await run(`INSERT INTO departments (name, description, status) VALUES (?, ?, 'Active')`,
                        [name.trim(), (description || '').trim()]);
    addLog(req, 'Department Created', name.trim());
    res.status(201).json({ id: r.lastID, name: name.trim(), description: (description || '').trim(), status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Department already exists' });
    return res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/departments/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, description, status } = req.body || {};
  const fields = [], values = [];
  if (name !== undefined) { fields.push('name = ?'); values.push(String(name || '').trim()); }
  if (description !== undefined) { fields.push('description = ?'); values.push(String(description || '')); }
  if (status !== undefined) { fields.push('status = ?'); values.push(String(status || 'Active')); }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  values.push(id);
  try {
    const r = await run(`UPDATE departments SET ${fields.join(', ')} WHERE id = ?`, values);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/departments/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    const r = await run(`UPDATE departments SET status = 'Inactive' WHERE id = ?`, [id]);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// --- Teams create/update/delete
app.post('/api/teams', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const { name, description, color } = req.body || {};
  let { department_id, departmentId, department } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name is required' });

  const insertWithDep = async (depId) => {
    try {
      const r = await run(`INSERT INTO teams (name, description, color, department_id, status) VALUES (?, ?, ?, ?, 'Active')`,
                          [name.trim(), (description || '').trim(), String(color || ''), depId]);
      addLog(req, 'Team Created', name.trim());
      return res.status(201).json({ id: r.lastID, name: name.trim(), description: (description || '').trim(), color: String(color || ''), department_id: depId, status: 'Active' });
    } catch (e) {
      if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Team already exists' });
      if (String(e).includes('FOREIGN KEY') || String(e).includes('constraint')) return res.status(400).json({ error: 'Invalid department_id' });
      return res.status(500).json({ error: 'Database error' });
    }
  };

  const provided = department_id || departmentId || department;
  if (provided) return insertWithDep(parseInt(provided, 10) || null);

  try {
    const row = await get(`SELECT id FROM departments WHERE status = 'Active' ORDER BY id LIMIT 1`);
    if (!row) return res.status(400).json({ error: 'No active departments. Create a department first or provide department_id.' });
    return insertWithDep(row.id);
  } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

app.put('/api/teams/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, description, color, status, department_id } = req.body || {};
  const fields = [], values = [];
  if (name !== undefined) { fields.push('name = ?'); values.push(String(name || '')); }
  if (description !== undefined) { fields.push('description = ?'); values.push(String(description || '')); }
  if (color !== undefined) { fields.push('color = ?'); values.push(String(color || '')); }
  if (status !== undefined) { fields.push('status = ?'); values.push(String(status || 'Active')); }
  if (department_id !== undefined) { fields.push('department_id = ?'); values.push(department_id || null); }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  values.push(id);
  try {
    const r = await run(`UPDATE teams SET ${fields.join(', ')} WHERE id = ?`, values);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/teams/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    const r = await run(`UPDATE teams SET status = 'Inactive' WHERE id = ?`, [id]);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// --- Break Types
app.post('/api/break-types', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const { name, description, color } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Name is required' });
  try {
    const r = await run(`INSERT INTO break_types (name, description, color, status) VALUES (?, ?, ?, 'Active')`,
                        [String(name).trim(), String(description || ''), String(color || '')]);
    addLog(req, 'Break Type Created', String(name).trim());
    res.status(201).json({ id: r.lastID, name: String(name).trim(), description: String(description || ''), color: String(color || ''), status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Break type already exists' });
    return res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/break-types/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, description, color, status } = req.body || {};
  const fields = [], values = [];
  if (name !== undefined) { fields.push('name = ?'); values.push(String(name || '')); }
  if (description !== undefined) { fields.push('description = ?'); values.push(String(description || '')); }
  if (color !== undefined) { fields.push('color = ?'); values.push(String(color || '')); }
  if (status !== undefined) { fields.push('status = ?'); values.push(String(status || 'Active')); }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  values.push(id);
  try {
    const r = await run(`UPDATE break_types SET ${fields.join(', ')} WHERE id = ?`, values);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/break-types/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  try {
    const r = await run(`UPDATE break_types SET status = 'Inactive' WHERE id = ?`, [id]);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// --- Users
app.post('/api/users', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const { username, password, name, email, role } = req.body || {};
  if (!username || !name || !role) return res.status(400).json({ error: 'Required fields missing' });
  const effectivePassword = password && password.length > 0 ? String(password) : 'ChangeMe123!';
  const hashed = bcrypt.hashSync(effectivePassword, 10);
  try {
    const r = await run(`INSERT INTO users (username, password, name, email, role, status, must_change_password) VALUES (?, ?, ?, ?, ?, 'Active', ?)`,
                        [username, hashed, name, email || '', role, password && password.length > 0 ? 0 : 1]);
    addLog(req, 'User Created', username);
    res.status(201).json({ id: r.lastID, username, name, email: email || '', role, status: 'Active' });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists' });
    return res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/users/:id', authenticateUser, checkPermission('Admin'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { name, email, role, status, new_password, must_change_password } = req.body || {};
  const fields = [], values = [];
  if (name !== undefined) { fields.push('name = ?'); values.push(String(name || '')); }
  if (email !== undefined) { fields.push('email = ?'); values.push(String(email || '')); }
  if (role !== undefined) { fields.push('role = ?'); values.push(String(role || 'Employee')); }
  if (status !== undefined) { fields.push('status = ?'); values.push(String(status || 'Active')); }
  if (typeof must_change_password !== 'undefined') { fields.push('must_change_password = ?'); values.push(must_change_password ? 1 : 0); }
  if (new_password) { const hashed = bcrypt.hashSync(String(new_password), 10); fields.push('password = ?'); values.push(hashed); if (typeof must_change_password === 'undefined') fields.push('must_change_password = 1'); }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  values.push(id);
  try {
    const r = await run(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, values);
    addLog(req, 'User Updated', `User ${id} updated`);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// --- Employees update
app.put('/api/employees/:id', authenticateUser, checkPermission('Manager'), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { team_id, department_id, status, user_id } = req.body || {};
  const fields = [], values = [];
  if (team_id !== undefined) { fields.push('team_id = ?'); values.push(team_id || null); }
  if (department_id !== undefined) { fields.push('department_id = ?'); values.push(department_id || null); }
  if (status !== undefined) { fields.push('status = ?'); values.push(status); }
  if (user_id !== undefined) { fields.push('user_id = ?'); values.push(user_id || null); }
  if (!fields.length) return res.status(400).json({ error: 'No fields to update' });
  values.push(id);
  try {
    const r = await run(`UPDATE employees SET ${fields.join(', ')} WHERE id = ?`, values);
    addLog(req, 'Employee Updated', `Employee ${id} updated`);
    res.json({ success: true, changes: r.changes });
  } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// --- Breaks
app.post('/api/breaks/start', authenticateUser, async (req, res) => {
  const userId = req.user.id;
  const { break_type_id } = req.body || {};
  if (!break_type_id) return res.status(400).json({ error: 'break_type_id is required' });

  try {
    const emp = await get(`SELECT * FROM employees WHERE user_id = ? AND status = 'Active'`, [userId]);
    if (!emp) return res.status(400).json({ error: 'No active employee linked to this user' });
    const bt = await get(`SELECT id, name FROM break_types WHERE id = ? AND status = 'Active'`, [break_type_id]);
    if (!bt) return res.status(400).json({ error: 'Invalid break type' });
    const start = new Date().toISOString();
    const r = await run(`INSERT INTO breaks (employee_id, employee_name, break_type_id, break_type_name, start_time) VALUES (?, ?, ?, ?, ?)`,
                        [emp.id, emp.name, bt.id, bt.name, start]);
    addLog(req, 'Break Started', `Employee ${emp.name} -> ${bt.name}`);
    return res.status(201).json({ id: r.lastID, start_time: start });
  } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/breaks/stop', authenticateUser, async (req, res) => {
  const userId = req.user.id;
  try {
    const emp = await get(`SELECT * FROM employees WHERE user_id = ? AND status = 'Active'`, [userId]);
    if (!emp) return res.status(400).json({ error: 'No active employee linked to this user' });
    const br = await get(`SELECT * FROM breaks WHERE employee_id = ? AND end_time IS NULL ORDER BY start_time DESC LIMIT 1`, [emp.id]);
    if (!br) return res.status(400).json({ error: 'No active break found' });
    const end = new Date();
    const start = new Date(br.start_time);
    const duration = Math.max(0, Math.round((end - start) / 60000));
    const endISO = end.toISOString();
    await run(`UPDATE breaks SET end_time = ?, duration = ? WHERE id = ?`, [endISO, duration, br.id]);
    addLog(req, 'Break Stopped', `Employee ${emp.name} (${duration} min)`);
    return res.json({ success: true, end_time: endISO, duration });
  } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

// --- Bootstrap DB and start
(async () => {
  await initSchema();
  await createDefaultAdmin();
  app.listen(PORT, () => console.log(`Break Tracker backend running on http://localhost:${PORT}`));
})();
