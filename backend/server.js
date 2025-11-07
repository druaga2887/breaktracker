try {
  const { ensureDependencies } = require('./scripts/ensure-deps');
  ensureDependencies();
} catch (err) {
  console.error(`Failed to prepare backend dependencies: ${err.message}`);
  process.exit(1);
}

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mountStaticUI = require('./serveStaticUI');

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));

const PORT = Number(process.env.PORT) || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.json');

const staticDir = path.join(__dirname, 'public');
const hasStatic = fs.existsSync(staticDir);
if (!hasStatic) {
  console.warn('[serveStaticUI] Static UI directory not found:', staticDir);
}

function defaultDatabase() {
  return {
    sequence: {
      users: 0,
      departments: 0,
      teams: 0,
      break_types: 0,
      employees: 0,
      breaks: 0,
    },
    users: [],
    departments: [],
    teams: [],
    break_types: [],
    employees: [],
    breaks: [],
  };
}

function loadDatabase() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      return defaultDatabase();
    }
    const contents = fs.readFileSync(DB_PATH, 'utf8');
    if (!contents.trim()) {
      return defaultDatabase();
    }
    const parsed = JSON.parse(contents);
    if (!parsed.sequence) {
      parsed.sequence = defaultDatabase().sequence;
    }
    return parsed;
  } catch (err) {
    console.error('Failed to read database file, falling back to empty store:', err.message);
    return defaultDatabase();
  }
}

const db = loadDatabase();

function ensureSequence(table) {
  const maxId = (db[table] || []).reduce((max, item) => (item.id && item.id > max ? item.id : max), 0);
  db.sequence[table] = Math.max(db.sequence[table] || 0, maxId);
}

['users', 'departments', 'teams', 'break_types', 'employees', 'breaks'].forEach(ensureSequence);

function persistDatabase() {
  try {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error('Failed to persist database:', err.message);
  }
}

function nextId(table) {
  db.sequence[table] = (db.sequence[table] || 0) + 1;
  return db.sequence[table];
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(derived, 'hex'));
}

function parseExpiry(expiresIn) {
  if (!expiresIn) return 0;
  if (typeof expiresIn === 'number') return expiresIn;
  const match = String(expiresIn).match(/^(\d+)([smhd])$/);
  if (!match) return 0;
  const value = Number(match[1]);
  const unit = match[2];
  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 3600;
    case 'd':
      return value * 86400;
    default:
      return 0;
  }
}

function signToken(payload, secret, options = {}) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const basePayload = { ...payload };
  const expires = parseExpiry(options.expiresIn);
  if (expires > 0) {
    basePayload.exp = Math.floor(Date.now() / 1000) + expires;
  }
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(basePayload)).toString('base64url');
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${signature}`;
}

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');
});

function run(sql, p=[]) { return new Promise((res, rej) => db.run(sql, p, function(e){e?rej(e):res(this)})); }
function get(sql, p=[]) { return new Promise((res, rej) => db.get(sql, p, (e,r)=>e?rej(e):res(r))); }
function all(sql, p=[]) { return new Promise((res, rej) => db.all(sql, p, (e,r)=>e?rej(e):res(r))); }

async function init() {
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, must_change_password INTEGER DEFAULT 1, name TEXT DEFAULT '', role TEXT DEFAULT 'employee')`);
  const userColumns = await all('PRAGMA table_info(users)');
  if (!userColumns.some((c) => c.name === 'role')) {
    await run(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'employee'`);
  }
  await run(`CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS teams (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', color TEXT DEFAULT '', department_id INTEGER, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(department_id) REFERENCES departments(id))`);
  await run(`CREATE TABLE IF NOT EXISTS break_types (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '', status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, name TEXT NOT NULL, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, department_id INTEGER, team_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(department_id) REFERENCES departments(id), FOREIGN KEY(team_id) REFERENCES teams(id))`);
  await run(`CREATE TABLE IF NOT EXISTS breaks (id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL, break_type_id INTEGER NOT NULL, start_time TEXT NOT NULL, end_time TEXT, duration INTEGER, FOREIGN KEY(employee_id) REFERENCES employees(id), FOREIGN KEY(break_type_id) REFERENCES break_types(id))`);

  let admin = await get(`SELECT * FROM users WHERE username='admin'`);
  if (!admin) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await run(`INSERT INTO users (username,password,must_change_password,name,role) VALUES (?,?,1,?,'admin')`, ['admin', hashed, 'Admin']);
    admin = await get(`SELECT * FROM users WHERE username='admin'`);
    console.log('Seeded admin / admin123');
  } else if (existing.role !== 'admin') {
    existing.role = 'admin';
  }

  const admin = db.users.find((user) => user.username === 'admin');
  const existingEmployee = db.employees.find((emp) => emp.user_id === admin.id);
  if (!existingEmployee) {
    db.employees.push({
      id: nextId('employees'),
      user_id: admin.id,
      name: admin.name || 'Admin',
      department_id: null,
      team_id: null,
      status: 'Active',
      created_at: new Date().toISOString(),
    });
  }
  if (admin.role !== 'admin') {
    await run(`UPDATE users SET role='admin' WHERE id=?`, [admin.id]);
  }
  const emp = await get(`SELECT id FROM employees WHERE user_id=?`, [admin.id]);
  if (!emp) await run(`INSERT INTO employees (user_id,name,status) VALUES (?,?, 'Active')`, [admin.id, 'Admin']);
}

// health
app.get('/api/health', async (_req, res) => {
  try {
    const row = await get('SELECT 1 AS ok');
    res.json({ status: 'ok', db: row?.ok === 1 ? 'ok' : 'unknown', version: '1.0.0' });
  } catch {
    res.status(500).json({ status: 'error', db: 'down', version: '1.0.0' });
  }
});

// auth
function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ')? h.slice(7): '';
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error:'Unauthorized' }); }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}
app.post('/api/auth/login', async (req,res)=>{
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'Missing credentials' });
  const u = await get(`SELECT * FROM users WHERE username=?`, [username]).catch(()=>null);
  if (!u || !bcrypt.compareSync(password, u.password)) return res.status(401).json({ error:'Invalid credentials' });
  const token = jwt.sign({ id: u.id, username: u.username, role: u.role || 'employee' }, JWT_SECRET, { expiresIn:'8h' });
  res.json({ token, must_change_password: !!u.must_change_password, role: u.role || 'employee' });
});
app.post('/api/auth/change-password', auth, async (req,res)=>{
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password || new_password.length<8) return res.status(400).json({ error:'Invalid payload' });
  const u = await get(`SELECT * FROM users WHERE id=?`, [req.user.id]).catch(()=>null);
  if (!u || !bcrypt.compareSync(current_password, u.password)) return res.status(400).json({ error:'Current password incorrect' });
  const hashed = bcrypt.hashSync(new_password, 10);
  await run(`UPDATE users SET password=?, must_change_password=0 WHERE id=?`, [hashed, req.user.id]);
  res.json({ success:true });
});

app.get('/api/auth/me', auth, async (req, res) => {
  const u = await get(`SELECT id, username, name, role, must_change_password FROM users WHERE id=?`, [req.user.id]).catch(()=>null);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json(u);
});

// departments
app.get('/api/departments', auth, async (_req,res)=>{
  res.json(await all(`SELECT * FROM departments ORDER BY id ASC`).catch(()=>[]));
});
app.post('/api/departments', auth, requireRole('admin'), async (req,res)=>{
  const { name, description } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error:'Name is required' });
  try {
    const r = await run(`INSERT INTO departments (name,description,status) VALUES (?,?, 'Active')`, [name.trim(), String(description||'')]);
    res.status(201).json({ id:r.lastID, name:name.trim(), description:String(description||''), status:'Active' });
  } catch(e){
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error:'Department already exists' });
    res.status(500).json({ error:'Database error' });
  }
  user.password = hashPassword(new_password);
  user.must_change_password = 0;
  persistDatabase();
  return { status: 200, body: { success: true } };
});
app.put('/api/departments/:id', auth, requireRole('admin'), async (req,res)=>{
  const id = parseInt(req.params.id, 10);
  const { name, description, status } = req.body || {};
  const fields = [];
  const values = [];
  if (name !== undefined) { fields.push('name=?'); values.push(String(name || '')); }
  if (description !== undefined) { fields.push('description=?'); values.push(String(description || '')); }
  if (status !== undefined) { fields.push('status=?'); values.push(String(status || 'Active')); }
  if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
  try {
    values.push(id);
    const r = await run(`UPDATE departments SET ${fields.join(', ')} WHERE id=?`, values);
    res.json({ success: true, changes: r.changes });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Department already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});

// teams
app.get('/api/teams', auth, async (_req,res)=>{
  const rows = await all(`
    SELECT t.*, d.name AS department_name
    FROM teams t
    LEFT JOIN departments d ON d.id = t.department_id
    ORDER BY t.id ASC
  `).catch(()=>[]);
  res.json(rows);
});
app.post('/api/teams', auth, requireRole('admin'), async (req,res)=>{
  const { name, description, color } = req.body || {}; let { department_id } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error:'Name is required' });
  try {
    if (!department_id) {
      const dep = await get(`SELECT id FROM departments WHERE status='Active' ORDER BY id ASC LIMIT 1`);
      if (!dep) return res.status(400).json({ error:'No departments. Create one first or provide department_id.' });
      department_id = dep.id;
    }
    const r = await run(`INSERT INTO teams (name,description,color,department_id,status) VALUES (?,?,?,?, 'Active')`,
      [name.trim(), String(description||''), String(color||''), department_id]);
    res.status(201).json({ id:r.lastID, name:name.trim(), description:String(description||''), color:String(color||''), department_id, status:'Active' });
  } catch(e){
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error:'Team already exists' });
    if (String(e).includes('FOREIGN KEY')) return res.status(400).json({ error:'Invalid department_id' });
    res.status(500).json({ error:'Database error' });
  }
});
app.put('/api/teams/:id', auth, requireRole('admin'), async (req,res)=>{
  const id = parseInt(req.params.id, 10);
  const { name, description, color, department_id, status } = req.body || {};
  const fields = [];
  const values = [];
  if (name !== undefined) { fields.push('name=?'); values.push(String(name || '')); }
  if (description !== undefined) { fields.push('description=?'); values.push(String(description || '')); }
  if (color !== undefined) { fields.push('color=?'); values.push(String(color || '')); }
  if (department_id !== undefined) {
    if (department_id === null) {
      fields.push('department_id=NULL');
    } else {
      const dep = await get(`SELECT id FROM departments WHERE id=?`, [department_id]).catch(()=>null);
      if (!dep) return res.status(400).json({ error:'Invalid department_id' });
      fields.push('department_id=?'); values.push(department_id);
    }
  }
  if (status !== undefined) { fields.push('status=?'); values.push(String(status || 'Active')); }
  if (!fields.length) return res.status(400).json({ error: 'nothing to update' });
  try {
    if (!fields.some(f => f.startsWith('department_id'))) {
      // no department change requested, safe to append id at end
      values.push(id);
      const r = await run(`UPDATE teams SET ${fields.join(', ')} WHERE id=?`, values);
      return res.json({ success: true, changes: r.changes });
    }
    const query = `UPDATE teams SET ${fields.join(', ')} WHERE id=?`;
    values.push(id);
    const r = await run(query, values);
    res.json({ success: true, changes: r.changes });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Team already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});

// break types
app.get('/api/break-types', auth, async (req,res)=>{
  const includeInactive = req.query.includeInactive === '1';
  const sql = includeInactive ?
    'SELECT * FROM break_types ORDER BY id ASC' :
    `SELECT * FROM break_types WHERE status='Active' ORDER BY id ASC`;
  res.json(await all(sql).catch(()=>[]));
});
app.post('/api/break-types', auth, requireRole('admin'), async (req,res)=>{
  const { name, color } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error:'Name is required' });
  try {
    const r = await run(`INSERT INTO break_types (name,color,status) VALUES (?,?,'Active')`, [name.trim(), String(color||'')]);
    res.status(201).json({ id:r.lastID, name:name.trim(), color:String(color||''), status:'Active' });
  } catch(e){
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error:'Break type already exists' });
    res.status(500).json({ error:'Database error' });
  }
});
app.put('/api/break-types/:id', auth, requireRole('admin'), async (req,res)=>{
  const id = parseInt(req.params.id, 10);
  const { name, color, status } = req.body || {};
  const fields = [];
  const values = [];
  if (name !== undefined) { fields.push('name=?'); values.push(String(name || '')); }
  if (color !== undefined) { fields.push('color=?'); values.push(String(color || '')); }
  if (status !== undefined) { fields.push('status=?'); values.push(String(status || 'Active')); }
  if (!fields.length) return res.status(400).json({ error:'nothing to update' });
  try {
    values.push(id);
    const r = await run(`UPDATE break_types SET ${fields.join(', ')} WHERE id=?`, values);
    res.json({ success:true, changes:r.changes });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error:'Break type already exists' });
    res.status(500).json({ error:'Database error' });
  }
});

// users
app.get('/api/users', auth, requireRole('admin'), async (_req,res)=>{
  const users = await all(`SELECT id, username, must_change_password, name, role FROM users ORDER BY id ASC`).catch(()=>[]);
  res.json(users);
});
app.post('/api/users', auth, requireRole('admin'), async (req,res)=>{
  const { username, password, name, role = 'employee', must_change_password = 1 } = req.body || {};
  if (!username || !username.trim()) return res.status(400).json({ error: 'username required' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });
  const normalizedRole = ['admin', 'manager', 'employee'].includes(role) ? role : 'employee';
  const hashed = bcrypt.hashSync(password, 10);
  try {
    const r = await run(
      `INSERT INTO users (username, password, must_change_password, name, role) VALUES (?,?,?,?,?)`,
      [username.trim(), hashed, must_change_password ? 1 : 0, String(name || ''), normalizedRole]
    );
    res.status(201).json({ id: r.lastID, username: username.trim(), must_change_password: !!must_change_password, name: String(name || ''), role: normalizedRole });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});
app.put('/api/users/:id', auth, requireRole('admin'), async (req,res)=>{
  const id = parseInt(req.params.id, 10);
  const { name, password, must_change_password, role } = req.body || {};
  const fields = [];
  const values = [];
  if (name !== undefined) { fields.push('name=?'); values.push(String(name || '')); }
  if (must_change_password !== undefined) { fields.push('must_change_password=?'); values.push(must_change_password ? 1 : 0); }
  if (role !== undefined) {
    const normalizedRole = ['admin', 'manager', 'employee'].includes(role) ? role : 'employee';
    fields.push('role=?');
    values.push(normalizedRole);
  }
  if (password !== undefined) {
    if (!password || password.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });
    const hashed = bcrypt.hashSync(password, 10);
    fields.push('password=?');
    values.push(hashed);
    if (!fields.some(f => f.startsWith('must_change_password'))) {
      fields.push('must_change_password=?');
      values.push(1);
    }
  }
  if (!fields.length) return res.status(400).json({ error:'nothing to update' });
  try {
    values.push(id);
    const r = await run(`UPDATE users SET ${fields.join(', ')} WHERE id=?`, values);
    res.json({ success:true, changes:r.changes });
  } catch (e) {
    res.status(500).json({ error:'Database error' });
  }
});

// breaks
app.post('/api/breaks/start', auth, async (req,res)=>{
  const { break_type_id } = req.body || {};
  if (!break_type_id) return res.status(400).json({ error:'break_type_id is required' });
  const bt = await get(`SELECT id FROM break_types WHERE id = ? AND status='Active'`, [break_type_id]).catch(()=>null);
  if (!bt) return res.status(400).json({ error:'Invalid break type' });
  let emp = await get(`SELECT id,name FROM employees WHERE user_id=?`, [req.user.id]).catch(()=>null);
  if (!emp) {
    const user = await get(`SELECT username FROM users WHERE id=?`, [req.user.id]).catch(()=>null);
    const name = (user?.username || `User${req.user.id}`);
    const r = await run(`INSERT INTO employees (user_id,name,status) VALUES (?,?,'Active')`, [req.user.id, name]);
    emp = { id:r.lastID, name };
  }
  const start = new Date().toISOString();
  const r = await run(`INSERT INTO breaks (employee_id,break_type_id,start_time) VALUES (?,?,?)`, [emp.id, break_type_id, start]);
  res.status(201).json({ id:r.lastID, start_time:start });
});
app.post('/api/breaks/stop', auth, async (req,res)=>{
  const emp = await get(`SELECT id FROM employees WHERE user_id=?`, [req.user.id]).catch(()=>null);
  if (!emp) return res.status(400).json({ error:'No employee found' });
  const br = await get(`SELECT * FROM breaks WHERE employee_id=? AND end_time IS NULL ORDER BY id DESC LIMIT 1`, [emp.id]).catch(()=>null);
  if (!br) return res.status(400).json({ error:'No active break' });
  const end = new Date();
  const duration = Math.max(0, Math.round((end - new Date(br.start_time))/60000));
  await run(`UPDATE breaks SET end_time=?, duration=? WHERE id=?`, [end.toISOString(), duration, br.id]);
  res.json({ success:true, duration });
});

app.get('/api/status/live', auth, requireRole('manager', 'admin'), async (_req,res)=>{
  const rows = await all(`
    SELECT b.id as break_id,
           e.name AS employee_name,
           e.department_id,
           e.team_id,
           t.name AS team_name,
           d.name AS department_name,
           bt.name AS break_type,
           b.start_time,
           bt.color AS break_color
    FROM breaks b
    JOIN employees e ON e.id = b.employee_id
    LEFT JOIN teams t ON t.id = e.team_id
    LEFT JOIN departments d ON d.id = e.department_id
    JOIN break_types bt ON bt.id = b.break_type_id
    WHERE b.end_time IS NULL
    ORDER BY b.start_time ASC
  `).catch(()=>[]);
  res.json(rows);
});

app.get('/api/reports/summary', auth, requireRole('manager', 'admin'), async (req,res)=>{
  let { start, end, department_id, team_id, break_type_id } = req.query;
  const now = new Date();
  const defaultStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const parsedStart = start ? new Date(start) : defaultStart;
  const parsedEnd = end ? new Date(end) : now;
  if (isNaN(parsedStart)) return res.status(400).json({ error: 'Invalid start date' });
  if (isNaN(parsedEnd)) return res.status(400).json({ error: 'Invalid end date' });
  const startIso = parsedStart.toISOString();
  const endIso = parsedEnd.toISOString();
  const filters = [];
  const params = [startIso, endIso];
  if (department_id) {
    filters.push('e.department_id = ?');
    params.push(Number(department_id));
  }
  if (team_id) {
    filters.push('e.team_id = ?');
    params.push(Number(team_id));
  }
  if (break_type_id) {
    filters.push('bt.id = ?');
    params.push(Number(break_type_id));
  }
  const filterClause = filters.length ? ` AND ${filters.join(' AND ')}` : '';
  const rows = await all(`
    SELECT e.id AS employee_id,
           e.name AS employee_name,
           e.department_id,
           e.team_id,
           d.name AS department_name,
           t.name AS team_name,
           bt.name AS break_type,
           bt.id AS break_type_id,
           COUNT(b.id) AS break_count,
           COALESCE(SUM(b.duration), 0) AS total_minutes
    FROM breaks b
    JOIN employees e ON e.id = b.employee_id
    LEFT JOIN teams t ON t.id = e.team_id
    LEFT JOIN departments d ON d.id = e.department_id
    JOIN break_types bt ON bt.id = b.break_type_id
    WHERE b.start_time BETWEEN ? AND ?
      AND b.end_time IS NOT NULL
      ${filterClause}
    GROUP BY e.id, bt.id
    ORDER BY department_name, team_name, employee_name, bt.name
  `, params).catch(()=>[]);
  res.json({ start: startIso, end: endIso, rows });
});

// employees
app.get('/api/employees', auth, requireRole('admin'), async (_req,res)=>{ res.json(await all(`SELECT * FROM employees ORDER BY id ASC`).catch(()=>[])); });
app.post('/api/employees', auth, requireRole('admin'), async (req,res)=>{
  const { user_id, name, department_id, team_id, status } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error:'name required' });
  if (user_id) { const u = await get(`SELECT id FROM users WHERE id=?`, [user_id]).catch(()=>null); if (!u) return res.status(400).json({ error:'invalid user_id' }); }
  if (department_id) { const d = await get(`SELECT id FROM departments WHERE id=?`, [department_id]).catch(()=>null); if (!d) return res.status(400).json({ error:'invalid department_id' }); }
  if (team_id) { const t = await get(`SELECT id FROM teams WHERE id=?`, [team_id]).catch(()=>null); if (!t) return res.status(400).json({ error:'invalid team_id' }); }
  const r = await run(`INSERT INTO employees (user_id,name,department_id,team_id,status) VALUES (?,?,?,?,?)`,
    [user_id || null, name.trim(), department_id || null, team_id || null, status || 'Active']);
  res.status(201).json({ id:r.lastID, name:name.trim(), user_id:user_id||null, department_id:department_id||null, team_id:team_id||null, status:status||'Active' });
});
app.put('/api/employees/:id', auth, requireRole('admin'), async (req,res)=>{
  const id = parseInt(req.params.id,10);
  const { name, department_id, team_id, status, user_id } = req.body || {};
  const f=[], v=[];
  if (name!==undefined){ f.push('name=?'); v.push(String(name||'')); }
  if (department_id!==undefined){ f.push('department_id=?'); v.push(department_id||null); }
  if (team_id!==undefined){ f.push('team_id=?'); v.push(team_id||null); }
  if (status!==undefined){ f.push('status=?'); v.push(String(status||'Active')); }
  if (user_id!==undefined){ f.push('user_id=?'); v.push(user_id||null); }
  if (!f.length) return res.status(400).json({ error:'nothing to update' });
  v.push(id);
  const r = await run(`UPDATE employees SET ${f.join(', ')} WHERE id=?`, v);
  res.json({ success:true, changes:r.changes });
});

// ---- serve built UI (after /api routes, before any 404/error handlers) ----
mountStaticUI(app);

process.on('unhandledRejection', e=>{ console.error('unhandledRejection:', e); process.exit(1); });
process.on('uncaughtException', e=>{ console.error('uncaughtException:', e); process.exit(1); });

init().then(()=> app.listen(PORT, HOST, ()=>console.log(`Backend running on http://${HOST}:${PORT}`)));
