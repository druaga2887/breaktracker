const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

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

function run(sql, p=[]) { return new Promise((res, rej) => db.run(sql, p, function(e){e?rej(e):res(this)})); }
function get(sql, p=[]) { return new Promise((res, rej) => db.get(sql, p, (e,r)=>e?rej(e):res(r))); }
function all(sql, p=[]) { return new Promise((res, rej) => db.all(sql, p, (e,r)=>e?rej(e):res(r))); }

async function init() {
  await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, must_change_password INTEGER DEFAULT 1, name TEXT DEFAULT '')`);
  await run(`CREATE TABLE IF NOT EXISTS departments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS teams (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, description TEXT DEFAULT '', color TEXT DEFAULT '', department_id INTEGER, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(department_id) REFERENCES departments(id))`);
  await run(`CREATE TABLE IF NOT EXISTS break_types (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, color TEXT DEFAULT '', status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER UNIQUE, name TEXT NOT NULL, status TEXT DEFAULT 'Active', created_at TEXT DEFAULT CURRENT_TIMESTAMP, department_id INTEGER, team_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id), FOREIGN KEY(department_id) REFERENCES departments(id), FOREIGN KEY(team_id) REFERENCES teams(id))`);
  await run(`CREATE TABLE IF NOT EXISTS breaks (id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id INTEGER NOT NULL, break_type_id INTEGER NOT NULL, start_time TEXT NOT NULL, end_time TEXT, duration INTEGER, FOREIGN KEY(employee_id) REFERENCES employees(id), FOREIGN KEY(break_type_id) REFERENCES break_types(id))`);

  let admin = await get(`SELECT * FROM users WHERE username='admin'`);
  if (!admin) {
    const hashed = bcrypt.hashSync('admin123', 10);
    await run(`INSERT INTO users (username,password,must_change_password,name) VALUES (?,?,1,?)`, ['admin', hashed, 'Admin']);
    admin = await get(`SELECT * FROM users WHERE username='admin'`);
    console.log('Seeded admin / admin123');
  }
  const emp = await get(`SELECT id FROM employees WHERE user_id=?`, [admin.id]);
  if (!emp) await run(`INSERT INTO employees (user_id,name,status) VALUES (?,?, 'Active')`, [admin.id, 'Admin']);
}

// health
app.get('/api/health', async (_req, res) => {
  try { const row = await get('SELECT 1 AS ok'); res.json({ status:'ok', db: row?.ok===1?'ok':'unknown' }); }
  catch { res.status(500).json({ status:'error', db:'down' }); }
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
app.post('/api/auth/login', async (req,res)=>{
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'Missing credentials' });
  const u = await get(`SELECT * FROM users WHERE username=?`, [username]).catch(()=>null);
  if (!u || !bcrypt.compareSync(password, u.password)) return res.status(401).json({ error:'Invalid credentials' });
  const token = jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn:'8h' });
  res.json({ token, must_change_password: !!u.must_change_password });
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

// departments
app.get('/api/departments', auth, async (_req,res)=>{ res.json(await all(`SELECT * FROM departments ORDER BY id ASC`).catch(()=>[])); });
app.post('/api/departments', auth, async (req,res)=>{
  const { name, description } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error:'Name is required' });
  try {
    const r = await run(`INSERT INTO departments (name,description,status) VALUES (?,?, 'Active')`, [name.trim(), String(description||'')]);
    res.status(201).json({ id:r.lastID, name:name.trim(), description:String(description||''), status:'Active' });
  } catch(e){
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error:'Department already exists' });
    res.status(500).json({ error:'Database error' });
  }
});

// teams
app.post('/api/teams', auth, async (req,res)=>{
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

// break types
app.get('/api/break-types', auth, async (_req,res)=>{ res.json(await all(`SELECT * FROM break_types WHERE status='Active' ORDER BY id ASC`).catch(()=>[])); });
app.post('/api/break-types', auth, async (req,res)=>{
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
app.post('/api/breaks/stop', auth, async (_req,res)=>{
  const emp = await get(`SELECT id FROM employees WHERE user_id=?`, [req.user.id]).catch(()=>null);
  if (!emp) return res.status(400).json({ error:'No employee found' });
  const br = await get(`SELECT * FROM breaks WHERE employee_id=? AND end_time IS NULL ORDER BY id DESC LIMIT 1`, [emp.id]).catch(()=>null);
  if (!br) return res.status(400).json({ error:'No active break' });
  const end = new Date();
  const duration = Math.max(0, Math.round((end - new Date(br.start_time))/60000));
  await run(`UPDATE breaks SET end_time=?, duration=? WHERE id=?`, [end.toISOString(), duration, br.id]);
  res.json({ success:true, duration });
});

// employees
app.get('/api/employees', auth, async (_req,res)=>{ res.json(await all(`SELECT * FROM employees ORDER BY id ASC`).catch(()=>[])); });
app.post('/api/employees', auth, async (req,res)=>{
  const { user_id, name, department_id, team_id, status } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error:'name required' });
  if (user_id) { const u = await get(`SELECT id FROM users WHERE id=?`, [user_id]).catch(()=>null); if (!u) return res.status(400).json({ error:'invalid user_id' }); }
  if (department_id) { const d = await get(`SELECT id FROM departments WHERE id=?`, [department_id]).catch(()=>null); if (!d) return res.status(400).json({ error:'invalid department_id' }); }
  if (team_id) { const t = await get(`SELECT id FROM teams WHERE id=?`, [team_id]).catch(()=>null); if (!t) return res.status(400).json({ error:'invalid team_id' }); }
  const r = await run(`INSERT INTO employees (user_id,name,department_id,team_id,status) VALUES (?,?,?,?,?)`,
    [user_id || null, name.trim(), department_id || null, team_id || null, status || 'Active']);
  res.status(201).json({ id:r.lastID, name:name.trim(), user_id:user_id||null, department_id:department_id||null, team_id:team_id||null, status:status||'Active' });
});
app.put('/api/employees/:id', auth, async (req,res)=>{
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
const publicDir = path.resolve(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir, { index: 'index.html', maxAge: '15m' }));
  app.get(/^\/(?!api).*/, (_req, res) => res.sendFile(path.join(publicDir, 'index.html')));
} else {
  console.warn('Static UI directory not found:', publicDir);
}

process.on('unhandledRejection', e=>{ console.error('unhandledRejection:', e); process.exit(1); });
process.on('uncaughtException', e=>{ console.error('uncaughtException:', e); process.exit(1); });

init().then(()=> app.listen(PORT, HOST, ()=>console.log(`Backend running on http://${HOST}:${PORT}`)));
