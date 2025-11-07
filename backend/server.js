const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const PORT = Number(process.env.PORT || 3001);
const HOST = process.env.HOST || '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function seedAdmin() {
  const admin = await get('SELECT id FROM users WHERE username = ?', ['admin']);
  if (!admin) {
    const hash = await bcrypt.hash('admin123', 10);
    await run(
      `INSERT INTO users (username, password, must_change_password, name, role, status)
       VALUES (?, ?, 1, ?, 'admin', 'Active')`,
      ['admin', hash, 'Admin']
    );
    console.log('Seeded default admin user (admin / admin123).');
  }
}

function toUserResponse(row) {
  if (!row) return null;
  const { password, ...rest } = row;
  return {
    ...rest,
    must_change_password: Boolean(row.must_change_password),
  };
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = header.slice('Bearer '.length);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.get('/api/health', async (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  try {
    const user = await get('SELECT * FROM users WHERE username = ? AND status = "Active"', [username]);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, {
      expiresIn: '8h',
    });
    res.json({
      token,
      role: user.role,
      must_change_password: Boolean(user.must_change_password),
      name: user.name,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Both current and new password are required' });
  }
  try {
    const user = await get('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const ok = await bcrypt.compare(current_password, user.password);
    if (!ok) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    const hash = await bcrypt.hash(new_password, 10);
    await run('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?', [hash, req.user.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await get('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(toUserResponse(user));
  } catch (err) {
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.get('/api/departments', authMiddleware, async (_req, res) => {
  try {
    const rows = await all('SELECT * FROM departments');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load departments' });
  }
});

app.post('/api/departments', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, description = '', status = 'Active' } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Name is required' });
  try {
    const result = await run('INSERT INTO departments (name, description, status) VALUES (?, ?, ?)', [name, description, status]);
    const created = await get('SELECT * FROM departments WHERE id = ?', [result.lastID]);
    res.status(201).json(created);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create department' });
  }
});

app.put('/api/departments/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, description, status } = req.body || {};
  try {
    const existing = await get('SELECT * FROM departments WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Department not found' });
    await run(
      'UPDATE departments SET name = ?, description = ?, status = ? WHERE id = ?',
      [name ?? existing.name, description ?? existing.description, status ?? existing.status, req.params.id]
    );
    const updated = await get('SELECT * FROM departments WHERE id = ?', [req.params.id]);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update department' });
  }
});

app.get('/api/teams', authMiddleware, async (_req, res) => {
  try {
    const rows = await all(
      `SELECT teams.*, departments.name AS department_name
       FROM teams
       LEFT JOIN departments ON teams.department_id = departments.id`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load teams' });
  }
});

app.post('/api/teams', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, description = '', department_id, status = 'Active' } = req.body || {};
  if (!name || !department_id) {
    return res.status(400).json({ error: 'Name and department are required' });
  }
  try {
    const department = await get('SELECT id FROM departments WHERE id = ?', [department_id]);
    if (!department) return res.status(400).json({ error: 'Invalid department' });
    const result = await run(
      'INSERT INTO teams (name, description, department_id, status) VALUES (?, ?, ?, ?)',
      [name, description, department_id, status]
    );
    const created = await get('SELECT * FROM teams WHERE id = ?', [result.lastID]);
    res.status(201).json(created);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create team' });
  }
});

app.put('/api/teams/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, description, department_id, status } = req.body || {};
  try {
    const existing = await get('SELECT * FROM teams WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Team not found' });
    const deptId = department_id ?? existing.department_id;
    const department = await get('SELECT id FROM departments WHERE id = ?', [deptId]);
    if (!department) return res.status(400).json({ error: 'Invalid department' });
    await run(
      'UPDATE teams SET name = ?, description = ?, department_id = ?, status = ? WHERE id = ?',
      [name ?? existing.name, description ?? existing.description, deptId, status ?? existing.status, req.params.id]
    );
    const updated = await get('SELECT * FROM teams WHERE id = ?', [req.params.id]);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update team' });
  }
});

app.get('/api/break-types', authMiddleware, async (_req, res) => {
  try {
    const rows = await all('SELECT * FROM break_types');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load break types' });
  }
});

app.post('/api/break-types', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, color = '#cccccc', status = 'Active' } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Name is required' });
  try {
    const result = await run('INSERT INTO break_types (name, color, status) VALUES (?, ?, ?)', [name, color, status]);
    const created = await get('SELECT * FROM break_types WHERE id = ?', [result.lastID]);
    res.status(201).json(created);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create break type' });
  }
});

app.put('/api/break-types/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, color, status } = req.body || {};
  try {
    const existing = await get('SELECT * FROM break_types WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Break type not found' });
    await run(
      'UPDATE break_types SET name = ?, color = ?, status = ? WHERE id = ?',
      [name ?? existing.name, color ?? existing.color, status ?? existing.status, req.params.id]
    );
    const updated = await get('SELECT * FROM break_types WHERE id = ?', [req.params.id]);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update break type' });
  }
});

app.get('/api/users', authMiddleware, requireRole('admin'), async (_req, res) => {
  try {
    const rows = await all('SELECT id, username, name, role, status, must_change_password FROM users');
    res.json(rows.map(toUserResponse));
  } catch (err) {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

app.post('/api/users', authMiddleware, requireRole('admin'), async (req, res) => {
  const { username, password, name, role = 'employee', must_change_password = 1, status = 'Active' } = req.body || {};
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Username, password, and name are required' });
  }
  if (!['admin', 'manager', 'employee'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await run(
      `INSERT INTO users (username, password, name, role, must_change_password, status)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [username, hash, name, role, must_change_password ? 1 : 0, status]
    );
    const created = await get('SELECT * FROM users WHERE id = ?', [result.lastID]);
    res.status(201).json(toUserResponse(created));
  } catch (err) {
    if (err && err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/users/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, role, status, must_change_password } = req.body || {};
  try {
    const existing = await get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'User not found' });
    const updatedRole = role ?? existing.role;
    if (!['admin', 'manager', 'employee'].includes(updatedRole)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    await run(
      'UPDATE users SET name = ?, role = ?, status = ?, must_change_password = ? WHERE id = ?',
      [
        name ?? existing.name,
        updatedRole,
        status ?? existing.status,
        must_change_password === undefined ? existing.must_change_password : must_change_password ? 1 : 0,
        req.params.id,
      ]
    );
    const updated = await get('SELECT * FROM users WHERE id = ?', [req.params.id]);
    res.json(toUserResponse(updated));
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.get('/api/employees', authMiddleware, async (_req, res) => {
  try {
    const rows = await all(
      `SELECT employees.*, users.username, users.role
       FROM employees
       LEFT JOIN users ON employees.user_id = users.id`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load employees' });
  }
});

app.post('/api/employees', authMiddleware, requireRole('admin'), async (req, res) => {
  const { user_id, name, department_id, team_id, status = 'Active' } = req.body || {};
  if (!user_id || !name) {
    return res.status(400).json({ error: 'User and name are required' });
  }
  try {
    const user = await get('SELECT id FROM users WHERE id = ?', [user_id]);
    if (!user) return res.status(400).json({ error: 'Invalid user' });
    if (department_id) {
      const dept = await get('SELECT id FROM departments WHERE id = ?', [department_id]);
      if (!dept) return res.status(400).json({ error: 'Invalid department' });
    }
    if (team_id) {
      const team = await get('SELECT id FROM teams WHERE id = ?', [team_id]);
      if (!team) return res.status(400).json({ error: 'Invalid team' });
    }
    const result = await run(
      `INSERT INTO employees (user_id, name, department_id, team_id, status)
       VALUES (?, ?, ?, ?, ?)`,
      [user_id, name, department_id || null, team_id || null, status]
    );
    const created = await get('SELECT * FROM employees WHERE id = ?', [result.lastID]);
    res.status(201).json(created);
  } catch (err) {
    if (err && err.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Employee already exists for this user' });
    }
    res.status(500).json({ error: 'Failed to create employee' });
  }
});

app.put('/api/employees/:id', authMiddleware, requireRole('admin'), async (req, res) => {
  const { name, department_id, team_id, status } = req.body || {};
  try {
    const existing = await get('SELECT * FROM employees WHERE id = ?', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Employee not found' });
    const deptId = department_id ?? existing.department_id;
    const teamId = team_id ?? existing.team_id;
    if (deptId) {
      const dept = await get('SELECT id FROM departments WHERE id = ?', [deptId]);
      if (!dept) return res.status(400).json({ error: 'Invalid department' });
    }
    if (teamId) {
      const team = await get('SELECT id FROM teams WHERE id = ?', [teamId]);
      if (!team) return res.status(400).json({ error: 'Invalid team' });
    }
    await run(
      `UPDATE employees SET name = ?, department_id = ?, team_id = ?, status = ? WHERE id = ?`,
      [
        name ?? existing.name,
        deptId || null,
        teamId || null,
        status ?? existing.status,
        req.params.id,
      ]
    );
    const updated = await get('SELECT * FROM employees WHERE id = ?', [req.params.id]);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update employee' });
  }
});

async function getEmployeeForUser(userId) {
  return get('SELECT * FROM employees WHERE user_id = ? AND status = "Active"', [userId]);
}

app.post('/api/breaks/start', authMiddleware, requireRole('admin', 'manager', 'employee'), async (req, res) => {
  const { break_type_id } = req.body || {};
  if (!break_type_id) return res.status(400).json({ error: 'Break type is required' });
  try {
    const breakType = await get('SELECT * FROM break_types WHERE id = ? AND status = "Active"', [break_type_id]);
    if (!breakType) return res.status(400).json({ error: 'Invalid break type' });
    const employee = await getEmployeeForUser(req.user.id);
    if (!employee) return res.status(400).json({ error: 'No employee record for user' });
    const active = await get('SELECT * FROM breaks WHERE employee_id = ? AND end_time IS NULL', [employee.id]);
    if (active) return res.status(400).json({ error: 'Break already active' });
    const now = new Date().toISOString();
    const result = await run(
      'INSERT INTO breaks (employee_id, break_type_id, start_time) VALUES (?, ?, ?)',
      [employee.id, break_type_id, now]
    );
    const created = await get('SELECT * FROM breaks WHERE id = ?', [result.lastID]);
    res.status(201).json(created);
  } catch (err) {
    res.status(500).json({ error: 'Failed to start break' });
  }
});

app.post('/api/breaks/stop', authMiddleware, requireRole('admin', 'manager', 'employee'), async (req, res) => {
  try {
    const employee = await getEmployeeForUser(req.user.id);
    if (!employee) return res.status(400).json({ error: 'No employee record for user' });
    const active = await get('SELECT * FROM breaks WHERE employee_id = ? AND end_time IS NULL', [employee.id]);
    if (!active) return res.status(400).json({ error: 'No active break' });
    const end = new Date();
    const start = new Date(active.start_time);
    const duration = Math.round((end.getTime() - start.getTime()) / 60000);
    await run('UPDATE breaks SET end_time = ?, duration = ? WHERE id = ?', [end.toISOString(), duration, active.id]);
    const updated = await get('SELECT * FROM breaks WHERE id = ?', [active.id]);
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to stop break' });
  }
});

app.get('/api/status/live', authMiddleware, requireRole('admin', 'manager'), async (req, res) => {
  try {
    const rows = await all(
      `SELECT breaks.*, employees.name AS employee_name, break_types.name AS break_type_name,
              employees.department_id, employees.team_id
       FROM breaks
       INNER JOIN employees ON breaks.employee_id = employees.id
       INNER JOIN break_types ON breaks.break_type_id = break_types.id
       WHERE breaks.end_time IS NULL`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load live status' });
  }
});

app.get('/api/reports/summary', authMiddleware, requireRole('admin', 'manager'), async (req, res) => {
  const { start, end } = req.query;
  const startDate = start ? new Date(start) : null;
  const endDate = end ? new Date(end) : null;
  const params = [];
  let where = 'WHERE breaks.end_time IS NOT NULL';
  if (startDate) {
    where += ' AND breaks.start_time >= ?';
    params.push(new Date(startDate).toISOString());
  }
  if (endDate) {
    where += ' AND breaks.end_time <= ?';
    params.push(new Date(endDate).toISOString());
  }
  try {
    const rows = await all(
      `SELECT employees.name AS employee_name,
              SUM(breaks.duration) AS total_minutes,
              COUNT(breaks.id) AS break_count
       FROM breaks
       INNER JOIN employees ON breaks.employee_id = employees.id
       ${where}
       GROUP BY employees.id
       ORDER BY employees.name`,
      params
    );
    res.json({ rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load report' });
  }
});

const distDir = path.join(__dirname, '..', 'frontend', 'dist');
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir));
  app.get('*', (req, res) => {
    res.sendFile(path.join(distDir, 'index.html'));
  });
}

seedAdmin()
  .then(() => {
    app.listen(PORT, HOST, () => {
      console.log(`Server listening on http://${HOST}:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to seed admin user', err);
    process.exit(1);
  });
