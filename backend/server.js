const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

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

function verifyToken(token, secret) {
  if (!token) throw new Error('Missing token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const [encodedHeader, encodedPayload, signature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const expected = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    throw new Error('Invalid signature');
  }
  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  if (payload.exp && Date.now() / 1000 > payload.exp) {
    throw new Error('Token expired');
  }
  return payload;
}

function seedAdmin() {
  const existing = db.users.find((user) => user.username === 'admin');
  if (!existing) {
    const passwordHash = hashPassword('admin123');
    const now = new Date().toISOString();
    const adminUser = {
      id: nextId('users'),
      username: 'admin',
      password: passwordHash,
      must_change_password: 1,
      name: 'Admin',
      role: 'admin',
      created_at: now,
    };
    db.users.push(adminUser);
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

  persistDatabase();
}

seedAdmin();

const routes = [];

function pathToRegex(pattern) {
  const keys = [];
  const regex = pattern
    .replace(/\//g, '\\/')
    .replace(/:(\w+)/g, (_, key) => {
      keys.push(key);
      return '([^/]+)';
    });
  return { regex: new RegExp(`^${regex}$`), keys };
}

function registerRoute(method, pattern, options, handler) {
  const { regex, keys } = pathToRegex(pattern);
  routes.push({ method: method.toUpperCase(), regex, keys, options: options || {}, handler });
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
}

function sendJson(res, status, body) {
  if (res.writableEnded) return;
  setCors(res);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

function notFound(res) {
  sendJson(res, 404, { error: 'Not found' });
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1e6) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', (err) => reject(err));
  });
}

function getQueryObject(urlObj) {
  const query = {};
  for (const [key, value] of urlObj.searchParams.entries()) {
    if (query[key] === undefined) {
      query[key] = value;
    } else if (Array.isArray(query[key])) {
      query[key].push(value);
    } else {
      query[key] = [query[key], value];
    }
  }
  return query;
}

function serveStatic(req, res, pathname) {
  if (!hasStatic) return false;
  let filePath = path.join(staticDir, pathname);
  if (pathname.endsWith('/')) {
    filePath = path.join(staticDir, 'index.html');
  }
  if (!filePath.startsWith(staticDir)) {
    return false;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(staticDir, 'index.html');
    if (!fs.existsSync(filePath)) {
      return false;
    }
  }
  const ext = path.extname(filePath).toLowerCase();
  const type =
    ext === '.html' ? 'text/html' :
    ext === '.css' ? 'text/css' :
    ext === '.js' ? 'application/javascript' :
    ext === '.json' ? 'application/json' :
    ext === '.png' ? 'image/png' :
    ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg' :
    ext === '.svg' ? 'image/svg+xml' :
    'application/octet-stream';
  const stream = fs.createReadStream(filePath);
  stream.on('open', () => {
    res.statusCode = 200;
    res.setHeader('Content-Type', type);
    stream.pipe(res);
  });
  stream.on('error', (err) => {
    console.error('Static file error:', err.message);
    if (!res.headersSent) {
      res.statusCode = 500;
      res.end('Internal Server Error');
    } else {
      res.destroy();
    }
  });
  return true;
}

function requireAuth(context) {
  const authHeader = context.req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    throw Object.assign(new Error('Unauthorized'), { status: 401 });
  }
  const token = authHeader.slice(7);
  const payload = verifyToken(token, JWT_SECRET);
  const user = db.users.find((u) => u.id === payload.id);
  if (!user) {
    throw Object.assign(new Error('Unauthorized'), { status: 401 });
  }
  context.user = {
    id: user.id,
    username: user.username,
    role: user.role || 'employee',
    must_change_password: !!user.must_change_password,
  };
}

function enforceRoles(context, roles) {
  if (!context.user || !roles.includes(context.user.role)) {
    throw Object.assign(new Error('Forbidden'), { status: 403 });
  }
}

function normalizedRole(role) {
  return ['admin', 'manager', 'employee'].includes(role) ? role : 'employee';
}

function findDepartment(id) {
  return db.departments.find((dep) => dep.id === id);
}

function findTeam(id) {
  return db.teams.find((team) => team.id === id);
}

function findBreakType(id) {
  return db.break_types.find((type) => type.id === id);
}

function ensureDefaultDepartment() {
  const active = db.departments
    .filter((dep) => dep.status !== 'Inactive')
    .sort((a, b) => a.id - b.id);
  return active.length ? active[0] : null;
}

registerRoute('GET', '/api/health', {}, async () => ({
  status: 200,
  body: {
    status: 'ok',
    db: 'ok',
    version: '1.0.0',
  },
}));

registerRoute('POST', '/api/auth/login', {}, async (context) => {
  const { username, password } = context.body || {};
  if (!username || !password) {
    return { status: 400, body: { error: 'Missing credentials' } };
  }
  const user = db.users.find((u) => u.username === username);
  if (!user || !verifyPassword(password, user.password)) {
    return { status: 401, body: { error: 'Invalid credentials' } };
  }
  const token = signToken({ id: user.id, username: user.username, role: user.role || 'employee' }, JWT_SECRET, { expiresIn: '8h' });
  return {
    status: 200,
    body: {
      token,
      must_change_password: !!user.must_change_password,
      role: user.role || 'employee',
    },
  };
});

registerRoute('POST', '/api/auth/change-password', { auth: true }, async (context) => {
  const { current_password, new_password } = context.body || {};
  if (!current_password || !new_password || new_password.length < 8) {
    return { status: 400, body: { error: 'Invalid payload' } };
  }
  const user = db.users.find((u) => u.id === context.user.id);
  if (!user || !verifyPassword(current_password, user.password)) {
    return { status: 400, body: { error: 'Current password incorrect' } };
  }
  user.password = hashPassword(new_password);
  user.must_change_password = 0;
  persistDatabase();
  return { status: 200, body: { success: true } };
});

registerRoute('GET', '/api/auth/me', { auth: true }, async (context) => {
  const user = db.users.find((u) => u.id === context.user.id);
  if (!user) {
    return { status: 404, body: { error: 'Not found' } };
  }
  return {
    status: 200,
    body: {
      id: user.id,
      username: user.username,
      name: user.name || '',
      role: user.role || 'employee',
      must_change_password: !!user.must_change_password,
    },
  };
});

registerRoute('GET', '/api/departments', { auth: true }, async () => ({
  status: 200,
  body: db.departments.slice().sort((a, b) => a.id - b.id),
}));

registerRoute('POST', '/api/departments', { auth: true, roles: ['admin'] }, async (context) => {
  const { name, description } = context.body || {};
  if (!name || !String(name).trim()) {
    return { status: 400, body: { error: 'Name is required' } };
  }
  const trimmed = String(name).trim();
  const exists = db.departments.find((dep) => dep.name.toLowerCase() === trimmed.toLowerCase());
  if (exists) {
    return { status: 409, body: { error: 'Department already exists' } };
  }
  const now = new Date().toISOString();
  const department = {
    id: nextId('departments'),
    name: trimmed,
    description: String(description || ''),
    status: 'Active',
    created_at: now,
  };
  db.departments.push(department);
  persistDatabase();
  return { status: 201, body: department };
});

registerRoute('PUT', '/api/departments/:id', { auth: true, roles: ['admin'] }, async (context) => {
  const id = Number(context.params.id);
  const department = findDepartment(id);
  if (!department) {
    return { status: 404, body: { error: 'Not found' } };
  }
  const { name, description, status } = context.body || {};
  let updated = false;
  if (name !== undefined) {
    const trimmed = String(name || '').trim();
    if (!trimmed) {
      return { status: 400, body: { error: 'Name cannot be empty' } };
    }
    const exists = db.departments.find((dep) => dep.id !== id && dep.name.toLowerCase() === trimmed.toLowerCase());
    if (exists) {
      return { status: 409, body: { error: 'Department already exists' } };
    }
    department.name = trimmed;
    updated = true;
  }
  if (description !== undefined) {
    department.description = String(description || '');
    updated = true;
  }
  if (status !== undefined) {
    department.status = String(status || 'Active');
    updated = true;
  }
  if (!updated) {
    return { status: 400, body: { error: 'nothing to update' } };
  }
  persistDatabase();
  return { status: 200, body: { success: true } };
});

registerRoute('GET', '/api/teams', { auth: true }, async () => {
  const rows = db.teams
    .map((team) => ({
      ...team,
      department_name: team.department_id ? (findDepartment(team.department_id)?.name || null) : null,
    }))
    .sort((a, b) => a.id - b.id);
  return { status: 200, body: rows };
});

registerRoute('POST', '/api/teams', { auth: true, roles: ['admin'] }, async (context) => {
  const { name, description, color, department_id } = context.body || {};
  if (!name || !String(name).trim()) {
    return { status: 400, body: { error: 'Name is required' } };
  }
  const trimmed = String(name).trim();
  const exists = db.teams.find((team) => team.name.toLowerCase() === trimmed.toLowerCase());
  if (exists) {
    return { status: 409, body: { error: 'Team already exists' } };
  }
  let resolvedDepartmentId = department_id ? Number(department_id) : null;
  if (!resolvedDepartmentId) {
    const defaultDepartment = ensureDefaultDepartment();
    if (!defaultDepartment) {
      return { status: 400, body: { error: 'No departments. Create one first or provide department_id.' } };
    }
    resolvedDepartmentId = defaultDepartment.id;
  }
  if (!findDepartment(resolvedDepartmentId)) {
    return { status: 400, body: { error: 'Invalid department_id' } };
  }
  const now = new Date().toISOString();
  const team = {
    id: nextId('teams'),
    name: trimmed,
    description: String(description || ''),
    color: String(color || ''),
    department_id: resolvedDepartmentId,
    status: 'Active',
    created_at: now,
  };
  db.teams.push(team);
  persistDatabase();
  return { status: 201, body: team };
});

registerRoute('PUT', '/api/teams/:id', { auth: true, roles: ['admin'] }, async (context) => {
  const id = Number(context.params.id);
  const team = findTeam(id);
  if (!team) {
    return { status: 404, body: { error: 'Not found' } };
  }
  const { name, description, color, department_id, status } = context.body || {};
  let updated = false;
  if (name !== undefined) {
    const trimmed = String(name || '').trim();
    if (!trimmed) {
      return { status: 400, body: { error: 'Name cannot be empty' } };
    }
    const exists = db.teams.find((t) => t.id !== id && t.name.toLowerCase() === trimmed.toLowerCase());
    if (exists) {
      return { status: 409, body: { error: 'Team already exists' } };
    }
    team.name = trimmed;
    updated = true;
  }
  if (description !== undefined) {
    team.description = String(description || '');
    updated = true;
  }
  if (color !== undefined) {
    team.color = String(color || '');
    updated = true;
  }
  if (department_id !== undefined) {
    if (department_id === null) {
      team.department_id = null;
    } else {
      const depId = Number(department_id);
      if (!findDepartment(depId)) {
        return { status: 400, body: { error: 'Invalid department_id' } };
      }
      team.department_id = depId;
    }
    updated = true;
  }
  if (status !== undefined) {
    team.status = String(status || 'Active');
    updated = true;
  }
  if (!updated) {
    return { status: 400, body: { error: 'nothing to update' } };
  }
  persistDatabase();
  return { status: 200, body: { success: true } };
});

registerRoute('GET', '/api/break-types', { auth: true }, async (context) => {
  const includeInactive = context.query.includeInactive === '1';
  const rows = db.break_types
    .filter((type) => includeInactive || type.status === 'Active')
    .sort((a, b) => a.id - b.id);
  return { status: 200, body: rows };
});

registerRoute('POST', '/api/break-types', { auth: true, roles: ['admin'] }, async (context) => {
  const { name, color } = context.body || {};
  if (!name || !String(name).trim()) {
    return { status: 400, body: { error: 'Name is required' } };
  }
  const trimmed = String(name).trim();
  const exists = db.break_types.find((type) => type.name.toLowerCase() === trimmed.toLowerCase());
  if (exists) {
    return { status: 409, body: { error: 'Break type already exists' } };
  }
  const now = new Date().toISOString();
  const breakType = {
    id: nextId('break_types'),
    name: trimmed,
    color: String(color || ''),
    status: 'Active',
    created_at: now,
  };
  db.break_types.push(breakType);
  persistDatabase();
  return { status: 201, body: breakType };
});

registerRoute('PUT', '/api/break-types/:id', { auth: true, roles: ['admin'] }, async (context) => {
  const id = Number(context.params.id);
  const breakType = findBreakType(id);
  if (!breakType) {
    return { status: 404, body: { error: 'Not found' } };
  }
  const { name, color, status } = context.body || {};
  let updated = false;
  if (name !== undefined) {
    const trimmed = String(name || '').trim();
    if (!trimmed) {
      return { status: 400, body: { error: 'Name cannot be empty' } };
    }
    const exists = db.break_types.find((bt) => bt.id !== id && bt.name.toLowerCase() === trimmed.toLowerCase());
    if (exists) {
      return { status: 409, body: { error: 'Break type already exists' } };
    }
    breakType.name = trimmed;
    updated = true;
  }
  if (color !== undefined) {
    breakType.color = String(color || '');
    updated = true;
  }
  if (status !== undefined) {
    breakType.status = String(status || 'Active');
    updated = true;
  }
  if (!updated) {
    return { status: 400, body: { error: 'nothing to update' } };
  }
  persistDatabase();
  return { status: 200, body: { success: true } };
});

registerRoute('GET', '/api/users', { auth: true, roles: ['admin'] }, async () => {
  const rows = db.users
    .map((user) => ({
      id: user.id,
      username: user.username,
      must_change_password: !!user.must_change_password,
      name: user.name || '',
      role: user.role || 'employee',
    }))
    .sort((a, b) => a.id - b.id);
  return { status: 200, body: rows };
});

registerRoute('POST', '/api/users', { auth: true, roles: ['admin'] }, async (context) => {
  const { username, password, name, role = 'employee', must_change_password = 1 } = context.body || {};
  if (!username || !String(username).trim()) {
    return { status: 400, body: { error: 'username required' } };
  }
  if (!password || password.length < 8) {
    return { status: 400, body: { error: 'password must be at least 8 characters' } };
  }
  const trimmed = String(username).trim();
  const exists = db.users.find((user) => user.username.toLowerCase() === trimmed.toLowerCase());
  if (exists) {
    return { status: 409, body: { error: 'Username already exists' } };
  }
  const now = new Date().toISOString();
  const user = {
    id: nextId('users'),
    username: trimmed,
    password: hashPassword(password),
    must_change_password: must_change_password ? 1 : 0,
    name: String(name || ''),
    role: normalizedRole(role),
    created_at: now,
  };
  db.users.push(user);
  persistDatabase();
  return {
    status: 201,
    body: {
      id: user.id,
      username: user.username,
      must_change_password: !!user.must_change_password,
      name: user.name,
      role: user.role,
    },
  };
});

registerRoute('PUT', '/api/users/:id', { auth: true, roles: ['admin'] }, async (context) => {
  const id = Number(context.params.id);
  const user = db.users.find((u) => u.id === id);
  if (!user) {
    return { status: 404, body: { error: 'Not found' } };
  }
  const { name, password, must_change_password, role } = context.body || {};
  let updated = false;
  if (name !== undefined) {
    user.name = String(name || '');
    updated = true;
  }
  if (must_change_password !== undefined) {
    user.must_change_password = must_change_password ? 1 : 0;
    updated = true;
  }
  if (role !== undefined) {
    user.role = normalizedRole(role);
    updated = true;
  }
  if (password !== undefined) {
    if (!password || password.length < 8) {
      return { status: 400, body: { error: 'password must be at least 8 characters' } };
    }
    user.password = hashPassword(password);
    if (must_change_password === undefined) {
      user.must_change_password = 1;
    }
    updated = true;
  }
  if (!updated) {
    return { status: 400, body: { error: 'nothing to update' } };
  }
  persistDatabase();
  return { status: 200, body: { success: true } };
});

registerRoute('GET', '/api/employees', { auth: true, roles: ['admin'] }, async () => {
  const rows = db.employees.slice().sort((a, b) => a.id - b.id);
  return { status: 200, body: rows };
});

registerRoute('POST', '/api/employees', { auth: true, roles: ['admin'] }, async (context) => {
  const { user_id, name, department_id, team_id, status } = context.body || {};
  if (!name || !String(name).trim()) {
    return { status: 400, body: { error: 'name required' } };
  }
  if (user_id) {
    const user = db.users.find((u) => u.id === Number(user_id));
    if (!user) {
      return { status: 400, body: { error: 'invalid user_id' } };
    }
  }
  if (department_id) {
    if (!findDepartment(Number(department_id))) {
      return { status: 400, body: { error: 'invalid department_id' } };
    }
  }
  if (team_id) {
    if (!findTeam(Number(team_id))) {
      return { status: 400, body: { error: 'invalid team_id' } };
    }
  }
  const employee = {
    id: nextId('employees'),
    user_id: user_id ? Number(user_id) : null,
    name: String(name).trim(),
    department_id: department_id ? Number(department_id) : null,
    team_id: team_id ? Number(team_id) : null,
    status: status || 'Active',
    created_at: new Date().toISOString(),
  };
  db.employees.push(employee);
  persistDatabase();
  return { status: 201, body: employee };
});

registerRoute('PUT', '/api/employees/:id', { auth: true, roles: ['admin'] }, async (context) => {
  const id = Number(context.params.id);
  const employee = db.employees.find((emp) => emp.id === id);
  if (!employee) {
    return { status: 404, body: { error: 'Not found' } };
  }
  const { name, department_id, team_id, status, user_id } = context.body || {};
  let updated = false;
  if (name !== undefined) {
    employee.name = String(name || '');
    updated = true;
  }
  if (department_id !== undefined) {
    employee.department_id = department_id ? Number(department_id) : null;
    updated = true;
  }
  if (team_id !== undefined) {
    employee.team_id = team_id ? Number(team_id) : null;
    updated = true;
  }
  if (status !== undefined) {
    employee.status = String(status || 'Active');
    updated = true;
  }
  if (user_id !== undefined) {
    employee.user_id = user_id ? Number(user_id) : null;
    updated = true;
  }
  if (!updated) {
    return { status: 400, body: { error: 'nothing to update' } };
  }
  persistDatabase();
  return { status: 200, body: { success: true } };
});

registerRoute('POST', '/api/breaks/start', { auth: true }, async (context) => {
  const { break_type_id } = context.body || {};
  if (!break_type_id) {
    return { status: 400, body: { error: 'break_type_id is required' } };
  }
  const breakType = findBreakType(Number(break_type_id));
  if (!breakType || breakType.status === 'Inactive') {
    return { status: 400, body: { error: 'Invalid break type' } };
  }
  let employee = db.employees.find((emp) => emp.user_id === context.user.id);
  if (!employee) {
    const user = db.users.find((u) => u.id === context.user.id);
    employee = {
      id: nextId('employees'),
      user_id: context.user.id,
      name: user?.name || user?.username || `User${context.user.id}`,
      department_id: null,
      team_id: null,
      status: 'Active',
      created_at: new Date().toISOString(),
    };
    db.employees.push(employee);
  }
  const startTime = new Date().toISOString();
  const record = {
    id: nextId('breaks'),
    employee_id: employee.id,
    break_type_id: Number(break_type_id),
    start_time: startTime,
    end_time: null,
    duration: null,
  };
  db.breaks.push(record);
  persistDatabase();
  return { status: 201, body: { id: record.id, start_time: startTime } };
});

registerRoute('POST', '/api/breaks/stop', { auth: true }, async (context) => {
  const employee = db.employees.find((emp) => emp.user_id === context.user.id);
  if (!employee) {
    return { status: 400, body: { error: 'No employee found' } };
  }
  const active = db.breaks
    .filter((brk) => brk.employee_id === employee.id && !brk.end_time)
    .sort((a, b) => b.id - a.id)[0];
  if (!active) {
    return { status: 400, body: { error: 'No active break' } };
  }
  const end = new Date();
  const duration = Math.max(0, Math.round((end - new Date(active.start_time)) / 60000));
  active.end_time = end.toISOString();
  active.duration = duration;
  persistDatabase();
  return { status: 200, body: { success: true, duration } };
});

registerRoute('GET', '/api/status/live', { auth: true, roles: ['manager', 'admin'] }, async () => {
  const rows = db.breaks
    .filter((brk) => !brk.end_time)
    .map((brk) => {
      const employee = db.employees.find((emp) => emp.id === brk.employee_id);
      const team = employee?.team_id ? findTeam(employee.team_id) : null;
      const department = employee?.department_id ? findDepartment(employee.department_id) : null;
      const breakType = findBreakType(brk.break_type_id);
      return {
        break_id: brk.id,
        employee_name: employee?.name || 'Unknown',
        employee_id: employee?.id || null,
        department_id: employee?.department_id || null,
        team_id: employee?.team_id || null,
        team_name: team?.name || null,
        department_name: department?.name || null,
        break_type: breakType?.name || 'Unknown',
        break_type_id: breakType?.id || null,
        start_time: brk.start_time,
        break_color: breakType?.color || '',
      };
    })
    .sort((a, b) => new Date(a.start_time) - new Date(b.start_time));
  return { status: 200, body: rows };
});

registerRoute('GET', '/api/reports/summary', { auth: true, roles: ['manager', 'admin'] }, async (context) => {
  const { start, end, department_id, team_id, break_type_id } = context.query;
  const now = new Date();
  const defaultStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const parsedStart = start ? new Date(start) : defaultStart;
  const parsedEnd = end ? new Date(end) : now;
  if (Number.isNaN(parsedStart.getTime())) {
    return { status: 400, body: { error: 'Invalid start date' } };
  }
  if (Number.isNaN(parsedEnd.getTime())) {
    return { status: 400, body: { error: 'Invalid end date' } };
  }
  const startIso = parsedStart.toISOString();
  const endIso = parsedEnd.toISOString();

  const rows = [];
  const filters = {
    department_id: department_id ? Number(department_id) : null,
    team_id: team_id ? Number(team_id) : null,
    break_type_id: break_type_id ? Number(break_type_id) : null,
  };

  const grouped = new Map();
  for (const brk of db.breaks) {
    if (!brk.end_time) continue;
    if (brk.start_time < startIso || brk.start_time > endIso) continue;
    const employee = db.employees.find((emp) => emp.id === brk.employee_id);
    if (!employee) continue;
    if (filters.department_id && employee.department_id !== filters.department_id) continue;
    if (filters.team_id && employee.team_id !== filters.team_id) continue;
    if (filters.break_type_id && brk.break_type_id !== filters.break_type_id) continue;
    const breakType = findBreakType(brk.break_type_id);
    const key = `${employee.id}:${brk.break_type_id}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        employee_id: employee.id,
        employee_name: employee.name,
        department_id: employee.department_id,
        team_id: employee.team_id,
        department_name: employee.department_id ? findDepartment(employee.department_id)?.name || null : null,
        team_name: employee.team_id ? findTeam(employee.team_id)?.name || null : null,
        break_type: breakType?.name || 'Unknown',
        break_type_id: breakType?.id || null,
        break_count: 0,
        total_minutes: 0,
      });
    }
    const bucket = grouped.get(key);
    bucket.break_count += 1;
    bucket.total_minutes += brk.duration || 0;
  }

  for (const value of grouped.values()) {
    rows.push(value);
  }
  rows.sort((a, b) => {
    const dep = (a.department_name || '').localeCompare(b.department_name || '');
    if (dep !== 0) return dep;
    const team = (a.team_name || '').localeCompare(b.team_name || '');
    if (team !== 0) return team;
    const emp = (a.employee_name || '').localeCompare(b.employee_name || '');
    if (emp !== 0) return emp;
    return (a.break_type || '').localeCompare(b.break_type || '');
  });

  return {
    status: 200,
    body: {
      start: startIso,
      end: endIso,
      rows,
    },
  };
});

const server = http.createServer(async (req, res) => {
  const startTime = Date.now();
  const method = req.method.toUpperCase();
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = urlObj.pathname;

  if (method === 'OPTIONS') {
    setCors(res);
    res.statusCode = 204;
    res.end();
    return;
  }

  const route = routes.find((r) => r.method === method && r.regex.test(pathname));

  if (!route) {
    if ((method === 'GET' || method === 'HEAD') && !pathname.startsWith('/api')) {
      if (serveStatic(req, res, pathname)) {
        return;
      }
    }
    if (!res.writableEnded) {
      notFound(res);
    }
    return;
  }

  const match = pathname.match(route.regex);
  const params = {};
  if (match) {
    route.keys.forEach((key, index) => {
      params[key] = match[index + 1];
    });
  }

  const context = {
    req,
    res,
    params,
    query: getQueryObject(urlObj),
    body: {},
    user: null,
  };

  try {
    if (route.options && route.options.auth) {
      requireAuth(context);
      if (route.options.roles) {
        enforceRoles(context, route.options.roles);
      }
    }

    if (['POST', 'PUT'].includes(method)) {
      context.body = await parseBody(req);
    }

    const result = await route.handler(context);
    if (result && !res.writableEnded) {
      sendJson(res, result.status || 200, result.body || {});
    }
  } catch (err) {
    const status = err.status || 500;
    if (status >= 500) {
      console.error('Request error:', err);
    }
    sendJson(res, status, { error: err.status ? err.message : 'Internal Server Error' });
  } finally {
    const duration = Date.now() - startTime;
    if (!res.headersSent) {
      res.setHeader('X-Response-Time', `${duration}ms`);
    }
    console.log(`${method} ${pathname} -> ${res.statusCode} (${duration}ms)`);
  }
});

process.on('unhandledRejection', (err) => {
  console.error('unhandledRejection:', err);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('uncaughtException:', err);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`Backend running on http://${HOST}:${PORT}`);
});
