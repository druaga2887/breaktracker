#!/usr/bin/env node
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ensureDependencies } = require('../scripts/ensure-deps');

const SERVER_PORT = 4100;
const BASE_URL = `http://127.0.0.1:${SERVER_PORT}`;
const TOKEN_HEADER = (token) => ({ Authorization: `Bearer ${token}` });

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

const fetchImpl = globalThis.fetch;
if (typeof fetchImpl !== 'function') {
  throw new Error('Global fetch API is required to run smoke tests.');
}

async function fetchJson(url, options = {}) {
  const response = await fetchImpl(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (err) {
    throw new Error(`Failed to parse JSON from ${url}: ${text}`);
  }
  return { response, data };
}

async function waitForHealth(token) {
  const start = Date.now();
  const timeoutMs = 15000;
  while (Date.now() - start < timeoutMs) {
    try {
      const { response, data } = await fetchJson(`${BASE_URL}/api/health`, {
        headers: token ? TOKEN_HEADER(token) : undefined,
      });
      if (response.ok && data?.status === 'ok') {
        return;
      }
    } catch (err) {
      // ignore until timeout
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('Server did not become healthy in time');
}

async function run() {
  try {
    ensureDependencies();
  } catch (err) {
    console.error(`Failed to ensure backend dependencies: ${err.message}`);
    process.exit(1);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'breaktracker-test-'));
  const dbPath = path.join(tmpDir, 'test.sqlite');

  const server = spawn('node', ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(SERVER_PORT),
      DB_PATH: dbPath,
      JWT_SECRET: 'testsecret',
      NODE_ENV: 'test',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  server.stdout.on('data', (chunk) => {
    process.stdout.write(`[server] ${chunk}`);
  });
  server.stderr.on('data', (chunk) => {
    process.stderr.write(`[server] ${chunk}`);
  });

  let closed = false;
  server.on('close', (code) => {
    closed = true;
    console.log(`Server exited with code ${code}`);
  });

  try {
    await waitForHealth();

    console.log('Health check OK');

    const loginInitial = await fetchJson(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'admin', password: 'admin123' }),
    });
    assert(loginInitial.response.ok, `Initial login failed: ${loginInitial.response.status}`);
    assert(loginInitial.data.must_change_password === true, 'Admin should require password change');
    assert(loginInitial.data.role === 'admin', 'Admin role missing from login response');

    const initialToken = loginInitial.data.token;

    const changePassword = await fetchJson(`${BASE_URL}/api/auth/change-password`, {
      method: 'POST',
      headers: TOKEN_HEADER(initialToken),
      body: JSON.stringify({ current_password: 'admin123', new_password: 'AdminTest123!' }),
    });
    assert(changePassword.response.ok, `Password change failed: ${changePassword.response.status}`);

    const loginAfterChange = await fetchJson(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'admin', password: 'AdminTest123!' }),
    });
    assert(loginAfterChange.response.ok, 'Admin login after password change failed');
    assert(loginAfterChange.data.must_change_password === false, 'Admin should no longer require password change');

    const adminToken = loginAfterChange.data.token;

    const me = await fetchJson(`${BASE_URL}/api/auth/me`, {
      headers: TOKEN_HEADER(adminToken),
    });
    assert(me.response.ok, '/api/auth/me failed');
    assert(me.data.role === 'admin', '/api/auth/me should return admin role');

    const createdDepartment = await fetchJson(`${BASE_URL}/api/departments`, {
      method: 'POST',
      headers: TOKEN_HEADER(adminToken),
      body: JSON.stringify({ name: 'Engineering', description: 'Builds the product' }),
    });
    assert(createdDepartment.response.status === 201, 'Department creation failed');
    const departmentId = createdDepartment.data.id;

    const createdTeam = await fetchJson(`${BASE_URL}/api/teams`, {
      method: 'POST',
      headers: TOKEN_HEADER(adminToken),
      body: JSON.stringify({ name: 'Platform', description: 'Core services', department_id: departmentId }),
    });
    assert(createdTeam.response.status === 201, 'Team creation failed');
    const teamId = createdTeam.data.id;

    const createdBreakType = await fetchJson(`${BASE_URL}/api/break-types`, {
      method: 'POST',
      headers: TOKEN_HEADER(adminToken),
      body: JSON.stringify({ name: 'Coffee', color: '#ffcc00' }),
    });
    assert(createdBreakType.response.status === 201, 'Break type creation failed');
    const breakTypeId = createdBreakType.data.id;

    const createdUser = await fetchJson(`${BASE_URL}/api/users`, {
      method: 'POST',
      headers: TOKEN_HEADER(adminToken),
      body: JSON.stringify({
        username: 'manager1',
        password: 'ManagerTest123!',
        name: 'Manager One',
        role: 'manager',
        must_change_password: 0,
      }),
    });
    assert(createdUser.response.status === 201, 'Manager user creation failed');
    const managerUserId = createdUser.data.id;

    const createdEmployee = await fetchJson(`${BASE_URL}/api/employees`, {
      method: 'POST',
      headers: TOKEN_HEADER(adminToken),
      body: JSON.stringify({
        user_id: managerUserId,
        name: 'Manager One',
        department_id: departmentId,
        team_id: teamId,
        status: 'Active',
      }),
    });
    assert(createdEmployee.response.status === 201, 'Employee creation failed');

    const managerLogin = await fetchJson(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username: 'manager1', password: 'ManagerTest123!' }),
    });
    assert(managerLogin.response.ok, 'Manager login failed');
    assert(managerLogin.data.role === 'manager', 'Manager role missing in login response');
    const managerToken = managerLogin.data.token;

    const startBreak = await fetchJson(`${BASE_URL}/api/breaks/start`, {
      method: 'POST',
      headers: TOKEN_HEADER(managerToken),
      body: JSON.stringify({ break_type_id: breakTypeId }),
    });
    assert(startBreak.response.status === 201, 'Starting break failed');

    const liveStatus = await fetchJson(`${BASE_URL}/api/status/live`, {
      headers: TOKEN_HEADER(managerToken),
    });
    assert(liveStatus.response.ok, 'Live status request failed');
    assert(Array.isArray(liveStatus.data) && liveStatus.data.length === 1, 'Live status should have one active break');

    const stopBreak = await fetchJson(`${BASE_URL}/api/breaks/stop`, {
      method: 'POST',
      headers: TOKEN_HEADER(managerToken),
    });
    assert(stopBreak.response.ok, 'Stopping break failed');

    const report = await fetchJson(`${BASE_URL}/api/reports/summary`, {
      headers: TOKEN_HEADER(managerToken),
      method: 'GET',
    });
    assert(report.response.ok, 'Report summary failed');
    assert(Array.isArray(report.data.rows), 'Report rows missing');
    assert(report.data.rows.some((row) => row.employee_name === 'Manager One'), 'Report missing break record');

    console.log('All smoke tests passed');
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      // ignore cleanup errors
    }
    if (!closed) {
      await new Promise((resolve) => {
        server.once('close', resolve);
        server.kill();
      });
    }
  }
}

run().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
