const axios = require('axios');

const BASE = process.env.BASE_URL || 'http://localhost:3001';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const NEW_ADMIN_PASS = process.env.NEW_ADMIN_PASS || 'admin1234!';

const api = axios.create({ baseURL: BASE, validateStatus: () => true });
let token;

const authHeader = () => ({ headers: { Authorization: `Bearer ${token}` } });

describe('Break Tracker API smoke', () => {
  test('health', async () => {
    const r = await api.get('/api/health');
    expect(r.status).toBe(200);
  });

  test('login and change password (handle first-login gate)', async () => {
    let r = await api.post('/api/auth/login', { username: ADMIN_USER, password: ADMIN_PASS });
    expect([200, 201]).toContain(r.status);
    token = r.data.token;
    expect(token).toBeTruthy();

    r = await api.post('/api/auth/change-password',
      { current_password: ADMIN_PASS, new_password: NEW_ADMIN_PASS },
      authHeader()
    );
    // First run may need it; later runs may return 400/403 — both OK for CI
    expect([200, 400, 403]).toContain(r.status);

    r = await api.post('/api/auth/login', { username: ADMIN_USER, password: NEW_ADMIN_PASS });
    expect([200, 201]).toContain(r.status);
    token = r.data.token;
  });

  let depId, teamId, btId;

  test('create department', async () => {
    const r = await api.post('/api/departments', { name: 'CI Dept', description: 'from CI' }, authHeader());
    expect([200, 201, 409]).toContain(r.status);
    depId = r.data?.id || depId;
  });

  test('create team (server should pick department if missing)', async () => {
    const r = await api.post('/api/teams', { name: 'CI Team', description: 'from CI' }, authHeader());
    expect([200, 201, 409]).toContain(r.status);
    teamId = r.data?.id || teamId;
  });

  test('create break type', async () => {
    const r = await api.post('/api/break-types', { name: 'CI Break', color: '#ccc' }, authHeader());
    expect([200, 201, 409]).toContain(r.status);
    btId = r.data?.id || btId;
  });

  test('start & stop break (skip gracefully if no employee linked)', async () => {
    const start = await api.post('/api/breaks/start', { break_type_id: btId || 1 }, authHeader());
    if (![200, 201].includes(start.status)) {
      expect([400]).toContain(start.status);
      return;
    }
    const stop = await api.post('/api/breaks/stop', {}, authHeader());
    expect([200]).toContain(stop.status);
  });
});
