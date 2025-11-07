import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { api } from './api';

const styles = {
  container: {
    fontFamily: 'system-ui,-apple-system,Segoe UI,Roboto,sans-serif',
    padding: 16,
    maxWidth: 1080,
    margin: '0 auto',
  },
  card: {
    border: '1px solid #e5e7eb',
    borderRadius: 12,
    padding: 16,
    marginTop: 16,
    background: '#fff',
    boxShadow: '0 1px 2px rgba(15,23,42,0.08)',
  },
  sectionTitle: {
    marginTop: 0,
    fontSize: 18,
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    marginTop: 8,
  },
  th: {
    textAlign: 'left',
    borderBottom: '1px solid #e5e7eb',
    padding: '6px 4px',
    fontSize: 14,
    color: '#475569',
  },
  td: {
    borderBottom: '1px solid #f3f4f6',
    padding: '6px 4px',
    fontSize: 14,
  },
  input: {
    border: '1px solid #cbd5f5',
    borderRadius: 8,
    padding: '8px 10px',
    fontSize: 14,
  },
  button: {
    borderRadius: 8,
    border: '1px solid #4f46e5',
    background: '#4f46e5',
    color: '#fff',
    padding: '8px 14px',
    fontSize: 14,
    cursor: 'pointer',
  },
  smallButton: {
    borderRadius: 6,
    border: '1px solid #4f46e5',
    background: '#4f46e5',
    color: '#fff',
    padding: '4px 10px',
    fontSize: 13,
    cursor: 'pointer',
  },
  secondaryButton: {
    borderRadius: 8,
    border: '1px solid #d1d5db',
    background: '#fff',
    color: '#111827',
    padding: '8px 14px',
    fontSize: 14,
    cursor: 'pointer',
  },
  pill: {
    background: '#eef2ff',
    padding: '2px 8px',
    borderRadius: 999,
    color: '#3730a3',
    fontSize: 13,
  },
  navButton: {
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid transparent',
    cursor: 'pointer',
    fontSize: 14,
  },
};

function mergeStyles(base, override) {
  return Object.assign({}, base, override);
}

function getIsoDate(defaultDate = new Date()) {
  const iso = new Date(defaultDate.getTime() - defaultDate.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 10);
  return iso;
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('bt_token') || '');
  const [credentials, setCredentials] = useState({ username: 'admin', password: 'admin123' });
  const [pendingToken, setPendingToken] = useState('');
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [passwordReset, setPasswordReset] = useState({ current: '', next: '', confirm: '' });
  const [profile, setProfile] = useState(null);
  const [loadingProfile, setLoadingProfile] = useState(false);
  const [health, setHealth] = useState('');
  const [msg, setMsg] = useState('');
  const [view, setView] = useState('live');

  const [breakTypes, setBreakTypes] = useState([]);
  const [selectedBt, setSelectedBt] = useState(null);
  const [live, setLive] = useState([]);
  const [liveFilters, setLiveFilters] = useState({ department: '', team: '' });

  const [departments, setDepartments] = useState([]);
  const [teams, setTeams] = useState([]);
  const [users, setUsers] = useState([]);
  const [employees, setEmployees] = useState([]);

  const todayIso = getIsoDate();
  const [reportRange, setReportRange] = useState({ start: todayIso, end: todayIso });
  const [report, setReport] = useState({ rows: [], start: '', end: '' });
  const [loadingReport, setLoadingReport] = useState(false);
  const [reportFilters, setReportFilters] = useState({ department: '', team: '', break_type: '' });

  const [newDepartment, setNewDepartment] = useState({ name: '', description: '' });
  const [newTeam, setNewTeam] = useState({ name: '', description: '', color: '#2563eb', department_id: '' });
  const [newBreakType, setNewBreakType] = useState({ name: '', color: '#16a34a' });
  const [newUser, setNewUser] = useState({ username: '', password: '', name: '', must_change_password: true, role: 'employee' });
  const [newEmployee, setNewEmployee] = useState({ name: '', user_id: '', department_id: '', team_id: '' });
  const [editingDepartment, setEditingDepartment] = useState(null);
  const [editingTeam, setEditingTeam] = useState(null);
  const [editingBreakType, setEditingBreakType] = useState(null);
  const [editingUser, setEditingUser] = useState(null);
  const [editingEmployee, setEditingEmployee] = useState(null);

  const isManagerOrAdmin = profile && (profile.role === 'manager' || profile.role === 'admin');
  const isAdmin = profile?.role === 'admin';

  const logout = useCallback(() => {
    setToken('');
    setPendingToken('');
    setProfile(null);
    setMustChangePassword(false);
    setPasswordReset({ current: '', next: '', confirm: '' });
    setBreakTypes([]);
    setSelectedBt(null);
    setLive([]);
    setDepartments([]);
    setTeams([]);
    setUsers([]);
    setEmployees([]);
    setReport({ rows: [], start: '', end: '' });
    setReportFilters({ department: '', team: '', break_type: '' });
    setLiveFilters({ department: '', team: '' });
    setEditingDepartment(null);
    setEditingTeam(null);
    setEditingBreakType(null);
    setEditingUser(null);
    setEditingEmployee(null);
    localStorage.removeItem('bt_token');
  }, []);

  const handleApiError = useCallback(
    (error) => {
      const message = String(error?.message || error);
      if (message.includes('401')) {
        setMsg('Session expired. Please sign in again.');
        logout();
      } else if (message.includes('403')) {
        setMsg('You do not have access to that action.');
      } else {
        setMsg(message);
      }
    },
    [logout]
  );

  useEffect(() => {
    api('/api/health')
      .then((h) => setHealth(`${h.status} v${h.version}`))
      .catch((e) => setHealth(String(e)));
  }, []);

  useEffect(() => {
    if (!token) {
      setProfile(null);
      return;
    }
    setLoadingProfile(true);
    api('/api/auth/me', { token })
      .then((data) => {
        if (data.must_change_password) {
          setPendingToken(token);
          setMustChangePassword(true);
          setPasswordReset({ current: '', next: '', confirm: '' });
          setMsg('You must change your password before continuing.');
          localStorage.removeItem('bt_token');
          setToken('');
        } else {
          setProfile(data);
        }
      })
      .catch((e) => handleApiError(e))
      .finally(() => setLoadingProfile(false));
  }, [token, handleApiError]);

  const refreshBreakTypes = useCallback(async () => {
    if (!token) return;
    try {
      const includeInactive = isAdmin ? '?includeInactive=1' : '';
      const rows = await api(`/api/break-types${includeInactive}`, { token });
      setBreakTypes(rows);
      setSelectedBt((prev) => {
        const stillActive = rows.find((b) => b.id === prev && b.status === 'Active');
        if (stillActive) return prev;
        const active = rows.find((b) => b.status === 'Active');
        return active ? active.id : null;
      });
    } catch (e) {
      handleApiError(e);
    }
  }, [token, isAdmin, handleApiError]);

  const refreshLive = useCallback(async () => {
    if (!token || !isManagerOrAdmin) return;
    try {
      const rows = await api('/api/status/live', { token });
      setLive(rows);
    } catch (e) {
      if (String(e?.message || e).includes('403')) {
        setLive([]);
      }
      handleApiError(e);
    }
  }, [token, isManagerOrAdmin, handleApiError]);

  const refreshDepartments = useCallback(async () => {
    if (!token) return;
    try {
      const rows = await api('/api/departments', { token });
      setDepartments(rows);
    } catch (e) {
      handleApiError(e);
    }
  }, [token, handleApiError]);

  const refreshTeams = useCallback(async () => {
    if (!token) return;
    try {
      const rows = await api('/api/teams', { token });
      setTeams(rows);
    } catch (e) {
      handleApiError(e);
    }
  }, [token, handleApiError]);

  const refreshUsers = useCallback(async () => {
    if (!token || !isAdmin) return;
    try {
      const rows = await api('/api/users', { token });
      setUsers(rows);
    } catch (e) {
      handleApiError(e);
    }
  }, [token, isAdmin, handleApiError]);

  const refreshEmployees = useCallback(async () => {
    if (!token || !isAdmin) return;
    try {
      const rows = await api('/api/employees', { token });
      setEmployees(rows);
    } catch (e) {
      handleApiError(e);
    }
  }, [token, isAdmin, handleApiError]);

  useEffect(() => {
    if (!token) return;
    refreshBreakTypes();
  }, [token, refreshBreakTypes]);

  useEffect(() => {
    if (!token) return;
    refreshDepartments();
    refreshTeams();
  }, [token, refreshDepartments, refreshTeams]);

  useEffect(() => {
    if (!token || !isManagerOrAdmin) return;
    refreshLive();
    const id = setInterval(() => {
      refreshLive();
    }, 5000);
    return () => clearInterval(id);
  }, [token, isManagerOrAdmin, refreshLive]);

  useEffect(() => {
    if (!token || !isAdmin) return;
    refreshUsers();
    refreshEmployees();
  }, [token, isAdmin, refreshUsers, refreshEmployees]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setMsg('');
    try {
      const r = await api('/api/auth/login', { method: 'POST', body: credentials });
      if (r.must_change_password) {
        setPendingToken(r.token);
        setMustChangePassword(true);
        setPasswordReset({ current: credentials.password, next: '', confirm: '' });
        setMsg('Please update your password to continue.');
      } else {
        setToken(r.token);
        localStorage.setItem('bt_token', r.token);
        setPendingToken('');
        setMustChangePassword(false);
        setPasswordReset({ current: '', next: '', confirm: '' });
      }
    } catch (e2) {
      setMsg(String(e2.message || e2));
    }
  };

  const handlePasswordReset = async (e) => {
    e.preventDefault();
    if (!pendingToken) return;
    if (!passwordReset.current || !passwordReset.next) {
      setMsg('Enter your current and new password.');
      return;
    }
    if (passwordReset.next !== passwordReset.confirm) {
      setMsg('New passwords do not match.');
      return;
    }
    setMsg('');
    try {
      await api('/api/auth/change-password', {
        method: 'POST',
        token: pendingToken,
        body: { current_password: passwordReset.current, new_password: passwordReset.next },
      });
      localStorage.setItem('bt_token', pendingToken);
      setToken(pendingToken);
      setPendingToken('');
      setMustChangePassword(false);
      setPasswordReset({ current: '', next: '', confirm: '' });
      setMsg('Password updated.');
    } catch (e2) {
      setMsg(String(e2.message || e2));
    }
  };

  const activeBreakTypes = useMemo(() => breakTypes.filter((b) => b.status === 'Active'), [breakTypes]);

  const teamOptionsForFilters = useMemo(() => {
    if (!liveFilters.department) return teams;
    return teams.filter((team) => String(team.department_id || '') === String(liveFilters.department));
  }, [teams, liveFilters.department]);

  const reportTeamOptions = useMemo(() => {
    if (!reportFilters.department) return teams;
    return teams.filter((team) => String(team.department_id || '') === String(reportFilters.department));
  }, [teams, reportFilters.department]);

  useEffect(() => {
    if (!liveFilters.team) return;
    const stillValid = teamOptionsForFilters.some((team) => String(team.id) === String(liveFilters.team));
    if (!stillValid) {
      setLiveFilters((prev) => ({ ...prev, team: '' }));
    }
  }, [liveFilters.team, teamOptionsForFilters]);

  useEffect(() => {
    if (!reportFilters.team) return;
    const stillValid = reportTeamOptions.some((team) => String(team.id) === String(reportFilters.team));
    if (!stillValid) {
      setReportFilters((prev) => ({ ...prev, team: '' }));
    }
  }, [reportFilters.team, reportTeamOptions]);

  const filteredLive = useMemo(() => {
    return live.filter((row) => {
      if (liveFilters.department && String(row.department_id || '') !== String(liveFilters.department)) return false;
      if (liveFilters.team && String(row.team_id || '') !== String(liveFilters.team)) return false;
      return true;
    });
  }, [live, liveFilters]);

  const liveStats = useMemo(() => {
    if (!filteredLive.length) {
      return { count: 0, averageMinutes: 0, longestMinutes: 0 };
    }
    const now = Date.now();
    const durations = filteredLive.map((row) => Math.max(0, Math.round((now - new Date(row.start_time).getTime()) / 60000)));
    const totalMinutes = durations.reduce((sum, mins) => sum + mins, 0);
    const longestMinutes = durations.reduce((max, mins) => Math.max(max, mins), 0);
    return {
      count: durations.length,
      averageMinutes: Math.round((totalMinutes / durations.length) * 10) / 10,
      longestMinutes,
    };
  }, [filteredLive]);

  const reportTotals = useMemo(() => {
    const totalMinutes = report.rows.reduce((sum, row) => sum + Number(row.total_minutes || 0), 0);
    const totalBreaks = report.rows.reduce((sum, row) => sum + Number(row.break_count || 0), 0);
    return { totalMinutes, totalBreaks };
  }, [report]);

  const startBreak = async () => {
    try {
      setMsg('');
      if (!selectedBt) throw new Error('Select a break type');
      await api('/api/breaks/start', { method: 'POST', token, body: { break_type_id: selectedBt } });
      await refreshLive();
    } catch (e) {
      handleApiError(e);
    }
  };

  const stopBreak = async () => {
    try {
      setMsg('');
      await api('/api/breaks/stop', { method: 'POST', token });
      await refreshLive();
    } catch (e) {
      handleApiError(e);
    }
  };

  const handleCreateDepartment = async (e) => {
    e.preventDefault();
    try {
      setMsg('');
      await api('/api/departments', { method: 'POST', token, body: newDepartment });
      setNewDepartment({ name: '', description: '' });
      await refreshDepartments();
    } catch (e2) {
      handleApiError(e2);
    }
  };

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    try {
      setMsg('');
      await api('/api/teams', {
        method: 'POST',
        token,
        body: {
          name: newTeam.name,
          description: newTeam.description,
          color: newTeam.color,
          department_id: newTeam.department_id ? Number(newTeam.department_id) : undefined,
        },
      });
      setNewTeam({ name: '', description: '', color: '#2563eb', department_id: '' });
      await refreshTeams();
    } catch (e2) {
      handleApiError(e2);
    }
  };

  const handleCreateBreakType = async (e) => {
    e.preventDefault();
    try {
      setMsg('');
      await api('/api/break-types', { method: 'POST', token, body: newBreakType });
      setNewBreakType({ name: '', color: '#16a34a' });
      await refreshBreakTypes();
    } catch (e2) {
      handleApiError(e2);
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      setMsg('');
      await api('/api/users', {
        method: 'POST',
        token,
        body: {
          username: newUser.username,
          password: newUser.password,
          name: newUser.name,
          must_change_password: newUser.must_change_password,
          role: newUser.role,
        },
      });
      setNewUser({ username: '', password: '', name: '', must_change_password: true, role: 'employee' });
      await refreshUsers();
    } catch (e2) {
      handleApiError(e2);
    }
  };

  const handleCreateEmployee = async (e) => {
    e.preventDefault();
    try {
      setMsg('');
      await api('/api/employees', {
        method: 'POST',
        token,
        body: {
          name: newEmployee.name,
          user_id: newEmployee.user_id ? Number(newEmployee.user_id) : undefined,
          department_id: newEmployee.department_id ? Number(newEmployee.department_id) : undefined,
          team_id: newEmployee.team_id ? Number(newEmployee.team_id) : undefined,
        },
      });
      setNewEmployee({ name: '', user_id: '', department_id: '', team_id: '' });
      await refreshEmployees();
    } catch (e2) {
      handleApiError(e2);
    }
  };

  const saveDepartmentEdit = async () => {
    if (!editingDepartment) return;
    try {
      setMsg('');
      await api(`/api/departments/${editingDepartment.id}`, {
        method: 'PUT',
        token,
        body: {
          name: editingDepartment.name,
          description: editingDepartment.description,
          status: editingDepartment.status,
        },
      });
      setEditingDepartment(null);
      await refreshDepartments();
    } catch (e) {
      handleApiError(e);
    }
  };

  const toggleDepartmentStatus = async (dept) => {
    try {
      setMsg('');
      await api(`/api/departments/${dept.id}`, {
        method: 'PUT',
        token,
        body: { status: dept.status === 'Active' ? 'Inactive' : 'Active' },
      });
      await refreshDepartments();
    } catch (e) {
      handleApiError(e);
    }
  };

  const saveTeamEdit = async () => {
    if (!editingTeam) return;
    try {
      setMsg('');
      await api(`/api/teams/${editingTeam.id}`, {
        method: 'PUT',
        token,
        body: {
          name: editingTeam.name,
          description: editingTeam.description,
          color: editingTeam.color,
          department_id: editingTeam.department_id ? Number(editingTeam.department_id) : null,
          status: editingTeam.status,
        },
      });
      setEditingTeam(null);
      await refreshTeams();
    } catch (e) {
      handleApiError(e);
    }
  };

  const toggleTeamStatus = async (team) => {
    try {
      setMsg('');
      await api(`/api/teams/${team.id}`, {
        method: 'PUT',
        token,
        body: { status: team.status === 'Active' ? 'Inactive' : 'Active' },
      });
      await refreshTeams();
    } catch (e) {
      handleApiError(e);
    }
  };

  const saveBreakTypeEdit = async () => {
    if (!editingBreakType) return;
    try {
      setMsg('');
      await api(`/api/break-types/${editingBreakType.id}`, {
        method: 'PUT',
        token,
        body: {
          name: editingBreakType.name,
          color: editingBreakType.color,
          status: editingBreakType.status,
        },
      });
      setEditingBreakType(null);
      await refreshBreakTypes();
    } catch (e) {
      handleApiError(e);
    }
  };

  const toggleBreakTypeStatus = async (bt) => {
    try {
      setMsg('');
      await api(`/api/break-types/${bt.id}`, {
        method: 'PUT',
        token,
        body: { status: bt.status === 'Active' ? 'Inactive' : 'Active' },
      });
      await refreshBreakTypes();
    } catch (e) {
      handleApiError(e);
    }
  };

  const saveUserEdit = async () => {
    if (!editingUser) return;
    try {
      setMsg('');
      await api(`/api/users/${editingUser.id}`, {
        method: 'PUT',
        token,
        body: {
          name: editingUser.name,
          role: editingUser.role,
          must_change_password: editingUser.must_change_password ? 1 : 0,
        },
      });
      setEditingUser(null);
      await refreshUsers();
    } catch (e) {
      handleApiError(e);
    }
  };

  const resetUserPassword = async (user) => {
    try {
      setMsg('');
      await api(`/api/users/${user.id}`, {
        method: 'PUT',
        token,
        body: { must_change_password: 1 },
      });
      await refreshUsers();
    } catch (e) {
      handleApiError(e);
    }
  };

  const saveEmployeeEdit = async () => {
    if (!editingEmployee) return;
    try {
      setMsg('');
      await api(`/api/employees/${editingEmployee.id}`, {
        method: 'PUT',
        token,
        body: {
          name: editingEmployee.name,
          status: editingEmployee.status,
          department_id: editingEmployee.department_id ? Number(editingEmployee.department_id) : null,
          team_id: editingEmployee.team_id ? Number(editingEmployee.team_id) : null,
          user_id: editingEmployee.user_id ? Number(editingEmployee.user_id) : null,
        },
      });
      setEditingEmployee(null);
      await refreshEmployees();
    } catch (e) {
      handleApiError(e);
    }
  };

  const toggleEmployeeStatus = async (employee) => {
    try {
      setMsg('');
      await api(`/api/employees/${employee.id}`, {
        method: 'PUT',
        token,
        body: { status: employee.status === 'Active' ? 'Inactive' : 'Active' },
      });
      await refreshEmployees();
    } catch (e) {
      handleApiError(e);
    }
  };

  const runReport = useCallback(
    async (e) => {
      if (e?.preventDefault) e.preventDefault();
      try {
        setMsg('');
        setLoadingReport(true);
        const params = new URLSearchParams();
        if (reportRange.start) params.set('start', new Date(`${reportRange.start}T00:00:00`).toISOString());
        if (reportRange.end) params.set('end', new Date(`${reportRange.end}T23:59:59`).toISOString());
        if (reportFilters.department) params.set('department_id', reportFilters.department);
        if (reportFilters.team) params.set('team_id', reportFilters.team);
        if (reportFilters.break_type) params.set('break_type_id', reportFilters.break_type);
        const query = params.toString();
        const data = await api(`/api/reports/summary${query ? `?${query}` : ''}`, { token });
        setReport(data);
      } catch (e2) {
        handleApiError(e2);
      } finally {
        setLoadingReport(false);
      }
    },
    [token, reportRange, reportFilters, handleApiError]
  );

  useEffect(() => {
    if (!token || !isManagerOrAdmin) return;
    runReport();
  }, [token, isManagerOrAdmin, runReport]);

  const navViews = useMemo(() => {
    const base = [{ id: 'live', label: isManagerOrAdmin ? 'Live' : 'Your break' }];
    if (isManagerOrAdmin) {
      base.push({ id: 'reports', label: 'Reports' });
    }
    if (isAdmin) {
      base.push({ id: 'admin', label: 'Admin' });
    }
    return base;
  }, [isManagerOrAdmin, isAdmin]);

  useEffect(() => {
    if (!navViews.length) return;
    if (!navViews.find((v) => v.id === view)) {
      setView(navViews[0].id);
    }
  }, [navViews, view]);

  const activeView = navViews.find((v) => v.id === view) || navViews[0] || { id: 'live', label: 'Your break' };

  return (
    <div style={styles.container}>
      <h1 style={{ fontSize: 30, marginBottom: 4 }}>Break Tracker</h1>
      <div style={{ color: '#6b7280', marginBottom: 12 }}>
        API health: <span style={styles.pill}>{health || '...'}</span>
      </div>

      {!token && mustChangePassword && pendingToken ? (
        <form onSubmit={handlePasswordReset} style={mergeStyles(styles.card, { maxWidth: 480 })}>
          <h2 style={styles.sectionTitle}>Change your password</h2>
          <p style={{ color: '#6b7280', marginTop: 0 }}>
            For security, update your password before accessing Break Tracker.
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input
              style={styles.input}
              placeholder="current password"
              type="password"
              value={passwordReset.current}
              onChange={(e) => setPasswordReset((prev) => ({ ...prev, current: e.target.value }))}
            />
            <input
              style={styles.input}
              placeholder="new password (min 8 chars)"
              type="password"
              value={passwordReset.next}
              onChange={(e) => setPasswordReset((prev) => ({ ...prev, next: e.target.value }))}
            />
            <input
              style={styles.input}
              placeholder="confirm new password"
              type="password"
              value={passwordReset.confirm}
              onChange={(e) => setPasswordReset((prev) => ({ ...prev, confirm: e.target.value }))}
            />
            <button style={styles.button} type="submit" disabled={loadingProfile}>
              Update password
            </button>
            <button
              style={styles.secondaryButton}
              type="button"
              onClick={() => {
                setMustChangePassword(false);
                setPendingToken('');
              }}
            >
              Cancel
            </button>
          </div>
          {msg && <div style={{ color: '#b91c1c', marginTop: 8 }}>{msg}</div>}
        </form>
      ) : !token ? (
        <form onSubmit={handleLogin} style={mergeStyles(styles.card, { maxWidth: 420 })}>
          <h2 style={styles.sectionTitle}>Sign in</h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <input
              style={styles.input}
              placeholder="username"
              value={credentials.username}
              onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
            />
            <input
              style={styles.input}
              placeholder="password"
              type="password"
              value={credentials.password}
              onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
            />
            <button style={styles.button} type="submit">
              Sign in
            </button>
          </div>
          <div style={{ color: '#6b7280', marginTop: 8 }}>
            Default admin: <b>admin / admin123</b>
          </div>
          {msg && <div style={{ color: '#b91c1c', marginTop: 8 }}>{msg}</div>}
        </form>
      ) : (
        <Fragment>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {navViews.map((v) => (
                <button
                  key={v.id}
                  onClick={() => setView(v.id)}
                  style={mergeStyles(styles.navButton, {
                    background: v.id === activeView.id ? '#eef2ff' : '#fff',
                    borderColor: v.id === activeView.id ? '#4338ca' : '#d1d5db',
                    color: v.id === activeView.id ? '#312e81' : '#111827',
                  })}
                >
                  {v.label}
                </button>
              ))}
            </div>
            {profile && (
              <div style={{ marginLeft: 'auto', textAlign: 'right', fontSize: 13, color: '#475569' }}>
                <div style={{ fontWeight: 600 }}>{profile.name || profile.username}</div>
                <div style={{ textTransform: 'capitalize' }}>{profile.role}</div>
              </div>
            )}
            <button style={mergeStyles(styles.secondaryButton, { marginLeft: profile ? 0 : 'auto' })} onClick={logout}>
              Logout
            </button>
          </div>

          {msg && <div style={{ color: '#b91c1c', marginTop: 8 }}>{msg}</div>}

          {activeView.id === 'live' && (
            <div style={styles.card}>
              <h2 style={styles.sectionTitle}>{isManagerOrAdmin ? 'Live breaks dashboard' : 'Your break'}</h2>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                <select
                  style={mergeStyles(styles.input, { minWidth: 220 })}
                  value={selectedBt ?? ''}
                  onChange={(e) => setSelectedBt(e.target.value ? Number(e.target.value) : null)}
                >
                  <option value="">Select break type…</option>
                  {activeBreakTypes.map((bt) => (
                    <option key={bt.id} value={bt.id}>
                      {bt.name}
                    </option>
                  ))}
                </select>
                <button style={styles.button} onClick={startBreak}>
                  Start break
                </button>
                <button style={mergeStyles(styles.secondaryButton, { borderColor: '#d1d5db' })} onClick={stopBreak}>
                  Stop break
                </button>
              </div>

              {isManagerOrAdmin ? (
                <Fragment>
                  <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 24 }}>
                    <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                      Department
                      <select
                        style={mergeStyles(styles.input, { padding: '6px 10px', minWidth: 180 })}
                        value={liveFilters.department}
                        onChange={(e) => setLiveFilters((prev) => ({ ...prev, department: e.target.value }))}
                      >
                        <option value="">All</option>
                        {departments.map((dept) => (
                          <option key={dept.id} value={dept.id}>
                            {dept.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                      Team
                      <select
                        style={mergeStyles(styles.input, { padding: '6px 10px', minWidth: 180 })}
                        value={liveFilters.team}
                        onChange={(e) => setLiveFilters((prev) => ({ ...prev, team: e.target.value }))}
                      >
                        <option value="">All</option>
                        {teamOptionsForFilters.map((team) => (
                          <option key={team.id} value={team.id}>
                            {team.name}
                          </option>
                        ))}
                      </select>
                    </label>
                    <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap', color: '#1f2937', fontSize: 14 }}>
                      <div>
                        <strong>{liveStats.count}</strong> on break
                      </div>
                      <div>
                        Avg <strong>{liveStats.averageMinutes}</strong> min
                      </div>
                      <div>
                        Longest <strong>{liveStats.longestMinutes}</strong> min
                      </div>
                    </div>
                  </div>

                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.th}>Employee</th>
                        <th style={styles.th}>Team</th>
                        <th style={styles.th}>Department</th>
                        <th style={styles.th}>Type</th>
                        <th style={styles.th}>Started</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredLive.length === 0 && (
                        <tr>
                          <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={5}>
                            No active breaks match the selected filters.
                          </td>
                        </tr>
                      )}
                      {filteredLive.map((row) => (
                        <tr key={row.break_id}>
                          <td style={styles.td}>{row.employee_name}</td>
                          <td style={styles.td}>{row.team_name || '-'}</td>
                          <td style={styles.td}>{row.department_name || '-'}</td>
                          <td style={styles.td}>{row.break_type}</td>
                          <td style={styles.td}>{new Date(row.start_time).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <div style={{ color: '#6b7280', marginTop: 6 }}>Updates every ~5s.</div>
                </Fragment>
              ) : (
                <div style={{ color: '#6b7280', marginTop: 24 }}>
                  Managers can view live status for their teams. Reach out to an admin if you need access.
                </div>
              )}
            </div>
          )}

          {activeView.id === 'reports' && (
            <div style={styles.card}>
              <h2 style={styles.sectionTitle}>Break summary</h2>
              <form onSubmit={runReport} style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                  Start date
                  <input
                    type="date"
                    value={reportRange.start}
                    onChange={(e) => setReportRange((prev) => ({ ...prev, start: e.target.value }))}
                    style={mergeStyles(styles.input, { padding: '6px 10px' })}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                  End date
                  <input
                    type="date"
                    value={reportRange.end}
                    onChange={(e) => setReportRange((prev) => ({ ...prev, end: e.target.value }))}
                    style={mergeStyles(styles.input, { padding: '6px 10px' })}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                  Department
                  <select
                    value={reportFilters.department}
                    onChange={(e) => setReportFilters((prev) => ({ ...prev, department: e.target.value }))}
                    style={mergeStyles(styles.input, { padding: '6px 10px', minWidth: 160 })}
                  >
                    <option value="">All</option>
                    {departments.map((dept) => (
                      <option key={dept.id} value={dept.id}>
                        {dept.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                  Team
                  <select
                    value={reportFilters.team}
                    onChange={(e) => setReportFilters((prev) => ({ ...prev, team: e.target.value }))}
                    style={mergeStyles(styles.input, { padding: '6px 10px', minWidth: 160 })}
                  >
                    <option value="">All</option>
                    {reportTeamOptions.map((team) => (
                      <option key={team.id} value={team.id}>
                        {team.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', fontSize: 13, color: '#475569' }}>
                  Break type
                  <select
                    value={reportFilters.break_type}
                    onChange={(e) => setReportFilters((prev) => ({ ...prev, break_type: e.target.value }))}
                    style={mergeStyles(styles.input, { padding: '6px 10px', minWidth: 160 })}
                  >
                    <option value="">All</option>
                    {breakTypes.map((bt) => (
                      <option key={bt.id} value={bt.id}>
                        {bt.name}
                      </option>
                    ))}
                  </select>
                </label>
                <button style={styles.button} type="submit" disabled={loadingReport}>
                  {loadingReport ? 'Loading…' : 'Run report'}
                </button>
              </form>

              <div style={{ color: '#6b7280', marginTop: 8 }}>
                Showing data from{' '}
                <b>{report.start ? new Date(report.start).toLocaleString() : '—'}</b> to{' '}
                <b>{report.end ? new Date(report.end).toLocaleString() : '—'}</b>
              </div>

              <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginTop: 12, fontSize: 14, color: '#1f2937' }}>
                <div>
                  <strong>{reportTotals.totalBreaks}</strong> breaks
                </div>
                <div>
                  <strong>{reportTotals.totalMinutes}</strong> total minutes
                </div>
                <div>
                  <strong>{report.rows.length}</strong> rows returned
                </div>
              </div>

              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Employee</th>
                    <th style={styles.th}>Department</th>
                    <th style={styles.th}>Team</th>
                    <th style={styles.th}>Break type</th>
                    <th style={styles.th}>Breaks</th>
                    <th style={styles.th}>Minutes</th>
                  </tr>
                </thead>
                <tbody>
                  {report.rows.length === 0 && (
                    <tr>
                      <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={6}>
                        No breaks logged in this range.
                      </td>
                    </tr>
                  )}
                  {report.rows.map((row) => (
                    <tr key={`${row.employee_id}-${row.break_type_id || row.break_type}`}>
                      <td style={styles.td}>{row.employee_name}</td>
                      <td style={styles.td}>{row.department_name || '-'}</td>
                      <td style={styles.td}>{row.team_name || '-'}</td>
                      <td style={styles.td}>{row.break_type}</td>
                      <td style={styles.td}>{row.break_count}</td>
                      <td style={styles.td}>{row.total_minutes}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeView.id === 'admin' && (
            <div style={styles.card}>
              <h2 style={styles.sectionTitle}>Admin management</h2>

              <div>
                <h3 style={{ marginBottom: 8 }}>Departments</h3>
                <form onSubmit={handleCreateDepartment} style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 200px' })}
                    placeholder="Name"
                    value={newDepartment.name}
                    onChange={(e) => setNewDepartment((prev) => ({ ...prev, name: e.target.value }))}
                  />
                  <input
                    style={mergeStyles(styles.input, { flex: '2 1 280px' })}
                    placeholder="Description"
                    value={newDepartment.description}
                    onChange={(e) => setNewDepartment((prev) => ({ ...prev, description: e.target.value }))}
                  />
                  <button style={styles.button} type="submit">
                    Add department
                  </button>
                </form>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Name</th>
                      <th style={styles.th}>Description</th>
                      <th style={styles.th}>Status</th>
                      <th style={styles.th}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {departments.map((d) => {
                      const isEditing = editingDepartment?.id === d.id;
                      return (
                        <tr key={d.id}>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingDepartment.name}
                                onChange={(e) => setEditingDepartment((prev) => ({ ...prev, name: e.target.value }))}
                              />
                            ) : (
                              d.name
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingDepartment.description || ''}
                                onChange={(e) => setEditingDepartment((prev) => ({ ...prev, description: e.target.value }))}
                              />
                            ) : (
                              d.description || '—'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingDepartment.status}
                                onChange={(e) => setEditingDepartment((prev) => ({ ...prev, status: e.target.value }))}
                              >
                                <option value="Active">Active</option>
                                <option value="Inactive">Inactive</option>
                              </select>
                            ) : (
                              d.status
                            )}
                          </td>
                          <td style={mergeStyles(styles.td, { display: 'flex', gap: 6, flexWrap: 'wrap' })}>
                            {isEditing ? (
                              <Fragment>
                                <button style={styles.smallButton} onClick={saveDepartmentEdit}>
                                  Save
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => setEditingDepartment(null)}
                                  type="button"
                                >
                                  Cancel
                                </button>
                              </Fragment>
                            ) : (
                              <Fragment>
                                <button style={styles.smallButton} onClick={() => setEditingDepartment({ ...d })}>
                                  Edit
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => toggleDepartmentStatus(d)}
                                  type="button"
                                >
                                  {d.status === 'Active' ? 'Deactivate' : 'Activate'}
                                </button>
                              </Fragment>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {departments.length === 0 && (
                      <tr>
                        <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={4}>
                          No departments yet
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div>
                <h3 style={{ marginBottom: 8 }}>Teams</h3>
                <form onSubmit={handleCreateTeam} style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 180px' })}
                    placeholder="Name"
                    value={newTeam.name}
                    onChange={(e) => setNewTeam((prev) => ({ ...prev, name: e.target.value }))}
                  />
                  <input
                    style={mergeStyles(styles.input, { flex: '2 1 260px' })}
                    placeholder="Description"
                    value={newTeam.description}
                    onChange={(e) => setNewTeam((prev) => ({ ...prev, description: e.target.value }))}
                  />
                  <input
                    style={mergeStyles(styles.input, { width: 120 })}
                    type="color"
                    value={newTeam.color}
                    onChange={(e) => setNewTeam((prev) => ({ ...prev, color: e.target.value }))}
                  />
                  <select
                    style={mergeStyles(styles.input, { flex: '1 1 200px' })}
                    value={newTeam.department_id}
                    onChange={(e) => setNewTeam((prev) => ({ ...prev, department_id: e.target.value }))}
                  >
                    <option value="">Department…</option>
                    {departments.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                  <button style={styles.button} type="submit">
                    Add team
                  </button>
                </form>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Name</th>
                      <th style={styles.th}>Description</th>
                      <th style={styles.th}>Department</th>
                      <th style={styles.th}>Color</th>
                      <th style={styles.th}>Status</th>
                      <th style={styles.th}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {teams.map((t) => {
                      const isEditing = editingTeam?.id === t.id;
                      return (
                        <tr key={t.id}>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingTeam.name}
                                onChange={(e) => setEditingTeam((prev) => ({ ...prev, name: e.target.value }))}
                              />
                            ) : (
                              t.name
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingTeam.description || ''}
                                onChange={(e) => setEditingTeam((prev) => ({ ...prev, description: e.target.value }))}
                              />
                            ) : (
                              t.description || '—'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingTeam.department_id || ''}
                                onChange={(e) => setEditingTeam((prev) => ({ ...prev, department_id: e.target.value }))}
                              >
                                <option value="">None</option>
                                {departments.map((dept) => (
                                  <option key={dept.id} value={dept.id}>
                                    {dept.name}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              t.department_name || '—'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                type="color"
                                value={editingTeam.color || '#cbd5f5'}
                                onChange={(e) => setEditingTeam((prev) => ({ ...prev, color: e.target.value }))}
                              />
                            ) : (
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                                <span
                                  style={{
                                    display: 'inline-block',
                                    background: t.color || '#cbd5f5',
                                    width: 16,
                                    height: 16,
                                    borderRadius: 4,
                                    border: '1px solid #cbd5f5',
                                  }}
                                />
                                {t.color}
                              </span>
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingTeam.status}
                                onChange={(e) => setEditingTeam((prev) => ({ ...prev, status: e.target.value }))}
                              >
                                <option value="Active">Active</option>
                                <option value="Inactive">Inactive</option>
                              </select>
                            ) : (
                              t.status
                            )}
                          </td>
                          <td style={mergeStyles(styles.td, { display: 'flex', gap: 6, flexWrap: 'wrap' })}>
                            {isEditing ? (
                              <Fragment>
                                <button style={styles.smallButton} onClick={saveTeamEdit}>
                                  Save
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => setEditingTeam(null)}
                                  type="button"
                                >
                                  Cancel
                                </button>
                              </Fragment>
                            ) : (
                              <Fragment>
                                <button style={styles.smallButton} onClick={() => setEditingTeam({ ...t })}>
                                  Edit
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => toggleTeamStatus(t)}
                                  type="button"
                                >
                                  {t.status === 'Active' ? 'Deactivate' : 'Activate'}
                                </button>
                              </Fragment>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {teams.length === 0 && (
                      <tr>
                        <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={6}>
                          No teams yet
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div>
                <h3 style={{ marginBottom: 8 }}>Break types</h3>
                <form onSubmit={handleCreateBreakType} style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 200px' })}
                    placeholder="Name"
                    value={newBreakType.name}
                    onChange={(e) => setNewBreakType((prev) => ({ ...prev, name: e.target.value }))}
                  />
                  <input
                    style={mergeStyles(styles.input, { width: 120 })}
                    type="color"
                    value={newBreakType.color}
                    onChange={(e) => setNewBreakType((prev) => ({ ...prev, color: e.target.value }))}
                  />
                  <button style={styles.button} type="submit">
                    Add break type
                  </button>
                </form>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Name</th>
                      <th style={styles.th}>Color</th>
                      <th style={styles.th}>Status</th>
                      <th style={styles.th}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {breakTypes.map((bt) => {
                      const isEditing = editingBreakType?.id === bt.id;
                      return (
                        <tr key={bt.id}>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingBreakType.name}
                                onChange={(e) => setEditingBreakType((prev) => ({ ...prev, name: e.target.value }))}
                              />
                            ) : (
                              bt.name
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                type="color"
                                value={editingBreakType.color || '#16a34a'}
                                onChange={(e) => setEditingBreakType((prev) => ({ ...prev, color: e.target.value }))}
                              />
                            ) : (
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                                <span
                                  style={{
                                    display: 'inline-block',
                                    background: bt.color || '#16a34a',
                                    width: 16,
                                    height: 16,
                                    borderRadius: 4,
                                    border: '1px solid #cbd5f5',
                                  }}
                                />
                                {bt.color}
                              </span>
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingBreakType.status}
                                onChange={(e) => setEditingBreakType((prev) => ({ ...prev, status: e.target.value }))}
                              >
                                <option value="Active">Active</option>
                                <option value="Inactive">Inactive</option>
                              </select>
                            ) : (
                              bt.status
                            )}
                          </td>
                          <td style={mergeStyles(styles.td, { display: 'flex', gap: 6, flexWrap: 'wrap' })}>
                            {isEditing ? (
                              <Fragment>
                                <button style={styles.smallButton} onClick={saveBreakTypeEdit}>
                                  Save
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => setEditingBreakType(null)}
                                  type="button"
                                >
                                  Cancel
                                </button>
                              </Fragment>
                            ) : (
                              <Fragment>
                                <button style={styles.smallButton} onClick={() => setEditingBreakType({ ...bt })}>
                                  Edit
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => toggleBreakTypeStatus(bt)}
                                  type="button"
                                >
                                  {bt.status === 'Active' ? 'Deactivate' : 'Activate'}
                                </button>
                              </Fragment>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {breakTypes.length === 0 && (
                      <tr>
                        <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={4}>
                          No break types yet
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div>
                <h3 style={{ marginBottom: 8 }}>Users</h3>
                <form onSubmit={handleCreateUser} style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 160px' })}
                    placeholder="Username"
                    value={newUser.username}
                    onChange={(e) => setNewUser((prev) => ({ ...prev, username: e.target.value }))}
                  />
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 160px' })}
                    placeholder="Temp password"
                    value={newUser.password}
                    onChange={(e) => setNewUser((prev) => ({ ...prev, password: e.target.value }))}
                  />
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 200px' })}
                    placeholder="Full name"
                    value={newUser.name}
                    onChange={(e) => setNewUser((prev) => ({ ...prev, name: e.target.value }))}
                  />
                  <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                    <input
                      type="checkbox"
                      checked={newUser.must_change_password}
                      onChange={(e) => setNewUser((prev) => ({ ...prev, must_change_password: e.target.checked }))}
                    />
                    Must change password
                  </label>
                  <select
                    style={mergeStyles(styles.input, { flex: '1 1 160px' })}
                    value={newUser.role}
                    onChange={(e) => setNewUser((prev) => ({ ...prev, role: e.target.value }))}
                  >
                    <option value="employee">Employee</option>
                    <option value="manager">Manager</option>
                    <option value="admin">Admin</option>
                  </select>
                  <button style={styles.button} type="submit">
                    Add user
                  </button>
                </form>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Username</th>
                      <th style={styles.th}>Name</th>
                      <th style={styles.th}>Role</th>
                      <th style={styles.th}>Must reset?</th>
                      <th style={styles.th}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => {
                      const isEditing = editingUser?.id === u.id;
                      return (
                        <tr key={u.id}>
                          <td style={styles.td}>{u.username}</td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingUser.name || ''}
                                onChange={(e) => setEditingUser((prev) => ({ ...prev, name: e.target.value }))}
                              />
                            ) : (
                              u.name || '—'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingUser.role}
                                onChange={(e) => setEditingUser((prev) => ({ ...prev, role: e.target.value }))}
                              >
                                <option value="employee">Employee</option>
                                <option value="manager">Manager</option>
                                <option value="admin">Admin</option>
                              </select>
                            ) : (
                              u.role
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                                <input
                                  type="checkbox"
                                  checked={!!editingUser.must_change_password}
                                  onChange={(e) => setEditingUser((prev) => ({ ...prev, must_change_password: e.target.checked }))}
                                />
                                Require reset
                              </label>
                            ) : (
                              u.must_change_password ? 'Yes' : 'No'
                            )}
                          </td>
                          <td style={mergeStyles(styles.td, { display: 'flex', gap: 6, flexWrap: 'wrap' })}>
                            {isEditing ? (
                              <Fragment>
                                <button style={styles.smallButton} onClick={saveUserEdit}>
                                  Save
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => setEditingUser(null)}
                                  type="button"
                                >
                                  Cancel
                                </button>
                              </Fragment>
                            ) : (
                              <Fragment>
                                <button style={styles.smallButton} onClick={() => setEditingUser({ ...u })}>
                                  Edit
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => resetUserPassword(u)}
                                  type="button"
                                >
                                  Force reset
                                </button>
                              </Fragment>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {users.length === 0 && (
                      <tr>
                        <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={5}>
                          No users yet
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div>
                <h3 style={{ marginBottom: 8 }}>Employees</h3>
                <form onSubmit={handleCreateEmployee} style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  <input
                    style={mergeStyles(styles.input, { flex: '1 1 200px' })}
                    placeholder="Name"
                    value={newEmployee.name}
                    onChange={(e) => setNewEmployee((prev) => ({ ...prev, name: e.target.value }))}
                  />
                  <select
                    style={mergeStyles(styles.input, { flex: '1 1 160px' })}
                    value={newEmployee.user_id}
                    onChange={(e) => setNewEmployee((prev) => ({ ...prev, user_id: e.target.value }))}
                  >
                    <option value="">User (optional)…</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.username}
                      </option>
                    ))}
                  </select>
                  <select
                    style={mergeStyles(styles.input, { flex: '1 1 160px' })}
                    value={newEmployee.department_id}
                    onChange={(e) => setNewEmployee((prev) => ({ ...prev, department_id: e.target.value }))}
                  >
                    <option value="">Department…</option>
                    {departments.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                  </select>
                  <select
                    style={mergeStyles(styles.input, { flex: '1 1 160px' })}
                    value={newEmployee.team_id}
                    onChange={(e) => setNewEmployee((prev) => ({ ...prev, team_id: e.target.value }))}
                  >
                    <option value="">Team…</option>
                    {teams.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                  <button style={styles.button} type="submit">
                    Add employee
                  </button>
                </form>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Name</th>
                      <th style={styles.th}>User</th>
                      <th style={styles.th}>Department</th>
                      <th style={styles.th}>Team</th>
                      <th style={styles.th}>Status</th>
                      <th style={styles.th}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {employees.map((emp) => {
                      const isEditing = editingEmployee?.id === emp.id;
                      return (
                        <tr key={emp.id}>
                          <td style={styles.td}>
                            {isEditing ? (
                              <input
                                style={mergeStyles(styles.input, { width: '100%', padding: '4px 6px' })}
                                value={editingEmployee.name || ''}
                                onChange={(e) => setEditingEmployee((prev) => ({ ...prev, name: e.target.value }))}
                              />
                            ) : (
                              emp.name
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingEmployee.user_id || ''}
                                onChange={(e) => setEditingEmployee((prev) => ({ ...prev, user_id: e.target.value }))}
                              >
                                <option value="">Unassigned</option>
                                {users.map((u) => (
                                  <option key={u.id} value={u.id}>
                                    {u.username}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              users.find((u) => u.id === emp.user_id)?.username || '-'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingEmployee.department_id || ''}
                                onChange={(e) => setEditingEmployee((prev) => ({ ...prev, department_id: e.target.value }))}
                              >
                                <option value="">None</option>
                                {departments.map((d) => (
                                  <option key={d.id} value={d.id}>
                                    {d.name}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              departments.find((d) => d.id === emp.department_id)?.name || '-'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingEmployee.team_id || ''}
                                onChange={(e) => setEditingEmployee((prev) => ({ ...prev, team_id: e.target.value }))}
                              >
                                <option value="">None</option>
                                {teams.map((t) => (
                                  <option key={t.id} value={t.id}>
                                    {t.name}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              teams.find((t) => t.id === emp.team_id)?.name || '-'
                            )}
                          </td>
                          <td style={styles.td}>
                            {isEditing ? (
                              <select
                                style={mergeStyles(styles.input, { padding: '4px 6px' })}
                                value={editingEmployee.status}
                                onChange={(e) => setEditingEmployee((prev) => ({ ...prev, status: e.target.value }))}
                              >
                                <option value="Active">Active</option>
                                <option value="Inactive">Inactive</option>
                              </select>
                            ) : (
                              emp.status
                            )}
                          </td>
                          <td style={mergeStyles(styles.td, { display: 'flex', gap: 6, flexWrap: 'wrap' })}>
                            {isEditing ? (
                              <Fragment>
                                <button style={styles.smallButton} onClick={saveEmployeeEdit}>
                                  Save
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => setEditingEmployee(null)}
                                  type="button"
                                >
                                  Cancel
                                </button>
                              </Fragment>
                            ) : (
                              <Fragment>
                                <button style={styles.smallButton} onClick={() => setEditingEmployee({ ...emp })}>
                                  Edit
                                </button>
                                <button
                                  style={mergeStyles(styles.smallButton, {
                                    background: '#fff',
                                    color: '#1f2937',
                                    borderColor: '#d1d5db',
                                  })}
                                  onClick={() => toggleEmployeeStatus(emp)}
                                  type="button"
                                >
                                  {emp.status === 'Active' ? 'Deactivate' : 'Activate'}
                                </button>
                              </Fragment>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {employees.length === 0 && (
                      <tr>
                        <td style={mergeStyles(styles.td, { color: '#6b7280' })} colSpan={6}>
                          No employees yet
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </Fragment>
      )}
    </div>
  );
}
