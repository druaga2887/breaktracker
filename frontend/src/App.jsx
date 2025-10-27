import React, { useEffect, useState } from 'react';
import { api } from './api';

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('bt_token') || '');
  const [user, setUser] = useState({ username: 'admin', password: 'admin123' });
  const [health, setHealth] = useState('');
  const [live, setLive] = useState([]);
  const [breakTypes, setBreakTypes] = useState([]);
  const [selectedBt, setSelectedBt] = useState(null);
  const [msg, setMsg] = useState('');

  // API health
  useEffect(() => {
    api('/api/health')
      .then(h => setHealth(`${h.status} v${h.version}`))
      .catch(e => setHealth(String(e)));
  }, []);

  // After login: load break types + live status and poll
  useEffect(() => {
    if (!token) return;
    const load = async () => {
      try {
        const types = await api('/api/break-types', { token });
        setBreakTypes(types);
        setSelectedBt(types[0]?.id || null);
        const rows = await api('/api/status/live', { token });
        setLive(rows);
      } catch (e) {
        setMsg(String(e.message || e));
      }
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, [token]);

  const onLogin = async (e) => {
    e.preventDefault();
    setMsg('');
    try {
      const r = await api('/api/auth/login', { method: 'POST', body: user });
      setToken(r.token);
      localStorage.setItem('bt_token', r.token);
    } catch (e) {
      setMsg(String(e.message || e));
    }
  };

  const startBreak = async () => {
    setMsg('');
    try {
      if (!selectedBt) throw new Error('No break types. Ask an admin to create one.');
      await api('/api/breaks/start', { method: 'POST', token, body: { break_type_id: selectedBt } });
      const rows = await api('/api/status/live', { token });
      setLive(rows);
    } catch (e) {
      setMsg(String(e.message || e));
    }
  };

  const stopBreak = async () => {
    setMsg('');
    try {
      await api('/api/breaks/stop', { method: 'POST', token, body: {} });
      const rows = await api('/api/status/live', { token });
      setLive(rows);
    } catch (e) {
      setMsg(String(e.message || e));
    }
  };

  const logout = () => {
    setToken('');
    localStorage.removeItem('bt_token');
  };

  return (
    <div style={{fontFamily:'system-ui, -apple-system, Segoe UI, Roboto, sans-serif', padding: 16, maxWidth: 960, margin: '0 auto'}}>
      <h1>Break Tracker</h1>
      <div style={{color:'#6b7280', marginBottom: 12}}>
        API health: <span style={{background:'#eef2ff', padding:'2px 8px', borderRadius:999}}>{health || '...'}</span>
      </div>

      {!token ? (
        <form onSubmit={onLogin} style={{marginTop:16}}>
          <div style={{display:'flex', gap:8}}>
            <input placeholder="username" value={user.username}
                   onChange={e => setUser({...user, username: e.target.value})}/>
            <input placeholder="password" type="password" value={user.password}
                   onChange={e => setUser({...user, password: e.target.value})}/>
            <button type="submit">Sign in</button>
          </div>
          <div style={{color:'#6b7280', marginTop:8}}>Default admin: <b>admin / admin123</b></div>
          {msg && <div style={{color:'#b91c1c', marginTop:8}}>{msg}</div>}
        </form>
      ) : (
        <>
          <div style={{display:'flex', gap:8, alignItems:'center', marginTop:16}}>
            <select value={selectedBt ?? ''} onChange={e => setSelectedBt(Number(e.target.value) || null)}>
              <option value="">Select break type…</option>
              {breakTypes.map(bt => <option key={bt.id} value={bt.id}>{bt.name}</option>)}
            </select>
            <button onClick={startBreak}>Start break</button>
            <button onClick={stopBreak}>Stop break</button>
            <button onClick={logout} style={{marginLeft:'auto'}}>Logout</button>
          </div>

          {msg && <div style={{color:'#b91c1c', marginTop:8}}>{msg}</div>}

          <h3 style={{marginTop:24}}>Currently on break</h3>
          <table width="100%" cellPadding="6" style={{borderCollapse:'collapse'}}>
            <thead>
              <tr style={{textAlign:'left', borderBottom:'1px solid #e5e7eb'}}>
                <th>Employee</th><th>Team</th><th>Department</th><th>Type</th><th>Started</th>
              </tr>
            </thead>
            <tbody>
            {live.length === 0 && (<tr><td colSpan="5" style={{color:'#6b7280'}}>No active breaks</td></tr>)}
            {live.map(r => (
              <tr key={r.break_id} style={{borderBottom:'1px solid #f3f4f6'}}>
                <td>{r.employee_name}</td>
                <td>{r.team_name || '-'}</td>
                <td>{r.department_name || '-'}</td>
                <td>{r.break_type}</td>
                <td>{new Date(r.start_time).toLocaleString()}</td>
              </tr>
            ))}
            </tbody>
          </table>
          <div style={{color:'#6b7280', marginTop:6}}>Updates every ~5s.</div>
        </>
      )}
    </div>
  );
}
