// Simple fetch wrapper that talks to the backend API
const envApiBase =
  typeof import.meta !== 'undefined' &&
  import.meta.env &&
  import.meta.env.VITE_API_URL
    ? import.meta.env.VITE_API_URL
    : undefined;

let runtimeApiBase;
if (typeof window !== 'undefined') {
  if (window.__API_URL__) {
    runtimeApiBase = window.__API_URL__;
  } else if (window.location && window.location.origin) {
    runtimeApiBase = window.location.origin;

    const hostname = window.location.hostname;
    const port = window.location.port;
    const isLocalHost =
      hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';

    if (isLocalHost && port && port !== '3001') {
      runtimeApiBase = `${window.location.protocol}//${hostname}:3001`;
    }
  }
}

export const API_BASE = envApiBase || runtimeApiBase || 'http://localhost:3001';

export async function api(path, { method = 'GET', token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let msg = res.statusText;
    try {
      const data = await res.json();
      msg = data.error || data.message || JSON.stringify(data);
    } catch (_) {}
    throw new Error(`${res.status} ${msg}`);
  }

  if (res.status === 204) return null;

  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? await res.json() : await res.text();
}
