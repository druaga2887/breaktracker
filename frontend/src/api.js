// Simple fetch wrapper that talks to the backend API
export const API_BASE =
  (typeof import.meta !== 'undefined' &&
    import.meta.env &&
    import.meta.env.VITE_API_URL) ||
  window.__API_URL__ ||
  'http://localhost:3001';

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
      msg = data.message || JSON.stringify(data);
    } catch (_) {}
    throw new Error(`${res.status} ${msg}`);
  }

  if (res.status === 204) return null;

  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? await res.json() : await res.text();
}
