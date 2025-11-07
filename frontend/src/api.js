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
    const { protocol, hostname, origin } = window.location;
    runtimeApiBase = origin;

    const isLocalHost =
      hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';

    if (isLocalHost) {
      const baseProtocol = protocol || 'http:';
      runtimeApiBase = `${baseProtocol}//${hostname}:3001`;
    } else if (hostname) {
      const codespaceMatch = hostname.match(/^\d+-(.+\.app\.github\.dev)$/);
      if (codespaceMatch) {
        runtimeApiBase = `${protocol}//3001-${codespaceMatch[1]}`;
      }
    }
  }
}

export const API_BASE = envApiBase || runtimeApiBase || 'http://localhost:3001';

const LOCALHOST_NAMES = new Set(['localhost', '127.0.0.1', '::1']);

function unique(items) {
  return Array.from(new Set(items.filter(Boolean)));
}

function deriveGithubHostedBase(protocol, hostname) {
  if (!hostname || !protocol) return null;

  const normalizedHost = hostname.toLowerCase();
  const isGithubHosted =
    normalizedHost.endsWith('.app.github.dev') ||
    normalizedHost.endsWith('.githubpreview.dev') ||
    normalizedHost.endsWith('.preview.app.github.dev');

  if (!isGithubHosted) return null;

  const [subdomain, ...domainParts] = hostname.split('.');
  if (!subdomain || domainParts.length === 0) return null;

  const restDomain = domainParts.join('.');
  const subParts = subdomain.split('-');
  if (subParts.length < 2) return null;

  const candidates = [];

  const restSubdomain = subParts.slice(1).join('-');
  if (restSubdomain) {
    candidates.push(`${protocol}//3001-${restSubdomain}.${restDomain}`);
  }

  const numericIndex = subParts.findIndex((segment) => /^\d+$/.test(segment));
  if (numericIndex !== -1) {
    const replaced = subParts.slice();
    replaced[numericIndex] = '3001';
    candidates.push(`${protocol}//${replaced.join('-')}.${restDomain}`);
  }

  if (numericIndex === -1) {
    candidates.push(`${protocol}//${subParts.join('-')}-3001.${restDomain}`);
  }

  return candidates.length ? unique(candidates) : null;
}

function flattenCandidates(candidate) {
  if (!candidate) return [];
  return Array.isArray(candidate) ? candidate : [candidate];
}

function computeRuntimeCandidates() {
  if (envApiBase) {
    return [envApiBase];
  }

  const candidates = [];

  if (typeof window !== 'undefined' && window.location) {
    const { protocol = 'http:', hostname, origin } = window.location;

    if (window.__API_URL__) {
      candidates.push(window.__API_URL__);
    }

    if (origin) {
      candidates.push(origin);
    }

    if (hostname && LOCALHOST_NAMES.has(hostname)) {
      candidates.push(`${protocol}//${hostname}:3001`);
      candidates.push('http://127.0.0.1:3001');
    }

    flattenCandidates(deriveGithubHostedBase(protocol, hostname)).forEach((c) =>
      candidates.push(c)
    );
  }

  candidates.push('http://localhost:3001');
  candidates.push('http://127.0.0.1:3001');

  return unique(candidates);
}

let resolvedApiBase = envApiBase || null;

async function performRequest(base, path, options) {
  const headers = { 'Content-Type': 'application/json' };
  if (options.token) headers['Authorization'] = `Bearer ${options.token}`;

  const response = await fetch(`${base}${path}`, {
    method: options.method,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (!response.ok) {
    const isPotentialProxy404 =
      !envApiBase &&
      typeof window !== 'undefined' &&
      window.location &&
      base === window.location.origin &&
      response.status === 404;

    if (isPotentialProxy404) {
      throw new Error('retry-next-base');
    }

    let message = response.statusText;
    try {
      const data = await res.json();
      msg = data.error || data.message || JSON.stringify(data);
    } catch (_) {}
    throw new Error(`${response.status} ${message}`);
  }

  if (response.status === 204) return null;

  const contentType = response.headers.get('content-type') || '';
  return contentType.includes('application/json')
    ? await response.json()
    : await response.text();
}

export async function api(path, { method = 'GET', token, body } = {}) {
  const options = { method, token, body };

  if (resolvedApiBase) {
    return performRequest(resolvedApiBase, path, options);
  }

  const candidates = computeRuntimeCandidates();
  let lastError = null;

  for (const base of candidates) {
    try {
      const result = await performRequest(base, path, options);
      resolvedApiBase = base;
      return result;
    } catch (err) {
      if (err.message === 'retry-next-base') {
        lastError = null;
        continue;
      }
      lastError = err;
    }
  }

  if (lastError) throw lastError;
  throw new Error('Unable to reach the Break Tracker API.');
}

export function getApiBase() {
  if (resolvedApiBase) return resolvedApiBase;
  const [first] = computeRuntimeCandidates();
  return first;
}
