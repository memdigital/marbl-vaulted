interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  RATE_LIMIT_STORE: { limit: (opts: { key: string }) => Promise<{ success: boolean }> };
  RATE_LIMIT_READ: { limit: (opts: { key: string }) => Promise<{ success: boolean }> };
}

const TTL_SECONDS = 60 * 60;
const MAX_CIPHERTEXT_B64_CHARS = 24000;

const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=()',
    'usb=()',
    'magnetometer=()',
    'gyroscope=()',
    'accelerometer=()',
    'interest-cohort=()',
    'browsing-topics=()',
    'attribution-reporting=()',
    'private-state-token-redemption=()',
    'private-state-token-issuance=()',
  ].join(', '),
};

const APP_ORIGIN = 'https://vaulted.marbl.codes';

const NO_STORE_HEADERS: Record<string, string> = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

const CSP_DEFAULT = [
  "default-src 'self'",
  "script-src 'self' https://marbl.codes",
  "style-src 'self' 'unsafe-inline' https://marbl.codes",
  "font-src 'self' https://marbl.codes data:",
  "img-src 'self' data: https://marbl.codes",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'self'",
  "object-src 'none'",
].join('; ');

function applyHeaders(
  response: Response,
  extras?: Record<string, string>,
): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  headers.set('Content-Security-Policy', CSP_DEFAULT);
  if (extras) for (const [k, v] of Object.entries(extras)) headers.set(k, v);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function jsonResponse(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    ...NO_STORE_HEADERS,
  };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  return new Response(JSON.stringify(data), { status, headers });
}

function generateId(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function isValidId(id: string): boolean {
  return /^[A-Za-z0-9_-]{16}$/.test(id);
}

function requireSameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin');
  return origin === APP_ORIGIN;
}

const B64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const IV_B64_LENGTH = 16;
const VERIFIER_HASH_LENGTH = 43;
const VERIFIER_LENGTH = 22;
const DUMMY_VERIFIER_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

async function sha256B64Url(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function handleStore(request: Request, env: Env): Promise<Response> {
  try {
    if (!requireSameOrigin(request)) {
      return jsonResponse({ error: 'forbidden' }, 403);
    }
    const ip = request.headers.get('cf-connecting-ip');
    if (!ip) {
      return jsonResponse({ error: 'forbidden' }, 403);
    }

    const contentLength = request.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > 32 * 1024) {
      return jsonResponse({ error: 'too_large' }, 413);
    }

    const limited = await env.RATE_LIMIT_STORE.limit({ key: `store:${ip}` });
    if (!limited.success) {
      return jsonResponse({ error: 'rate_limited' }, 429);
    }

    let body: { ciphertext?: unknown; iv?: unknown; verifierHash?: unknown };
    try {
      body = (await request.json()) as { ciphertext?: unknown; iv?: unknown; verifierHash?: unknown };
    } catch {
      return jsonResponse({ error: 'invalid_payload' }, 400);
    }

    if (
      typeof body.ciphertext !== 'string' ||
      typeof body.iv !== 'string' ||
      typeof body.verifierHash !== 'string'
    ) {
      return jsonResponse({ error: 'invalid_payload' }, 400);
    }
    if (
      !B64URL_PATTERN.test(body.ciphertext) ||
      !B64URL_PATTERN.test(body.iv) ||
      !B64URL_PATTERN.test(body.verifierHash)
    ) {
      return jsonResponse({ error: 'invalid_payload' }, 400);
    }
    if (body.iv.length !== IV_B64_LENGTH) {
      return jsonResponse({ error: 'invalid_payload' }, 400);
    }
    if (body.verifierHash.length !== VERIFIER_HASH_LENGTH) {
      return jsonResponse({ error: 'invalid_payload' }, 400);
    }
    if (body.ciphertext.length === 0) {
      return jsonResponse({ error: 'invalid_payload' }, 400);
    }
    if (body.ciphertext.length > MAX_CIPHERTEXT_B64_CHARS) {
      return jsonResponse({ error: 'too_large' }, 413);
    }

    const id = generateId();
    const expiresAt = Math.floor(Date.now() / 1000) + TTL_SECONDS;
    await env.DB.prepare(
      'INSERT INTO secrets (id, c, i, h, expires_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind(id, body.ciphertext, body.iv, body.verifierHash, expiresAt)
      .run();

    return jsonResponse({ id });
  } catch (err) {
    console.error('[vaulted] handleStore unexpected error:', err);
    return jsonResponse({ error: 'server_error' }, 500);
  }
}

async function handleReveal(id: string, request: Request, env: Env): Promise<Response> {
  const opaqueNotFound = () => jsonResponse({ error: 'not_found' }, 404);

  try {
    if (!requireSameOrigin(request)) {
      return opaqueNotFound();
    }

    if (!isValidId(id)) {
      return opaqueNotFound();
    }

    const ip = request.headers.get('cf-connecting-ip');
    if (!ip) {
      return opaqueNotFound();
    }

    const [ipOk, idOk] = await Promise.all([
      env.RATE_LIMIT_READ.limit({ key: `read:${ip}` }),
      env.RATE_LIMIT_READ.limit({ key: `id:${id}` }),
    ]);
    if (!ipOk.success || !idOk.success) {
      return opaqueNotFound();
    }

    let body: { verifier?: unknown };
    try {
      body = (await request.json()) as { verifier?: unknown };
    } catch {
      return opaqueNotFound();
    }
    const candidate = body.verifier;
    if (typeof candidate !== 'string' || !B64URL_PATTERN.test(candidate) || candidate.length !== VERIFIER_LENGTH) {
      return opaqueNotFound();
    }

    const stored = await env.DB.prepare(
      'SELECT c, i, h FROM secrets WHERE id = ? AND expires_at > unixepoch()',
    )
      .bind(id)
      .first<{ c: string; i: string; h: string }>();
    const candidateHash = await sha256B64Url(candidate);
    const compareTarget = stored ? stored.h : DUMMY_VERIFIER_HASH;
    const hashOk = constantTimeEqual(candidateHash, compareTarget);
    if (!stored || !hashOk) {
      return opaqueNotFound();
    }

    const deleted = await env.DB.prepare(
      'DELETE FROM secrets WHERE id = ? AND expires_at > unixepoch() RETURNING c, i',
    )
      .bind(id)
      .first<{ c: string; i: string }>();
    if (!deleted) {
      return opaqueNotFound();
    }

    return new Response(JSON.stringify({ c: deleted.c, i: deleted.i }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        ...NO_STORE_HEADERS,
      },
    });
  } catch (err) {
    console.error('[vaulted] handleReveal unexpected error:', err);
    return opaqueNotFound();
  }
}

const FATHOM_ALLOWED_METHODS = new Set(['GET']);

async function handleFathomProxy(request: Request, url: URL, path: string): Promise<Response> {
  try {
    if (!FATHOM_ALLOWED_METHODS.has(request.method)) {
      return applyHeaders(new Response('Method not allowed', { status: 405 }));
    }

    const upstreamPath = path.slice('/fathom-proxy/'.length);
    if (upstreamPath !== 'script.js' && upstreamPath !== '') {
      return applyHeaders(new Response('Not found', { status: 404 }));
    }

    const upstreamUrl = `https://cdn.usefathom.com/${upstreamPath}${url.search}`;
    const upstream = await fetch(upstreamUrl, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'User-Agent': 'Marbl-Vaulted-Fathom-Proxy/1.0' },
    });

    if (upstream.status >= 300 && upstream.status < 400) {
      console.warn('[fathom-proxy] upstream tried to redirect, refusing', upstream.status);
      return applyHeaders(new Response('Not found', { status: 404 }));
    }

    if (upstreamPath === 'script.js') {
      const original = await upstream.text();
      const rewritten = original.replace(
        'trackerUrl="https://"+scriptUrl.hostname+"/"',
        'trackerUrl="https://"+scriptUrl.hostname+"/fathom-proxy/"',
      );
      if (rewritten === original) {
        console.warn('[fathom-proxy] tracker URL rewrite no-oped - upstream changed');
      }
      return applyHeaders(new Response(rewritten, {
        status: upstream.status,
        headers: {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=1800',
        },
      }));
    }

    const ct = upstream.headers.get('content-type') || 'application/octet-stream';
    return applyHeaders(new Response(upstream.body, {
      status: upstream.status,
      headers: {
        'Content-Type': ct,
        'Cache-Control': 'no-store',
      },
    }));
  } catch (err) {
    console.error('[vaulted] handleFathomProxy unexpected error:', err);
    return applyHeaders(new Response('Bad gateway', { status: 502 }));
  }
}

function requireBindings(env: Env): string | null {
  if (!env.DB) return 'DB';
  if (!env.ASSETS) return 'ASSETS';
  if (!env.RATE_LIMIT_STORE) return 'RATE_LIMIT_STORE';
  if (!env.RATE_LIMIT_READ) return 'RATE_LIMIT_READ';
  return null;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const missing = requireBindings(env);
    if (missing) {
      console.error(`[vaulted] missing binding: ${missing}`);
      return applyHeaders(new Response('Service misconfigured', { status: 500 }));
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/fathom-proxy/')) {
      return handleFathomProxy(request, url, path);
    }

    if (path === '/api/store' && request.method === 'POST') {
      return applyHeaders(await handleStore(request, env));
    }
    if (path.startsWith('/api/reveal/') && request.method === 'POST') {
      const id = path.slice('/api/reveal/'.length);
      return applyHeaders(await handleReveal(id, request, env));
    }
    if (path.startsWith('/api/')) {
      return applyHeaders(jsonResponse({ error: 'not_found' }, 404));
    }

    if (path === '/v' || path === '/v/') {
      return applyHeaders(Response.redirect(new URL('/', url).toString(), 302));
    }
    if (path.startsWith('/v/')) {
      const id = path.slice('/v/'.length);
      if (!isValidId(id)) {
        return applyHeaders(Response.redirect(new URL('/', url).toString(), 302));
      }
      const vRequest = new Request(new URL('/v', url), request);
      const response = await env.ASSETS.fetch(vRequest);
      return applyHeaders(
        response,
        {
          'X-Robots-Tag': 'noindex, nofollow',
          'Referrer-Policy': 'no-referrer',
          ...NO_STORE_HEADERS,
        },
      );
    }

    if (path === '/about') {
      const aboutRequest = new Request(new URL('/about', url), request);
      const response = await env.ASSETS.fetch(aboutRequest);
      return applyHeaders(response);
    }

    const response = await env.ASSETS.fetch(request);
    return applyHeaders(response);
  },

  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const missing = requireBindings(env);
    if (missing) {
      console.error(`[vaulted] cron missing binding: ${missing}`);
      return;
    }
    const CRON_SWEEP_LIMIT = 10000;
    const result = await env.DB.prepare(
      `DELETE FROM secrets WHERE id IN (
         SELECT id FROM secrets WHERE expires_at <= unixepoch() LIMIT ?
       )`,
    )
      .bind(CRON_SWEEP_LIMIT)
      .run();
    const swept = result.meta?.changes ?? 0;
    console.log(`[vaulted] cron swept ${swept} expired row(s)`);
    if (swept >= CRON_SWEEP_LIMIT) {
      console.warn(
        `[vaulted] cron hit sweep cap (${CRON_SWEEP_LIMIT}) - backlog remains, next cron continues`,
      );
    }
  },
};
