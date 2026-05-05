/**
 * Marbl Vaulted - one-time encrypted secret share.
 *
 * The Worker:
 *   - Routes API endpoints (POST /api/store, POST /api/reveal/:id)
 *   - Serves the recipient page /v/:id with X-Robots-Tag: noindex
 *   - Passes everything else through to the static assets binding
 *   - Adds strict security headers to every response
 *
 * Crypto runs entirely client-side. The server only sees ciphertext + IV.
 * The decryption key travels in the URL fragment, which never reaches the server.
 */

interface Env {
  VAULTED: KVNamespace;
  ASSETS: Fetcher;
  RATE_LIMIT_STORE: { limit: (opts: { key: string }) => Promise<{ success: boolean }> };
  RATE_LIMIT_READ: { limit: (opts: { key: string }) => Promise<{ success: boolean }> };
}

const TTL_SECONDS = 60 * 60; // 1 hour
const MAX_CIPHERTEXT_BYTES = 8192;

const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};

// Strict CSP. We pull canonical Marbl assets (CSS, fonts, GSAP, marbl-core.js)
// from marbl.codes itself - this matches the Atlas pattern. Fathom CDN allowed for analytics.
const CSP = [
  "default-src 'self'",
  "script-src 'self' https://marbl.codes https://cdn.usefathom.com",
  "style-src 'self' 'unsafe-inline' https://marbl.codes",
  "font-src 'self' https://marbl.codes data:",
  "img-src 'self' data: https://marbl.codes",
  "connect-src 'self' https://*.usefathom.com",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "base-uri 'self'",
  "object-src 'none'",
].join('; ');

function applyHeaders(response: Response, extras?: Record<string, string>): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) headers.set(k, v);
  headers.set('Content-Security-Policy', CSP);
  if (extras) for (const [k, v] of Object.entries(extras)) headers.set(k, v);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function generateId(): string {
  // 12 random bytes -> 16 chars base64url -> 96 bits entropy
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function isValidId(id: string): boolean {
  return /^[A-Za-z0-9_-]{16}$/.test(id);
}

async function handleStore(request: Request, env: Env): Promise<Response> {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const limited = await env.RATE_LIMIT_STORE.limit({ key: ip });
  if (!limited.success) {
    return jsonResponse({ error: 'rate_limited' }, 429);
  }

  let body: { ciphertext?: unknown; iv?: unknown };
  try {
    body = (await request.json()) as { ciphertext?: unknown; iv?: unknown };
  } catch {
    return jsonResponse({ error: 'invalid_json' }, 400);
  }

  if (typeof body.ciphertext !== 'string' || typeof body.iv !== 'string') {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }
  if (body.ciphertext.length === 0 || body.iv.length === 0) {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }
  if (body.ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    return jsonResponse({ error: 'too_large' }, 413);
  }

  const id = generateId();
  await env.VAULTED.put(
    id,
    JSON.stringify({ c: body.ciphertext, i: body.iv }),
    { expirationTtl: TTL_SECONDS },
  );

  return jsonResponse({ id });
}

async function handleReveal(id: string, request: Request, env: Env): Promise<Response> {
  if (!isValidId(id)) {
    return jsonResponse({ error: 'invalid_id' }, 400);
  }

  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const limited = await env.RATE_LIMIT_READ.limit({ key: ip });
  if (!limited.success) {
    return jsonResponse({ error: 'rate_limited' }, 429);
  }

  // Atomic destructive read: get + delete before returning ciphertext.
  // The KV delete may not propagate globally for ~60s, but the entry is
  // unreachable from this PoP immediately, and the GCM auth tag means
  // any in-flight cached read still requires the URL fragment key to decrypt.
  const stored = await env.VAULTED.get(id);
  if (stored === null) {
    return jsonResponse({ error: 'not_found' }, 404);
  }
  await env.VAULTED.delete(id);

  return new Response(stored, {
    status: 200,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // API routes
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

    // Recipient page: serve static v.html ONLY for /v/{valid-id}.
    // Bare /v or /v/ has no secret to reveal - redirect home so users get a
    // clear page instead of a confusing reveal flow that can't succeed.
    if (path === '/v' || path === '/v/') {
      return Response.redirect(new URL('/', url).toString(), 302);
    }
    if (path.startsWith('/v/')) {
      const id = path.slice('/v/'.length);
      if (!isValidId(id)) {
        return Response.redirect(new URL('/', url).toString(), 302);
      }
      const vRequest = new Request(new URL('/v.html', url), request);
      const response = await env.ASSETS.fetch(vRequest);
      return applyHeaders(response, { 'X-Robots-Tag': 'noindex, nofollow' });
    }

    // About page route alias (so /about works as well as /about.html).
    if (path === '/about') {
      const aboutRequest = new Request(new URL('/about.html', url), request);
      const response = await env.ASSETS.fetch(aboutRequest);
      return applyHeaders(response);
    }

    // Static assets: index.html, app.js, llms.txt, robots.txt, sitemap.xml, etc.
    const response = await env.ASSETS.fetch(request);
    return applyHeaders(response);
  },
};
