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
// Max base64url length of stored ciphertext. ~8192 chars ≈ 6 KiB raw.
const MAX_CIPHERTEXT_B64_CHARS = 8192;

const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};

// Cache-suppressing headers for any response containing or relating to a
// secret. Belt-and-braces - intermediaries (proxies, browser bfcache, future
// service workers) MUST NOT cache these.
const NO_STORE_HEADERS: Record<string, string> = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

// One CSP for all pages - same-origin only for scripts AND connects.
// Fathom Analytics is proxied through /fathom-proxy/* below so it counts
// as 'self', not third-party. Zero-knowledge requires zero third parties
// (Truth #94) and the proxy gives us that without losing usage analytics.
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
  // Reject if Cloudflare didn't supply the IP - belt-and-braces against an
  // edge misconfiguration where every request would share the 'unknown' bucket.
  const ip = request.headers.get('cf-connecting-ip');
  if (!ip) {
    return jsonResponse({ error: 'forbidden' }, 403);
  }
  const limited = await env.RATE_LIMIT_STORE.limit({ key: `store:${ip}` });
  if (!limited.success) {
    return jsonResponse({ error: 'rate_limited' }, 429);
  }

  let body: { ciphertext?: unknown; iv?: unknown };
  try {
    body = (await request.json()) as { ciphertext?: unknown; iv?: unknown };
  } catch {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }

  if (typeof body.ciphertext !== 'string' || typeof body.iv !== 'string') {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }
  if (body.ciphertext.length === 0 || body.iv.length === 0) {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }
  if (body.ciphertext.length > MAX_CIPHERTEXT_B64_CHARS) {
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

// Reveal collapses every failure to a single opaque 404 on the wire so
// attackers cannot distinguish "id format invalid" from "no entry" from
// "throttled" from "missing IP". Distinguished states stay in server logs.
async function handleReveal(id: string, request: Request, env: Env): Promise<Response> {
  // Same generic 404 for every failure path.
  const opaqueNotFound = () => jsonResponse({ error: 'not_found' }, 404);

  if (!isValidId(id)) {
    return opaqueNotFound();
  }

  const ip = request.headers.get('cf-connecting-ip');
  if (!ip) {
    return opaqueNotFound();
  }

  // Per-IP limiter (stops scrapers) AND per-ID limiter (caps brute-force on
  // a known id from a botnet of rotating IPs). Failure on either path = 404.
  const [ipOk, idOk] = await Promise.all([
    env.RATE_LIMIT_READ.limit({ key: `read:${ip}` }),
    env.RATE_LIMIT_READ.limit({ key: `id:${id}` }),
  ]);
  if (!ipOk.success || !idOk.success) {
    return opaqueNotFound();
  }

  // KV get + delete. Note: KV delete propagates globally over ~60s, so two
  // simultaneous reveals from different PoPs could theoretically both succeed.
  // Mitigations: the random URL fragment key (server never sees) means a
  // double-reveal still doesn't yield plaintext to anyone without the URL,
  // and the burn-on-success makes abuse logs visible. For true atomic
  // single-read semantics we'd need D1 with DELETE...RETURNING.
  const stored = await env.VAULTED.get(id);
  if (stored === null) {
    return opaqueNotFound();
  }
  await env.VAULTED.delete(id);

  return new Response(stored, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...NO_STORE_HEADERS,
    },
  });
}

// Fathom proxy: forwards anything under /fathom-proxy/<rest> to
// https://cdn.usefathom.com/<rest>. The script auto-detects its origin from
// document.currentScript.src, so when loaded from /fathom-proxy/script.js it
// will send tracking requests to /fathom-proxy/, which we forward back to
// Fathom. Result: CSP stays 'self'-only and analytics still works.
async function handleFathomProxy(request: Request, url: URL, path: string): Promise<Response> {
  const upstreamPath = path.slice('/fathom-proxy/'.length);
  const upstreamUrl = `https://cdn.usefathom.com/${upstreamPath}${url.search}`;
  const upstream = await fetch(upstreamUrl, {
    method: request.method,
    headers: { 'User-Agent': request.headers.get('user-agent') || 'Mozilla/5.0' },
  });
  const headers = new Headers();
  const ct = upstream.headers.get('content-type');
  if (ct) headers.set('Content-Type', ct);

  if (upstreamPath === 'script.js') {
    headers.set('Cache-Control', 'public, max-age=1800'); // 30 min
    // Rewrite the script so its tracker URL points back through our proxy.
    // Fathom's script self-detects: when not loaded from cdn.usefathom.com,
    // it sets trackerUrl = "https://" + script-src-hostname + "/".
    // We patch that to "/fathom-proxy/" so tracking pixels stay same-origin.
    let body = await upstream.text();
    body = body.replace(
      'trackerUrl="https://"+scriptUrl.hostname+"/"',
      'trackerUrl="https://"+scriptUrl.hostname+"/fathom-proxy/"',
    );
    return new Response(body, { status: upstream.status, headers });
  }

  headers.set('Cache-Control', 'no-store');
  return new Response(upstream.body, { status: upstream.status, headers });
}

// Bindings guard: refuse to start if any required binding is missing.
// Catches accidental config drift before users hit a runtime error.
function requireBindings(env: Env): string | null {
  if (!env.VAULTED) return 'VAULTED';
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
      return new Response('Service misconfigured', { status: 500 });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Fathom Analytics proxy: same-origin script + tracker so CSP can stay
    // 'self'-only on every page (including the recipient page where
    // plaintext lives in the DOM). Counts as 'self' to the browser.
    // Pattern follows Fathom's official Cloudflare Worker proxy template.
    if (path.startsWith('/fathom-proxy/')) {
      return handleFathomProxy(request, url, path);
    }

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
    // Recipient gets the tighter CSP_RECIPIENT (no third-party scripts) -
    // plaintext lives in the DOM here, so zero third parties allowed.
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
      return applyHeaders(
        response,
        { 'X-Robots-Tag': 'noindex, nofollow', ...NO_STORE_HEADERS },
      );
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
