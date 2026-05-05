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
// Max base64url length of stored ciphertext. Client caps plaintext at 4000
// chars; worst-case UTF-8 expansion = 4 bytes/char = 16000 bytes; AES-GCM adds
// a 16-byte auth tag; base64url expansion = ceil(N*4/3) ≈ 21356 chars. Round
// up to 24000 with headroom so unicode-heavy 4000-char inputs don't get
// rejected after client-side encryption work.
const MAX_CIPHERTEXT_B64_CHARS = 24000;

const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  // Privacy-first: opt out of every permission-gated API we don't use,
  // including modern privacy-relevant ones (FLoC/Topics, attribution-reporting).
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

// CSRF defence: reject any POST whose Origin header doesn't match our app
// origin. Without this, a malicious page could trigger /api/reveal/{id} via
// no-cors fetch - the response is opaque to the attacker, but the burn still
// happens, denying the legitimate user. Rejected BEFORE rate-limit so cross-
// origin attempts don't drain a real user's bucket.
function requireSameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin');
  return origin === APP_ORIGIN;
}

// Shape validators for stored payload. AES-GCM IV is 12 bytes = 16 base64url
// chars without padding. Ciphertext must be base64url too.
const B64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const IV_B64_LENGTH = 16;

async function handleStore(request: Request, env: Env): Promise<Response> {
  if (!requireSameOrigin(request)) {
    return jsonResponse({ error: 'forbidden' }, 403);
  }
  // Reject if Cloudflare didn't supply the IP - belt-and-braces against an
  // edge misconfiguration where every request would share the 'unknown' bucket.
  const ip = request.headers.get('cf-connecting-ip');
  if (!ip) {
    return jsonResponse({ error: 'forbidden' }, 403);
  }

  // Reject oversized bodies BEFORE parsing JSON (cheap server protection).
  // Rough budget: max ciphertext + iv + JSON wrapper overhead ≈ 25KB worst case.
  const contentLength = request.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > 32 * 1024) {
    return jsonResponse({ error: 'too_large' }, 413);
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
  // Charset + length checks: base64url charset, IV is exactly 16 chars (12B),
  // ciphertext is non-empty and within budget.
  if (!B64URL_PATTERN.test(body.ciphertext) || !B64URL_PATTERN.test(body.iv)) {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }
  if (body.iv.length !== IV_B64_LENGTH) {
    return jsonResponse({ error: 'invalid_payload' }, 400);
  }
  if (body.ciphertext.length === 0) {
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

  // CSRF burn defence - cross-origin reveal calls would burn a legitimate
  // user's secret without yielding plaintext to the attacker (opaque fetch).
  // Reject BEFORE rate-limit so it doesn't drain the bucket.
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
// Fathom proxy: served on /index.html and /about.html only. NEVER on /v/*
// (recipient page). Path is allowlisted - the proxy is NOT a generic forward
// to cdn.usefathom.com. Only requests for the script itself and the bare-root
// tracker pixel (sent as GET with query params for pageview/event) are served.
const FATHOM_ALLOWED_METHODS = new Set(['GET']);

async function handleFathomProxy(request: Request, url: URL, path: string): Promise<Response> {
  if (!FATHOM_ALLOWED_METHODS.has(request.method)) {
    return applyHeaders(new Response('Method not allowed', { status: 405 }));
  }

  const upstreamPath = path.slice('/fathom-proxy/'.length);
  // Reject any path traversal or unexpected characters. Only known endpoints:
  //   - script.js (the tracker library)
  //   - "" (the bare root - tracker pixel events arrive as GET / with query)
  if (upstreamPath !== 'script.js' && upstreamPath !== '') {
    return applyHeaders(new Response('Not found', { status: 404 }));
  }

  const upstreamUrl = `https://cdn.usefathom.com/${upstreamPath}${url.search}`;
  // redirect: 'manual' so an upstream redirect can't escape the allowlist.
  const upstream = await fetch(upstreamUrl, {
    method: 'GET',
    redirect: 'manual',
    headers: { 'User-Agent': request.headers.get('user-agent') || 'Mozilla/5.0' },
  });

  if (upstream.status >= 300 && upstream.status < 400) {
    console.warn('[fathom-proxy] upstream tried to redirect, refusing', upstream.status);
    return applyHeaders(new Response('Not found', { status: 404 }));
  }

  if (upstreamPath === 'script.js') {
    // Rewrite the script so its tracker URL points back through our proxy.
    // Fathom's script self-detects: when not loaded from cdn.usefathom.com,
    // it sets trackerUrl = "https://" + script-src-hostname + "/".
    // We patch that to "/fathom-proxy/" so tracking pixels stay same-origin.
    // BRITTLE: depends on Fathom's exact minified output. If they ship a
    // new build that changes this token, the replace silently no-ops, the
    // script keeps trying to POST to cdn.usefathom.com directly, and CSP
    // connect-src 'self' blocks it - making the failure visible. We also
    // log here so the failure is surfaceable in logs not just user reports.
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

  // Tracker pixel - pass through with no-store and explicit content type.
  const ct = upstream.headers.get('content-type') || 'application/octet-stream';
  return applyHeaders(new Response(upstream.body, {
    status: upstream.status,
    headers: {
      'Content-Type': ct,
      'Cache-Control': 'no-store',
    },
  }));
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
    // The recipient HTML itself loads NO analytics (see v.html comment).
    if (path === '/v' || path === '/v/') {
      return Response.redirect(new URL('/', url).toString(), 302);
    }
    if (path.startsWith('/v/')) {
      const id = path.slice('/v/'.length);
      if (!isValidId(id)) {
        return Response.redirect(new URL('/', url).toString(), 302);
      }
      // Fetch the extension-less canonical URL the Static Assets binding
      // resolves to v.html. Calling /v.html would trigger the binding's
      // auto-trailing-slash 307 to /v, which the browser would follow,
      // stripping the id segment from the URL and breaking the recipient
      // flow. /v gets the file content without the redirect.
      const vRequest = new Request(new URL('/v', url), request);
      const response = await env.ASSETS.fetch(vRequest);
      return applyHeaders(
        response,
        { 'X-Robots-Tag': 'noindex, nofollow', ...NO_STORE_HEADERS },
      );
    }

    // About page route alias (so /about works as well as /about.html).
    if (path === '/about') {
      // Same reasoning as /v: fetch the extension-less URL.
      const aboutRequest = new Request(new URL('/about', url), request);
      const response = await env.ASSETS.fetch(aboutRequest);
      return applyHeaders(response);
    }

    // Static assets: index.html, app.js, llms.txt, robots.txt, sitemap.xml, etc.
    const response = await env.ASSETS.fetch(request);
    return applyHeaders(response);
  },
};
