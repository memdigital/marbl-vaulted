# Vaulted - One-Time Encrypted Password Share

**Domain:** vaulted.marbl.codes
**Repo:** Projects/Internal/vaulted/
**Date:** 2026-05-05
**Drafter:** Serene (CTO)
**Scope:** Same-day MVP. Richard needs to use it tonight.

---

## What it is

Tool for sharing a secret (password, API key, anything sensitive) with someone via a one-time URL. Recipient reveals the secret once, copies it, confirms, and the server entry is destroyed.

## User flow

**Sender** (Richard):
1. Open vaulted.marbl.codes
2. Enter secret in textarea
3. Click "Vault it"
4. Frontend generates a key, encrypts secret client-side, POSTs ciphertext to API
5. API returns short ID, frontend builds URL: `vaulted.marbl.codes/v/<id>#k=<key>`
6. URL displayed with click-to-copy button
7. Click to copy, confirm copied
8. Paste URL into email, send

**Recipient:**
1. Click URL
2. Sees branded page: "We've got a secret for you, shhhh!"
3. Click "Reveal it"
4. Frontend fetches ciphertext, decrypts client-side using key from URL fragment
5. Secret displayed with click-to-copy button
6. Click to copy, sees confirmation
7. Click "I've got it - destroy it"
8. Server-side DELETE of the entry, success page: "Gone for good"

---

## Architecture

**Single Cloudflare Worker** + **KV namespace** + **custom domain**. No Pages, no D1, no separate frontend repo. Worker serves both static HTML and API.

**Routes:**
- `GET /` - sender page (HTML)
- `GET /v/:id` - recipient page (HTML)
- `POST /api/store` - body = `{ ciphertext, iv }`, returns `{ id }`. Key NEVER sent.
- `GET /api/get/:id` - returns `{ ciphertext, iv }` if present, 404 if not
- `DELETE /api/destroy/:id` - removes KV entry

**KV storage:**
- Key: random 16-char base64url id
- Value: JSON `{ ciphertext: base64, iv: base64 }`
- TTL: 24h (KV `expirationTtl`)
- Single-use: explicit DELETE on confirmation

**Crypto:**
- Algorithm: AES-GCM 256-bit
- Key: client-side `crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 })`, exported and base64url-encoded into URL fragment
- IV: 12 random bytes, sent with ciphertext to server
- Server NEVER sees the key (URL fragment, `window.location.hash`, never sent in HTTP requests)

---

## Security model

**Threat: server compromise.** Attacker reads KV blob. Cannot decrypt - key is in URL fragment which never reached the server.

**Threat: shoulder surfing during sharing.** Mitigated by single-use - if attacker glimpses URL and visits it, the secret is destroyed before legitimate recipient arrives. Recipient's failure to find a working link IS a signal of compromise.

**Threat: man-in-the-middle.** HTTPS via Cloudflare. Out of scope: anything below TLS.

**Threat: brute-force the ID.** 16-char base64url = ~96 bits entropy. Effectively unguessable.

**Threat: replay.** Server-side single-DELETE on confirmation prevents accidental re-share. Even before confirmation, the URL fragment must be intact - attacker with only the URL path cannot decrypt.

**Threat: malicious sender embedding tracking.** Out of scope - sender is trusted.

**Threat: log leakage.** Server only sees ciphertext + IV + ID. NEVER the plaintext or the key. Logs are safe.

**Rate limiting:** simple per-IP via KV - max 20 stores per hour, max 50 reads per hour. Prevents abuse without being annoying for a one-off use.

**CSP:** strict, self-hosted assets only. No inline scripts (use external `app.js` or use nonce). For MVP simplicity - inline script with `'unsafe-inline'` and tight CSP otherwise. Trade-off documented.

---

## Brand surface

Marbl Brand Kit canonical tokens:
- Charcoal `#171415` background, deep-charcoal `#0d0b0c` for surfaces
- Ember `#F35226` primary CTA
- Inter for body, Urbanist for headings, Petrona italic for accent
- 10/20/40 spacing scale, default radius 10px
- Buttons follow ui-items canonical patterns (fill-up primary, outline secondary)
- "shhhh!" headline uses Urbanist + Petrona "shhhh!" italic accent
- Marbl logomark in header, link to marbl.codes

---

## Click-to-copy implementation (MUST be bulletproof)

**Primary:** `navigator.clipboard.writeText()` - HTTPS + user-gesture required. The click handler MUST call writeText synchronously inside the click event - no async chains that break the gesture.

**Fallback:** `document.execCommand('copy')` via temporarily-injected textarea. Still works on older browsers.

**Confirmation UI:** button changes to "Copied!" with green tick icon for 2 seconds, then resets. ALWAYS visible feedback - never silent.

**Test plan:**
- Chrome desktop: writeText path
- Safari iOS: writeText path (works on Safari 13.1+)
- Firefox: writeText path
- Older Edge: execCommand fallback

Specifically test the recipient flow on iOS - that's the highest-failure-rate platform for clipboard ops.

---

## Out of scope (MVP)

- User accounts / auth
- Custom expiry settings (fixed 24h TTL)
- Passphrase on top of fragment key (single-layer encryption only)
- Audit notification webhook ("your secret was viewed")
- File attachments
- Read-receipt
- Multi-recipient
- Branding for other accounts (Marbl-only)

These are all add-on candidates if Richard wants to extend post-MVP.

---

## Build order

1. Create `Projects/Internal/vaulted/` with `wrangler.jsonc`, `src/index.ts`, `package.json`
2. Update `Marbl/ecosystem/canonical-urls.md` with `vaulted.marbl.codes`
3. Create KV namespace via wrangler (`npx wrangler kv namespace create VAULTED_KV`)
4. Write Worker code (TypeScript, single file): inline HTML, API routes, KV ops, rate limit
5. Local test via `wrangler dev`
6. Deploy to Cloudflare via `wrangler deploy`
7. DNS: add CNAME or custom domain route for `vaulted.marbl.codes`
8. End-to-end test: sender flow on Hearth, recipient flow on phone
9. llms.txt + robots.txt added (lightweight)

**Time estimate:** 90-120 min focused. Most of that is test + deploy + DNS.

---

## Open questions

1. Default TTL: 24h reasonable, or shorter for MVP (1h)?
2. After "destroy", should the success page link back to vaulted.marbl.codes/ for sharing another, or be a dead-end?
3. Marbl footer with logomark or fully minimal page?
4. Email a launch note to anyone, or silent ship?

---

## Success criteria

- Sender can paste URL into Gmail and email it to themselves, click the link on phone, reveal + copy + destroy. End-to-end works.
- Click-to-copy works on Chrome desktop and Safari iOS.
- Server logs never contain plaintext or key.
- 24h TTL fires correctly (verify by setting TTL to 60s in test mode).
- Rate limit kicks in after threshold.
- Page passes Lighthouse 90+ on Performance, Accessibility, Best Practices, SEO.
