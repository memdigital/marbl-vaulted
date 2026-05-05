# Marbl Vaulted

Free one-time encrypted secret share tool. Live at [vaulted.marbl.codes](https://vaulted.marbl.codes).

End-to-end encrypted in the browser via AES-GCM-256. The server only ever sees ciphertext. Decryption key travels in the URL fragment (never reaches the server). Single-use - reveal triggers an atomic destructive read.

## Stack

- Cloudflare Worker + Static Assets binding
- Cloudflare KV for ciphertext storage (1-hour TTL)
- Cloudflare Native Rate Limiting (per-IP)
- Vanilla HTML/CSS/JS (no framework, no client deps)
- Web Crypto API for AES-GCM-256
- Canonical Marbl chrome from [marbl.codes](https://marbl.codes)
- Fathom Analytics (page-level, privacy-friendly)

## Routes

| Path | Purpose |
|------|---------|
| `GET /` | Sender page (paste secret, get URL) |
| `GET /v/:id` | Recipient page (reveal once, destroy) |
| `GET /about` | About page |
| `POST /api/store` | Store ciphertext, return id |
| `POST /api/reveal/:id` | Atomic get-and-delete ciphertext |

## Security headers

- HSTS, X-Content-Type-Options, X-Frame-Options DENY, Referrer-Policy, Permissions-Policy
- Strict CSP allowing self + marbl.codes + Fathom CDN
- `X-Robots-Tag: noindex, nofollow` on `/v/:id` recipient pages

## Local dev

```bash
npm install
npx wrangler kv namespace create VAULTED
# paste returned id into wrangler.jsonc
npx wrangler dev
```

## Deploy

GitHub-first. Push to `main` -> Cloudflare Workers Builds picks up the commit and deploys. No manual `wrangler deploy` in normal operation.

## Architecture notes

- Random 96-bit ID per secret, base64url-encoded (16 chars).
- Server stores `{ c: ciphertext, i: iv }` only.
- Reveal is atomic: get + delete in the same handler before returning ciphertext.
- KV delete may take ~60s to propagate globally, but the entry is unreachable from the originating PoP immediately, and the GCM auth tag means any in-flight cached read still requires the URL fragment key to decrypt.
- Maximum ciphertext: 8KiB at the worker boundary. Maximum plaintext: 4,000 characters at the UI.

## Built by

[Marbl Codes](https://marbl.codes) - Richard Bland and Serene [AI] running on Claude Opus 4.7.

Co-Authored-By: Serene [AI] running on Claude Opus 4.7
