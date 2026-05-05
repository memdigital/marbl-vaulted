/* eslint-env browser */
/* Marbl Vaulted - client-side AES-GCM-256 + clipboard handling.
   No external libraries. Web Crypto only. */
(() => {
  'use strict';

  const fathom = (event) => {
    if (typeof window.fathom !== 'undefined' && typeof window.fathom.trackEvent === 'function') {
      try { window.fathom.trackEvent(event); } catch (_) { /* ignore */ }
    }
  };

  const $ = (id) => document.getElementById(id);

  const showError = (el, msg) => {
    if (!el) return;
    el.hidden = false;
    el.textContent = msg;
  };

  const hide = (el) => { if (el) el.hidden = true; };
  const show = (el) => { if (el) el.hidden = false; };

  const b64encode = (bytes) => {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  // SHA-256 of an input string -> base64url. Used to hash the verifier
  // client-side so the server stores only the hash, not the verifier itself.
  const sha256B64Url = async (input) => {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return b64encode(new Uint8Array(buf));
  };

  const b64decode = (str) => {
    // Correct padding: append (4 - len%4) % 4 equals signs.
    // The previous formula '==='.slice((str.length+3)%4) silently appended
    // a stray '=' on length-multiple-of-4 inputs, breaking IV decode.
    const padding = '='.repeat((4 - (str.length % 4)) % 4);
    const padded = str.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };

  // Visually-hidden live region for AT announcements. Created once at boot
  // (NVDA in particular needs aria-live regions present in the DOM at page
  // load to register them - lazy creation on first use can miss).
  const ensureLiveRegion = () => {
    let region = document.getElementById('a11y-live');
    if (region) return region;
    region = document.createElement('div');
    region.id = 'a11y-live';
    region.setAttribute('role', 'status');
    region.setAttribute('aria-live', 'polite');
    region.setAttribute('aria-atomic', 'true');
    region.style.cssText = 'position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden;';
    document.body.appendChild(region);
    return region;
  };
  const announceLive = (msg) => {
    const region = ensureLiveRegion();
    // Re-empty then set so AT re-announces even on repeat.
    region.textContent = '';
    setTimeout(() => { region.textContent = msg; }, 50);
  };

  const flashCopy = (btn, label) => {
    if (!btn) return;
    const original = btn.dataset.originalText || btn.textContent;
    btn.dataset.originalText = original;
    btn.textContent = label || 'Copied!';
    btn.classList.add('btn--copied');
    announceLive(label || 'Copied to clipboard');
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove('btn--copied');
    }, 2000);
  };

  // Click-to-copy. MUST be called synchronously inside a click handler so the user-gesture
  // requirement on navigator.clipboard.writeText is satisfied.
  const copyToClipboard = async (text, btn) => {
    // Try the modern clipboard API first.
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        flashCopy(btn);
        return true;
      } catch (_) { /* fall through */ }
    }
    // Fallback: temporary textarea + execCommand('copy').
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.top = '0';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, text.length);
      const ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) {
        flashCopy(btn);
        return true;
      }
    } catch (_) { /* ignore */ }
    if (btn) {
      btn.textContent = 'Copy failed - select manually';
    }
    announceLive('Copy failed. Select the text manually.');
    return false;
  };

  // === Sender flow ===
  const initSender = () => {
    const formStage = $('form-stage');
    const resultStage = $('result-stage');
    const errorStage = $('error-stage');
    const secretInput = $('secret');
    const vaultBtn = $('vault-btn');
    const copyBtn = $('copy-btn');
    const resetBtn = $('reset-btn');
    const resultUrl = $('result-url');

    if (!vaultBtn) return;

    vaultBtn.addEventListener('click', async () => {
      const secret = secretInput.value;
      if (!secret) {
        showError(errorStage, 'Please enter a secret to vault.');
        return;
      }
      if (secret.length > 4000) {
        showError(errorStage, 'Secret is too long. Max 4000 characters.');
        return;
      }
      hide(errorStage);
      vaultBtn.disabled = true;
      vaultBtn.textContent = 'Encrypting...';
      fathom('vault-it-clicked');

      try {
        const key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt'],
        );
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(secret);
        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          encoded,
        );
        const exportedKey = await crypto.subtle.exportKey('raw', key);

        // Verifier: 16 random bytes the recipient will present to prove
        // knowledge of the URL fragment before the server burns the entry.
        // The server stores only its SHA-256 hash, not the verifier itself.
        const verifierBytes = crypto.getRandomValues(new Uint8Array(16));
        const verifierB64 = b64encode(verifierBytes);
        const verifierHash = await sha256B64Url(verifierB64);

        const res = await fetch('/api/store', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ciphertext: b64encode(new Uint8Array(ciphertext)),
            iv: b64encode(iv),
            verifierHash,
          }),
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          if (data.error === 'rate_limited') {
            throw new Error('Too many requests. Wait a moment and try again.');
          }
          if (data.error === 'too_large') {
            throw new Error('Secret too large. Max 4000 characters.');
          }
          throw new Error('Could not vault the secret. Please try again.');
        }
        const { id } = await res.json();
        const keyB64 = b64encode(new Uint8Array(exportedKey));
        // Both key (for decryption) AND verifier (for proof-of-knowledge)
        // travel in the URL fragment. Neither reaches the server via the URL.
        const url = `${window.location.origin}/v/${id}#k=${keyB64}&v=${verifierB64}`;

        resultUrl.textContent = url;
        hide(formStage);
        show(resultStage);
        fathom('vault-it-success');

        // Wipe the input.
        secretInput.value = '';
      } catch (err) {
        showError(errorStage, (err && err.message) ? err.message : 'Something went wrong.');
        fathom('vault-it-error');
      } finally {
        vaultBtn.disabled = false;
        vaultBtn.textContent = 'Vault it';
      }
    });

    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        const ok = await copyToClipboard(resultUrl.textContent, copyBtn);
        if (ok) fathom('copy-url-clicked');
      });
    }

    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        hide(resultStage);
        hide(errorStage);
        show(formStage);
        resultUrl.textContent = '';
        secretInput.value = '';
        secretInput.focus();
        fathom('reset-clicked');
      });
    }
  };

  // === Recipient flow ===
  // CRITICAL: reveal MUST require an explicit user gesture (button click).
  // DO NOT auto-fire fetch('/api/reveal/...') on page load - email scanners
  // and link-preview bots will burn the secret before the recipient sees it.
  const initRecipient = () => {
    const revealStage = $('reveal-stage');
    const secretStage = $('secret-stage');
    const successStage = $('success-stage');
    const errorStage = $('error-stage');
    const revealBtn = $('reveal-btn');
    const copySecretBtn = $('copy-secret-btn');
    const confirmBtn = $('confirm-btn');
    const secretText = $('secret-text');
    const copyStatus = $('copy-status');

    if (!revealBtn) return;

    const pathParts = window.location.pathname.split('/').filter(Boolean);
    // Path is /v/{id} - id must be the segment after "v" (16-char base64url).
    const id = (pathParts[0] === 'v' && pathParts.length >= 2) ? pathParts[1] : '';
    const fragment = window.location.hash.slice(1);
    const params = new URLSearchParams(fragment);
    const keyB64 = params.get('k');
    const verifierB64 = params.get('v');

    // Capture the key into a closure variable, then strip the fragment from
    // the URL IMMEDIATELY (not on success). Eliminates the error-path leak
    // where a failed decrypt left the AES key persisted in browser history.
    // Preserve query string in case future UTM-tagged share links arrive.
    // FAIL CLOSED: if replaceState throws (sandboxed iframe, extension
    // context), the key would persist in the URL bar. Refuse to proceed -
    // the security model relies on the fragment being stripped.
    try {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    } catch (e) {
      console.error('[vaulted] history.replaceState failed; refusing to proceed', e);
      hide(revealStage);
      showError(errorStage, "Your browser blocked a security step. Refresh the page or open the link in a different browser.");
      return;
    }

    // Validate id, AES key, AND verifier client-side BEFORE reveal can fire.
    // Server requires the verifier to authorise destructive read - a malformed
    // verifier means the server will return 404, the secret stays alive.
    // 256-bit AES key = 43 base64url chars. 16-byte verifier = 22 base64url chars.
    const ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;
    const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
    const VERIFIER_PATTERN = /^[A-Za-z0-9_-]{22}$/;
    if (
      !id || !ID_PATTERN.test(id) ||
      !keyB64 || !KEY_PATTERN.test(keyB64) ||
      !verifierB64 || !VERIFIER_PATTERN.test(verifierB64)
    ) {
      hide(revealStage);
      showError(errorStage, "This link is incomplete. Ask the sender to send a fresh one.");
      return;
    }

    revealBtn.addEventListener('click', async () => {
      revealBtn.disabled = true;
      revealBtn.textContent = 'Revealing...';
      fathom('reveal-clicked');

      try {
        const res = await fetch(`/api/reveal/${encodeURIComponent(id)}`, {
          method: 'POST',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verifier: verifierB64 }),
        });
        // Server returns generic 404 for every failure (not_found, invalid_id,
        // rate_limited, missing IP) so attackers can't enumerate state.
        // We surface the most likely human cause to the user.
        if (!res.ok) {
          throw new Error('This secret has already been revealed, expired, or the link is malformed.');
        }

        const stored = await res.json();
        const ciphertext = b64decode(stored.c);
        const iv = b64decode(stored.i);
        const keyBytes = b64decode(keyB64);

        const cryptoKey = await crypto.subtle.importKey(
          'raw',
          keyBytes,
          { name: 'AES-GCM' },
          false,
          ['decrypt'],
        );
        const decrypted = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          cryptoKey,
          ciphertext,
        );
        const plaintext = new TextDecoder().decode(decrypted);

        secretText.textContent = plaintext;
        hide(revealStage);
        show(secretStage);

        // Move focus to the secret block so screen readers announce it.
        // <pre> needs tabindex="-1" in v.html for .focus() to actually work.
        secretText.focus();

        fathom('reveal-success');
      } catch (err) {
        hide(revealStage);
        showError(errorStage, (err && err.message) ? err.message : 'Could not reveal the secret. The link may be corrupt or already used.');
        fathom('reveal-error');
      }
    });

    if (copySecretBtn) {
      copySecretBtn.addEventListener('click', async () => {
        const ok = await copyToClipboard(secretText.textContent, copySecretBtn);
        if (ok) fathom('copy-secret-clicked');
      });
    }

    if (confirmBtn) {
      confirmBtn.addEventListener('click', () => {
        // Wipe the in-DOM copy of the secret. The server-side entry was already destroyed at reveal time.
        if (secretText) secretText.textContent = '';
        hide(secretStage);
        show(successStage);
        fathom('confirm-clicked');
      });
    }
  };

  // Boot
  document.addEventListener('DOMContentLoaded', () => {
    // Create the AT live region at page load so screen readers register it
    // before any flashCopy / announceLive call.
    ensureLiveRegion();
    if (document.body.dataset.page === 'recipient') {
      initRecipient();
    } else if (document.body.dataset.page === 'sender') {
      initSender();
    }
  });
})();
