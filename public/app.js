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

  const b64decode = (str) => {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };

  const flashCopy = (btn, label) => {
    if (!btn) return;
    const original = btn.dataset.originalText || btn.textContent;
    btn.dataset.originalText = original;
    btn.textContent = label || 'Copied!';
    btn.classList.add('btn--copied');
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

        const res = await fetch('/api/store', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ciphertext: b64encode(new Uint8Array(ciphertext)),
            iv: b64encode(iv),
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
        const url = `${window.location.origin}/v/${id}#k=${keyB64}`;

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
  const initRecipient = () => {
    const revealStage = $('reveal-stage');
    const secretStage = $('secret-stage');
    const successStage = $('success-stage');
    const errorStage = $('error-stage');
    const revealBtn = $('reveal-btn');
    const copySecretBtn = $('copy-secret-btn');
    const confirmBtn = $('confirm-btn');
    const secretText = $('secret-text');

    if (!revealBtn) return;

    const id = window.location.pathname.split('/').filter(Boolean).pop() || '';
    const fragment = window.location.hash.slice(1);
    const params = new URLSearchParams(fragment);
    const keyB64 = params.get('k');

    if (!id || !keyB64) {
      hide(revealStage);
      showError(errorStage, "This link is incomplete. Ask the sender to send a fresh one.");
      return;
    }

    revealBtn.addEventListener('click', async () => {
      revealBtn.disabled = true;
      revealBtn.textContent = 'Revealing...';
      fathom('reveal-clicked');

      try {
        const res = await fetch(`/api/reveal/${encodeURIComponent(id)}`, { method: 'POST' });
        if (res.status === 404) {
          throw new Error('This secret has already been revealed or has expired.');
        }
        if (res.status === 429) {
          throw new Error('Too many requests. Wait a moment and try again.');
        }
        if (!res.ok) {
          throw new Error('Could not retrieve the secret. Please try again.');
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

        // Strip fragment from URL so the key doesn't persist in browser history / sync.
        try { history.replaceState(null, '', window.location.pathname); } catch (_) { /* ignore */ }

        // Move focus to the secret block so screen readers can read it.
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
    if (document.body.dataset.page === 'recipient') {
      initRecipient();
    } else if (document.body.dataset.page === 'sender') {
      initSender();
    }
  });
})();
