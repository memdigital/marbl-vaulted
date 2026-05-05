/* eslint-env browser */
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

  const sha256B64Url = async (input) => {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
    return b64encode(new Uint8Array(buf));
  };

  const b64decode = (str) => {
    const padding = '='.repeat((4 - (str.length % 4)) % 4);
    const padded = str.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };

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

  const copyToClipboard = async (text, btn) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        flashCopy(btn);
        return true;
      } catch (_) { /* fall through */ }
    }
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
        const url = `${window.location.origin}/v/${id}#k=${keyB64}&v=${verifierB64}`;

        resultUrl.textContent = url;
        hide(formStage);
        show(resultStage);
        fathom('vault-it-success');

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

    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const id = (pathParts[0] === 'v' && pathParts.length >= 2) ? pathParts[1] : '';
    const fragment = window.location.hash.slice(1);
    const params = new URLSearchParams(fragment);
    const keyB64 = params.get('k');
    const verifierB64 = params.get('v');

    try {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    } catch (e) {
      hide(revealStage);
      showError(errorStage, "Your browser blocked a step. Open the link in a different browser.");
      return;
    }

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
        if (secretText) secretText.textContent = '';
        hide(secretStage);
        show(successStage);
        fathom('confirm-clicked');
      });
    }
  };

  document.addEventListener('DOMContentLoaded', () => {
    ensureLiveRegion();
    if (document.body.dataset.page === 'recipient') {
      initRecipient();
    } else if (document.body.dataset.page === 'sender') {
      initSender();
    }
  });
})();
