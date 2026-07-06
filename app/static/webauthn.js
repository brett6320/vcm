// Minimal WebAuthn helpers for passkey register + auth.
function b64urlToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Register a (possibly additional) passkey. `redirect` is where to go on success.
async function registerPasskey(redirect) {
  const name = window.prompt('Name this passkey (e.g. YubiKey, Laptop, Phone):', 'passkey');
  if (name === null) return;  // cancelled
  const opts = await (await fetch('/mfa/enroll/passkey/options', { method: 'POST' })).json();
  opts.challenge = b64urlToBuf(opts.challenge);
  opts.user.id = b64urlToBuf(opts.user.id);
  (opts.excludeCredentials || []).forEach(c => c.id = b64urlToBuf(c.id));
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: opts });
  } catch (e) {
    alert('Passkey registration cancelled or not possible on this authenticator.\n' +
          'Already-registered authenticators are excluded — use a different one.');
    return;
  }
  const body = {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
    name: name || 'passkey',
    response: {
      attestationObject: bufToB64url(cred.response.attestationObject),
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
    },
  };
  const r = await fetch('/mfa/enroll/passkey/verify',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (r.ok) { const d = await r.json().catch(() => ({})); location.href = d.redirect || redirect || '/'; }
  else alert('Passkey registration failed');
}

async function authPasskey() {
  const opts = await (await fetch('/mfa/passkey/options', { method: 'POST' })).json();
  opts.challenge = b64urlToBuf(opts.challenge);
  (opts.allowCredentials || []).forEach(c => c.id = b64urlToBuf(c.id));
  const cred = await navigator.credentials.get({ publicKey: opts });
  const body = {
    id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
    response: {
      authenticatorData: bufToB64url(cred.response.authenticatorData),
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      signature: bufToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
    },
  };
  const r = await fetch('/mfa/passkey/verify',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (r.ok) { const d = await r.json().catch(() => ({})); location.href = d.redirect || '/'; }
  else alert('Passkey authentication failed');
}
