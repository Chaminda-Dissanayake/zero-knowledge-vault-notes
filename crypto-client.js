/* Vault Notes v3 browser cryptography.
 * All vault/note plaintext and the vault key stay in browser memory/sessionStorage.
 * Uses Web Crypto AES-256-GCM + PBKDF2-SHA-256 + P-256 ECDSA.
 */
(() => {
  'use strict';

  const ITERATIONS = 600000;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64e(bytes) {
    let s = '';
    const a = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const chunk = 0x8000;

    for (let i = 0; i < a.length; i += chunk) {
      s += String.fromCharCode(...a.subarray(i, i + chunk));
    }

    return btoa(s)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  function b64d(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    s += '='.repeat((4 - s.length % 4) % 4);

    const bin = atob(s);
    const out = new Uint8Array(bin.length);

    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }

    return out;
  }

  function randomBytes(n = 32) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  function validBase64Length(value, expectedLength) {
    try {
      return b64d(value).length === expectedLength;
    } catch {
      return false;
    }
  }

  async function deriveOne(password, saltB64, purpose) {
    const salt = b64d(saltB64);

    if (salt.length !== 16) {
      throw new Error('Invalid derivation salt.');
    }

    const purposeBytes = enc.encode('vault-notes-v3/' + purpose);

    const domainSalt = new Uint8Array(
      salt.length + purposeBytes.length
    );

    domainSalt.set(salt);
    domainSalt.set(purposeBytes, salt.length);

    const material = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    return new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: domainSalt,
          iterations: ITERATIONS,
          hash: 'SHA-256'
        },
        material,
        256
      )
    );
  }

  async function deriveAuthSecret(password, authSaltB64) {
    return deriveOne(password, authSaltB64, 'authentication');
  }

  async function deriveVaultWrapKey(password, vaultSaltB64) {
    return deriveOne(password, vaultSaltB64, 'vault-wrap');
  }

  async function derivePasswordKeys(password, authSaltB64, vaultSaltB64) {
    return {
      authSecret: await deriveAuthSecret(password, authSaltB64),
      wrapKey: await deriveVaultWrapKey(password, vaultSaltB64)
    };
  }

  async function importAesKey(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) {
      throw new Error('Invalid AES key.');
    }

    return crypto.subtle.importKey(
      'raw',
      raw,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptBytes(plainBytes, rawKey, aadText) {
    if (!(plainBytes instanceof Uint8Array)) {
      plainBytes = new Uint8Array(plainBytes);
    }

    const iv = randomBytes(12);
    const key = await importAesKey(rawKey);
    const aad = enc.encode(aadText);

    const cipher = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData: aad,
          tagLength: 128
        },
        key,
        plainBytes
      )
    );

    const packed = new Uint8Array(iv.length + cipher.length);

    packed.set(iv);
    packed.set(cipher, iv.length);

    return b64e(packed);
  }

  async function decryptBytes(packedB64, rawKey, aadText) {
    const packed = b64d(packedB64);

    if (packed.length < 12 + 16) {
      throw new Error('Invalid encrypted value.');
    }

    const iv = packed.slice(0, 12);
    const cipher = packed.slice(12);

    const key = await importAesKey(rawKey);

    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: enc.encode(aadText),
        tagLength: 128
      },
      key,
      cipher
    );

    return new Uint8Array(plain);
  }

  async function encryptText(text, rawKey, aadText) {
    return encryptBytes(
      enc.encode(text),
      rawKey,
      aadText
    );
  }

  async function decryptText(packed, rawKey, aadText) {
    return dec.decode(
      await decryptBytes(packed, rawKey, aadText)
    );
  }

  function getVaultKey() {
    const value = sessionStorage.getItem('vaultKey');

    if (!value) {
      return null;
    }

    const raw = b64d(value);

    if (raw.length !== 32) {
      throw new Error('Invalid vault key.');
    }

    return raw;
  }

  function setVaultKey(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 32) {
      throw new Error('Invalid vault key.');
    }

    sessionStorage.setItem('vaultKey', b64e(raw));
  }

  function clearVaultKey() {
    sessionStorage.removeItem('vaultKey');
  }

  async function createRecoveryKey() {
    const pair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      true,
      ['sign', 'verify']
    );

    const privateJwk = await crypto.subtle.exportKey(
      'jwk',
      pair.privateKey
    );

    const publicJwk = await crypto.subtle.exportKey(
      'jwk',
      pair.publicKey
    );

    if (
      privateJwk.kty !== 'EC' ||
      privateJwk.crv !== 'P-256' ||
      publicJwk.kty !== 'EC' ||
      publicJwk.crv !== 'P-256'
    ) {
      throw new Error('Failed to create valid recovery key.');
    }

    const secret = b64d(privateJwk.d);

    if (secret.length !== 32) {
      throw new Error('Invalid recovery private key.');
    }

    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', secret)
    );

    return {
      privateJwk,
      publicJwk,
      aesKey: digest
    };
  }

  function validateRecoveryPrivateJwk(privateJwk) {
    if (
      !privateJwk ||
      privateJwk.kty !== 'EC' ||
      privateJwk.crv !== 'P-256' ||
      typeof privateJwk.x !== 'string' ||
      typeof privateJwk.y !== 'string' ||
      typeof privateJwk.d !== 'string'
    ) {
      throw new Error('Invalid recovery private key.');
    }

    if (
      !validBase64Length(privateJwk.x, 32) ||
      !validBase64Length(privateJwk.y, 32) ||
      !validBase64Length(privateJwk.d, 32)
    ) {
      throw new Error('Invalid recovery private key.');
    }
  }

  function validateRecoveryPublicJwk(publicJwk) {
    if (
      !publicJwk ||
      publicJwk.kty !== 'EC' ||
      publicJwk.crv !== 'P-256' ||
      typeof publicJwk.x !== 'string' ||
      typeof publicJwk.y !== 'string'
    ) {
      throw new Error('Invalid recovery public key.');
    }

    if (
      !validBase64Length(publicJwk.x, 32) ||
      !validBase64Length(publicJwk.y, 32)
    ) {
      throw new Error('Invalid recovery public key.');
    }
  }

  function recoveryAesKey(privateJwk) {
    validateRecoveryPrivateJwk(privateJwk);

    const secret = b64d(privateJwk.d);

    return crypto.subtle.digest(
      'SHA-256',
      secret
    ).then(
      digest => new Uint8Array(digest)
    );
  }

  async function signRecoveryChallenge(privateJwk, challenge) {
    validateRecoveryPrivateJwk(privateJwk);

    const key = await crypto.subtle.importKey(
      'jwk',
      privateJwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      false,
      ['sign']
    );

    const sig = new Uint8Array(
      await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: 'SHA-256'
        },
        key,
        enc.encode(challenge)
      )
    );

    if (sig.length !== 64) {
      throw new Error('Invalid recovery signature.');
    }

    return b64e(sig);
  }

  /*
   * Proof used when rotating the recovery key.
   *
   * This proves that the browser possesses the private key corresponding
   * to the newly submitted public key.
   */
  async function signRecoveryRotation(
    privateJwk,
    accountId,
    recoveryWrap,
    publicJwk
  ) {
    validateRecoveryPrivateJwk(privateJwk);
    validateRecoveryPublicJwk(publicJwk);

    const canonical =
      'vault-notes-v3/recovery-rotation|' +
      String(accountId) +
      '|' +
      recoveryWrap +
      '|' +
      JSON.stringify(publicJwk);

    const key = await crypto.subtle.importKey(
      'jwk',
      privateJwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256'
      },
      false,
      ['sign']
    );

    const sig = new Uint8Array(
      await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: 'SHA-256'
        },
        key,
        enc.encode(canonical)
      )
    );

    if (sig.length !== 64) {
      throw new Error('Invalid recovery rotation signature.');
    }

    return b64e(sig);
  }

  function makeRecoveryPayload(
    username,
    accountId,
    privateJwk,
    publicJwk
  ) {
    validateRecoveryPrivateJwk(privateJwk);
    validateRecoveryPublicJwk(publicJwk);

    if (
      privateJwk.x !== publicJwk.x ||
      privateJwk.y !== publicJwk.y
    ) {
      throw new Error('Recovery key pair does not match.');
    }

    return {
      format: 'vault-notes-recovery-v3',
      username,
      account_id: Number(accountId),
      private_key: privateJwk,
      public_key: publicJwk,
      created_at: new Date().toISOString()
    };
  }

  function parseRecoveryFile(text) {
    let json;

    try {
      json = dec.decode(
        b64d(String(text).trim())
      );
    } catch {
      throw new Error('Invalid recovery file.');
    }

    let p;

    try {
      p = JSON.parse(json);
    } catch {
      throw new Error('Invalid recovery file.');
    }

    if (p.format !== 'vault-notes-recovery-v3') {
      throw new Error('Invalid recovery file.');
    }

    const accountId = Number(p.account_id);

    if (
      !Number.isInteger(accountId) ||
      accountId <= 0
    ) {
      throw new Error('Invalid recovery file.');
    }

    validateRecoveryPrivateJwk(p.private_key);
    validateRecoveryPublicJwk(p.public_key);

    /*
     * The public coordinates embedded in the private JWK must match
     * the public JWK stored in the recovery file.
     */
    if (
      p.private_key.x !== p.public_key.x ||
      p.private_key.y !== p.public_key.y
    ) {
      throw new Error(
        'Recovery key pair does not match.'
      );
    }

    return {
      ...p,
      account_id: accountId,
      privateJwk: p.private_key,
      publicJwk: p.public_key
    };
  }

  function downloadRecovery(payload, username) {
    const json = JSON.stringify(payload);
    const encoded = b64e(enc.encode(json));

    const blob = new Blob(
      [encoded],
      {
        type: 'application/octet-stream'
      }
    );

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');

    a.href = url;
    a.download = `${username}-vault-recovery.srec`;

    document.body.appendChild(a);
    a.click();
    a.remove();

    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  window.VaultCrypto = {
    ITERATIONS,

    b64e,
    b64d,
    randomBytes,

    derivePasswordKeys,
    deriveAuthSecret,
    deriveVaultWrapKey,

    encryptBytes,
    decryptBytes,
    encryptText,
    decryptText,

    getVaultKey,
    setVaultKey,
    clearVaultKey,

    createRecoveryKey,
    recoveryAesKey,
    signRecoveryChallenge,
    signRecoveryRotation,

    makeRecoveryPayload,
    downloadRecovery,
    parseRecoveryFile
  };
})();