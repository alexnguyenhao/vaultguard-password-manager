const crypto = require('crypto');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 32 * 1024 * 1024 };
const KEY_LENGTH = 32; // 256 bits for AES-256-GCM

/**
 * Generate a random hex salt
 */
function generateSalt(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Derive a 256-bit Vault Encryption Key (VEK) from Master Password and vault salt
 */
function deriveEncryptionKey(masterPassword, saltHex) {
  if (!masterPassword || typeof masterPassword !== 'string') {
    throw new Error('Master password is required');
  }
  const saltBuf = Buffer.from(saltHex, 'hex');
  return crypto.scryptSync(
    Buffer.from(masterPassword.normalize('NFKC'), 'utf8'),
    Buffer.concat([saltBuf, Buffer.from(':vault-encryption-key-v1', 'utf8')]),
    KEY_LENGTH,
    SCRYPT_PARAMS
  );
}

/**
 * Derive an authentication verifier hash (stored on disk so the raw encryption key is never stored)
 */
function deriveAuthVerifier(masterPassword, saltHex) {
  const saltBuf = Buffer.from(saltHex, 'hex');
  return crypto
    .scryptSync(
      Buffer.from(masterPassword.normalize('NFKC'), 'utf8'),
      Buffer.concat([saltBuf, Buffer.from(':vault-auth-verifier-v1', 'utf8')]),
      KEY_LENGTH,
      SCRYPT_PARAMS
    )
    .toString('hex');
}

/**
 * Timing-safe verification of Master Password against stored verifier hash
 */
function verifyMasterPassword(masterPassword, saltHex, expectedVerifierHex) {
  try {
    const candidateHex = deriveAuthVerifier(masterPassword, saltHex);
    const a = Buffer.from(candidateHex, 'hex');
    const b = Buffer.from(expectedVerifierHex, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Encrypt arbitrary JSON-serializable data with AES-256-GCM
 */
function encryptAES256GCM(data, keyBuffer) {
  if (!Buffer.isBuffer(keyBuffer) || keyBuffer.length !== KEY_LENGTH) {
    throw new Error('Invalid 256-bit encryption key');
  }
  const iv = crypto.randomBytes(12); // 96-bit IV recommended by NIST for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  const plaintext = JSON.stringify(data);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  return {
    alg: 'AES-256-GCM',
    iv: iv.toString('hex'),
    tag: authTag.toString('hex'),
    ciphertext: encrypted.toString('base64')
  };
}

/**
 * Decrypt AES-256-GCM payload
 */
function decryptAES256GCM(payload, keyBuffer) {
  if (!payload || !payload.iv || !payload.tag || typeof payload.ciphertext !== 'string') {
    throw new Error('Malformed encrypted payload');
  }
  if (!Buffer.isBuffer(keyBuffer) || keyBuffer.length !== KEY_LENGTH) {
    throw new Error('Invalid 256-bit encryption key');
  }
  const iv = Buffer.from(payload.iv, 'hex');
  const authTag = Buffer.from(payload.tag, 'hex');
  const encrypted = Buffer.from(payload.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
  return JSON.parse(decrypted.toString('utf8'));
}

/**
 * Generate human-readable recovery codes (e.g., XXXX-XXXX-XXXX)
 */
function generateRecoveryCodes(count = 8) {
  const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const codes = [];
  for (let i = 0; i < count; i++) {
    let parts = [];
    for (let p = 0; p < 3; p++) {
      let segment = '';
      const bytes = crypto.randomBytes(4);
      for (let b = 0; b < 4; b++) {
        segment += alphabet[bytes[b] % alphabet.length];
      }
      parts.push(segment);
    }
    codes.push(parts.join('-'));
  }
  return codes;
}

/**
 * Hash a recovery code with salt for safe storage
 */
function hashRecoveryCode(code, saltHex) {
  const normalized = String(code).trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  return crypto
    .createHmac('sha256', Buffer.from(saltHex, 'hex'))
    .update('recovery:' + normalized)
    .digest('hex');
}

module.exports = {
  generateSalt,
  deriveEncryptionKey,
  deriveAuthVerifier,
  verifyMasterPassword,
  encryptAES256GCM,
  decryptAES256GCM,
  generateRecoveryCodes,
  hashRecoveryCode
};
