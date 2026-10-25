const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Generate a cryptographically strong Base32 secret for Google Authenticator (RFC 4648)
 */
function generateBase32Secret(byteLength = 20) {
  const randomBytes = crypto.randomBytes(byteLength);
  return encodeBase32(randomBytes);
}

/**
 * Encode a Buffer into Base32 string (RFC 4648 without padding)
 */
function encodeBase32(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Decode a Base32 string into Buffer
 */
function decodeBase32(base32Str) {
  const cleaned = String(base32Str || '')
    .toUpperCase()
    .replace(/[\s=-]+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: ${cleaned[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Generate a 6-digit TOTP code according to RFC 6238 (Google Authenticator standard)
 */
function generateTOTP(base32Secret, timestampMs = Date.now(), stepSeconds = 30, digits = 6) {
  const key = decodeBase32(base32Secret);
  if (key.length === 0) {
    throw new Error('Empty TOTP secret key');
  }
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  // Write 64-bit big-endian integer
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  counterBuf.writeUInt32BE(high, 0);
  counterBuf.writeUInt32BE(low, 4);

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = (binaryCode % Math.pow(10, digits)).toString().padStart(digits, '0');
  const remainingSeconds = stepSeconds - (Math.floor(timestampMs / 1000) % stepSeconds);

  return {
    code: otp,
    remainingSeconds,
    stepSeconds
  };
}

/**
 * Constant-time verification of a 6-digit TOTP token with ±window step tolerance
 */
function verifyTOTP(base32Secret, tokenInput, windowSteps = 1, timestampMs = Date.now()) {
  const cleanedToken = String(tokenInput || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleanedToken)) {
    return false;
  }

  const stepSeconds = 30;
  for (let w = -windowSteps; w <= windowSteps; w++) {
    const checkTime = timestampMs + w * stepSeconds * 1000;
    const { code } = generateTOTP(base32Secret, checkTime, stepSeconds, 6);
    const a = Buffer.from(code, 'utf8');
    const b = Buffer.from(cleanedToken, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return true;
    }
  }
  return false;
}

/**
 * Build standard otpauth:// URI for Google Authenticator QR Code
 */
function buildOtpAuthUri({ secret, accountName = 'AdminVault', issuer = 'VaultGuard Local' }) {
  const cleanSecret = String(secret).replace(/\s+/g, '').toUpperCase();
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}`;
  const params = new URLSearchParams({
    secret: cleanSecret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30'
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = {
  generateBase32Secret,
  encodeBase32,
  decodeBase32,
  generateTOTP,
  verifyTOTP,
  buildOtpAuthUri
};
