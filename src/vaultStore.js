const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  generateSalt,
  deriveEncryptionKey,
  deriveAuthVerifier,
  verifyMasterPassword,
  encryptAES256GCM,
  decryptAES256GCM,
  generateRecoveryCodes,
  hashRecoveryCode
} = require('./crypto');
const { generateTOTP, verifyTOTP } = require('./totp');

const DATA_DIR = path.join(__dirname, '..', 'data');
const VAULT_FILE = path.join(DATA_DIR, 'vault.enc.json');
const DEVICE_KEY_FILE = path.join(DATA_DIR, '.device.key');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

/**
 * Get or create a local machine wrapping key (32 bytes) so that if the user chooses
 * "Quick Unlock via Google Authenticator 6-digit OTP", the Vault Encryption Key (VEK)
 * remains AES-256-GCM encrypted at rest on disk.
 */
function getOrCreateDeviceKey() {
  ensureDataDir();
  if (fs.existsSync(DEVICE_KEY_FILE)) {
    const raw = fs.readFileSync(DEVICE_KEY_FILE, 'utf8').trim();
    const buf = Buffer.from(raw, 'hex');
    if (buf.length === 32) return buf;
  }
  const newKey = crypto.randomBytes(32);
  fs.writeFileSync(DEVICE_KEY_FILE, newKey.toString('hex'), { mode: 0o600 });
  return newKey;
}

function isVaultInitialized() {
  return fs.existsSync(VAULT_FILE);
}

function readRawVault() {
  if (!isVaultInitialized()) return null;
  const raw = fs.readFileSync(VAULT_FILE, 'utf8');
  return JSON.parse(raw);
}

function writeRawVault(vaultObj) {
  ensureDataDir();
  const tempFile = `${VAULT_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(vaultObj, null, 2), { mode: 0o600 });
  fs.renameSync(tempFile, VAULT_FILE);
}

/**
 * Initialize a brand-new encrypted vault after verifying the user scanned the Google Authenticator QR code
 */
function initializeVault({
  ownerName = 'Chủ sở hữu Vault',
  googleEmail = '',
  googleClientId = '',
  masterPassword,
  totpSecret,
  totpToken,
  authMode = 'totp_and_master', // 'totp_and_master' | 'totp_only' | 'google_oauth_and_totp'
  seedSampleAccounts = false
}) {
  if (isVaultInitialized()) {
    throw new Error('Kho mật khẩu đã được thiết lập trước đó.');
  }
  if (!masterPassword || masterPassword.length < 6) {
    throw new Error('Mật khẩu chính (Master Password) phải từ 6 ký tự trở lên.');
  }
  if (!totpSecret || !verifyTOTP(totpSecret, totpToken, 1)) {
    throw new Error('Mã 6 số Google Authenticator không chính xác hoặc đã hết hạn.');
  }

  const salt = generateSalt(32);
  const vek = deriveEncryptionKey(masterPassword, salt);
  const passwordVerifier = deriveAuthVerifier(masterPassword, salt);
  const deviceKey = getOrCreateDeviceKey();

  // Encrypt the TOTP secret and the VEK with the local device key so TOTP verification works seamlessly
  const encryptedTotpSecret = encryptAES256GCM(totpSecret, deviceKey);
  const deviceWrappedVek = encryptAES256GCM(vek.toString('hex'), deviceKey);

  // Generate 8 single-use recovery codes
  const recoveryCodesPlain = generateRecoveryCodes(8);
  const recoveryCodeHashes = recoveryCodesPlain.map((code) => ({
    hash: hashRecoveryCode(code, salt),
    used: false,
    usedAt: null
  }));

  const initialAccounts = seedSampleAccounts ? createSampleAccounts() : [];
  const encryptedAccounts = encryptAES256GCM(initialAccounts, vek);

  const now = new Date().toISOString();
  const vaultData = {
    version: 1,
    createdAt: now,
    updatedAt: now,
    ownerName: String(ownerName || 'Chủ sở hữu Vault').trim(),
    authConfig: {
      authMode, // 'totp_and_master' | 'totp_only' | 'google_oauth_and_totp'
      googleEmail: String(googleEmail || '').trim().toLowerCase(),
      googleClientId: String(googleClientId || '').trim(),
      autoLockMinutes: 15
    },
    crypto: {
      kdf: 'scrypt',
      cipher: 'AES-256-GCM',
      salt,
      passwordVerifier,
      encryptedTotpSecret,
      deviceWrappedVek,
      recoveryCodeHashes
    },
    encryptedAccounts,
    auditLogs: [
      {
        id: crypto.randomUUID(),
        timestamp: now,
        event: 'VAULT_INITIALIZED',
        detail: `Khởi tạo kho mật khẩu với Google Authenticator (${authMode})`
      }
    ]
  };

  writeRawVault(vaultData);

  return {
    recoveryCodes: recoveryCodesPlain,
    vek,
    vaultMeta: getPublicVaultMeta(vaultData)
  };
}

function getPublicVaultMeta(vaultData = readRawVault()) {
  if (!vaultData) {
    return { initialized: false };
  }
  const remainingRecoveryCodes = (vaultData.crypto.recoveryCodeHashes || []).filter(
    (r) => !r.used
  ).length;

  return {
    initialized: true,
    ownerName: vaultData.ownerName,
    createdAt: vaultData.createdAt,
    updatedAt: vaultData.updatedAt,
    authMode: vaultData.authConfig?.authMode || 'totp_and_master',
    googleEmail: vaultData.authConfig?.googleEmail || '',
    googleClientId: vaultData.authConfig?.googleClientId || '',
    autoLockMinutes: vaultData.authConfig?.autoLockMinutes || 15,
    remainingRecoveryCodes
  };
}

/**
 * Authenticate user via Google Authenticator 6-digit OTP (+ Master Password or Recovery Code or Google OAuth)
 * Returns the 32-byte Vault Encryption Key (VEK) on success
 */
function authenticateAndUnlock({
  masterPassword = '',
  totpToken = '',
  recoveryCode = '',
  googleVerifiedEmail = ''
}) {
  const vaultData = readRawVault();
  if (!vaultData) {
    throw new Error('Kho mật khẩu chưa được khởi tạo.');
  }

  const { salt, passwordVerifier, encryptedTotpSecret, deviceWrappedVek, recoveryCodeHashes } =
    vaultData.crypto;
  const authMode = vaultData.authConfig?.authMode || 'totp_and_master';
  const deviceKey = getOrCreateDeviceKey();
  const totpSecret = decryptAES256GCM(encryptedTotpSecret, deviceKey);

  // Step 1: Verify Google Authenticator TOTP OR Recovery Code
  let totpOrRecoveryValid = false;
  let usedMethod = 'GOOGLE_AUTHENTICATOR_TOTP';

  if (recoveryCode && String(recoveryCode).trim().length > 0) {
    const candidateHash = hashRecoveryCode(recoveryCode, salt);
    const matched = recoveryCodeHashes.find((item) => !item.used && item.hash === candidateHash);
    if (!matched) {
      appendAuditLog(vaultData, 'LOGIN_FAILED', 'Mã khôi phục (Recovery Code) không hợp lệ hoặc đã dùng');
      throw new Error('Mã khôi phục (Recovery Code) không chính xác hoặc đã được sử dụng.');
    }
    matched.used = true;
    matched.usedAt = new Date().toISOString();
    totpOrRecoveryValid = true;
    usedMethod = 'RECOVERY_CODE';
  } else {
    if (!verifyTOTP(totpSecret, totpToken, 1)) {
      appendAuditLog(vaultData, 'LOGIN_FAILED', 'Nhập sai mã 6 số Google Authenticator');
      throw new Error('Mã 6 số Google Authenticator không đúng hoặc đã hết hạn (30s).');
    }
    totpOrRecoveryValid = true;
  }

  // Step 2: Check additional factor based on authMode
  let vek;
  if (authMode === 'totp_only') {
    // Unwrap VEK using deviceKey after Google Authenticator TOTP passed
    const vekHex = decryptAES256GCM(deviceWrappedVek, deviceKey);
    vek = Buffer.from(vekHex, 'hex');
  } else if (authMode === 'google_oauth_and_totp') {
    const expectedEmail = (vaultData.authConfig?.googleEmail || '').toLowerCase();
    if (expectedEmail && googleVerifiedEmail.toLowerCase() !== expectedEmail) {
      // Allow fallback to Master Password if user provides Master Password instead of OAuth popup
      if (!masterPassword || !verifyMasterPassword(masterPassword, salt, passwordVerifier)) {
        appendAuditLog(
          vaultData,
          'LOGIN_FAILED',
          'Chưa xác thực đúng tài khoản Google OAuth hoặc sai Master Password'
        );
        throw new Error(
          `Vui lòng đăng nhập đúng tài khoản Google (${expectedEmail}) hoặc nhập đúng Master Password kèm mã Google Authenticator.`
        );
      }
      vek = deriveEncryptionKey(masterPassword, salt);
      usedMethod = 'GOOGLE_AUTH_TOTP + MASTER_PASSWORD';
    } else {
      const vekHex = decryptAES256GCM(deviceWrappedVek, deviceKey);
      vek = Buffer.from(vekHex, 'hex');
      usedMethod = 'GOOGLE_OAUTH + GOOGLE_AUTHENTICATOR_TOTP';
    }
  } else {
    // Default: 'totp_and_master'
    if (!masterPassword || !verifyMasterPassword(masterPassword, salt, passwordVerifier)) {
      appendAuditLog(vaultData, 'LOGIN_FAILED', 'Nhập sai Master Password');
      throw new Error('Mật khẩu chính (Master Password) không chính xác.');
    }
    vek = deriveEncryptionKey(masterPassword, salt);
    usedMethod = `${usedMethod} + MASTER_PASSWORD`;
  }

  // Test decrypting accounts to verify VEK integrity
  decryptAES256GCM(vaultData.encryptedAccounts, vek);

  appendAuditLog(vaultData, 'VAULT_UNLOCKED', `Đăng nhập thành công qua ${usedMethod}`);
  writeRawVault(vaultData);

  return {
    vek,
    vaultMeta: getPublicVaultMeta(vaultData)
  };
}

function appendAuditLog(vaultData, event, detail) {
  if (!Array.isArray(vaultData.auditLogs)) {
    vaultData.auditLogs = [];
  }
  vaultData.auditLogs.unshift({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    event,
    detail
  });
  if (vaultData.auditLogs.length > 150) {
    vaultData.auditLogs = vaultData.auditLogs.slice(0, 150);
  }
  writeRawVault(vaultData);
}

/**
 * Read and decrypt all stored accounts using the active session's VEK
 */
function getDecryptedAccounts(vek) {
  const vaultData = readRawVault();
  if (!vaultData) throw new Error('Vault not initialized');
  const accounts = decryptAES256GCM(vaultData.encryptedAccounts, vek);
  // Attach live 6-digit TOTP code for any account that has its own 2FA secret saved!
  return accounts.map((acc) => {
    let liveTotp = null;
    if (acc.totpSecret && String(acc.totpSecret).trim()) {
      try {
        liveTotp = generateTOTP(acc.totpSecret);
      } catch {
        liveTotp = null;
      }
    }
    return {
      ...acc,
      liveTotp
    };
  });
}

/**
 * Save updated accounts array encrypted with AES-256-GCM
 */
function saveDecryptedAccounts(accounts, vek, auditDetail = null) {
  const vaultData = readRawVault();
  if (!vaultData) throw new Error('Vault not initialized');
  // Strip computed liveTotp before encrypting at rest
  const cleanAccounts = accounts.map(({ liveTotp, ...rest }) => rest);
  vaultData.encryptedAccounts = encryptAES256GCM(cleanAccounts, vek);
  vaultData.updatedAt = new Date().toISOString();
  if (auditDetail) {
    appendAuditLog(vaultData, 'VAULT_UPDATED', auditDetail);
  } else {
    writeRawVault(vaultData);
  }
}

/**
 * Update authentication / Google settings while unlocked
 */
function updateVaultSettings(vek, { ownerName, authMode, googleEmail, googleClientId, autoLockMinutes }) {
  const vaultData = readRawVault();
  if (!vaultData) throw new Error('Vault not initialized');
  // Verify VEK is valid
  decryptAES256GCM(vaultData.encryptedAccounts, vek);

  if (ownerName !== undefined) {
    vaultData.ownerName = String(ownerName).trim() || vaultData.ownerName;
  }
  if (!vaultData.authConfig) vaultData.authConfig = {};
  if (authMode && ['totp_and_master', 'totp_only', 'google_oauth_and_totp'].includes(authMode)) {
    vaultData.authConfig.authMode = authMode;
  }
  if (googleEmail !== undefined) {
    vaultData.authConfig.googleEmail = String(googleEmail).trim().toLowerCase();
  }
  if (googleClientId !== undefined) {
    vaultData.authConfig.googleClientId = String(googleClientId).trim();
  }
  if (autoLockMinutes !== undefined) {
    const mins = Number(autoLockMinutes);
    if (!Number.isNaN(mins) && mins >= 1 && mins <= 240) {
      vaultData.authConfig.autoLockMinutes = mins;
    }
  }
  appendAuditLog(
    vaultData,
    'SETTINGS_UPDATED',
    `Cập nhật cấu hình bảo mật (Chế độ: ${vaultData.authConfig.authMode})`
  );
  return getPublicVaultMeta(vaultData);
}

/**
 * Get current TOTP secret while unlocked (so user can scan QR on a new phone)
 */
function getVaultTotpSecret(vek) {
  const vaultData = readRawVault();
  if (!vaultData) throw new Error('Vault not initialized');
  decryptAES256GCM(vaultData.encryptedAccounts, vek);
  const deviceKey = getOrCreateDeviceKey();
  return decryptAES256GCM(vaultData.crypto.encryptedTotpSecret, deviceKey);
}

/**
 * Get recent security audit logs
 */
function getAuditLogs(vek) {
  const vaultData = readRawVault();
  if (!vaultData) throw new Error('Vault not initialized');
  decryptAES256GCM(vaultData.encryptedAccounts, vek);
  return vaultData.auditLogs || [];
}

function createSampleAccounts() {
  const now = new Date().toISOString();
  return [
    {
      id: crypto.randomUUID(),
      platform: 'Google / Gmail',
      category: 'email',
      accountLabel: 'Tài khoản Chính (Cá nhân)',
      username: 'nguyen.personal@gmail.com',
      password: 'Gm!98#Personal$VaultKey2026',
      url: 'https://mail.google.com',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      notes: 'Email chính liên kết ngân hàng và Google Drive cá nhân.',
      tags: ['Chính', 'Quan trọng', '2FA'],
      favorite: true,
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    },
    {
      id: crypto.randomUUID(),
      platform: 'Google / Gmail',
      category: 'email',
      accountLabel: 'Tài khoản Công ty (Work)',
      username: 'nguyen.work@company.vn',
      password: 'Wk@2026!Workspace#Corp99',
      url: 'https://mail.google.com',
      totpSecret: '',
      notes: 'Tài khoản Google Workspace dự án công ty.',
      tags: ['Công việc', 'Workspace'],
      favorite: true,
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    },
    {
      id: crypto.randomUUID(),
      platform: 'Facebook',
      category: 'social',
      accountLabel: 'Nick Chính',
      username: '0901234567',
      password: 'Fb#MainAccount!2026$Secure',
      url: 'https://facebook.com',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      notes: 'Bật xác thực 2 bước và cảnh báo đăng nhập lạ.',
      tags: ['Mạng xã hội', 'Chính'],
      favorite: true,
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    },
    {
      id: crypto.randomUUID(),
      platform: 'Facebook',
      category: 'social',
      accountLabel: 'Nick Bán Hàng / Seeding #2',
      username: 'shop.marketing.fb@gmail.com',
      password: 'Fb#ShopClone!8821$Ads',
      url: 'https://business.facebook.com',
      totpSecret: '',
      notes: 'Dùng chạy Facebook Ads và quản lý Fanpage.',
      tags: ['Kinh doanh', 'Clone'],
      favorite: false,
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    },
    {
      id: crypto.randomUUID(),
      platform: 'GitHub',
      category: 'dev',
      accountLabel: 'GitHub Cá nhân (Open Source)',
      username: 'dev-master-vn',
      password: 'Gh$Personal_99182!RepoKey',
      url: 'https://github.com/login',
      totpSecret: 'JBSWY3DPEHPK3PXP',
      notes: 'Lưu kèm SSH Key trên máy trạm.',
      tags: ['Dev', 'Code', '2FA'],
      favorite: true,
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    },
    {
      id: crypto.randomUUID(),
      platform: 'Vietcombank Digibank',
      category: 'finance',
      accountLabel: 'Tài khoản Thanh toán Chính',
      username: '0901234567',
      password: 'Vcb$SmartOTP#2026!Banking',
      url: 'https://vcbdigibank.vietcombank.com.vn',
      totpSecret: '',
      notes: 'SmartOTP gắn trên iPhone chính.',
      tags: ['Ngân hàng', 'Tài chính'],
      favorite: true,
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    }
  ];
}

module.exports = {
  VAULT_FILE,
  isVaultInitialized,
  readRawVault,
  getPublicVaultMeta,
  initializeVault,
  authenticateAndUnlock,
  getDecryptedAccounts,
  saveDecryptedAccounts,
  updateVaultSettings,
  getVaultTotpSecret,
  getAuditLogs
};
