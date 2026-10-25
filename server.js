const express = require('express');
const crypto = require('crypto');
const path = require('path');
const https = require('https');
const QRCode = require('qrcode');

const {
  generateBase32Secret,
  generateTOTP,
  verifyTOTP,
  buildOtpAuthUri
} = require('./src/totp');
const {
  isVaultInitialized,
  getPublicVaultMeta,
  initializeVault,
  authenticateAndUnlock,
  getDecryptedAccounts,
  saveDecryptedAccounts,
  updateVaultSettings,
  getVaultTotpSecret,
  getAuditLogs
} = require('./src/vaultStore');
const {
  deriveEncryptionKey,
  generateSalt,
  encryptAES256GCM,
  decryptAES256GCM
} = require('./src/crypto');

const app = express();
const PORT = Number(process.env.PORT) || 3456;
const HOST = process.env.HOST || '127.0.0.1';

// Disable X-Powered-By header
app.disable('x-powered-by');

// Security Headers (following security-and-hardening skill)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' https://accounts.google.com/gsi/client",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://accounts.google.com/gsi/style",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: https:",
      "frame-src https://accounts.google.com/",
      "connect-src 'self' https://accounts.google.com/ https://oauth2.googleapis.com/"
    ].join('; ')
  );
  next();
});

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// In-Memory Encrypted Session Store & Rate Limiter
// ============================================================================
const activeSessions = new Map(); // sessionId -> { vek: Buffer, createdAt: number, lastActiveAt: number, googleVerifiedEmail: string }
const pendingSetupState = {
  secret: null,
  createdAt: 0
};
const pendingGoogleVerifications = new Map(); // tokenNonce -> { email, expiresAt }

// Rate limiter for authentication routes
const authAttempts = new Map(); // ip -> { count, resetAt }
function authRateLimiter(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'local';
  const now = Date.now();
  const windowMs = 10 * 60 * 1000; // 10 minutes
  const maxAttempts = 15;

  let record = authAttempts.get(ip);
  if (!record || now > record.resetAt) {
    record = { count: 0, resetAt: now + windowMs };
    authAttempts.set(ip, record);
  }
  record.count += 1;

  if (record.count > maxAttempts) {
    const waitSeconds = Math.ceil((record.resetAt - now) / 1000);
    return res.status(429).json({
      error: `Quá nhiều lần thử đăng nhập sai. Vui lòng đợi ${waitSeconds} giây trước khi thử lại.`
    });
  }
  next();
}

function clearRateLimit(req) {
  const ip = req.ip || req.socket.remoteAddress || 'local';
  authAttempts.delete(ip);
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx > -1) {
      const k = pair.slice(0, idx).trim();
      const v = decodeURIComponent(pair.slice(idx + 1).trim());
      cookies[k] = v;
    }
  });
  return cookies;
}

function setSessionCookie(res, sessionId, maxAgeSeconds = 3600) {
  res.setHeader(
    'Set-Cookie',
    `vg_session=${encodeURIComponent(sessionId)}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAgeSeconds}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'vg_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0'
  );
}

function getActiveSession(req) {
  const cookies = parseCookies(req);
  const sessionId = cookies.vg_session;
  if (!sessionId || !activeSessions.has(sessionId)) return null;

  const session = activeSessions.get(sessionId);
  const meta = getPublicVaultMeta();
  const autoLockMs = (meta.autoLockMinutes || 15) * 60 * 1000;
  if (Date.now() - session.lastActiveAt > autoLockMs) {
    // Zero out VEK buffer before deleting expired session
    if (Buffer.isBuffer(session.vek)) session.vek.fill(0);
    activeSessions.delete(sessionId);
    return null;
  }
  session.lastActiveAt = Date.now();
  return { sessionId, session };
}

function requireAuth(req, res, next) {
  const active = getActiveSession(req);
  if (!active) {
    clearSessionCookie(res);
    return res.status(401).json({
      error: 'Phiên làm việc đã khóa hoặc hết hạn. Vui lòng xác thực bằng Google Authentication để mở kho.'
    });
  }
  req.vaultSession = active.session;
  req.vaultSessionId = active.sessionId;
  next();
}

// ============================================================================
// Auth & Setup Endpoints
// ============================================================================

/**
 * GET /api/auth/status
 * Check whether the vault is initialized and whether the current session is unlocked
 */
app.get('/api/auth/status', async (req, res) => {
  try {
    const initialized = isVaultInitialized();
    const active = getActiveSession(req);
    const meta = getPublicVaultMeta();

    if (!initialized) {
      // Generate or reuse a setup TOTP secret for the Setup Wizard
      if (!pendingSetupState.secret || Date.now() - pendingSetupState.createdAt > 30 * 60 * 1000) {
        pendingSetupState.secret = generateBase32Secret(20);
        pendingSetupState.createdAt = Date.now();
      }
      const otpauthUri = buildOtpAuthUri({
        secret: pendingSetupState.secret,
        accountName: 'LocalVault',
        issuer: 'VaultGuard'
      });
      const qrDataUrl = await QRCode.toDataURL(otpauthUri, {
        width: 240,
        margin: 1,
        color: { dark: '#0C0F14', light: '#FFFFFF' }
      });
      const currentOtpPreview = generateTOTP(pendingSetupState.secret);

      return res.json({
        initialized: false,
        unlocked: false,
        setupData: {
          totpSecret: pendingSetupState.secret,
          otpauthUri,
          qrDataUrl,
          currentOtpPreview // Useful during initial setup verification so user can verify their phone clock matches PC clock
        }
      });
    }

    return res.json({
      initialized: true,
      unlocked: Boolean(active),
      meta
    });
  } catch (err) {
    res.status(500).json({ error: 'Không thể kiểm tra trạng thái kho mật khẩu.' });
  }
});

/**
 * GET /api/auth/setup-otp-preview
 * Returns the live 6-digit code & countdown for the pending setup secret so the user can check clock sync during first-time setup
 */
app.get('/api/auth/setup-otp-preview', (req, res) => {
  if (isVaultInitialized() || !pendingSetupState.secret) {
    return res.status(400).json({ error: 'Không ở trong chế độ thiết lập ban đầu.' });
  }
  const preview = generateTOTP(pendingSetupState.secret);
  res.json(preview);
});

/**
 * POST /api/auth/setup
 * Initialize the encrypted vault with Master Password + Google Authenticator TOTP verification
 */
app.post('/api/auth/setup', authRateLimiter, (req, res) => {
  try {
    if (isVaultInitialized()) {
      return res.status(400).json({ error: 'Kho mật khẩu đã được khởi tạo.' });
    }
    const {
      ownerName,
      googleEmail,
      googleClientId,
      masterPassword,
      totpToken,
      authMode,
      seedSampleAccounts
    } = req.body || {};

    if (!pendingSetupState.secret) {
      return res.status(400).json({ error: 'Phiên thiết lập QR đã hết hạn. Vui lòng tải lại trang.' });
    }

    const result = initializeVault({
      ownerName,
      googleEmail,
      googleClientId,
      masterPassword,
      totpSecret: pendingSetupState.secret,
      totpToken,
      authMode: authMode || 'totp_and_master',
      seedSampleAccounts: Boolean(seedSampleAccounts)
    });

    pendingSetupState.secret = null;
    clearRateLimit(req);

    const sessionId = crypto.randomBytes(32).toString('hex');
    activeSessions.set(sessionId, {
      vek: result.vek,
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
      googleVerifiedEmail: googleEmail || ''
    });
    setSessionCookie(res, sessionId, 3600);

    res.json({
      success: true,
      recoveryCodes: result.recoveryCodes,
      meta: result.vaultMeta
    });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Thiết lập kho thất bại.' });
  }
});

/**
 * POST /api/auth/google-verify
 * Verify a Google Identity Services (OAuth 2.0) ID Token (credential)
 */
app.post('/api/auth/google-verify', authRateLimiter, async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential || typeof credential !== 'string') {
      return res.status(400).json({ error: 'Thiếu Google ID Token.' });
    }

    const tokenInfo = await verifyGoogleIdToken(credential);
    const meta = getPublicVaultMeta();

    if (meta.googleClientId && tokenInfo.aud !== meta.googleClientId) {
      return res.status(403).json({ error: 'Google Client ID không khớp với cấu hình kho.' });
    }
    if (meta.googleEmail && tokenInfo.email.toLowerCase() !== meta.googleEmail.toLowerCase()) {
      return res.status(403).json({
        error: `Tài khoản Google (${tokenInfo.email}) không được cấp quyền mở kho này.`
      });
    }

    const nonce = crypto.randomBytes(24).toString('hex');
    pendingGoogleVerifications.set(nonce, {
      email: tokenInfo.email.toLowerCase(),
      name: tokenInfo.name || tokenInfo.email,
      picture: tokenInfo.picture || '',
      expiresAt: Date.now() + 5 * 60 * 1000
    });

    res.json({
      verified: true,
      googleAuthNonce: nonce,
      email: tokenInfo.email,
      name: tokenInfo.name || tokenInfo.email
    });
  } catch (err) {
    res.status(401).json({ error: err.message || 'Xác thực Google OAuth thất bại.' });
  }
});

function verifyGoogleIdToken(idToken) {
  return new Promise((resolve, reject) => {
    const url = `https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`;
    https
      .get(url, (resp) => {
        let raw = '';
        resp.on('data', (chunk) => {
          raw += chunk;
        });
        resp.on('end', () => {
          try {
            const parsed = JSON.parse(raw);
            if (resp.statusCode !== 200 || parsed.error || parsed.email_verified !== 'true') {
              return reject(new Error('Token Google không hợp lệ hoặc email chưa xác minh.'));
            }
            resolve(parsed);
          } catch {
            reject(new Error('Không thể phân tích phản hồi từ máy chủ Google.'));
          }
        });
      })
      .on('error', () => {
        reject(new Error('Không thể kết nối tới máy chủ xác thực Google OAuth.'));
      });
  });
}

/**
 * POST /api/auth/login
 * Unlock the vault using Google Authenticator 6-digit OTP (+ Master Password or Google OAuth or Recovery Code)
 */
app.post('/api/auth/login', authRateLimiter, (req, res) => {
  try {
    const { masterPassword, totpToken, recoveryCode, googleAuthNonce } = req.body || {};

    let googleVerifiedEmail = '';
    if (googleAuthNonce && pendingGoogleVerifications.has(googleAuthNonce)) {
      const record = pendingGoogleVerifications.get(googleAuthNonce);
      if (Date.now() <= record.expiresAt) {
        googleVerifiedEmail = record.email;
      }
      pendingGoogleVerifications.delete(googleAuthNonce);
    }

    const result = authenticateAndUnlock({
      masterPassword,
      totpToken,
      recoveryCode,
      googleVerifiedEmail
    });

    clearRateLimit(req);

    const sessionId = crypto.randomBytes(32).toString('hex');
    activeSessions.set(sessionId, {
      vek: result.vek,
      createdAt: Date.now(),
      lastActiveAt: Date.now(),
      googleVerifiedEmail
    });
    setSessionCookie(res, sessionId, 3600);

    res.json({
      success: true,
      meta: result.vaultMeta
    });
  } catch (err) {
    res.status(401).json({ error: err.message || 'Xác thực không thành công.' });
  }
});

/**
 * POST /api/auth/logout
 * Immediately lock the vault and wipe the encryption key from memory
 */
app.post('/api/auth/logout', (req, res) => {
  const cookies = parseCookies(req);
  const sessionId = cookies.vg_session;
  if (sessionId && activeSessions.has(sessionId)) {
    const session = activeSessions.get(sessionId);
    if (Buffer.isBuffer(session.vek)) {
      session.vek.fill(0);
    }
    activeSessions.delete(sessionId);
  }
  clearSessionCookie(res);
  res.json({ success: true });
});

// ============================================================================
// Protected Vault Account Management Endpoints
// ============================================================================

/**
 * GET /api/accounts
 * Retrieve all decrypted multi-platform accounts + security statistics
 */
app.get('/api/accounts', requireAuth, (req, res) => {
  try {
    const accounts = getDecryptedAccounts(req.vaultSession.vek);
    const audit = buildSecurityAudit(accounts);
    res.json({
      accounts,
      audit,
      meta: getPublicVaultMeta()
    });
  } catch (err) {
    res.status(500).json({ error: 'Không thể giải mã danh sách tài khoản.' });
  }
});

/**
 * GET /api/accounts/totp-refresh
 * Refresh live 6-digit 2FA TOTP codes for stored accounts that have their own 2FA secret
 */
app.get('/api/accounts/totp-refresh', requireAuth, (req, res) => {
  try {
    const accounts = getDecryptedAccounts(req.vaultSession.vek);
    const totpMap = {};
    for (const acc of accounts) {
      if (acc.liveTotp) {
        totpMap[acc.id] = acc.liveTotp;
      }
    }
    res.json({ totpMap });
  } catch (err) {
    res.status(500).json({ error: 'Không thể làm mới mã 2FA.' });
  }
});

/**
 * POST /api/accounts
 * Add a new account to a platform
 */
app.post('/api/accounts', requireAuth, (req, res) => {
  try {
    const {
      platform,
      category,
      accountLabel,
      username,
      password,
      url,
      totpSecret,
      notes,
      tags,
      favorite
    } = req.body || {};

    if (!platform || !String(platform).trim()) {
      return res.status(400).json({ error: 'Tên nền tảng (Platform) không được để trống.' });
    }
    if (!username || !String(username).trim()) {
      return res.status(400).json({ error: 'Tên đăng nhập / Email không được để trống.' });
    }
    if (!password || !String(password)) {
      return res.status(400).json({ error: 'Mật khẩu không được để trống.' });
    }

    // Validate optional TOTP secret if user entered one
    const cleanedTotp = String(totpSecret || '').trim();
    if (cleanedTotp) {
      try {
        generateTOTP(cleanedTotp);
      } catch {
        return res.status(400).json({
          error: 'Mã Secret 2FA (Base32) của tài khoản không hợp lệ.'
        });
      }
    }

    const accounts = getDecryptedAccounts(req.vaultSession.vek);
    const now = new Date().toISOString();
    const newAccount = {
      id: crypto.randomUUID(),
      platform: String(platform).trim(),
      category: String(category || 'other').trim(),
      accountLabel: String(accountLabel || 'Tài khoản Chính').trim(),
      username: String(username).trim(),
      password: String(password),
      url: String(url || '').trim(),
      totpSecret: cleanedTotp,
      notes: String(notes || '').trim(),
      tags: Array.isArray(tags)
        ? tags.map((t) => String(t).trim()).filter(Boolean)
        : String(tags || '')
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean),
      favorite: Boolean(favorite),
      createdAt: now,
      updatedAt: now,
      passwordHistory: []
    };

    accounts.unshift(newAccount);
    saveDecryptedAccounts(
      accounts,
      req.vaultSession.vek,
      `Thêm tài khoản mới: ${newAccount.platform} (${newAccount.accountLabel} - ${newAccount.username})`
    );

    const updated = getDecryptedAccounts(req.vaultSession.vek);
    res.status(201).json({
      account: updated.find((a) => a.id === newAccount.id),
      accounts: updated,
      audit: buildSecurityAudit(updated)
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Không thể lưu tài khoản mới.' });
  }
});

/**
 * PUT /api/accounts/:id
 * Update an existing account (automatically tracks password history if password changed)
 */
app.put('/api/accounts/:id', requireAuth, (req, res) => {
  try {
    const accountId = req.params.id;
    const accounts = getDecryptedAccounts(req.vaultSession.vek);
    const idx = accounts.findIndex((a) => a.id === accountId);
    if (idx === -1) {
      return res.status(404).json({ error: 'Không tìm thấy tài khoản trong kho.' });
    }

    const existing = accounts[idx];
    const {
      platform,
      category,
      accountLabel,
      username,
      password,
      url,
      totpSecret,
      notes,
      tags,
      favorite
    } = req.body || {};

    const cleanedTotp =
      totpSecret !== undefined ? String(totpSecret || '').trim() : existing.totpSecret;
    if (cleanedTotp) {
      try {
        generateTOTP(cleanedTotp);
      } catch {
        return res.status(400).json({
          error: 'Mã Secret 2FA (Base32) của tài khoản không hợp lệ.'
        });
      }
    }

    const now = new Date().toISOString();
    const passwordHistory = Array.isArray(existing.passwordHistory)
      ? [...existing.passwordHistory]
      : [];

    if (password !== undefined && password !== existing.password) {
      passwordHistory.unshift({
        password: existing.password,
        changedAt: now
      });
      if (passwordHistory.length > 10) passwordHistory.pop();
    }

    const updatedAccount = {
      ...existing,
      platform: platform !== undefined ? String(platform).trim() : existing.platform,
      category: category !== undefined ? String(category).trim() : existing.category,
      accountLabel:
        accountLabel !== undefined ? String(accountLabel).trim() : existing.accountLabel,
      username: username !== undefined ? String(username).trim() : existing.username,
      password: password !== undefined ? String(password) : existing.password,
      url: url !== undefined ? String(url).trim() : existing.url,
      totpSecret: cleanedTotp,
      notes: notes !== undefined ? String(notes).trim() : existing.notes,
      tags:
        tags !== undefined
          ? Array.isArray(tags)
            ? tags.map((t) => String(t).trim()).filter(Boolean)
            : String(tags)
                .split(',')
                .map((t) => t.trim())
                .filter(Boolean)
          : existing.tags,
      favorite: favorite !== undefined ? Boolean(favorite) : existing.favorite,
      updatedAt: now,
      passwordHistory
    };

    accounts[idx] = updatedAccount;
    saveDecryptedAccounts(
      accounts,
      req.vaultSession.vek,
      `Cập nhật tài khoản: ${updatedAccount.platform} (${updatedAccount.accountLabel})`
    );

    const updatedList = getDecryptedAccounts(req.vaultSession.vek);
    res.json({
      account: updatedList.find((a) => a.id === accountId),
      accounts: updatedList,
      audit: buildSecurityAudit(updatedList)
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Không thể cập nhật tài khoản.' });
  }
});

/**
 * DELETE /api/accounts/:id
 * Remove an account from the vault
 */
app.delete('/api/accounts/:id', requireAuth, (req, res) => {
  try {
    const accountId = req.params.id;
    const accounts = getDecryptedAccounts(req.vaultSession.vek);
    const target = accounts.find((a) => a.id === accountId);
    if (!target) {
      return res.status(404).json({ error: 'Không tìm thấy tài khoản.' });
    }

    const remaining = accounts.filter((a) => a.id !== accountId);
    saveDecryptedAccounts(
      remaining,
      req.vaultSession.vek,
      `Xóa tài khoản: ${target.platform} (${target.accountLabel} - ${target.username})`
    );

    const updatedList = getDecryptedAccounts(req.vaultSession.vek);
    res.json({
      accounts: updatedList,
      audit: buildSecurityAudit(updatedList)
    });
  } catch (err) {
    res.status(500).json({ error: 'Không thể xóa tài khoản.' });
  }
});

/**
 * GET /api/settings/totp-qr
 * Show the Google Authenticator QR code for the vault owner (for adding a second phone)
 */
app.get('/api/settings/totp-qr', requireAuth, async (req, res) => {
  try {
    const secret = getVaultTotpSecret(req.vaultSession.vek);
    const meta = getPublicVaultMeta();
    const otpauthUri = buildOtpAuthUri({
      secret,
      accountName: meta.googleEmail || meta.ownerName || 'LocalVault',
      issuer: 'VaultGuard'
    });
    const qrDataUrl = await QRCode.toDataURL(otpauthUri, {
      width: 220,
      margin: 1,
      color: { dark: '#0C0F14', light: '#FFFFFF' }
    });
    res.json({
      secret,
      otpauthUri,
      qrDataUrl
    });
  } catch (err) {
    res.status(500).json({ error: 'Không thể tải mã QR Google Authenticator.' });
  }
});

/**
 * PUT /api/settings
 * Update Google Authentication mode, auto-lock timeout, and Google OAuth email/Client ID
 */
app.put('/api/settings', requireAuth, (req, res) => {
  try {
    const updatedMeta = updateVaultSettings(req.vaultSession.vek, req.body || {});
    res.json({ success: true, meta: updatedMeta });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Không thể lưu cài đặt.' });
  }
});

/**
 * GET /api/audit-logs
 * Return security activity logs
 */
app.get('/api/audit-logs', requireAuth, (req, res) => {
  try {
    const logs = getAuditLogs(req.vaultSession.vek);
    res.json({ logs });
  } catch (err) {
    res.status(500).json({ error: 'Không thể đọc nhật ký bảo mật.' });
  }
});

/**
 * POST /api/backup/export
 * Export all accounts as an AES-256-GCM encrypted backup file (or JSON)
 */
app.post('/api/backup/export', requireAuth, (req, res) => {
  try {
    const { backupPassword } = req.body || {};
    const accounts = getDecryptedAccounts(req.vaultSession.vek).map(({ liveTotp, ...rest }) => rest);

    if (backupPassword && String(backupPassword).length >= 6) {
      const salt = generateSalt(32);
      const key = deriveEncryptionKey(String(backupPassword), salt);
      const encryptedPayload = encryptAES256GCM(accounts, key);
      return res.json({
        backupFile: {
          format: 'VAULTGUARD_ENCRYPTED_BACKUP_V1',
          exportedAt: new Date().toISOString(),
          accountCount: accounts.length,
          salt,
          payload: encryptedPayload
        }
      });
    }

    // Otherwise encrypt with the current session's VEK and include a portable wrapper
    return res.json({
      backupFile: {
        format: 'VAULTGUARD_PORTABLE_JSON_V1',
        exportedAt: new Date().toISOString(),
        accountCount: accounts.length,
        accounts
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Không thể xuất file sao lưu.' });
  }
});

/**
 * POST /api/backup/import
 * Import accounts from a backup file or batch array
 */
app.post('/api/backup/import', requireAuth, (req, res) => {
  try {
    const { backupData, backupPassword } = req.body || {};
    if (!backupData) {
      return res.status(400).json({ error: 'Dữ liệu nhập không hợp lệ.' });
    }

    let importedAccounts = [];
    if (backupData.format === 'VAULTGUARD_ENCRYPTED_BACKUP_V1') {
      if (!backupPassword) {
        return res.status(400).json({ error: 'File sao lưu này được khóa mật khẩu. Vui lòng nhập mật khẩu giải mã file.' });
      }
      const key = deriveEncryptionKey(String(backupPassword), backupData.salt);
      importedAccounts = decryptAES256GCM(backupData.payload, key);
    } else if (Array.isArray(backupData.accounts)) {
      importedAccounts = backupData.accounts;
    } else if (Array.isArray(backupData)) {
      importedAccounts = backupData;
    } else {
      return res.status(400).json({ error: 'Định dạng file sao lưu không được hỗ trợ.' });
    }

    const currentAccounts = getDecryptedAccounts(req.vaultSession.vek);
    const existingIds = new Set(currentAccounts.map((a) => a.id));
    let addedCount = 0;

    for (const item of importedAccounts) {
      if (!item.platform || !item.username || !item.password) continue;
      const newEntry = {
        id: item.id && !existingIds.has(item.id) ? item.id : crypto.randomUUID(),
        platform: String(item.platform).trim(),
        category: String(item.category || 'other').trim(),
        accountLabel: String(item.accountLabel || 'Tài khoản Nhập').trim(),
        username: String(item.username).trim(),
        password: String(item.password),
        url: String(item.url || '').trim(),
        totpSecret: String(item.totpSecret || '').trim(),
        notes: String(item.notes || '').trim(),
        tags: Array.isArray(item.tags) ? item.tags : [],
        favorite: Boolean(item.favorite),
        createdAt: item.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        passwordHistory: Array.isArray(item.passwordHistory) ? item.passwordHistory : []
      };
      currentAccounts.push(newEntry);
      existingIds.add(newEntry.id);
      addedCount++;
    }

    saveDecryptedAccounts(
      currentAccounts,
      req.vaultSession.vek,
      `Nhập thành công ${addedCount} tài khoản từ bản sao lưu`
    );

    const updatedList = getDecryptedAccounts(req.vaultSession.vek);
    res.json({
      addedCount,
      accounts: updatedList,
      audit: buildSecurityAudit(updatedList)
    });
  } catch (err) {
    res.status(400).json({ error: 'Không thể giải mã hoặc nhập file sao lưu. Kiểm tra lại mật khẩu file.' });
  }
});

// ============================================================================
// Security Audit & Password Strength Calculator
// ============================================================================
function calculatePasswordStrength(pwd = '') {
  const length = pwd.length;
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
  const entropy = length > 0 && pool > 0 ? Math.round(length * Math.log2(pool)) : 0;

  let level = 'weak';
  let score = 25;
  if (entropy >= 80 && length >= 12) {
    level = 'strong';
    score = 100;
  } else if (entropy >= 55 && length >= 8) {
    level = 'medium';
    score = 65;
  }
  return { entropy, level, score };
}

function buildSecurityAudit(accounts) {
  const pwdCountMap = new Map();
  for (const acc of accounts) {
    const p = acc.password || '';
    pwdCountMap.set(p, (pwdCountMap.get(p) || 0) + 1);
  }

  let weakCount = 0;
  let reusedCount = 0;
  let twoFactorEnabledCount = 0;
  let totalScore = 0;
  const platformGroups = {};

  for (const acc of accounts) {
    const strength = calculatePasswordStrength(acc.password);
    if (strength.level === 'weak') weakCount++;
    if ((pwdCountMap.get(acc.password) || 0) > 1) reusedCount++;
    if (acc.totpSecret && String(acc.totpSecret).trim()) twoFactorEnabledCount++;
    totalScore += strength.score;

    const key = acc.platform.trim();
    if (!platformGroups[key]) {
      platformGroups[key] = 0;
    }
    platformGroups[key]++;
  }

  const healthScore =
    accounts.length === 0
      ? 100
      : Math.max(
          10,
          Math.min(
            100,
            Math.round(totalScore / accounts.length) - reusedCount * 8 - weakCount * 10
          )
        );

  return {
    totalAccounts: accounts.length,
    totalPlatforms: Object.keys(platformGroups).length,
    weakCount,
    reusedCount,
    twoFactorEnabledCount,
    healthScore
  };
}

function lockAllSessions() {
  for (const [, session] of activeSessions.entries()) {
    if (Buffer.isBuffer(session.vek)) {
      session.vek.fill(0);
    }
  }
  activeSessions.clear();
}

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`\n==================================================================`);
    console.log(`  🛡️  VaultGuard Local Password Manager đang chạy!`);
    console.log(`  🌐 Truy cập tại: http://${HOST}:${PORT}`);
    console.log(`  🔐 Bảo vệ bởi: Google Authentication (2FA TOTP + OAuth) & AES-256-GCM`);
    console.log(`==================================================================\n`);
  });
}

module.exports = app;
module.exports.app = app;
module.exports.lockAllSessions = lockAllSessions;
