/**
 * VaultGuard Browser Zero-Knowledge Engine (for 24/7 Static Hosting on GitHub Pages)
 * Automatically used when running on GitHub Pages (serverless static hosting)
 * Implements RFC 6238 Google Authenticator TOTP + AES-256-GCM via Web Crypto API
 */
(() => {
  'use strict';

  const STORAGE_KEY = 'vaultguard_cloud_enc_v1';
  const SESSION_KEY = 'vaultguard_cloud_session_v1';
  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function bufToHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function hexToBuf(hex) {
    const clean = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function bufToBase64(buf) {
    let bin = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function base64ToBuf(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function generateBase32Secret(byteLen = 20) {
    const bytes = new Uint8Array(byteLen);
    window.crypto.getRandomValues(bytes);
    let bits = 0;
    let value = 0;
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }
    return out;
  }

  function decodeBase32(str) {
    const cleaned = String(str || '').toUpperCase().replace(/[\s=-]+/g, '');
    let bits = 0;
    let value = 0;
    const bytes = [];
    for (let i = 0; i < cleaned.length; i++) {
      const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
      if (idx === -1) throw new Error('Mã Secret Base32 không hợp lệ');
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(bytes);
  }

  async function generateTOTP(base32Secret, timestampMs = Date.now(), stepSeconds = 30, digits = 6) {
    const keyBytes = decodeBase32(base32Secret);
    const counter = Math.floor(timestampMs / 1000 / stepSeconds);
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );
    const sig = new Uint8Array(await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuf));
    const offset = sig[sig.length - 1] & 0x0f;
    const binary =
      ((sig[offset] & 0x7f) << 24) |
      ((sig[offset + 1] & 0xff) << 16) |
      ((sig[offset + 2] & 0xff) << 8) |
      (sig[offset + 3] & 0xff);
    const code = (binary % Math.pow(10, digits)).toString().padStart(digits, '0');
    const remainingSeconds = stepSeconds - (Math.floor(timestampMs / 1000) % stepSeconds);
    return { code, remainingSeconds, stepSeconds };
  }

  async function verifyTOTP(base32Secret, tokenInput, windowSteps = 1) {
    const cleaned = String(tokenInput || '').replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleaned)) return false;
    const now = Date.now();
    for (let w = -windowSteps; w <= windowSteps; w++) {
      const { code } = await generateTOTP(base32Secret, now + w * 30000);
      if (code === cleaned) return true;
    }
    return false;
  }

  async function deriveAesKey(password, saltHex) {
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: hexToBuf(saltHex),
        iterations: 120000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptJson(data, cryptoKey) {
    const iv = new Uint8Array(12);
    window.crypto.getRandomValues(iv);
    const encoded = new TextEncoder().encode(JSON.stringify(data));
    const cipherBuf = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      encoded
    );
    return {
      alg: 'AES-256-GCM-WEBCRYPTO',
      iv: bufToHex(iv),
      ciphertext: bufToBase64(cipherBuf)
    };
  }

  async function decryptJson(payload, cryptoKey) {
    const iv = hexToBuf(payload.iv);
    const cipherBuf = base64ToBuf(payload.ciphertext);
    const plainBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      cipherBuf
    );
    return JSON.parse(new TextDecoder().decode(plainBuf));
  }

  function buildOtpAuthUri({ secret, accountName = 'WebVault', issuer = 'VaultGuard' }) {
    const params = new URLSearchParams({
      secret,
      issuer,
      algorithm: 'SHA1',
      digits: '6',
      period: '30'
    });
    return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?${params.toString()}`;
  }

  function makeQrUrl(otpauthUri) {
    return `https://api.qrserver.com/v1/create-qr-code/?size=220x220&margin=8&data=${encodeURIComponent(otpauthUri)}`;
  }

  function generateRecoveryCodes(count = 8) {
    const chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    const codes = [];
    for (let i = 0; i < count; i++) {
      const rand = new Uint8Array(12);
      window.crypto.getRandomValues(rand);
      let s = '';
      for (let j = 0; j < 12; j++) {
        if (j > 0 && j % 4 === 0) s += '-';
        s += chars[rand[j] % chars.length];
      }
      codes.push(s);
    }
    return codes;
  }

  function getSampleAccounts() {
    const now = new Date().toISOString();
    return [
      {
        id: crypto.randomUUID(),
        platform: 'Google / Gmail',
        category: 'email',
        accountLabel: 'Tài khoản Chính (Cá nhân)',
        username: 'alex.personal@gmail.com',
        password: 'Gm!98#Personal$VaultKey2026',
        url: 'https://mail.google.com',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        notes: 'Email chính liên kết ngân hàng và Google Drive.',
        tags: ['Chính', 'Quan trọng', '2FA'],
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
        notes: 'Bật xác thực 2 bước.',
        tags: ['Mạng xã hội', 'Chính'],
        favorite: true,
        createdAt: now,
        updatedAt: now,
        passwordHistory: []
      },
      {
        id: crypto.randomUUID(),
        platform: 'GitHub',
        category: 'dev',
        accountLabel: 'GitHub Cá nhân',
        username: 'alexnguyenhao',
        password: 'Gh$Personal_99182!RepoKey',
        url: 'https://github.com/alexnguyenhao',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        notes: 'Tài khoản GitHub chính.',
        tags: ['Dev', 'Code', '2FA'],
        favorite: true,
        createdAt: now,
        updatedAt: now,
        passwordHistory: []
      }
    ];
  }

  function calculatePasswordStrength(pwd = '') {
    const length = pwd.length;
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
    const entropy = length > 0 && pool > 0 ? Math.round(length * Math.log2(pool)) : 0;
    if (entropy >= 80 && length >= 12) return { entropy, level: 'strong', score: 100 };
    if (entropy >= 55 && length >= 8) return { entropy, level: 'medium', score: 65 };
    return { entropy, level: 'weak', score: 25 };
  }

  function buildAudit(accounts) {
    const pwdMap = new Map();
    accounts.forEach((a) => pwdMap.set(a.password, (pwdMap.get(a.password) || 0) + 1));
    let weakCount = 0;
    let reusedCount = 0;
    let twoFactorEnabledCount = 0;
    let totalScore = 0;
    for (const acc of accounts) {
      const st = calculatePasswordStrength(acc.password);
      if (st.level === 'weak') weakCount++;
      if ((pwdMap.get(acc.password) || 0) > 1) reusedCount++;
      if (acc.totpSecret) twoFactorEnabledCount++;
      totalScore += st.score;
    }
    const healthScore =
      accounts.length === 0
        ? 100
        : Math.max(10, Math.min(100, Math.round(totalScore / accounts.length) - reusedCount * 8 - weakCount * 10));
    return {
      totalAccounts: accounts.length,
      weakCount,
      reusedCount,
      twoFactorEnabledCount,
      healthScore
    };
  }

  // In-memory unlocked key & pending setup state
  let unlockedCryptoKey = null;
  let pendingSecret = sessionStorage.getItem('vg_pending_secret') || '';

  async function getUnlockedKey() {
    if (unlockedCryptoKey) return unlockedCryptoKey;
    const rawJwk = sessionStorage.getItem(SESSION_KEY);
    if (!rawJwk) return null;
    try {
      unlockedCryptoKey = await window.crypto.subtle.importKey(
        'jwk',
        JSON.parse(rawJwk),
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      return unlockedCryptoKey;
    } catch {
      return null;
    }
  }

  async function setUnlockedKey(key) {
    unlockedCryptoKey = key;
    if (!key) {
      sessionStorage.removeItem(SESSION_KEY);
      return;
    }
    const jwk = await window.crypto.subtle.exportKey('jwk', key);
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(jwk));
  }

  function loadStoredVault() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  function saveStoredVault(vault) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
  }

  async function enrichAccountsWithTotp(accounts) {
    const out = [];
    for (const acc of accounts) {
      let liveTotp = null;
      if (acc.totpSecret && String(acc.totpSecret).trim()) {
        try {
          liveTotp = await generateTOTP(acc.totpSecret);
        } catch {
          liveTotp = null;
        }
      }
      out.push({ ...acc, liveTotp });
    }
    return out;
  }

  /**
   * Handle API requests purely in the browser when no Node.js server is present (e.g. GitHub Pages 24/7)
   */
  window.vaultBrowserEngine = {
    async handleRequest(url, options = {}) {
      const method = (options.method || 'GET').toUpperCase();
      const body = options.body ? JSON.parse(options.body) : {};
      const vault = loadStoredVault();
      const activeKey = await getUnlockedKey();

      if (url === '/api/auth/status' && method === 'GET') {
        if (!vault) {
          if (!pendingSecret) {
            pendingSecret = generateBase32Secret(20);
            sessionStorage.setItem('vg_pending_secret', pendingSecret);
          }
          const otpauthUri = buildOtpAuthUri({ secret: pendingSecret });
          const currentOtpPreview = await generateTOTP(pendingSecret);
          return {
            initialized: false,
            unlocked: false,
            setupData: {
              totpSecret: pendingSecret,
              otpauthUri,
              qrDataUrl: makeQrUrl(otpauthUri),
              currentOtpPreview
            }
          };
        }
        return {
          initialized: true,
          unlocked: Boolean(activeKey),
          meta: vault.meta
        };
      }

      if (url === '/api/auth/setup-otp-preview' && method === 'GET') {
        if (!pendingSecret) throw new Error('Không có phiên thiết lập');
        return await generateTOTP(pendingSecret);
      }

      if (url === '/api/auth/setup' && method === 'POST') {
        const { ownerName, authMode, googleEmail, googleClientId, masterPassword, totpToken, seedSampleAccounts } = body;
        if (!masterPassword || masterPassword.length < 6) {
          throw new Error('Master Password phải từ 6 ký tự trở lên.');
        }
        const valid = await verifyTOTP(pendingSecret, totpToken, 1);
        if (!valid) {
          throw new Error('Mã 6 số Google Authenticator không chính xác hoặc đã hết hạn.');
        }

        const saltBytes = new Uint8Array(16);
        window.crypto.getRandomValues(saltBytes);
        const saltHex = bufToHex(saltBytes);
        const key = await deriveAesKey(masterPassword, saltHex);
        const exportedJwk = await window.crypto.subtle.exportKey('jwk', key);

        const recoveryCodes = generateRecoveryCodes(8);
        const initialAccounts = seedSampleAccounts ? getSampleAccounts() : [];
        const encryptedAccounts = await encryptJson(initialAccounts, key);
        const now = new Date().toISOString();

        const newVault = {
          meta: {
            initialized: true,
            ownerName: ownerName || 'Kho Mật Khẩu Cá Nhân',
            authMode: authMode || 'totp_and_master',
            googleEmail: googleEmail || '',
            googleClientId: googleClientId || '',
            autoLockMinutes: 15,
            createdAt: now,
            updatedAt: now
          },
          saltHex,
          totpSecret: pendingSecret,
          recoveryCodes,
          wrappedKeyJwk: authMode === 'totp_only' ? exportedJwk : null,
          encryptedAccounts,
          auditLogs: [
            {
              id: crypto.randomUUID(),
              timestamp: now,
              event: 'VAULT_INITIALIZED',
              detail: 'Khởi tạo kho mật khẩu trên trình duyệt (WebCrypto AES-256-GCM)'
            }
          ]
        };

        saveStoredVault(newVault);
        await setUnlockedKey(key);
        sessionStorage.removeItem('vg_pending_secret');
        return {
          success: true,
          recoveryCodes,
          meta: newVault.meta
        };
      }

      if (url === '/api/auth/login' && method === 'POST') {
        if (!vault) throw new Error('Kho chưa được khởi tạo.');
        const { masterPassword, totpToken, recoveryCode } = body;

        if (recoveryCode) {
          const idx = (vault.recoveryCodes || []).indexOf(recoveryCode.trim().toUpperCase());
          if (idx === -1) throw new Error('Mã khôi phục dự phòng không đúng hoặc đã dùng.');
          vault.recoveryCodes.splice(idx, 1);
        } else {
          const ok = await verifyTOTP(vault.totpSecret, totpToken, 1);
          if (!ok) throw new Error('Mã 6 số Google Authenticator không đúng hoặc đã hết hạn.');
        }

        let key;
        if (vault.meta.authMode === 'totp_only' && vault.wrappedKeyJwk) {
          key = await window.crypto.subtle.importKey(
            'jwk',
            vault.wrappedKeyJwk,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
          );
        } else {
          if (!masterPassword) throw new Error('Vui lòng nhập Master Password.');
          key = await deriveAesKey(masterPassword, vault.saltHex);
        }

        try {
          await decryptJson(vault.encryptedAccounts, key);
        } catch {
          throw new Error('Mật khẩu chính (Master Password) không chính xác.');
        }

        vault.auditLogs = vault.auditLogs || [];
        vault.auditLogs.unshift({
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          event: 'VAULT_UNLOCKED',
          detail: 'Mở khóa kho thành công qua Google Authentication'
        });
        saveStoredVault(vault);
        await setUnlockedKey(key);
        return { success: true, meta: vault.meta };
      }

      if (url === '/api/auth/logout' && method === 'POST') {
        await setUnlockedKey(null);
        return { success: true };
      }

      // Protected routes below
      if (!vault || !activeKey) {
        throw new Error('Phiên làm việc đã khóa. Vui lòng đăng nhập lại.');
      }

      const rawAccounts = await decryptJson(vault.encryptedAccounts, activeKey);

      if (url === '/api/accounts' && method === 'GET') {
        const accounts = await enrichAccountsWithTotp(rawAccounts);
        return { accounts, audit: buildAudit(accounts), meta: vault.meta };
      }

      if (url === '/api/accounts/totp-refresh' && method === 'GET') {
        const accounts = await enrichAccountsWithTotp(rawAccounts);
        const totpMap = {};
        accounts.forEach((a) => {
          if (a.liveTotp) totpMap[a.id] = a.liveTotp;
        });
        return { totpMap };
      }

      if (url === '/api/accounts' && method === 'POST') {
        const now = new Date().toISOString();
        const newAcc = {
          id: crypto.randomUUID(),
          platform: String(body.platform || '').trim(),
          category: String(body.category || 'other'),
          accountLabel: String(body.accountLabel || 'Tài khoản Chính').trim(),
          username: String(body.username || '').trim(),
          password: String(body.password || ''),
          url: String(body.url || '').trim(),
          totpSecret: String(body.totpSecret || '').trim(),
          notes: String(body.notes || '').trim(),
          tags: String(body.tags || '')
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean),
          favorite: Boolean(body.favorite),
          createdAt: now,
          updatedAt: now,
          passwordHistory: []
        };
        rawAccounts.unshift(newAcc);
        vault.encryptedAccounts = await encryptJson(rawAccounts, activeKey);
        saveStoredVault(vault);
        const accounts = await enrichAccountsWithTotp(rawAccounts);
        return { account: newAcc, accounts, audit: buildAudit(accounts) };
      }

      if (url.startsWith('/api/accounts/') && method === 'PUT') {
        const id = decodeURIComponent(url.replace('/api/accounts/', ''));
        const idx = rawAccounts.findIndex((a) => a.id === id);
        if (idx === -1) throw new Error('Không tìm thấy tài khoản.');
        rawAccounts[idx] = {
          ...rawAccounts[idx],
          ...body,
          tags: Array.isArray(body.tags)
            ? body.tags
            : String(body.tags || '')
                .split(',')
                .map((t) => t.trim())
                .filter(Boolean),
          updatedAt: new Date().toISOString()
        };
        vault.encryptedAccounts = await encryptJson(rawAccounts, activeKey);
        saveStoredVault(vault);
        const accounts = await enrichAccountsWithTotp(rawAccounts);
        return { account: rawAccounts[idx], accounts, audit: buildAudit(accounts) };
      }

      if (url.startsWith('/api/accounts/') && method === 'DELETE') {
        const id = decodeURIComponent(url.replace('/api/accounts/', ''));
        const filtered = rawAccounts.filter((a) => a.id !== id);
        vault.encryptedAccounts = await encryptJson(filtered, activeKey);
        saveStoredVault(vault);
        const accounts = await enrichAccountsWithTotp(filtered);
        return { accounts, audit: buildAudit(accounts) };
      }

      if (url === '/api/settings/totp-qr' && method === 'GET') {
        const otpauthUri = buildOtpAuthUri({
          secret: vault.totpSecret,
          accountName: vault.meta.ownerName
        });
        return {
          secret: vault.totpSecret,
          otpauthUri,
          qrDataUrl: makeQrUrl(otpauthUri)
        };
      }

      if (url === '/api/settings' && method === 'PUT') {
        vault.meta = { ...vault.meta, ...body };
        if (vault.meta.authMode === 'totp_only') {
          vault.wrappedKeyJwk = await window.crypto.subtle.exportKey('jwk', activeKey);
        }
        saveStoredVault(vault);
        return { success: true, meta: vault.meta };
      }

      if (url === '/api/audit-logs' && method === 'GET') {
        return { logs: vault.auditLogs || [] };
      }

      if (url === '/api/backup/export' && method === 'POST') {
        return {
          backupFile: {
            format: 'VAULTGUARD_PORTABLE_JSON_V1',
            exportedAt: new Date().toISOString(),
            accountCount: rawAccounts.length,
            accounts: rawAccounts
          }
        };
      }

      if (url === '/api/backup/import' && method === 'POST') {
        const imported = body.backupData?.accounts || body.backupData || [];
        let addedCount = 0;
        for (const item of imported) {
          if (!item.platform || !item.username || !item.password) continue;
          rawAccounts.push({ ...item, id: crypto.randomUUID() });
          addedCount++;
        }
        vault.encryptedAccounts = await encryptJson(rawAccounts, activeKey);
        saveStoredVault(vault);
        const accounts = await enrichAccountsWithTotp(rawAccounts);
        return { addedCount, accounts, audit: buildAudit(accounts) };
      }

      throw new Error('Endpoint không hỗ trợ');
    }
  };
})();
