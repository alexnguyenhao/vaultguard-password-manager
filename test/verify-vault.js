const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');

const {
  generateSalt,
  deriveEncryptionKey,
  encryptAES256GCM,
  decryptAES256GCM
} = require('../src/crypto');
const {
  generateBase32Secret,
  generateTOTP,
  verifyTOTP
} = require('../src/totp');
const app = require('../server');

function requestJson(port, method, reqPath, body = null, cookie = '') {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {
      'Content-Type': 'application/json'
    };
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload);
    if (cookie) headers['Cookie'] = cookie;

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: reqPath,
        method,
        headers
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          const setCookie = res.headers['set-cookie']
            ? res.headers['set-cookie'][0].split(';')[0]
            : '';
          let parsed = {};
          try {
            parsed = JSON.parse(raw);
          } catch {
            parsed = { raw };
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            cookie: setCookie,
            data: parsed
          });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  console.log('1. Testing AES-256-GCM encryption & tamper resistance...');
  const salt = generateSalt();
  const key = deriveEncryptionKey('MySuperStrongMasterPass!2026', salt);
  const sampleData = [{ platform: 'Gmail', username: 'test@gmail.com', password: 'SecretPassword123!' }];
  const encrypted = encryptAES256GCM(sampleData, key);
  const decrypted = decryptAES256GCM(encrypted, key);
  assert.deepStrictEqual(decrypted, sampleData, 'Decrypted data must match original');

  // Tamper test
  const tampered = { ...encrypted, tag: '00'.repeat(16) };
  assert.throws(() => decryptAES256GCM(tampered, key), 'Tampered authTag must throw error');
  console.log('   ✓ AES-256-GCM encryption & integrity check passed.');

  console.log('2. Testing Google Authenticator RFC 6238 TOTP...');
  const totpSecret = generateBase32Secret(20);
  const { code } = generateTOTP(totpSecret);
  assert.strictEqual(code.length, 6, 'TOTP must be 6 digits');
  assert.strictEqual(verifyTOTP(totpSecret, code, 1), true, 'Valid TOTP must verify');
  assert.strictEqual(verifyTOTP(totpSecret, '000000', 0) && code !== '000000', false, 'Invalid TOTP must fail');
  console.log('   ✓ Google Authenticator TOTP generation & verification passed.');

  console.log('3. Testing HTTP Server & Google Authentication Gate end-to-end...');
  const dataDir = path.join(__dirname, '..', 'data');
  const backupVaultPath = path.join(dataDir, 'vault.enc.json.bak-test');
  const vaultPath = path.join(dataDir, 'vault.enc.json');
  if (fs.existsSync(vaultPath)) {
    fs.renameSync(vaultPath, backupVaultPath);
  }

  const server = await new Promise((resolve, reject) => {
    const srv = app.listen(0, '127.0.0.1', () => resolve(srv));
    srv.on('error', reject);
  });
  const port = server.address().port;

  try {
    // 3.1 Verify unauthenticated request to /api/accounts is blocked (401)
    const unauthRes = await requestJson(port, 'GET', '/api/accounts');
    assert.strictEqual(unauthRes.status, 401, 'Unauthenticated access to /api/accounts must return 401');

    // 3.2 Fetch setup QR & secret
    const statusRes = await requestJson(port, 'GET', '/api/auth/status');
    assert.strictEqual(statusRes.data.initialized, false);
    assert.ok(statusRes.data.setupData.totpSecret, 'Setup secret must be provided');
    assert.ok(statusRes.data.setupData.qrDataUrl.startsWith('data:image/png;base64,'), 'QR Code image must be generated');

    const setupSecret = statusRes.data.setupData.totpSecret;
    const validSetupOtp = generateTOTP(setupSecret).code;

    // 3.3 Attempt setup with WRONG Google Authenticator code -> must fail
    const badSetup = await requestJson(port, 'POST', '/api/auth/setup', {
      ownerName: 'Test Vault',
      masterPassword: 'MasterPassword#2026',
      totpToken: validSetupOtp === '123456' ? '654321' : '123456',
      authMode: 'totp_and_master',
      seedSampleAccounts: true
    });
    assert.strictEqual(badSetup.status, 400, 'Setup with wrong TOTP must be rejected');

    // 3.4 Complete setup with VALID Google Authenticator 6-digit OTP
    const goodSetup = await requestJson(port, 'POST', '/api/auth/setup', {
      ownerName: 'Test Vault',
      masterPassword: 'MasterPassword#2026',
      totpToken: validSetupOtp,
      authMode: 'totp_and_master',
      seedSampleAccounts: true
    });
    assert.strictEqual(goodSetup.status, 200, 'Setup with valid TOTP must succeed');
    assert.strictEqual(goodSetup.data.recoveryCodes.length, 8, '8 recovery codes must be returned');
    const sessionCookie = goodSetup.cookie;

    // 3.5 Fetch decrypted accounts using session cookie
    const accountsRes = await requestJson(port, 'GET', '/api/accounts', null, sessionCookie);
    assert.strictEqual(accountsRes.status, 200);
    assert.strictEqual(accountsRes.data.accounts.length, 6, 'Sample accounts should be decrypted');

    // 3.6 Add a 3rd Facebook account to test multi-account per platform
    const addRes = await requestJson(
      port,
      'POST',
      '/api/accounts',
      {
        platform: 'Facebook',
        category: 'social',
        accountLabel: 'Nick Clone #3',
        username: 'clone3.fb@gmail.com',
        password: 'SuperStrong!FbClone#3_2026',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        tags: ['Clone', 'Marketing']
      },
      sessionCookie
    );
    assert.strictEqual(addRes.status, 201);
    assert.strictEqual(addRes.data.accounts.length, 7);

    // 3.7 Lock the vault (logout) and verify /api/accounts is blocked again
    await requestJson(port, 'POST', '/api/auth/logout', {}, sessionCookie);
    const afterLogout = await requestJson(port, 'GET', '/api/accounts', null, sessionCookie);
    assert.strictEqual(afterLogout.status, 401, 'Locked vault must reject access');

    // 3.8 Unlock with valid Master Password + Google Authenticator 6-digit code
    const loginOtp = generateTOTP(setupSecret).code;
    const loginRes = await requestJson(port, 'POST', '/api/auth/login', {
      masterPassword: 'MasterPassword#2026',
      totpToken: loginOtp
    });
    assert.strictEqual(loginRes.status, 200, 'Login with valid Google Authenticator OTP must succeed');
    console.log('   ✓ End-to-end Google Authentication gate & multi-account CRUD passed!');
  } finally {
    server.close();
    if (fs.existsSync(vaultPath)) {
      fs.unlinkSync(vaultPath);
    }
    if (fs.existsSync(backupVaultPath)) {
      fs.renameSync(backupVaultPath, vaultPath);
    }
  }
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
