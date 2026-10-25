(() => {
  'use strict';

  // ==========================================================================
  // Application State
  // ==========================================================================
  const state = {
    initialized: false,
    unlocked: false,
    meta: null,
    accounts: [],
    audit: null,
    activeCategory: 'all', // 'all' | 'favorites' | 'email' | 'social' | 'finance' | 'dev' | 'gaming' | 'shopping'
    securityFilter: null,  // null | 'weak' | 'reused'
    searchQuery: '',
    viewMode: 'grouped',   // 'grouped' | 'table'
    revealedPasswords: new Set(),
    recoveryMode: false,
    googleAuthNonce: null,
    lastRecoveryCodes: [],
    clipboardInterval: null,
    setupOtpPollTimer: null,
    vaultTotpPollTimer: null
  };

  // ==========================================================================
  // Utility & XSS-Safe Helpers (following security-and-hardening skill)
  // ==========================================================================
  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function showToast(message, isError = false) {
    const container = document.getElementById('toastContainer');
    const item = document.createElement('div');
    item.className = `toast-item${isError ? ' error' : ''}`;
    item.textContent = message;
    container.appendChild(item);
    setTimeout(() => {
      item.remove();
    }, 3400);
  }

  let useBrowserFallbackEngine =
    window.location.hostname.endsWith('github.io') ||
    window.location.protocol === 'file:';

  async function apiRequest(url, options = {}) {
    if (useBrowserFallbackEngine && window.vaultBrowserEngine) {
      return await window.vaultBrowserEngine.handleRequest(url, options);
    }
    try {
      const res = await fetch(url, {
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        ...options
      });
      const contentType = res.headers.get('content-type') || '';
      if (res.status === 404 && !contentType.includes('application/json') && window.vaultBrowserEngine) {
        // Static hosting detected -> switch automatically to 24/7 Browser WebCrypto Engine
        useBrowserFallbackEngine = true;
        return await window.vaultBrowserEngine.handleRequest(url, options);
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 401 && state.unlocked) {
          state.unlocked = false;
          showLoginView();
        }
        throw new Error(data.error || `Lỗi yêu cầu (${res.status})`);
      }
      return data;
    } catch (err) {
      if (err instanceof TypeError && window.vaultBrowserEngine) {
        useBrowserFallbackEngine = true;
        return await window.vaultBrowserEngine.handleRequest(url, options);
      }
      throw err;
    }
  }

  function copyWithAutoClear(text, label = 'Mật khẩu', autoClearSeconds = 20) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`Đã sao chép ${label} vào bộ nhớ tạm!`);
      if (autoClearSeconds > 0) {
        startClipboardAutoClear(text, autoClearSeconds);
      }
    }).catch(() => {
      showToast('Không thể truy cập Clipboard.', true);
    });
  }

  function startClipboardAutoClear(copiedSecret, seconds = 20) {
    const banner = document.getElementById('clipboardBanner');
    const timerEl = document.getElementById('clipboardTimer');
    if (state.clipboardInterval) clearInterval(state.clipboardInterval);

    let remaining = seconds;
    timerEl.textContent = String(remaining);
    banner.classList.remove('hidden');

    state.clipboardInterval = setInterval(async () => {
      remaining -= 1;
      timerEl.textContent = String(remaining);
      if (remaining <= 0) {
        clearInterval(state.clipboardInterval);
        state.clipboardInterval = null;
        banner.classList.add('hidden');
        try {
          await navigator.clipboard.writeText('');
          showToast('Đã tự động xóa mật khẩu khỏi Clipboard để bảo mật.');
        } catch {
          // Ignore if browser tab not focused
        }
      }
    }, 1000);
  }

  function evaluatePasswordStrength(pwd = '') {
    const len = pwd.length;
    if (!len) return { score: 0, level: 'weak', label: 'Chưa nhập', entropy: 0 };
    let pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 32;
    const entropy = Math.round(len * Math.log2(pool || 1));

    if (entropy >= 80 && len >= 12) {
      return { score: 100, level: 'strong', label: `Rất mạnh (${entropy} bits)`, entropy };
    }
    if (entropy >= 55 && len >= 8) {
      return { score: 65, level: 'medium', label: `Khá (${entropy} bits)`, entropy };
    }
    return { score: 28, level: 'weak', label: `Yếu (${entropy} bits)`, entropy };
  }

  function generateSecurePassword(length = 20, opts = { upper: true, lower: true, digits: true, symbols: true }) {
    let chars = '';
    if (opts.upper) chars += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    if (opts.lower) chars += 'abcdefghijkmnopqrstuvwxyz';
    if (opts.digits) chars += '23456789';
    if (opts.symbols) chars += '!@#$%^&*()-_=+[]{}?';
    if (!chars) chars = 'abcdefghijkmnopqrstuvwxyz23456789';

    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);
    let out = '';
    for (let i = 0; i < length; i++) {
      out += chars[randomValues[i] % chars.length];
    }
    return out;
  }

  // ==========================================================================
  // View Switching & Initialization
  // ==========================================================================
  async function bootstrapApp() {
    bindAllEvents();
    await initElectronDesktopBridge();
    if (!window.vaultDesktop || !window.vaultDesktop.isElectron) {
      const ribbon = document.getElementById('webDownloadRibbon');
      if (ribbon) ribbon.classList.remove('hidden');
    }
    try {
      const status = await apiRequest('/api/auth/status');
      state.initialized = status.initialized;
      state.unlocked = status.unlocked;
      state.meta = status.meta || null;

      if (!status.initialized) {
        showSetupView(status.setupData);
      } else if (!status.unlocked) {
        showLoginView();
      } else {
        await enterVaultWorkspace();
      }
    } catch (err) {
      showToast(err.message || 'Không thể kết nối máy chủ VaultGuard.', true);
    }
  }

  function stopPollingTimers() {
    if (state.setupOtpPollTimer) {
      clearInterval(state.setupOtpPollTimer);
      state.setupOtpPollTimer = null;
    }
    if (state.vaultTotpPollTimer) {
      clearInterval(state.vaultTotpPollTimer);
      state.vaultTotpPollTimer = null;
    }
  }

  function showSetupView(setupData) {
    stopPollingTimers();
    document.getElementById('setupView').classList.remove('hidden');
    document.getElementById('loginView').classList.add('hidden');
    document.getElementById('vaultWorkspace').classList.add('hidden');

    if (setupData) {
      document.getElementById('setupQrImage').src = setupData.qrDataUrl;
      document.getElementById('setupSecretText').textContent = setupData.totpSecret;
      if (setupData.currentOtpPreview) {
        document.getElementById('setupLiveOtpCode').textContent = setupData.currentOtpPreview.code;
        document.getElementById('setupLiveOtpCountdown').textContent = `${setupData.currentOtpPreview.remainingSeconds}s`;
      }
    }

    state.setupOtpPollTimer = setInterval(async () => {
      try {
        const preview = await apiRequest('/api/auth/setup-otp-preview');
        document.getElementById('setupLiveOtpCode').textContent = preview.code;
        document.getElementById('setupLiveOtpCountdown').textContent = `${preview.remainingSeconds}s`;
      } catch {
        // Ignore
      }
    }, 1000);
  }

  function showLoginView() {
    stopPollingTimers();
    document.getElementById('setupView').classList.add('hidden');
    document.getElementById('vaultWorkspace').classList.add('hidden');
    document.getElementById('loginView').classList.remove('hidden');

    const meta = state.meta || {};
    document.getElementById('loginVaultTitle').textContent = meta.ownerName || 'VaultGuard Local';

    const masterGroup = document.getElementById('loginMasterPasswordGroup');
    const oauthSection = document.getElementById('googleOAuthLoginSection');
    const subtitle = document.getElementById('loginModeSubtitle');

    if (meta.authMode === 'totp_only') {
      masterGroup.classList.add('hidden');
      oauthSection.classList.add('hidden');
      subtitle.innerHTML = 'Nhập mã <strong>6 chữ số từ ứng dụng Google Authenticator</strong> trên điện thoại của bạn để mở khóa nhanh.';
    } else if (meta.authMode === 'google_oauth_and_totp') {
      oauthSection.classList.remove('hidden');
      masterGroup.classList.remove('hidden');
      subtitle.innerHTML = 'Đăng nhập bằng <strong>Tài khoản Google</strong> (hoặc Master Password) kèm mã <strong>6 số Google Authenticator</strong>.';
      initGoogleIdentityButton(meta.googleClientId);
    } else {
      masterGroup.classList.remove('hidden');
      oauthSection.classList.add('hidden');
      subtitle.innerHTML = 'Nhập <strong>Master Password</strong> và mã <strong>6 số từ Google Authenticator</strong> để giải mã kho.';
    }

    clearOtpDigits();
    // Focus first field
    if (meta.authMode === 'totp_only') {
      const firstDigit = document.querySelector('.otp-digit[data-index="0"]');
      if (firstDigit) firstDigit.focus();
    } else {
      document.getElementById('loginMasterPassword').focus();
    }
  }

  function initGoogleIdentityButton(clientId) {
    const container = document.getElementById('googleSignInButtonContainer');
    const statusEl = document.getElementById('googleOAuthStatus');
    container.innerHTML = '';

    if (!clientId) {
      statusEl.textContent = 'Chưa cấu hình Google Client ID (Bạn có thể dùng Master Password + Mã 6 số Google Authenticator bên dưới)';
      return;
    }

    if (window.google && window.google.accounts && window.google.accounts.id) {
      window.google.accounts.id.initialize({
        client_id: clientId,
        callback: async (response) => {
          try {
            const res = await apiRequest('/api/auth/google-verify', {
              method: 'POST',
              body: JSON.stringify({ credential: response.credential })
            });
            state.googleAuthNonce = res.googleAuthNonce;
            statusEl.textContent = `✓ Đã xác thực Google: ${res.email}. Bây giờ hãy nhập 6 số Google Authenticator!`;
            statusEl.classList.add('verified');
            document.getElementById('loginMasterPasswordGroup').classList.add('hidden');
            const firstDigit = document.querySelector('.otp-digit[data-index="0"]');
            if (firstDigit) firstDigit.focus();
          } catch (err) {
            showToast(err.message, true);
          }
        }
      });
      window.google.accounts.id.renderButton(container, {
        theme: 'filled_black',
        size: 'large',
        text: 'signin_with',
        shape: 'rectangular'
      });
    }
  }

  async function enterVaultWorkspace() {
    stopPollingTimers();
    document.getElementById('setupView').classList.add('hidden');
    document.getElementById('loginView').classList.add('hidden');
    document.getElementById('vaultWorkspace').classList.remove('hidden');

    await loadVaultAccounts();

    // Poll every 1 second to update countdowns for accounts that have 2FA TOTP secrets
    state.vaultTotpPollTimer = setInterval(async () => {
      const hasAnyTotp = state.accounts.some((a) => a.totpSecret && a.totpSecret.trim());
      if (!hasAnyTotp || !state.unlocked) return;
      try {
        const { totpMap } = await apiRequest('/api/accounts/totp-refresh');
        for (const acc of state.accounts) {
          if (totpMap[acc.id]) {
            acc.liveTotp = totpMap[acc.id];
          }
        }
        updateLiveTotpBadgesInDom(totpMap);
      } catch {
        // Ignore transient error
      }
    }, 1000);
  }

  async function loadVaultAccounts() {
    const data = await apiRequest('/api/accounts');
    state.accounts = data.accounts || [];
    state.audit = data.audit || {};
    state.meta = data.meta || state.meta;
    state.unlocked = true;

    document.getElementById('sidebarVaultName').textContent =
      state.meta?.ownerName || 'VaultGuard Local';

    renderSidebarStats();
    renderAccountsView();
  }

  // ==========================================================================
  // Rendering Sidebar Stats & Multi-Platform Accounts
  // ==========================================================================
  function renderSidebarStats() {
    const audit = state.audit || {};
    const score = audit.healthScore ?? 100;
    const scoreEl = document.getElementById('healthScoreValue');
    const fillEl = document.getElementById('healthBarFill');

    scoreEl.textContent = `${score}/100`;
    fillEl.style.width = `${score}%`;
    fillEl.style.background =
      score >= 80 ? 'var(--accent-emerald)' : score >= 50 ? 'var(--accent-amber)' : 'var(--accent-crimson)';

    document.getElementById('statTotalAccounts').textContent = String(audit.totalAccounts || 0);
    document.getElementById('statWeakAccounts').textContent = String(audit.weakCount || 0);
    document.getElementById('statReusedAccounts').textContent = String(audit.reusedCount || 0);

    // Category counts
    const counts = {
      all: state.accounts.length,
      favorites: 0,
      email: 0,
      social: 0,
      finance: 0,
      dev: 0,
      gaming: 0,
      shopping: 0
    };

    for (const acc of state.accounts) {
      if (acc.favorite) counts.favorites++;
      const cat = acc.category || 'shopping';
      if (counts[cat] !== undefined) counts[cat]++;
      else counts.shopping++;
    }

    document.getElementById('countAll').textContent = String(counts.all);
    document.getElementById('countFavorites').textContent = String(counts.favorites);
    document.getElementById('countEmail').textContent = String(counts.email);
    document.getElementById('countSocial').textContent = String(counts.social);
    document.getElementById('countFinance').textContent = String(counts.finance);
    document.getElementById('countDev').textContent = String(counts.dev);
    document.getElementById('countGaming').textContent = String(counts.gaming);
    document.getElementById('countShopping').textContent = String(counts.shopping);
  }

  function getFilteredAccounts() {
    // Count password occurrences for reused detection
    const pwdCounts = new Map();
    for (const acc of state.accounts) {
      pwdCounts.set(acc.password, (pwdCounts.get(acc.password) || 0) + 1);
    }

    return state.accounts.filter((acc) => {
      // Category filter
      if (state.activeCategory === 'favorites' && !acc.favorite) return false;
      if (
        state.activeCategory !== 'all' &&
        state.activeCategory !== 'favorites' &&
        acc.category !== state.activeCategory
      ) {
        return false;
      }

      // Security health filter
      if (state.securityFilter === 'weak') {
        const st = evaluatePasswordStrength(acc.password);
        if (st.level !== 'weak') return false;
      } else if (state.securityFilter === 'reused') {
        if ((pwdCounts.get(acc.password) || 0) <= 1) return false;
      }

      // Search query filter
      if (state.searchQuery) {
        const q = state.searchQuery.toLowerCase();
        const hay = [
          acc.platform,
          acc.accountLabel,
          acc.username,
          acc.url,
          acc.notes,
          ...(acc.tags || [])
        ]
          .join(' ')
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }

      return true;
    });
  }

  function renderAccountsView() {
    const container = document.getElementById('accountsContainer');
    const filtered = getFilteredAccounts();

    // Update active filter strip
    const filterStrip = document.getElementById('activeFilterStrip');
    const filterText = document.getElementById('activeFilterText');
    if (state.securityFilter || state.searchQuery) {
      filterStrip.classList.remove('hidden');
      const parts = [];
      if (state.securityFilter === 'weak') parts.push('Cảnh báo: Mật khẩu yếu');
      if (state.securityFilter === 'reused') parts.push('Cảnh báo: Mật khẩu bị dùng trùng lặp');
      if (state.searchQuery) parts.push(`Từ khóa: "${state.searchQuery}"`);
      filterText.textContent = `Đang lọc (${filtered.length} kết quả) — ${parts.join(' • ')}`;
    } else {
      filterStrip.classList.add('hidden');
    }

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="empty-vault-state">
          <h3>Chưa có tài khoản nào trong mục này</h3>
          <p>Bạn có thể lưu nhiều tài khoản cho cùng một nền tảng (VD: 5 Gmail, 3 Facebook, GitHub, Ngân hàng...) và tất cả đều được mã hóa AES-256-GCM.</p>
          <button type="button" class="btn-primary" id="emptyAddAccountBtn">+ Thêm Tài Khoản Đầu Tiên</button>
        </div>
      `;
      const btn = document.getElementById('emptyAddAccountBtn');
      if (btn) btn.addEventListener('click', () => openAccountModal());
      return;
    }

    if (state.viewMode === 'table') {
      renderFlatTable(container, filtered);
    } else {
      renderPlatformGroupedCards(container, filtered);
    }
  }

  function renderPlatformGroupedCards(container, accounts) {
    // Group accounts by platform name (case-insensitive key)
    const groupsMap = new Map();
    for (const acc of accounts) {
      const key = acc.platform.trim();
      if (!groupsMap.has(key)) {
        groupsMap.set(key, []);
      }
      groupsMap.get(key).push(acc);
    }

    let html = '';
    for (const [platformName, platformAccounts] of groupsMap.entries()) {
      const initial = escapeHtml(platformName.charAt(0).toUpperCase());
      const firstCategory = escapeHtml(platformAccounts[0].category || 'other');

      html += `
        <article class="platform-group-card">
          <header class="platform-group-header">
            <div class="platform-title-wrap">
              <div class="platform-avatar">${initial}</div>
              <div>
                <h3>${escapeHtml(platformName)}</h3>
              </div>
              <span class="account-count-pill">${platformAccounts.length} tài khoản</span>
            </div>
            <button
              type="button"
              class="btn-mini"
              data-action="add-same-platform"
              data-platform="${escapeHtml(platformName)}"
              data-category="${firstCategory}"
            >
              + Thêm nick ${escapeHtml(platformName)} khác
            </button>
          </header>
          <div class="accounts-grid">
            ${platformAccounts.map((acc) => buildAccountCardHtml(acc)).join('')}
          </div>
        </article>
      `;
    }

    container.innerHTML = html;
  }

  function buildAccountCardHtml(acc) {
    const isRevealed = state.revealedPasswords.has(acc.id);
    const displayedPassword = isRevealed ? escapeHtml(acc.password) : '••••••••••••••••';
    const strength = evaluatePasswordStrength(acc.password);
    const favStar = acc.favorite ? '<span class="fav-star" title="Quan trọng">★</span>' : '';

    let totpSectionHtml = '';
    if (acc.liveTotp) {
      totpSectionHtml = `
        <div class="credential-field-row totp-live-row">
          <div class="cred-meta">
            <span class="cred-label">Mã 2FA TOTP (${acc.liveTotp.remainingSeconds}s)</span>
            <div class="totp-code-display" data-totp-code="${escapeHtml(acc.id)}">${escapeHtml(acc.liveTotp.code)}</div>
          </div>
          <div class="cred-buttons">
            <span class="otp-countdown-badge" data-totp-timer="${escapeHtml(acc.id)}">${acc.liveTotp.remainingSeconds}s</span>
            <button type="button" class="btn-icon" data-action="copy-totp" data-id="${escapeHtml(acc.id)}">Copy 2FA</button>
          </div>
        </div>
      `;
    }

    const tagsHtml = (acc.tags || [])
      .map((t) => `<span class="tag-chip">${escapeHtml(t)}</span>`)
      .join('');

    const notesHtml = acc.notes
      ? `<div style="font-size:12px;color:var(--text-secondary);background:var(--bg-surface);padding:6px 10px;border-radius:6px;">📝 ${escapeHtml(acc.notes)}</div>`
      : '';

    return `
      <div class="account-card" data-card-id="${escapeHtml(acc.id)}">
        <div class="account-card-top">
          <div class="account-label-badge">
            ${favStar}
            <span>${escapeHtml(acc.accountLabel || 'Tài khoản Chính')}</span>
          </div>
          <div class="account-actions-top">
            ${
              acc.url
                ? `<a href="${escapeHtml(acc.url)}" target="_blank" rel="noopener noreferrer" class="btn-icon" title="Mở trang web">Mở Web ↗</a>`
                : ''
            }
            <button type="button" class="btn-icon" data-action="edit-account" data-id="${escapeHtml(acc.id)}">Sửa</button>
            <button type="button" class="btn-icon" style="color:var(--accent-crimson);border-color:rgba(239,68,68,0.3);" data-action="delete-account" data-id="${escapeHtml(acc.id)}">Xóa</button>
          </div>
        </div>

        <!-- Username Row -->
        <div class="credential-field-row">
          <div class="cred-meta">
            <span class="cred-label">Tài khoản / Email / SĐT</span>
            <div class="cred-value" title="${escapeHtml(acc.username)}">${escapeHtml(acc.username)}</div>
          </div>
          <div class="cred-buttons">
            <button type="button" class="btn-icon" data-action="copy-username" data-id="${escapeHtml(acc.id)}">Copy</button>
          </div>
        </div>

        <!-- Password Row -->
        <div class="credential-field-row">
          <div class="cred-meta">
            <span class="cred-label">Mật khẩu (AES-256-GCM)</span>
            <div class="cred-value">${displayedPassword}</div>
          </div>
          <div class="cred-buttons">
            <button type="button" class="btn-icon" data-action="toggle-reveal" data-id="${escapeHtml(acc.id)}">
              ${isRevealed ? 'Ẩn' : 'Hiện'}
            </button>
            <button type="button" class="btn-icon" data-action="copy-password" data-id="${escapeHtml(acc.id)}">Copy</button>
          </div>
        </div>

        ${totpSectionHtml}
        ${notesHtml}

        <div class="account-card-footer">
          <div class="tag-list">${tagsHtml}</div>
          <span class="strength-badge ${strength.level}">${strength.label}</span>
        </div>
      </div>
    `;
  }

  function renderFlatTable(container, accounts) {
    const rowsHtml = accounts
      .map((acc) => {
        const isRevealed = state.revealedPasswords.has(acc.id);
        const pwdDisplay = isRevealed ? escapeHtml(acc.password) : '••••••••••••';
        const strength = evaluatePasswordStrength(acc.password);

        return `
          <tr>
            <td><strong>${escapeHtml(acc.platform)}</strong></td>
            <td><span class="account-label-badge">${escapeHtml(acc.accountLabel)}</span></td>
            <td class="mono-text">${escapeHtml(acc.username)}</td>
            <td class="mono-text">${pwdDisplay}</td>
            <td><span class="strength-badge ${strength.level}">${strength.label}</span></td>
            <td>
              <div style="display:flex;gap:6px;">
                <button type="button" class="btn-icon" data-action="copy-username" data-id="${escapeHtml(acc.id)}">Copy User</button>
                <button type="button" class="btn-icon" data-action="toggle-reveal" data-id="${escapeHtml(acc.id)}">${isRevealed ? 'Ẩn' : 'Hiện'}</button>
                <button type="button" class="btn-icon" data-action="copy-password" data-id="${escapeHtml(acc.id)}">Copy Mật khẩu</button>
                <button type="button" class="btn-icon" data-action="edit-account" data-id="${escapeHtml(acc.id)}">Sửa</button>
                <button type="button" class="btn-icon" style="color:var(--accent-crimson);" data-action="delete-account" data-id="${escapeHtml(acc.id)}">Xóa</button>
              </div>
            </td>
          </tr>
        `;
      })
      .join('');

    container.innerHTML = `
      <div class="ledger-table-wrap">
        <table class="ledger-table">
          <thead>
            <tr>
              <th>Nền tảng</th>
              <th>Nhãn phân biệt</th>
              <th>Username / Email</th>
              <th>Mật khẩu</th>
              <th>Độ mạnh</th>
              <th>Thao tác nhanh</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;
  }

  function updateLiveTotpBadgesInDom(totpMap) {
    for (const [accId, totp] of Object.entries(totpMap)) {
      const codeEl = document.querySelector(`[data-totp-code="${accId}"]`);
      const timerEl = document.querySelector(`[data-totp-timer="${accId}"]`);
      if (codeEl) codeEl.textContent = totp.code;
      if (timerEl) timerEl.textContent = `${totp.remainingSeconds}s`;
    }
  }

  // ==========================================================================
  // Add / Edit Account Modal Logic
  // ==========================================================================
  function openAccountModal(account = null, presetPlatform = '', presetCategory = 'email') {
    const modal = document.getElementById('accountModal');
    const title = document.getElementById('accountModalTitle');
    const errBox = document.getElementById('accountModalError');
    const historySec = document.getElementById('accHistorySection');
    const historyList = document.getElementById('accHistoryList');

    errBox.classList.add('hidden');
    document.getElementById('accPassword').type = 'password';
    document.getElementById('toggleAccPasswordBtn').textContent = 'Hiện';

    if (account) {
      title.textContent = `Chỉnh sửa: ${account.platform} (${account.accountLabel})`;
      document.getElementById('accId').value = account.id;
      document.getElementById('accPlatform').value = account.platform;
      document.getElementById('accCategory').value = account.category || 'other';
      document.getElementById('accLabel').value = account.accountLabel || '';
      document.getElementById('accUsername').value = account.username || '';
      document.getElementById('accPassword').value = account.password || '';
      document.getElementById('accUrl').value = account.url || '';
      document.getElementById('accTotpSecret').value = account.totpSecret || '';
      document.getElementById('accTags').value = (account.tags || []).join(', ');
      document.getElementById('accNotes').value = account.notes || '';
      document.getElementById('accFavorite').checked = Boolean(account.favorite);

      if (Array.isArray(account.passwordHistory) && account.passwordHistory.length > 0) {
        historySec.classList.remove('hidden');
        historyList.innerHTML = account.passwordHistory
          .map(
            (h) => `
            <div class="history-item">
              <span>${escapeHtml(h.password)}</span>
              <span>${new Date(h.changedAt).toLocaleDateString('vi-VN')}</span>
            </div>
          `
          )
          .join('');
      } else {
        historySec.classList.add('hidden');
      }
    } else {
      title.textContent = presetPlatform
        ? `Thêm tài khoản mới cho ${presetPlatform}`
        : 'Thêm Tài Khoản Mới';
      document.getElementById('accountForm').reset();
      document.getElementById('accId').value = '';
      if (presetPlatform) {
        document.getElementById('accPlatform').value = presetPlatform;
        document.getElementById('accCategory').value = presetCategory || 'email';
        const existingSameCount = state.accounts.filter(
          (a) => a.platform.toLowerCase() === presetPlatform.toLowerCase()
        ).length;
        document.getElementById('accLabel').value = `Tài khoản #${existingSameCount + 1}`;
      } else {
        document.getElementById('accLabel').value = 'Tài khoản Chính';
      }
      historySec.classList.add('hidden');
    }

    updateModalPasswordMeter();
    modal.classList.remove('hidden');
    document.getElementById('accPlatform').focus();
  }

  function updateModalPasswordMeter() {
    const pwd = document.getElementById('accPassword').value;
    const st = evaluatePasswordStrength(pwd);
    const fill = document.getElementById('accPwdStrengthFill');
    const label = document.getElementById('accPwdStrengthLabel');

    fill.style.width = `${st.score}%`;
    fill.style.background =
      st.level === 'strong'
        ? 'var(--accent-emerald)'
        : st.level === 'medium'
        ? 'var(--accent-amber)'
        : 'var(--accent-crimson)';
    label.textContent = st.label;
  }

  // ==========================================================================
  // Segmented 6-Digit Google Authenticator OTP Input Helpers
  // ==========================================================================
  function getEnteredOtpCode() {
    const inputs = Array.from(document.querySelectorAll('.otp-digit'));
    return inputs.map((el) => el.value.trim()).join('');
  }

  function clearOtpDigits() {
    document.querySelectorAll('.otp-digit').forEach((el) => {
      el.value = '';
    });
  }

  function setupOtpDigitGridEvents() {
    const digits = Array.from(document.querySelectorAll('.otp-digit'));
    digits.forEach((input, idx) => {
      input.addEventListener('input', (e) => {
        const val = e.target.value.replace(/\D/g, '');
        e.target.value = val.slice(-1);
        if (val && idx < digits.length - 1) {
          digits[idx + 1].focus();
        }
      });

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !input.value && idx > 0) {
          digits[idx - 1].focus();
        }
      });

      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
        for (let i = 0; i < pasted.length; i++) {
          if (digits[i]) digits[i].value = pasted[i];
        }
        if (pasted.length === 6) {
          digits[5].focus();
        }
      });
    });
  }

  // ==========================================================================
  // Event Listeners Binding
  // ==========================================================================
  function bindAllEvents() {
    setupOtpDigitGridEvents();

    // Clear clipboard now button
    document.getElementById('clearClipboardNowBtn').addEventListener('click', async () => {
      if (state.clipboardInterval) clearInterval(state.clipboardInterval);
      document.getElementById('clipboardBanner').classList.add('hidden');
      try {
        await navigator.clipboard.writeText('');
        showToast('Đã xóa bộ nhớ tạm ngay lập tức.');
      } catch {
        // Ignore
      }
    });

    // Setup Form Auth Mode Change
    document.getElementById('setupAuthMode').addEventListener('change', (e) => {
      const box = document.getElementById('setupGoogleOAuthFields');
      if (e.target.value === 'google_oauth_and_totp') {
        box.classList.remove('hidden');
      } else {
        box.classList.add('hidden');
      }
    });

    // Copy Setup Secret
    document.getElementById('copySetupSecretBtn').addEventListener('click', () => {
      const secret = document.getElementById('setupSecretText').textContent;
      copyWithAutoClear(secret, 'Mã khóa Secret Base32', 0);
    });

    // Quick Fill Setup OTP button (for easy verification on PC)
    document.getElementById('fillSetupOtpBtn').addEventListener('click', () => {
      const code = document.getElementById('setupLiveOtpCode').textContent.trim();
      if (/^\d{6}$/.test(code)) {
        document.getElementById('setupTotpInput').value = code;
      }
    });

    // Submit First-Time Setup
    document.getElementById('setupForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errBox = document.getElementById('setupErrorBox');
      errBox.classList.add('hidden');

      const ownerName = document.getElementById('setupOwnerName').value.trim();
      const authMode = document.getElementById('setupAuthMode').value;
      const googleEmail = document.getElementById('setupGoogleEmail').value.trim();
      const googleClientId = document.getElementById('setupGoogleClientId').value.trim();
      const masterPassword = document.getElementById('setupMasterPassword').value;
      const confirmPassword = document.getElementById('setupMasterPasswordConfirm').value;
      const totpToken = document.getElementById('setupTotpInput').value.trim();
      const seedSampleAccounts = document.getElementById('setupSeedSamples').checked;

      if (masterPassword !== confirmPassword) {
        errBox.textContent = 'Mật khẩu xác nhận không khớp với Mật khẩu chính.';
        errBox.classList.remove('hidden');
        return;
      }

      try {
        const res = await apiRequest('/api/auth/setup', {
          method: 'POST',
          body: JSON.stringify({
            ownerName,
            authMode,
            googleEmail,
            googleClientId,
            masterPassword,
            totpToken,
            seedSampleAccounts
          })
        });

        state.initialized = true;
        state.unlocked = true;
        state.meta = res.meta;
        state.lastRecoveryCodes = res.recoveryCodes || [];

        showRecoveryCodesModal(state.lastRecoveryCodes);
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
      }
    });

    // Recovery Codes Modal actions
    document.getElementById('downloadRecoveryCodesBtn').addEventListener('click', () => {
      const content = [
        '============================================================',
        '  VAULTGUARD LOCAL - MÃ KHÔI PHỤC DỰ PHÒNG (RECOVERY CODES)',
        '  Mỗi mã chỉ sử dụng được 1 lần khi mất Google Authenticator',
        '============================================================',
        '',
        ...state.lastRecoveryCodes.map((c, i) => `  ${i + 1}. ${c}`),
        '',
        `Ngày tạo: ${new Date().toLocaleString('vi-VN')}`
      ].join('\r\n');

      const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'vaultguard-recovery-codes.txt';
      a.click();
      URL.revokeObjectURL(url);
    });

    document.getElementById('ackRecoveryCodesBtn').addEventListener('click', async () => {
      document.getElementById('recoveryCodesModal').classList.add('hidden');
      await enterVaultWorkspace();
    });

    // Login Form Submit
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errBox = document.getElementById('loginErrorBox');
      errBox.classList.add('hidden');

      const masterPassword = document.getElementById('loginMasterPassword').value;
      const totpToken = getEnteredOtpCode();
      const recoveryCode = document.getElementById('loginRecoveryInput').value.trim();

      try {
        const res = await apiRequest('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({
            masterPassword,
            totpToken: state.recoveryMode ? '' : totpToken,
            recoveryCode: state.recoveryMode ? recoveryCode : '',
            googleAuthNonce: state.googleAuthNonce
          })
        });

        state.unlocked = true;
        state.meta = res.meta;
        document.getElementById('loginMasterPassword').value = '';
        document.getElementById('loginRecoveryInput').value = '';
        clearOtpDigits();
        showToast('Xác thực Google Authentication thành công!');
        await enterVaultWorkspace();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
      }
    });

    // Toggle Login Password Eye
    document.getElementById('toggleLoginPasswordBtn').addEventListener('click', () => {
      const inp = document.getElementById('loginMasterPassword');
      const btn = document.getElementById('toggleLoginPasswordBtn');
      if (inp.type === 'password') {
        inp.type = 'text';
        btn.textContent = 'Ẩn';
      } else {
        inp.type = 'password';
        btn.textContent = 'Hiện';
      }
    });

    // Toggle Recovery Code Mode on Login
    document.getElementById('toggleRecoveryModeBtn').addEventListener('click', () => {
      state.recoveryMode = !state.recoveryMode;
      const totpGroup = document.getElementById('loginTotpGroup');
      const recGroup = document.getElementById('loginRecoveryGroup');
      const btn = document.getElementById('toggleRecoveryModeBtn');

      if (state.recoveryMode) {
        totpGroup.classList.add('hidden');
        recGroup.classList.remove('hidden');
        btn.textContent = '← Quay lại nhập mã 6 số Google Authenticator';
      } else {
        totpGroup.classList.remove('hidden');
        recGroup.classList.add('hidden');
        btn.textContent = 'Mất điện thoại Google Authenticator? Dùng mã khôi phục dự phòng';
      }
    });

    // Sidebar Category Filter clicks
    document.querySelectorAll('.sidebar-nav .nav-item[data-category]').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.sidebar-nav .nav-item[data-category]').forEach((b) =>
          b.classList.remove('active')
        );
        btn.classList.add('active');
        state.activeCategory = btn.getAttribute('data-category');
        state.securityFilter = null;
        renderAccountsView();
      });
    });

    // Health Stat filter clicks
    document.querySelectorAll('.health-stat-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const f = btn.getAttribute('data-filter');
        state.securityFilter = f === 'all' ? null : f;
        renderAccountsView();
      });
    });

    document.getElementById('resetFilterBtn').addEventListener('click', () => {
      state.securityFilter = null;
      state.searchQuery = '';
      document.getElementById('searchInput').value = '';
      renderAccountsView();
    });

    // Search Input
    document.getElementById('searchInput').addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim();
      renderAccountsView();
    });

    // View Mode Switcher
    document.getElementById('viewGroupedBtn').addEventListener('click', () => {
      state.viewMode = 'grouped';
      document.getElementById('viewGroupedBtn').classList.add('active');
      document.getElementById('viewTableBtn').classList.remove('active');
      renderAccountsView();
    });

    document.getElementById('viewTableBtn').addEventListener('click', () => {
      state.viewMode = 'table';
      document.getElementById('viewTableBtn').classList.add('active');
      document.getElementById('viewGroupedBtn').classList.remove('active');
      renderAccountsView();
    });

    // Add Account Button
    document.getElementById('addAccountBtn').addEventListener('click', () => {
      openAccountModal();
    });

    // Delegated Actions inside Accounts Container
    document.getElementById('accountsContainer').addEventListener('click', async (e) => {
      const btn = e.target.closest('[data-action]');
      if (!btn) return;

      const action = btn.getAttribute('data-action');
      const id = btn.getAttribute('data-id');
      const acc = state.accounts.find((a) => a.id === id);

      if (action === 'add-same-platform') {
        const platform = btn.getAttribute('data-platform');
        const category = btn.getAttribute('data-category');
        openAccountModal(null, platform, category);
        return;
      }

      if (!acc) return;

      if (action === 'copy-username') {
        copyWithAutoClear(acc.username, `Username (${acc.platform})`, 0);
      } else if (action === 'copy-password') {
        copyWithAutoClear(acc.password, `Mật khẩu ${acc.platform} - ${acc.accountLabel}`, 20);
      } else if (action === 'copy-totp') {
        if (acc.liveTotp) {
          copyWithAutoClear(acc.liveTotp.code, `Mã 2FA (${acc.platform})`, 20);
        }
      } else if (action === 'toggle-reveal') {
        if (state.revealedPasswords.has(acc.id)) {
          state.revealedPasswords.delete(acc.id);
        } else {
          state.revealedPasswords.add(acc.id);
        }
        renderAccountsView();
      } else if (action === 'edit-account') {
        openAccountModal(acc);
      } else if (action === 'delete-account') {
        if (!window.confirm(`Bạn có chắc chắn muốn xóa tài khoản "${acc.accountLabel}" (${acc.username}) khỏi nền tảng ${acc.platform}?`)) {
          return;
        }
        try {
          const res = await apiRequest(`/api/accounts/${encodeURIComponent(acc.id)}`, {
            method: 'DELETE'
          });
          state.accounts = res.accounts;
          state.audit = res.audit;
          renderSidebarStats();
          renderAccountsView();
          showToast(`Đã xóa tài khoản khỏi ${acc.platform}.`);
        } catch (err) {
          showToast(err.message, true);
        }
      }
    });

    // Account Modal Events
    document.getElementById('accPassword').addEventListener('input', updateModalPasswordMeter);

    document.getElementById('toggleAccPasswordBtn').addEventListener('click', () => {
      const inp = document.getElementById('accPassword');
      const btn = document.getElementById('toggleAccPasswordBtn');
      if (inp.type === 'password') {
        inp.type = 'text';
        btn.textContent = 'Ẩn';
      } else {
        inp.type = 'password';
        btn.textContent = 'Hiện';
      }
    });

    document.getElementById('generateQuickPwdBtn').addEventListener('click', () => {
      const pwd = generateSecurePassword(20);
      const inp = document.getElementById('accPassword');
      inp.value = pwd;
      inp.type = 'text';
      document.getElementById('toggleAccPasswordBtn').textContent = 'Ẩn';
      updateModalPasswordMeter();
    });

    document.getElementById('accountForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errBox = document.getElementById('accountModalError');
      errBox.classList.add('hidden');

      const accId = document.getElementById('accId').value;
      const payload = {
        platform: document.getElementById('accPlatform').value.trim(),
        category: document.getElementById('accCategory').value,
        accountLabel: document.getElementById('accLabel').value.trim(),
        username: document.getElementById('accUsername').value.trim(),
        password: document.getElementById('accPassword').value,
        url: document.getElementById('accUrl').value.trim(),
        totpSecret: document.getElementById('accTotpSecret').value.trim(),
        tags: document.getElementById('accTags').value,
        notes: document.getElementById('accNotes').value.trim(),
        favorite: document.getElementById('accFavorite').checked
      };

      try {
        const res = accId
          ? await apiRequest(`/api/accounts/${encodeURIComponent(accId)}`, {
              method: 'PUT',
              body: JSON.stringify(payload)
            })
          : await apiRequest('/api/accounts', {
              method: 'POST',
              body: JSON.stringify(payload)
            });

        state.accounts = res.accounts;
        state.audit = res.audit;
        document.getElementById('accountModal').classList.add('hidden');
        renderSidebarStats();
        renderAccountsView();
        showToast(accId ? 'Đã cập nhật tài khoản thành công!' : 'Đã thêm tài khoản mới vào kho!');
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
      }
    });

    // Lock Vault Immediately
    document.getElementById('lockVaultBtn').addEventListener('click', lockVaultNow);

    // Password Generator Modal
    document.getElementById('openGeneratorModalBtn').addEventListener('click', () => {
      refreshGeneratorOutput();
      document.getElementById('generatorModal').classList.remove('hidden');
    });

    document.getElementById('genLengthRange').addEventListener('input', (e) => {
      document.getElementById('genLengthValue').textContent = `${e.target.value} ký tự`;
      refreshGeneratorOutput();
    });

    ['genUpper', 'genLower', 'genDigits', 'genSymbols'].forEach((id) => {
      document.getElementById(id).addEventListener('change', refreshGeneratorOutput);
    });

    document.getElementById('regeneratePwdBtn').addEventListener('click', refreshGeneratorOutput);

    document.getElementById('copyGeneratedPwdBtn').addEventListener('click', () => {
      const pwd = document.getElementById('generatedPwdOutput').textContent;
      copyWithAutoClear(pwd, 'Mật khẩu vừa tạo', 20);
    });

    // Settings Modal
    document.getElementById('openSettingsModalBtn').addEventListener('click', async () => {
      try {
        const qrData = await apiRequest('/api/settings/totp-qr');
        document.getElementById('settingsQrImage').src = qrData.qrDataUrl;
        document.getElementById('settingsSecretText').textContent = qrData.secret;

        const meta = state.meta || {};
        document.getElementById('settingsOwnerName').value = meta.ownerName || '';
        document.getElementById('settingsAuthMode').value = meta.authMode || 'totp_and_master';
        document.getElementById('settingsGoogleEmail').value = meta.googleEmail || '';
        document.getElementById('settingsGoogleClientId').value = meta.googleClientId || '';
        document.getElementById('settingsAutoLock').value = meta.autoLockMinutes || 15;

        document.getElementById('settingsModal').classList.remove('hidden');
      } catch (err) {
        showToast(err.message, true);
      }
    });

    document.getElementById('settingsForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const res = await apiRequest('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({
            ownerName: document.getElementById('settingsOwnerName').value.trim(),
            authMode: document.getElementById('settingsAuthMode').value,
            googleEmail: document.getElementById('settingsGoogleEmail').value.trim(),
            googleClientId: document.getElementById('settingsGoogleClientId').value.trim(),
            autoLockMinutes: Number(document.getElementById('settingsAutoLock').value)
          })
        });
        state.meta = res.meta;
        document.getElementById('sidebarVaultName').textContent = state.meta.ownerName;
        document.getElementById('settingsModal').classList.add('hidden');
        showToast('Đã lưu cài đặt Google Authentication!');
      } catch (err) {
        showToast(err.message, true);
      }
    });

    // Backup & Restore Modal
    document.getElementById('openBackupModalBtn').addEventListener('click', () => {
      document.getElementById('backupModal').classList.remove('hidden');
    });

    document.getElementById('exportBackupBtn').addEventListener('click', async () => {
      try {
        const backupPassword = document.getElementById('exportBackupPassword').value;
        const res = await apiRequest('/api/backup/export', {
          method: 'POST',
          body: JSON.stringify({ backupPassword })
        });
        const blob = new Blob([JSON.stringify(res.backupFile, null, 2)], {
          type: 'application/json'
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vaultguard-backup-${new Date().toISOString().slice(0, 10)}.vault.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('Đã tải xuống file sao lưu thành công!');
      } catch (err) {
        showToast(err.message, true);
      }
    });

    document.getElementById('importBackupBtn').addEventListener('click', async () => {
      const fileInput = document.getElementById('importBackupFile');
      const backupPassword = document.getElementById('importBackupPassword').value;
      if (!fileInput.files || !fileInput.files[0]) {
        showToast('Vui lòng chọn file .vault.json cần nhập.', true);
        return;
      }
      try {
        const text = await fileInput.files[0].text();
        const backupData = JSON.parse(text);
        const res = await apiRequest('/api/backup/import', {
          method: 'POST',
          body: JSON.stringify({ backupData, backupPassword })
        });
        state.accounts = res.accounts;
        state.audit = res.audit;
        renderSidebarStats();
        renderAccountsView();
        document.getElementById('backupModal').classList.add('hidden');
        showToast(`Đã nhập thành công ${res.addedCount} tài khoản!`);
      } catch (err) {
        showToast(err.message || 'File sao lưu không hợp lệ.', true);
      }
    });

    // Security Audit Logs Modal
    document.getElementById('openAuditLogsModalBtn').addEventListener('click', async () => {
      try {
        const { logs } = await apiRequest('/api/audit-logs');
        const listEl = document.getElementById('auditLogsList');
        listEl.innerHTML = (logs || [])
          .map(
            (l) => `
            <div class="audit-log-row">
              <div>
                <strong class="mono-text" style="color:var(--accent-emerald);font-size:12px;">${escapeHtml(l.event)}</strong>
                <div style="font-size:13px;color:var(--text-primary);">${escapeHtml(l.detail)}</div>
              </div>
              <span class="mono-text" style="font-size:11.5px;color:var(--text-secondary);white-space:nowrap;">
                ${new Date(l.timestamp).toLocaleString('vi-VN')}
              </span>
            </div>
          `
          )
          .join('');
        document.getElementById('auditLogsModal').classList.remove('hidden');
      } catch (err) {
        showToast(err.message, true);
      }
    });

    // Close Modal Buttons
    document.querySelectorAll('[data-close-modal]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-close-modal');
        document.getElementById(targetId).classList.add('hidden');
      });
    });

    // Global Keyboard Shortcuts (Ctrl+K search, Ctrl+L lock vault)
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        if (state.unlocked) {
          e.preventDefault();
          document.getElementById('searchInput').focus();
        }
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'l') {
        if (state.unlocked) {
          e.preventDefault();
          lockVaultNow();
        }
      }
    });
  }

  function showRecoveryCodesModal(codes) {
    const grid = document.getElementById('recoveryCodesGrid');
    grid.innerHTML = codes
      .map((c) => `<div class="recovery-code-item">${escapeHtml(c)}</div>`)
      .join('');
    document.getElementById('recoveryCodesModal').classList.remove('hidden');
  }

  function refreshGeneratorOutput() {
    const len = Number(document.getElementById('genLengthRange').value) || 20;
    const pwd = generateSecurePassword(len, {
      upper: document.getElementById('genUpper').checked,
      lower: document.getElementById('genLower').checked,
      digits: document.getElementById('genDigits').checked,
      symbols: document.getElementById('genSymbols').checked
    });
    document.getElementById('generatedPwdOutput').textContent = pwd;
  }

  async function initElectronDesktopBridge() {
    if (!window.vaultDesktop || !window.vaultDesktop.isElectron) return;

    const desktopBar = document.getElementById('electronDesktopControls');
    const protectBtn = document.getElementById('toggleScreenProtectBtn');
    const pinBtn = document.getElementById('toggleAlwaysOnTopBtn');

    if (desktopBar) desktopBar.classList.remove('hidden');

    function syncDesktopButtons(info) {
      if (protectBtn) {
        protectBtn.textContent = info.contentProtection
          ? '🛡️ Chống chụp màn hình: BẬT'
          : '🛡️ Chống chụp màn hình: TẮT';
        protectBtn.classList.toggle('active', Boolean(info.contentProtection));
      }
      if (pinBtn) {
        pinBtn.textContent = info.alwaysOnTop ? '📌 Đang ghim nổi' : '📌 Ghim nổi cửa sổ';
        pinBtn.classList.toggle('active', Boolean(info.alwaysOnTop));
      }
    }

    try {
      const info = await window.vaultDesktop.getDesktopInfo();
      syncDesktopButtons(info);
    } catch {
      // Ignore
    }

    if (protectBtn) {
      protectBtn.addEventListener('click', async () => {
        const updated = await window.vaultDesktop.toggleContentProtection();
        syncDesktopButtons(updated);
        showToast(
          updated.contentProtection
            ? 'Đã BẬT chế độ chống chụp/quay màn hình (Windows Content Protection).'
            : 'Đã TẮT chế độ chống chụp màn hình.'
        );
      });
    }

    if (pinBtn) {
      pinBtn.addEventListener('click', async () => {
        const updated = await window.vaultDesktop.toggleAlwaysOnTop();
        syncDesktopButtons(updated);
        showToast(
          updated.alwaysOnTop
            ? 'Đã ghim cửa sổ VaultGuard luôn nổi trên cùng.'
            : 'Đã tắt ghim cửa sổ.'
        );
      });
    }

    window.vaultDesktop.onOsLocked(() => {
      state.unlocked = false;
      state.accounts = [];
      state.revealedPasswords.clear();
      showToast('Đã tự động khóa kho mật khẩu do máy tính khóa màn hình.');
      showLoginView();
    });

    window.vaultDesktop.onDesktopStateChanged((newState) => {
      syncDesktopButtons(newState);
    });
  }

  async function lockVaultNow() {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // Ignore
    }
    state.unlocked = false;
    state.accounts = [];
    state.revealedPasswords.clear();
    showToast('Đã khóa kho mật khẩu an toàn.');
    showLoginView();
  }

  document.addEventListener('DOMContentLoaded', bootstrapApp);
})();
