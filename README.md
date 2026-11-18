# 🛡️ VaultGuard — Kho Mật Khẩu Đa Nền Tảng (Electron Desktop & Web 24/7)

Ứng dụng quản lý mật khẩu đa nền tảng (Facebook, Gmail, GitHub, Ngân hàng, Game...) được mã hóa chuẩn **AES-256-GCM** và bắt buộc xác thực bằng **Google Authentication** (**Google Authenticator 2FA QR Code 6 số** + **Google OAuth 2.0**) trước khi mở khóa.

---

## 🌐 1. Dùng Trực Tiếp 24/7 Trên Web (Hoạt động liên tục cả khi máy tính cá nhân đã tắt)

Bạn và người dùng khác có thể truy cập sử dụng trực tiếp 24/7 tại:

👉 **[Mở VaultGuard Web App Live 24/7 (GitHub Pages)](https://alexnguyenhao.github.io/vaultguard-password-manager/)**

- Hoạt động **24/7 miễn phí** trên hạ tầng GitHub Pages ngay cả khi máy tính của bạn đã tắt.
- Toàn bộ mật khẩu được mã hóa **Zero-Knowledge AES-256-GCM** trực tiếp trong trình duyệt của từng người dùng kèm xác thực **Google Authenticator (TOTP 6 số)**.

### ☁️ Triển khai Server Node.js 24/7 lên Đám mây (Render / Railway / Docker)
Nếu bạn muốn chạy máy chủ Backend Node.js (`server.js`) 24/7 trên Cloud chỉ với 1 cú nhấp chuột:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/alexnguyenhao/vaultguard-password-manager)

---

## 📥 2. Tải Bản Cài Đặt Desktop (Windows `.EXE` & macOS `.DMG`)

Phần mềm Desktop được đóng gói bằng **Electron** cho cả **Windows** và **macOS**.

### 🪟 Windows (`.EXE` Portable — chạy ngay không cần cài đặt)

- 👉 **[⬇️ Tải Trực Tiếp File `VaultGuard-Portable-1.0.2.exe` (Click là tải ngay)](https://github.com/alexnguyenhao/vaultguard-password-manager/releases/download/v1.0.2/VaultGuard-Portable-1.0.2.exe)**
- 👉 **[📦 Tải Bản Nén `VaultGuard-Portable-1.0.2.zip`](https://github.com/alexnguyenhao/vaultguard-password-manager/releases/download/v1.0.2/VaultGuard-Portable-1.0.2.zip)**

### 🍎 macOS (`.DMG` — kéo thả vào Applications)

- 👉 **[⬇️ Tải cho Mac Apple Silicon (M1 / M2 / M3 / M4) — `VaultGuard-1.0.2-arm64.dmg`](https://github.com/alexnguyenhao/vaultguard-password-manager/releases/download/v1.0.2/VaultGuard-1.0.2-arm64.dmg)**
- 👉 **[⬇️ Tải cho Mac Intel — `VaultGuard-1.0.2-x64.dmg`](https://github.com/alexnguyenhao/vaultguard-password-manager/releases/download/v1.0.2/VaultGuard-1.0.2-x64.dmg)**

Sau khi tải: mở file `.dmg` → kéo **VaultGuard** vào thư mục **Applications**.

> ⚠️ **Lần đầu mở bản chưa ký số (Unsigned):** macOS có thể báo *"VaultGuard is damaged"* hoặc *"unidentified developer"*.
> Hãy bấm **chuột phải vào VaultGuard → Open → Open**, hoặc chạy lệnh sau trong Terminal:
> ```bash
> xattr -dr com.apple.quarantine /Applications/VaultGuard.app
> ```

- 👉 **[Xem trang GitHub Releases mới nhất](https://github.com/alexnguyenhao/vaultguard-password-manager/releases/latest)**

### Hoặc tải mã nguồn về chạy trên máy (Local):
```bash
git clone https://github.com/alexnguyenhao/vaultguard-password-manager.git
cd vaultguard-password-manager
npm install
npm start
```
*(Trên Windows, bạn cũng có thể click đúp trực tiếp vào file `start-vault.bat`. Trên macOS, click đúp `start-vault.command`.)*

### Tự build bản cài đặt trên máy của bạn:
```bash
npm run dist        # Windows: .EXE portable + .ZIP
npm run dist:mac    # macOS: .DMG cho Apple Silicon + Intel
npm run dist:all    # Cả hai nền tảng (chỉ build được macOS .DMG trên máy Mac/Linux runner)
```

> 💡 Bản `.DMG` hiện **chưa ký số (unsigned)** nên chưa cần Apple Developer ID. Nếu bạn có chứng chỉ Apple Developer, hãy đặt biến môi trường `CSC_LINK` và `CSC_KEY_PASSWORD` khi build để electron-builder tự ký và có thể bật notarization.

---

## 🔐 3. Các Tính Năng Bảo Mật Nổi Bật

1. **Xác thực Google Authentication đa chế độ**:
   - Quét mã QR trên ứng dụng **Google Authenticator** (iOS/Android) lấy mã 6 số thay đổi mỗi 30 giây.
   - Hỗ trợ 3 chế độ mở khóa:
     1. **Mã 6 số Google Authenticator + Master Password** (Bảo mật 2 lớp).
     2. **Chỉ nhập mã 6 số Google Authenticator** (Mở nhanh).
     3. **Đăng nhập Google OAuth 2.0 + Mã 6 số Google Authenticator**.
   - Cấp **8 Mã Khôi Phục Dự Phòng (Recovery Codes)** phòng trường hợp mất điện thoại.
2. **Quản lý Nhiều Tài Khoản trên Nhiều Nền Tảng**:
   - Gom nhóm nhiều nick trong cùng 1 nền tảng (VD: 5 tài khoản Gmail, 3 nick Facebook, nhiều tài khoản GitHub/Ngân hàng...).
   - Tích hợp bộ đếm mã **2FA TOTP trực tiếp** cho từng tài khoản lưu trong kho.
   - Tự động xóa bộ nhớ tạm (Clipboard) sau 20 giây khi Copy mật khẩu.
3. **Bảo vệ Đặc Quyền trên Bản Electron Desktop (Windows & macOS)**:
   - **Chống chụp/quay lén màn hình (`setContentProtection`)** trên Windows và macOS.
   - **Tự động khóa kho ngay lập tức** khi bạn khóa màn hình máy tính (`Win + L` trên Windows, `Control + Command + Q` trên macOS) hoặc khi máy Sleep.
   - **Ghim nổi cửa sổ (`Always on Top`)** để tiện đăng nhập nhiều tài khoản.
   - **Menu native macOS** (About / Hide / Quit / Window) và phím tắt `⌘L`, `⌘R`, `⌘Q` chuẩn Mac.
   - Dữ liệu được lưu tại `%LOCALAPPDATA%\VaultGuardData` (Windows) hoặc `~/Library/Application Support/VaultGuardData` (macOS).
