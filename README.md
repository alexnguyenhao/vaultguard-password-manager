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

## 📥 2. Tải Bản Cài Đặt Desktop Windows (`.EXE` Portable)

Người dùng có thể tải trực tiếp phần mềm Desktop đóng gói bằng **Electron** về máy tính Windows:

👉 **[Tải Xuống VaultGuard-Portable.exe tại mục GitHub Releases](https://github.com/alexnguyenhao/vaultguard-password-manager/releases/latest)**

### Hoặc tải mã nguồn về chạy trên máy (Local):
```bash
git clone https://github.com/alexnguyenhao/vaultguard-password-manager.git
cd vaultguard-password-manager
npm install
npm start
```
*(Trên Windows, bạn cũng có thể click đúp trực tiếp vào file `start-vault.bat` để mở ứng dụng).*

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
3. **Bảo vệ Đặc Quyền trên Bản Electron Desktop**:
   - **Chống chụp/quay lén màn hình (`setContentProtection`)** trên Windows.
   - **Tự động khóa kho ngay lập tức** khi bạn bấm khóa màn hình máy tính (`Win + L`) hoặc Sleep.
   - **Ghim nổi cửa sổ (`Always on Top`)** để tiện đăng nhập nhiều tài khoản.
