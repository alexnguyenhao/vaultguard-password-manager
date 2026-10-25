---
name: password-vault-architect
description: >-
  Architecture and cryptographic workflow for building a local, zero-trust Password
  Manager Vault with Google Authentication (Google Authenticator TOTP 2FA QR Code +
  Google OAuth 2.0 Sign-In) and AES-256-GCM encryption at rest.
---

# Password Vault Architect Skill

## Core Architecture & Security Requirements

1. **Dual-Mode Google Authentication Gate**:
   - **Google Authenticator (TOTP RFC 6238)**:
     - First-run setup generates a 160-bit Base32 secret and renders an `otpauth://totp/VaultGuard:...` QR code scannable by the **Google Authenticator** mobile app, along with single-use Recovery Codes and a Master Password.
     - Subsequent logins require Master Password + 6-digit Google Authenticator OTP code (or optional Google OAuth 2.0 verification + TOTP).
   - **Google OAuth 2.0 (Sign in with Google)**:
     - Configurable right from the UI or `.env` (`GOOGLE_CLIENT_ID`) using Google Identity Services (GIS) ID Token verification, locked to an allowed Google email address, plus 2FA TOTP verification.

2. **Cryptographic Vault Storage (AES-256-GCM + PBKDF2/Scrypt)**:
   - Every stored credential password, note, and TOTP secret is encrypted at rest using **AES-256-GCM** with a random 96-bit IV and 128-bit authentication tag.
   - The Vault Encryption Key (VEK) is derived from the user's Master Password + unique salt using `crypto.scryptSync` (`N=16384, r=8, p=1`, 32 bytes) and held only in memory during an active unlocked session (or auto-locked after inactivity).
   - Vault database is stored locally in `data/vault.enc.json` with strict file permissions and automatic encrypted backup/export capability.

3. **Session & API Hardening**:
   - `httpOnly`, `SameSite=Strict` session cookies with short TTL and automatic idle lock.
   - Strict rate limiting on `/api/auth/*` endpoints to prevent brute-force of 6-digit TOTP or Master Password.
   - Security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`).

4. **Multi-Platform Account Management Features**:
   - Categorize credentials by platform (Social, Banking/Finance, Work, Gaming, Cloud/Dev, Email, Shopping, Custom).
   - Multi-account support per platform (e.g., multiple Gmail, GitHub, Facebook, or AWS accounts) with tags, custom fields, URL launch, username/password one-click copy with auto-clear clipboard countdown.
   - Built-in Password Generator (customizable length, symbols, entropy bits & strength meter) and Security Audit Dashboard (detects weak, reused, or old passwords).
   - Encrypted Vault Export & Import (`.vault` / JSON encrypted backup).
