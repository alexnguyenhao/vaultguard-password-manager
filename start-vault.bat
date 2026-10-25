@echo off
chcp 65001 >nul
title VaultGuard Desktop - Quan Ly Mat Khau (Electron + Google Authentication)
cd /d "%~dp0"
echo ==================================================================
echo   Dang khoi dong ung dung Desktop Electron: VaultGuard Local...
echo   Bao ve boi: Google Authentication (2FA TOTP + OAuth) va AES-256-GCM
echo ==================================================================
call npx electron .
