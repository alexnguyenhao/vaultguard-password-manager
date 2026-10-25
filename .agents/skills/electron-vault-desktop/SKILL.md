---
name: electron-vault-desktop
description: >-
  Electron desktop application architecture and security hardening for local
  cryptographic password vaults (Context Isolation, Process Sandboxing,
  Content Protection against screen capture, and OS Lock-Screen Auto-Lock).
---

# Electron Vault Desktop Skill

## Security & Hardening Rules for Electron Password Managers

1. **Strict Renderer Isolation**:
   - Always configure `BrowserWindow` with `contextIsolation: true`, `nodeIntegration: false`, and `sandbox: true`.
   - Expose only a minimal, allowlisted IPC bridge via `contextBridge.exposeInMainWorld('vaultDesktop', ...)` in `electron/preload.js`.

2. **Anti-Screen-Capture Protection (`setContentProtection`)**:
   - Enable `mainWindow.setContentProtection(true)` by default on Windows/macOS so screen-recording malware or unauthorized remote-desktop tools cannot capture decrypted passwords on screen. Provide an IPC toggle in the UI if the user intentionally wants to take a screenshot.

3. **OS Power & Lock-Screen Auto-Lock (`powerMonitor`)**:
   - Listen to `powerMonitor.on('lock-screen')` and `powerMonitor.on('suspend')`.
   - Immediately wipe the in-memory Vault Encryption Key (`lockAllSessions()`) and notify the renderer to return to the Google Authentication login gate whenever the user locks their computer (`Win + L`) or puts the machine to sleep.

4. **Safe External Link Handling**:
   - Intercept `setWindowOpenHandler` and `will-navigate` on `webContents`.
   - Never navigate the Vault window to external third-party URLs; instead, validate that the protocol is `https:` or `http:` and open external login URLs in the user's default system browser via `shell.openExternal(url)`.
