const {
  app,
  BrowserWindow,
  ipcMain,
  shell,
  powerMonitor,
  Menu
} = require('electron');
const path = require('path');
const os = require('os');
const fs = require('fs');
const http = require('http');

// 1. Resolve a real writable data directory on disk (works both in dev and packaged .EXE / app.asar)
function resolveWritableBaseDir() {
  if (!app.isPackaged && !__dirname.includes('app.asar')) {
    return path.join(__dirname, '..', 'data');
  }
  // When running as Portable .EXE, store data in AppData\Local\VaultGuard (or next to executable if writable)
  const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), '.vaultguard');
  return path.join(localAppData, 'VaultGuardData');
}

const baseDataDir = resolveWritableBaseDir();
try {
  fs.mkdirSync(baseDataDir, { recursive: true });
} catch {
  // Fallback to OS temp/home directory if needed
}
process.env.VAULTGUARD_DATA_DIR = baseDataDir;

// 2. Select an unlocked profile directory so Windows never throws 0x20 lockfile or 0x5 disk_cache errors
let profileDir = path.join(baseDataDir, 'electron-profile');
let isSecondaryInstance = false;
try {
  fs.mkdirSync(profileDir, { recursive: true });
  const lockFilePath = path.join(profileDir, 'lockfile');
  if (fs.existsSync(lockFilePath)) {
    const fd = fs.openSync(lockFilePath, 'r+');
    fs.closeSync(fd);
  }
} catch {
  isSecondaryInstance = true;
  profileDir = path.join(baseDataDir, `electron-session-${process.pid}`);
  try {
    fs.mkdirSync(profileDir, { recursive: true });
  } catch {
    // Ignore
  }
}

app.setPath('userData', profileDir);
app.commandLine.appendSwitch('disable-http-cache');
app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
app.commandLine.appendSwitch('disable-gpu-program-cache');

const serverModule = require('../server');
const expressApp = serverModule.app || serverModule;
const lockAllSessions = serverModule.lockAllSessions || (() => {});

let mainWindow = null;
let localServer = null;
let serverPort = Number(process.env.PORT) || 3456;
let contentProtectionEnabled = true;
let alwaysOnTopEnabled = false;

/**
 * Start embedded local Express server on 127.0.0.1 (or reuse port 3456 if already active)
 */
function startEmbeddedServer() {
  return new Promise((resolve, reject) => {
    const srv = http.createServer(expressApp);

    srv.once('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        const req = http.get(`http://127.0.0.1:${serverPort}/api/auth/status`, (res) => {
          res.resume();
          if (res.statusCode === 200) {
            resolve(serverPort);
          } else {
            listenOnRandomPort(resolve, reject);
          }
        });
        req.on('error', () => listenOnRandomPort(resolve, reject));
      } else {
        reject(err);
      }
    });

    srv.listen(serverPort, '127.0.0.1', () => {
      localServer = srv;
      serverPort = srv.address().port;
      resolve(serverPort);
    });
  });
}

function listenOnRandomPort(resolve, reject) {
  const fallbackSrv = http.createServer(expressApp);
  fallbackSrv.once('error', reject);
  fallbackSrv.listen(0, '127.0.0.1', () => {
    localServer = fallbackSrv;
    serverPort = fallbackSrv.address().port;
    resolve(serverPort);
  });
}

function createApplicationMenu() {
  const template = [
    {
      label: 'VaultGuard',
      submenu: [
        {
          label: 'Khóa Kho Ngay (Lock Vault)',
          accelerator: 'CmdOrCtrl+L',
          click: () => {
            lockAllSessions();
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.webContents.send('vault:os-locked');
            }
          }
        },
        { type: 'separator' },
        {
          label: 'Chống chụp màn hình (Anti-Screen Capture)',
          type: 'checkbox',
          checked: contentProtectionEnabled,
          click: (menuItem) => {
            contentProtectionEnabled = menuItem.checked;
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.setContentProtection(contentProtectionEnabled);
              mainWindow.webContents.send('vault:desktop-state', {
                contentProtection: contentProtectionEnabled,
                alwaysOnTop: alwaysOnTopEnabled
              });
            }
          }
        },
        {
          label: 'Ghim cửa sổ trên cùng (Always on Top)',
          type: 'checkbox',
          checked: alwaysOnTopEnabled,
          click: (menuItem) => {
            alwaysOnTopEnabled = menuItem.checked;
            if (mainWindow && !mainWindow.isDestroyed()) {
              mainWindow.setAlwaysOnTop(alwaysOnTopEnabled);
              mainWindow.webContents.send('vault:desktop-state', {
                contentProtection: contentProtectionEnabled,
                alwaysOnTop: alwaysOnTopEnabled
              });
            }
          }
        },
        { type: 'separator' },
        {
          label: 'Làm mới giao diện',
          accelerator: 'CmdOrCtrl+R',
          click: () => {
            if (mainWindow && !mainWindow.isDestroyed()) mainWindow.reload();
          }
        },
        {
          label: 'Thoát VaultGuard',
          accelerator: 'CmdOrCtrl+Q',
          click: () => {
            app.quit();
          }
        }
      ]
    },
    {
      label: 'Chỉnh sửa',
      submenu: [
        { role: 'undo', label: 'Hoàn tác' },
        { role: 'redo', label: 'Làm lại' },
        { type: 'separator' },
        { role: 'cut', label: 'Cắt' },
        { role: 'copy', label: 'Sao chép' },
        { role: 'paste', label: 'Dán' },
        { role: 'selectAll', label: 'Chọn tất cả' }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

async function createMainWindow() {
  const port = await startEmbeddedServer();
  const appUrl = `http://127.0.0.1:${port}`;

  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 960,
    minHeight: 640,
    title: 'VaultGuard Desktop — Quản Lý Mật Khẩu Đa Nền Tảng (Google Authentication)',
    backgroundColor: '#0A0D12',
    show: false,
    autoHideMenuBar: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false
    }
  });

  mainWindow.setContentProtection(contentProtectionEnabled);

  mainWindow.once('ready-to-show', () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.show();
      mainWindow.focus();
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url);
      if (
        (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
        parsed.hostname !== '127.0.0.1' &&
        parsed.hostname !== 'localhost'
      ) {
        shell.openExternal(url);
        return { action: 'deny' };
      }
      if (parsed.hostname.endsWith('google.com')) {
        return { action: 'allow' };
      }
    } catch {
      // Ignore invalid URL
    }
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
    try {
      const parsed = new URL(navigationUrl);
      if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
        event.preventDefault();
        if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
          shell.openExternal(navigationUrl);
        }
      }
    } catch {
      event.preventDefault();
    }
  });

  await mainWindow.loadURL(appUrl);
}

// ============================================================================
// IPC Handlers for Electron Desktop Controls
// ============================================================================
ipcMain.handle('vault:get-desktop-info', () => {
  return {
    isElectron: true,
    electronVersion: process.versions.electron,
    nodeVersion: process.versions.node,
    platform: process.platform,
    contentProtection: contentProtectionEnabled,
    alwaysOnTop: alwaysOnTopEnabled
  };
});

ipcMain.handle('vault:toggle-content-protection', () => {
  contentProtectionEnabled = !contentProtectionEnabled;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setContentProtection(contentProtectionEnabled);
  }
  return {
    contentProtection: contentProtectionEnabled,
    alwaysOnTop: alwaysOnTopEnabled
  };
});

ipcMain.handle('vault:toggle-always-on-top', () => {
  alwaysOnTopEnabled = !alwaysOnTopEnabled;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.setAlwaysOnTop(alwaysOnTopEnabled);
  }
  return {
    contentProtection: contentProtectionEnabled,
    alwaysOnTop: alwaysOnTopEnabled
  };
});

// ============================================================================
// App Lifecycle & OS Lock-Screen Auto-Lock
// ============================================================================
app.whenReady().then(async () => {
  createApplicationMenu();
  await createMainWindow();

  const handleSystemLockOrSuspend = () => {
    lockAllSessions();
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('vault:os-locked');
    }
  };

  powerMonitor.on('lock-screen', handleSystemLockOrSuspend);
  powerMonitor.on('suspend', handleSystemLockOrSuspend);

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('window-all-closed', () => {
  lockAllSessions();
  if (localServer) {
    try {
      localServer.close();
    } catch {
      // Ignore
    }
  }
  if (isSecondaryInstance) {
    try {
      fs.rmSync(profileDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
