const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vaultDesktop', {
  isElectron: true,
  getDesktopInfo: () => ipcRenderer.invoke('vault:get-desktop-info'),
  toggleContentProtection: () => ipcRenderer.invoke('vault:toggle-content-protection'),
  toggleAlwaysOnTop: () => ipcRenderer.invoke('vault:toggle-always-on-top'),
  onOsLocked: (callback) => {
    ipcRenderer.on('vault:os-locked', () => callback());
  },
  onDesktopStateChanged: (callback) => {
    ipcRenderer.on('vault:desktop-state', (_event, state) => callback(state));
  }
});
