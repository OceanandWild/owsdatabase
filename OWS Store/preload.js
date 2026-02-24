const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('owsUpdater', {
  onUpdateAvailable: (cb) => ipcRenderer.on('update-available', (_, info) => cb(info)),
  onUpdateDownloaded: (cb) => ipcRenderer.on('update-downloaded', () => cb()),
  onDownloadProgress: (cb) => ipcRenderer.on('update-download-progress', (_, prog) => cb(prog)),
  onUpdateNotAvailable: (cb) => ipcRenderer.on('update-not-available', () => cb()),
  onUpdateError: (cb) => ipcRenderer.on('update-error', (_, err) => cb(err)),
  onExternalInstallStatus: (cb) => ipcRenderer.on('external-install-status', (_, status) => cb(status)),
  installUpdate: () => ipcRenderer.invoke('install-update'),
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  installExternalInstaller: (payload) => ipcRenderer.invoke('install-external-installer', payload),
  cancelExternalInstaller: (payload) => ipcRenderer.invoke('cancel-external-installer', payload),
  openExternalUrl: (url) => ipcRenderer.invoke('open-external-url', url),
  resolveInstalledApp: (payload) => ipcRenderer.invoke('resolve-installed-app', payload),
  launchInstalledApp: (payload) => ipcRenderer.invoke('launch-installed-app', payload),
  uninstallInstalledApp: (payload) => ipcRenderer.invoke('uninstall-installed-app', payload),
  platform: process.platform,
  isElectron: true,
});
