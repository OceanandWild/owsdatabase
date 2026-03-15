const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ecoxionUpdater', {
  onUpdateAvailable: (cb) => ipcRenderer.on('update-available', (_, info) => cb(info)),
  onUpdateDownloaded: (cb) => ipcRenderer.on('update-downloaded', () => cb()),
  onDownloadProgress: (cb) => ipcRenderer.on('update-download-progress', (_, prog) => cb(prog)),
  onUpdateNotAvailable: (cb) => ipcRenderer.on('update-not-available', () => cb()),
  onUpdateError: (cb) => ipcRenderer.on('update-error', (_, err) => cb(err)),
  installUpdate: () => ipcRenderer.invoke('install-update'),
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  showSystemNotification: (payload) => ipcRenderer.invoke('show-system-notification', payload),
  openExternalUrl: (url) => ipcRenderer.invoke('open-external-url', url),
  platform: process.platform,
  isElectron: true,
});
