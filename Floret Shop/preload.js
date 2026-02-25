const { contextBridge, ipcRenderer } = require('electron');

function subscribe(channel, cb) {
  if (typeof cb !== 'function') return () => {};
  const handler = (_event, payload) => cb(payload);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
}

contextBridge.exposeInMainWorld('floretUpdater', {
  checkForUpdates: () => ipcRenderer.invoke('floret-updater:check'),
  installUpdate: () => ipcRenderer.invoke('floret-updater:install'),
  getAppVersion: () => ipcRenderer.invoke('floret-updater:version'),
  openExternalUrl: (url) => ipcRenderer.invoke('floret-updater:open-external', url),
  onChecking: (cb) => subscribe('floret-updater:checking', cb),
  onUpdateAvailable: (cb) => subscribe('floret-updater:available', cb),
  onUpdateNotAvailable: (cb) => subscribe('floret-updater:not-available', cb),
  onDownloadProgress: (cb) => subscribe('floret-updater:progress', cb),
  onUpdateDownloaded: (cb) => subscribe('floret-updater:downloaded', cb),
  onUpdateError: (cb) => subscribe('floret-updater:error', cb),
});
