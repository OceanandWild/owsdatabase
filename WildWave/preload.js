const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('wildwaveUpdater', {
  check: () => ipcRenderer.invoke('wildwave-updater:check'),
  install: () => ipcRenderer.invoke('wildwave-updater:install'),
  version: () => ipcRenderer.invoke('wildwave-updater:version'),
  openExternal: (url) => ipcRenderer.invoke('wildwave-updater:open-external', url),
  onChecking: (cb) => ipcRenderer.on('wildwave-updater:checking', () => cb && cb()),
  onAvailable: (cb) => ipcRenderer.on('wildwave-updater:available', (_e, payload) => cb && cb(payload)),
  onNotAvailable: (cb) => ipcRenderer.on('wildwave-updater:not-available', () => cb && cb()),
  onProgress: (cb) => ipcRenderer.on('wildwave-updater:progress', (_e, payload) => cb && cb(payload)),
  onDownloaded: (cb) => ipcRenderer.on('wildwave-updater:downloaded', () => cb && cb()),
  onError: (cb) => ipcRenderer.on('wildwave-updater:error', (_e, payload) => cb && cb(payload))
});
