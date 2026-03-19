const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('oceanAiUpdater', {
  check: () => ipcRenderer.invoke('oceanai-updater:check'),
  install: () => ipcRenderer.invoke('oceanai-updater:install'),
  version: () => ipcRenderer.invoke('oceanai-updater:version'),
  openExternal: (url) => ipcRenderer.invoke('oceanai-updater:open-external', url),
  onChecking: (cb) => ipcRenderer.on('oceanai-updater:checking', () => cb && cb()),
  onAvailable: (cb) => ipcRenderer.on('oceanai-updater:available', (_e, payload) => cb && cb(payload)),
  onNotAvailable: (cb) => ipcRenderer.on('oceanai-updater:not-available', () => cb && cb()),
  onProgress: (cb) => ipcRenderer.on('oceanai-updater:progress', (_e, payload) => cb && cb(payload)),
  onDownloaded: (cb) => ipcRenderer.on('oceanai-updater:downloaded', () => cb && cb()),
  onError: (cb) => ipcRenderer.on('oceanai-updater:error', (_e, payload) => cb && cb(payload))
});
