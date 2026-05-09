const { contextBridge, shell } = require('electron');
const { ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('wwmHost', {
  openExternal: (url) => {
    if (typeof url === 'string' && /^https?:\/\//i.test(url)) {
      shell.openExternal(url);
    }
  },
  onUpdateAvailable: (cb) => ipcRenderer.on('update-available', (_, info) => cb(info)),
  onUpdateDownloaded: (cb) => ipcRenderer.on('update-downloaded', () => cb()),
  onDownloadProgress: (cb) => ipcRenderer.on('update-download-progress', (_, prog) => cb(prog)),
  onUpdateNotAvailable: (cb) => ipcRenderer.on('update-not-available', () => cb()),
  onUpdateError: (cb) => ipcRenderer.on('update-error', (_, err) => cb(err)),
  installUpdate: () => ipcRenderer.invoke('install-update'),
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),
  isElectron: true,
});
