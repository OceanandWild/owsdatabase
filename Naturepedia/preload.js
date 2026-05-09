const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('naturepediaDesktop', {
  isDesktop: true,
  platform: process.platform
});
