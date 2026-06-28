const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('awqgDesktop', {
  platform: process.platform,
  isDesktop: true
});
