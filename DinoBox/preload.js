const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('dinoboxDesktop', {
  platform: process.platform,
  isDesktop: true
});
