const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("ows", {
  platform: process.platform
});
