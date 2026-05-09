const { contextBridge, ipcRenderer } = require("electron");

function onUpdateStatus(callback) {
  if (typeof callback !== "function") return () => {};
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on("app:update-status", listener);
  return () => ipcRenderer.removeListener("app:update-status", listener);
}

contextBridge.exposeInMainWorld("oceanPayDesktop", {
  getVersion: () => ipcRenderer.invoke("app:get-version"),
  checkForUpdates: () => ipcRenderer.invoke("app:check-for-updates"),
  quitAndInstall: () => ipcRenderer.invoke("app:quit-and-install"),
  onUpdateStatus
});
