const path = require("path");
const { app, BrowserWindow, ipcMain, shell } = require("electron");
const { autoUpdater } = require("electron-updater");

const APP_ID = "com.oceanwildstudios.oceanpay";
const isDev = !app.isPackaged;
let mainWindow = null;

app.setAppUserModelId(APP_ID);

function iconPath() {
  return path.join(__dirname, "build", "icon.ico");
}

function sendUpdateStatus(payload) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send("app:update-status", payload);
}

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1200,
    minHeight: 760,
    show: false,
    backgroundColor: "#0b1220",
    icon: iconPath(),
    autoHideMenuBar: true,
    title: "Ocean Pay",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      devTools: true
    }
  });

  win.once("ready-to-show", () => {
    win.show();
  });

  // Keep OAuth and external links in system browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  win.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith("file://")) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  win.loadFile(path.join(__dirname, "index.html"));
  return win;
}

function configureUpdater() {
  if (isDev) return;

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;

  autoUpdater.on("checking-for-update", () => {
    sendUpdateStatus({ phase: "checking", message: "Checking for updates..." });
  });

  autoUpdater.on("update-available", (info) => {
    sendUpdateStatus({
      phase: "available",
      version: info?.version || "",
      message: "Update available"
    });
  });

  autoUpdater.on("download-progress", (progress) => {
    sendUpdateStatus({
      phase: "downloading",
      percent: Number(progress?.percent || 0),
      transferred: Number(progress?.transferred || 0),
      total: Number(progress?.total || 0),
      bytesPerSecond: Number(progress?.bytesPerSecond || 0)
    });
  });

  autoUpdater.on("update-not-available", () => {
    sendUpdateStatus({ phase: "idle", message: "No updates available" });
  });

  autoUpdater.on("update-downloaded", (info) => {
    sendUpdateStatus({
      phase: "ready",
      version: info?.version || "",
      message: "Update downloaded"
    });
  });

  autoUpdater.on("error", (err) => {
    sendUpdateStatus({
      phase: "error",
      message: err?.message || String(err)
    });
  });
}

app.whenReady().then(() => {
  mainWindow = createMainWindow();
  configureUpdater();

  if (!isDev) {
    setTimeout(() => {
      autoUpdater.checkForUpdates().catch((err) => {
        sendUpdateStatus({
          phase: "error",
          message: err?.message || String(err)
        });
      });
    }, 1800);
  }

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createMainWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

ipcMain.handle("app:get-version", () => app.getVersion());

ipcMain.handle("app:check-for-updates", async () => {
  if (isDev) return { ok: false, message: "Updates disabled in development mode." };
  try {
    await autoUpdater.checkForUpdates();
    return { ok: true };
  } catch (err) {
    return { ok: false, message: err?.message || String(err) };
  }
});

ipcMain.handle("app:quit-and-install", () => {
  if (!isDev) {
    autoUpdater.quitAndInstall();
  }
  return true;
});
