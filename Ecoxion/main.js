const { app, BrowserWindow, ipcMain, nativeImage, shell, Notification } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');

const APP_ID = 'com.oceanandwild.ecoxion';
const APP_DISPLAY_NAME = 'Ecoxion';

let mainWindow = null;
let updaterReady = false;
let windowsUpdateDownloaded = false;

app.setAppUserModelId(APP_ID);
app.setName(APP_DISPLAY_NAME);

function createWindow() {
  const iconPath = path.join(__dirname, 'build', 'ecoxion.ico');
  const appIcon = fs.existsSync(iconPath) ? nativeImage.createFromPath(iconPath) : null;

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    icon: fs.existsSync(iconPath) ? iconPath : undefined,
    titleBarStyle: 'default',
    title: APP_DISPLAY_NAME,
    backgroundColor: '#05070a',
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  if (process.platform === 'win32' && appIcon && !appIcon.isEmpty()) {
    mainWindow.setIcon(appIcon);
  }

  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });
}

function sendToRenderer(channel, ...args) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, ...args);
  }
}

function initAutoUpdater() {
  if (!app.isPackaged || updaterReady) return;
  try {
    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowPrerelease = false;
    autoUpdater.channel = 'latest';
    autoUpdater.on('update-available', (info) => {
      windowsUpdateDownloaded = false;
      sendToRenderer('update-available', info);
    });
    autoUpdater.on('update-not-available', () => {
      windowsUpdateDownloaded = false;
      sendToRenderer('update-not-available');
    });
    autoUpdater.on('download-progress', (p) => sendToRenderer('update-download-progress', p));
    autoUpdater.on('error', (err) => sendToRenderer('update-error', err.message));
    autoUpdater.on('update-downloaded', () => {
      windowsUpdateDownloaded = true;
      sendToRenderer('update-downloaded');
    });
    updaterReady = true;
  } catch (err) {
    updaterReady = false;
    const message = err && err.message ? err.message : String(err);
    sendToRenderer('update-error', `No se pudo inicializar updater: ${message}`);
  }
}

ipcMain.handle('install-update', () => {
  if (!app.isPackaged) return { ok: false, reason: 'not-packaged' };
  if (!updaterReady) initAutoUpdater();
  if (!updaterReady) return { ok: false, reason: 'updater-not-ready' };
  if (!windowsUpdateDownloaded) return { ok: false, reason: 'update-not-downloaded' };
  try {
    autoUpdater.quitAndInstall(false, true);
    return { ok: true, closing: true };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return { ok: false, reason: message };
  }
});

ipcMain.handle('get-app-version', () => app.getVersion());

ipcMain.handle('check-for-updates', async () => {
  if (!app.isPackaged) return { ok: false, reason: 'not-packaged' };
  if (!updaterReady) initAutoUpdater();
  if (!updaterReady) return { ok: false, reason: 'updater-init-failed' };
  try {
    await autoUpdater.checkForUpdates();
    return { ok: true };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    sendToRenderer('update-error', message);
    return { ok: false, reason: 'check-failed', message };
  }
});

ipcMain.handle('open-external-url', (_, url) => {
  if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return false;
  shell.openExternal(url);
  return true;
});

ipcMain.handle('show-system-notification', (_, payload) => {
  try {
    if (!Notification || !Notification.isSupported()) {
      return { ok: false, reason: 'unsupported' };
    }
    const title = String(payload?.title || APP_DISPLAY_NAME).trim() || APP_DISPLAY_NAME;
    const body = String(payload?.body || '').trim();
    const silent = Boolean(payload?.silent);
    const iconPath = path.join(__dirname, 'build', 'ecoxion.ico');
    const toast = new Notification({
      title,
      body,
      silent,
      icon: fs.existsSync(iconPath) ? iconPath : undefined,
    });
    toast.show();
    return { ok: true };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return { ok: false, reason: message };
  }
});

app.whenReady().then(() => {
  createWindow();
  initAutoUpdater();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
