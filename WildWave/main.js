const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const path = require('path');
const { autoUpdater } = require('electron-updater');

const APP_ID = 'com.oceanandwild.wildwave';
const isPackaged = app.isPackaged;
let mainWindow = null;
let updaterReady = false;

app.setAppUserModelId(APP_ID);

function sendToRenderer(channel, payload) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send(channel, payload);
}

function createWindow() {
  const iconPath = path.join(__dirname, 'build', 'icon.ico');
  const preloadPath = path.join(__dirname, 'preload.js');

  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 980,
    minHeight: 680,
    icon: iconPath,
    title: 'WildWave',
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: preloadPath,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url) shell.openExternal(url).catch(() => {});
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    const currentUrl = mainWindow?.webContents?.getURL?.() || '';
    if (url && url !== currentUrl) {
      event.preventDefault();
      shell.openExternal(url).catch(() => {});
    }
  });
}

async function checkForUpdatesSafe() {
  if (!isPackaged) return { ok: false, reason: 'unpackaged' };
  try {
    await autoUpdater.checkForUpdates();
    return { ok: true };
  } catch (err) {
    sendToRenderer('wildwave-updater:error', err?.message || 'Updater error');
    return { ok: false, reason: err?.message || 'unknown' };
  }
}

function setupUpdater() {
  if (!isPackaged || updaterReady) return;
  updaterReady = true;

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.allowPrerelease = true;
  autoUpdater.channel = 'latest';

  autoUpdater.on('checking-for-update', () => sendToRenderer('wildwave-updater:checking'));
  autoUpdater.on('update-available', (info) => sendToRenderer('wildwave-updater:available', info));
  autoUpdater.on('update-not-available', () => sendToRenderer('wildwave-updater:not-available'));
  autoUpdater.on('download-progress', (progress) => sendToRenderer('wildwave-updater:progress', progress));
  autoUpdater.on('error', (err) => sendToRenderer('wildwave-updater:error', err?.message || 'Updater error'));
  autoUpdater.on('update-downloaded', async () => {
    sendToRenderer('wildwave-updater:downloaded');
    const result = await dialog.showMessageBox(mainWindow || null, {
      type: 'info',
      buttons: ['Reiniciar ahora', 'Despues'],
      defaultId: 0,
      cancelId: 1,
      title: 'Actualizacion lista',
      message: 'WildWave descargo una actualizacion.',
      detail: 'Quieres reiniciar ahora para instalarla?',
    });
    if (result.response === 0) {
      autoUpdater.quitAndInstall(false, true);
    }
  });

  setTimeout(() => {
    checkForUpdatesSafe().catch(() => {});
  }, 10000);

  setInterval(() => {
    checkForUpdatesSafe().catch(() => {});
  }, 45 * 60 * 1000);
}

app.whenReady().then(() => {
  createWindow();
  setupUpdater();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

ipcMain.handle('wildwave-updater:check', async () => checkForUpdatesSafe());
ipcMain.handle('wildwave-updater:install', async () => {
  if (!isPackaged) return { ok: false, reason: 'unpackaged' };
  autoUpdater.quitAndInstall(false, true);
  return { ok: true };
});
ipcMain.handle('wildwave-updater:version', () => app.getVersion());
ipcMain.handle('wildwave-updater:open-external', async (_event, rawUrl) => {
  const url = String(rawUrl || '').trim();
  if (!url) return { ok: false, reason: 'empty-url' };
  await shell.openExternal(url);
  return { ok: true };
});
