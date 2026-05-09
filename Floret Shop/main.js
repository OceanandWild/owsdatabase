const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const path = require('path');
const { autoUpdater } = require('electron-updater');

const APP_ID = 'com.ows.floretshop';
const isPackaged = app.isPackaged;
let mainWindow = null;
let updaterBootstrapped = false;

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
    minWidth: 960,
    minHeight: 680,
    icon: iconPath,
    title: 'Floret Shop',
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
    const message = err?.message || 'Error desconocido';
    sendToRenderer('floret-updater:error', message);
    return { ok: false, reason: message };
  }
}

function setupUpdater() {
  if (!isPackaged || updaterBootstrapped) return;
  updaterBootstrapped = true;

  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.allowPrerelease = true;
  autoUpdater.channel = 'latest';

  autoUpdater.on('checking-for-update', () => sendToRenderer('floret-updater:checking'));
  autoUpdater.on('update-available', (info) => sendToRenderer('floret-updater:available', info));
  autoUpdater.on('update-not-available', () => sendToRenderer('floret-updater:not-available'));
  autoUpdater.on('download-progress', (progress) => sendToRenderer('floret-updater:progress', progress));
  autoUpdater.on('error', (err) => sendToRenderer('floret-updater:error', err?.message || 'Error de updater'));
  autoUpdater.on('update-downloaded', async () => {
    sendToRenderer('floret-updater:downloaded');
    const result = await dialog.showMessageBox(mainWindow || null, {
      type: 'info',
      buttons: ['Reiniciar ahora', 'Despues'],
      defaultId: 0,
      cancelId: 1,
      title: 'Actualizacion lista',
      message: 'Floret Shop descargó una actualización.',
      detail: '¿Quieres reiniciar ahora para instalarla?',
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

ipcMain.handle('floret-updater:check', async () => checkForUpdatesSafe());
ipcMain.handle('floret-updater:install', async () => {
  if (!isPackaged) return { ok: false, reason: 'unpackaged' };
  autoUpdater.quitAndInstall(false, true);
  return { ok: true };
});
ipcMain.handle('floret-updater:version', () => app.getVersion());
ipcMain.handle('floret-updater:open-external', async (_event, rawUrl) => {
  const url = String(rawUrl || '').trim();
  if (!url) return { ok: false, reason: 'empty-url' };
  await shell.openExternal(url);
  return { ok: true };
});
