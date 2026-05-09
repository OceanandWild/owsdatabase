const { app, BrowserWindow, shell, ipcMain, nativeImage } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');

const APP_ID = 'com.oceanwildstudios.wildweaponmayhem';
let mainWindow = null;
let updaterReady = false;
const semverTripletRegex = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$/;

app.setAppUserModelId(APP_ID);
app.setName('WildWeapon Mayhem');

function resolveRuntimeIconPath() {
  const candidates = [
    path.join(__dirname, 'wildweaponmayhem.ico'),
    path.join(process.resourcesPath || '', 'wildweaponmayhem.ico'),
    path.join(process.resourcesPath || '', 'app.asar.unpacked', 'wildweaponmayhem.ico'),
  ];
  for (const p of candidates) {
    try {
      if (p && fs.existsSync(p)) return p;
    } catch (_) {}
  }
  return '';
}

function createWindow() {
  const iconPath = resolveRuntimeIconPath();
  const appIcon = iconPath ? nativeImage.createFromPath(iconPath) : null;
  mainWindow = new BrowserWindow({
    width: 1366,
    height: 768,
    minWidth: 1024,
    minHeight: 640,
    show: false,
    autoHideMenuBar: true,
    icon: iconPath || undefined,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    backgroundColor: '#050510',
    title: 'WildWeapon Mayhem',
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  if (process.platform === 'win32' && appIcon && !appIcon.isEmpty()) {
    mainWindow.setIcon(appIcon);
    mainWindow.webContents.on('did-finish-load', () => {
      try { mainWindow.setIcon(appIcon); } catch (_) {}
    });
  }
  mainWindow.once('ready-to-show', () => mainWindow.show());

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      shell.openExternal(url);
      return { action: 'deny' };
    }
    return { action: 'allow' };
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    const isLocal = url.startsWith('file://');
    if (!isLocal) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function sendToRenderer(channel, ...args) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, ...args);
  }
}

function compactUpdaterError(err) {
  const raw = err && err.message ? String(err.message) : String(err || 'Unknown updater error');
  const firstLine = raw.split('\n')[0].trim();
  if (/latest\.yml/i.test(raw) && /404/.test(raw)) {
    return 'No se encontro latest.yml en la release latest de GitHub.';
  }
  if (/Cannot find channel/i.test(raw)) {
    return 'Canal de actualizacion no encontrado.';
  }
  return firstLine || 'Error desconocido del updater.';
}

function initAutoUpdater() {
  if (!app.isPackaged || updaterReady) return;
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.allowPrerelease = true;
  autoUpdater.channel = 'latest';
  autoUpdater.on('update-available', (info) => sendToRenderer('update-available', info));
  autoUpdater.on('update-not-available', () => sendToRenderer('update-not-available'));
  autoUpdater.on('download-progress', (prog) => sendToRenderer('update-download-progress', prog));
  autoUpdater.on('update-downloaded', () => sendToRenderer('update-downloaded'));
  autoUpdater.on('error', (err) => sendToRenderer('update-error', compactUpdaterError(err)));
  updaterReady = true;
}

async function checkForUpdatesSafe() {
  if (!app.isPackaged) return { ok: false, reason: 'not-packaged' };
  if (!updaterReady) initAutoUpdater();
  const currentVersion = app.getVersion();
  if (!semverTripletRegex.test(currentVersion)) {
    const msg = `Auto-update disabled: invalid app version "${currentVersion}"`;
    sendToRenderer('update-error', msg);
    return { ok: false, reason: 'invalid-version', message: msg };
  }
  try {
    await autoUpdater.checkForUpdates();
    return { ok: true };
  } catch (err) {
    const message = compactUpdaterError(err);
    sendToRenderer('update-error', message);
    return { ok: false, reason: 'check-failed', message };
  }
}

ipcMain.handle('get-app-version', () => app.getVersion());
ipcMain.handle('check-for-updates', () => checkForUpdatesSafe());
ipcMain.handle('install-update', () => {
  autoUpdater.quitAndInstall(false, true);
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
