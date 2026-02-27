const { app, BrowserWindow, shell } = require('electron');
const path = require('path');

const APP_ID = 'com.oceanandwild.velocitysurge';

if (process.platform === 'win32') {
  app.setAppUserModelId(APP_ID);
}

function createWindow() {
  const iconPath = path.join(__dirname, 'build', 'velocitysurge.ico');

  const win = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 1024,
    minHeight: 680,
    icon: iconPath,
    autoHideMenuBar: true,
    show: false,
    backgroundColor: '#070b14',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  win.once('ready-to-show', () => {
    win.show();
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  win.loadFile(path.join(__dirname, 'index.html'));
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
