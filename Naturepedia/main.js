const { app, BrowserWindow, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');

function createWindow() {
  const iconPath = path.join(__dirname, 'build', 'naturepedia-icon.png');
  const icon = fs.existsSync(iconPath) ? nativeImage.createFromPath(iconPath) : undefined;

  const win = new BrowserWindow({
    width: 1366,
    height: 820,
    minWidth: 1024,
    minHeight: 680,
    icon,
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: path.join(__dirname, 'preload.js')
    }
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
