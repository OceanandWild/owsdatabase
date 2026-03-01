const { app, BrowserWindow, ipcMain, nativeImage, shell } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const os = require('os');
const https = require('https');
const http = require('http');
const { spawn } = require('child_process');

let mainWindow = null;
const semverTripletRegex = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const APP_ID = 'com.oceanwildstudios.nexusstore';
const APP_DISPLAY_NAME = 'OWS Store';
const INSTALLER_CACHE_DIR = path.join(os.tmpdir(), 'ows-store-installers');
let updaterReady = false;
const externalInstallTasks = new Map();
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 8 });
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });
const DOWNLOAD_PROGRESS_EMIT_MS = 900;
const DOWNLOAD_PROGRESS_EMIT_BYTES = 2 * 1024 * 1024;
const DOWNLOAD_PROGRESS_EMIT_STEP = 2;

app.setAppUserModelId(APP_ID);
app.setName(APP_DISPLAY_NAME);

function createWindow() {
  const iconPath = path.join(__dirname, 'build', 'icon.ico');
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
    backgroundColor: '#020617',
    show: false,
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  if (process.platform === 'win32' && appIcon && !appIcon.isEmpty()) {
    mainWindow.setIcon(appIcon);
  }

  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });

  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
}

function sendToRenderer(channel, ...args) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, ...args);
  }
}

function sanitizeInstallerName(rawName) {
  const base = String(rawName || 'installer.exe').replace(/[^a-zA-Z0-9._-]/g, '_');
  return base.toLowerCase().endsWith('.exe') ? base : `${base}.exe`;
}

function sanitizeTaskId(rawId) {
  const base = String(rawId || '').replace(/[^a-zA-Z0-9._-]/g, '_');
  return base || `task_${Date.now()}`;
}

function uniqNonEmpty(values) {
  return Array.from(new Set((Array.isArray(values) ? values : [])
    .map((v) => String(v || '').trim())
    .filter(Boolean)));
}

function safeExists(filePath) {
  try {
    return fs.existsSync(filePath);
  } catch (_) {
    return false;
  }
}

function ensureDir(dirPath) {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
    return true;
  } catch (_) {
    return false;
  }
}

function getInstallerCachePath(installerName) {
  ensureDir(INSTALLER_CACHE_DIR);
  return path.join(INSTALLER_CACHE_DIR, installerName);
}

function buildRequestOptions(url, method = 'GET') {
  const parsed = new URL(url);
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || undefined,
    path: `${parsed.pathname}${parsed.search}`,
    method,
    headers: {
      'User-Agent': 'OWS-Store-Installer/1.0',
      Accept: '*/*',
    },
    agent: parsed.protocol === 'https:' ? httpsAgent : httpAgent,
  };
}

function canReuseCachedInstaller(filePath, expectedSize = 0) {
  if (!safeExists(filePath)) return false;
  try {
    const stats = fs.statSync(filePath);
    if (!stats.isFile() || stats.size <= 0) return false;
    const expected = Number(expectedSize || 0);
    if (expected > 0) return stats.size === expected;
    return stats.size > 2 * 1024 * 1024;
  } catch (_) {
    return false;
  }
}

function fetchRemoteFileSizeWithRedirects(url, redirectsLeft = 4) {
  return new Promise((resolve) => {
    if (!/^https?:\/\//i.test(String(url || ''))) return resolve(0);
    const transport = url.startsWith('https://') ? https : http;
    const options = buildRequestOptions(url, 'HEAD');
    const req = transport.request(options, (response) => {
      const code = response.statusCode || 0;
      const location = response.headers.location;
      if ([301, 302, 303, 307, 308].includes(code) && location && redirectsLeft > 0) {
        response.resume();
        const redirected = new URL(location, url).toString();
        return resolve(fetchRemoteFileSizeWithRedirects(redirected, redirectsLeft - 1));
      }
      if (code < 200 || code >= 300) {
        response.resume();
        return resolve(0);
      }
      const size = Number(response.headers['content-length'] || 0);
      response.resume();
      resolve(Number.isFinite(size) ? size : 0);
    });
    req.setTimeout(10000, () => {
      req.destroy(new Error('HEAD timeout'));
      resolve(0);
    });
    req.on('error', () => resolve(0));
    req.end();
  });
}

function resolveInstalledPaths(payload) {
  if (process.platform !== 'win32') return { installed: false };

  const installDirNames = uniqNonEmpty(payload?.installDirNames);
  const executableNames = uniqNonEmpty(payload?.executableNames);
  const uninstallerNames = uniqNonEmpty(payload?.uninstallerNames);
  const roots = uniqNonEmpty([
    path.join(process.env.LOCALAPPDATA || '', 'Programs'),
    process.env.ProgramFiles || '',
    process.env['ProgramFiles(x86)'] || '',
  ]);

  const candidates = [];
  for (const root of roots) {
    for (const dirName of installDirNames) {
      const dir = path.join(root, dirName);
      if (!safeExists(dir)) continue;
      for (const exeName of executableNames) {
        candidates.push({ type: 'exe', filePath: path.join(dir, exeName), installDir: dir });
      }
      for (const unName of uninstallerNames) {
        candidates.push({ type: 'uninstall', filePath: path.join(dir, unName), installDir: dir });
      }
    }
  }

  let exePath = '';
  let uninstallPath = '';
  let installDir = '';
  for (const c of candidates) {
    if (!safeExists(c.filePath)) continue;
    if (!installDir) installDir = c.installDir;
    if (c.type === 'exe' && !exePath) exePath = c.filePath;
    if (c.type === 'uninstall' && !uninstallPath) uninstallPath = c.filePath;
  }

  return {
    installed: Boolean(exePath),
    exePath,
    uninstallPath,
    installDir,
  };
}

function humanSize(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let n = bytes;
  let idx = 0;
  while (n >= 1024 && idx < units.length - 1) {
    n /= 1024;
    idx += 1;
  }
  return `${n.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function buildDownloadMessage(progress) {
  const downloaded = humanSize(progress.downloadedBytes || 0);
  const total = progress.totalBytes > 0 ? humanSize(progress.totalBytes) : null;
  const speed = progress.bytesPerSecond > 0 ? `${humanSize(progress.bytesPerSecond)}/s` : null;
  if (total && Number.isFinite(progress.percent)) {
    return `Descargando instalador... ${Math.round(progress.percent)}% (${downloaded} / ${total})${speed ? ` - ${speed}` : ''}`;
  }
  return `Descargando instalador... ${downloaded}${speed ? ` - ${speed}` : ''}`;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isValidSemverVersion(version) {
  const value = String(version || '').trim();
  const match = semverTripletRegex.exec(value);
  if (!match) return false;
  const prerelease = match[4] || '';
  if (!prerelease) return true;
  const parts = prerelease.split('.');
  for (const part of parts) {
    if (/^\d+$/.test(part) && part.length > 1 && part.startsWith('0')) {
      return false;
    }
  }
  return true;
}

async function openPathWithRetry(filePath, attempts = 6, delayMs = 350) {
  let lastError = '';
  for (let i = 0; i < attempts; i += 1) {
    const error = await shell.openPath(filePath);
    if (!error) return '';
    lastError = error;
    if (/being used by another process|used by another process|in use|locked|bloquead/i.test(String(error))) {
      await wait(delayMs);
      continue;
    }
    break;
  }
  return lastError || 'No se pudo abrir instalador.';
}

function downloadWithRedirects(url, destinationPath, taskRef, onProgress, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    if (taskRef?.cancelled) return reject(new Error('Descarga cancelada por el usuario.'));
    const transport = url.startsWith('https://') ? https : http;
    const requestOptions = buildRequestOptions(url, 'GET');
    const request = transport.request(requestOptions, (response) => {
      if (taskRef) taskRef.request = request;
      const code = response.statusCode || 0;
      const location = response.headers.location;

      if ([301, 302, 303, 307, 308].includes(code) && location) {
        response.resume();
        if (redirectsLeft <= 0) return reject(new Error('Demasiadas redirecciones al descargar instalador.'));
        const redirectedUrl = new URL(location, url).toString();
        return resolve(downloadWithRedirects(redirectedUrl, destinationPath, taskRef, onProgress, redirectsLeft - 1));
      }

      if (code < 200 || code >= 300) {
        response.resume();
        return reject(new Error(`Descarga fallida (HTTP ${code}).`));
      }

      const totalBytes = Number(response.headers['content-length'] || 0);
      let downloadedBytes = 0;
      const startedAt = Date.now();
      let lastEmit = 0;
      let lastEmitBytes = 0;
      let lastEmitPercent = -1;
      let settled = false;
      const file = fs.createWriteStream(destinationPath);
      if (taskRef) taskRef.file = file;

      const fail = (err) => {
        if (settled) return;
        settled = true;
        try { file.destroy(); } catch (_) {}
        try { response.destroy(); } catch (_) {}
        fs.unlink(destinationPath, () => reject(err));
      };

      response.on('data', (chunk) => {
        if (taskRef?.cancelled) {
          return fail(new Error('Descarga cancelada por el usuario.'));
        }

        downloadedBytes += chunk.length;
        if (!onProgress) return;
        const now = Date.now();
        const elapsedSec = Math.max((now - startedAt) / 1000, 0.001);
        const bytesPerSecond = downloadedBytes / elapsedSec;
        const percent = totalBytes > 0 ? (downloadedBytes / totalBytes) * 100 : null;
        const percentInt = Number.isFinite(percent) ? Math.floor(percent) : -1;
        const dueByTime = (now - lastEmit) >= DOWNLOAD_PROGRESS_EMIT_MS;
        const dueByBytes = (downloadedBytes - lastEmitBytes) >= DOWNLOAD_PROGRESS_EMIT_BYTES;
        const dueByPercent = percentInt >= 0 && (percentInt - lastEmitPercent) >= DOWNLOAD_PROGRESS_EMIT_STEP;
        const reachedEnd = totalBytes > 0 && downloadedBytes >= totalBytes;
        if (!(dueByTime || dueByBytes || dueByPercent || reachedEnd)) return;
        lastEmit = now;
        lastEmitBytes = downloadedBytes;
        if (percentInt >= 0) lastEmitPercent = percentInt;
        onProgress({ downloadedBytes, totalBytes, bytesPerSecond, percent });
      });

      response.on('error', (err) => fail(err));
      response.pipe(file);
      file.on('finish', () => {
        if (settled) return;
        if (taskRef?.cancelled) return fail(new Error('Descarga cancelada por el usuario.'));

        settled = true;
        if (onProgress) {
          const elapsedSec = Math.max((Date.now() - startedAt) / 1000, 0.001);
          const bytesPerSecond = downloadedBytes / elapsedSec;
          const percent = totalBytes > 0 ? 100 : null;
          onProgress({ downloadedBytes, totalBytes, bytesPerSecond, percent });
        }
        file.close(() => resolve(destinationPath));
      });
      file.on('error', (err) => fail(err));
    });

    request.setTimeout(45000, () => {
      request.destroy(new Error('Tiempo de espera agotado descargando instalador.'));
    });
    request.on('error', (err) => reject(err));
    request.end();
  });
}

function initAutoUpdater() {
  if (!app.isPackaged || updaterReady) return;
  try {
    // Manual-controlled updater flow:
    // Windows checks for updates automatically, but download/install is user-driven.
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowPrerelease = false;
    autoUpdater.channel = 'latest';
    autoUpdater.on('update-available', (info) => sendToRenderer('update-available', info));
    autoUpdater.on('update-not-available', () => sendToRenderer('update-not-available'));
    autoUpdater.on('download-progress', (p) => sendToRenderer('update-download-progress', p));
    autoUpdater.on('error', (err) => sendToRenderer('update-error', err.message));
    autoUpdater.on('update-downloaded', () => sendToRenderer('update-downloaded'));
    updaterReady = true;
  } catch (err) {
    updaterReady = false;
    const message = err && err.message ? err.message : String(err);
    sendToRenderer('update-error', `No se pudo inicializar updater: ${message}`);
  }
}

async function checkForUpdatesSafe() {
  if (!app.isPackaged) return { ok: false, reason: 'not-packaged' };
  if (!updaterReady) initAutoUpdater();
  if (!updaterReady) {
    return { ok: false, reason: 'updater-init-failed' };
  }

  const currentVersion = app.getVersion();
  if (!isValidSemverVersion(currentVersion)) {
    const msg = `Auto-update deshabilitado: version invalida "${currentVersion}". Usa formato SemVer (x.y.z).`;
    sendToRenderer('update-error', msg);
    return { ok: false, reason: 'invalid-version', message: msg };
  }

  try {
    await autoUpdater.checkForUpdates();
    return { ok: true };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    sendToRenderer('update-error', message);
    return { ok: false, reason: 'check-failed', message };
  }
}

ipcMain.handle('install-update', () => {
  autoUpdater.quitAndInstall(false, true);
});
ipcMain.handle('get-app-version', () => app.getVersion());
ipcMain.handle('check-for-updates', () => checkForUpdatesSafe());
ipcMain.handle('open-external-url', (_, url) => {
  if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return false;
  shell.openExternal(url);
  return true;
});

ipcMain.handle('install-external-installer', async (_, payload) => {
  const url = payload && typeof payload.url === 'string' ? payload.url : '';
  const installerName = sanitizeInstallerName(payload && payload.name ? payload.name : 'installer.exe');
  const taskId = sanitizeTaskId(payload && payload.taskId ? payload.taskId : installerName);
  const expectedSize = Number(payload && payload.expectedSize ? payload.expectedSize : 0);

  if (!/^https?:\/\//i.test(url)) {
    return { ok: false, error: 'URL de instalador invalida.' };
  }
  if (externalInstallTasks.has(taskId)) {
    return { ok: false, error: 'Ya existe una instalacion en curso para este proyecto.' };
  }

  try {
    const taskRef = { id: taskId, cancelled: false, request: null, file: null, path: '' };
    externalInstallTasks.set(taskId, taskRef);

    const targetPath = getInstallerCachePath(installerName);
    taskRef.path = targetPath;
    let useCached = canReuseCachedInstaller(targetPath, expectedSize);

    if (useCached) {
      sendToRenderer('external-install-status', {
        taskId,
        phase: 'launching',
        message: 'Instalador en cache encontrado. Abriendo...',
      });
      const launchCachedError = await openPathWithRetry(targetPath);
      if (launchCachedError) {
        return { ok: false, error: launchCachedError };
      }
      sendToRenderer('external-install-status', { taskId, phase: 'done', message: 'Instalador abierto desde cache.' });
      return { ok: true, filePath: targetPath, taskId, cached: true };
    }

    try { if (safeExists(targetPath)) fs.unlinkSync(targetPath); } catch (_) {}
    sendToRenderer('external-install-status', {
      taskId,
      phase: 'downloading',
      message: 'Descargando instalador...',
    });

    await downloadWithRedirects(url, targetPath, taskRef, (progress) => {
      sendToRenderer('external-install-status', {
        taskId,
        phase: 'downloading',
        ...progress,
        message: buildDownloadMessage(progress),
      });
    });

    if (taskRef.cancelled) {
      return { ok: false, error: 'Instalacion cancelada por el usuario.' };
    }

    sendToRenderer('external-install-status', { taskId, phase: 'launching', message: 'Abriendo instalador...' });
    const launchError = await openPathWithRetry(targetPath);
    if (launchError) {
      return { ok: false, error: launchError };
    }

    sendToRenderer('external-install-status', { taskId, phase: 'done', message: 'Instalador abierto.' });
    return { ok: true, filePath: targetPath, taskId };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    sendToRenderer('external-install-status', { taskId, phase: 'error', message });
    return { ok: false, error: message };
  } finally {
    const taskRef = externalInstallTasks.get(taskId);
    if (taskRef?.file) {
      try { taskRef.file.destroy(); } catch (_) {}
    }
    externalInstallTasks.delete(taskId);
  }
});

ipcMain.handle('cancel-external-installer', async (_, payload) => {
  const taskId = sanitizeTaskId(payload && payload.taskId ? payload.taskId : '');
  const taskRef = externalInstallTasks.get(taskId);
  if (!taskRef) return { ok: false, error: 'No hay descarga activa para cancelar.' };

  taskRef.cancelled = true;
  try {
    if (taskRef.request) taskRef.request.destroy(new Error('Cancelado por el usuario.'));
    if (taskRef.file) taskRef.file.destroy();
    if (taskRef.path && safeExists(taskRef.path)) fs.unlink(taskRef.path, () => {});
  } catch (_) {}

  sendToRenderer('external-install-status', { taskId, phase: 'cancelled', message: 'Instalacion cancelada.' });
  externalInstallTasks.delete(taskId);
  return { ok: true };
});

ipcMain.handle('resolve-installed-app', (_, payload) => {
  try {
    return resolveInstalledPaths(payload || {});
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return { installed: false, error: message };
  }
});

ipcMain.handle('launch-installed-app', async (_, payload) => {
  const exePath = payload && typeof payload.exePath === 'string' ? payload.exePath : '';
  if (!exePath || !safeExists(exePath)) return { ok: false, error: 'Ejecutable no encontrado.' };
  const launchError = await shell.openPath(exePath);
  if (launchError) return { ok: false, error: launchError };
  return { ok: true };
});

ipcMain.handle('uninstall-installed-app', (_, payload) => {
  const uninstallPath = payload && typeof payload.uninstallPath === 'string' ? payload.uninstallPath : '';
  if (!uninstallPath || !safeExists(uninstallPath)) return { ok: false, error: 'Desinstalador no encontrado.' };
  try {
    const child = spawn(uninstallPath, [], {
      detached: true,
      stdio: 'ignore',
      windowsHide: false,
    });
    child.unref();
    return { ok: true };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return { ok: false, error: message };
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
