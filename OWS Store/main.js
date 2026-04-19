const { app, BrowserWindow, ipcMain, nativeImage, shell, Notification, Tray, Menu } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const fs = require('fs');
const os = require('os');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

let mainWindow = null;
let appTray = null;
let isQuitting = false;
let backgroundHintShown = false;
const semverTripletRegex = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const APP_ID = 'com.oceanwildstudios.nexusstore';
const APP_DISPLAY_NAME = 'OWS Store';
const API_URL = 'https://owsdatabase.onrender.com';
const INSTALLER_CACHE_DIR = path.join(os.tmpdir(), 'ows-store-installers');
const INSTALLER_LAUNCH_DIR = path.join(os.tmpdir(), 'ows-store-installer-launch');
const PUSH_STATE_FILENAME = 'ows-push-state.json';
const PUSH_WORKER_TASK_NAME = 'OWSStorePushWorker';
const PUSH_REALTIME_POLL_MS = 30 * 1000;
let updaterReady = false;
let windowsUpdateDownloaded = false;
let wnsChannelCache = '';
let wnsChannelCacheAt = 0;
let pushRealtimeTimer = null;
const externalInstallTasks = new Map();
const httpsAgent = new https.Agent({ keepAlive: true, maxSockets: 32, keepAliveMsecs: 3000, scheduling: 'fifo' });
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });
const DOWNLOAD_PROGRESS_EMIT_MS = 750;        // reduce IPC chatter, keep UI responsive
const DOWNLOAD_PROGRESS_EMIT_BYTES = 512 * 1024; // emit each 512KB downloaded
const DOWNLOAD_PROGRESS_EMIT_STEP = 1;            // emit each 1%
const DOWNLOAD_STALL_TIMEOUT_MS = 20 * 1000;      // 20s sin datos = estancado (antes 45s)
const DOWNLOAD_MIN_SPEED_BPS = 30 * 1024;         // 30 KB/s velocidad minima sostenida
const DOWNLOAD_MIN_SPEED_WINDOW_MS = 30 * 1000;   // ventana de 30s para medir velocidad minima
const DOWNLOAD_RETRY_ATTEMPTS = 5;                 // mas reintentos (antes 3)
const DOWNLOAD_RETRY_BASE_DELAY_MS = 800;
const DOWNLOAD_PARALLEL_CHUNKS = 6;               // conexiones paralelas para superar throttling
const DOWNLOAD_CHUNK_MIN_SIZE = 4 * 1024 * 1024;  // minimo 4MB por chunk para usar paralelo

app.setAppUserModelId(APP_ID);
app.setName(APP_DISPLAY_NAME);

function readJsonFileSafe(filePath, fallback = null) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return fallback;
  }
}

function writeJsonFileSafe(filePath, data) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (_) {
    return false;
  }
}

function getPushStatePath() {
  return path.join(app.getPath('userData'), PUSH_STATE_FILENAME);
}

function getOrCreatePushState() {
  const statePath = getPushStatePath();
  const current = readJsonFileSafe(statePath, {});
  const nowIso = new Date().toISOString();
  if (!current.deviceId) {
    current.deviceId = `ows-${crypto.randomBytes(12).toString('hex')}`;
  }
  current.platform = 'windows';
  if (!current.createdAt) current.createdAt = nowIso;
  current.updatedAt = nowIso;
  writeJsonFileSafe(statePath, current);
  return current;
}

async function registerPushDeviceInBackend() {
  const state = getOrCreatePushState();
  try {
    const res = await fetch(`${API_URL}/ows-store/push/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id: state.deviceId,
        platform: 'windows',
        provider: 'local',
        metadata: {
          source: 'ows-store-worker',
          appVersion: app.getVersion(),
        },
      }),
    });
    return res.ok;
  } catch (_) {
    return false;
  }
}

async function fetchPushInboxFromBackend(limit = 20) {
  const state = getOrCreatePushState();
  try {
    const url = `${API_URL}/ows-store/push/inbox?device_id=${encodeURIComponent(state.deviceId)}&platform=windows&limit=${Math.max(1, Number(limit || 20))}&nocache=${Date.now()}`;
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) return [];
    const json = await res.json().catch(() => ({}));
    return Array.isArray(json?.notifications) ? json.notifications : [];
  } catch (_) {
    return [];
  }
}

async function ackPushInboxItem(id) {
  const state = getOrCreatePushState();
  const numericId = Number(id || 0);
  if (!Number.isFinite(numericId) || numericId <= 0) return false;
  try {
    const res = await fetch(`${API_URL}/ows-store/push/inbox/${numericId}/ack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: state.deviceId }),
    });
    return res.ok;
  } catch (_) {
    return false;
  }
}

function showWorkerNotification(title, body) {
  try {
    if (!Notification || !Notification.isSupported()) return false;
    const iconPath = path.join(__dirname, 'build', 'icon.ico');
    const toast = new Notification({
      title: String(title || APP_DISPLAY_NAME),
      body: String(body || 'Nueva actualizacion disponible'),
      icon: fs.existsSync(iconPath) ? iconPath : undefined,
      silent: false,
    });
    toast.show();
    return true;
  } catch (_) {
    return false;
  }
}

async function runPushWorkerOnce() {
  await registerPushDeviceInBackend().catch(() => {});
  const inbox = await fetchPushInboxFromBackend(20);
  if (!inbox.length) return { ok: true, delivered: 0 };
  let delivered = 0;
  for (const item of inbox) {
    const title = String(item?.title || 'OWS Store');
    const body = String(item?.body || 'Nueva actualizacion disponible');
    if (showWorkerNotification(title, body)) delivered += 1;
    await ackPushInboxItem(item?.id).catch(() => {});
  }
  return { ok: true, delivered };
}

function startWindowsRealtimePushLoop() {
  if (process.platform !== 'win32') return;
  if (pushRealtimeTimer) return;
  runPushWorkerOnce().catch(() => {});
  pushRealtimeTimer = setInterval(() => {
    runPushWorkerOnce().catch(() => {});
  }, PUSH_REALTIME_POLL_MS);
}

function stopWindowsRealtimePushLoop() {
  if (!pushRealtimeTimer) return;
  clearInterval(pushRealtimeTimer);
  pushRealtimeTimer = null;
}

function ensureWindowsPushWorkerScheduledTask() {
  if (process.platform !== 'win32' || !app.isPackaged) return;
  const exe = process.execPath;
  const taskAction = `"${exe}" --ows-push-worker`;
  const args = [
    '/Create',
    '/F',
    '/TN',
    PUSH_WORKER_TASK_NAME,
    '/SC',
    'MINUTE',
    '/MO',
    '5',
    '/TR',
    taskAction,
  ];
  try {
    const child = spawn('schtasks.exe', args, { windowsHide: true, stdio: 'ignore' });
    child.on('error', () => {});
  } catch (_) {}
}

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
  mainWindow.on('close', (event) => {
    if (isQuitting || process.platform === 'darwin') return;
    event.preventDefault();
    mainWindow.hide();
    mainWindow.setSkipTaskbar(true);
    if (!backgroundHintShown && Notification && Notification.isSupported()) {
      backgroundHintShown = true;
      try {
        const toast = new Notification({
          title: APP_DISPLAY_NAME,
          body: 'OWS Store sigue activo en segundo plano para alertas de updates.'
        });
        toast.show();
      } catch (_) {}
    }
  });
  mainWindow.on('show', () => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.setSkipTaskbar(false);
  });
  mainWindow.on('closed', () => { mainWindow = null; });

  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
}

function showMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    createWindow();
    return;
  }
  if (!mainWindow.isVisible()) mainWindow.show();
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.setSkipTaskbar(false);
  mainWindow.focus();
}

function createTray() {
  if (appTray || process.platform !== 'win32') return;
  const iconPath = path.join(__dirname, 'build', 'icon.ico');
  const fallbackPath = path.join(__dirname, 'resources', 'icon.png');
  const trayIconPath = fs.existsSync(iconPath) ? iconPath : fallbackPath;
  if (!fs.existsSync(trayIconPath)) return;
  appTray = new Tray(trayIconPath);
  appTray.setToolTip(APP_DISPLAY_NAME);
  const menu = Menu.buildFromTemplate([
    { label: 'Abrir OWS Store', click: () => showMainWindow() },
    { type: 'separator' },
    {
      label: 'Salir',
      click: () => {
        isQuitting = true;
        app.quit();
      }
    }
  ]);
  appTray.setContextMenu(menu);
  appTray.on('double-click', () => showMainWindow());
  appTray.on('click', () => showMainWindow());
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

function getInstallerLaunchPath(installerName) {
  ensureDir(INSTALLER_LAUNCH_DIR);
  const ext = path.extname(installerName) || '.exe';
  const base = path.basename(installerName, ext).replace(/[^a-zA-Z0-9._-]/g, '_') || 'installer';
  return path.join(INSTALLER_LAUNCH_DIR, `${base}-${Date.now()}-${Math.floor(Math.random() * 10000)}${ext}`);
}

function cleanupOldLauncherCopies(maxAgeMs = 24 * 60 * 60 * 1000) {
  try {
    ensureDir(INSTALLER_LAUNCH_DIR);
    const now = Date.now();
    const entries = fs.readdirSync(INSTALLER_LAUNCH_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const filePath = path.join(INSTALLER_LAUNCH_DIR, entry.name);
      try {
        const stats = fs.statSync(filePath);
        if (!stats.isFile()) continue;
        const ageMs = now - Number(stats.mtimeMs || 0);
        if (Number.isFinite(ageMs) && ageMs >= maxAgeMs) {
          fs.unlinkSync(filePath);
        }
      } catch (_) {}
    }
  } catch (_) {}
}

function prepareInstallerLaunchPath(sourcePath, installerName) {
  const isExe = /\.exe$/i.test(String(sourcePath || ''));
  if (!isExe || !safeExists(sourcePath)) return sourcePath;
  cleanupOldLauncherCopies();
  const launchPath = getInstallerLaunchPath(installerName || path.basename(sourcePath));
  fs.copyFileSync(sourcePath, launchPath);
  return launchPath;
}

function buildRequestOptions(url, method = 'GET') {
  const parsed = new URL(url);
  // Use browser-like headers for GitHub releases to avoid throttling
  const isGitHub = parsed.hostname.includes('github.com') || parsed.hostname.includes('objects.githubusercontent.com');
  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || undefined,
    path: `${parsed.pathname}${parsed.search}`,
    method,
    headers: isGitHub ? {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': 'application/octet-stream',
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    } : {
      'User-Agent': 'OWS-Store-Installer/1.0',
      'Accept': '*/*',
    },
    agent: parsed.protocol === 'https:' ? httpsAgent : httpAgent,
  };
}

function canReuseCachedInstaller(filePath, expectedSize = 0) {
  if (!safeExists(filePath)) return false;
  try {
    const stats = fs.statSync(filePath);
    if (!stats.isFile() || stats.size <= 0) return false;
    // Never trust cache if the file does not look like a Windows executable.
    if (!isLikelyWindowsExecutable(filePath)) return false;
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
  let exeLastWriteMs = 0;
  let installDirLastWriteMs = 0;
  if (exePath && safeExists(exePath)) {
    try {
      const st = fs.statSync(exePath);
      exeLastWriteMs = Number(st.mtimeMs || 0);
    } catch (_) {}
  }
  if (installDir && safeExists(installDir)) {
    try {
      const st = fs.statSync(installDir);
      installDirLastWriteMs = Number(st.mtimeMs || 0);
    } catch (_) {}
  }

  return {
    installed: Boolean(exePath),
    exePath,
    uninstallPath,
    installDir,
    exeLastWriteMs: Number.isFinite(exeLastWriteMs) ? exeLastWriteMs : 0,
    installDirLastWriteMs: Number.isFinite(installDirLastWriteMs) ? installDirLastWriteMs : 0,
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

// Resolve final URL after redirects (HEAD request) to get content-length and check Range support
function resolveDownloadUrl(url, redirectsLeft = 6) {
  return new Promise((resolve) => {
    if (!/^https?:\/\//i.test(String(url || ''))) return resolve({ url, size: 0, acceptsRanges: false });
    const transport = url.startsWith('https://') ? https : http;
    const options = buildRequestOptions(url, 'HEAD');
    const req = transport.request(options, (res) => {
      const code = res.statusCode || 0;
      const location = res.headers.location;
      if ([301, 302, 303, 307, 308].includes(code) && location && redirectsLeft > 0) {
        res.resume();
        return resolve(resolveDownloadUrl(new URL(location, url).toString(), redirectsLeft - 1));
      }
      res.resume();
      const size = Number(res.headers['content-length'] || 0);
      const acceptsRanges = String(res.headers['accept-ranges'] || '').toLowerCase() === 'bytes';
      resolve({ url, size: Number.isFinite(size) ? size : 0, acceptsRanges });
    });
    req.setTimeout(12000, () => { req.destroy(); resolve({ url, size: 0, acceptsRanges: false }); });
    req.on('error', () => resolve({ url, size: 0, acceptsRanges: false }));
    req.end();
  });
}

// Download a single byte range into a buffer
function downloadChunk(url, start, end, taskRef) {
  return new Promise((resolve, reject) => {
    if (taskRef?.cancelled) return reject(new Error('Descarga cancelada.'));
    const transport = url.startsWith('https://') ? https : http;
    const options = buildRequestOptions(url, 'GET');
    options.headers = { ...options.headers, 'Range': `bytes=${start}-${end}` };
    const req = transport.request(options, (res) => {
      const code = res.statusCode || 0;
      if (code !== 206 && code !== 200) {
        res.resume();
        return reject(new Error(`Chunk HTTP ${code} para rango ${start}-${end}`));
      }
      const chunks = [];
      res.on('data', (c) => {
        if (taskRef?.cancelled) { res.destroy(); return reject(new Error('Descarga cancelada.')); }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.setTimeout(60000, () => { req.destroy(new Error(`Chunk timeout ${start}-${end}`)); });
    req.on('error', reject);
    req.end();
  });
}

// Parallel chunked download — splits file into N chunks and downloads simultaneously
async function downloadParallel(url, destinationPath, totalBytes, taskRef, onProgress) {
  const numChunks = DOWNLOAD_PARALLEL_CHUNKS;
  const chunkSize = Math.ceil(totalBytes / numChunks);
  const ranges = [];
  for (let i = 0; i < numChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize - 1, totalBytes - 1);
    ranges.push({ start, end, index: i });
  }

  const startedAt = Date.now();
  const chunkProgress = new Array(numChunks).fill(0); // bytes downloaded per chunk
  const SPEED_WINDOW_MS = 8000;
  const speedSamples = [];
  let speedWindowBytes = 0;
  let lastEmit = 0;
  let lastEmitBytes = 0;
  let lastEmitPercent = -1;

  const emitProgress = () => {
    if (!onProgress) return;
    const now = Date.now();
    while (speedSamples.length > 0 && (now - speedSamples[0].t) > SPEED_WINDOW_MS) {
      speedWindowBytes -= speedSamples[0].bytes;
      speedSamples.shift();
    }
    const windowElapsedSec = Math.min((now - startedAt) / 1000, SPEED_WINDOW_MS / 1000);
    const bytesPerSecond = windowElapsedSec > 0.5 ? speedWindowBytes / Math.min(windowElapsedSec, SPEED_WINDOW_MS / 1000) : 0;
    const downloadedBytes = chunkProgress.reduce((a, b) => a + b, 0);
    const percent = totalBytes > 0 ? (downloadedBytes / totalBytes) * 100 : null;
    const percentInt = Number.isFinite(percent) ? Math.floor(percent) : -1;
    const dueByTime = (now - lastEmit) >= DOWNLOAD_PROGRESS_EMIT_MS;
    const dueByBytes = (downloadedBytes - lastEmitBytes) >= DOWNLOAD_PROGRESS_EMIT_BYTES;
    const dueByPercent = percentInt >= 0 && (percentInt - lastEmitPercent) >= DOWNLOAD_PROGRESS_EMIT_STEP;
    if (!(dueByTime || dueByBytes || dueByPercent)) return;
    lastEmit = now;
    lastEmitBytes = downloadedBytes;
    if (percentInt >= 0) lastEmitPercent = percentInt;
    onProgress({ downloadedBytes, totalBytes, bytesPerSecond, percent });
  };

  // Download all chunks in parallel with per-chunk retry
  const buffers = await Promise.all(ranges.map(async ({ start, end, index }) => {
    let lastErr = null;
    for (let attempt = 0; attempt < 4; attempt++) {
      if (taskRef?.cancelled) throw new Error('Descarga cancelada.');
      try {
        // Wrap downloadChunk to track progress incrementally
        const chunkLen = end - start + 1;
        const transport = url.startsWith('https://') ? https : http;
        const options = buildRequestOptions(url, 'GET');
        options.headers = { ...options.headers, 'Range': `bytes=${start}-${end}` };
        const buf = await new Promise((resolve, reject) => {
          const req = transport.request(options, (res) => {
            const code = res.statusCode || 0;
            if (code !== 206 && code !== 200) { res.resume(); return reject(new Error(`HTTP ${code}`)); }
            const chunks = [];
            let received = 0;
            res.on('data', (c) => {
              if (taskRef?.cancelled) { res.destroy(); return reject(new Error('Cancelado.')); }
              chunks.push(c);
              received += c.length;
              const delta = c.length;
              chunkProgress[index] += delta;
              const now = Date.now();
              speedSamples.push({ t: now, bytes: delta });
              speedWindowBytes += delta;
              emitProgress();
            });
            res.on('end', () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
          });
          req.setTimeout(90000, () => req.destroy(new Error('Chunk timeout')));
          req.on('error', reject);
          req.end();
        });
        return buf;
      } catch (err) {
        lastErr = err;
        chunkProgress[index] = 0; // reset progress for retry
        if (attempt < 3) await wait(600 * (attempt + 1));
      }
    }
    throw lastErr || new Error(`Chunk ${index} fallido`);
  }));

  // Write all chunks sequentially to file
  const file = fs.createWriteStream(destinationPath);
  await new Promise((resolve, reject) => {
    file.on('finish', resolve);
    file.on('error', reject);
    for (const buf of buffers) file.write(buf);
    file.end();
  });

  // Final progress emit
  if (onProgress) {
    const elapsedSec = Math.max((Date.now() - startedAt) / 1000, 0.001);
    onProgress({ downloadedBytes: totalBytes, totalBytes, bytesPerSecond: totalBytes / elapsedSec, percent: 100 });
  }
}

async function downloadInstallerWithRetries(url, destinationPath, taskRef, onProgress, attempts = DOWNLOAD_RETRY_ATTEMPTS) {
  let lastError = null;
  const maxAttempts = Math.max(1, Number(attempts || DOWNLOAD_RETRY_ATTEMPTS));

  // Resolve final URL and check if server supports Range requests
  let resolvedUrl = url;
  let totalBytes = 0;
  let acceptsRanges = false;
  try {
    const info = await resolveDownloadUrl(url);
    resolvedUrl = info.url || url;
    totalBytes = info.size || 0;
    acceptsRanges = info.acceptsRanges;
  } catch (_) {}

  const useParallel = acceptsRanges && totalBytes >= DOWNLOAD_CHUNK_MIN_SIZE;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (taskRef?.cancelled) throw new Error('Descarga cancelada por el usuario.');
    try {
      if (attempt > 1 && safeExists(destinationPath)) {
        try { fs.unlinkSync(destinationPath); } catch (_) {}
      }
      if (useParallel) {
        await downloadParallel(resolvedUrl, destinationPath, totalBytes, taskRef, onProgress);
      } else {
        await downloadWithRedirects(url, destinationPath, taskRef, onProgress);
      }
      return destinationPath;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err || 'Error de descarga desconocido.'));
      if (taskRef?.cancelled) throw new Error('Descarga cancelada por el usuario.');
      if (attempt >= maxAttempts) break;
      await wait(DOWNLOAD_RETRY_BASE_DELAY_MS * attempt);
    }
  }
  throw lastError || new Error('No se pudo descargar el instalador.');
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
  const isExe = /\.exe$/i.test(String(filePath || ''));
  const launchDirect = () => {
    const child = spawn(filePath, [], {
      detached: true,
      stdio: 'ignore',
      windowsHide: false,
    });
    child.unref();
  };
  const launchViaPowerShell = () => {
    const escapedPath = String(filePath || '').replace(/'/g, "''");
    const child = spawn('powershell.exe', [
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-Command',
      `Start-Process -FilePath '${escapedPath}'`,
    ], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.unref();
  };

  let lastError = '';
  for (let i = 0; i < attempts; i += 1) {
    if (isExe) {
      try {
        launchDirect();
        return '';
      } catch (err) {
        lastError = err && err.message ? err.message : String(err);
        if (/being used by another process|used by another process|in use|locked|bloquead/i.test(String(lastError))) {
          await wait(delayMs);
          continue;
        }
      }
      try {
        launchViaPowerShell();
        return '';
      } catch (err) {
        lastError = err && err.message ? err.message : String(err);
        if (/being used by another process|used by another process|in use|locked|bloquead/i.test(String(lastError))) {
          await wait(delayMs);
          continue;
        }
      }
    }

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

function isLikelyWindowsExecutable(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const header = Buffer.alloc(2);
    const read = fs.readSync(fd, header, 0, 2, 0);
    fs.closeSync(fd);
    if (read < 2) return false;
    return header[0] === 0x4d && header[1] === 0x5a; // "MZ"
  } catch (_) {
    return false;
  }
}

function resolveWnsChannelUriViaPowerShell(timeoutMs = 20000) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve({ ok: false, reason: 'not-windows' });
    const psScript = `
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
  $op = [Windows.Networking.PushNotifications.PushNotificationChannelManager, Windows.Networking.PushNotifications, ContentType=WindowsRuntime]::CreatePushNotificationChannelForApplicationAsync()
  $task = [System.WindowsRuntimeSystemExtensions]::AsTask($op)
  $null = $task.Wait(${Math.max(5000, Number(timeoutMs || 20000))})
  if ($task.IsCompleted -and $task.Result -and $task.Result.Uri) {
    Write-Output $task.Result.Uri
    exit 0
  }
  exit 2
} catch {
  Write-Output $_.Exception.Message
  exit 1
}
`.trim();

    let stdout = '';
    let stderr = '';
    const child = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', psScript], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    const killer = setTimeout(() => {
      try { child.kill(); } catch (_) {}
      resolve({ ok: false, reason: 'timeout', stderr: stderr.trim() });
    }, Math.max(5000, Number(timeoutMs || 20000)));

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (err) => {
      clearTimeout(killer);
      resolve({ ok: false, reason: err?.message || 'spawn-error', stderr: stderr.trim() });
    });
    child.on('close', (code) => {
      clearTimeout(killer);
      const uri = String(stdout || '').trim();
      if (code === 0 && uri) return resolve({ ok: true, uri });
      return resolve({ ok: false, reason: `exit-${code}`, stderr: String(stderr || stdout || '').trim() });
    });
  });
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
      let lastChunkAt = Date.now();
      // Sliding window for speed calculation (last 8 seconds)
      const SPEED_WINDOW_MS = 8000;
      const speedSamples = []; // { t, bytes }
      let speedWindowBytes = 0;
      // Minimum speed tracking
      let minSpeedWindowStart = Date.now();
      let minSpeedWindowBytes = 0;
      let settled = false;
      let stallTimer = null;
      // 64KB write buffer — avoids backpressure stalls that throttle the TCP receive window.
      const file = fs.createWriteStream(destinationPath, { highWaterMark: 64 * 1024 });
      if (taskRef) taskRef.file = file;

      const fail = (err) => {
        if (settled) return;
        settled = true;
        if (stallTimer) {
          clearInterval(stallTimer);
          stallTimer = null;
        }
        try { file.destroy(); } catch (_) {}
        try { response.destroy(); } catch (_) {}
        fs.unlink(destinationPath, () => reject(err));
      };

      const emitProgress = () => {
        if (!onProgress) return;
        const now = Date.now();
        // Sliding window speed: drop samples older than SPEED_WINDOW_MS
        while (speedSamples.length > 0 && (now - speedSamples[0].t) > SPEED_WINDOW_MS) {
          speedWindowBytes -= speedSamples[0].bytes;
          speedSamples.shift();
        }
        const windowElapsedSec = Math.min((now - startedAt) / 1000, SPEED_WINDOW_MS / 1000);
        const bytesPerSecond = windowElapsedSec > 0.5 ? speedWindowBytes / Math.min(windowElapsedSec, SPEED_WINDOW_MS / 1000) : 0;
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
      };

      // Manual backpressure handling: pause response when write buffer is full,
      // resume on 'drain'. This prevents TCP window shrinkage that stalls downloads.
      response.on('data', (chunk) => {
        if (taskRef?.cancelled) return fail(new Error('Descarga cancelada por el usuario.'));
        const now = Date.now();
        lastChunkAt = now;
        downloadedBytes += chunk.length;
        // Update sliding window
        speedSamples.push({ t: now, bytes: chunk.length });
        speedWindowBytes += chunk.length;
        // Update min-speed window
        minSpeedWindowBytes += chunk.length;
        if ((now - minSpeedWindowStart) >= DOWNLOAD_MIN_SPEED_WINDOW_MS) {
          const windowSec = (now - minSpeedWindowStart) / 1000;
          const windowSpeedBps = minSpeedWindowBytes / windowSec;
          // If sustained speed is below minimum, abort for retry
          if (downloadedBytes > 2 * 1024 * 1024 && windowSpeedBps < DOWNLOAD_MIN_SPEED_BPS) {
            return fail(new Error(`Velocidad insuficiente (${Math.round(windowSpeedBps / 1024)} KB/s). Reintentando con nueva conexion...`));
          }
          // Reset window
          minSpeedWindowStart = now;
          minSpeedWindowBytes = 0;
        }
        emitProgress();
        const canContinue = file.write(chunk);
        if (!canContinue) {
          response.pause();
          file.once('drain', () => {
            if (!taskRef?.cancelled) response.resume();
          });
        }
      });

      response.on('error', (err) => fail(err));
      response.on('end', () => {
        if (!settled) file.end();
      });
      stallTimer = setInterval(() => {
        if (settled) return;
        if ((Date.now() - lastChunkAt) > DOWNLOAD_STALL_TIMEOUT_MS) {
          fail(new Error('La descarga del instalador se estanco. Reintentando...'));
        }
      }, 5000);
      file.on('finish', () => {
        if (settled) return;
        if (taskRef?.cancelled) return fail(new Error('Descarga cancelada por el usuario.'));
        if (totalBytes > 0 && downloadedBytes !== totalBytes) {
          return fail(new Error(`Descarga incompleta (${downloadedBytes}/${totalBytes} bytes).`));
        }
        if (downloadedBytes < (128 * 1024)) {
          return fail(new Error('Descarga incompleta: instalador demasiado pequeno.'));
        }
        settled = true;
        if (stallTimer) {
          clearInterval(stallTimer);
          stallTimer = null;
        }
        if (onProgress) {
          // Use sliding window speed for final emit
          const now = Date.now();
          while (speedSamples.length > 0 && (now - speedSamples[0].t) > SPEED_WINDOW_MS) {
            speedWindowBytes -= speedSamples[0].bytes;
            speedSamples.shift();
          }
          const windowElapsedSec = Math.min((now - startedAt) / 1000, SPEED_WINDOW_MS / 1000);
          const bytesPerSecond = windowElapsedSec > 0.5 ? speedWindowBytes / windowElapsedSec : downloadedBytes / Math.max((now - startedAt) / 1000, 0.001);
          const percent = totalBytes > 0 ? 100 : null;
          onProgress({ downloadedBytes, totalBytes, bytesPerSecond, percent });
        }
        file.close(() => resolve(destinationPath));
      });
      file.on('error', (err) => fail(err));
    });

    request.setTimeout(120000, () => {
      request.destroy(new Error('Tiempo de espera agotado descargando instalador.'));
    });
    request.on('error', (err) => reject(err));
    request.end();
  });
}

function initAutoUpdater() {
  if (!app.isPackaged || updaterReady) return;
  try {
    // Auto updater flow:
    // Windows checks and downloads automatically; install remains user-driven (button restart/install).
    autoUpdater.autoDownload = true;
    autoUpdater.autoInstallOnAppQuit = false;
    autoUpdater.allowPrerelease = true;  // Necesario: nuestro formato YYYY.M.D-tHHMM tiene sufijo que semver trata como pre-release
    autoUpdater.channel = 'latest';

    // Headers para evitar throttling de GitHub en descargas directas
    autoUpdater.requestHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': 'application/octet-stream',
      'Accept-Encoding': 'identity',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    };
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
ipcMain.handle('check-for-updates', () => checkForUpdatesSafe());
ipcMain.handle('open-external-url', (_, url) => {
  if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return false;
  shell.openExternal(url);
  return true;
});

ipcMain.handle('get-wns-channel-uri', async () => {
  if (process.platform !== 'win32') return { ok: false, reason: 'not-windows' };
  const now = Date.now();
  if (wnsChannelCache && (now - wnsChannelCacheAt) < (15 * 60 * 1000)) {
    return { ok: true, uri: wnsChannelCache, cached: true };
  }
  const result = await resolveWnsChannelUriViaPowerShell(20000);
  if (result?.ok && result.uri) {
    wnsChannelCache = String(result.uri).trim();
    wnsChannelCacheAt = now;
    return { ok: true, uri: wnsChannelCache, cached: false };
  }
  return { ok: false, reason: result?.reason || 'wns-unavailable', detail: result?.stderr || '' };
});

ipcMain.handle('show-system-notification', (_, payload) => {
  try {
    if (!Notification || !Notification.isSupported()) {
      return { ok: false, reason: 'unsupported' };
    }
    const title = String(payload?.title || APP_DISPLAY_NAME).trim() || APP_DISPLAY_NAME;
    const body = String(payload?.body || '').trim();
    const silent = Boolean(payload?.silent);
    const iconPath = path.join(__dirname, 'build', 'icon.ico');
    const toast = new Notification({
      title,
      body,
      silent,
      icon: safeExists(iconPath) ? iconPath : undefined,
    });
    toast.show();
    return { ok: true };
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    return { ok: false, reason: message };
  }
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

    // If size was not provided, probe remote size and avoid reusing stale/truncated cache.
    if (useCached && expectedSize <= 0) {
      const remoteSize = await fetchRemoteFileSizeWithRedirects(url);
      if (remoteSize > 0) {
        try {
          const localSize = fs.statSync(targetPath).size;
          if (Number(localSize) !== Number(remoteSize)) {
            useCached = false;
            try { fs.unlinkSync(targetPath); } catch (_) {}
          }
        } catch (_) {
          useCached = false;
        }
      }
    }

    if (useCached) {
      sendToRenderer('external-install-status', {
        taskId,
        phase: 'launching',
        message: 'Instalador en cache encontrado. Abriendo...',
      });
      let launchPath = targetPath;
      try {
        launchPath = prepareInstallerLaunchPath(targetPath, installerName);
      } catch (_) {
        launchPath = targetPath;
      }
      const launchCachedError = await openPathWithRetry(launchPath);
      if (!launchCachedError) {
        sendToRenderer('external-install-status', { taskId, phase: 'done', message: 'Instalador abierto desde cache.' });
        return { ok: true, filePath: launchPath || targetPath, taskId, cached: true };
      }
      // Cache invalida o bloqueada: borrar y rehacer descarga limpia.
      try { if (safeExists(targetPath)) fs.unlinkSync(targetPath); } catch (_) {}
      try { if (launchPath !== targetPath && safeExists(launchPath)) fs.unlinkSync(launchPath); } catch (_) {}
      useCached = false;
      sendToRenderer('external-install-status', {
        taskId,
        phase: 'downloading',
        message: 'Cache invalida. Reintentando descarga limpia...',
      });
    }

    try { if (safeExists(targetPath)) fs.unlinkSync(targetPath); } catch (_) {}
    sendToRenderer('external-install-status', {
      taskId,
      phase: 'downloading',
      message: 'Descargando instalador...',
    });

    await downloadInstallerWithRetries(url, targetPath, taskRef, (progress) => {
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
    if (!isLikelyWindowsExecutable(targetPath)) {
      try { fs.unlinkSync(targetPath); } catch (_) {}
      return {
        ok: false,
        error: 'El archivo descargado no es un instalador Windows valido. Recarga OWS Store y reintenta.'
      };
    }

    sendToRenderer('external-install-status', { taskId, phase: 'launching', message: 'Abriendo instalador...' });
    let launchPath = targetPath;
    try {
      launchPath = prepareInstallerLaunchPath(targetPath, installerName);
    } catch (_) {
      launchPath = targetPath;
    }
    const launchError = await openPathWithRetry(launchPath);
    if (launchError) {
      try { if (launchPath !== targetPath && safeExists(launchPath)) fs.unlinkSync(launchPath); } catch (_) {}
      return { ok: false, error: launchError };
    }

    sendToRenderer('external-install-status', { taskId, phase: 'done', message: 'Instalador abierto.' });
    return { ok: true, filePath: launchPath || targetPath, taskId };
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

// Batch scan: resolve multiple projects at once in a single IPC call
ipcMain.handle('resolve-installed-apps-batch', (_, projects) => {
  if (!Array.isArray(projects)) return [];
  return projects.map((p) => {
    try {
      const result = resolveInstalledPaths(p.hints || {});
      return { slug: p.slug, ...result };
    } catch (err) {
      return { slug: p.slug, installed: false, error: String(err?.message || err) };
    }
  });
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
  if (process.argv.includes('--ows-push-worker')) {
    runPushWorkerOnce()
      .catch(() => {})
      .finally(() => setTimeout(() => app.quit(), 1200));
    return;
  }

  if (process.platform === 'win32') {
    try {
      app.setLoginItemSettings({
        openAtLogin: true,
        openAsHidden: true
      });
    } catch (_) {}
  }
  ensureWindowsPushWorkerScheduledTask();
  startWindowsRealtimePushLoop();
  registerPushDeviceInBackend().catch(() => {});
  createWindow();
  createTray();
  initAutoUpdater();
});

app.on('before-quit', () => {
  isQuitting = true;
  stopWindowsRealtimePushLoop();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
