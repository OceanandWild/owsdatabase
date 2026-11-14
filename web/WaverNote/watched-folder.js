/* ------------------------------------------------------------
   WaverNote · carpeta vigilada

   La app no descarga música de ninguna plataforma. Este módulo solo
   mira una carpeta que el usuario elige, reconoce los archivos que
   completan canciones pendientes y los sube con el mismo endpoint que
   usa una subida manual.

   Windows: comandos nativos de Tauri (elegir, escanear y leer).
   Android: puente WaverNoteAndroid (SAF, etiquetas y subida nativa).
   Web: la tarjeta no se muestra; la función es exclusiva de la app.
   ------------------------------------------------------------ */

(function () {
  "use strict";

  const Core = window.WaverNoteWatchCore;
  if (!Core) return;

  const STORAGE_PREFIX = "wavernote.watchedFolder.v2";
  const SCAN_INTERVAL_MS = 5 * 60 * 1000;
  const MIN_SCAN_GAP_MS = 30 * 1000;
  const MAX_UPLOADS_PER_SCAN = 25;
  const MAX_TAG_FILES_ANDROID = 120;
  const MAX_TAG_FILES_DESKTOP = 12;
  const MAX_TAG_BYTES_DESKTOP = 40 * 1024 * 1024;
  const FAILURE_RETRY_MS = 30 * 60 * 1000;
  const MAX_KNOWN = 4000;
  const MAX_FAILURES = 300;
  const READ_CHUNK_BYTES = 4 * 1024 * 1024;

  const IS_ANDROID = /Android/i.test(navigator.userAgent || "");
  const bridge = () => window.WaverNoteFolder || null;
  const tauriCore = () => window.__TAURI__?.core || null;
  const canUseNative = () =>
    IS_ANDROID ? Boolean(bridge()) : Boolean(tauriCore()?.invoke);

  const runtime = {
    supported: canUseNative(),
    started: false,
    userId: 0,
    config: null,
    scanning: false,
    phase: "idle",
    timer: null,
    scanTimer: null,
    lastScanStarted: 0,
    pickWaiter: null,
    scanWaiter: null,
    uploadSeq: 0,
    uploads: new Map(),
    tagChecked: new Set(),
    cardQueued: false
  };

  /* ------------------------------------------------------------
     Configuración por cuenta
     ------------------------------------------------------------ */

  const emptyConfig = () => ({
    folder: null,
    enabled: true,
    permissionLost: false,
    folderMissing: false,
    known: {},
    failures: {},
    addedAt: 0,
    lastScanAt: 0,
    lastResult: null
  });

  const storageKey = (userId) => `${STORAGE_PREFIX}.${Number(userId) || 0}`;

  const normalizeConfig = (raw) => {
    const base = emptyConfig();
    if (!raw || typeof raw !== "object") return base;

    const folder = raw.folder;
    return {
      ...base,
      ...raw,
      folder:
        folder && (folder.value || folder.uri)
          ? {
              kind: folder.kind === "tree" ? "tree" : "path",
              value: String(folder.value || folder.uri || ""),
              label: String(folder.label || "Carpeta de música")
            }
          : null,
      enabled: raw.enabled !== false,
      permissionLost: Boolean(raw.permissionLost),
      folderMissing: Boolean(raw.folderMissing),
      known: raw.known && typeof raw.known === "object" ? raw.known : {},
      failures: raw.failures && typeof raw.failures === "object" ? raw.failures : {},
      addedAt: Number(raw.addedAt) || 0,
      lastScanAt: Number(raw.lastScanAt) || 0,
      lastResult: raw.lastResult && typeof raw.lastResult === "object" ? raw.lastResult : null
    };
  };

  const trimEntryMap = (map, limit) => {
    const entries = Object.entries(map || {})
      .filter(([, value]) => value && typeof value === "object")
      .sort((a, b) => (Number(b[1].at) || 0) - (Number(a[1].at) || 0))
      .slice(0, limit);
    return Object.fromEntries(entries);
  };

  const saveConfig = () => {
    if (!runtime.config) return;
    runtime.config.known = trimEntryMap(runtime.config.known, MAX_KNOWN);
    runtime.config.failures = trimEntryMap(runtime.config.failures, MAX_FAILURES);
    try {
      writeJSON(storageKey(runtime.userId), runtime.config);
    } catch (err) {
      /* modo privado o almacenamiento lleno */
    }
  };

  const loadConfig = (userId) => {
    let raw = null;
    try {
      raw = readJSON(storageKey(userId), null);
    } catch (err) {
      raw = null;
    }
    return normalizeConfig(raw);
  };

  /* ------------------------------------------------------------
     Utilidades de presentación
     ------------------------------------------------------------ */

  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  const timeAgo = (value) => {
    const time = Number(value) || 0;
    if (!time) return "";
    const diff = Date.now() - time;
    if (diff < 45 * 1000) return "recién";
    if (diff < 60 * 60 * 1000) return `hace ${Math.max(1, Math.round(diff / 60000))} min`;
    if (diff < 24 * 60 * 60 * 1000) return `hace ${Math.round(diff / 3600000)} h`;

    const date = new Date(time);
    return date.toLocaleDateString("es", {
      day: "2-digit",
      month: "short"
    });
  };

  const shortLabel = (value) => {
    const text = String(value || "").split(/[\\/]/).filter(Boolean).pop() || String(value || "");
    return text.length > 46 ? `${text.slice(0, 43)}…` : text;
  };

  const layoutHint = (result) => {
    const kind = result?.kind;
    if (kind === "empty") {
      return "No encontramos audio en esta carpeta. Probá con la carpeta principal donde guardás tu música.";
    }
    if (kind === "single-file") {
      return "La carpeta elegida tiene un solo archivo. Si querés completar más pendientes, cambiá a la carpeta principal de música.";
    }
    if (kind === "large" || result?.truncated) {
      return "La carpeta tiene muchísimos archivos. Revisamos una parte; si falta una canción, elegí una carpeta más específica (por ejemplo, la del artista).";
    }
    if (kind === "too-deep" || result?.depthLimited) {
      return "Hay subcarpetas más profundas de las que revisamos. Movelas un nivel arriba o elegí directamente esa carpeta.";
    }
    if (kind === "artist-tree") {
      return "Detectamos una carpeta de artista. También buscamos dentro de cada canción y en todas sus subcarpetas.";
    }
    if (kind === "deep-tree") {
      return "La carpeta tiene varias subcarpetas: revisamos cada nivel y usamos el nombre del archivo, la carpeta y las etiquetas para reconocer la canción.";
    }
    return "";
  };

  const statusInfo = () => {
    const config = runtime.config;
    if (!config?.folder) return { label: "Sin carpeta", tone: "paused" };
    if (config.permissionLost) return { label: "Permiso vencido", tone: "warning" };
    if (config.folderMissing) return { label: "No disponible", tone: "warning" };
    if (!config.enabled) return { label: "Pausada", tone: "paused" };
    if (runtime.scanning) return { label: "Revisando", tone: "busy" };
    return { label: "Activa", tone: "active" };
  };

  const button = (action, label, iconName, className = "btn btn--small btn--ghost", extra = "") =>
    `<button class="${className}" data-action="${action}" ${extra}>${icon(iconName)}${label ? ` <span>${label}</span>` : ""}</button>`;

  const legalNote = () =>
    `<p class="watch-card__legal">${icon("lock")} Solo se suben archivos que coinciden con canciones pendientes. No descargamos música de Spotify ni de otras plataformas.</p>`;

  const inviteCardHTML = () => `
    <section class="watch-card watch-card--invite">
      <span class="watch-card__icon">${icon("folder")}</span>
      <div class="watch-card__body">
        <div class="watch-card__head">
          <div>
            <h3 class="watch-card__title">Completá pendientes sin buscar archivo por archivo</h3>
            <p class="watch-card__copy">Elegí la carpeta donde guardás tu música. Cuando aparezca un archivo que coincide con una canción pendiente, WaverNote lo sube sola con tus datos y portada.</p>
          </div>
          <span class="watch-pill watch-pill--paused">Opcional</span>
        </div>
        <p class="watch-card__meta">Windows y Android · funciona con subcarpetas · no toca ni borra tus archivos</p>
        <div class="watch-card__actions">
          ${button("watched-pick", "Elegir carpeta", "folder", "btn btn--small btn--primary")}
          ${button("watched-help", "Cómo funciona", "sparkles")}
        </div>
        ${legalNote()}
      </div>
    </section>`;

  const cardHTML = () => {
    if (!runtime.supported) return "";

    const config = runtime.config;
    if (!config?.folder) return inviteCardHTML();

    const status = statusInfo();
    const result = config.lastResult;
    const pendingCount = Array.isArray(state.pending) ? state.pending.length : 0;
    const folderLabel = escapeHTML(config.folder.label || shortLabel(config.folder.value));

    const stats = [];
    if (pendingCount) stats.push(`${plural(pendingCount, "canción pendiente", "canciones pendientes")}`);
    if (result?.files) stats.push(`${plural(result.files, "archivo revisado", "archivos revisados")}`);
    if (result?.uploaded) stats.push(`${plural(result.uploaded, "completada", "completadas")}`);
    if (result?.ambiguous) stats.push(`${result.ambiguous} para revisar`);

    const metaParts = [];
    if (config.lastScanAt) metaParts.push(`Último escaneo ${timeAgo(config.lastScanAt)}`);
    if (stats.length) metaParts.push(stats.join(" · "));

    const ambiguity =
      result?.ambiguous > 0
        ? `<p class="watch-card__ambiguity">${icon("x")} ${plural(result.ambiguous, "archivo coincide", "archivos coinciden")} con más de una canción pendiente y quedó sin subir. Usá ${icon("upload")} en la fila para elegir vos.</p>`
        : "";

    const permission = config.permissionLost
      ? `<p class="watch-card__warning">${icon("lock")} Android dejó de dar acceso a esta carpeta. Volvé a elegirla para que WaverNote pueda leerla otra vez.</p>`
      : config.folderMissing
        ? `<p class="watch-card__warning">${icon("folder")} No encontramos la carpeta en este equipo. Si la moviste, cambiaste el nombre o desconectaste el disco, elegí la nueva ubicación.</p>`
        : "";

    return `
      <section class="watch-card watch-card--configured">
        <span class="watch-card__icon">${icon("folder")}</span>
        <div class="watch-card__body">
          <div class="watch-card__head">
            <div class="watch-card__head-main">
              <p class="watch-card__eyebrow">Carpeta vigilada</p>
              <h3 class="watch-card__folder" title="${escapeHTML(config.folder.value)}">${folderLabel}</h3>
            </div>
            <span class="watch-pill watch-pill--${status.tone}">${status.label}</span>
          </div>

          <p class="watch-card__copy">${
            config.permissionLost
              ? "Necesitamos permiso para leer la carpeta. Tus archivos siguen donde están."
              : config.folderMissing
                ? "La carpeta ya no está en la ubicación guardada. Tus archivos siguen donde los dejaste."
                : config.enabled
                  ? "Revisamos esta carpeta al abrir la app, al volver a ella y cada pocos minutos. Solo subimos lo que completa un pendiente."
                  : "La vigilancia está en pausa. Las canciones pendientes siguen esperando su archivo."
          }</p>

          ${metaParts.length ? `<p class="watch-card__meta">${escapeHTML(metaParts.join(" · "))}</p>` : ""}
          ${permission}
          ${ambiguity}
          ${!config.permissionLost && !config.folderMissing && result ? `<p class="watch-card__hint">${escapeHTML(layoutHint(result))}</p>` : ""}

          <div class="watch-card__actions">
            ${config.permissionLost || config.folderMissing ? "" : button("watched-scan", runtime.scanning ? "Revisando…" : "Escanear ahora", "search", "btn btn--small btn--primary", runtime.scanning ? "disabled" : "")}
            ${config.folderMissing ? "" : button("watched-toggle", config.enabled ? "Pausar" : "Activar", config.enabled ? "pause" : "play")}
            ${button("watched-pick", config.permissionLost || config.folderMissing ? "Volver a elegir" : "Cambiar", "folder")}
            ${button("watched-help", "", "sparkles", "icon-btn icon-btn--tiny watch-card__help", 'aria-label="Cómo funciona la carpeta vigilada" title="Cómo funciona"')}
            ${button("watched-forget", "", "trash", "icon-btn icon-btn--tiny watch-card__forget", 'aria-label="Olvidar esta carpeta" title="Olvidar esta carpeta"')}
          </div>
          ${legalNote()}
        </div>
      </section>`;
  };

  /* ------------------------------------------------------------
     Native bridge
     ------------------------------------------------------------ */

  const parsePayload = (value) => {
    if (!value) return null;
    if (typeof value === "object") return value;
    try {
      return JSON.parse(String(value));
    } catch (err) {
      return null;
    }
  };

  const desktopInvoke = (command, args = {}) => {
    const core = tauriCore();
    if (!core?.invoke) return Promise.reject(new Error("El puente de la app no está disponible."));
    return core.invoke(command, args);
  };

  const waitForPick = () =>
    new Promise((resolve, reject) => {
      if (runtime.pickWaiter) runtime.pickWaiter.reject(new Error("Ya hay un selector abierto."));
      const timer = window.setTimeout(() => {
        if (runtime.pickWaiter?.timer === timer) runtime.pickWaiter = null;
        reject(new Error("El selector de carpetas no respondió."));
      }, 5 * 60 * 1000);
      runtime.pickWaiter = { resolve, reject, timer };
    });

  const waitForScan = () =>
    new Promise((resolve, reject) => {
      if (runtime.scanWaiter) runtime.scanWaiter.reject(new Error("Ya hay un escaneo en curso."));
      const timer = window.setTimeout(() => {
        if (runtime.scanWaiter?.timer === timer) runtime.scanWaiter = null;
        reject(new Error("El escaneo de la carpeta tardó demasiado."));
      }, 4 * 60 * 1000);
      runtime.scanWaiter = { resolve, reject, timer };
    });

  const settlePick = (payload) => {
    const waiter = runtime.pickWaiter;
    if (!waiter) return;
    runtime.pickWaiter = null;
    window.clearTimeout(waiter.timer);
    const data = parsePayload(payload);
    if (!data) {
      waiter.reject(new Error("No se pudo leer la carpeta elegida."));
      return;
    }
    if (data.ok === false) {
      if (data.cancelled) {
        waiter.resolve(null);
        return;
      }
      const error = new Error(data.error || "No se pudo abrir la carpeta.");
      error.permissionLost = Boolean(data.permission);
      waiter.reject(error);
      return;
    }
    waiter.resolve({
      kind: data.kind === "tree" ? "tree" : "path",
      value: String(data.value || data.uri || ""),
      label: String(data.label || "Carpeta de música")
    });
  };

  const settleScan = (payload) => {
    const waiter = runtime.scanWaiter;
    if (!waiter) return;
    runtime.scanWaiter = null;
    window.clearTimeout(waiter.timer);
    const data = parsePayload(payload);
    if (!data) {
      waiter.reject(new Error("No se pudo leer el resultado del escaneo."));
      return;
    }
    if (data.ok === false || data.permissionLost) {
      const error = new Error(data.error || "No se pudo revisar la carpeta.");
      error.permissionLost = Boolean(data.permission || data.permissionLost);
      waiter.reject(error);
      return;
    }
    waiter.resolve(data);
  };

  const settleUpload = (payload) => {
    const data = parsePayload(payload);
    if (!data?.requestId) return;
    const waiter = runtime.uploads.get(String(data.requestId));
    if (!waiter) return;
    runtime.uploads.delete(String(data.requestId));
    if (data.ok === false) {
      const error = new Error(data.error || "No se pudo subir el archivo.");
      error.status = Number(data.status) || 0;
      waiter.reject(error);
      return;
    }
    waiter.resolve(data.track || null);
  };

  const onNativeFolderPicked = (payload) => settlePick(payload);
  const onNativeScan = (payload) => settleScan(payload);

  const nativePick = async () => {
    if (IS_ANDROID) {
      const api = bridge();
      if (!api?.pickWatchedFolder) throw new Error("El selector de Android no está disponible.");
      const promise = waitForPick();
      api.pickWatchedFolder();
      return promise;
    }

    const picked = await desktopInvoke("watched_pick_folder");
    if (!picked) return null;
    return {
      kind: "path",
      value: String(picked),
      label: shortLabel(picked)
    };
  };

  const normalizeFile = (raw) => {
    const relative = String(raw?.relative || raw?.name || "").replace(/\\/g, "/");
    const segments = relative.split("/").filter(Boolean);
    return {
      path: String(raw?.path || raw?.uri || ""),
      uri: String(raw?.uri || ""),
      name: String(raw?.name || segments[segments.length - 1] || ""),
      relative,
      parent: segments.length >= 2 ? segments[segments.length - 2] : "",
      grandparent: segments.length >= 3 ? segments[segments.length - 3] : "",
      size: Math.max(0, Number(raw?.size) || 0),
      modified: Math.max(0, Number(raw?.modified) || 0)
    };
  };

  const nativeScan = async (folder) => {
    if (IS_ANDROID) {
      const api = bridge();
      if (!api?.scanWatchedFolder) throw new Error("El escaneo de Android no está disponible.");
      const promise = waitForScan();
      api.scanWatchedFolder(folder.value);
      return promise;
    }

    const result = await desktopInvoke("watched_scan_folder", {
      root: folder.value,
      maxFiles: 20000,
      maxDepth: 12
    });
    return result || {};
  };

  const chunkBytes = (value) => {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) return Uint8Array.from(value);
    return new Uint8Array(0);
  };

  const mimeFor = (name) => {
    const extension = String(name || "").split(".").pop().toLowerCase();
    const map = {
      mp3: "audio/mpeg",
      wav: "audio/wav",
      ogg: "audio/ogg",
      oga: "audio/ogg",
      opus: "audio/ogg",
      m4a: "audio/mp4",
      mp4: "audio/mp4",
      aac: "audio/aac",
      flac: "audio/flac",
      webm: "audio/webm"
    };
    return map[extension] || "application/octet-stream";
  };

  const readDesktopFile = async (file) => {
    const size = Number(file.size) || 0;
    if (!size) throw new Error("El archivo está vacío.");

    const chunks = [];
    let offset = 0;
    while (offset < size) {
      const length = Math.min(READ_CHUNK_BYTES, size - offset);
      const part = await desktopInvoke("watched_read_chunk", {
        path: file.path,
        offset,
        length
      });
      const bytes = chunkBytes(part);
      if (!bytes.byteLength) break;
      chunks.push(bytes);
      offset += bytes.byteLength;
    }

    if (offset < size) throw new Error("El archivo cambió mientras lo leíamos.");
    return new File(chunks, file.name, {
      type: mimeFor(file.name),
      lastModified: file.modified || Date.now()
    });
  };

  const desktopMetadata = async (file) => {
    if (Number(file.size) > MAX_TAG_BYTES_DESKTOP) return null;
    if (typeof WNMetadata === "undefined" || !WNMetadata.readTrackMetadata) return null;
    try {
      const object = await readDesktopFile(file);
      const metadata = await WNMetadata.readTrackMetadata(object);
      return {
        title: metadata.title,
        artist: metadata.artist,
        album: metadata.album,
        duration: metadata.duration
      };
    } catch (err) {
      return null;
    }
  };

  const androidMetadata = async (files) => {
    const api = bridge();
    if (!api?.readWatchedTags || !files.length) return new Map();
    try {
      const payload = files.map((file) => ({
        uri: file.uri,
        name: file.name,
        size: file.size
      }));
      const raw = api.readWatchedTags(JSON.stringify(payload));
      const parsed = parsePayload(raw);
      const map = new Map();
      (Array.isArray(parsed) ? parsed : []).forEach((entry) => {
        if (!entry?.uri) return;
        map.set(String(entry.uri), {
          title: String(entry.title || ""),
          artist: String(entry.artist || ""),
          album: String(entry.album || ""),
          duration: Number(entry.duration) || 0
        });
      });
      return map;
    } catch (err) {
      return null;
    }
  };

  const androidUpload = (file, fields) =>
    new Promise((resolve, reject) => {
      const api = bridge();
      if (!api?.uploadWatchedFile) {
        reject(new Error("La subida de Android no está disponible."));
        return;
      }

      runtime.uploadSeq += 1;
      const requestId = `watch-${Date.now()}-${runtime.uploadSeq}`;
      const timer = window.setTimeout(() => {
        runtime.uploads.delete(requestId);
        reject(new Error("La subida tardó demasiado."));
      }, 6 * 60 * 1000);

      runtime.uploads.set(requestId, {
        resolve: (track) => {
          window.clearTimeout(timer);
          resolve(track);
        },
        reject: (err) => {
          window.clearTimeout(timer);
          reject(err);
        }
      });

      try {
        api.uploadWatchedFile(
          JSON.stringify({
            requestId,
            uri: file.uri,
            name: file.name,
            fields,
            token: getToken(),
            apiBase: API_BASE
          })
        );
      } catch (err) {
        runtime.uploads.delete(requestId);
        window.clearTimeout(timer);
        reject(err);
      }
    });

  /* ------------------------------------------------------------
     Búsqueda de coincidencias
     ------------------------------------------------------------ */

  const recentFailure = (config, contentKey) => {
    const failure = config.failures?.[contentKey];
    if (!failure) return false;
    if (Date.now() - (Number(failure.at) || 0) < FAILURE_RETRY_MS) return true;
    delete config.failures[contentKey];
    return false;
  };

  const planMatches = (files, pending, config) => {
    const index = Core.buildPendingIndex(pending);
    const usedPending = new Set();
    const matchedFiles = new Set();
    const matches = [];
    const ambiguous = [];

    const consider = (file, metadata = null) => {
      const result = Core.matchPendingForFile(file, index, metadata);
      if (!result) return;

      if (result.ambiguous) {
        if (!matchedFiles.has(file.path)) {
          matchedFiles.add(file.path);
          ambiguous.push({ file, result });
        }
        return;
      }

      const pendingId = Number(result.pending?.id) || 0;
      if (!pendingId || usedPending.has(pendingId)) return;

      const keys = Core.fileKeys(file);
      if (config.known?.[keys.contentKey]) return;
      if (recentFailure(config, keys.contentKey)) return;

      usedPending.add(pendingId);
      matchedFiles.add(file.path);
      matches.push({
        file,
        pending: result.pending,
        contentKey: keys.contentKey,
        pathKey: keys.pathKey
      });
    };

    files.forEach((file) => consider(file));

    const unmatched = files.filter((file) => !matchedFiles.has(file.path) && file.size > 0);
    return { index, matches, ambiguous, unmatched, consider };
  };

  const addMetadataMatches = async (plan, config, pending) => {
    if (!pending.length || !plan.unmatched.length) return;

    // Las etiquetas son el último recurso: leerlas cuesta más que comparar
    // nombres. Priorizamos los archivos más recientes y no repetimos la
    // lectura de un archivo que ya revisamos en esta sesión.
    const fresh = plan.unmatched
      .filter((file) => file.size > 0)
      .filter((file) => !runtime.tagChecked.has(Core.fileKeys(file).contentKey))
      .sort((a, b) => (Number(b.modified) || 0) - (Number(a.modified) || 0));

    if (IS_ANDROID) {
      const candidates = fresh.slice(0, MAX_TAG_FILES_ANDROID);
      if (!candidates.length) return;
      const metadata = await androidMetadata(candidates);
      if (!metadata) return;
      candidates.forEach((file) => {
        runtime.tagChecked.add(Core.fileKeys(file).contentKey);
        const tags = metadata.get(file.uri);
        if (tags) plan.consider(file, tags);
      });
      return;
    }

    const candidates = fresh
      .filter((file) => file.size <= MAX_TAG_BYTES_DESKTOP)
      .slice(0, MAX_TAG_FILES_DESKTOP);
    for (const file of candidates) {
      const tags = await desktopMetadata(file);
      if (!tags) continue;
      runtime.tagChecked.add(Core.fileKeys(file).contentKey);
      plan.consider(file, tags);
    }
  };

  const uploadMatch = async (match, pending) => {
    const fields = {
      pendingId: pending.id,
      title: pending.title,
      artist: pending.artist,
      album: pending.album,
      duration: pending.duration
    };

    if (IS_ANDROID) {
      return androidUpload(match.file, fields);
    }

    const file = await readDesktopFile(match.file);
    return uploadTrackFile({
      file,
      fields,
      cover: null,
      onProgress: () => {}
    });
  };

  /* ------------------------------------------------------------
     Flujo de escaneo
     ------------------------------------------------------------ */

  const removePendingLocally = (pendingId) => {
    if (!Array.isArray(state.pending)) return;
    state.pending = state.pending.filter((item) => Number(item.id) !== Number(pendingId));
  };

  const markKnown = (contentKey, pendingId, trackId) => {
    if (!runtime.config?.folder) return;
    runtime.config.known[contentKey] = {
      at: Date.now(),
      pendingId: Number(pendingId) || 0,
      trackId: Number(trackId) || 0
    };
  };

  const refreshPendingView = () => {
    if (!runtime.started) return;
    if (typeof renderView !== "function") return;
    if (state.route?.view !== "library" || state.libraryTab !== "pending") return;
    try {
      renderView({ resetScroll: false });
    } catch (err) {
      /* la vista pudo haberse cerrado mientras subía */
    }
  };

  const queueCardRefresh = () => {
    if (runtime.cardQueued) return;
    runtime.cardQueued = true;
    window.requestAnimationFrame(() => {
      runtime.cardQueued = false;
      refreshPendingView();
    });
  };

  const finishScan = (result) => {
    if (!runtime.config?.folder) return;
    runtime.config.lastScanAt = Date.now();
    runtime.config.lastResult = {
      at: Date.now(),
      kind: result.kind || "ok",
      files: Number(result.files) || 0,
      matched: Number(result.matched) || 0,
      uploaded: Number(result.uploaded) || 0,
      ambiguous: Number(result.ambiguous) || 0,
      failed: Number(result.failed) || 0,
      skipped: Number(result.skipped) || 0,
      truncated: Boolean(result.truncated),
      depthLimited: Boolean(result.depthLimited)
    };
    saveConfig();
    queueCardRefresh();
  };

  const runScan = async () => {
    const config = runtime.config;
    if (!config?.folder || runtime.scanning) return;
    if (!navigator.onLine) return;
    if (state.uploading) {
      scheduleScan(30 * 1000);
      return;
    }

    runtime.scanning = true;
    runtime.phase = "scanning";
    runtime.lastScanStarted = Date.now();
    queueCardRefresh();

    let uploaded = 0;
    let failed = 0;
    let skipped = 0;
    let matched = 0;
    let ambiguous = 0;
    let scanned = 0;
    let kind = "ok";
    let truncated = false;
    let depthLimited = false;

    try {
      const raw = await nativeScan(config.folder);
      const files = (Array.isArray(raw.files) ? raw.files : []).map(normalizeFile).filter((file) => file.path);
      scanned = files.length;
      truncated = Boolean(raw.truncated);
      depthLimited = Boolean(raw.depthLimited);

      const described = Core.describeFolder({ files, truncated, depthLimited });
      kind = described.kind;

      if (config.permissionLost || config.folderMissing) {
        config.permissionLost = false;
        config.folderMissing = false;
        saveConfig();
      }

      const pending = Array.isArray(state.pending) ? state.pending.slice() : [];
      if (!pending.length) {
        finishScan({ kind, files: scanned, truncated, depthLimited });
        return;
      }

      const plan = planMatches(files, pending, config);
      await addMetadataMatches(plan, config, pending);
      matched = plan.matches.length;
      ambiguous = plan.ambiguous.length;

      const batch = plan.matches.slice(0, MAX_UPLOADS_PER_SCAN);
      skipped += plan.matches.length - batch.length;

      if (!batch.length) {
        finishScan({ kind, files: scanned, matched, ambiguous, truncated, depthLimited });
        return;
      }

      toast(
        `Carpeta vigilada: ${plural(batch.length, "canción coincide", "canciones coinciden")}. Subiendo…`
      );

      const pendingById = new Map(pending.map((item) => [Number(item.id), item]));

      for (let index = 0; index < batch.length; index += 1) {
        const match = batch[index];
        const current = pendingById.get(Number(match.pending.id));
        if (!current) {
          skipped += 1;
          continue;
        }

        runtime.phase = `uploading:${index + 1}:${batch.length}`;
        queueCardRefresh();

        try {
          const track = await uploadMatch(match, current);
          markKnown(match.contentKey, current.id, track?.id);
          delete config.failures[match.contentKey];
          removePendingLocally(current.id);
          uploaded += 1;
        } catch (err) {
          config.failures[match.contentKey] = {
            at: Date.now(),
            message: String(err?.message || err || "Error de subida").slice(0, 200)
          };
          failed += 1;
        }

        saveConfig();
      }

      if (uploaded) {
        try {
          await refreshLibrary();
          if (typeof renderSidebarPlaylists === "function") renderSidebarPlaylists();
          queueCardRefresh();
        } catch (err) {
          /* la subida ya terminó; la próxima apertura reconcilia la biblioteca */
        }
      }

      if (uploaded && !failed) {
        toast(`${plural(uploaded, "canción completada", "canciones completadas")} desde tu carpeta.`);
      } else if (uploaded && failed) {
        toast(`${uploaded} completadas; ${failed} no se pudieron subir. Reintentamos más tarde.`, "error");
      } else if (failed && !uploaded) {
        toast("No se pudo subir ningún archivo de la carpeta vigilada. Revisá la conexión.", "error");
      }
    } catch (err) {
      if (err?.permissionLost) {
        config.permissionLost = true;
        config.enabled = false;
        saveConfig();
        toast("Android pidió permiso otra vez para la carpeta vigilada. Volvé a elegirla.", "error");
      } else if (!navigator.onLine) {
        /* sin conexión: se reintenta en el próximo ciclo */
      } else {
        console.error("[WaverNote] watched folder:", err);
        // En Windows un error de lectura suele significar que la carpeta se
        // movió, cambió de nombre o el disco ya no está conectado. Pausamos
        // para no repetir el aviso cada cinco minutos.
        if (!IS_ANDROID) {
          config.folderMissing = true;
          config.enabled = false;
          saveConfig();
          queueCardRefresh();
        }
        toast(`Carpeta vigilada: ${err?.message || "no se pudo revisar la carpeta."}`, "error");
      }
    } finally {
      runtime.scanning = false;
      runtime.phase = "idle";
      finishScan({
        kind,
        files: scanned,
        matched,
        uploaded,
        ambiguous,
        failed,
        skipped,
        truncated,
        depthLimited
      });
      if (runtime.started && config.enabled && !config.permissionLost && !config.folderMissing) scheduleScan(SCAN_INTERVAL_MS);
    }
  };

  const scheduleScan = (delay) => {
    if (!runtime.started) return;
    if (runtime.scanTimer) window.clearTimeout(runtime.scanTimer);
    runtime.scanTimer = window.setTimeout(() => {
      runtime.scanTimer = null;
      requestScan({ force: true });
    }, Math.max(1000, Number(delay) || SCAN_INTERVAL_MS));
  };

  const requestScan = ({ force = false, manual = false } = {}) => {
    const config = runtime.config;
    if (!runtime.supported || !runtime.started || !config?.folder) return;
    if ((!config.enabled && !manual) || config.permissionLost || config.folderMissing) return;
    if (runtime.scanning) return;
    if (state.uploading) {
      scheduleScan(30 * 1000);
      return;
    }
    if (!force && Date.now() - runtime.lastScanStarted < MIN_SCAN_GAP_MS) return;
    runScan();
  };

  /* ------------------------------------------------------------
     Acciones de la tarjeta
     ------------------------------------------------------------ */

  const pickFolder = async () => {
    if (!runtime.supported) {
      toast("La carpeta vigilada está disponible en la app de Windows y Android.", "error");
      return;
    }
    if (runtime.scanning) {
      toast("Esperá a que termine el escaneo actual.");
      return;
    }

    try {
      const picked = await nativePick();
      if (!picked?.value) return;

      const config = runtime.config || emptyConfig();
      const changed = config.folder?.value !== picked.value;
      config.folder = picked;
      config.enabled = true;
      config.permissionLost = false;
      config.folderMissing = false;
      config.lastScanAt = 0;
      config.lastResult = null;
      if (changed) {
        config.known = {};
        config.failures = {};
        runtime.tagChecked.clear();
      }
      if (!config.addedAt) config.addedAt = Date.now();
      runtime.config = config;
      saveConfig();
      queueCardRefresh();
      toast(`Carpeta vigilada: ${shortLabel(picked.label || picked.value)}.`);
      runScan();
    } catch (err) {
      toast(err?.message || "No se pudo elegir la carpeta.", "error");
    }
  };

  const scanNow = () => {
    if (!runtime.config?.folder || runtime.config.folderMissing) {
      pickFolder();
      return;
    }
    if (runtime.scanning) {
      toast("Ya estamos revisando la carpeta.");
      return;
    }
    if (state.uploading) {
      toast("Terminá la subida manual y revisamos la carpeta.");
      return;
    }
    requestScan({ force: true, manual: true });
  };

  const toggleEnabled = () => {
    if (!runtime.config) return;
    if (runtime.config.folderMissing) {
      pickFolder();
      return;
    }
    runtime.config.enabled = !runtime.config.enabled;
    runtime.config.permissionLost = false;
    saveConfig();
    queueCardRefresh();
    if (runtime.config.enabled) {
      toast("Carpeta vigilada activada.");
      requestScan({ force: true });
    } else {
      toast("Carpeta vigilada en pausa.");
    }
  };

  const forget = () => {
    if (!runtime.config) return;
    runtime.config = emptyConfig();
    runtime.userId = Number(state.user?.id) || 0;
    try {
      localStorage.removeItem(storageKey(runtime.userId));
    } catch (err) {
      /* noop */
    }
    closeModal(true);
    queueCardRefresh();
    toast("WaverNote dejó de vigilar la carpeta.");
  };

  const openForget = () => {
    if (!runtime.config?.folder) return;
    openModal({
      title: "Dejar de vigilar",
      eyebrow: "Carpeta vigilada",
      body: `
        <div class="watch-help">
          <p>WaverNote va a dejar de revisar <strong>${escapeHTML(runtime.config.folder.label || shortLabel(runtime.config.folder.value))}</strong>. No se borra ningún archivo de tu dispositivo ni canción de tu biblioteca.</p>
          <p class="watch-help__muted">Las canciones que sigan pendientes van a esperar a que subas su archivo a mano.</p>
          <div class="watch-help__actions">
            <button class="btn btn--danger" data-action="watched-forget-confirm">${icon("trash")} Dejar de vigilar</button>
            <button class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          </div>
        </div>`
    });
  };

  const openHelp = () => {
    openModal({
      title: "Carpeta vigilada",
      eyebrow: "Cómo funciona",
      body: `
        <div class="watch-help">
          <p><strong>WaverNote no descarga música de Spotify.</strong> La carpeta vigilada solo mira archivos que ya tenés en tu dispositivo y sube los que completan una canción pendiente de tu lista.</p>
          <ul>
            <li>Elegí la carpeta principal de tu música. También sirve una carpeta de artista: buscamos en todas sus subcarpetas.</li>
            <li>Revisamos al abrir la app, al volver a ella y cada pocos minutos mientras esté abierta.</li>
            <li>Reconocemos el nombre del archivo, las carpetas (Artista/Álbum/01 - Canción) y, si hace falta, las etiquetas del audio.</li>
            <li>Las versiones en vivo, remixes, instrumentales y acústicas se tratan como canciones distintas.</li>
            <li>Si dos canciones pendientes se parecen demasiado, no adivinamos: el archivo queda para que lo subas vos desde su fila.</li>
            <li>No modificamos, movemos ni borramos tus archivos. Tampoco subimos canciones que no estén pendientes.</li>
          </ul>
          <p class="watch-help__muted">${
            IS_ANDROID
              ? "En Android el acceso se guarda con el permiso del selector del sistema. Si el sistema lo retira, te pedimos elegir la carpeta otra vez."
              : "En Windows la carpeta se lee directamente desde tu equipo. Si la movés o la desconectás, elegí la nueva ubicación."
          }</p>
          <div class="watch-help__actions">
            <button class="btn btn--primary" data-action="watched-pick">${icon("folder")} Elegir carpeta</button>
            <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
          </div>
        </div>`
    });
  };

  /* ------------------------------------------------------------
     Ciclo de vida
     ------------------------------------------------------------ */

  const start = () => {
    if (!runtime.supported) return;
    const userId = Number(state.user?.id) || 0;
    if (!userId) return;

    if (runtime.started && runtime.userId === userId) {
      requestScan();
      return;
    }

    runtime.userId = userId;
    runtime.config = loadConfig(userId);
    runtime.started = true;
    runtime.lastScanStarted = 0;

    if (runtime.timer) window.clearInterval(runtime.timer);
    runtime.timer = window.setInterval(() => requestScan(), SCAN_INTERVAL_MS);

    queueCardRefresh();
    if (
      runtime.config.folder &&
      runtime.config.enabled &&
      !runtime.config.permissionLost &&
      !runtime.config.folderMissing
    ) {
      scheduleScan(2500);
    }
  };

  const stop = () => {
    runtime.started = false;
    runtime.scanning = false;
    runtime.phase = "idle";
    runtime.userId = 0;
    runtime.config = null;
    runtime.lastScanStarted = 0;

    if (runtime.timer) window.clearInterval(runtime.timer);
    if (runtime.scanTimer) window.clearTimeout(runtime.scanTimer);
    runtime.timer = null;
    runtime.scanTimer = null;
    runtime.tagChecked.clear();

    if (runtime.pickWaiter) {
      window.clearTimeout(runtime.pickWaiter.timer);
      runtime.pickWaiter = null;
    }
    if (runtime.scanWaiter) {
      window.clearTimeout(runtime.scanWaiter.timer);
      runtime.scanWaiter = null;
    }
    runtime.uploads.forEach((waiter) => waiter.reject(new Error("Sesión cerrada.")));
    runtime.uploads.clear();
  };

  const onVisible = () => {
    if (document.visibilityState === "visible") requestScan();
  };

  if (runtime.supported) {
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
  }

  window.WaverNoteWatched = {
    cardHTML,
    forget,
    onNativeFolderPicked,
    onNativeScan,
    onNativeUpload: settleUpload,
    openForget,
    openHelp,
    pickFolder,
    requestScan,
    scanNow,
    start,
    stop,
    toggleEnabled
  };
})();
