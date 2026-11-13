/* ============================================================
   WaverNote · sincronización de cuenta
   Todo lo que el usuario hace en un dispositivo viaja a su
   cuenta Surface: cola, posición, volumen, historial, conteos
   de reproducción y preferencias de la interfaz.
   ============================================================ */

const WA_CLOUD_SYNC_DELAY = 700;
const WA_CLOUD_RETRY_MAX = 30000;
const WA_CLOUD_PLAY_BATCH = 60;

const waCloud = {
  stateReady: false,
  playsReady: false,
  hydrated: false,
  restore: null,
  restoreRoute: null,
  remoteMissing: new Set(),
  dirty: new Set(),
  timers: new Map(),
  retryDelay: 1500,
  sendingState: false,
  sendingPlays: false,
  pendingPlayTracks: new Set(),
  playTimer: 0,
  retryPlayTimer: 0
};

const cloudStorageKey = () => {
  const userId = Number(state.user?.id) || 0;
  return userId ? `${STORAGE.cloudPrefix}${userId}` : "";
};

/* ------------------------------------------------------------
   Instantáneas de la cuenta
   ------------------------------------------------------------ */

const cloudSettingsSnapshot = () => ({
  volume: clamp(Number(state.volume) || 0, 0, 1),
  muted: Boolean(state.muted),
  shuffle: Boolean(state.shuffle),
  repeat: ["off", "all", "one"].includes(state.repeat) ? state.repeat : "off",
  libraryTab: ["songs", "most-played", "albums", "playlists"].includes(state.libraryTab)
    ? state.libraryTab
    : "songs",
  catalogTab: state.catalogTab === "genre" ? "genre" : "artist",
  npTab: state.npTab === "queue" ? "queue" : "now",
  route: { ...state.route }
});

const cloudPlaybackSnapshot = () => ({
  queue: state.queue.map(Number).filter(Number.isFinite).slice(0, 5000),
  queueIndex: Number.isInteger(state.queueIndex) ? state.queueIndex : -1,
  currentTrackId: Number(state.currentTrackId) || null,
  currentTime: Math.max(0, Number(state.currentTime) || 0),
  baseQueue: Array.isArray(state.baseQueue)
    ? state.baseQueue.map(Number).filter(Number.isFinite).slice(0, 5000)
    : null,
  savedAt: Date.now()
});

const cloudRecentSnapshot = () => state.recent.map(Number).filter(Number.isFinite).slice(0, 24);

const readCloudLocal = () => {
  const key = cloudStorageKey();
  if (!key) return null;
  const saved = readJSON(key, null);
  return saved && typeof saved === "object" && !Array.isArray(saved) ? saved : null;
};

const persistCloudLocal = () => {
  const key = cloudStorageKey();
  if (!key) return;
  writeJSON(key, {
    settings: cloudSettingsSnapshot(),
    playback: cloudPlaybackSnapshot(),
    recent: cloudRecentSnapshot()
  });
};

// Guardado local frecuente mientras suena la música. Se escribe solo el
// playback y se conserva el resto del caché para que un cierre forzado (sin
// pagehide) no pierda la posición ni la cola de los últimos segundos.
const persistPlaybackLocal = () => {
  if (!state.user?.id || !waCloud.hydrated) return;
  const key = cloudStorageKey();
  if (!key) return;

  const saved = readCloudLocal() || {};
  writeJSON(key, {
    settings:
      saved.settings && typeof saved.settings === "object" && !Array.isArray(saved.settings)
        ? saved.settings
        : cloudSettingsSnapshot(),
    playback: cloudPlaybackSnapshot(),
    recent: Array.isArray(saved.recent) ? saved.recent : cloudRecentSnapshot()
  });
};

// La posición va en una clave aparte y muy chica: se puede guardar cada
// segundo sin reescribir toda la cola ni depender de que el sistema avise
// que la app se está cerrando.
const cloudPositionStorageKey = () => {
  const userId = Number(state.user?.id) || 0;
  return userId ? `${STORAGE.positionPrefix}${userId}` : "";
};

const persistPlaybackPosition = () => {
  if (!state.user?.id || !waCloud.hydrated) return;
  const key = cloudPositionStorageKey();
  if (!key) return;
  writeJSON(key, {
    trackId: Number(state.currentTrackId) || null,
    queueIndex: Number.isInteger(state.queueIndex) ? state.queueIndex : -1,
    currentTime: Math.max(0, Number(state.currentTime) || 0),
    savedAt: Date.now()
  });
};

const readCloudPosition = () => {
  const key = cloudPositionStorageKey();
  if (!key) return null;
  const saved = readJSON(key, null);
  return saved && typeof saved === "object" && !Array.isArray(saved) ? saved : null;
};

/* ------------------------------------------------------------
   Guardado del estado (secciones independientes)
   ------------------------------------------------------------ */

const scheduleCloudSync = (section, delay = WA_CLOUD_SYNC_DELAY) => {
  if (!state.user?.id || !waCloud.stateReady) return;
  if (!["settings", "playback", "recent"].includes(section)) return;

  waCloud.dirty.add(section);

  const pending = waCloud.timers.get(section);
  if (pending) window.clearTimeout(pending);

  const timer = window.setTimeout(() => {
    waCloud.timers.delete(section);
    flushCloudSync();
  }, Math.max(0, Number(delay) || 0));

  waCloud.timers.set(section, timer);
};

const cloudSectionsPayload = (sections) => {
  const payload = {};
  sections.forEach((section) => {
    if (section === "settings") payload.settings = cloudSettingsSnapshot();
    if (section === "playback") payload.playback = cloudPlaybackSnapshot();
    if (section === "recent") payload.recent = cloudRecentSnapshot();
  });
  return payload;
};

const flushCloudSync = async ({ keepalive = false } = {}) => {
  persistCloudLocal();

  if (!state.user?.id || !waCloud.stateReady || waCloud.sendingState) return;

  const sections = Array.from(waCloud.dirty);
  if (!sections.length) return;

  const payload = cloudSectionsPayload(sections);
  if (!Object.keys(payload).length) {
    waCloud.dirty.clear();
    return;
  }

  waCloud.sendingState = true;
  let failed = false;

  try {
    await api("/wavernote/state", {
      method: "PUT",
      body: { state: payload },
      keepalive
    });
    sections.forEach((section) => waCloud.dirty.delete(section));
    waCloud.retryDelay = 1500;
  } catch (err) {
    failed = true;

    if (err.status === 404) {
      // Backend viejo: la app sigue funcionando con el caché local.
      waCloud.stateReady = false;
      return;
    }

    if (err.status === 401 || navigator.onLine === false) return;

    waCloud.retryDelay = Math.min(WA_CLOUD_RETRY_MAX, waCloud.retryDelay * 1.7);
    const retry = window.setTimeout(() => flushCloudSync(), waCloud.retryDelay);
    waCloud.timers.set("retry-state", retry);
  } finally {
    waCloud.sendingState = false;

    if (!failed && waCloud.dirty.size && !keepalive) {
      const timer = window.setTimeout(() => flushCloudSync(), 260);
      waCloud.timers.set("flush-state", timer);
    }
  }
};

/* ------------------------------------------------------------
   Reproducciones: fusión sin duplicados
   ------------------------------------------------------------ */

const cloudPlayEvents = (stats) =>
  Array.isArray(stats?.events) ? stats.events.map(cleanPlayEvent).filter(Boolean) : [];

const cloudPlayTime = (value) => {
  const time = value ? new Date(value).getTime() : 0;
  return Number.isFinite(time) && time > 0 ? time : 0;
};

const mergeCloudPlayStats = (a, b) => {
  const events = Array.from(new Set([...cloudPlayEvents(a), ...cloudPlayEvents(b)]))
    .sort((x, y) => x - y)
    .slice(-PLAY_EVENTS_LIMIT);

  const firstTimes = [
    cloudPlayTime(a?.firstPlayedAt),
    cloudPlayTime(b?.firstPlayedAt),
    events[0] || 0
  ].filter(Boolean);

  const lastTimes = [
    cloudPlayTime(a?.lastPlayedAt),
    cloudPlayTime(b?.lastPlayedAt),
    events[events.length - 1] || 0
  ].filter(Boolean);

  return {
    count: Math.max(Number(a?.count) || 0, Number(b?.count) || 0, events.length),
    firstPlayedAt: firstTimes.length ? new Date(Math.min(...firstTimes)).toISOString() : null,
    lastPlayedAt: lastTimes.length ? new Date(Math.max(...lastTimes)).toISOString() : null,
    events
  };
};

const cloudPlayHasPending = (localStats, remoteStats) => {
  const remoteEvents = new Set(cloudPlayEvents(remoteStats));
  if (cloudPlayEvents(localStats).some((time) => !remoteEvents.has(time))) return true;
  return (Number(localStats?.count) || 0) > (Number(remoteStats?.count) || 0);
};

const schedulePlaySync = (delay = 900) => {
  if (!waCloud.playsReady) return;
  if (waCloud.playTimer) window.clearTimeout(waCloud.playTimer);
  waCloud.playTimer = window.setTimeout(() => {
    waCloud.playTimer = 0;
    flushPlaySync();
  }, Math.max(0, Number(delay) || 0));
};

const queuePlaySync = (id) => {
  if (!waCloud.playsReady) return;
  const trackId = Number(id);
  if (!Number.isFinite(trackId)) return;
  waCloud.pendingPlayTracks.add(trackId);
  schedulePlaySync();
};

const flushPlaySync = async ({ keepalive = false } = {}) => {
  if (!state.user?.id || !waCloud.playsReady || !waCloud.pendingPlayTracks.size) return;
  if (waCloud.sendingPlays) {
    schedulePlaySync(400);
    return;
  }

  const ids = Array.from(waCloud.pendingPlayTracks).slice(0, WA_CLOUD_PLAY_BATCH);
  const plays = {};

  ids.forEach((id) => {
    const stats = state.plays?.[String(id)];
    if (stats) plays[id] = stats;
  });

  if (!Object.keys(plays).length) {
    ids.forEach((id) => waCloud.pendingPlayTracks.delete(id));
    return;
  }

  waCloud.sendingPlays = true;
  let failed = false;

  try {
    await api("/wavernote/plays", {
      method: "PUT",
      body: { plays },
      keepalive
    });
    ids.forEach((id) => waCloud.pendingPlayTracks.delete(id));
    if (waCloud.pendingPlayTracks.size) schedulePlaySync(220);
  } catch (err) {
    failed = true;

    if (err.status === 404) {
      waCloud.playsReady = false;
      return;
    }

    if (err.status === 401 || navigator.onLine === false) return;

    if (waCloud.retryPlayTimer) window.clearTimeout(waCloud.retryPlayTimer);
    waCloud.retryPlayTimer = window.setTimeout(() => flushPlaySync(), 5000);
  } finally {
    waCloud.sendingPlays = false;
  }

  // Si durante el envío entró otra reproducción, el temporizador la recoge.
  if (!failed && waCloud.pendingPlayTracks.size) schedulePlaySync(220);
};

/* ------------------------------------------------------------
   Restauración de la cuenta
   ------------------------------------------------------------ */

const normalizeCloudRoute = (raw) => {
  if (!raw || typeof raw !== "object") return null;

  const view = String(raw.view || "");
  if (view === "home") return { view: "home" };
  if (["trends", "recommendations", "catalog", "library"].includes(view)) return { view };

  if (view === "search") {
    const q = String(raw.q || "").slice(0, 160);
    return q ? { view: "search", q } : null;
  }

  if (view === "album") {
    const id = String(raw.id || "");
    return id && allAlbums().some((album) => album.id === id) ? { view, id } : null;
  }

  if (view === "playlist") {
    const id = String(raw.id || "");
    return id && playlistById(id) ? { view, id } : null;
  }

  return null;
};

const loadCloudData = async () => {
  if (!state.user?.id || waCloud.hydrated) return;

  const local = readCloudLocal() || {};
  const localSettings =
    local.settings && typeof local.settings === "object" && !Array.isArray(local.settings)
      ? local.settings
      : { ...cloudSettingsSnapshot(), route: { view: "home" } };
  const localPlayback =
    local.playback && typeof local.playback === "object" && !Array.isArray(local.playback)
      ? local.playback
      : null;
  const localRecent = Array.isArray(local.recent)
    ? local.recent.map(Number).filter(Number.isFinite)
    : state.recent.slice();

  const [stateResult, playsResult] = await Promise.allSettled([
    api("/wavernote/state"),
    api("/wavernote/plays")
  ]);

  let remoteState = null;
  let stateError = null;
  if (stateResult.status === "fulfilled") {
    const data = stateResult.value?.state;
    remoteState = data && typeof data === "object" && !Array.isArray(data) ? data : null;
  } else {
    stateError = stateResult.reason;
  }

  let remotePlays = null;
  if (playsResult.status === "fulfilled") {
    const data = playsResult.value?.plays;
    remotePlays = data && typeof data === "object" && !Array.isArray(data) ? data : {};
  }

  // Reproducciones: gana la unión de ambos historiales. Lo que quedó solo
  // en este dispositivo se empuja al servidor en segundo plano.
  if (remotePlays) {
    const merged = {};
    const keys = new Set([...Object.keys(remotePlays), ...Object.keys(state.plays || {})]);

    keys.forEach((key) => {
      const trackId = Number(key);
      if (!state.trackById.has(trackId)) return;

      const remoteStats = remotePlays[key] || null;
      const localStats = state.plays?.[key] || null;
      const stats = mergeCloudPlayStats(remoteStats, localStats);
      if (!stats.count && !stats.events.length) return;

      merged[key] = stats;
      if (localStats && cloudPlayHasPending(localStats, remoteStats)) {
        waCloud.pendingPlayTracks.add(trackId);
      }
    });

    state.plays = merged;
    writeJSON(playsStorageKey(), merged);
    waCloud.playsReady = true;
  }

  const remoteSettings =
    remoteState?.settings && typeof remoteState.settings === "object" && !Array.isArray(remoteState.settings)
      ? remoteState.settings
      : null;
  const remotePlayback =
    remoteState?.playback && typeof remoteState.playback === "object" && !Array.isArray(remoteState.playback)
      ? remoteState.playback
      : null;
  const remoteRecent = Array.isArray(remoteState?.recent) ? remoteState.recent : null;

  // El servidor puede haberse quedado atrás si la app se cerró de golpe:
  // se usa la copia más reciente entre el caché local y la cuenta.
  const localPlaybackAt = Math.max(0, Number(localPlayback?.savedAt) || 0);
  const remotePlaybackAt = Math.max(0, Number(remotePlayback?.savedAt) || 0);
  const useLocalPlayback = Boolean(
    localPlayback && (!remotePlayback || localPlaybackAt > remotePlaybackAt)
  );

  waCloud.restore = {
    settings: remoteSettings || localSettings,
    playback: useLocalPlayback ? localPlayback : remotePlayback,
    recent: remoteRecent || localRecent
  };
  waCloud.restoreRoute = normalizeCloudRoute(
    remoteSettings?.route || localSettings?.route
  );

  waCloud.remoteMissing.clear();
  if (!remoteSettings) waCloud.remoteMissing.add("settings");
  if (useLocalPlayback) waCloud.remoteMissing.add("playback");
  if (!remoteRecent && localRecent.length) waCloud.remoteMissing.add("recent");

  // Si la consulta falló por red, se conserva el caché local y no se
  // intenta pisar el servidor hasta la próxima apertura.
  waCloud.stateReady = !stateError;
  waCloud.hydrated = true;

  if (waCloud.pendingPlayTracks.size) schedulePlaySync(1200);
};

const applyCloudRestore = () => {
  const restore = waCloud.restore;
  if (!restore) return false;

  const settings =
    restore.settings && typeof restore.settings === "object" && !Array.isArray(restore.settings)
      ? restore.settings
      : {};

  const volume = Number(settings.volume);
  if (Number.isFinite(volume)) state.volume = clamp(volume, 0, 1);
  if (typeof settings.muted === "boolean") state.muted = settings.muted;
  if (typeof settings.shuffle === "boolean") state.shuffle = settings.shuffle;
  if (["off", "all", "one"].includes(settings.repeat)) state.repeat = settings.repeat;
  if (["songs", "most-played", "albums", "playlists"].includes(settings.libraryTab)) {
    state.libraryTab = settings.libraryTab;
  }
  if (["artist", "genre"].includes(settings.catalogTab)) state.catalogTab = settings.catalogTab;
  if (["now", "queue"].includes(settings.npTab)) state.npTab = settings.npTab;

  const playback =
    restore.playback && typeof restore.playback === "object" && !Array.isArray(restore.playback)
      ? restore.playback
      : null;

  if (playback) {
    const queue = Array.isArray(playback.queue)
      ? playback.queue.map(Number).filter((id) => state.trackById.has(id))
      : [];

    if (queue.length) {
      let index = Number(playback.queueIndex);
      if (!Number.isInteger(index) || index < 0 || index >= queue.length) index = 0;

      let currentId = Number(playback.currentTrackId);
      if (!state.trackById.has(currentId)) currentId = queue[index] || null;

      const currentIndex = currentId ? queue.indexOf(currentId) : -1;
      if (currentIndex >= 0) index = currentIndex;

      state.queue = queue;
      state.queueIndex = index;
      state.currentTrackId = currentId;

      const track = trackById(currentId);
      state.duration = Number(track?.duration) || 0;

      const position = Math.max(0, Number(playback.currentTime) || 0);
      state.currentTime =
        state.duration > 0 ? clamp(position, 0, state.duration) : position;

      // El guardado de posición es más frecuente que el de la cola: si es
      // más nuevo y corresponde a la misma canción, se retoma ese punto.
      const localPosition = readCloudPosition();
      const localPositionAt = Math.max(0, Number(localPosition?.savedAt) || 0);
      if (
        localPositionAt > Math.max(0, Number(playback.savedAt) || 0) &&
        Number(localPosition.trackId) === Number(state.currentTrackId) &&
        Number(localPosition.queueIndex) === Number(state.queueIndex)
      ) {
        const precise = Math.max(0, Number(localPosition.currentTime) || 0);
        state.currentTime =
          state.duration > 0 ? clamp(precise, 0, state.duration) : precise;
      }

      state.baseQueue = Array.isArray(playback.baseQueue)
        ? playback.baseQueue.map(Number).filter((id) => state.trackById.has(id))
        : null;
      state.isPlaying = false;
    }
  }

  const recent = Array.isArray(restore.recent)
    ? restore.recent.map(Number).filter((id) => state.trackById.has(id)).slice(0, 24)
    : null;

  if (recent) {
    state.recent = recent;
    const userId = Number(state.user?.id) || 0;
    if (userId) writeJSON(`${STORAGE.recentPrefix}${userId}`, state.recent);
  }

  if (waCloud.restoreRoute) {
    state.route = waCloud.restoreRoute;
    state.history = [waCloud.restoreRoute];
    state.historyIndex = 0;

    if (waCloud.restoreRoute.view === "search") {
      state.search = waCloud.restoreRoute.q || "";
      const input = $("#searchInput");
      if (input) input.value = state.search;
      updateSearchChrome();
    }
  }

  // Deja el caché local alineado con la sesión restaurada, para que un
  // siguiente cierre forzado no vuelva a una copia vieja.
  if (playback) {
    persistCloudLocal();
    persistPlaybackPosition();
  }

  return true;
};

const pushCloudFallbacks = () => {
  if (!waCloud.stateReady || !waCloud.remoteMissing.size) return;
  waCloud.remoteMissing.forEach((section) => scheduleCloudSync(section, 0));
  waCloud.remoteMissing.clear();
};

const resetCloudSync = () => {
  waCloud.timers.forEach((timer) => window.clearTimeout(timer));
  waCloud.timers.clear();
  if (waCloud.playTimer) window.clearTimeout(waCloud.playTimer);
  if (waCloud.retryPlayTimer) window.clearTimeout(waCloud.retryPlayTimer);

  waCloud.stateReady = false;
  waCloud.playsReady = false;
  waCloud.hydrated = false;
  waCloud.restore = null;
  waCloud.restoreRoute = null;
  waCloud.remoteMissing.clear();
  waCloud.dirty.clear();
  waCloud.pendingPlayTracks.clear();
  waCloud.sendingState = false;
  waCloud.sendingPlays = false;
  waCloud.playTimer = 0;
  waCloud.retryPlayTimer = 0;
  waCloud.retryDelay = 1500;
};

/* ------------------------------------------------------------
   Cierre de la app y reconexión
   ------------------------------------------------------------ */

const flushCloudNow = () => {
  persistCloudLocal();
  if (waCloud.stateReady) flushCloudSync({ keepalive: true });
  if (waCloud.playsReady) flushPlaySync({ keepalive: true });
};

window.addEventListener("pagehide", flushCloudNow);
window.addEventListener("beforeunload", flushCloudNow);
window.addEventListener("online", () => {
  flushCloudSync();
  flushPlaySync();
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") flushCloudNow();
});
