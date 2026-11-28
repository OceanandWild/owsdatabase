/* ============================================================
   WaverNote · núcleo
   Utilidades, sesión Surface, API, estado y navegación.
   ============================================================ */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const formatTime = (seconds) => {
  const safe = Math.max(0, Math.floor(Number(seconds) || 0));
  const m = Math.floor(safe / 60);
  const s = safe % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
};

const formatTotal = (seconds) => {
  const safe = Math.max(0, Math.round(Number(seconds) || 0));
  const h = Math.floor(safe / 3600);
  const m = Math.round((safe % 3600) / 60);
  return h > 0 ? `${h} h ${m} min` : `${m} min`;
};

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

// Vibración corta para acciones táctiles. En Android se siente como una app
// nativa; en el resto de los dispositivos no hace nada.
const haptic = (pattern = 8) => {
  try {
    if (typeof navigator.vibrate !== "function") return;
    navigator.vibrate(pattern);
  } catch (err) {
    /* el navegador puede bloquear la vibración sin gesto */
  }
};

const escapeHTML = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (char) => {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return map[char];
  });

const normalize = (value) =>
  String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim();

const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const shuffleArray = (array) => {
  for (let i = array.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
};

const icon = (name, className = "") =>
  `<svg class="icon ${className}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="#i-${name}"></use></svg>`;

const greeting = () => {
  const hour = new Date().getHours();
  if (hour < 6) return "Buenas noches";
  if (hour < 13) return "Buenos días";
  if (hour < 20) return "Buenas tardes";
  return "Buenas noches";
};

const todayLabel = () => {
  const raw = new Intl.DateTimeFormat("es", { weekday: "long", day: "numeric", month: "long" }).format(new Date());
  return raw.charAt(0).toUpperCase() + raw.slice(1);
};

const dateLabel = (value) => {
  const date = value ? new Date(value) : null;
  if (!date || Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat("es", { day: "numeric", month: "short", year: "numeric" }).format(date);
};

/* ------------------------------------------------------------
   API + sesión Surface
   ------------------------------------------------------------ */

const WAVERNOTE_DEFAULT_API = "https://owsdatabase.onrender.com";

const resolveApiBase = () => {
  try {
    const params = new URLSearchParams(window.location.search || "");
    const override = (params.get("api") || localStorage.getItem("wavernote_api_base") || "").trim();
    if (override && /^https?:\/\//i.test(override)) return override.replace(/\/+$/, "");
  } catch (err) {
    /* noop */
  }
  return WAVERNOTE_DEFAULT_API;
};

const API_BASE = resolveApiBase();

const TOKEN_KEY = "ocean_pay_token";
const USER_KEY = "ocean_pay_user";

const readJSON = (key, fallback) => {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : JSON.parse(raw);
  } catch (err) {
    return fallback;
  }
};

const writeJSON = (key, value) => {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    /* modo privado o almacenamiento lleno */
  }
};

const getToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY) || "";
  } catch (err) {
    return "";
  }
};

// El token de Surface incluye el id de la cuenta. Se usa como respaldo cuando
// la respuesta de sesión no trae `user.id`; sin ese dato las descargas y la
// biblioteca guardada quedaban asociadas al usuario 0 y "desaparecían".
const decodeTokenPayload = (token) => {
  try {
    const segment = String(token || "").split(".")[1];
    if (!segment) return null;
    const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch (err) {
    return null;
  }
};

const userIdFromToken = (token) => {
  const payload = decodeTokenPayload(token);
  const id = Number(payload?.id ?? payload?.userId ?? payload?.uid ?? payload?.sub);
  return Number.isFinite(id) && id > 0 ? Math.trunc(id) : 0;
};

const resolveUserId = (user, token = getToken()) =>
  Number(user?.id ?? user?.userId ?? user?.uid) || userIdFromToken(token);

const getStoredUser = () => readJSON(USER_KEY, null);

const saveSession = (token, user) => {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
  } catch (err) {
    /* noop */
  }
  const safeUser = {
    id: resolveUserId(user, token || getToken()),
    username: user?.username || ""
  };
  writeJSON(USER_KEY, safeUser);
  return safeUser;
};

const clearSession = () => {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch (err) {
    /* noop */
  }
};

const apiErrorMessage = (status, text, fallback) => {
  const raw = String(text || "").trim();
  if (!raw) return fallback || `Error ${status}`;
  if (/^<!doctype html|^<html[\s>]/i.test(raw)) {
    if (status === 404) {
      return "La API todavía no tiene esta función. Puede que el servidor esté desplegándose: probá de nuevo en unos minutos.";
    }
    if (status >= 500) {
      return "El servidor está iniciando o no está disponible. Probá de nuevo en unos instantes.";
    }
    return `El servidor rechazó la solicitud (${status}).`;
  }
  const clean = raw.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  if (!clean) return fallback || `Error ${status}`;
  return clean.length > 280 ? `${clean.slice(0, 280)}…` : clean;
};

const api = async (path, options = {}) => {
  const { method = "GET", body, auth = true, signal, keepalive = false } = options;
  const headers = {};

  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  let payload = body;
  if (body !== undefined && body !== null) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${path}`, { method, headers, body: payload, signal, keepalive });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (err) {
    data = { error: apiErrorMessage(response.status, text, `Error ${response.status}`) };
  }

  if (!response.ok) {
    const error = new Error((data?.error && apiErrorMessage(response.status, data.error, `Error ${response.status}`)) || `Error ${response.status}`);
    error.status = response.status;
    error.code = data?.code || "";
    throw error;
  }
  return data;
};

// Un fallo de red (sin respuesta HTTP) no trae status. Sirve para distinguir
// "no hay internet" de un error del servidor y no borrar la sesión.
const isOfflineError = (err) => Boolean(err) && !Number(err.status);

const loginWithSurface = async (username, password) => {
  const data = await api("/surface/login", {
    method: "POST",
    auth: false,
    body: { username, password }
  });
  if (!data?.token) throw new Error("Surface no devolvió una sesión válida.");
  return { token: data.token, user: data.user || { username } };
};

const registerInSurface = async (username, password) => {
  const data = await api("/surface/register", {
    method: "POST",
    auth: false,
    body: { username, password }
  });
  if (!data?.token) throw new Error("No se pudo crear la cuenta.");
  return { token: data.token, user: data.user || { username } };
};

const validateSurfaceSession = async () => {
  const data = await api("/surface/me");
  return {
    token: data?.token || getToken(),
    user: { id: Number(data?.id) || 0, username: data?.username || "" }
  };
};

/* ------------------------------------------------------------
   Estado y catálogo derivado
   ------------------------------------------------------------ */

const STORAGE = {
  volume: "wavernote.volume.v2",
  nextCard: "wavernote.next-card.v1",
  seekStep: "wavernote.seek-step.v1",
  openNowOnSelect: "wavernote.open-now-on-select.v1",
  theme: "wavernote.theme.v1",
  trends: "wavernote.trends.v1",
  autoQueue: "wavernote.auto-queue.v1",
  randomExcluded: "wavernote.random-excluded.v1",
  recentPrefix: "wavernote.recent.v2.",
  playsPrefix: "wavernote.plays.v2.",
  cloudPrefix: "wavernote.cloud.v3.",
  positionPrefix: "wavernote.position.v1."
};

// El aviso «A continuación» se puede anticipar con distintos tiempos. Se
// guardan como texto para que la preferencia viaje tal cual a la cuenta y se
// pueda sumar una opción nueva sin romper lo ya guardado.
const DEFAULT_NEXT_CARD_TIMING = "20";
const NEXT_CARD_OPTIONS = [
  { value: "off", label: "Nunca", hint: "El aviso queda oculto" },
  { value: "always", label: "Desde el inicio", hint: "Visible durante toda la canción" },
  { value: "5", label: "5 segundos antes" },
  { value: "10", label: "10 segundos antes" },
  { value: "15", label: "15 segundos antes" },
  { value: "20", label: "20 segundos antes", hint: "Predeterminado" },
  { value: "25", label: "25 segundos antes" },
  { value: "30", label: "30 segundos antes" },
  { value: "45", label: "45 segundos antes" },
  { value: "60", label: "1 minuto antes" },
  { value: "90", label: "1 minuto y medio antes" },
  { value: "120", label: "2 minutos antes" },
  { value: "p10", label: "Último 10%", hint: "Según la duración de cada canción" },
  { value: "p25", label: "Último 25%", hint: "Según la duración de cada canción" }
];
const NEXT_CARD_TIMINGS = new Set(NEXT_CARD_OPTIONS.map((option) => option.value));

const normalizeNextCardTiming = (value) => {
  const key = String(value ?? "");
  return NEXT_CARD_TIMINGS.has(key) ? key : DEFAULT_NEXT_CARD_TIMING;
};

const nextCardTimingLabel = (value) =>
  NEXT_CARD_OPTIONS.find((option) => option.value === normalizeNextCardTiming(value))?.label ||
  "20 segundos antes";

// Los botones de salto y las flechas mueven la canción unos segundos. El
// valor se guarda como texto para que viaje a la cuenta igual que el resto
// de las preferencias.
const DEFAULT_SEEK_STEP = "5";
const SEEK_STEP_OPTIONS = [
  { value: "5", label: "5 segundos" },
  { value: "10", label: "10 segundos" },
  { value: "15", label: "15 segundos" }
];
const SEEK_STEP_VALUES = new Set(SEEK_STEP_OPTIONS.map((option) => option.value));

const normalizeSeekStep = (value) => {
  const key = String(value ?? "");
  return SEEK_STEP_VALUES.has(key) ? key : DEFAULT_SEEK_STEP;
};

const seekStepSeconds = () => Number(normalizeSeekStep(state.seekStep)) || Number(DEFAULT_SEEK_STEP);

// El tema se guarda como texto para que viaje tal cual a la cuenta. Azul
// Oceánico es el predeterminado y los otros dos son variantes completas.
const DEFAULT_THEME = "blue";
const THEME_OPTIONS = [
  { value: "blue", label: "Azul Oceánico", hint: "Predeterminado" },
  { value: "green", label: "Verde" },
  { value: "red", label: "Rojo" }
];
const THEMES = new Set(THEME_OPTIONS.map((option) => option.value));

const normalizeTheme = (value) => {
  const key = String(value ?? "");
  return THEMES.has(key) ? key : DEFAULT_THEME;
};

// Cuando la cola termina, la app puede armar otra con canciones al azar.
// Preguntar es el comportamiento predeterminado: rellenar la cola sin avisar
// cambia lo que el usuario eligió escuchar.
const DEFAULT_AUTO_QUEUE = "ask";
const AUTO_QUEUE_OPTIONS = [
  { value: "ask", label: "Preguntar", hint: "Avisa antes de sumar canciones al azar" },
  { value: "always", label: "Siempre", hint: "Rellena la cola sin preguntar" },
  { value: "never", label: "Nunca", hint: "La cola queda vacía al terminar" }
];
const AUTO_QUEUE_VALUES = new Set(AUTO_QUEUE_OPTIONS.map((option) => option.value));

const normalizeAutoQueue = (value) => {
  const key = String(value ?? "");
  return AUTO_QUEUE_VALUES.has(key) ? key : DEFAULT_AUTO_QUEUE;
};

// Canciones que el usuario saca del modo aleatorio. Se guardan solo los ids:
// si una canción se borra, el id deja de coincidir y no afecta a la cola.
const normalizeRandomExcluded = (value) => {
  if (!Array.isArray(value)) return [];
  return [
    ...new Set(
      value
        .map(Number)
        .filter((id) => Number.isInteger(id) && id > 0)
    )
  ].slice(0, 10000);
};

const savedVolume = readJSON(STORAGE.volume, 0.72);
const savedNextCardTiming = readJSON(STORAGE.nextCard, DEFAULT_NEXT_CARD_TIMING);
const savedSeekStep = readJSON(STORAGE.seekStep, DEFAULT_SEEK_STEP);
const savedOpenNowOnSelect = readJSON(STORAGE.openNowOnSelect, false);
const savedTheme = readJSON(STORAGE.theme, DEFAULT_THEME);
const savedAutoQueue = readJSON(STORAGE.autoQueue, DEFAULT_AUTO_QUEUE);
const savedRandomExcluded = readJSON(STORAGE.randomExcluded, []);

const state = {
  ready: false,
  user: null,
  tracks: [],
  pending: [],
  playlists: [],
  trackById: new Map(),
  playlistById: new Map(),
  liked: new Set(),
  recent: [],
  plays: {},
  recommendations: null,
  route: { view: "home" },
  catalogTab: "artist",
  history: [{ view: "home" }],
  historyIndex: 0,
  search: "",
  libraryTab: "songs",
  queue: [],
  queueIndex: -1,
  currentTrackId: null,
  duration: 0,
  currentTime: 0,
  isPlaying: false,
  seeking: false,
  ending: false,
  shuffle: false,
  repeat: "off",
  volume: Number.isFinite(Number(savedVolume)) ? clamp(Number(savedVolume), 0, 1) : 0.72,
  muted: false,
  nextCardTiming: normalizeNextCardTiming(savedNextCardTiming),
  seekStep: normalizeSeekStep(savedSeekStep),
  openNowPlayingOnSelect: Boolean(savedOpenNowOnSelect),
  theme: normalizeTheme(savedTheme),
  trendSets: [],
  trendActiveSet: "all",
  autoQueue: normalizeAutoQueue(savedAutoQueue),
  randomExcluded: new Set(normalizeRandomExcluded(savedRandomExcluded)),
  baseQueue: null,
  baseIndex: 0,
  panelOpen: false,
  npTab: "now",
  uploading: false,
  savingOffline: false,
  isBuffering: false,
  offline: false
};

// El atributo data-theme en <html> activa la paleta; el CSS resuelve el resto.
const syncThemeOptions = () => {
  $$('[data-action="set-theme"]').forEach((option) => {
    const active = option.dataset.value === state.theme;
    option.classList.toggle("is-active", active);
    option.setAttribute("aria-checked", String(active));
    const check = option.querySelector(".settings-option__check");
    if (check) check.innerHTML = active ? icon("check") : "";
  });
};

const applyTheme = (theme = state.theme) => {
  state.theme = normalizeTheme(theme);
  document.documentElement.dataset.theme = state.theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    const deep = getComputedStyle(document.documentElement).getPropertyValue("--bg-deep").trim();
    if (deep) meta.setAttribute("content", deep);
  }
  syncThemeOptions();
};

applyTheme();

// Agrupar la biblioteca por álbum recorre y ordena todas las canciones: si se
// hace una vez por fila, abrir la lista completa se vuelve cuadrático. El
// resultado se guarda hasta que cambie la biblioteca.
let albumListCache = null;
let albumByNameCache = new Map();

const invalidateAlbumCache = () => {
  albumListCache = null;
  albumByNameCache = new Map();
};

const rebuildIndexes = () => {
  state.trackById = new Map(state.tracks.map((track) => [Number(track.id), track]));
  state.playlistById = new Map(state.playlists.map((playlist) => [Number(playlist.id), playlist]));
  invalidateAlbumCache();
};

const trackById = (id) => state.trackById.get(Number(id)) || null;
const playlistById = (id) => state.playlistById.get(Number(id)) || null;
const isLiked = (id) => state.liked.has(Number(id));

const albumNameOf = (track) => (track?.album || "").trim() || "Sin álbum";
const albumIdOf = (name) => encodeURIComponent(name || "Sin álbum");
const albumNameFromId = (id) => {
  try {
    return decodeURIComponent(id || "");
  } catch (err) {
    return id || "";
  }
};

const albumNameOfId = (id) => albumNameOf({ album: albumNameFromId(id) });

const albumTracks = (albumId) => {
  const name = albumNameFromId(albumId);
  return state.tracks
    .filter((track) => albumNameOf(track) === name)
    .sort((a, b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0) || a.id - b.id);
};

const buildAlbumList = () => {
  const groups = new Map();

  state.tracks.forEach((track) => {
    const name = albumNameOf(track);
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(track);
  });

  return Array.from(groups.entries())
    .map(([name, tracks]) => {
      const sorted = tracks
        .slice()
        .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0) || b.id - a.id);
      const artists = new Map();
      tracks.forEach((track) => {
        const artist = (track.artist || "").trim();
        if (artist) artists.set(artist, (artists.get(artist) || 0) + 1);
      });
      const artist = Array.from(artists.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || "Artista desconocido";

      return {
        id: albumIdOf(name),
        title: name,
        artist,
        genre: tracks.find((track) => track.genre)?.genre || "",
        coverUrl: tracks.find((track) => track.coverUrl)?.coverUrl || null,
        tracks,
        duration: tracks.reduce((total, track) => total + (Number(track.duration) || 0), 0),
        year: new Date(sorted[0]?.createdAt || Date.now()).getFullYear(),
        createdAt: sorted[0]?.createdAt || null
      };
    })
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
};

const allAlbums = () => {
  if (albumListCache) return albumListCache;
  albumListCache = buildAlbumList();
  albumByNameCache = new Map(albumListCache.map((album) => [album.title, album]));
  return albumListCache;
};

const albumByTrack = (track) => {
  if (!track) return null;
  const name = albumNameOf(track);
  let album = albumByNameCache.get(name);
  if (!album) {
    allAlbums();
    album = albumByNameCache.get(name);
  }
  return (
    album || {
      id: albumIdOf(name),
      title: name,
      artist: track.artist || "Artista desconocido",
      coverUrl: track.coverUrl || null,
      tracks: [track],
      duration: Number(track.duration) || 0
    }
  );
};

const playlistTracks = (playlist) =>
  (playlist?.trackIds || []).map((id) => trackById(id)).filter(Boolean);

const playlistDuration = (playlist) =>
  playlistTracks(playlist).reduce((total, track) => total + (Number(track.duration) || 0), 0);

const playlistCover = (playlist) => ({
  title: playlist?.name || "Playlist",
  coverUrl: playlistTracks(playlist).find((track) => track.coverUrl)?.coverUrl || null
});

const likedTracks = () => state.tracks.filter((track) => isLiked(track.id));

const recentTracks = () => state.recent.map((id) => trackById(id)).filter(Boolean);

const RECENT_ADDITIONS_DAYS = 7;
const RECENT_ADDITIONS_DAY_MS = 86400000;

const recentlyAddedTracks = (days = RECENT_ADDITIONS_DAYS) => {
  const since = Date.now() - days * RECENT_ADDITIONS_DAY_MS;
  return state.tracks
    .filter((track) => {
      const time = new Date(track.createdAt || 0).getTime();
      return Number.isFinite(time) && time >= since;
    })
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0) || b.id - a.id);
};

const searchLibrary = (rawQuery) => {
  const query = normalize(rawQuery);
  if (!query) return { tracks: [], albums: [], playlists: [], total: 0 };

  const matches = (values) => values.some((value) => normalize(value).includes(query));

  const albums = allAlbums().filter((album) => matches([album.title, album.artist, album.genre]));
  const albumIds = new Set(albums.map((album) => album.title));
  const tracks = state.tracks.filter(
    (track) =>
      matches([track.title, track.artist, track.album, track.genre]) || albumIds.has(albumNameOf(track))
  );
  const playlists = state.playlists.filter((playlist) => matches([playlist.name, playlist.description]));

  return { tracks, albums, playlists, total: tracks.length + albums.length + playlists.length };
};

const loadRecent = () => {
  const userId = Number(state.user?.id) || 0;
  if (!userId) {
    state.recent = [];
    return;
  }
  const saved = readJSON(`${STORAGE.recentPrefix}${userId}`, []);
  state.recent = Array.isArray(saved) ? saved.map(Number).filter((id) => state.trackById.has(id)) : [];
};

const rememberTrack = (id) => {
  const trackId = Number(id);
  if (!state.trackById.has(trackId)) return;
  state.recent = [trackId, ...state.recent.filter((item) => item !== trackId)].slice(0, 12);
  const userId = Number(state.user?.id) || 0;
  if (userId) writeJSON(`${STORAGE.recentPrefix}${userId}`, state.recent);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("recent");
};

const playsStorageKey = () => {
  const userId = Number(state.user?.id) || 0;
  return userId ? `${STORAGE.playsPrefix}${userId}` : "";
};

const PLAY_EVENTS_LIMIT = 80;

const cleanPlayEvent = (value) => {
  const time = typeof value === "number" ? value : new Date(value).getTime();
  return Number.isFinite(time) && time > 0 ? time : 0;
};

const loadPlays = () => {
  const key = playsStorageKey();
  const saved = key ? readJSON(key, {}) : {};
  const clean = {};

  if (saved && typeof saved === "object" && !Array.isArray(saved)) {
    Object.entries(saved).forEach(([id, value]) => {
      const trackId = Number(id);
      const count = Math.max(0, Number(value?.count) || 0);
      if (!state.trackById.has(trackId) || !count) return;
      const events = Array.isArray(value?.events)
        ? value.events.map(cleanPlayEvent).filter(Boolean).slice(-PLAY_EVENTS_LIMIT)
        : [];
      clean[String(trackId)] = {
        count,
        firstPlayedAt: value?.firstPlayedAt || null,
        lastPlayedAt: value?.lastPlayedAt || null,
        events
      };
    });
  }

  state.plays = clean;
};

const recordPlay = (id) => {
  const trackId = Number(id);
  if (!state.trackById.has(trackId)) return;

  const now = Date.now();
  const current = state.plays[String(trackId)] || null;
  const events = Array.isArray(current?.events) ? current.events.slice(-(PLAY_EVENTS_LIMIT - 1)) : [];
  events.push(now);

  state.plays[String(trackId)] = {
    count: (current?.count || 0) + 1,
    firstPlayedAt: current?.firstPlayedAt || new Date(now).toISOString(),
    lastPlayedAt: new Date(now).toISOString(),
    events
  };

  const key = playsStorageKey();
  if (key) writeJSON(key, state.plays);
  if (typeof queuePlaySync === "function") queuePlaySync(trackId);
};

const playStatsOf = (trackOrId) => {
  const id = Number(typeof trackOrId === "object" ? trackOrId?.id : trackOrId);
  const saved = state.plays?.[String(id)] || null;
  return {
    count: Math.max(0, Number(saved?.count) || 0),
    firstPlayedAt: saved?.firstPlayedAt || null,
    lastPlayedAt: saved?.lastPlayedAt || null
  };
};

const totalPlayCount = () =>
  state.tracks.reduce((sum, track) => sum + playStatsOf(track).count, 0);

const mostPlayedTracks = () =>
  state.tracks
    .map((track) => ({ track, ...playStatsOf(track) }))
    .sort(
      (a, b) =>
        b.count - a.count ||
        new Date(b.lastPlayedAt || 0).getTime() - new Date(a.lastPlayedAt || 0).getTime() ||
        String(a.track.title).localeCompare(String(b.track.title), "es")
    );

const saveVolume = () => {
  writeJSON(STORAGE.volume, state.volume);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const saveNextCardTiming = () => {
  state.nextCardTiming = normalizeNextCardTiming(state.nextCardTiming);
  writeJSON(STORAGE.nextCard, state.nextCardTiming);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const saveSeekStep = () => {
  state.seekStep = normalizeSeekStep(state.seekStep);
  writeJSON(STORAGE.seekStep, state.seekStep);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const saveOpenNowOnSelect = () => {
  state.openNowPlayingOnSelect = Boolean(state.openNowPlayingOnSelect);
  writeJSON(STORAGE.openNowOnSelect, state.openNowPlayingOnSelect);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const saveTheme = () => {
  state.theme = normalizeTheme(state.theme);
  writeJSON(STORAGE.theme, state.theme);
  applyTheme();
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const saveAutoQueue = () => {
  state.autoQueue = normalizeAutoQueue(state.autoQueue);
  writeJSON(STORAGE.autoQueue, state.autoQueue);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const isRandomExcluded = (id) => state.randomExcluded.has(Number(id));

const randomExcludedCount = () =>
  state.tracks.reduce(
    (total, track) => total + (state.randomExcluded.has(Number(track.id)) ? 1 : 0),
    0
  );

const saveRandomExcluded = () => {
  writeJSON(STORAGE.randomExcluded, [...state.randomExcluded]);
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const setRandomExcluded = (id, excluded) => {
  const trackId = Number(id);
  if (!state.trackById.has(trackId)) return false;
  if (excluded) state.randomExcluded.add(trackId);
  else state.randomExcluded.delete(trackId);
  saveRandomExcluded();
  return true;
};

const clearRandomExcluded = () => {
  if (!state.randomExcluded.size) return false;
  state.randomExcluded.clear();
  saveRandomExcluded();
  return true;
};

const forgetRandomExcluded = (id) => {
  const trackId = Number(id);
  if (!state.randomExcluded.delete(trackId)) return;
  saveRandomExcluded();
};

const applyLibraryPayload = (data) => {
  state.tracks = Array.isArray(data?.tracks) ? data.tracks : [];
  state.pending = Array.isArray(data?.pending) ? data.pending : [];
  state.playlists = Array.isArray(data?.playlists) ? data.playlists : [];
  state.liked = new Set((data?.likes || []).map(Number));
  rebuildIndexes();
  loadPlays();
  loadRecent();
};

const refreshLibrary = async ({ silent = false, retry = false } = {}) => {
  try {
    const data = await api("/wavernote/library");
    applyLibraryPayload(data);
    state.offline = false;
    // Se espera la escritura: si la app se cierra enseguida, la copia sin
    // conexión igual queda guardada antes de seguir.
    await waOffline.saveLibrary(state.user?.id, data);
    if (typeof updateOfflineUI === "function") updateOfflineUI();
    return data;
  } catch (err) {
    // Sin respuesta del servidor: se usa la copia guardada para que la
    // biblioteca siga disponible aunque no haya internet.
    if (!isOfflineError(err)) throw err;

    const wasOffline = state.offline;
    state.offline = true;

    // Reintento en segundo plano: si ya se está mostrando la copia, no se
    // vuelve a pintar ni se avisa otra vez. Solo importa si el servidor volvió.
    if (retry && wasOffline) {
      if (typeof updateOfflineUI === "function") updateOfflineUI();
      throw err;
    }

    const cached = await waOffline.readLibrary(state.user?.id);
    const fallback =
      cached ||
      (waOffline.hasDownloads() ? waOffline.libraryFromDownloads() : null);

    if (!fallback) {
      if (typeof updateOfflineUI === "function") updateOfflineUI();
      throw err;
    }

    applyLibraryPayload(fallback);
    if (!silent && typeof toast === "function") {
      toast(
        cached
          ? "No pudimos conectar con el servidor: abrimos tu biblioteca guardada."
          : "No pudimos conectar con el servidor: mostrando tus copias guardadas."
      );
    }
    if (typeof updateOfflineUI === "function") updateOfflineUI();
    return fallback;
  }
};

/* ------------------------------------------------------------
   Portadas: imagen subida o arte generativo estable por título
   ------------------------------------------------------------ */

const COVER_PALETTES = [
  ["#0f7a88", "#05111f", "#63e6c8"],
  ["#2449a8", "#070d20", "#8fb7ff"],
  ["#8c3e2e", "#160a09", "#ff9e82"],
  ["#236b55", "#06140f", "#8cf2cb"],
  ["#623d8a", "#0f091c", "#d6b4ff"],
  ["#26688a", "#07131c", "#8be0ff"],
  ["#8a6122", "#160f05", "#ffd98c"],
  ["#782d5e", "#160712", "#ff9ed0"],
  ["#33489c", "#080b1d", "#7ce8ff"],
  ["#1b6a6b", "#051416", "#a6ffde"]
];

const hashString = (value) => {
  let hash = 2166136261;
  const text = String(value || "WaverNote");
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
};

const paletteFor = (value) => COVER_PALETTES[hashString(value) % COVER_PALETTES.length];

const coverMotifSVG = (hash) => {
  const variant = (hash >>> 3) % 5;
  const shift = ((hash >>> 7) % 18) - 9;

  if (variant === 0) {
    // Ondas acústicas + horizonte luminoso
    return `
      <span class="cover-orb cover-orb--soft"></span>
      <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
        <path d="M0 ${74 + shift} C 22 ${54 + shift} 38 ${86 + shift} 58 ${70 + shift} S 90 ${50 + shift} 120 ${66 + shift} V120 H0Z" fill="var(--c1)" opacity=".72"/>
        <path d="M0 ${90 + shift * 0.5} C 26 ${74 + shift * 0.5} 44 ${102 + shift * 0.5} 68 ${88 + shift * 0.5} S 100 ${70 + shift * 0.5} 120 ${82 + shift * 0.5} V120 H0Z" fill="var(--c2)" opacity=".88"/>
        <path d="M0 ${70 + shift} C 22 ${50 + shift} 38 ${82 + shift} 58 ${66 + shift} S 90 ${46 + shift} 120 ${62 + shift}" fill="none" stroke="var(--c3)" stroke-width="1.1" opacity=".62"/>
        <path d="M0 ${84 + shift * 0.5} C 26 ${68 + shift * 0.5} 44 ${96 + shift * 0.5} 68 ${82 + shift * 0.5} S 100 ${64 + shift * 0.5} 120 ${76 + shift * 0.5}" fill="none" stroke="var(--c3)" stroke-width=".55" opacity=".32"/>
      </svg>`;
  }

  if (variant === 1) {
    // Anillos concéntricos + eclipse
    return `
      <span class="cover-glow"></span>
      <span class="cover-orb cover-orb--sun"></span>
      <span class="cover-ring cover-ring--1"></span>
      <span class="cover-ring cover-ring--2"></span>
      <span class="cover-ring cover-ring--3"></span>
      <span class="cover-horizon"></span>`;
  }

  if (variant === 2) {
    // Espectro prismático vertical
    const bars = Array.from({ length: 9 }, (_, i) => {
      const h = 24 + (((hash >> ((i * 3) % 24)) & 15) * 3.4);
      const y = 96 - h;
      const x = 14 + i * 10.5;
      const op = (0.28 + (i % 3) * 0.18).toFixed(2);
      return `<rect x="${x}" y="${y}" width="5.2" height="${h}" rx="2.6" fill="var(--c3)" opacity="${op}"/>`;
    }).join("");
    return `
      <span class="cover-glow"></span>
      <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
        ${bars}
        <line x1="12" y1="98" x2="108" y2="98" stroke="var(--c3)" stroke-width=".8" opacity=".4"/>
      </svg>`;
  }

  if (variant === 3) {
    // Destello radial + orbe flotante
    return `
      <span class="cover-bloom"></span>
      <span class="cover-orb"></span>
      <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
        <circle cx="${60 + shift}" cy="${60 - shift * 0.5}" r="36" fill="none" stroke="var(--c3)" stroke-width=".7" stroke-dasharray="3 4" opacity=".45"/>
      </svg>`;
  }

  // Arcos orbitales + marea sutil
  return `
    <span class="cover-orb cover-orb--soft"></span>
    <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
      <circle cx="94" cy="26" r="24" fill="var(--c3)" opacity=".18"/>
      <circle cx="94" cy="26" r="14" fill="var(--c3)" opacity=".32"/>
      <path d="M-10 86 Q 42 ${44 + shift} 130 78" fill="none" stroke="var(--c3)" stroke-width="1.2" opacity=".52"/>
      <path d="M-10 98 Q 48 ${58 + shift} 130 92" fill="none" stroke="var(--c3)" stroke-width=".7" opacity=".3"/>
      <path d="M-10 108 Q 54 ${72 + shift} 130 104 L 130 120 L -10 120 Z" fill="var(--c1)" opacity=".45"/>
    </svg>`;
};

const coverHTML = (item, className = "") => {
  const title = item?.title || item?.name || "WaverNote";

  // Si la canción está descargada, la portada también vive en el
  // dispositivo: así se ve igual sin conexión.
  const localCover =
    item?.id && typeof waOffline !== "undefined" ? waOffline.coverURL(item.id) : "";
  const src = localCover || item?.coverUrl;

  if (src) {
    return `<img class="cover cover--photo ${className}" src="${escapeHTML(src)}" alt="" loading="lazy" onerror="this.style.display='none'" />`;
  }

  const hash = hashString(title);
  const [c1, c2, c3] = COVER_PALETTES[hash % COVER_PALETTES.length];
  return `<div class="cover ${className}" style="--c1:${c1};--c2:${c2};--c3:${c3}" aria-hidden="true">
    <span class="cover__wash"></span>
    ${coverMotifSVG(hash)}
    <span class="cover__grain"></span>
  </div>`;
};

/* ------------------------------------------------------------
   Carga de archivos
   ------------------------------------------------------------ */

const readAudioDuration = (file) =>
  new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const audio = document.createElement("audio");
    audio.preload = "metadata";

    const finish = (value) => {
      URL.revokeObjectURL(url);
      audio.removeAttribute("src");
      resolve(Number.isFinite(value) ? value : 0);
    };

    audio.addEventListener("loadedmetadata", () => finish(audio.duration), { once: true });
    audio.addEventListener("error", () => finish(0), { once: true });
    window.setTimeout(() => finish(audio.duration || 0), 12000);
    audio.src = url;
  });

const uploadTrackFile = ({ file, fields, cover, onProgress }) =>
  new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}/wavernote/tracks`);

    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);

    if (xhr.upload && typeof onProgress === "function") {
      xhr.upload.addEventListener("progress", (event) => {
        if (event.lengthComputable && event.total > 0) onProgress(event.loaded / event.total);
      });
    }

    xhr.addEventListener("load", async () => {
      let data = null;
      try {
        data = JSON.parse(xhr.responseText || "null");
      } catch (err) {
        data = { error: apiErrorMessage(xhr.status, xhr.responseText, `No se pudo subir el archivo (${xhr.status}).`) };
      }

      if (xhr.status >= 200 && xhr.status < 300 && data?.track) {
        // El audio salió de este dispositivo: se guarda la misma copia para
        // que quede disponible sin conexión sin pedir otra descarga.
        try {
          if (typeof waOffline !== "undefined" && typeof waOffline.saveUploadedTrack === "function") {
            await waOffline.saveUploadedTrack(data.track, file, { cover });
          }
        } catch (err) {
          /* la subida ya está bien; la copia local es opcional */
        }
        resolve(data.track);
        return;
      }

      const error = new Error(data?.error || `No se pudo subir el archivo (${xhr.status}).`);
      error.status = xhr.status;
      reject(error);
    });

    xhr.addEventListener("error", () => reject(new Error("No se pudo conectar con el servidor.")));
    xhr.addEventListener("abort", () => reject(new Error("Subida cancelada.")));

    const form = new FormData();
    form.append("audio", file, file.name);
    Object.entries(fields || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && String(value).trim() !== "") {
        form.append(key, String(value));
      }
    });
    if (cover) form.append("cover", cover, cover.name);

    xhr.send(form);
  });

// Edición de la ficha de una canción. Solo usa multipart cuando hay una
// miniatura nueva o se quita la actual; el resto viaja como JSON liviano.
const updateTrackDetails = async ({ trackId, fields, cover = null, removeCover = false }) => {
  const id = Number(trackId);
  if (!id) throw new Error("Canción inválida.");

  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  let body;
  if (cover || removeCover) {
    body = new FormData();
    Object.entries(fields || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null) body.append(key, String(value));
    });
    if (cover) body.append("cover", cover, cover.name || "cover.jpg");
    if (removeCover) body.append("removeCover", "true");
  } else {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(fields || {});
  }

  const response = await fetch(`${API_BASE}/wavernote/tracks/${id}`, {
    method: "PATCH",
    headers,
    body
  });

  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (err) {
    data = {
      error: apiErrorMessage(response.status, text, `No se pudo guardar la canción (${response.status}).`)
    };
  }

  if (!response.ok) {
    const error = new Error(
      data?.error || `No se pudo guardar la canción (${response.status}).`
    );
    error.status = response.status;
    error.code = data?.code || "";
    throw error;
  }

  return data;
};

/* ------------------------------------------------------------
   Toasts
   ------------------------------------------------------------ */

const toast = (message, kind = "ok") => {
  const stack = $("#toasts");
  if (!stack) return;
  while (stack.children.length >= 3) stack.firstElementChild.remove();

  const node = document.createElement("div");
  node.className = `toast toast--${kind}`;
  node.innerHTML = `${icon(kind === "error" ? "x" : "check")}<span>${escapeHTML(message)}</span>`;
  stack.appendChild(node);
  requestAnimationFrame(() => node.classList.add("is-in"));
  window.setTimeout(() => {
    node.classList.remove("is-in");
    window.setTimeout(() => node.remove(), 220);
  }, 3200);
};

/* ------------------------------------------------------------
   Navegación
   ------------------------------------------------------------ */

const resolveListContext = (context) => {
  if (!context) return null;
  if (context === "all") return state.tracks.map((track) => track.id);
  if (context === "liked") return likedTracks().map((track) => track.id);
  if (context === "recent") return recentTracks().map((track) => track.id);
  if (context === "recent-additions") return recentlyAddedTracks().map((track) => track.id);
  if (context === "search") return searchLibrary(state.search).tracks.map((track) => track.id);
  if (context.startsWith("rec:")) return recommendationTrackIds(context.slice(4));
  if (context.startsWith("album:")) return albumTracks(context.slice(6)).map((track) => track.id);
  if (context.startsWith("playlist:")) {
    const playlist = playlistById(context.slice(9));
    return playlist ? playlist.trackIds.slice() : null;
  }
  return null;
};

const updateSearchChrome = () => {
  const wrap = $("#searchWrap");
  const input = $("#searchInput");
  if (!wrap || !input) return;
  wrap.classList.toggle("has-value", input.value.trim().length > 0);
};

const afterRouteChange = ({ focusSearch = false, resetScroll = true } = {}) => {
  const route = state.route;
  const input = $("#searchInput");

  if (route.view === "search") {
    state.search = route.q || "";
    if (input && document.activeElement !== input) input.value = state.search;
  }

  updateSearchChrome();
  renderView({ resetScroll });
  updateNavUI();

  if (focusSearch && input) {
    requestAnimationFrame(() => {
      input.focus({ preventScroll: true });
      const length = input.value.length;
      try {
        input.setSelectionRange(length, length);
      } catch (err) {
        /* noop */
      }
    });
  }

  // La última pantalla también viaja con la cuenta: al entrar desde otro
  // dispositivo se retoma donde quedó la sesión.
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");

  // El panel rápido del reproductor se cierra al cambiar de pantalla.
  window.dispatchEvent(new CustomEvent("wavernote:route-change"));
};

const navigate = (route, options = {}) => {
  const { replace = false, focusSearch = false, resetScroll = true } = options;
  const next = { ...route };

  if (replace) {
    state.history[state.historyIndex] = next;
  } else {
    if (state.history[state.historyIndex] && sameRoute(state.history[state.historyIndex], next)) {
      state.route = next;
      state.history[state.historyIndex] = next;
      afterRouteChange({ focusSearch, resetScroll });
      return;
    }
    state.history = state.history.slice(0, state.historyIndex + 1);
    state.history.push(next);
    state.historyIndex += 1;
  }

  state.route = next;
  afterRouteChange({ focusSearch, resetScroll });
};

const sameRoute = (a, b) =>
  a &&
  b &&
  a.view === b.view &&
  (a.id || "") === (b.id || "") &&
  (a.tab || "") === (b.tab || "") &&
  (a.q || "") === (b.q || "");

const goHistory = (delta) => {
  const index = state.historyIndex + delta;
  if (index < 0 || index >= state.history.length) return;
  state.historyIndex = index;
  state.route = state.history[index];
  afterRouteChange({ resetScroll: true });
};

const updateHistoryButtons = () => {
  const back = $("#backBtn");
  const forward = $("#forwardBtn");
  if (back) back.disabled = state.historyIndex <= 0;
  if (forward) forward.disabled = state.historyIndex >= state.history.length - 1;
};

const resetNavigation = () => {
  state.route = { view: "home" };
  state.history = [{ view: "home" }];
  state.historyIndex = 0;
  state.search = "";
  state.libraryTab = "songs";
  const input = $("#searchInput");
  if (input) input.value = "";
  updateSearchChrome();
};
