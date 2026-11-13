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

const getStoredUser = () => readJSON(USER_KEY, null);

const saveSession = (token, user) => {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
  } catch (err) {
    /* noop */
  }
  const safeUser = { id: Number(user?.id) || 0, username: user?.username || "" };
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
  recentPrefix: "wavernote.recent.v2.",
  playsPrefix: "wavernote.plays.v2.",
  cloudPrefix: "wavernote.cloud.v3.",
  positionPrefix: "wavernote.position.v1."
};

const savedVolume = readJSON(STORAGE.volume, 0.72);

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
  baseQueue: null,
  baseIndex: 0,
  panelOpen: false,
  npTab: "now",
  uploading: false,
  isBuffering: false
};

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

const refreshLibrary = async () => {
  const data = await api("/wavernote/library");
  state.tracks = Array.isArray(data?.tracks) ? data.tracks : [];
  state.pending = Array.isArray(data?.pending) ? data.pending : [];
  state.playlists = Array.isArray(data?.playlists) ? data.playlists : [];
  state.liked = new Set((data?.likes || []).map(Number));
  rebuildIndexes();
  loadPlays();
  loadRecent();
  return data;
};

/* ------------------------------------------------------------
   Portadas: imagen subida o degradado estable por título
   ------------------------------------------------------------ */

const COVER_PALETTES = [
  ["#0f6b78", "#06121f", "#6be8d2"],
  ["#1c3f8f", "#080f21", "#8fb7ff"],
  ["#7a3d2e", "#160b0a", "#ffb08a"],
  ["#2c6350", "#07130f", "#9af0c9"],
  ["#5b3b7a", "#100a1a", "#d6b4ff"],
  ["#2f5f7a", "#08131a", "#a4dcff"],
  ["#7a5a24", "#171006", "#ffe1a1"],
  ["#6b2f55", "#170812", "#ffa8d5"]
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

const coverHTML = (item, className = "") => {
  const title = item?.title || item?.name || "WaverNote";

  if (item?.coverUrl) {
    return `<img class="cover cover--photo ${className}" src="${escapeHTML(item.coverUrl)}" alt="" loading="lazy" />`;
  }

  const [c1, c2, c3] = paletteFor(title);
  return `<div class="cover ${className}" style="--c1:${c1};--c2:${c2};--c3:${c3}" aria-hidden="true">
    <span class="cover__wash"></span>
    <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
      <path d="M0 78 C 20 60 34 88 52 74 S 86 56 120 70 V120 H0Z" fill="var(--c1)" opacity=".7"/>
      <path d="M0 92 C 24 76 40 100 64 88 S 98 72 120 84 V120 H0Z" fill="var(--c2)" opacity=".85"/>
      <path d="M0 74 C 20 56 34 84 52 70 S 86 52 120 66" fill="none" stroke="var(--c3)" stroke-width=".8" opacity=".5"/>
      <path d="M0 88 C 24 72 40 96 64 84 S 98 68 120 80" fill="none" stroke="var(--c3)" stroke-width=".4" opacity=".28"/>
    </svg>
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

    xhr.addEventListener("load", () => {
      let data = null;
      try {
        data = JSON.parse(xhr.responseText || "null");
      } catch (err) {
        data = { error: apiErrorMessage(xhr.status, xhr.responseText, `No se pudo subir el archivo (${xhr.status}).`) };
      }

      if (xhr.status >= 200 && xhr.status < 300 && data?.track) {
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
