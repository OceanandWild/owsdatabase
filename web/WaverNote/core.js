/* ============================================================
   WaverNote · núcleo
   Utilidades, catálogo derivado, estado y navegación.
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
  String(value).replace(/[&<>"']/g, (char) => {
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

/* ------------------------------------------------------------
   Catálogo derivado
   ------------------------------------------------------------ */

const ALBUM_BY_ID = new Map(WN_ALBUMS.map((album) => [album.id, album]));
const TRACK_BY_ID = new Map(WN_TRACKS.map((track) => [track.id, track]));
const PLAYLIST_BY_ID = new Map(WN_PLAYLISTS.map((playlist) => [playlist.id, playlist]));

const albumOf = (track) => ALBUM_BY_ID.get(track.albumId);

const albumTracks = (albumId) => WN_TRACKS.filter((track) => track.albumId === albumId);

const albumDuration = (albumId) =>
  albumTracks(albumId).reduce((total, track) => total + track.duration, 0);

const playlistTracks = (playlist) =>
  playlist.tracks.map((id) => TRACK_BY_ID.get(id)).filter(Boolean);

const playlistDuration = (playlist) =>
  playlistTracks(playlist).reduce((total, track) => total + track.duration, 0);

const searchCatalog = (rawQuery) => {
  const query = normalize(rawQuery);
  if (!query) return { tracks: [], albums: [], playlists: [], total: 0 };

  const matches = (item, fields) => {
    if (fields.some((field) => normalize(item[field]).includes(query))) return true;
    return (item.tags || []).some((tag) => normalize(tag).includes(query));
  };

  const albums = WN_ALBUMS.filter((album) =>
    matches(album, ["title", "artist", "genre", "description"])
  );
  const albumIds = new Set(albums.map((album) => album.id));

  const tracks = WN_TRACKS.filter((track) => {
    if (normalize(track.title).includes(query)) return true;
    const album = albumOf(track);
    return albumIds.has(album.id) || matches(album, ["title", "artist", "genre"]);
  });

  const playlists = WN_PLAYLISTS.filter((playlist) =>
    matches(playlist, ["name", "description"])
  );

  return { tracks, albums, playlists, total: tracks.length + albums.length + playlists.length };
};

/* ------------------------------------------------------------
   Persistencia local
   ------------------------------------------------------------ */

const STORAGE = {
  liked: "wavernote.liked.v1",
  recent: "wavernote.recent.v1",
  volume: "wavernote.volume.v1",
};

const readStore = (key, fallback) => {
  try {
    const raw = localStorage.getItem(key);
    return raw === null ? fallback : JSON.parse(raw);
  } catch (err) {
    return fallback;
  }
};

const writeStore = (key, value) => {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (err) {
    /* modo privado o almacenamiento lleno: la demo sigue funcionando */
  }
};

const hadLikedStore = (() => {
  try {
    return localStorage.getItem(STORAGE.liked) !== null;
  } catch (err) {
    return false;
  }
})();

const savedVolume = readStore(STORAGE.volume, 0.72);

const state = {
  route: { view: "home" },
  history: [{ view: "home" }],
  historyIndex: 0,
  search: "",
  libraryTab: "songs",
  queue: WN_HOME_SESSION.slice(),
  queueIndex: Math.max(0, WN_HOME_SESSION.indexOf(WN_FEATURED_TRACK)),
  currentTrackId: WN_FEATURED_TRACK,
  duration: TRACK_BY_ID.get(WN_FEATURED_TRACK).duration,
  currentTime: 0,
  isPlaying: false,
  seeking: false,
  ending: false,
  shuffle: false,
  repeat: "off",
  volume: Number.isFinite(Number(savedVolume)) ? clamp(Number(savedVolume), 0, 1) : 0.72,
  muted: false,
  liked: new Set(hadLikedStore ? readStore(STORAGE.liked, []) : WN_DEFAULT_LIKED),
  recent: readStore(STORAGE.recent, []).filter((id) => TRACK_BY_ID.has(id)),
  baseQueue: null,
  baseIndex: 0,
  panelOpen: false,
  warnedNoAudio: false,
};

const saveLiked = () => writeStore(STORAGE.liked, Array.from(state.liked));
const saveVolume = () => writeStore(STORAGE.volume, state.volume);

const rememberTrack = (id) => {
  state.recent = [id, ...state.recent.filter((item) => item !== id)].slice(0, 12);
  writeStore(STORAGE.recent, state.recent);
};

const isLiked = (id) => state.liked.has(id);

/* ------------------------------------------------------------
   Portadas generativas (CSS + SVG, sin imágenes externas)
   ------------------------------------------------------------ */

const coverArtwork = (art) => {
  switch (art) {
    case "rings":
      return `<span class="cover-orb cover-orb--sun"></span>
        <span class="cover-ring cover-ring--1"></span>
        <span class="cover-ring cover-ring--2"></span>
        <span class="cover-ring cover-ring--3"></span>
        <span class="cover-horizon"></span>`;
    case "orb":
      return `<span class="cover-orb"></span>
        <span class="cover-glow"></span>
        <span class="cover-horizon"></span>`;
    case "dunes":
      return `<svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
        <path d="M0 88 C 22 62 44 92 66 74 S 98 58 120 76 V120 H0Z" fill="var(--c2)" opacity=".72"/>
        <path d="M0 98 C 26 78 52 104 78 88 S 106 74 120 88 V120 H0Z" fill="var(--c1)" opacity=".8"/>
        <path d="M0 74 C 22 52 44 78 66 62 S 98 48 120 64" fill="none" stroke="var(--c3)" stroke-width=".8" opacity=".45"/>
        <path d="M0 84 C 26 66 48 92 72 76 S 104 62 120 74" fill="none" stroke="var(--c3)" stroke-width=".4" opacity=".25"/>
      </svg>`;
    case "grid":
      return `<span class="cover-orb cover-orb--sun"></span>
        <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
          <g stroke="var(--c3)" stroke-width=".5" opacity=".32">
            <path d="M0 86 H120 M0 94 H120 M0 104 H120 M0 116 H120"/>
            <path d="M10 120 L28 80 M34 120 L44 80 M58 120 L60 80 M84 120 L76 80 M110 120 L92 80"/>
          </g>
          <path d="M12 78 H108" stroke="var(--c3)" stroke-width="1" opacity=".55"/>
        </svg>`;
    case "bloom":
      return `<span class="cover-orb cover-orb--soft"></span>
        <span class="cover-bloom"></span>
        <span class="cover-horizon"></span>`;
    default:
      return `<span class="cover-orb cover-orb--soft"></span>
        <svg class="cover-svg" viewBox="0 0 120 120" preserveAspectRatio="none" aria-hidden="true">
          <path d="M0 72 C 18 58 32 84 48 72 S 82 54 120 68 V120 H0Z" fill="var(--c1)" opacity=".72"/>
          <path d="M0 84 C 22 70 36 94 58 82 S 90 66 120 80 V120 H0Z" fill="var(--c2)" opacity=".8"/>
          <path d="M0 96 C 24 84 40 104 64 94 S 96 82 120 92 V120 H0Z" fill="#03060c" opacity=".6"/>
          <path d="M0 72 C 18 58 32 84 48 72 S 82 54 120 68" fill="none" stroke="var(--c3)" stroke-width=".7" opacity=".5"/>
        </svg>`;
  }
};

const coverHTML = (item, className = "") => {
  const palette = item.palette || ["#0f6b78", "#06121f", "#6be8d2"];
  return `<div class="cover ${className}" style="--c1:${palette[0]};--c2:${palette[1]};--c3:${palette[2]}" aria-hidden="true">
    <span class="cover__wash"></span>
    ${coverArtwork(item.art || "ridge")}
    <span class="cover__grain"></span>
  </div>`;
};

/* ------------------------------------------------------------
   Toasts
   ------------------------------------------------------------ */

const toast = (message) => {
  const stack = $("#toasts");
  if (!stack) return;
  while (stack.children.length >= 3) stack.firstElementChild.remove();
  const node = document.createElement("div");
  node.className = "toast";
  node.innerHTML = `${icon("check")}<span>${escapeHTML(message)}</span>`;
  stack.appendChild(node);
  requestAnimationFrame(() => node.classList.add("is-in"));
  setTimeout(() => {
    node.classList.remove("is-in");
    setTimeout(() => node.remove(), 220);
  }, 2600);
};

/* ------------------------------------------------------------
   Navegación
   ------------------------------------------------------------ */

const resolveListContext = (context) => {
  if (!context) return null;
  if (context === "home-session") return WN_HOME_SESSION.slice();
  if (context === "liked") {
    return WN_TRACKS.filter((track) => state.liked.has(track.id)).map((track) => track.id);
  }
  if (context === "recent") return state.recent.filter((id) => TRACK_BY_ID.has(id));
  if (context === "search") {
    return searchCatalog(state.search).tracks.map((track) => track.id);
  }
  if (context.startsWith("album:")) {
    return albumTracks(context.slice(6)).map((track) => track.id);
  }
  if (context.startsWith("playlist:")) {
    const playlist = PLAYLIST_BY_ID.get(context.slice(9));
    return playlist ? playlist.tracks.slice() : null;
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
