/* ============================================================
   WaverNote · interacción
   Eventos, búsqueda, panel de cola y arranque del prototipo.
   ============================================================ */

const searchInput = $("#searchInput");
const scrim = $("#scrim");

const isOverlay = () => window.matchMedia("(max-width: 1279px)").matches;

const updatePanelButtons = () => {
  const queueButton = $("#queueBtn");
  if (queueButton) queueButton.setAttribute("aria-expanded", String(state.panelOpen));
  $$('.mobile-nav__item[data-mobile-nav="panel"]').forEach((button) => {
    button.classList.toggle("is-active", state.panelOpen);
  });
};

const openPanel = () => {
  if (!isOverlay()) {
    const queue = $(".np__queue");
    const panel = $("#nowPlaying");
    panel?.classList.add("is-focused");
    queue?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    setTimeout(() => panel?.classList.remove("is-focused"), 1000);
    return;
  }
  state.panelOpen = true;
  els.app?.classList.add("np-open");
  updatePanelButtons();
  setTimeout(() => $("#npClose")?.focus({ preventScroll: true }), 180);
};

const closePanel = () => {
  state.panelOpen = false;
  els.app?.classList.remove("np-open");
  updatePanelButtons();
};

const togglePanel = () => {
  if (!isOverlay()) {
    openPanel();
    return;
  }
  if (state.panelOpen) closePanel();
  else openPanel();
};

/* ------------------------------------------------------------
   Piezas de interfaz estáticas
   ------------------------------------------------------------ */

const renderSidebarPlaylists = () => {
  const nav = $("#playlistNav");
  if (!nav) return;
  nav.innerHTML = WN_PLAYLISTS.map(
    (playlist) => `<button class="side-playlist" data-action="open-playlist" data-id="${playlist.id}" title="${escapeHTML(playlist.name)}">
      <span class="side-playlist__art">${coverHTML(playlist)}</span>
      <span class="side-playlist__name">${escapeHTML(playlist.name)}</span>
    </button>`
  ).join("");
};

const focusSearch = () => {
  if (!searchInput) return;
  searchInput.focus({ preventScroll: true });
  const length = searchInput.value.length;
  try {
    searchInput.setSelectionRange(length, length);
  } catch (err) {
    /* noop */
  }
};

const goSearch = () => {
  navigate({ view: "search", q: state.search }, { focusSearch: true });
};

const clearSearch = () => {
  if (!searchInput) return;
  searchInput.value = "";
  state.search = "";
  updateSearchChrome();

  if (state.route.view === "search") {
    state.route.q = "";
    state.history[state.historyIndex] = state.route;
    renderView({ resetScroll: false });
  }
  focusSearch();
};

const applyMood = (query) => {
  if (!searchInput) return;
  searchInput.value = query;
  state.search = query;
  updateSearchChrome();

  if (state.route.view === "search") {
    state.route.q = query;
    state.history[state.historyIndex] = state.route;
    renderView({ resetScroll: true });
  } else {
    navigate({ view: "search", q: query }, { resetScroll: true });
  }
  focusSearch();
};

const handleSearchInput = () => {
  if (!searchInput) return;
  const value = searchInput.value;
  state.search = value;
  updateSearchChrome();

  if (state.route.view === "search") {
    state.route.q = value;
    state.history[state.historyIndex] = state.route;
    renderView({ resetScroll: false });
  } else {
    navigate({ view: "search", q: value }, { resetScroll: true });
  }
};

const playLiked = () => {
  const ids = WN_TRACKS.filter((track) => isLiked(track.id)).map((track) => track.id);
  if (!ids.length) {
    toast("Todavía no guardaste ninguna canción");
    return;
  }
  startQueue(ids, { startIndex: 0 });
};

const playRow = (row) => {
  const id = row.dataset.id;
  if (!TRACK_BY_ID.has(id)) return;

  if (id === state.currentTrackId) {
    togglePlay();
    return;
  }

  const list = row.closest("[data-list-context]");
  const context = list?.dataset.listContext || "";
  const ids = resolveListContext(context) || [id];
  let index = ids.indexOf(id);
  if (index < 0) {
    ids.unshift(id);
    index = 0;
  }
  startQueue(ids, { startIndex: index });
};

const playQueueIndex = (index) => {
  const target = Number(index);
  if (!Number.isInteger(target) || target < 0 || target >= state.queue.length) return;
  if (target === state.queueIndex) {
    togglePlay();
    return;
  }
  state.queueIndex = target;
  playCurrent();
};

/* ------------------------------------------------------------
   Eventos de puntero
   ------------------------------------------------------------ */

document.addEventListener("click", (event) => {
  const actionEl = event.target.closest("[data-action]");
  if (!actionEl) return;
  if (actionEl.matches('a[href="#"]')) event.preventDefault();

  const action = actionEl.dataset.action;
  const id = actionEl.dataset.id;

  switch (action) {
    case "nav-home":
      closePanel();
      navigate({ view: "home" });
      break;
    case "nav-search":
      closePanel();
      goSearch();
      break;
    case "nav-library":
      closePanel();
      navigate({ view: "library" });
      break;
    case "open-library": {
      closePanel();
      const tab = actionEl.dataset.tab;
      if (tab) state.libraryTab = tab;
      navigate({ view: "library" });
      break;
    }
    case "history-back":
      closePanel();
      goHistory(-1);
      break;
    case "history-forward":
      closePanel();
      goHistory(1);
      break;
    case "open-album":
      if (!ALBUM_BY_ID.has(id)) return;
      closePanel();
      navigate({ view: "album", id });
      break;
    case "open-playlist":
      if (!PLAYLIST_BY_ID.has(id)) return;
      closePanel();
      navigate({ view: "playlist", id });
      break;
    case "play-row": {
      const row = actionEl.closest("[data-track-row]");
      if (row) playRow(row);
      break;
    }
    case "play-album": {
      const tracks = albumTracks(id).map((track) => track.id);
      if (tracks.length) startQueue(tracks, { startIndex: 0 });
      break;
    }
    case "shuffle-album": {
      const tracks = albumTracks(id).map((track) => track.id);
      if (tracks.length) startQueue(tracks, { shuffle: true, randomStart: true });
      break;
    }
    case "queue-album": {
      const ids = albumTracks(id).map((track) => track.id);
      if (ids.length) queueCollection(ids, ALBUM_BY_ID.get(id)?.title || "Álbum");
      break;
    }
    case "play-playlist": {
      const playlist = PLAYLIST_BY_ID.get(id);
      if (playlist) startQueue(playlist.tracks, { startIndex: 0 });
      break;
    }
    case "shuffle-playlist": {
      const playlist = PLAYLIST_BY_ID.get(id);
      if (playlist) startQueue(playlist.tracks, { shuffle: true, randomStart: true });
      break;
    }
    case "queue-playlist": {
      const playlist = PLAYLIST_BY_ID.get(id);
      if (playlist) queueCollection(playlist.tracks, playlist.name);
      break;
    }
    case "play-session":
      startQueue(WN_HOME_SESSION, { startIndex: 0 });
      break;
    case "play-liked":
      playLiked();
      break;
    case "play-queue":
      playQueueIndex(actionEl.dataset.index);
      break;
    case "toggle-play":
      togglePlay();
      break;
    case "toggle-mute":
      toggleMute();
      break;
    case "next-track":
      nextTrack();
      break;
    case "prev-track":
      previousTrack();
      break;
    case "shuffle":
      toggleShuffle();
      break;
    case "repeat":
      cycleRepeat();
      break;
    case "like":
      toggleLike(id);
      break;
    case "like-current":
      toggleLike(state.currentTrackId);
      break;
    case "queue-add":
      addToQueue(id);
      break;
    case "library-tab":
      state.libraryTab = actionEl.dataset.tab || "songs";
      if (state.route.view !== "library") navigate({ view: "library" });
      else renderView({ resetScroll: true });
      updateNavUI();
      break;
    case "apply-mood":
      applyMood(actionEl.dataset.query || "");
      break;
    case "clear-search":
      clearSearch();
      break;
    case "toggle-panel":
      togglePanel();
      break;
    case "close-panel":
      closePanel();
      break;
    default:
      break;
  }
});

/* Soporte de teclado para elementos clickeables no nativos */
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const target = event.target;
  const roleButton = target.closest?.('[role="button"][data-action]');
  if (!roleButton) return;
  const nativeInteractive = target.closest?.("button, a, input, select, textarea");
  if (nativeInteractive && nativeInteractive !== roleButton) return;
  event.preventDefault();
  roleButton.click();
});

/* ------------------------------------------------------------
   Controles
   ------------------------------------------------------------ */

if (els.seek) {
  els.seek.addEventListener("input", () => {
    state.seeking = true;
    const seconds = (Number(els.seek.value) / 1000) * state.duration;
    if (els.current) els.current.textContent = formatTime(seconds);
    paintRange(els.seek, Number(els.seek.value) / 10);
  });

  els.seek.addEventListener("change", () => {
    const seconds = (Number(els.seek.value) / 1000) * state.duration;
    state.seeking = false;
    seekTo(seconds);
  });

  els.seek.addEventListener("pointerdown", () => {
    state.seeking = true;
  });
}

if (els.volume) {
  els.volume.addEventListener("input", () => {
    setVolume(Number(els.volume.value) / 100);
  });
}

if (searchInput) {
  searchInput.addEventListener("input", handleSearchInput);
  searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      const results = searchCatalog(state.search);
      if (results.tracks.length) {
        event.preventDefault();
        startQueue(results.tracks.map((track) => track.id), { startIndex: 0 });
      }
    }
    if (event.key === "Escape") {
      event.preventDefault();
      searchInput.blur();
    }
  });
}

scrim?.addEventListener("click", closePanel);

window.addEventListener("resize", () => {
  if (!isOverlay() && state.panelOpen) closePanel();
});

/* ------------------------------------------------------------
   Atajos globales
   ------------------------------------------------------------ */

document.addEventListener("keydown", (event) => {
  const target = event.target;
  const typing =
    target instanceof HTMLElement &&
    (target.matches("input, textarea, select") || target.isContentEditable);

  const key = event.key;

  if ((event.ctrlKey || event.metaKey) && key.toLowerCase() === "k") {
    event.preventDefault();
    goSearch();
    return;
  }

  if (typing) return;

  const nativeControl =
    target instanceof HTMLElement &&
    target.closest("button, a, input, select, textarea, [role='button']");

  if (key === " " && nativeControl) return;

  if (key === " ") {
    event.preventDefault();
    togglePlay();
    return;
  }

  if (key === "ArrowRight") {
    event.preventDefault();
    seekTo(state.currentTime + 5);
    return;
  }

  if (key === "ArrowLeft") {
    event.preventDefault();
    seekTo(state.currentTime - 5);
    return;
  }

  if (key.toLowerCase() === "l") {
    event.preventDefault();
    toggleLike(state.currentTrackId);
    return;
  }

  if (key.toLowerCase() === "m") {
    event.preventDefault();
    toggleMute();
    return;
  }

  if (key === "/") {
    event.preventDefault();
    goSearch();
    return;
  }

  if (key === "Escape") {
    if (state.panelOpen) {
      closePanel();
      return;
    }
    searchInput?.blur();
  }
});

/* ------------------------------------------------------------
   Inicio
   ------------------------------------------------------------ */

const init = () => {
  renderSidebarPlaylists();

  engine.setVolume(state.volume);
  engine.setMuted(state.muted);

  if (els.seek) {
    els.seek.min = "0";
    els.seek.max = "1000";
  }

  if (els.volume) els.volume.value = String(Math.round(state.volume * 100));

  renderView({ resetScroll: true });
  updateNowPlaying();
  updateVolumeUI();
  updateNavUI();
  updatePanelButtons();
  setupMediaSession();
  startUiLoop();

  document.documentElement.classList.add("is-ready");
};

init();
