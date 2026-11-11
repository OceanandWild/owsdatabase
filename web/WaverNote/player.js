/* ============================================================
   WaverNote · reproductor
   Cola, transporte real, sincronización de interfaz y visualizador.
   ============================================================ */

const engine = new WaveEngine();

const els = {
  app: $("#app"),
  play: $("#playBtn"),
  prev: $("#prevBtn"),
  next: $("#nextBtn"),
  shuffle: $("#shuffleBtn"),
  repeat: $("#repeatBtn"),
  seek: $("#seek"),
  current: $("#curTime"),
  duration: $("#durTime"),
  volume: $("#volume"),
  volumeButton: $("#volBtn"),
  playerCover: $("#playerCover"),
  playerTitle: $("#playerTitle"),
  playerArtist: $("#playerArtist"),
  playerLike: $("#playerLike"),
  npCover: $("#npCover"),
  npTitle: $("#npTitle"),
  npArtist: $("#npArtist"),
  npAlbum: $("#npAlbum"),
  npEmpty: $("#npEmpty"),
  npFacts: $("#npFacts"),
  npLike: $("#npLike"),
  npQueue: $("#npQueue"),
  npQueueCount: $("#npQueueCount")
};

const currentTrack = () => trackById(state.currentTrackId);

let pendingPlayId = null;

const flushPendingPlay = () => {
  if (!pendingPlayId) return;
  const trackId = pendingPlayId;
  pendingPlayId = null;
  recordPlay(trackId);
};

engine.onEnded = () => handleTrackEnd();
engine.onMetadata = (duration) => {
  if (Number.isFinite(duration) && duration > 0) {
    state.duration = duration;
    updateProgressUI();
    syncMediaSessionState();
  }
};
engine.onError = () => {
  if (!currentTrack()) return;
  toast("No se pudo reproducir este archivo. Revisá que el formato siga disponible.", "error");
};

/* ------------------------------------------------------------
   Transporte
   ------------------------------------------------------------ */

const paintRange = (input, percent) => {
  if (!input) return;
  const safe = clamp(percent, 0, 100);
  input.style.setProperty("--fill", `${safe}%`);
};

const updateProgressUI = () => {
  if (!els.seek || state.seeking) return;
  const ratio = state.duration ? clamp(state.currentTime / state.duration, 0, 1) : 0;
  els.seek.value = String(Math.round(ratio * 1000));
  paintRange(els.seek, ratio * 100);
  document.documentElement.style.setProperty("--mobile-progress", `${ratio * 100}%`);
  if (els.current) els.current.textContent = formatTime(state.currentTime);
  if (els.duration) els.duration.textContent = formatTime(state.duration);
};

const updatePlayButton = () => {
  if (!els.play) return;
  els.play.innerHTML = state.isPlaying ? icon("pause", "icon--fill") : icon("play", "icon--fill");
  els.play.setAttribute("aria-label", state.isPlaying ? "Pausar" : "Reproducir");
  els.app?.classList.toggle("is-playing", state.isPlaying);
};

const updateShuffleUI = () => {
  if (!els.shuffle) return;
  els.shuffle.classList.toggle("is-active", state.shuffle);
  els.shuffle.setAttribute("aria-pressed", String(state.shuffle));
  els.shuffle.setAttribute("aria-label", state.shuffle ? "Desactivar aleatorio" : "Activar aleatorio");
};

const updateRepeatUI = () => {
  if (!els.repeat) return;
  els.repeat.classList.toggle("is-active", state.repeat !== "off");
  els.repeat.innerHTML = state.repeat === "one" ? icon("repeat-one") : icon("repeat");
  const labels = { off: "Activar repetición", all: "Repetir toda la cola", one: "Repetir esta canción" };
  els.repeat.setAttribute("aria-label", labels[state.repeat]);
  els.repeat.setAttribute("aria-pressed", String(state.repeat !== "off"));
  els.repeat.dataset.repeat = state.repeat;
};

const updateVolumeUI = () => {
  if (els.volume) {
    els.volume.value = String(Math.round(state.volume * 100));
    paintRange(els.volume, state.volume * 100);
  }
  if (els.volumeButton) {
    const name = state.muted || state.volume === 0 ? "volume-mute" : state.volume < 0.45 ? "volume-low" : "volume";
    els.volumeButton.innerHTML = icon(name);
    els.volumeButton.setAttribute("aria-label", state.muted ? "Activar sonido" : "Silenciar");
    els.volumeButton.setAttribute("aria-pressed", String(state.muted));
  }
};

const updatePlayerLike = () => {
  const track = currentTrack();
  const liked = track ? isLiked(track.id) : false;

  [els.playerLike, els.npLike].forEach((button) => {
    if (!button) return;
    button.disabled = !track;
    button.classList.toggle("is-liked", liked);
    button.setAttribute("aria-pressed", String(liked));
    button.setAttribute("aria-label", liked ? "Quitar de me gusta" : "Agregar a me gusta");
  });
};

const updateFacts = (track) => {
  if (!els.npFacts) return;
  const facts = [
    ["Artista", track.artist || "Desconocido"],
    ["Álbum", albumNameOf(track)],
    ["Género", track.genre || "—"],
    ["Duración", formatTime(track.duration)]
  ];
  els.npFacts.innerHTML = facts
    .map(([label, value]) => `<div class="fact"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`)
    .join("");
};

const updateHighlights = () => {
  $$("[data-track-row]").forEach((row) => {
    const id = Number(row.dataset.trackRow);
    const current = id === Number(state.currentTrackId);
    const playing = current && state.isPlaying;
    row.classList.toggle("is-current", current);
    row.classList.toggle("is-playing", playing);
    if (current) row.setAttribute("aria-current", "true");
    else row.removeAttribute("aria-current");
  });

  $$("[data-like-id]").forEach((button) => {
    const liked = isLiked(button.dataset.likeId);
    button.classList.toggle("is-liked", liked);
    button.setAttribute("aria-pressed", String(liked));
    button.setAttribute("aria-label", liked ? "Quitar de me gusta" : "Agregar a me gusta");
  });
};

const renderQueue = () => {
  if (!els.npQueue) return;

  if (!state.queue.length) {
    els.npQueue.innerHTML = `<li class="queue-empty">La cola está vacía. Elegí una canción para empezar.</li>`;
    if (els.npQueueCount) els.npQueueCount.textContent = "";
    return;
  }

  const start = Math.max(0, state.queueIndex);
  const indexes = [];
  for (let i = start; i < Math.min(state.queue.length, start + 6); i += 1) indexes.push(i);

  els.npQueue.innerHTML = indexes
    .map((queueIndex) => {
      const track = trackById(state.queue[queueIndex]);
      if (!track) return "";
      const current = queueIndex === state.queueIndex;
      return `<li class="queue-item ${current ? "is-current" : ""}">
        <button class="queue-item__button" data-action="play-queue" data-index="${queueIndex}" aria-label="Reproducir ${escapeHTML(track.title)}">
          <span class="queue-item__art">${coverHTML({ title: track.title, coverUrl: track.coverUrl })}</span>
          <span class="queue-item__info">
            <strong>${escapeHTML(track.title)}</strong>
            <small>${escapeHTML(track.artist || "Artista desconocido")}</small>
          </span>
          ${current
            ? `<span class="queue-item__now"><span class="eq eq--tiny ${state.isPlaying ? "is-running" : ""}" aria-hidden="true"><i></i><i></i><i></i></span>${state.isPlaying ? "Sonando" : "En pausa"}</span>`
            : `<span class="queue-item__time">${formatTime(track.duration)}</span>`}
        </button>
      </li>`;
    })
    .join("");

  if (els.npQueueCount) {
    const remaining = state.queue.length - state.queueIndex;
    els.npQueueCount.textContent = `${plural(remaining, "pista", "pistas")} en cola`;
  }
};

const updateNowPlaying = () => {
  const track = currentTrack();

  if (!track) {
    if (els.playerCover) {
      els.playerCover.innerHTML = `<span class="player__cover-empty">${icon("music")}</span>`;
    }
    if (els.playerTitle) {
      els.playerTitle.textContent = "Sin reproducción";
      els.playerTitle.removeAttribute("data-id");
    }
    if (els.playerArtist) els.playerArtist.textContent = "Subí tu primera canción";

    if (els.npCover) els.npCover.innerHTML = `<span class="np__cover-empty">${icon("music")}</span>`;
    if (els.npTitle) els.npTitle.textContent = "Nada sonando";
    if (els.npArtist) els.npArtist.textContent = "Subí tu primera canción";
    if (els.npAlbum) {
      els.npAlbum.hidden = true;
      els.npAlbum.textContent = "";
      els.npAlbum.removeAttribute("data-id");
    }
    if (els.npEmpty) els.npEmpty.hidden = !state.ready || Boolean(state.tracks.length);
    if (els.npFacts) els.npFacts.innerHTML = "";
    if (els.npQueue) els.npQueue.innerHTML = `<li class="queue-empty">La cola está vacía. Elegí una canción para empezar.</li>`;
    if (els.npQueueCount) els.npQueueCount.textContent = "";
    document.title = "WaverNote — Tu música";
    updatePlayerLike();
    updateHighlights();
    updateProgressUI();
    updatePlayButton();
    updateShuffleUI();
    updateRepeatUI();
    syncMediaSessionState();
    return;
  }

  const album = albumByTrack(track);

  if (els.npEmpty) els.npEmpty.hidden = true;
  if (els.playerCover) els.playerCover.innerHTML = coverHTML(track);
  if (els.playerTitle) {
    els.playerTitle.textContent = track.title;
    els.playerTitle.dataset.id = album.id;
  }
  if (els.playerArtist) {
    els.playerArtist.textContent = `${track.artist || "Artista desconocido"} · ${albumNameOf(track)}`;
  }

  if (els.npCover) els.npCover.innerHTML = coverHTML(track);
  if (els.npTitle) els.npTitle.textContent = track.title;
  if (els.npArtist) els.npArtist.textContent = track.artist || "Artista desconocido";
  if (els.npAlbum) {
    els.npAlbum.hidden = false;
    els.npAlbum.textContent = albumNameOf(track);
    els.npAlbum.dataset.id = album.id;
  }

  updateFacts(track);
  updatePlayerLike();
  updateHighlights();
  renderQueue();
  updateProgressUI();
  updatePlayButton();
  updateShuffleUI();
  updateRepeatUI();

  document.title = `${track.title} · ${track.artist || "WaverNote"}`;
  syncMediaSession();
};

const startQueue = (ids, options = {}) => {
  let queue = (ids || []).map(Number).filter((id) => state.trackById.has(id));
  if (!queue.length) {
    toast("Tu biblioteca está vacía. Subí una canción para empezar.", "error");
    return;
  }

  let index = clamp(Number(options.startIndex) || 0, 0, queue.length - 1);
  if (options.randomStart) index = Math.floor(Math.random() * queue.length);

  const shuffle = options.shuffle ?? state.shuffle;
  if (shuffle) {
    const first = queue[index];
    const rest = queue.filter((id) => id !== first);
    shuffleArray(rest);
    queue = [first, ...rest];
    index = 0;
  }

  state.shuffle = Boolean(shuffle);
  state.baseQueue = null;
  state.queue = queue;
  state.queueIndex = index;
  playCurrent();
};

const playCurrent = () => {
  const id = state.queue[state.queueIndex];
  const track = trackById(id);
  if (!track) return;

  engine.stop();
  state.currentTrackId = track.id;
  pendingPlayId = track.id;
  state.duration = Number(track.duration) || 0;
  state.currentTime = 0;
  state.isPlaying = true;
  state.ending = false;

  rememberTrack(track.id);
  updateNowPlaying();
  updateShuffleUI();
  syncMediaSessionState();

  engine
    .start(track, 0)
    .then((ok) => {
      if (ok) {
        flushPendingPlay();
      } else {
        state.isPlaying = false;
        updatePlayButton();
        updateHighlights();
        renderQueue();
        toast("El navegador no pudo iniciar el audio. Probá de nuevo con un clic.", "error");
      }
      syncMediaSessionState();
    })
    .catch(() => {
      state.isPlaying = false;
      updatePlayButton();
      updateHighlights();
    });
};

const togglePlay = () => {
  const track = currentTrack();

  if (!track) {
    if (state.tracks.length) {
      startQueue(state.tracks.map((item) => item.id), { startIndex: 0 });
    } else {
      toast("Subí tu primera canción para reproducir algo.");
    }
    return;
  }

  if (state.isPlaying) {
    state.currentTime = clamp(engine.getTime(), 0, state.duration);
    engine.pause();
    state.isPlaying = false;
    updatePlayButton();
    updateHighlights();
    updateProgressUI();
    renderQueue();
    syncMediaSessionState();
    return;
  }

  if (state.duration && state.currentTime >= state.duration - 0.35) state.currentTime = 0;
  state.isPlaying = true;
  updatePlayButton();
  updateHighlights();
  renderQueue();
  syncMediaSessionState();

  engine
    .start(track, state.currentTime)
    .then((ok) => {
      if (ok) {
        flushPendingPlay();
      } else {
        state.isPlaying = false;
        updatePlayButton();
        updateHighlights();
        renderQueue();
        toast("No se pudo reanudar el audio. Probá de nuevo.", "error");
      }
      syncMediaSessionState();
    })
    .catch(() => {});
};

const seekTo = (seconds) => {
  if (!currentTrack()) return;
  state.currentTime = clamp(Number(seconds) || 0, 0, state.duration);
  engine.seek(state.currentTime);
  updateProgressUI();
  syncMediaSessionState();
};

const handleTrackEnd = () => {
  if (state.ending) return;
  state.ending = true;

  if (state.repeat === "one") {
    playCurrent();
  } else if (state.queueIndex < state.queue.length - 1) {
    state.queueIndex += 1;
    playCurrent();
  } else if (state.repeat === "all") {
    state.queueIndex = 0;
    playCurrent();
  } else {
    engine.stop();
    state.isPlaying = false;
    state.currentTime = state.duration;
    updatePlayButton();
    updateHighlights();
    updateProgressUI();
    renderQueue();
    syncMediaSessionState();
  }

  window.setTimeout(() => {
    state.ending = false;
  }, 320);
};

const nextTrack = () => {
  if (!state.queue.length) {
    toast("La cola está vacía.");
    return;
  }
  if (state.queueIndex < state.queue.length - 1) {
    state.queueIndex += 1;
    playCurrent();
  } else if (state.repeat === "all") {
    state.queueIndex = 0;
    playCurrent();
  } else {
    engine.stop();
    state.isPlaying = false;
    state.currentTime = state.duration;
    updatePlayButton();
    updateHighlights();
    updateProgressUI();
    renderQueue();
    syncMediaSessionState();
  }
};

const previousTrack = () => {
  if (state.currentTime > 4) {
    seekTo(0);
    return;
  }
  if (state.queueIndex > 0) {
    state.queueIndex -= 1;
    playCurrent();
  } else if (state.repeat === "all" && state.queue.length) {
    state.queueIndex = state.queue.length - 1;
    playCurrent();
  } else {
    seekTo(0);
  }
};

const toggleShuffle = () => {
  const currentId = state.currentTrackId;
  if (!state.shuffle) {
    state.shuffle = true;
    state.baseQueue = state.queue.slice();
    state.baseIndex = state.queueIndex;
    const rest = state.queue.filter((id) => id !== currentId);
    shuffleArray(rest);
    state.queue = currentId ? [currentId, ...rest] : rest;
    state.queueIndex = 0;
    toast("Aleatorio activado");
  } else {
    state.shuffle = false;
    if (state.baseQueue && state.baseQueue.includes(currentId)) {
      state.queue = state.baseQueue.slice();
      state.queueIndex = Math.max(0, state.queue.indexOf(currentId));
    }
    state.baseQueue = null;
    toast("Aleatorio desactivado");
  }
  updateShuffleUI();
  renderQueue();
};

const cycleRepeat = () => {
  const order = ["off", "all", "one"];
  state.repeat = order[(order.indexOf(state.repeat) + 1) % order.length];
  const labels = {
    off: "Repetición desactivada",
    all: "Se repite toda la cola",
    one: "Se repite esta canción"
  };
  updateRepeatUI();
  toast(labels[state.repeat]);
};

const toggleLike = async (id) => {
  const track = trackById(id ?? state.currentTrackId);
  if (!track) {
    toast("Elegí una canción primero.");
    return;
  }

  const wasLiked = isLiked(track.id);
  if (wasLiked) state.liked.delete(track.id);
  else state.liked.add(track.id);

  updateHighlights();
  updatePlayerLike();
  if (state.route.view === "library" && state.libraryTab === "songs") renderView({ resetScroll: false });

  try {
    await api(`/wavernote/tracks/${track.id}/like`, { method: wasLiked ? "DELETE" : "POST" });
    toast(wasLiked ? "Quitado de Me gusta" : "Guardado en Me gusta");
  } catch (err) {
    if (wasLiked) state.liked.add(track.id);
    else state.liked.delete(track.id);
    updateHighlights();
    updatePlayerLike();
    if (state.route.view === "library" && state.libraryTab === "songs") renderView({ resetScroll: false });
    toast(err.message || "No se pudo guardar el favorito.", "error");
  }
};

const setVolume = (value) => {
  state.volume = clamp(Number(value) || 0, 0, 1);
  if (state.volume > 0) state.muted = false;
  engine.setVolume(state.volume);
  engine.setMuted(state.muted);
  saveVolume();
  updateVolumeUI();
};

const toggleMute = () => {
  state.muted = !state.muted;
  engine.setMuted(state.muted);
  updateVolumeUI();
};

const addToQueue = (id) => {
  const track = trackById(id);
  if (!track) return;

  if (!state.queue.length) {
    state.queue = [track.id];
    state.queueIndex = 0;
    state.currentTrackId = track.id;
    state.duration = Number(track.duration) || 0;
    state.currentTime = 0;
    state.isPlaying = false;
    updateNowPlaying();
    toast(`«${track.title}» quedó lista en la cola`);
    return;
  }

  if (state.queue.includes(track.id)) {
    toast("Esa canción ya está en la cola");
    return;
  }

  state.queue.push(track.id);
  renderQueue();
  toast(`«${track.title}» se sumó a la cola`);
};

const queueCollection = (ids, label) => {
  const fresh = (ids || []).map(Number).filter((id) => state.trackById.has(id) && !state.queue.includes(id));
  if (!fresh.length) {
    toast("Ya estaba todo en la cola");
    return;
  }
  state.queue.push(...fresh);
  renderQueue();
  toast(`${label}: ${plural(fresh.length, "pista agregada", "pistas agregadas")} a la cola`);
};

/* ------------------------------------------------------------
   Media Session
   ------------------------------------------------------------ */

const syncMediaSession = () => {
  if (!("mediaSession" in navigator)) return;
  const track = currentTrack();
  if (!track) return;

  try {
    if (typeof MediaMetadata === "function") {
      const artwork = track.coverUrl ? [{ src: track.coverUrl }] : [];
      navigator.mediaSession.metadata = new MediaMetadata({
        title: track.title,
        artist: track.artist || "WaverNote",
        album: albumNameOf(track),
        artwork
      });
    }
  } catch (err) {
    /* el navegador puede no soportar metadata */
  }
  syncMediaSessionState();
};

const syncMediaSessionState = () => {
  if (!("mediaSession" in navigator)) return;
  try {
    navigator.mediaSession.playbackState = state.isPlaying ? "playing" : "paused";
    if (typeof navigator.mediaSession.setPositionState === "function" && state.duration > 0) {
      navigator.mediaSession.setPositionState({
        duration: state.duration,
        playbackRate: 1,
        position: clamp(state.currentTime, 0, state.duration)
      });
    }
  } catch (err) {
    /* posición fuera de rango en algunos navegadores */
  }
};

const setupMediaSession = () => {
  if (!("mediaSession" in navigator)) return;
  const handlers = {
    play: () => {
      if (!state.isPlaying) togglePlay();
    },
    pause: () => {
      if (state.isPlaying) togglePlay();
    },
    previoustrack: previousTrack,
    nexttrack: nextTrack,
    seekbackward: (details) => seekTo(state.currentTime - (details?.seekOffset || 5)),
    seekforward: (details) => seekTo(state.currentTime + (details?.seekOffset || 5)),
    seekto: (details) => {
      if (typeof details?.seekTime === "number") seekTo(details.seekTime);
    }
  };
  Object.entries(handlers).forEach(([action, handler]) => {
    try {
      navigator.mediaSession.setActionHandler(action, handler);
    } catch (err) {
      /* acción no soportada */
    }
  });
};

/* ------------------------------------------------------------
   Visualizador
   ------------------------------------------------------------ */

let vizCanvas = null;
let vizContext = null;
let vizBars = new Array(36).fill(0);

const roundedBar = (ctx, x, y, width, height, radius) => {
  const r = Math.min(radius, width / 2, height / 2);
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + width, y, x + width, y + height, r);
  ctx.arcTo(x + width, y + height, x, y + height, r);
  ctx.arcTo(x, y + height, x, y, r);
  ctx.arcTo(x, y, x + width, y, r);
  ctx.closePath();
};

const drawVisualizer = (now) => {
  const canvas = $("#viz");
  if (!canvas) return;
  if (canvas !== vizCanvas) {
    vizCanvas = canvas;
    vizContext = canvas.getContext("2d");
    vizBars = new Array(36).fill(0);
  }
  if (!vizContext) return;

  const rect = canvas.getBoundingClientRect();
  if (rect.width < 2 || rect.height < 2) return;

  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const width = Math.round(rect.width * dpr);
  const height = Math.round(rect.height * dpr);
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }

  const ctx = vizContext;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, rect.width, rect.height);

  const levels = engine.getLevels();
  const count = vizBars.length;
  const gap = 3;
  const barWidth = Math.max(1, (rect.width - gap * (count - 1)) / count);
  const time = now / 1000;
  const activeBins = 15;
  let energy = 0;
  if (levels) {
    const bins = Math.min(activeBins, levels.length);
    for (let j = 0; j < bins; j += 1) energy += levels[j] / 255;
    energy /= bins;
  }

  const gradient = ctx.createLinearGradient(0, rect.height, 0, 0);
  gradient.addColorStop(0, "rgba(99, 230, 200, 0.32)");
  gradient.addColorStop(0.55, "rgba(99, 230, 200, 0.85)");
  gradient.addColorStop(1, "rgba(122, 167, 255, 0.95)");
  ctx.fillStyle = gradient;

  for (let i = 0; i < count; i += 1) {
    let target;
    if (state.isPlaying && levels) {
      const bin = Math.min(levels.length - 1, Math.floor((i / (count - 1)) * (activeBins - 1)));
      const spec = Math.pow((levels[bin] || 0) / 255, 1.2);
      const sway = 0.72 + 0.28 * Math.abs(Math.sin(time * 1.6 + i * 0.5));
      const shimmer = Math.abs(Math.sin(time * 1.4 + i * 0.45)) * 0.06;
      target = Math.min(1, 0.06 + energy * 0.3 + spec * sway * 1.7 + shimmer);
    } else if (state.isPlaying) {
      target = 0.12 + Math.abs(Math.sin(time * 1.5 + i * 0.55)) * 0.16;
    } else {
      target = 0.025 + Math.abs(Math.sin(time * 0.8 + i * 0.42)) * 0.03;
    }

    vizBars[i] += (target - vizBars[i]) * 0.16;
    const barHeight = Math.max(2, vizBars[i] * (rect.height - 5));
    const x = i * (barWidth + gap);
    const y = rect.height - barHeight;
    roundedBar(ctx, x, y, barWidth, barHeight, barWidth / 2);
    ctx.fill();
  }
};

let uiLoopStarted = false;

const startUiLoop = () => {
  if (uiLoopStarted) return;
  uiLoopStarted = true;

  const frame = (now) => {
    if (state.isPlaying && !state.seeking && state.duration > 0) {
      const time = engine.getTime();
      if (time >= state.duration - 0.12) {
        handleTrackEnd();
      } else {
        state.currentTime = clamp(time, 0, state.duration);
        updateProgressUI();
      }
    }
    drawVisualizer(now);
    requestAnimationFrame(frame);
  };

  requestAnimationFrame(frame);
};
