/* ============================================================
   WaverNote · reproductor
   Cola, transporte real, sincronización de interfaz y visualizador.
   ============================================================ */

const engine = new WaveEngine();

const els = {
  app: $("#app"),
  player: document.querySelector("footer.player"),
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
  npQueueCount: $("#npQueueCount"),
  npQueueHint: $("#npQueueHint"),
  npTabCount: $("#npTabCount"),
  npPlay: $("#npPlayBtn"),
  npShuffle: $("#npShuffleBtn"),
  npRepeat: $("#npRepeatBtn"),
  npSeek: $("#npSeek"),
  npCurrent: $("#npCurTime"),
  npDuration: $("#npDurTime"),
  quickPlayer: $("#quickPlayer"),
  quickCover: $("#quickCover"),
  quickTitle: $("#quickTitle"),
  quickArtist: $("#quickArtist"),
  quickSeek: $("#quickSeek"),
  quickCurrent: $("#quickCurTime"),
  quickDuration: $("#quickDurTime")
};

const currentTrack = () => trackById(state.currentTrackId);

// La cola conserva lo ya reproducido detrás de queueIndex para poder volver
// atrás. Eso es historial, no canciones en espera: no debe figurar como «En
// la cola» ni bloquear que se vuelva a agregar.
const queueIndexOf = (id) => state.queue.findIndex((trackId) => Number(trackId) === Number(id));

const isQueuedTrack = (id) => {
  const index = queueIndexOf(id);
  return index >= 0 && state.queueIndex >= 0 && index >= state.queueIndex;
};

const queueUpcomingCount = () => Math.max(0, state.queue.length - state.queueIndex - 1);

let pendingPlayId = null;
let libraryRefreshScheduled = false;

// La cola, la posición y las preferencias se guardan en la cuenta: desde
// cualquier otro dispositivo la sesión se retoma donde quedó.
const syncPlaybackState = () => {
  if (typeof persistPlaybackLocal === "function") persistPlaybackLocal();
  if (typeof persistPlaybackPosition === "function") persistPlaybackPosition();
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("playback");
};

const syncSettingsState = () => {
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

// Recontar la biblioteca entera en el instante en que arranca la canción
// trababa la app (se rehacía la vista de la lista en medio del play). Ahora
// el re-render se corre para cuando el hilo principal está libre.
const scheduleLibraryRefresh = () => {
  if (libraryRefreshScheduled) return;
  libraryRefreshScheduled = true;
  const run = () => {
    libraryRefreshScheduled = false;
    if (state.route.view === "library" && state.libraryTab === "most-played") {
      renderView({ resetScroll: false });
    }
  };
  if (typeof window.requestIdleCallback === "function") {
    window.requestIdleCallback(run, { timeout: 1500 });
  } else {
    window.setTimeout(run, 400);
  }
};

const mostPlayedTotals = () => {
  let top = 0;
  let total = 0;
  let played = 0;
  state.tracks.forEach((item) => {
    const count = playStatsOf(item).count;
    total += count;
    if (count > 0) played += 1;
    if (count > top) top = count;
  });
  return { top, total, played };
};

// En el ranking alcanza con actualizar la tarjeta de la canción que arrancó:
// reordenar las 700 tarjetas en cada cambio era otro de los bloqueos.
const refreshMostPlayedCard = (trackId) => {
  if (state.route.view !== "library" || state.libraryTab !== "most-played") return;

  const card = document.querySelector(`[data-plays-card="${Number(trackId)}"]`);
  if (!card) {
    // El ranking todavía no tenía tarjetas (primer play de la biblioteca).
    scheduleLibraryRefresh();
    return;
  }

  const track = trackById(trackId);
  if (!track) return;

  const stats = playStatsOf(track);
  const totals = mostPlayedTotals();
  const share = totals.top > 0 ? Math.round((stats.count / totals.top) * 100) : 0;

  const previousCurrent = document.querySelector("[data-plays-card].is-current");
  if (previousCurrent && previousCurrent !== card) {
    previousCurrent.classList.remove("is-current");
    previousCurrent.querySelector(".plays-card__now")?.remove();
  }
  card.classList.add("is-current");
  card.classList.remove("is-unplayed");

  // La etiqueta «Sonando» viaja con la canción actual sin rehacer la grilla.
  let nowBadge = card.querySelector(".plays-card__now");
  if (!nowBadge) {
    const art = card.querySelector(".plays-card__art");
    if (art) {
      nowBadge = document.createElement("span");
      nowBadge.className = "plays-card__now";
      nowBadge.innerHTML = `<span class="eq is-running" aria-hidden="true"><i></i><i></i><i></i></span><span>Sonando</span>`;
      art.appendChild(nowBadge);
    }
  } else {
    nowBadge.querySelector(".eq")?.classList.toggle("is-running", state.isPlaying);
    const label = nowBadge.lastElementChild;
    if (label) label.textContent = state.isPlaying ? "Sonando" : "En pausa";
  }
  const countEl = card.querySelector(".plays-card__count");
  if (countEl) countEl.textContent = plural(stats.count, "reproducción", "reproducciones");
  const shareEl = card.querySelector(".plays-card__share");
  if (shareEl) shareEl.textContent = `${share}%`;
  const meterEl = card.querySelector(".plays-card__meter > span");
  if (meterEl) meterEl.style.width = `${Math.max(share, 4)}%`;
  const sinceEl = card.querySelector(".plays-card__since");
  if (sinceEl) {
    sinceEl.textContent = track.createdAt ? `Agregada el ${dateLabel(track.createdAt)}` : "En tu ranking";
  }

  const totalEl = document.querySelector("[data-plays-total]");
  if (totalEl) totalEl.textContent = totals.total;
  const rankedEl = document.querySelector("[data-plays-ranked]");
  if (rankedEl) rankedEl.textContent = totals.played;
  const footEl = document.querySelector("[data-plays-foot-total]");
  if (footEl) footEl.textContent = plural(totals.total, "reproducción", "reproducciones");
};

const flushPendingPlay = () => {
  if (!pendingPlayId) return;
  const trackId = pendingPlayId;
  pendingPlayId = null;
  recordPlay(trackId);
  // Si el usuario está mirando el ranking, reflejamos el nuevo conteo al instante.
  refreshMostPlayedCard(trackId);
};

// La siguiente canción se va descargando en segundo plano: cuando llega el
// turno arranca al toque en vez de quedarse cargando.
const prefetchNext = () => {
  if (!state.queue.length) {
    engine.prefetch("");
    return;
  }
  let nextIndex = state.queueIndex + 1;
  if (nextIndex >= state.queue.length) {
    nextIndex = state.repeat === "all" ? 0 : -1;
  }
  const next = nextIndex >= 0 ? trackById(state.queue[nextIndex]) : null;
  engine.prefetch(next);
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
engine.onBuffering = (buffering) => {
  state.isBuffering = Boolean(buffering);
  updateBufferingUI();
};

// La barra de progreso y el reloj no necesitan 60 cuadros por segundo:
// refrescarlos en cada cuadro pesa el hilo principal y la app se traba
// justo cuando está sonando la canción.
const PROGRESS_INTERVAL_MS = 100;
// La posición también se guarda en el teléfono cada segundo, en una clave
// chica aparte. Así un cierre forzado de Android no depende de que llegue a
// ejecutarse pagehide y solo puede perder menos de un segundo.
const PLAYBACK_POSITION_SAVE_MS = 1000;
// Recalcular el tamaño del canvas obliga al navegador a recalcular el
// layout: una vez por segundo alcanza y evita el jank de cada cuadro.
const VIZ_MEASURE_INTERVAL_MS = 1000;
let lastProgressPaint = 0;
let vizRect = null;
let vizMeasuredAt = 0;

/* ------------------------------------------------------------
   Transporte
   ------------------------------------------------------------ */

const paintRange = (input, percent) => {
  if (!input) return;
  const safe = clamp(percent, 0, 100);
  input.style.setProperty("--fill", `${safe}%`);
};

const updateProgressUI = () => {
  if (state.seeking) return;
  const ratio = state.duration ? clamp(state.currentTime / state.duration, 0, 1) : 0;
  if (els.seek) {
    els.seek.value = String(Math.round(ratio * 1000));
    paintRange(els.seek, ratio * 100);
  }
  if (els.npSeek) {
    els.npSeek.value = String(Math.round(ratio * 1000));
    paintRange(els.npSeek, ratio * 100);
  }
  if (els.quickSeek) {
    els.quickSeek.value = String(Math.round(ratio * 1000));
    paintRange(els.quickSeek, ratio * 100);
  }
  document.documentElement.style.setProperty("--mobile-progress", `${ratio * 100}%`);
  if (els.current) els.current.textContent = formatTime(state.currentTime);
  if (els.duration) els.duration.textContent = formatTime(state.duration);
  if (els.npCurrent) els.npCurrent.textContent = formatTime(state.currentTime);
  if (els.npDuration) els.npDuration.textContent = formatTime(state.duration);
  if (els.quickCurrent) els.quickCurrent.textContent = formatTime(state.currentTime);
  if (els.quickDuration) els.quickDuration.textContent = formatTime(state.duration);
};

// Mientras el archivo se está descargando la app lo avisa en vez de quedar
// muda: sin esto parecía que la canción se trababa.
const updateBufferingUI = () => {
  const buffering = Boolean(state.isBuffering);
  els.player?.classList.toggle("is-buffering", buffering);

  [els.play, els.npPlay].forEach((play) => {
    if (!play) return;
    play.classList.toggle("is-loading", buffering);
    play.setAttribute("aria-busy", buffering ? "true" : "false");
  });

  const artist = els.playerArtist;
  if (!artist) return;
  if (buffering) {
    artist.dataset.buffering = "1";
    artist.textContent = "Cargando…";
    return;
  }
  if (artist.dataset.buffering !== "1") return;
  delete artist.dataset.buffering;
  const track = currentTrack();
  artist.textContent = track
    ? `${track.artist || "Artista desconocido"} · ${albumNameOf(track)}`
    : "Subí tu primera canción";
};

// En Android la pantalla se apaga sola mientras suena la música. Mientras
// haya reproducción activa pedimos un Wake Lock para que no se corte el
// gesto ni la lectura de la portada; se libera al pausar o salir de la app.
let screenWakeLock = null;
let wakeLockPending = false;

const releaseScreenWakeLock = async () => {
  const lock = screenWakeLock;
  screenWakeLock = null;
  if (!lock) return;
  try {
    await lock.release();
  } catch (err) {
    /* el sistema ya lo liberó */
  }
};

const syncScreenWakeLock = () => {
  if (!("wakeLock" in navigator) || typeof navigator.wakeLock?.request !== "function") return;
  const shouldHold = state.isPlaying && !document.hidden;
  if (!shouldHold) {
    releaseScreenWakeLock();
    return;
  }
  if (screenWakeLock || wakeLockPending) return;

  wakeLockPending = true;
  navigator.wakeLock
    .request("screen")
    .then((lock) => {
      if (!state.isPlaying || document.hidden) {
        lock.release?.().catch(() => {});
        return;
      }
      screenWakeLock = lock;
      lock.addEventListener?.("release", () => {
        if (screenWakeLock === lock) screenWakeLock = null;
      });
    })
    .catch(() => {
      /* el navegador puede negarlo si no hay gesto reciente */
    })
    .finally(() => {
      wakeLockPending = false;
    });
};

document.addEventListener("visibilitychange", () => {
  if (document.hidden) releaseScreenWakeLock();
  else syncScreenWakeLock();
});

const updatePlayButton = () => {
  [els.play, els.npPlay].forEach((button) => {
    if (!button) return;
    button.innerHTML = state.isPlaying ? icon("pause", "icon--fill") : icon("play", "icon--fill");
    button.setAttribute("aria-label", state.isPlaying ? "Pausar" : "Reproducir");
  });
  els.app?.classList.toggle("is-playing", state.isPlaying);
  syncScreenWakeLock();
};

const updateShuffleUI = () => {
  [els.shuffle, els.npShuffle].forEach((button) => {
    if (!button) return;
    button.classList.toggle("is-active", state.shuffle);
    button.setAttribute("aria-pressed", String(state.shuffle));
    button.setAttribute("aria-label", state.shuffle ? "Desactivar aleatorio" : "Activar aleatorio");
  });
};

const updateRepeatUI = () => {
  const labels = { off: "Activar repetición", all: "Repetir toda la cola", one: "Repetir esta canción" };
  [els.repeat, els.npRepeat].forEach((button) => {
    if (!button) return;
    button.classList.toggle("is-active", state.repeat !== "off");
    button.innerHTML = state.repeat === "one" ? icon("repeat-one") : icon("repeat");
    button.setAttribute("aria-label", labels[state.repeat]);
    button.setAttribute("aria-pressed", String(state.repeat !== "off"));
    button.dataset.repeat = state.repeat;
  });
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

  // El acceso rápido a la cola vive en la vista de inicio y no se vuelve a
  // dibujar con cada cambio de pista: sincronizamos su estado acá para que
  // una canción ya sonada recupere el botón de agregar.
  $$('[data-action="quick-listen-queue"]').forEach((button) => {
    const queued = isQueuedTrack(button.dataset.id);
    button.disabled = queued;
    button.innerHTML = queued ? icon("check") : icon("plus");
    button.setAttribute("aria-label", queued ? "Ya está en la cola" : "Agregar a la cola");
  });
};

/* ------------------------------------------------------------
   Cola: lista de espera reordenable
   ------------------------------------------------------------ */

let queueDrag = null;

// Una cola de cientos de canciones no se puede volcar entera en el DOM cada
// vez que cambia el tema: eso es lo que trababa la app justo en el autoavance.
// Se dibuja un primer tramo y el resto se suma cuando la lista se acerca al
// final, o cuando se toca «Ver más».
const QUEUE_INITIAL_ITEMS = 36;
const QUEUE_CHUNK_ITEMS = 60;

let queueRendered = 0;
let queueRenderIndex = -1;
let queueRenderLength = 0;
let queueObserver = null;
let queueAdvanceFrom = -1;

const queueUpcomingEntries = () => {
  const entries = [];
  for (let index = Math.max(0, state.queueIndex + 1); index < state.queue.length; index += 1) {
    const track = trackById(state.queue[index]);
    if (track) entries.push({ track, index });
  }
  return entries;
};

const queueCurrentHTML = (track) => `<li class="queue-item queue-item--current is-current" data-queue-current>
    <span class="queue-item__art">${coverHTML({ id: track.id, title: track.title, coverUrl: track.coverUrl })}</span>
    <span class="queue-item__info">
      <strong>${escapeHTML(track.title)}</strong>
      <small>${escapeHTML(track.artist || "Artista desconocido")}</small>
    </span>
    <span class="queue-item__now">
      <span class="eq eq--tiny ${state.isPlaying ? "is-running" : ""}" aria-hidden="true"><i></i><i></i><i></i></span>
      ${state.isPlaying ? "Sonando" : "En pausa"}
    </span>
  </li>`;

const queueItemHTML = ({ track: item }) => `<li class="queue-item" data-queue-id="${item.id}">
    <button class="queue-item__button" data-action="play-queue" data-id="${item.id}" aria-label="Reproducir ${escapeHTML(item.title)}">
      <span class="queue-item__art">${coverHTML({ id: item.id, title: item.title, coverUrl: item.coverUrl })}</span>
      <span class="queue-item__info">
        <strong>${escapeHTML(item.title)}</strong>
        <small>${escapeHTML(item.artist || "Artista desconocido")}</small>
      </span>
      <span class="queue-item__time">${formatTime(item.duration)}</span>
    </button>
    <span class="queue-item__actions">
      <button class="queue-item__action" type="button" data-action="queue-move-top" data-id="${item.id}" aria-label="Mover «${escapeHTML(item.title)}» al inicio de la cola" title="Que suene primero">
        ${icon("chevron-up")}
      </button>
      <button class="queue-item__action queue-item__action--remove" type="button" data-action="queue-remove" data-id="${item.id}" aria-label="Quitar «${escapeHTML(item.title)}» de la cola" title="Quitar de la cola">
        ${icon("x")}
      </button>
      <button class="queue-item__drag" type="button" data-queue-drag aria-label="Arrastrar «${escapeHTML(item.title)}» para reordenar la cola" title="Arrastrar para reordenar">
        ${icon("grip")}
      </button>
    </span>
  </li>`;

const queueMoreHTML = (shown, total) => `<li class="queue-more" data-queue-more>
    <span data-queue-more-label>${shown} de ${total} en la cola</span>
    <button class="btn btn--small btn--soft" type="button" data-action="queue-more">Ver más</button>
  </li>`;

const queueEmptyHTML = (track) => `<li class="queue-empty">${
  track
    ? "No hay más canciones en espera. Elegí otra desde tu biblioteca."
    : "La cola está vacía. Elegí una canción para empezar."
}</li>`;

const updateQueueSummary = (remaining) => {
  if (els.npQueueCount) {
    els.npQueueCount.textContent = remaining
      ? `${plural(remaining, "pista", "pistas")} en espera`
      : "Sin canciones en espera";
  }
  if (els.npTabCount) {
    els.npTabCount.textContent = remaining ? String(remaining) : "";
    els.npTabCount.hidden = !remaining;
  }
  if (els.npQueueHint) els.npQueueHint.hidden = remaining < 2;
};

const disconnectQueueObserver = () => {
  if (!queueObserver) return;
  queueObserver.disconnect();
  queueObserver = null;
};

const refreshQueueMoreLabel = (remaining) => {
  const sentinel = els.npQueue?.querySelector("[data-queue-more]");
  if (!sentinel || !remaining) return;
  const label = sentinel.querySelector("[data-queue-more-label]");
  if (label) label.textContent = `${queueRendered} de ${remaining} en la cola`;
};

const appendQueueChunk = () => {
  const list = els.npQueue;
  if (!list) return;
  const sentinel = list.querySelector("[data-queue-more]");
  if (!sentinel) return;

  const entries = queueUpcomingEntries();
  if (queueRendered >= entries.length) {
    sentinel.remove();
    disconnectQueueObserver();
    return;
  }

  const chunk = entries.slice(queueRendered, queueRendered + QUEUE_CHUNK_ITEMS);
  const template = document.createElement("template");
  template.innerHTML = chunk.map(queueItemHTML).join("");
  list.insertBefore(template.content, sentinel);
  queueRendered += chunk.length;

  if (queueRendered >= entries.length) {
    sentinel.remove();
    disconnectQueueObserver();
    return;
  }
  refreshQueueMoreLabel(entries.length);
};

const observeQueueMore = () => {
  disconnectQueueObserver();
  if (!("IntersectionObserver" in window) || !els.npQueue) return;
  const sentinel = els.npQueue.querySelector("[data-queue-more]");
  if (!sentinel) return;
  queueObserver = new IntersectionObserver(
    (entries) => {
      if (entries.some((entry) => entry.isIntersecting)) appendQueueChunk();
    },
    { rootMargin: "700px 0px" }
  );
  queueObserver.observe(sentinel);
};

// El autoavance es el caso más frecuente: en vez de rehacer la cola entera,
// se convierte la primera tarjeta en la canción actual y se descarta la
// anterior. O(1) en lugar de recorrer cientos de nodos.
const tryPatchQueueAdvance = (fromIndex) => {
  const list = els.npQueue;
  if (!list || queueDrag) return false;
  if (queueRenderIndex !== fromIndex || state.queueIndex !== fromIndex + 1) return false;
  if (queueRenderLength !== state.queue.length) return false;

  const track = currentTrack();
  if (!track) return false;
  const currentEl = list.querySelector("[data-queue-current]");
  const firstUpcoming = list.querySelector("[data-queue-id]");
  if (!currentEl || !firstUpcoming) return false;
  if (Number(firstUpcoming.dataset.queueId) !== Number(track.id)) return false;

  const template = document.createElement("template");
  template.innerHTML = queueCurrentHTML(track);
  const nextCurrent = template.content.firstElementChild;
  if (!nextCurrent) return false;

  firstUpcoming.replaceWith(nextCurrent);
  currentEl.remove();

  queueRendered = Math.max(0, queueRendered - 1);
  queueRenderIndex = state.queueIndex;
  updateQueueSummary(state.queue.length - state.queueIndex - 1);
  refreshQueueMoreLabel(state.queue.length - state.queueIndex - 1);
  return true;
};

const renderQueue = () => {
  if (!els.npQueue) return;
  // Mientras se arrastra una tarjeta el DOM es la fuente del orden: no lo
  // pisamos con un re-render que cortaría el gesto a mitad de camino.
  if (queueDrag) return;

  if (queueAdvanceFrom >= 0) {
    const from = queueAdvanceFrom;
    queueAdvanceFrom = -1;
    if (tryPatchQueueAdvance(from)) return;
  }

  disconnectQueueObserver();

  const track = currentTrack();
  const upcoming = queueUpcomingEntries();
  queueRenderIndex = state.queueIndex;
  queueRenderLength = state.queue.length;
  queueRendered = 0;

  let html = track ? queueCurrentHTML(track) : "";
  if (!upcoming.length) {
    els.npQueue.innerHTML = html + queueEmptyHTML(track);
    updateQueueSummary(0);
    return;
  }

  const chunk = upcoming.slice(0, QUEUE_INITIAL_ITEMS);
  html += chunk.map(queueItemHTML).join("");
  queueRendered = chunk.length;
  if (upcoming.length > chunk.length) html += queueMoreHTML(chunk.length, upcoming.length);
  els.npQueue.innerHTML = html;

  updateQueueSummary(upcoming.length);
  if (upcoming.length > queueRendered) observeQueueMore();
};

const applyQueueOrder = (upcomingIds, consumedCount) => {
  const ids = (upcomingIds || []).map(Number).filter((id) => state.trackById.has(id));
  const headEnd = Math.max(0, state.queueIndex + 1);
  const head = state.queue.slice(0, headEnd);
  // Solo se reordena el tramo que está dibujado: el resto de la cola (todavía
  // sin renderizar) se conserva tal cual detrás.
  const consumed = clamp(
    Number.isFinite(consumedCount) ? consumedCount : ids.length,
    0,
    Math.max(0, state.queue.length - headEnd)
  );
  const tail = state.queue.slice(headEnd + consumed);
  state.queue = [...head, ...ids, ...tail];

  if (state.shuffle) {
    state.shuffle = false;
    state.baseQueue = null;
    updateShuffleUI();
  }

  prefetchNext();
  renderQueue();
  syncPlaybackState();
};

const removeQueueItem = (id) => {
  const trackId = Number(id);
  const index = state.queue.indexOf(trackId);
  if (index < 0) {
    toast("Esa canción ya no está en la cola.");
    return;
  }
  if (index <= state.queueIndex) {
    toast("La canción que está sonando no se puede quitar desde la cola.", "error");
    return;
  }

  const track = trackById(trackId);
  state.queue.splice(index, 1);
  if (state.baseQueue) state.baseQueue = state.baseQueue.filter((item) => Number(item) !== trackId);

  prefetchNext();
  renderQueue();
  syncPlaybackState();
  toast(track ? `«${track.title}» salió de la cola` : "Canción quitada de la cola");
};

const moveQueueItemToTop = (id) => {
  const trackId = Number(id);
  const index = state.queue.indexOf(trackId);
  if (index < 0 || index <= state.queueIndex) return;

  if (index === state.queueIndex + 1) {
    toast("Esa canción ya suena a continuación.");
    return;
  }

  const track = trackById(trackId);
  state.queue.splice(index, 1);
  state.queue.splice(state.queueIndex + 1, 0, trackId);

  if (state.shuffle) {
    state.shuffle = false;
    state.baseQueue = null;
    updateShuffleUI();
  }

  prefetchNext();
  renderQueue();
  syncPlaybackState();
  toast(track ? `«${track.title}» suena a continuación` : "Cola actualizada");
};

const findQueueScrollBox = (node) => {
  let current = node;
  while (current && current !== document.body) {
    // La propia lista puede ser el contenedor con scroll (p. ej. en móvil).
    const style = window.getComputedStyle(current);
    if (/(auto|scroll)/.test(style.overflowY) && current.scrollHeight > current.clientHeight + 1) return current;
    current = current.parentElement;
  }
  return null;
};

const updateQueueDragTarget = (clientX, clientY) => {
  if (!queueDrag) return;
  const { item, list } = queueDrag;
  const under = document.elementFromPoint(clientX, clientY);
  const target = under?.closest?.("[data-queue-id]");
  if (target && target !== item && list.contains(target)) {
    const rect = target.getBoundingClientRect();
    const insertBefore = clientY < rect.top + rect.height / 2;
    list.insertBefore(item, insertBefore ? target : target.nextSibling);
  }
};

// El auto-scroll sigue activo aunque el dedo quede quieto en el borde,
// para poder llevar una canción al inicio de una cola larga sin soltar.
const autoScrollQueue = () => {
  if (!queueDrag) return;
  const { scrollBox, edge, lastX, lastY } = queueDrag;
  if (scrollBox && edge) {
    const before = scrollBox.scrollTop;
    scrollBox.scrollTop += edge * 10;
    if (scrollBox.scrollTop !== before) updateQueueDragTarget(lastX, lastY);
  }
  queueDrag.raf = window.requestAnimationFrame(autoScrollQueue);
};

const onQueueDragMove = (event) => {
  if (!queueDrag || event.pointerId !== queueDrag.pointerId) return;
  event.preventDefault();

  const { ghost, startY, offsetY } = queueDrag;
  const delta = event.clientY - startY;
  if (Math.abs(delta) > 3) queueDrag.moved = true;
  ghost.style.top = `${event.clientY - offsetY}px`;
  queueDrag.lastX = event.clientX;
  queueDrag.lastY = event.clientY;

  updateQueueDragTarget(event.clientX, event.clientY);

  queueDrag.edge = 0;
  if (queueDrag.scrollBox) {
    const box = queueDrag.scrollBox.getBoundingClientRect();
    if (event.clientY < box.top + 56) queueDrag.edge = -1;
    else if (event.clientY > box.bottom - 56) queueDrag.edge = 1;
  }
};

const onQueueDragEnd = (event) => {
  if (!queueDrag) return;
  if (event && event.pointerId !== queueDrag.pointerId) return;

  const { ghost, item, list, moved, trackId } = queueDrag;
  if (queueDrag.raf) window.cancelAnimationFrame(queueDrag.raf);
  ghost.remove();
  item.classList.remove("queue-item--dragging");
  window.removeEventListener("pointermove", onQueueDragMove);
  window.removeEventListener("pointerup", onQueueDragEnd);
  window.removeEventListener("pointercancel", onQueueDragEnd);
  queueDrag = null;

  const rendered = Array.from(list.querySelectorAll("[data-queue-id]"))
    .map((node) => Number(node.dataset.queueId))
    .filter((id) => state.trackById.has(id));
  const headEnd = Math.max(0, state.queueIndex + 1);
  const previous = state.queue.slice(headEnd, headEnd + rendered.length);
  const changed = rendered.join(",") !== previous.join(",");

  if (!changed) {
    renderQueue();
    return;
  }

  applyQueueOrder(rendered, rendered.length);

  if (!moved) return;
  if (rendered[0] === trackId) {
    const track = trackById(trackId);
    toast(track ? `«${track.title}» suena a continuación` : "La canción suena a continuación");
  } else {
    toast("Cola actualizada");
  }
};

const startQueueDrag = (event) => {
  if (event.button !== undefined && event.button > 0) return;
  if (queueDrag) return;

  const handle = event.target.closest?.("[data-queue-drag]");
  if (!handle) return;

  const item = handle.closest("[data-queue-id]");
  const list = els.npQueue;
  if (!item || !list || !list.contains(item)) return;

  const trackId = Number(item.dataset.queueId);
  const index = state.queue.indexOf(trackId);
  if (index <= state.queueIndex) return;

  event.preventDefault();
  const rect = item.getBoundingClientRect();
  const ghost = item.cloneNode(true);
  ghost.classList.add("queue-item--ghost");
  ghost.removeAttribute("data-queue-id");
  ghost.removeAttribute("data-queue-index");
  ghost.setAttribute("aria-hidden", "true");
  ghost.querySelectorAll("[data-action], [data-queue-drag]").forEach((node) => {
    node.removeAttribute("data-action");
    node.removeAttribute("data-queue-drag");
  });
  ghost.style.width = `${rect.width}px`;
  ghost.style.height = `${rect.height}px`;
  ghost.style.left = `${rect.left}px`;
  ghost.style.top = `${rect.top}px`;
  document.body.appendChild(ghost);

  item.classList.add("queue-item--dragging");
  queueDrag = {
    item,
    ghost,
    list,
    trackId,
    pointerId: event.pointerId,
    startY: event.clientY,
    offsetY: event.clientY - rect.top,
    moved: false,
    edge: 0,
    lastX: event.clientX,
    lastY: event.clientY,
    raf: 0,
    scrollBox: findQueueScrollBox(list)
  };

  try {
    handle.setPointerCapture(event.pointerId);
  } catch (err) {
    /* captura opcional */
  }

  window.addEventListener("pointermove", onQueueDragMove, { passive: false });
  window.addEventListener("pointerup", onQueueDragEnd);
  window.addEventListener("pointercancel", onQueueDragEnd);
  queueDrag.raf = window.requestAnimationFrame(autoScrollQueue);
};

els.npQueue?.addEventListener("pointerdown", startQueueDrag);

const updateQuickPlayer = (track) => {
  if (!els.quickPlayer) return;

  if (!track) {
    if (els.quickCover) els.quickCover.innerHTML = `<span class="player__cover-empty">${icon("music")}</span>`;
    if (els.quickTitle) els.quickTitle.textContent = "Sin reproducción";
    if (els.quickArtist) els.quickArtist.textContent = "Subí tu primera canción";
    return;
  }

  if (els.quickCover) els.quickCover.innerHTML = coverHTML(track);
  if (els.quickTitle) els.quickTitle.textContent = track.title;
  if (els.quickArtist) els.quickArtist.textContent = track.artist || "Artista desconocido";
};

const updateNowPlaying = () => {
  const track = currentTrack();
  updateQuickPlayer(track);

  if (!track) {
    // Sin canción no hay nada que mostrar arriba del pie: cerramos el panel
    // rápido para que no quede abierto con datos viejos.
    els.player?.classList.remove("is-quick-open");
    els.quickPlayer?.setAttribute("aria-hidden", "true");
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
    queueAdvanceFrom = -1;
    queueRendered = 0;
    queueRenderIndex = -1;
    queueRenderLength = 0;
    disconnectQueueObserver();
    if (els.npQueue) {
      els.npQueue.innerHTML = `<li class="queue-empty">La cola está vacía. Elegí una canción para empezar.</li>`;
    }
    if (els.npQueueCount) els.npQueueCount.textContent = "";
    document.title = "WaverNote — Tu música";
    updatePlayerLike();
    updateHighlights();
    updateProgressUI();
    updatePlayButton();
    updateShuffleUI();
    updateRepeatUI();
    updateBufferingUI();
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
  updateBufferingUI();

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

const playbackFailureMessage = (track, fallback) => {
  if (engine.lastError === "offline") {
    return `«${track?.title || "Esta canción"}» no está descargada. Conectate a internet o descargala desde su menú.`;
  }
  return fallback;
};

const playCurrent = () => {
  const id = state.queue[state.queueIndex];
  const track = trackById(id);
  if (!track) {
    queueAdvanceFrom = -1;
    return;
  }

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
  syncPlaybackState();

  engine
    .start(track, 0)
    .then((ok) => {
      if (ok) {
        flushPendingPlay();
        prefetchNext();
      } else {
        state.isPlaying = false;
        updatePlayButton();
        updateHighlights();
        renderQueue();
        toast(
          playbackFailureMessage(
            track,
            "El navegador no pudo iniciar el audio. Probá de nuevo con un clic."
          ),
          "error"
        );
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
    syncPlaybackState();
    return;
  }

  if (state.duration && state.currentTime >= state.duration - 0.35) state.currentTime = 0;
  state.isPlaying = true;
  updatePlayButton();
  updateHighlights();
  renderQueue();
  syncMediaSessionState();
  syncPlaybackState();

  engine
    .start(track, state.currentTime)
    .then((ok) => {
      if (ok) {
        flushPendingPlay();
        prefetchNext();
      } else {
        state.isPlaying = false;
        updatePlayButton();
        updateHighlights();
        renderQueue();
        toast(
          playbackFailureMessage(track, "No se pudo reanudar el audio. Probá de nuevo."),
          "error"
        );
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
  syncPlaybackState();
};

const handleTrackEnd = () => {
  if (state.ending) return;
  state.ending = true;

  if (state.repeat === "one") {
    playCurrent();
  } else if (state.queueIndex < state.queue.length - 1) {
    queueAdvanceFrom = state.queueIndex;
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
    syncPlaybackState();
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
    queueAdvanceFrom = state.queueIndex;
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
    syncPlaybackState();
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
  syncSettingsState();
  syncPlaybackState();
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
  syncSettingsState();
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
  syncSettingsState();
};

const addToQueue = (id, options = {}) => {
  const track = trackById(id);
  if (!track) return "invalid";

  if (!state.queue.length) {
    state.queue = [track.id];
    state.queueIndex = 0;
    state.currentTrackId = track.id;
    state.duration = Number(track.duration) || 0;
    state.currentTime = 0;
    state.isPlaying = false;
    updateNowPlaying();
    syncPlaybackState();
    if (!options.silent) toast(`«${track.title}» quedó lista en la cola`);
    return "started";
  }

  const existing = queueIndexOf(track.id);
  if (existing >= state.queueIndex) {
    if (!options.silent) toast("Esa canción ya está en la cola");
    return "duplicate";
  }

  // Si ya sonó, sale del historial y vuelve al final: re-agregarla no debe
  // duplicar la entrada ni mover la canción que está sonando.
  if (existing >= 0) {
    state.queue.splice(existing, 1);
    state.queueIndex = Math.max(0, state.queueIndex - 1);
  }

  state.queue.push(track.id);
  renderQueue();
  updateHighlights();
  syncPlaybackState();
  if (!options.silent) {
    toast(existing >= 0 ? `«${track.title}» volvió a la cola` : `«${track.title}» se sumó a la cola`);
  }
  return "added";
};

// «Suena a continuación»: deja la canción justo después de la actual sin
// tocar el resto de la cola. Si ya estaba más abajo, la sube.
const playNext = (id, options = {}) => {
  const track = trackById(id);
  if (!track) return "invalid";

  if (!state.queue.length) {
    addToQueue(track.id, options);
    return "started";
  }

  const currentId = state.queue[state.queueIndex];
  if (Number(currentId) === Number(track.id)) {
    if (!options.silent) toast("Esa canción ya está sonando");
    return "current";
  }

  const existing = state.queue.indexOf(track.id);
  if (existing === state.queueIndex + 1) {
    if (!options.silent) toast(`«${track.title}» ya suena a continuación`);
    return "next";
  }

  if (existing >= 0) {
    state.queue.splice(existing, 1);
    if (existing <= state.queueIndex) state.queueIndex = Math.max(0, state.queueIndex - 1);
  }

  state.queue.splice(state.queueIndex + 1, 0, track.id);
  renderQueue();
  updateHighlights();
  syncPlaybackState();
  if (!options.silent) toast(`«${track.title}» suena a continuación`);
  return "queued";
};

// Reproduce una canción concreta sin borrar la cola: la ubica después de la
// actual y salta a ella. Si ya estaba en la cola, se mueve directo a su lugar.
const playTrackNow = (id) => {
  const track = trackById(id);
  if (!track) return;
  if (!state.queue.length) {
    state.queue = [track.id];
    state.queueIndex = 0;
    playCurrent();
    return;
  }

  const existing = queueIndexOf(track.id);
  if (existing >= state.queueIndex) {
    state.queueIndex = existing;
    playCurrent();
    return;
  }

  // Si ya sonó, se reubica después de la actual en vez de retroceder la cola
  // entera: se escucha ahora y el resto sigue donde estaba.
  if (existing >= 0) {
    state.queue.splice(existing, 1);
    state.queueIndex = Math.max(0, state.queueIndex - 1);
  }

  state.queue.splice(state.queueIndex + 1, 0, track.id);
  state.queueIndex += 1;
  playCurrent();
};

const queueCollection = (ids, label, options = {}) => {
  const requested = [...new Set((ids || []).map(Number))].filter((id) => state.trackById.has(id));
  const fresh = [];

  for (const id of requested) {
    const existing = queueIndexOf(id);
    if (existing < 0) {
      fresh.push(id);
      continue;
    }
    // Ya sonó: se saca del historial y se vuelve a sumar al final. Las que
    // están sonando o esperando se dejan como están.
    if (existing < state.queueIndex) {
      state.queue.splice(existing, 1);
      state.queueIndex = Math.max(0, state.queueIndex - 1);
      fresh.push(id);
    }
  }

  if (!fresh.length) {
    if (!options.silent) toast(state.queue.length ? "Ya estaba todo en la cola" : "No hay canciones para agregar.");
    return 0;
  }

  // Con la cola vacía la primera pista queda lista (en pausa), igual que
  // cuando se agrega una canción suelta: así el pie ya muestra qué va a sonar.
  if (!state.queue.length) {
    const first = trackById(fresh[0]);
    state.queue = fresh;
    state.queueIndex = 0;
    state.currentTrackId = fresh[0];
    state.duration = Number(first?.duration) || 0;
    state.currentTime = 0;
    state.isPlaying = false;
    updateNowPlaying();
    syncPlaybackState();
    if (!options.silent) {
      toast(`${label}: ${plural(fresh.length, "pista lista", "pistas listas")} en la cola`);
    }
    return fresh.length;
  }

  state.queue.push(...fresh);
  renderQueue();
  updateHighlights();
  syncPlaybackState();
  if (!options.silent) {
    toast(`${label}: ${plural(fresh.length, "pista agregada", "pistas agregadas")} a la cola`);
  }
  return fresh.length;
};

/* ------------------------------------------------------------
   Media Session
   ------------------------------------------------------------ */

// Android muestra la carátula de la notificación con el primer tamaño que
// pueda descargar. Declarar varios tamaños evita el ícono genérico cuando el
// sistema pide una miniatura chica o una imagen grande para el lockscreen.
const MEDIA_ARTWORK_SIZES = ["96x96", "128x128", "192x192", "256x256", "384x384", "512x512"];

const mediaArtworkFor = (track) => {
  const src = track?.coverUrl || new URL("app-icon.png", window.location.href).href;
  return MEDIA_ARTWORK_SIZES.map((sizes) => ({ src, sizes }));
};

// Puente opcional con Android (APK): la notificación nativa y el servicio en
// primer plano los maneja Kotlin. En la web este objeto no existe y todo sigue
// funcionando con la Media Session del navegador.
const nativeMediaBridge = () => {
  try {
    const bridge = window.WaverNoteAndroid;
    if (bridge && typeof bridge.updateMedia === "function") return bridge;
  } catch (err) {
    /* el objeto inyectado no está disponible */
  }
  return null;
};

let lastNativeMediaSignature = "";
let lastNativeMediaPositionAt = 0;
let nativeMediaWasActive = false;

const nativeMediaSnapshot = () => {
  const track = currentTrack();
  if (!track) return null;
  return {
    id: track.id,
    title: track.title,
    artist: track.artist || "WaverNote",
    album: albumNameOf(track),
    artwork: track.coverUrl || "",
    isPlaying: Boolean(state.isPlaying),
    duration: Number(state.duration) || 0,
    position: Number(state.currentTime) || 0,
    canNext: state.queueIndex < state.queue.length - 1 || state.repeat === "all",
    canPrevious: state.queueIndex > 0 || state.repeat === "all"
  };
};

const syncNativeMedia = (force = false) => {
  const bridge = nativeMediaBridge();
  if (!bridge) return;

  const snapshot = nativeMediaSnapshot();
  if (!snapshot) {
    if (!nativeMediaWasActive) return;
    nativeMediaWasActive = false;
    lastNativeMediaSignature = "";
    try {
      bridge.setPlaybackActive(false);
      bridge.stopMedia();
    } catch (err) {
      /* el puente puede haberse desconectado */
    }
    return;
  }

  nativeMediaWasActive = true;
  const { position, ...meta } = snapshot;
  const signature = JSON.stringify(meta);
  const now = Date.now();
  if (!force && signature === lastNativeMediaSignature && now - lastNativeMediaPositionAt < 5000) return;

  lastNativeMediaSignature = signature;
  lastNativeMediaPositionAt = now;
  try {
    // Android necesita saber si debe mantener la WebView despierta. El audio
    // de la canción actual ya lo mantiene el motor de medios del sistema; esto
    // es para que el JS que avanza la cola no se congele.
    bridge.setPlaybackActive(Boolean(snapshot.isPlaying));
    bridge.updateMedia(JSON.stringify(snapshot));
  } catch (err) {
    /* la notificación es opcional: nunca debe cortar la reproducción */
  }
};

// Los botones de la notificación llegan acá. La app puede estar en segundo
// plano: el objetivo es que la cola siga viva aunque la pantalla esté apagada.
window.WaverNoteMediaControls = {
  handle(action) {
    if (!state.ready) return;
    const value = String(action || "");

    if (value.startsWith("seek:")) {
      const seconds = Number(value.slice(5));
      if (Number.isFinite(seconds)) {
        seekTo(seconds);
        syncNativeMedia(true);
      }
      return;
    }

    if (value === "play") {
      if (!state.isPlaying) togglePlay();
    } else if (value === "pause") {
      if (state.isPlaying) togglePlay();
    } else if (value === "next") {
      nextTrack();
    } else if (value === "previous") {
      previousTrack();
    } else if (value === "stop") {
      if (state.isPlaying) togglePlay();
      seekTo(0);
    }
    syncNativeMedia(true);
  }
};

const syncMediaSession = () => {
  const track = currentTrack();
  if (!track) {
    if ("mediaSession" in navigator) {
      try {
        navigator.mediaSession.metadata = null;
        navigator.mediaSession.playbackState = "none";
      } catch (err) {
        /* el navegador puede no soportar metadata */
      }
    }
    syncNativeMedia(true);
    return;
  }

  if ("mediaSession" in navigator) {
    try {
      if (typeof MediaMetadata === "function") {
        navigator.mediaSession.metadata = new MediaMetadata({
          title: track.title,
          artist: track.artist || "WaverNote",
          album: albumNameOf(track),
          artwork: mediaArtworkFor(track)
        });
      }
    } catch (err) {
      /* el navegador puede no soportar metadata */
    }
  }
  syncMediaSessionState();
};

const syncMediaSessionPosition = () => {
  if (!("mediaSession" in navigator)) return;
  if (typeof navigator.mediaSession.setPositionState !== "function") return;
  if (!Number.isFinite(state.duration) || state.duration <= 0) return;

  try {
    const duration = state.duration;
    const position = clamp(Number(state.currentTime) || 0, 0, Math.max(0, duration - 0.05));
    navigator.mediaSession.setPositionState({
      duration,
      playbackRate: 1,
      position
    });
  } catch (err) {
    /* posición fuera de rango en algunos navegadores */
  }
};

const syncMediaSessionState = () => {
  if ("mediaSession" in navigator) {
    try {
      navigator.mediaSession.playbackState = currentTrack()
        ? state.isPlaying
          ? "playing"
          : "paused"
        : "none";
    } catch (err) {
      /* el navegador puede no soportar el estado */
    }
  }
  syncMediaSessionPosition();
  syncNativeMedia();
};

// La notificación de Android queda «pegada» a la canción hasta que el sistema
// recibe el nuevo estado. Refrescarla al volver del segundo plano evita que
// muestre una pista vieja o que los botones de la cola dejen de responder.
document.addEventListener("visibilitychange", () => {
  syncMediaSessionState();
  if (!document.hidden) {
    state.currentTime = clamp(engine.getTime(), 0, state.duration);
    updateProgressUI();
  }
});

const setupMediaSession = () => {
  if (!("mediaSession" in navigator)) {
    syncNativeMedia(true);
    return;
  }
  const handlers = {
    play: () => {
      if (!state.isPlaying) togglePlay();
    },
    pause: () => {
      if (state.isPlaying) togglePlay();
    },
    stop: () => {
      if (!state.isPlaying) return;
      togglePlay();
      seekTo(0);
      syncMediaSessionState();
    },
    previoustrack: previousTrack,
    nexttrack: nextTrack,
    seekbackward: (details) => seekTo(state.currentTime - (details?.seekOffset || 5)),
    seekforward: (details) => seekTo(state.currentTime + (details?.seekOffset || 5)),
    seekto: (details) => {
      if (typeof details?.seekTime !== "number") return;
      seekTo(details.seekTime);
      syncMediaSessionPosition();
    }
  };
  Object.entries(handlers).forEach(([action, handler]) => {
    try {
      navigator.mediaSession.setActionHandler(action, handler);
    } catch (err) {
      /* acción no soportada */
    }
  });
  syncNativeMedia(true);
};

/* ------------------------------------------------------------
   Visualizador
   ------------------------------------------------------------ */

let vizCanvas = null;
let vizContext = null;
let vizBars = [];
let vizPeaks = [];
let vizBinKey = "";
let vizFrequencyEdges = [];
let vizLastFrame = 0;
let vizGradient = null;
let vizGradientHeight = 0;
let vizGradientContext = null;
let vizHalo = null;
let vizHaloHeight = 0;
let vizHaloContext = null;
let vizObserver = null;
let vizVisible = true;

const VIZ_MIN_BARS = 24;
const VIZ_MAX_BARS = 60;

// Al cambiar el tamaño de la ventana el canvas hay que remedirlo: si no,
// el visualizador queda con la medida anterior.
window.addEventListener("resize", () => {
  vizRect = null;
});

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

// Cada barra toma un tramo del espectro. Los tramos crecen de forma
// logarítmica, como el oído: muchas barras para graves/medios y las justas
// para agudos, en vez de repetir el mismo dato en varias barras.
const vizEdgesFor = (count, bins, sampleRate) => {
  const binHz = Math.max(1, sampleRate / 2 / Math.max(1, bins));
  const minBin = Math.max(1, Math.floor(40 / binHz));
  const maxBin = Math.min(bins - 1, Math.max(minBin + 1, Math.round(16000 / binHz)));
  const edges = new Array(count + 1);

  for (let i = 0; i <= count; i += 1) {
    const value = Math.round(minBin * Math.pow(maxBin / minBin, i / count));
    edges[i] = Math.min(maxBin, Math.max(minBin, value));
  }

  for (let i = 1; i <= count; i += 1) {
    if (edges[i] <= edges[i - 1]) edges[i] = Math.min(maxBin, edges[i - 1] + 1);
  }

  return edges;
};

const drawVisualizer = (now) => {
  let canvas = vizCanvas;
  if (!canvas || !canvas.isConnected) canvas = $("#viz");
  if (!canvas) return;
  if (canvas !== vizCanvas) {
    vizCanvas = canvas;
    vizContext = canvas.getContext("2d");
    vizBars = [];
    vizPeaks = [];
    vizBinKey = "";
    vizFrequencyEdges = [];
    vizGradient = null;
    vizHalo = null;
    vizRect = null;
    if ("IntersectionObserver" in window) {
      vizObserver?.disconnect();
      vizObserver = new IntersectionObserver(
        (entries) => {
          vizVisible = entries.some((entry) => entry.isIntersecting);
        },
        { rootMargin: "120px" }
      );
      vizObserver.observe(canvas);
    }
  }
  if (!vizContext) return;

  // Con la pestaña en segundo plano o el panel fuera de pantalla no hay nada
  // que mirar: seguir dibujando solo consume CPU y traba el resto de la app.
  if (document.hidden || !vizVisible) return;

  // getBoundingClientRect obliga al navegador a recalcular el layout: pedirlo
  // en cada cuadro trava la app mientras suena. Se mide una vez por segundo.
  if (!vizRect || now - vizMeasuredAt >= VIZ_MEASURE_INTERVAL_MS) {
    vizRect = canvas.getBoundingClientRect();
    vizMeasuredAt = now;
  }
  const rect = vizRect;
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

  const count = clamp(Math.round(rect.width / 8), VIZ_MIN_BARS, VIZ_MAX_BARS);
  if (count !== vizBars.length) {
    vizBars = new Array(count).fill(0);
    vizPeaks = new Array(count).fill(0);
    vizFrequencyEdges = [];
    vizBinKey = "";
  }

  // Solo se pide el espectro cuando suena algo: en pausa las barras bajan
  // solas y no se simula movimiento que no existe.
  const stats = state.isPlaying ? engine.getSpectrum() : null;
  const binKey = stats ? `${stats.bins}:${stats.sampleRate}` : "";
  if (binKey !== vizBinKey) {
    vizBinKey = binKey;
    vizFrequencyEdges = stats ? vizEdgesFor(count, stats.bins, stats.sampleRate) : [];
  }

  const levels = stats?.frequency || null;
  // El volumen real (RMS) manda en la altura general. Un tema con graves
  // potentes pero volumen bajo se ve bajo; uno fuerte se ve lleno.
  const loudness = stats
    ? clamp(Math.pow(Math.max(0, stats.rms) * 3.2, 0.65), 0.14, 1.3)
    : 0;
  const punch = stats ? clamp(stats.peak * 0.22, 0, 0.18) : 0;

  const dt = vizLastFrame ? clamp((now - vizLastFrame) / 1000, 0.001, 0.05) : 1 / 60;
  vizLastFrame = now;
  const attack = 1 - Math.exp(-dt / 0.038);
  const release = 1 - Math.exp(-dt / 0.18);

  const gap = count > 44 ? 2 : 3;
  const barWidth = Math.max(1.2, (rect.width - gap * (count - 1)) / count);
  const usableHeight = rect.height - 6;

  // Los degradados se recrean solo cuando cambia la altura del canvas: crear
  // uno por cuadro es caro y se nota en el hilo principal.
  if (!vizGradient || vizGradientHeight !== rect.height || vizGradientContext !== ctx) {
    vizGradient = ctx.createLinearGradient(0, rect.height, 0, 0);
    vizGradient.addColorStop(0, "rgba(72, 210, 184, 0.25)");
    vizGradient.addColorStop(0.35, "rgba(99, 230, 200, 0.75)");
    vizGradient.addColorStop(0.72, "rgba(112, 196, 236, 0.92)");
    vizGradient.addColorStop(1, "rgba(150, 172, 255, 0.98)");
    vizGradientHeight = rect.height;
    vizGradientContext = ctx;
  }
  const gradient = vizGradient;

  // Halo inferior que respira con el volumen real, detrás de las barras. La
  // intensidad se ajusta con globalAlpha para no crear otro degradado por
  // cuadro.
  if (stats) {
    if (!vizHalo || vizHaloHeight !== rect.height || vizHaloContext !== ctx) {
      vizHalo = ctx.createLinearGradient(0, rect.height, 0, rect.height * 0.28);
      vizHalo.addColorStop(0, "rgba(99, 230, 200, 1)");
      vizHalo.addColorStop(1, "rgba(99, 230, 200, 0)");
      vizHaloHeight = rect.height;
      vizHaloContext = ctx;
    }
    ctx.globalAlpha = clamp(0.05 + loudness * 0.08, 0, 1);
    ctx.fillStyle = vizHalo;
    ctx.fillRect(0, 0, rect.width, rect.height);
    ctx.globalAlpha = 1;
  }

  ctx.fillStyle = gradient;

  for (let i = 0; i < count; i += 1) {
    let target = 0;

    if (levels && vizFrequencyEdges.length) {
      const from = vizFrequencyEdges[i];
      const to = Math.max(from + 1, vizFrequencyEdges[i + 1]);
      let max = 0;
      let sum = 0;
      let bins = 0;

      for (let bin = from; bin < to && bin < levels.length; bin += 1) {
        const value = levels[bin] / 255;
        sum += value;
        if (value > max) max = value;
        bins += 1;
      }

      if (bins) {
        const mean = sum / bins;
        // Mezcla de pico y promedio: el pico marca el golpe rítmico y el
        // promedio le da cuerpo al nivel sostenido.
        const spectral = Math.max(0, max * 0.62 + mean * 0.38 - 0.02);
        const tilt = 1 + 1.5 * Math.pow(i / Math.max(1, count - 1), 1.2);
        target = clamp(Math.pow(spectral, 1.15) * tilt * loudness + punch, 0, 1);
      }
    }

    const current = vizBars[i] || 0;
    const factor = target > current ? attack : release;
    const next = current + (target - current) * factor;
    vizBars[i] = next;

    // El pico queda colgado un instante y baja lento, como en un ecualizador
    // real: marca el techo de cada golpe sin temblar cuadro a cuadro.
    let peak = vizPeaks[i] || 0;
    if (next >= peak) peak = next;
    else peak = Math.max(next, peak - dt * 0.5);
    vizPeaks[i] = peak;

    const barHeight = Math.max(2, next * usableHeight);
    const x = i * (barWidth + gap);
    const y = rect.height - barHeight;
    roundedBar(ctx, x, y, barWidth, barHeight, barWidth / 2);
    ctx.fill();

    // Reflejo superior tenue: le da el aspecto de vidrio del resto de la app.
    if (barHeight > 4) {
      ctx.fillStyle = "rgba(220, 255, 248, 0.32)";
      roundedBar(ctx, x, y, barWidth, Math.min(1.6, barHeight * 0.22), barWidth / 2);
      ctx.fill();
      ctx.fillStyle = gradient;
    }
  }

  // Tapas de pico, apenas por encima de cada barra.
  ctx.fillStyle = "rgba(178, 250, 238, 0.75)";
  for (let i = 0; i < count; i += 1) {
    const peak = vizPeaks[i] || 0;
    if (peak <= 0.03 || peak * usableHeight < 4) continue;
    const x = i * (barWidth + gap);
    const y = rect.height - peak * usableHeight - 2.5;
    roundedBar(ctx, x, y, barWidth, 1.6, barWidth / 2);
    ctx.fill();
  }

  // Línea de reposo: cuando no suena nada queda una base serena, sin fingir
  // que hay música.
  ctx.fillStyle = "rgba(99, 230, 200, 0.09)";
  ctx.fillRect(0, rect.height - 1, rect.width, 1);
};

let uiLoopStarted = false;
let lastPlaybackSync = 0;
let lastPlaybackPositionSave = 0;
let lastMediaPositionSync = 0;
let lastNativeMediaSync = 0;
let backgroundWatchdog = 0;

const startUiLoop = () => {
  if (uiLoopStarted) return;
  uiLoopStarted = true;

  // requestAnimationFrame se congela cuando Android manda la app al fondo.
  // Este vigilante usa un timer normal (los navegadores no lo frenan mientras
  // hay audio sonando) y es el que mantiene avanzando la cola en segundo
  // plano; además refresca la posición de la notificación del sistema.
  if (!backgroundWatchdog) {
    backgroundWatchdog = window.setInterval(() => {
      if (!state.isPlaying || state.seeking) return;
      const time = engine.getTime();
      if (state.duration > 0 && time >= state.duration - 0.12) {
        handleTrackEnd();
        return;
      }
      state.currentTime = clamp(time, 0, state.duration);
      syncMediaSessionPosition();
      syncNativeMedia();
    }, 1000);
  }

  const frame = (now) => {
    if (state.isPlaying && !state.seeking && state.duration > 0) {
      const time = engine.getTime();
      if (time >= state.duration - 0.12) {
        handleTrackEnd();
      } else {
        state.currentTime = clamp(time, 0, state.duration);
        // Refrescar la barra y el reloj 60 veces por segundo pesa el hilo
        // principal y se nota como tirones durante la canción.
        if (now - lastProgressPaint >= PROGRESS_INTERVAL_MS) {
          lastProgressPaint = now;
          updateProgressUI();
        }
        if (now - lastMediaPositionSync >= 1000) {
          lastMediaPositionSync = now;
          syncMediaSessionPosition();
        }
        if (now - lastNativeMediaSync >= 4000) {
          lastNativeMediaSync = now;
          syncNativeMedia();
        }
        // La posición también viaja con la cuenta: cada 10 segundos alcanza
        // para retomar la canción casi donde iba en otro dispositivo.
        if (now - lastPlaybackSync >= 10000) {
          lastPlaybackSync = now;
          syncPlaybackState();
        }
        if (now - lastPlaybackPositionSave >= PLAYBACK_POSITION_SAVE_MS) {
          lastPlaybackPositionSave = now;
          if (typeof persistPlaybackPosition === "function") persistPlaybackPosition();
        }
      }
    }
    drawVisualizer(now);
    requestAnimationFrame(frame);
  };

  requestAnimationFrame(frame);
};
