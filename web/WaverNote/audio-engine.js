/* ============================================================
   WaverNote · motor de audio real
   Reproduce los archivos subidos por el usuario con <audio>.
   El visualizador usa la salida real mediante Web Audio.
   ============================================================ */

class WaveEngine {
  constructor() {
    this.audio = new Audio();
    // "auto" y no "metadata": con metadata el archivo no se pedía hasta
    // apretar play, así que la canción tardaba en arrancar y se frenaba a
    // mitad de tema en cuanto la conexión flojeaba. Con "auto" el navegador
    // va bufferizando por adelantado.
    this.audio.preload = "auto";
    this.audio.crossOrigin = "anonymous";
    this.audio.addEventListener("ended", () => this.onEnded?.());
    this.audio.addEventListener("loadedmetadata", () => this.onMetadata?.(this.audio.duration || 0));
    this.audio.addEventListener("error", () => this.onError?.());

    // Estados de red del elemento de audio: cuando se queda sin datos hay que
    // avisarlo, si no la app parece trabada en mitad de la canción.
    this.audio.addEventListener("waiting", () => this.setBuffering(true));
    this.audio.addEventListener("stalled", () => this.setBuffering(true));
    this.audio.addEventListener("playing", () => this.setBuffering(false));
    this.audio.addEventListener("canplaythrough", () => this.setBuffering(false));

    this.context = null;
    this.source = null;
    this.analyser = null;
    this.levels = null;
    this.currentUrl = "";
    this.graphFailed = false;
    this.buffering = false;

    // Precarga de la siguiente canción: el archivo queda en la caché de medios
    // del navegador y cuando llega el turno arranca al toque.
    this.prefetchEl = null;
    this.prefetchUrl = "";

    this.onEnded = null;
    this.onMetadata = null;
    this.onError = null;
    this.onBuffering = null;
  }

  setBuffering(value) {
    const next = Boolean(value);
    if (next === this.buffering) return;
    this.buffering = next;
    this.onBuffering?.(next);
  }

  isBuffering() {
    return this.buffering;
  }

  // Deja el archivo de la siguiente canción downloading en segundo plano.
  prefetch(url) {
    const target = String(url || "").trim();
    // Sin siguiente canción no queda nada que precargar: se suelta lo anterior
    // para no seguir bajando un archivo al pedo.
    if (!target || target === this.currentUrl) {
      this.clearPrefetch();
      return;
    }
    if (this.prefetchUrl === target) return;

    this.clearPrefetch();
    try {
      const el = new Audio();
      el.preload = "auto";
      el.crossOrigin = "anonymous";
      el.src = target;
      if (typeof el.load === "function") el.load();
      this.prefetchEl = el;
      this.prefetchUrl = target;
    } catch (err) {
      this.prefetchEl = null;
      this.prefetchUrl = "";
    }
  }

  clearPrefetch() {
    const el = this.prefetchEl;
    this.prefetchEl = null;
    this.prefetchUrl = "";
    if (!el) return;
    try {
      el.pause();
      el.removeAttribute("src");
      if (typeof el.load === "function") el.load();
    } catch (err) {
      /* noop */
    }
  }

  ensureGraph() {
    if (this.context || this.graphFailed) return Boolean(this.context);

    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!AudioContextClass) {
        this.graphFailed = true;
        return false;
      }

      this.context = new AudioContextClass();
      this.source = this.context.createMediaElementSource(this.audio);
      this.analyser = this.context.createAnalyser();
      this.analyser.fftSize = 256;
      this.analyser.smoothingTimeConstant = 0.78;
      this.levels = new Uint8Array(this.analyser.frequencyBinCount);
      this.source.connect(this.analyser);
      this.analyser.connect(this.context.destination);
      return true;
    } catch (err) {
      this.graphFailed = true;
      this.context = null;
      this.analyser = null;
      return false;
    }
  }

  async start(track, offset = 0) {
    if (!track?.audioUrl) return false;

    if (this.currentUrl !== track.audioUrl) {
      // Si esta canción ya estaba precargada para el siguiente turno, se suelta
      // el elemento de precarga: si no, el archivo se descargaría dos veces.
      if (this.prefetchUrl === track.audioUrl) this.clearPrefetch();
      this.currentUrl = track.audioUrl;
      this.audio.src = track.audioUrl;
      try {
        this.audio.load();
      } catch (err) {
        /* algunos navegadores cargan solos */
      }
    }

    this.ensureGraph();

    // Si el archivo todavía no está listo la app queda en "cargando" hasta que
    // empieza a sonar: así se ve que la canción se está preparando y no que
    // la app se quedó trabada.
    if (Number(this.audio.readyState) < 3) {
      this.setBuffering(true);
    }

    if (this.context?.state === "suspended") {
      try {
        await this.context.resume();
      } catch (err) {
        /* el audio del elemento sigue funcionando */
      }
    }

    const safeOffset = Number(offset);
    if (Number.isFinite(safeOffset) && safeOffset > 0.05) {
      try {
        this.audio.currentTime = safeOffset;
      } catch (err) {
        /* el navegador ajustará al rango válido */
      }
    }

    try {
      await this.audio.play();
      return true;
    } catch (err) {
      return false;
    }
  }

  pause() {
    this.audio.pause();
    this.setBuffering(false);
  }

  stop() {
    this.audio.pause();
    this.setBuffering(false);
    try {
      this.audio.currentTime = 0;
    } catch (err) {
      /* noop */
    }
  }

  seek(seconds) {
    try {
      this.audio.currentTime = Math.max(0, Number(seconds) || 0);
    } catch (err) {
      /* noop */
    }
  }

  getTime() {
    return Number(this.audio.currentTime) || 0;
  }

  getDuration() {
    return Number(this.audio.duration) || 0;
  }

  setVolume(value) {
    this.audio.volume = clamp(Number(value) || 0, 0, 1);
  }

  setMuted(muted) {
    this.audio.muted = Boolean(muted);
  }

  getLevels() {
    if (!this.analyser || !this.levels) return null;
    this.analyser.getByteFrequencyData(this.levels);
    return this.levels;
  }
}
