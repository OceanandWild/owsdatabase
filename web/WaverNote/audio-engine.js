/* ============================================================
   WaverNote · motor de audio real
   Reproduce los archivos subidos por el usuario con <audio>.
   El visualizador usa la salida real mediante Web Audio.
   ============================================================ */

class WaveEngine {
  constructor() {
    this.audio = new Audio();
    this.audio.preload = "metadata";
    this.audio.crossOrigin = "anonymous";
    this.audio.addEventListener("ended", () => this.onEnded?.());
    this.audio.addEventListener("loadedmetadata", () => this.onMetadata?.(this.audio.duration || 0));
    this.audio.addEventListener("error", () => this.onError?.());

    this.context = null;
    this.source = null;
    this.analyser = null;
    this.levels = null;
    this.currentUrl = "";
    this.graphFailed = false;

    this.onEnded = null;
    this.onMetadata = null;
    this.onError = null;
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
      this.currentUrl = track.audioUrl;
      this.audio.src = track.audioUrl;
      try {
        this.audio.load();
      } catch (err) {
        /* algunos navegadores cargan solos */
      }
    }

    this.ensureGraph();

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
  }

  stop() {
    this.audio.pause();
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
