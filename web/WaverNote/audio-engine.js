/* ============================================================
   WaverNote · motor de audio generativo
   No hay archivos de audio: cada pista se sintetiza en vivo con
   Web Audio API a partir de su progresión, tempo y timbre.
   ============================================================ */

(function () {
  const AC = window.AudioContext || window.webkitAudioContext;

  const midiToFreq = (midi) => 440 * Math.pow(2, (midi - 69) / 12);

  function seedFrom(text) {
    let h = 2166136261;
    for (let i = 0; i < text.length; i += 1) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return Math.abs(h);
  }

  class WaveEngine {
    constructor() {
      this.ctx = null;
      this.master = null;
      this.analyser = null;
      this.delay = null;
      this.delaySend = null;
      this.noiseBuffer = null;
      this.playing = false;
      this.silent = false;
      this.track = null;
      this.offset = 0;
      this.startAt = 0;
      this.step = 0;
      this.stepDur = 0.18;
      this.nextTime = 0;
      this.timer = null;
      this.sources = new Set();
      this.volume = 0.72;
      this.muted = false;
      this.seed = 0;
      this._token = 0;
      this._levels = null;
      this.supported = Boolean(AC);
    }

    async ensure() {
      if (!this.supported) return false;
      if (!this.ctx) {
        try {
          this.ctx = new AC();
          this._build();
        } catch (err) {
          this.supported = false;
          return false;
        }
      }
      if (this.ctx.state === "suspended") {
        try {
          await this.ctx.resume();
        } catch (err) {
          /* el navegador puede bloquearlo hasta un gesto posterior */
        }
      }
      return this.ctx.state === "running";
    }

    _build() {
      const ctx = this.ctx;

      this.master = ctx.createGain();
      this.master.gain.value = 0.0001;

      const comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -22;
      comp.knee.value = 20;
      comp.ratio.value = 3;
      comp.attack.value = 0.006;
      comp.release.value = 0.28;

      this.analyser = ctx.createAnalyser();
      this.analyser.fftSize = 256;
      this.analyser.smoothingTimeConstant = 0.84;
      this._levels = new Uint8Array(this.analyser.frequencyBinCount);

      this.master.connect(comp);
      comp.connect(this.analyser);
      this.analyser.connect(ctx.destination);

      // Eco suave compartido, para dar profundidad sin reverb pesada.
      this.delay = ctx.createDelay(1.2);
      this.delay.delayTime.value = 0.44;
      const feedback = ctx.createGain();
      feedback.gain.value = 0.3;
      const damp = ctx.createBiquadFilter();
      damp.type = "lowpass";
      damp.frequency.value = 2400;
      this.delaySend = ctx.createGain();
      this.delaySend.gain.value = 0.2;

      this.delaySend.connect(this.delay);
      this.delay.connect(damp);
      damp.connect(feedback);
      feedback.connect(this.delay);
      damp.connect(this.master);

      // Ruido blanco reutilizable para percusión.
      const length = Math.floor(ctx.sampleRate * 1.2);
      const buffer = ctx.createBuffer(1, length, ctx.sampleRate);
      const data = buffer.getChannelData(0);
      for (let i = 0; i < length; i += 1) data[i] = Math.random() * 2 - 1;
      this.noiseBuffer = buffer;
    }

    _targetGain() {
      return this.muted ? 0.0001 : Math.max(0.0001, this.volume);
    }

    _rampMaster(time = 0.25) {
      if (!this.ctx || !this.master) return;
      const now = this.ctx.currentTime;
      this.master.gain.cancelScheduledValues(now);
      this.master.gain.setValueAtTime(0.0001, now);
      this.master.gain.linearRampToValueAtTime(this._targetGain(), now + time);
    }

    setVolume(value) {
      this.volume = Math.min(1, Math.max(0, Number(value) || 0));
      if (!this.ctx || !this.master) return;
      const now = this.ctx.currentTime;
      this.master.gain.cancelScheduledValues(now);
      this.master.gain.setTargetAtTime(this._targetGain(), now, 0.03);
    }

    setMuted(muted) {
      this.muted = Boolean(muted);
      if (!this.ctx || !this.master) return;
      const now = this.ctx.currentTime;
      this.master.gain.cancelScheduledValues(now);
      this.master.gain.setTargetAtTime(this._targetGain(), now, 0.02);
    }

    async start(track, offset = 0) {
      const token = (this._token += 1);
      const audioOk = await this.ensure();
      if (token !== this._token) return false;

      this._teardown();

      this.track = track;
      this.offset = Math.max(0, Number(offset) || 0);
      this.seed = seedFrom(track.id || "wavernote");
      this.playing = true;
      this.silent = !audioOk;

      if (audioOk) {
        const now = this.ctx.currentTime;
        this.stepDur = 60 / track.sonic.bpm / 4;
        this.startAt = now - this.offset;
        this.step = Math.floor(this.offset / this.stepDur) % 64;
        this.nextTime = now + 0.06;
        this._rampMaster(0.3);
        this.timer = setInterval(() => this._tick(), 90);
        this._tick();
      } else {
        this.startAt = performance.now() - this.offset * 1000;
      }

      return audioOk;
    }

    pause() {
      this._token += 1;
      if (!this.playing) return;
      this.offset = this.getTime();
      this.playing = false;
      this._teardown();
      if (this.ctx && this.master) {
        const now = this.ctx.currentTime;
        this.master.gain.cancelScheduledValues(now);
        this.master.gain.setTargetAtTime(0.0001, now, 0.02);
      }
    }

    stop() {
      this._token += 1;
      this.playing = false;
      this.offset = 0;
      this._teardown();
    }

    seek(seconds) {
      const target = Math.max(0, Number(seconds) || 0);
      this.offset = target;

      if (!this.playing) return;
      if (this.silent || !this.ctx) {
        this.startAt = performance.now() - target * 1000;
        return;
      }

      this._stopSources();
      const now = this.ctx.currentTime;
      this.startAt = now - target;
      this.step = Math.floor(target / this.stepDur) % 64;
      this.nextTime = now + 0.05;
      this._tick();
    }

    getTime() {
      if (!this.playing) return this.offset;
      if (this.silent || !this.ctx) {
        return Math.max(0, (performance.now() - this.startAt) / 1000);
      }
      return Math.max(0, this.ctx.currentTime - this.startAt);
    }

    getLevels() {
      if (!this.analyser || !this._levels) return null;
      this.analyser.getByteFrequencyData(this._levels);
      return this._levels;
    }

    get usingAudio() {
      return Boolean(this.ctx && this.ctx.state === "running" && !this.silent);
    }

    _teardown() {
      if (this.timer) {
        clearInterval(this.timer);
        this.timer = null;
      }
      this._stopSources();
    }

    _stopSources() {
      for (const source of this.sources) {
        try {
          source.stop();
        } catch (err) {
          /* la fuente ya había terminado */
        }
      }
      this.sources.clear();
    }

    _register(sources, nodes) {
      const primary = sources[0];
      if (!primary) return;
      this.sources.add(primary);
      primary.addEventListener(
        "ended",
        () => {
          this.sources.delete(primary);
          nodes.forEach((node) => {
            try {
              node.disconnect();
            } catch (err) {
              /* nodo ya desconectado */
            }
          });
        },
        { once: true }
      );
      if (sources.length > 1) {
        sources.slice(1).forEach((source) => {
          try {
            source.addEventListener("ended", () => {
              try {
                source.disconnect();
              } catch (err) {
                /* noop */
              }
            });
          } catch (err) {
            /* noop */
          }
        });
      }
    }

    _tick() {
      if (!this.playing || !this.ctx || this.silent) return;
      const horizon = this.ctx.currentTime + 0.7;
      let guard = 0;
      while (this.nextTime < horizon && guard < 48) {
        this._playStep(this.step, this.nextTime);
        this.nextTime += this.stepDur;
        this.step = (this.step + 1) % 64;
        guard += 1;
      }
    }

    _playStep(step, time) {
      if (!this.track) return;
      const sonic = this.track.sonic;
      const barStep = step % 16;
      const chordIndex = Math.floor(step / 16) % sonic.chords.length;
      const chord = sonic.chords[chordIndex];
      const seed = this.seed;
      const swing = seed % 3;

      // Colchón armónico: un acorde por compás.
      if (barStep === 0) {
        chord.forEach((semi, index) => {
          const midi = sonic.root + semi;
          const pan = (index - 1.5) * 0.16;
          this._pad(midi, time, this.stepDur * 17, 0.018, pan, 4 + index);
        });
        this._bass(sonic.root + chord[0] - 24, time, this.stepDur * 13, 0.15);
      }

      if (sonic.drums) {
        // Pulso de bajo en la segunda mitad del compás.
        if (barStep === 8) {
          this._bass(sonic.root + chord[0] - 24, time, this.stepDur * 6, 0.09);
        }

        // Melodía/arpegio: brillo sobre el acorde.
        if (barStep % 2 === 0) {
          const skip = (step + seed) % (5 + swing) === 0;
          if (!skip) {
            const tones = [...chord, chord[0] + 12];
            const note = tones[(Math.floor(step / 2) + seed) % tones.length];
            const octave = step % 16 === 6 ? 24 : 12;
            this._pluck(
              sonic.root + note + octave,
              time,
              0.34,
              barStep === 0 ? 0.045 : 0.032,
              step % 4 < 2 ? -0.22 : 0.22
            );
          }
        }

        // Bombo.
        if (barStep === 0 || barStep === 8) this._kick(time, 0.5);
        if (swing === 2 && barStep === 11) this._kick(time, 0.24);

        // Aire y percusión.
        if (barStep % 2 === 0) this._hat(time, barStep % 4 === 0 ? 0.032 : 0.018);
        if (sonic.clap && (barStep === 4 || barStep === 12)) this._clap(time, 0.08);
      } else {
        // Álbumes cinemáticos: piano espaciado en lugar de batería.
        if (barStep === 0) {
          const tones = [...chord, chord[0] + 12];
          const note = tones[(chordIndex + seed) % tones.length];
          this._piano(sonic.root + note + 12, time, 0.06);
        }
        if (barStep === 10) {
          const note = chord[(chordIndex + 2) % chord.length];
          this._piano(sonic.root + note + 24, time, 0.028);
        }
      }

      // Campana lejana cada cuatro compases.
      if (step === 32 || step === 52) {
        const tone = chord[(step + seed) % chord.length] + 24;
        this._bell(sonic.root + tone, time, 0.02);
      }
    }

    _pad(midi, time, duration, level, pan, detune) {
      this._tone(midi, time, duration, {
        level,
        type: "sawtooth",
        attack: 0.85,
        filter: 1150,
        send: 0.3,
        pan,
        detune,
      });
      this._tone(midi, time, duration, {
        level: level * 0.8,
        type: "triangle",
        attack: 0.95,
        filter: 1900,
        send: 0.18,
        pan: -pan,
        detune: -detune,
      });
    }

    _bass(midi, time, duration, level) {
      this._tone(midi, time, duration, {
        level,
        type: "sine",
        attack: 0.02,
        filter: 320,
        send: 0.04,
        pan: 0,
      });
      this._tone(midi + 12, time, duration * 0.8, {
        level: level * 0.3,
        type: "triangle",
        attack: 0.01,
        filter: 500,
        send: 0.02,
        pan: 0,
      });
    }

    _pluck(midi, time, duration, level, pan) {
      this._tone(midi, time, duration, {
        level,
        type: "triangle",
        attack: 0.008,
        filter: 3200,
        send: 0.34,
        pan,
      });
    }

    _piano(midi, time, level) {
      this._tone(midi, time, 2.8, {
        level,
        type: "triangle",
        attack: 0.006,
        filter: 4200,
        send: 0.42,
        pan: 0.12,
      });
      this._tone(midi + 12, time, 1.6, {
        level: level * 0.35,
        type: "sine",
        attack: 0.004,
        filter: 6000,
        send: 0.3,
        pan: -0.16,
      });
    }

    _bell(midi, time, level) {
      this._tone(midi, time, 2.2, {
        level,
        type: "sine",
        attack: 0.01,
        filter: 8000,
        send: 0.55,
        pan: (this.seed % 2 ? 1 : -1) * 0.25,
      });
    }

    _tone(midi, time, duration, options = {}) {
      if (!this.ctx || !this.master) return;
      const ctx = this.ctx;
      const {
        level = 0.05,
        type = "triangle",
        attack = 0.01,
        filter = 2400,
        send = 0,
        pan = 0,
        detune = 0,
      } = options;

      const osc = ctx.createOscillator();
      osc.type = type;
      osc.frequency.setValueAtTime(midiToFreq(midi), time);
      osc.detune.setValueAtTime(detune, time);

      const env = ctx.createGain();
      const peak = Math.max(0.0004, level);
      const attackEnd = time + Math.min(attack, duration * 0.6);
      env.gain.setValueAtTime(0.0001, time);
      env.gain.linearRampToValueAtTime(peak, attackEnd);
      env.gain.exponentialRampToValueAtTime(0.0001, time + Math.max(duration, attack + 0.05));

      const toneFilter = ctx.createBiquadFilter();
      toneFilter.type = "lowpass";
      toneFilter.frequency.setValueAtTime(filter, time);
      toneFilter.Q.value = 0.6;

      osc.connect(toneFilter);
      toneFilter.connect(env);

      let tail = env;
      if (typeof ctx.createStereoPanner === "function" && pan) {
        const panner = ctx.createStereoPanner();
        panner.pan.setValueAtTime(pan, time);
        env.connect(panner);
        tail = panner;
      }

      tail.connect(this.master);

      if (send > 0) {
        const sendGain = ctx.createGain();
        sendGain.gain.value = send;
        tail.connect(sendGain);
        sendGain.connect(this.delaySend);
        this._register(
          [osc],
          [osc, env, toneFilter, tail, sendGain].filter((node, index, arr) => arr.indexOf(node) === index)
        );
      } else {
        this._register([osc], [osc, env, toneFilter, tail]);
      }

      const stopAt = time + Math.max(duration, attack + 0.05) + 0.05;
      osc.start(time);
      osc.stop(stopAt);
    }

    _kick(time, level) {
      if (!this.ctx || !this.master) return;
      const ctx = this.ctx;
      const osc = ctx.createOscillator();
      osc.type = "sine";
      osc.frequency.setValueAtTime(120, time);
      osc.frequency.exponentialRampToValueAtTime(42, time + 0.16);

      const env = ctx.createGain();
      env.gain.setValueAtTime(0.0001, time);
      env.gain.linearRampToValueAtTime(level, time + 0.008);
      env.gain.exponentialRampToValueAtTime(0.0001, time + 0.34);

      osc.connect(env);
      env.connect(this.master);
      this._register([osc], [osc, env]);
      osc.start(time);
      osc.stop(time + 0.38);
    }

    _hat(time, level) {
      if (!this.ctx || !this.noiseBuffer) return;
      const ctx = this.ctx;
      const source = ctx.createBufferSource();
      source.buffer = this.noiseBuffer;
      source.loopStart = 0;
      source.loopEnd = 0.2;

      const filter = ctx.createBiquadFilter();
      filter.type = "highpass";
      filter.frequency.value = 7200;
      filter.Q.value = 0.7;

      const env = ctx.createGain();
      env.gain.setValueAtTime(level, time);
      env.gain.exponentialRampToValueAtTime(0.0001, time + 0.05);

      source.connect(filter);
      filter.connect(env);
      env.connect(this.master);
      this._register([source], [source, filter, env]);
      source.start(time);
      source.stop(time + 0.07);
    }

    _clap(time, level) {
      if (!this.ctx || !this.noiseBuffer) return;
      const ctx = this.ctx;
      const source = ctx.createBufferSource();
      source.buffer = this.noiseBuffer;
      source.loopStart = 0.2;
      source.loopEnd = 0.7;

      const filter = ctx.createBiquadFilter();
      filter.type = "bandpass";
      filter.frequency.value = 1900;
      filter.Q.value = 1.1;

      const env = ctx.createGain();
      env.gain.setValueAtTime(0.0001, time);
      env.gain.linearRampToValueAtTime(level, time + 0.006);
      env.gain.exponentialRampToValueAtTime(0.0001, time + 0.16);

      source.connect(filter);
      filter.connect(env);
      env.connect(this.master);
      this._register([source], [source, filter, env]);
      source.start(time);
      source.stop(time + 0.2);
    }
  }

  window.WaveEngine = WaveEngine;
})();
