/* ═══════════════════════════════════════════════════════════
   OWS HUB 3.4.30 · PRESENTACIÓN
   Motor de timeline, escenas, reproductor y audio ambiental.
   ═══════════════════════════════════════════════════════════ */

(() => {
  'use strict';

  const TOTAL = 180;

  /* ── Capítulos ─────────────────────────────────────────────
     intro + 8 actos + cierre = 180 s exactos.
     Las duraciones de los cambios suman el tiempo de cada acto. */
  const CHAPTERS = [
    { id: 'intro', num: '00', name: 'Apertura', short: 'Apertura', start: 0, end: 10 },
    {
      id: 'a1', num: '01', name: 'Actualizaciones', short: 'Actualizaciones', start: 10, end: 46,
      intro: 4.0, durs: [4.2, 4.4, 4.8, 4.2, 4.4, 4.2, 5.8]
    },
    {
      id: 'a2', num: '02', name: 'Changelogs', short: 'Changelogs', start: 46, end: 58,
      intro: 3.4, durs: [4.2, 4.4]
    },
    {
      id: 'a3', num: '03', name: 'Noticias', short: 'Noticias', start: 58, end: 74,
      intro: 3.4, durs: [4.2, 4.1, 4.3]
    },
    {
      id: 'a4', num: '04', name: 'Eventos', short: 'Eventos', start: 74, end: 85,
      intro: 3.2, durs: [3.8, 4.0]
    },
    {
      id: 'a5', num: '05', name: 'Lanzamientos', short: 'Lanzamientos', start: 85, end: 94,
      intro: 3.0, durs: [6.0]
    },
    {
      id: 'a6', num: '06', name: 'Surface · identidad', short: 'Surface', start: 94, end: 112,
      intro: 3.4, durs: [3.4, 3.6, 3.8, 3.8]
    },
    {
      id: 'a7', num: '07', name: 'Surface · envíos', short: 'Envíos', start: 112, end: 138,
      intro: 3.6, durs: [6.0, 4.6, 4.2, 3.8, 3.8]
    },
    {
      id: 'a8', num: '08', name: 'Surface · billetera', short: 'Billetera', start: 138, end: 162,
      intro: 3.6, durs: [4.4, 4.6, 3.8, 4.0, 3.6]
    },
    { id: 'outro', num: '09', name: 'Cierre', short: 'Cierre', start: 162, end: 180 }
  ];

  CHAPTERS.forEach(ch => {
    ch.steps = [];
    if (ch.durs) {
      let cursor = ch.start + (ch.intro || 0);
      ch.durs.forEach(d => {
        ch.steps.push(cursor);
        cursor += d;
      });
    }
  });

  const clamp = (v, min, max) => Math.min(max, Math.max(min, v));
  const setText = (el, value) => { if (el && el.textContent !== value) el.textContent = value; };
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

  /* ── DOM ─────────────────────────────────────────────────── */
  const body = document.body;
  const viewport = document.getElementById('viewport');
  const stage = document.getElementById('stage');
  const scenes = $$('.scene');
  const sceneById = new Map(scenes.map(s => [s.dataset.scene, s]));
  const labelsEl = document.getElementById('tlLabels');
  const rail = document.getElementById('tlRail');
  const fill = document.getElementById('tlFill');
  const head = document.getElementById('tlHead');
  const tNow = document.getElementById('tNow');
  const tTotal = document.getElementById('tTotal');
  const topNum = document.getElementById('topChapNum');
  const topName = document.getElementById('topChapName');
  const prChapter = document.getElementById('prChapter');
  const playState = document.getElementById('playState');
  const btnPlay = document.getElementById('btnPlay');
  const btnRestart = document.getElementById('btnRestart');
  const btnSound = document.getElementById('btnSound');
  const btnFull = document.getElementById('btnFull');
  const loader = document.getElementById('loader');
  const sweep = document.getElementById('sweep');

  /* ── Estado ──────────────────────────────────────────────── */
  const params = new URLSearchParams(location.search);
  const startT = clamp(parseFloat(params.get('t')) || 0, 0, TOTAL);
  const autoplay = params.has('autoplay')
    ? params.get('autoplay') !== '0'
    : !params.has('t');

  let t = startT;
  let playing = false;
  let ended = false;
  let chapterIdx = -1;
  let step = -2;
  let newsIdx = -1;
  let lastPct = -1;
  let lastEta = '';
  let booted = false;
  let scrubbing = false;

  /* ── Escala del stage ────────────────────────────────────── */
  function fit() {
    const margin = document.fullscreenElement ? 0 : Math.min(34, innerWidth * 0.022);
    const s = Math.min(
      (innerWidth - margin * 2) / 1440,
      (innerHeight - margin * 2) / 810
    );
    stage.style.transform = `translate(-50%, -50%) scale(${Math.max(0.2, s)})`;
  }

  /* ── Estrellas ───────────────────────────────────────────── */
  const canvas = document.getElementById('stars');
  const ctx2d = canvas.getContext('2d');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const W = 1440;
  const H = 810;
  let dpr = Math.min(window.devicePixelRatio || 1, 2);
  let stars = [];
  let shooters = [];
  let starsReady = false;

  function sizeCanvas() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx2d.setTransform(dpr, 0, 0, dpr, 0, 0);
    starsReady = false;
  }

  function initStars() {
    stars = Array.from({ length: 170 }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      r: Math.random() * 1.25 + 0.25,
      base: Math.random() * 0.5 + 0.2,
      amp: Math.random() * 0.35,
      phase: Math.random() * Math.PI * 2,
      spd: Math.random() * 1.2 + 0.25,
      drift: Math.random() * 0.9 + 0.15,
      warm: Math.random() < 0.28
    }));
    shooters = [];
    starsReady = true;
  }

  function spawnShooter() {
    const angle = Math.random() * 0.35 + 0.18;
    shooters.push({
      x: Math.random() * W * 0.8,
      y: Math.random() * H * 0.4,
      vx: Math.cos(angle) * (240 + Math.random() * 160),
      vy: Math.sin(angle) * (150 + Math.random() * 90),
      len: 70 + Math.random() * 90,
      life: 1,
      fade: 0.7 + Math.random() * 0.7
    });
  }

  function drawStars(dt) {
    if (!starsReady) initStars();
    ctx2d.clearRect(0, 0, W, H);

    for (const s of stars) {
      if (!reducedMotion) {
        s.phase += s.spd * dt;
        s.x += s.drift * dt;
        if (s.x > W + 4) s.x = -4;
      }
      const o = clamp(s.base + Math.sin(s.phase) * s.amp, 0.05, 1);
      ctx2d.beginPath();
      ctx2d.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx2d.fillStyle = s.warm
        ? `rgba(255, 221, 143, ${o})`
        : `rgba(242, 236, 255, ${o})`;
      ctx2d.fill();
    }

    if (reducedMotion) return;

    if (Math.random() < dt * 0.22 && shooters.length < 3) spawnShooter();

    for (let i = shooters.length - 1; i >= 0; i--) {
      const sh = shooters[i];
      sh.x += sh.vx * dt;
      sh.y += sh.vy * dt;
      sh.life -= sh.fade * dt;
      if (sh.life <= 0 || sh.x > W + 120 || sh.y > H + 120) {
        shooters.splice(i, 1);
        continue;
      }
      const nx = sh.x - sh.vx * 0.14;
      const ny = sh.y - sh.vy * 0.14;
      const g = ctx2d.createLinearGradient(sh.x, sh.y, nx, ny);
      g.addColorStop(0, `rgba(255, 233, 176, ${sh.life * 0.85})`);
      g.addColorStop(1, 'rgba(255, 233, 176, 0)');
      ctx2d.strokeStyle = g;
      ctx2d.lineWidth = 1.2;
      ctx2d.beginPath();
      ctx2d.moveTo(sh.x, sh.y);
      ctx2d.lineTo(nx, ny);
      ctx2d.stroke();
    }
  }

  /* ── Audio ambiental ─────────────────────────────────────── */
  const AudioEngine = {
    ctx: null,
    master: null,
    enabled: false,
    noise: null,

    init() {
      if (this.ctx) return true;
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return false;
      try {
        const ctx = new AC();
        const master = ctx.createGain();
        master.gain.value = 0;
        master.connect(ctx.destination);

        const filter = ctx.createBiquadFilter();
        filter.type = 'lowpass';
        filter.frequency.value = 480;
        filter.Q.value = 0.6;

        const padBus = ctx.createGain();
        padBus.gain.value = 0.075;
        filter.connect(padBus);
        padBus.connect(master);

        [55, 82.41, 110, 164.81, 220].forEach((freq, i) => {
          const osc = ctx.createOscillator();
          osc.type = i % 2 === 0 ? 'sine' : 'triangle';
          osc.frequency.value = freq;
          osc.detune.value = (i - 2) * 3;
          const g = ctx.createGain();
          g.gain.value = i === 0 ? 0.5 : 0.2;
          osc.connect(g);
          g.connect(filter);
          osc.start();
        });

        const lfo = ctx.createOscillator();
        lfo.frequency.value = 0.055;
        const lfoGain = ctx.createGain();
        lfoGain.gain.value = 190;
        lfo.connect(lfoGain);
        lfoGain.connect(filter.frequency);
        lfo.start();

        const delay = ctx.createDelay(1.4);
        delay.delayTime.value = 0.58;
        const feedback = ctx.createGain();
        feedback.gain.value = 0.26;
        const wet = ctx.createGain();
        wet.gain.value = 0.16;
        padBus.connect(delay);
        delay.connect(feedback);
        feedback.connect(delay);
        delay.connect(wet);
        wet.connect(master);

        this.ctx = ctx;
        this.master = master;
        return true;
      } catch {
        return false;
      }
    },

    setEnabled(on) {
      if (on) {
        if (!this.init()) return false;
        this.enabled = true;
        const now = this.ctx.currentTime;
        this.master.gain.cancelScheduledValues(now);
        this.master.gain.setValueAtTime(Math.max(0.0001, this.master.gain.value), now);
        this.master.gain.exponentialRampToValueAtTime(0.62, now + 1.2);
        this.ctx.resume();
      } else {
        this.enabled = false;
        if (!this.ctx) return true;
        const now = this.ctx.currentTime;
        this.master.gain.cancelScheduledValues(now);
        this.master.gain.setValueAtTime(Math.max(0.0001, this.master.gain.value), now);
        this.master.gain.exponentialRampToValueAtTime(0.0001, now + 0.45);
      }
      return true;
    },

    setPlaying(on) {
      if (!this.ctx || !this.enabled) return;
      if (on) this.ctx.resume();
      else this.ctx.suspend();
    },

    getNoise() {
      if (this.noise) return this.noise;
      const ctx = this.ctx;
      const len = Math.floor(ctx.sampleRate * 1.4);
      const buffer = ctx.createBuffer(1, len, ctx.sampleRate);
      const data = buffer.getChannelData(0);
      for (let i = 0; i < len; i++) data[i] = Math.random() * 2 - 1;
      this.noise = buffer;
      return buffer;
    },

    whoosh() {
      if (!this.enabled || !this.ctx) return;
      const ctx = this.ctx;
      const now = ctx.currentTime;
      const src = ctx.createBufferSource();
      src.buffer = this.getNoise();
      const bp = ctx.createBiquadFilter();
      bp.type = 'bandpass';
      bp.Q.value = 1.1;
      bp.frequency.setValueAtTime(180, now);
      bp.frequency.exponentialRampToValueAtTime(1500, now + 0.42);
      bp.frequency.exponentialRampToValueAtTime(240, now + 1.05);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, now);
      g.gain.linearRampToValueAtTime(0.14, now + 0.2);
      g.gain.exponentialRampToValueAtTime(0.0001, now + 1.12);
      src.connect(bp);
      bp.connect(g);
      g.connect(this.master);
      src.start(now);
      src.stop(now + 1.18);
    },

    tick() {
      if (!this.enabled || !this.ctx) return;
      const ctx = this.ctx;
      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(760, now);
      osc.frequency.exponentialRampToValueAtTime(620, now + 0.1);
      const g = ctx.createGain();
      g.gain.setValueAtTime(0.0001, now);
      g.gain.linearRampToValueAtTime(0.018, now + 0.012);
      g.gain.exponentialRampToValueAtTime(0.0001, now + 0.13);
      osc.connect(g);
      g.connect(this.master);
      osc.start(now);
      osc.stop(now + 0.15);
    }
  };

  /* ── Etiquetas de capítulos ──────────────────────────────── */
  const chapterButtons = CHAPTERS.map((ch, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = ch.short;
    b.style.setProperty('--grow', String(ch.end - ch.start));
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-label', `Ir a ${ch.name} (${formatTime(ch.start)})`);
    b.addEventListener('click', () => {
      seek(ch.start + 0.02, { restart: true });
    });
    labelsEl.appendChild(b);
    return b;
  });

  function formatTime(sec) {
    const s = Math.max(0, Math.floor(sec));
    return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  }

  /* ── Utilidades de capítulo / paso ───────────────────────── */
  function chapterAt(time) {
    if (time < CHAPTERS[0].end) return 0;
    for (let i = 1; i < CHAPTERS.length; i++) {
      if (time < CHAPTERS[i].end) return i;
    }
    return CHAPTERS.length - 1;
  }

  function stepAt(ch, time) {
    if (!ch.steps.length) return -1;
    let n = -1;
    for (let i = 0; i < ch.steps.length; i++) {
      if (time >= ch.steps[i] - 1e-6) n = i;
      else break;
    }
    return n;
  }

  function runSweep() {
    sweep.classList.remove('run');
    void sweep.offsetWidth;
    sweep.classList.add('run');
  }

  function enterChapter(idx, animate) {
    const ch = CHAPTERS[idx];
    chapterIdx = idx;

    scenes.forEach(scene => {
      const on = scene.dataset.scene === ch.id;
      scene.classList.toggle('is-active', on);
      scene.setAttribute('aria-hidden', String(!on));
      if (on) {
        // reinicia animaciones de entrada de la escena
        scene.style.animation = 'none';
        void scene.offsetHeight;
        scene.style.animation = '';
      }
    });

    stage.dataset.chapter = ch.id;
    setText(topNum, ch.num);
    setText(topName, ch.name);
    setText(prChapter, ch.name);

    chapterButtons.forEach((b, i) => {
      b.classList.toggle('is-active', i === idx);
      b.classList.toggle('is-past', i < idx);
      b.setAttribute('aria-selected', String(i === idx));
    });

    step = -2;
    if (animate) {
      runSweep();
      if (playing) AudioEngine.whoosh();
    }
  }

  function applyStep(ch, nextStep, prevStep) {
    const scene = sceneById.get(ch.id);
    if (!scene) return;

    const demo = scene.querySelector('[data-demo]');
    if (demo) {
      if (nextStep >= 0) demo.dataset.step = String(nextStep);
      else delete demo.dataset.step;
    }

    const items = $$('.changes li', scene);
    items.forEach((li, i) => {
      li.classList.toggle('is-past', i < nextStep);
      li.classList.toggle('is-current', i === nextStep);
      li.classList.toggle('is-future', i > nextStep);
    });

    // Sonido de avance y desplazamiento del ítem activo
    if (nextStep > prevStep && nextStep >= 0) {
      if (playing) AudioEngine.tick();
      const current = items[nextStep];
      const list = current && current.parentElement;
      if (current && list) {
        const top = current.offsetTop - list.offsetTop;
        const bottom = top + current.offsetHeight;
        if (top < list.scrollTop + 2 || bottom > list.scrollTop + list.clientHeight - 2) {
          list.scrollTo({ top: Math.max(0, top - 8), behavior: 'smooth' });
        }
      }
    }

    if (ch.id === 'a1' && nextStep !== prevStep) {
      const cursor = scene.querySelector('.cursor-dot');
      if (cursor) {
        cursor.classList.remove('is-tap');
        void cursor.offsetWidth;
        if (nextStep >= 0) cursor.classList.add('is-tap');
      }
    }

    step = nextStep;
  }

  /* ── Dinámicas: cuenta atrás, descarga, variantes ────────── */
  const eventDemo = sceneById.get('a4')?.querySelector('.event');
  const cd = {
    w: document.getElementById('cdW'),
    d: document.getElementById('cdD'),
    h: document.getElementById('cdH'),
    m: document.getElementById('cdM'),
    s: document.getElementById('cdS')
  };
  const dlBar = document.getElementById('dlBar');
  const dlPct = document.getElementById('dlPct');
  const dlEta = document.getElementById('dlEta');
  const nwArticle = sceneById.get('a3')?.querySelector('.nw-article');
  const nwName = document.getElementById('nwAnimName');
  const nwChips = $$('.nw-variants [data-variant]');
  const NEWS_VARIANTS = [
    ['fade', 'Fundido'],
    ['rise', 'Subida'],
    ['zoom', 'Zoom'],
    ['slide', 'Lateral'],
    ['blur', 'Desenfoque'],
    ['flip', 'Volteo']
  ];

  if (nwArticle) nwArticle.dataset.anim = 'fade';

  function updateDynamics() {
    const ch = CHAPTERS[chapterIdx];

    /* Evento: cuenta atrás y retiro automático */
    if (ch && ch.id === 'a4' && eventDemo) {
      const step1Start = ch.steps[1];
      let remaining;
      if (t >= step1Start) {
        remaining = Math.max(0, 9.6 - (t - step1Start) * 2.55);
      } else {
        const base = 11 * 86400 + 7 * 3600 + 22 * 60 + 41;
        remaining = Math.max(0, base - (t - ch.start));
      }

      const total = Math.floor(remaining);
      const weeks = Math.floor(total / 604800);
      const days = Math.floor((total % 604800) / 86400);
      const hours = Math.floor((total % 86400) / 3600);
      const mins = Math.floor((total % 3600) / 60);
      const secs = total % 60;
      setText(cd.w, String(weeks).padStart(2, '0'));
      setText(cd.d, String(days).padStart(2, '0'));
      setText(cd.h, String(hours).padStart(2, '0'));
      setText(cd.m, String(mins).padStart(2, '0'));
      setText(cd.s, String(secs).padStart(2, '0'));

      const retired = t >= step1Start && remaining <= 0;
      eventDemo.classList.toggle('is-retired', retired);
    }

    /* Actualizaciones: descarga, progreso y cuenta regresiva */
    if (ch && ch.id === 'a1' && dlBar) {
      const startDownload = ch.steps[6];
      let pct = 0;
      if (t >= startDownload) {
        pct = Math.round(clamp((t - startDownload) / 3.15, 0, 1) * 100);
      }
      if (pct !== lastPct) {
        lastPct = pct;
        dlBar.style.width = `${pct}%`;
        setText(dlPct, `${pct}%`);
      }
      let eta;
      if (pct < 100) {
        eta = pct <= 0 ? 'Preparando descarga…' : `86,4 MB · ${(86.4 * (100 - pct) / 100).toFixed(1)} MB restantes`;
      } else {
        const left = Math.max(0, Math.ceil(ch.end - t));
        eta = left > 0 ? `Descarga completa · reinicio en ${left}…` : 'Listo para reiniciar';
      }
      if (eta !== lastEta) {
        lastEta = eta;
        setText(dlEta, eta);
      }
    }

    /* Noticias: variantes de animación de entrada */
    if (ch && ch.id === 'a3' && nwArticle) {
      const variantsStart = ch.steps[2];
      if (t >= variantsStart) {
        const idx = Math.floor((t - variantsStart) / 1.35) % NEWS_VARIANTS.length;
        if (idx !== newsIdx) {
          newsIdx = idx;
          const [key, label] = NEWS_VARIANTS[idx];
          nwArticle.dataset.anim = key;
          setText(nwName, label);
          nwChips.forEach(chip => chip.classList.toggle('is-active', chip.dataset.variant === key));
        }
      } else {
        newsIdx = -1;
        nwArticle.dataset.anim = 'fade';
        nwChips.forEach(chip => chip.classList.remove('is-active'));
      }
    }
  }

  /* ── Render principal ────────────────────────────────────── */
  function render() {
    const ci = chapterAt(t);
    if (ci !== chapterIdx) {
      enterChapter(ci, chapterIdx !== -1);
    }

    const ch = CHAPTERS[ci];
    const nextStep = stepAt(ch, t);
    if (nextStep !== step) {
      applyStep(ch, nextStep, step);
    }

    const ratio = clamp(t / TOTAL, 0, 1);
    fill.style.width = `${ratio * 100}%`;
    head.style.left = `${ratio * 100}%`;
    setText(tNow, formatTime(t));

    updateDynamics();
  }

  /* ── Reproductor ─────────────────────────────────────────── */
  function setPlayUI() {
    body.classList.toggle('is-playing', playing);
    body.classList.toggle('is-paused', !playing && !ended);
    btnPlay.setAttribute('aria-label', playing ? 'Pausar' : (ended ? 'Volver a reproducir' : 'Reproducir'));
    playState.textContent = playing ? 'REPRODUCIENDO' : (ended ? 'FIN' : 'EN PAUSA');
    playState.classList.toggle('is-paused', !playing);
  }

  function play() {
    if (ended || t >= TOTAL - 0.001) {
      ended = false;
      t = 0;
      chapterIdx = -1;
      step = -2;
      render();
    }
    playing = true;
    ended = false;
    audioWanted = btnSound.getAttribute('aria-pressed') === 'true';
    body.classList.remove('is-paused');
    setPlayUI();
    AudioEngine.setPlaying(true);
  }

  function pause(opts = {}) {
    playing = false;
    if (opts.freeze !== false) body.classList.add('is-paused');
    setPlayUI();
    AudioEngine.setPlaying(false);
  }

  function togglePlay() {
    if (playing) pause();
    else play();
  }

  function seek(seconds, opts = {}) {
    t = clamp(seconds, 0, TOTAL);
    ended = t >= TOTAL - 0.001;
    body.classList.remove('is-paused');
    if (opts.restart && chapterIdx >= 0) {
      const scene = sceneById.get(CHAPTERS[chapterIdx].id);
      if (scene) {
        scene.classList.remove('is-active');
        void scene.offsetWidth;
        scene.classList.add('is-active');
      }
      step = -2;
    }
    // Si el capítulo cambia estando pausado, dejar correr las animaciones
    render();
    setPlayUI();
  }

  btnPlay.addEventListener('click', togglePlay);
  btnRestart.addEventListener('click', () => {
    seek(0, { restart: true });
    play();
  });

  /* barra de progreso */
  function seekFromPointer(e) {
    const rect = rail.getBoundingClientRect();
    const ratio = clamp((e.clientX - rect.left) / rect.width, 0, 1);
    seek(ratio * TOTAL);
  }
  rail.addEventListener('pointerdown', e => {
    scrubbing = true;
    rail.setPointerCapture?.(e.pointerId);
    seekFromPointer(e);
  });
  rail.addEventListener('pointermove', e => {
    if (scrubbing) seekFromPointer(e);
  });
  const endScrub = () => { scrubbing = false; };
  rail.addEventListener('pointerup', endScrub);
  rail.addEventListener('pointercancel', endScrub);
  window.addEventListener('pointerup', endScrub);

  /* sonido */
  let audioWanted = false;
  btnSound.addEventListener('click', () => {
    const want = btnSound.getAttribute('aria-pressed') !== 'true';
    if (want) {
      if (!AudioEngine.setEnabled(true)) {
        btnSound.title = 'Este navegador no permite audio';
        return;
      }
      audioWanted = true;
      btnSound.setAttribute('aria-pressed', 'true');
      btnSound.setAttribute('aria-label', 'Desactivar sonido');
      AudioEngine.setPlaying(playing);
    } else {
      audioWanted = false;
      AudioEngine.setEnabled(false);
      btnSound.setAttribute('aria-pressed', 'false');
      btnSound.setAttribute('aria-label', 'Activar sonido');
    }
  });

  /* pantalla completa */
  async function toggleFullscreen() {
    try {
      if (!document.fullscreenElement) {
        await viewport.requestFullscreen();
      } else {
        await document.exitFullscreen();
      }
    } catch {
      /* sin permisos o no soportado */
    }
  }
  btnFull.addEventListener('click', toggleFullscreen);
  document.addEventListener('fullscreenchange', () => {
    body.classList.toggle('is-fullscreen', Boolean(document.fullscreenElement));
    fit();
  });

  /* teclado */
  window.addEventListener('keydown', e => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const tag = (e.target.tagName || '').toUpperCase();
    if (e.code === 'Space') {
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || tag === 'BUTTON' || tag === 'A') return;
      e.preventDefault();
      togglePlay();
    } else if (e.key === 'ArrowRight') {
      e.preventDefault();
      seek(t + 5);
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      seek(t - 5);
    } else if (e.key === 'r' || e.key === 'R') {
      seek(0, { restart: true });
      play();
    } else if (e.key === 'f' || e.key === 'F') {
      toggleFullscreen();
    } else if (e.key === 'm' || e.key === 'M') {
      btnSound.click();
    }
  });

  /* ── Loop maestro ────────────────────────────────────────── */
  let last = performance.now();
  let lastTimer = t;

  function loop(now) {
    const dt = Math.min(0.1, Math.max(0, (now - last) / 1000));
    last = now;

    if (playing) {
      t = Math.min(TOTAL, t + dt);
      if (t !== lastTimer) {
        render();
        lastTimer = t;
      }
      drawStars(dt);

      if (t >= TOTAL) {
        playing = false;
        ended = true;
        body.classList.remove('is-playing');
        setPlayUI();
        AudioEngine.setPlaying(false);
        drawStars(0);
      }
    }

    requestAnimationFrame(loop);
  }

  /* ── Boot ────────────────────────────────────────────────── */
  function boot() {
    if (booted) return;
    booted = true;
    render();
    loader.classList.add('is-done');
    setTimeout(() => { loader.style.display = 'none'; }, 900);
    setPlayUI();

    if (autoplay) {
      setTimeout(() => {
        if (!playing) play();
      }, 550);
    }
  }

  window.addEventListener('load', () => setTimeout(boot, 650));
  setTimeout(boot, 4200);

  /* ── Inicialización ──────────────────────────────────────── */
  setText(tTotal, formatTime(TOTAL));
  setText(tNow, formatTime(t));
  setPlayUI();
  sizeCanvas();
  initStars();
  fit();
  window.addEventListener('resize', () => {
    fit();
    sizeCanvas();
    initStars();
  });
  drawStars(0);

  // Estado inicial sin capítulo activo hasta que termine el loader.
  // Si se pidió un instante por URL, prepararlo ya.
  if (params.has('t')) {
    render();
  }

  // API mínima para pruebas y control externo
  window.OWS_REEL = {
    play,
    pause,
    seek: (seconds, opts) => seek(seconds, opts),
    get time() { return t; },
    get duration() { return TOTAL; },
    get playing() { return playing; },
    chapters: CHAPTERS
  };

  requestAnimationFrame(loop);
})();
