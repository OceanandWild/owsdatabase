// OWS Hub — Biblioteca local (solo app desktop Tauri).
// En navegador hace fallback a descarga clásica por <a href>.
// Estado de instalados: localStorage ows_hub_installed { slug: { version, exePath, dir } }.

(function () {
  'use strict';

  const STORE_KEY = 'ows_hub_installed';

  // NOTA: withGlobalTauri está desactivado en tauri.conf.json,
  // así que window.__TAURI__ no existe en el WebView. Se usan los puentes
  // que Tauri v2 sí inyecta siempre (__TAURI_INTERNALS__) + WebView2.
  function isTauriWebview() {
    try {
      if (window.__TAURI__ && window.__TAURI__.core) return true;
      if (window.__TAURI_INTERNALS__ && typeof window.__TAURI_INTERNALS__.invoke === 'function') return true;
      if (window.chrome && window.chrome.webview) return true;
    } catch (_) {}
    return false;
  }

  function isDesktop() {
    return isTauriWebview();
  }

  // App Android (Capacitor): aquí no hay puente Tauri ni carpetas de Windows.
  // getPlatform() solo existe en la web empaquetada como app nativa.
  function isAndroidNative() {
    try {
      const cap = window.Capacitor;
      return !!(cap && typeof cap.getPlatform === 'function' && cap.getPlatform() === 'android');
    } catch (_) { return false; }
  }

  // Resuelve el puente UNA vez. OJO: el `await invoke(...)` va FUERA del try;
  // si el comando Rust falla (no existe, ruta inválida, juego abierto…) ese
  // error es real y debe llegar a la UI. Si se captura aquí, el código caía al
  // import ESM y devolvía "Failed to resolve module specifier
  // '@tauri-apps/api/core'", que oculta el motivo de verdad.
  function resolveInvoker() {
    try {
      const core = window.__TAURI__ && window.__TAURI__.core;
      if (core && typeof core.invoke === 'function') return core.invoke.bind(core);
    } catch (_) {}
    try {
      const internals = window.__TAURI_INTERNALS__;
      if (internals && typeof internals.invoke === 'function') {
        return (cmd, args) => internals.invoke(cmd, args);
      }
    } catch (_) {}
    return null;
  }

  const tauriInvoke = resolveInvoker();

  async function invoke(cmd, args) {
    // En Android no existe el binario del Hub: se corta acá con un mensaje
    // claro (sin intentar importar el módulo ESM de Tauri, que daría 404).
    if (isAndroidNative()) {
      throw new Error('Esta acción solo existe en OWS Hub para PC.');
    }
    if (tauriInvoke) return tauriInvoke(cmd, args || {});
    // Sin puente: el import ESM solo funciona con bundler/importmap.
    const mod = await import('@tauri-apps/api/core');
    return mod.invoke(cmd, args || {});
  }

  // El binario del Hub es más viejo que el frontend: el comando no existe.
  function isMissingCommand(err) {
    const msg = String((err && err.message) || err || '').toLowerCase();
    return /unknown command|not found|no command|command .* not allowed|not registered/.test(msg)
      || /module specifier/.test(msg);
  }

  // v3.4.5: con timeout. Si el puente de eventos no responde en 15 s, se
  // sigue igual SIN % en vivo (no-op) en vez de dejar la instalación
  // colgada en "Conectando…" para siempre.
  async function listenDownloadProgress(handler, timeoutMs) {
    const ms = Number(timeoutMs) || 15000;
    const work = (async () => {
      const ev = window.__TAURI__ && window.__TAURI__.event;
      if (ev && typeof ev.listen === 'function') {
        return await ev.listen('ows-download-progress', (e) => handler(e.payload));
      }
      const mod = await import('@tauri-apps/api/event');
      return await mod.listen('ows-download-progress', (e) => handler(e.payload));
    })();
    let timer = null;
    let timedOut = false;
    try {
      return await Promise.race([
        work,
        new Promise((_, rej) => { timer = setTimeout(() => { timedOut = true; rej(new Error('listen-timeout')); }, ms); }),
      ]);
    } catch (_) {
      // Sin puente de eventos (binario sin withGlobalTauri ni importmap)
      // o timeout: devuelve unlisten no-op para no romper la instalación
      // (solo sin % en vivo).
      return function () {};
    } finally {
      try { if (timer) clearTimeout(timer); } catch (_) {}
      // Solo si ganó el timeout y el listen llega tarde: se libera
      // enseguida para no duplicar eventos de progreso.
      if (timedOut) {
        try { work.then((u) => { if (typeof u === 'function') u(); }).catch(() => {}); } catch (_) {}
      }
    }
  }

  function loadStore() {
    try {
      return JSON.parse(localStorage.getItem(STORE_KEY) || '{}') || {};
    } catch (_) {
      return {};
    }
  }

  function saveStore(data) {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(data || {}));
    } catch (_) {}
  }

  function downloadUrlFor(slug) {
    const base = (typeof API_BASE !== 'undefined' && API_BASE) || 'https://owsdatabase.onrender.com';
    return `${base}/ows-launch-projects/${encodeURIComponent(slug)}/download`;
  }

  function findProject(slug) {
    const cache = (typeof releasesCache !== 'undefined' && Array.isArray(releasesCache)) ? releasesCache : [];
    return cache.find((x) => String(x.slug) === String(slug)) || null;
  }

  // Carpeta personalizada del setup (ows_settings_v1). Solo vale en desktop
  // con downloadMode 'custom' y ruta con pinta de absoluta.
  function customLibraryBase() {
    try {
      if (window.OWSSettings && window.OWSSettings.downloadMode === 'custom') {
        const d = String(window.OWSSettings.downloadDir || '').trim();
        if (/^([a-zA-Z]:[\\/]|\\\\|\/)/.test(d)) return d.replace(/[/\\]+$/, '');
      }
      const raw = localStorage.getItem('ows_settings_v1');
      if (raw) {
        const s = JSON.parse(raw);
        if (s && s.downloadMode === 'custom') {
          const d = String(s.downloadDir || '').trim();
          if (/^([a-zA-Z]:[\\/]|\\\\|\/)/.test(d)) return d.replace(/[/\\]+$/, '');
        }
      }
    } catch (_) {}
    return '';
  }

  // TODAS las carpetas que el Hub reconoce como biblioteca: la del modo
  // 'custom' + cualquier ruta absoluta guardada en el setup. El comando Rust
  // solo borra hijas directas de alguna de estas, así que incluirlas no
  // abre la puerta a borrar nada fuera del ecosistema.
  function libraryBases() {
    const out = [];
    const push = (v) => {
      const d = String(v || '').trim();
      if (!d) return;
      if (!/^([a-zA-Z]:[\\/]|\\\\|\/)/.test(d)) return; // solo absolutas
      const clean = d.replace(/[/\\]+$/, '');
      if (clean && !out.includes(clean)) out.push(clean);
    };
    push(customLibraryBase());
    try {
      if (window.OWSSettings) push(window.OWSSettings.downloadDir);
      const raw = localStorage.getItem('ows_settings_v1');
      if (raw) push(JSON.parse(raw).downloadDir);
    } catch (_) {}
    return out;
  }

  // ── Comparación de versiones (semver-lite) ──
  // Espejo de compareVersionStrings() del server.js: "3.1.10" > "3.1.9"
  // (numérico, no lexicográfico) y 1.0.0 > 1.0.0-beta. Sin dato no se
  // puede ordenar, así que devuelve 0 (trátalo como "sin cambio").
  function parseVersionParts(value) {
    const raw = String(value == null ? '' : value).trim().replace(/^[vV]/, '');
    if (!raw) return null;
    // Núcleo numérico + pre-release + build metadata. El build metadata
    // (+build5) no ordena: 1.0.0 y 1.0.0+build5 son la misma versión.
    const m = raw.match(/^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/);
    if (!m) return null;
    const nums = m[1].split('.').map((n) => Number(n));
    while (nums.length < 3) nums.push(0);
    return { nums: nums.slice(0, 4), pre: m[2] || '' };
  }

  function compareVersions(a, b) {
    const pa = parseVersionParts(a);
    const pb = parseVersionParts(b);
    if (!pa && !pb) return 0;
    if (!pa) return -1;
    if (!pb) return 1;
    const len = Math.max(pa.nums.length, pb.nums.length);
    for (let i = 0; i < len; i += 1) {
      const na = Number(pa.nums[i] || 0);
      const nb = Number(pb.nums[i] || 0);
      if (na !== nb) return na > nb ? 1 : -1;
    }
    if (pa.pre === pb.pre) return 0;
    if (!pa.pre) return 1;
    if (!pb.pre) return -1;
    const as = pa.pre.split('.');
    const bs = pb.pre.split('.');
    for (let i = 0; i < Math.max(as.length, bs.length); i += 1) {
      if (i >= as.length) return -1;
      if (i >= bs.length) return 1;
      if (as[i] === bs[i]) continue;
      const na = /^\d+$/.test(as[i]) ? Number(as[i]) : null;
      const nb = /^\d+$/.test(bs[i]) ? Number(bs[i]) : null;
      if (na !== null && nb !== null) return na > nb ? 1 : -1;
      if (na !== null) return -1;
      if (nb !== null) return 1;
      return String(as[i]) > String(bs[i]) ? 1 : -1;
    }
    return 0;
  }

  // Versión real que se instala: manda la release oficial publicada en el
  // Admin (ows_project_releases) y la de itch.io queda de backup.
  function resolveRemoteVersion(project) {
    const p = project || {};
    const rel = p.latest_release || p.latestRelease || null;
    const fromRelease = rel && rel.version ? String(rel.version).trim() : '';
    if (fromRelease) return fromRelease;
    return String(p.itch_version || p.itchVersion || '').trim();
  }

  const OWSHubLibrary = {
    isDesktop: isDesktop(),

    installed(slug) {
      const store = loadStore();
      return store[String(slug)] || null;
    },

    markInstalled(slug, info) {
      const store = loadStore();
      store[String(slug)] = info;
      saveStore(store);
    },

    localVersion(slug) {
      const inst = this.installed(slug);
      return inst ? String(inst.version || '') : '';
    },

    needsUpdate(slug, remoteVersion) {
      const local = this.localVersion(slug);
      if (!local) return false; // no instalado → no es "update", es "instalar"
      const remote = String(remoteVersion || '').trim();
      if (!remote) return false;
      // Comparación semver: si la remota es más nueva (comparación > 0) hay
      // update. Con comparación por texto, 0.1.10 < 0.1.9 y el gestor
      // ofrecería "actualizar" para siempre.
      const cmp = compareVersions(remote, local);
      if (cmp > 0) return true;
      // Si la remota no se puede parsear (build de itch con nombre raro) se
      // cae a la comparación por texto de siempre.
      if (cmp === 0 && !parseVersionParts(remote) && remote !== local) return true;
      return false;
    },

    // ── Biblioteca: listar y desinstalar ──
    installedList() {
      const store = loadStore();
      return Object.keys(store).map((slug) => Object.assign({ slug }, store[slug]));
    },

    installedSizeBytes(slug) {
      const inst = this.installed(slug);
      if (!inst || !inst.dir) return Promise.resolve(0);
      return invoke('game_dir_size', { dir: inst.dir })
        .then((n) => Number(n) || 0)
        .catch(() => 0);
    },

    // Borra la carpeta del juego de la biblioteca del Hub y lo forgets del store.
    // onEvent({ type: 'done'|'error', ... }) para la UI. El borrado real lo hace
    // `uninstall_game`, que valida que la ruta sea una carpeta de juego real.
    async uninstall(slug, onEvent) {
      const emit = (e) => { try { onEvent && onEvent(e); } catch (_) {} };
      if (!this.isDesktop) throw new Error('Solo la app OWS Hub puede desinstalar juegos.');
      const inst = this.installed(slug);
      if (!inst || !inst.dir) throw new Error('Este juego no está instalado desde el Hub.');

      const bases = libraryBases();
      try {
        const res = await invoke('uninstall_game', {
          dir: inst.dir,
          libraryBases: bases.length ? bases : null,
        });
        const store = loadStore();
        delete store[String(slug)];
        saveStore(store);
        emit({ type: 'done', dir: (res && res.dir) || '', bytes: Number((res && res.bytes) || 0), deleted: !!(res && res.deleted), pending: (res && res.pending) || '' });
        return res || { dir: '', bytes: 0, deleted: true, pending: '' };
      } catch (err) {
        if (isMissingCommand(err)) {
          const friendly = new Error('Tu OWS Hub está desactualizado: actualízalo para poder desinstalar.');
          emit({ type: 'error', error: friendly.message, missingCommand: true });
          throw friendly;
        }
        emit({ type: 'error', error: String((err && err.message) || err) });
        throw err;
      }
    },

    // Barre las carpetas que una desinstalación anterior dejó a medias
    // ("<slug>.__borrando__"): con la app ya cerrada no hay Handles abiertos.
    sweepPendingRemovals() {
      if (!this.isDesktop) return Promise.resolve(0);
      return invoke('sweep_pending_removals', {})
        .then((n) => Number(n) || 0)
        .catch(() => 0);
    },

    // Desinstalación forzada: borra la carpeta que conste en el store aunque
    // el Hub no la reconozca como biblioteca suya (ruta movida o vieja), y
    // limpia el registro. Es el salida para no dejar al usuario atrapado.
    async forget(slug) {
      const inst = this.installed(slug);
      const store = loadStore();
      let removed = false;
      if (inst && inst.dir) {
        try {
          const bases = libraryBases();
          await invoke('uninstall_game', { dir: inst.dir, libraryBases: bases.length ? bases : null });
          removed = true;
        } catch (err) {
          if (isMissingCommand(err)) {
            throw new Error(
              'Esta versión del Hub no puede borrar la carpeta. Bórrala a mano desde el explorador: ' + inst.dir
            );
          }
          throw err;
        }
      }
      delete store[String(slug)];
      saveStore(store);
      return removed;
    },

    // v3.4.5: cancelación REAL. Antes el Gestor solo marcaba la tarjeta y
    // el Rust seguía descargando (y podía pisar el archivo de un reintento).
    cancel(slug) {
      if (!this.isDesktop) return Promise.resolve(false);
      return invoke('cancel_download', { slug: String(slug || '') })
        .then((v) => !!v)
        .catch(() => false);
    },

    async launch(slug) {
      if (isAndroidNative()) {
        throw new Error('En Android abrí el juego desde el menú de tu teléfono.');
      }
      const inst = this.installed(slug);
      if (!inst || !inst.exePath) throw new Error('Juego no instalado');
      if (!this.isDesktop) {
        window.open(downloadUrlFor(slug), '_blank', 'noopener');
        return;
      }
      await invoke('launch_game', { exePath: inst.exePath });
    },

    // Flujo launcher 1-clic: descargar ZIP real de itch.io → extraer todo → ejecutar.
    // Hace TODO sin que el usuario intervenga: al terminar, el juego ya está abierto.
    // onEvent({ type: 'status'|'progress'|'done'|'error', phase, ... }) para la UI.
    // opts: { version } → fuerza la versión que queda registrada al instalar.
    async downloadAndInstall(slug, onEvent, opts) {
      const emit = (e) => { try { onEvent && onEvent(e); } catch (_) {} };
      if (isAndroidNative()) {
        // El flujo Android es el canal APK (botón "Descargar e instalar APK").
        const friendly = new Error('En Android las descargas van por el APK del proyecto.');
        emit({ type: 'error', error: friendly.message });
        throw friendly;
      }
      const project = findProject(slug) || {};
      // La versión que se REGISTRA al instalar tiene que ser la misma que el
      // Gestor de Actualizaciones va a comparar después. Si se guardara la de
      // itch.io mientras el Admin ya publicó una release más nueva, el juego
      // aparecería para actualizar indefinidamente.
      // `opts.version` gana: el Gestor de Actualizaciones ya consultó la
      // release oficial y la pasa explícita, así el registro nunca queda
      // desfasado aunque releasesCache todavía no la tenga.
      const passedVersion = opts && opts.version ? String(opts.version).trim() : '';
      const version = passedVersion || resolveRemoteVersion(project);
      // Lo que se descarga es el ZIP; el ejecutable jugable va DENTRO.
      // Se pide el .exe (metadata.itch.file / download.exe), no el ZIP.
      const art = (project.download && typeof project.download === 'object') ? project.download : {};
      const preferredExe = String(
        art.exe || project.exe_file
        || (/\.exe$/i.test(String(project.itch_file || project.itchFile || '')) ? (project.itch_file || project.itchFile) : '')
        || `${slug}.exe`
      );

      if (!this.isDesktop) {
        // En navegador no se puede extraer/ejecutar por seguridad:
        // se fuerza la descarga del ZIP real y el usuario lo abre manual.
        const a = document.createElement('a');
        a.href = downloadUrlFor(slug);
        a.download = `${slug}.zip`;
        a.rel = 'noopener';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { try { a.remove(); } catch (_) {} }, 1000);
        emit({ type: 'done', fallback: true });
        return;
      }

      let unlisten = null;
      try {
        unlisten = await listenDownloadProgress((p) => {
          if (String(p.slug) !== String(slug)) return;
          emit({ type: 'progress', phase: 'downloading', downloaded: p.downloaded, total: p.total });
        });

        // 1) Descargar ZIP real (el servidor lo resuelve de itch.io vía ITCH_API_KEY)
        emit({ type: 'status', phase: 'downloading', zipSize: String(art.size || '') });
        const zipPath = await invoke('download_installer', { slug, url: downloadUrlFor(slug) });

        // 2) Extraer TODO el contenido a <biblioteca>/<slug>/
        //    Si el usuario personalizó su carpeta en el setup, se extrae AHÍ
        //    (extract_zip acepta cualquier ruta; el ZIP temporal sí queda en
        //    la biblioteca por defecto porque download_installer lo fija).
        emit({ type: 'status', phase: 'extracting' });
        const customBase = customLibraryBase();
        let cleanBase;
        if (customBase) {
          cleanBase = customBase;
        } else {
          const libDir = await invoke('get_library_dir', {});
          cleanBase = String(libDir || '').replace(/[/\\]+$/, '');
        }
        const destDir = `${cleanBase}/${slug}`;
        await invoke('extract_zip', { zipPath, destDir });

        // 3) Detectar el .exe jugable (ignora UnityCrashHandler/stockfish internos).
        //    find_game_exe es nuevo: si el Hub desktop está desactualizado, cae al
        //    nombre preferido de la DB como fallback.
        emit({ type: 'status', phase: 'searching' });
        let exePath = `${destDir}/${preferredExe}`;
        try {
          exePath = await invoke('find_game_exe', { destDir, preferred: preferredExe });
        } catch (_) {
          // Fallback: intenta coincidencia insensible a mayúsculas en raíz
          try {
            const withBackslash = String(destDir).replace(/\//g, '\\');
            exePath = await invoke('find_game_exe', { destDir: withBackslash, preferred: preferredExe });
          } catch (e2) {
            // Si ni siquiera existe el comando (Hub viejo), usa el preferido tal cual
            const msg = String((e2 && e2.message) || e2 || '');
            if (/unknown|no command|not found/i.test(msg)) {
              exePath = `${destDir}/${preferredExe}`;
            } else {
              throw e2;
            }
          }
        }

        this.markInstalled(slug, { version, exePath, dir: destDir, at: new Date().toISOString() });

        // 4) Ejecutar el juego automáticamente (sin segundo clic)
        emit({ type: 'status', phase: 'launching', exePath });
        await invoke('launch_game', { exePath });

        emit({ type: 'done', exePath, version, autoLaunched: true });
      } catch (err) {
        emit({ type: 'error', error: String((err && err.message) || err) });
        throw err;
      } finally {
        try { unlisten && unlisten(); } catch (_) {}
      }
    }
  };

  window.OWSHub = { isDesktop: OWSHubLibrary.isDesktop, isAndroid: isAndroidNative(), downloadUrlFor };
  window.OWSHubLibrary = OWSHubLibrary;

  // Progreso de descarga/instalación para el modal (bare global usado por app.js).
  // Fases: downloading → extracting → searching → launching → done (auto-ejecutado).
  window.OWSHubInstallProgress = function (e) {
    const note = document.getElementById('owshub-install-note');
    const bar = document.getElementById('owshub-install-bar');
    const pctLabel = document.getElementById('owshub-install-pct');
    const setBar = (pct) => {
      if (bar) {
        bar.style.width = `${Math.max(0, Math.min(100, pct))}%`;
        bar.setAttribute('aria-valuenow', String(Math.round(pct)));
      }
      if (pctLabel) pctLabel.textContent = `${Math.round(pct)}%`;
    };
    if (!note) return;
    if (e.type === 'status') {
      if (e.phase === 'downloading') {
        const zs = String(e.zipSize || '').trim();
        note.textContent = zs
          ? `⬇ Descargando ZIP oficial de itch.io (${zs})…`
          : '⬇ Descargando ZIP oficial de itch.io…';
        setBar(2);
      } else if (e.phase === 'extracting') {
        note.textContent = '📦 Extrayendo todos los archivos…';
        setBar(100);
      } else if (e.phase === 'searching') {
        note.textContent = '🔍 Localizando el ejecutable…';
      } else if (e.phase === 'launching') {
        note.textContent = '🚀 Ejecutando el juego…';
        setBar(100);
      }
    } else if (e.type === 'progress') {
      if (e.total > 0) {
        const pct = Math.round((e.downloaded / e.total) * 100);
        note.textContent = `⬇ Descargando… ${pct}% (${(e.downloaded / 1048576).toFixed(1)} / ${(e.total / 1048576).toFixed(1)} MB)`;
        setBar(pct);
      } else {
        note.textContent = `⬇ Descargando… ${(e.downloaded / 1048576).toFixed(1)} MB`;
      }
    } else if (e.type === 'done') {
      if (e.fallback) {
        note.textContent = '⬇ Descarga iniciada en el navegador. Extrae el ZIP y abre el .exe.';
      } else if (e.browserDownload) {
        note.textContent = '✓ ¡Descarga completa! Extrae el ZIP y abre el .exe ▶';
        setBar(100);
      } else {
        note.textContent = '¡Listo! El juego se está abriendo ▶';
        setBar(100);
      }
      setTimeout(() => { try { closeReleaseModal(); } catch (_) {} }, 1600);
    } else if (e.type === 'error') {
      note.textContent = `Error: ${e.error || 'descarga fallida'}`;
    }
  };
})();
