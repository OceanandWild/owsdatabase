/* ============================================================
   WaverNote · actualizaciones por dispositivo
   - Windows: plugin updater de Tauri + instalador NSIS firmado.
   - Android: canal APK estático (descarga verificada + instalador).
   - Web: solo muestra la versión; las actualizaciones se aplican
     desde la app instalada.
   ============================================================ */

(() => {
  const RAW_BASE = "https://raw.githubusercontent.com/OceanandWild/owsdatabase/main/";
  const CDN_BASE = "https://cdn.jsdelivr.net/gh/OceanandWild/owsdatabase@main/";
  const CHECK_TIMEOUT_MS = 20000;
  const AUTO_CHECK_DELAY_MS = 4000;
  const NOTIFIED_KEY = "wavernote.updateNotified.v1";
  // Changelog estructurado de la versión disponible: vive en el servidor,
  // junto al resto de los datos de WaverNote.
  const CHANGELOG_PROJECT = "wavernote";
  const CHANGELOG_LIMIT = 12;
  const CHANGELOG_TIMEOUT_MS = 10000;

  const state = {
    platform: "web", // windows | android | web | other
    localVersion: "",
    update: null, // { version, notes, date, url?, sha256?, sizeBytes?, fileName? }
    changelog: null, // changelog estructurado de state.update.version
    changelogShown: false, // el modal del changelog se muestra una vez por arranque
    status: "idle", // idle | checking | current | available | downloading | ready | error
    message: "",
    progress: 0,
    checking: false,
    busy: false,
    checkedAt: 0,
  };

  const getCore = () => (window.__TAURI__ && window.__TAURI__.core) || null;

  const isTauri = () => {
    const core = getCore();
    return Boolean(core && typeof core.invoke === "function");
  };

  const detectPlatform = () => {
    if (!isTauri()) return "web";
    if (/Android/i.test(navigator.userAgent || "")) return "android";
    if (/Windows/i.test(navigator.userAgent || "")) return "windows";
    return "other";
  };

  const invoke = (command, args) => {
    const core = getCore();
    if (!core) return Promise.reject(new Error("Abrí WaverNote desde la app instalada."));
    return core.invoke(command, args || {});
  };

  const withTimeout = (promise, ms) =>
    new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => reject(new Error("timeout")), ms);
      Promise.resolve(promise).then(
        (value) => {
          window.clearTimeout(timer);
          resolve(value);
        },
        (err) => {
          window.clearTimeout(timer);
          reject(err);
        }
      );
    });

  const metaVersion = () =>
    String(document.querySelector('meta[name="wavernote-version"]')?.content || "").trim();

  const loadLocalVersion = async () => {
    if (!isTauri()) return metaVersion();
    try {
      const info = await withTimeout(invoke("app_info"), 6000);
      const version = String(info?.version || "").trim();
      if (version) return version;
    } catch (err) {
      /* sin puente: cae al meta del HTML */
    }
    return metaVersion();
  };

  /* ------------------------------------------------------------
     Versiones
     ------------------------------------------------------------ */

  const parseVersion = (value) => {
    const match = String(value || "")
      .trim()
      .replace(/^[vV]/, "")
      .match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
    if (!match) return null;
    return {
      parts: [Number(match[1]), Number(match[2]), Number(match[3])],
      pre: match[4] ? match[4].split(".") : [],
    };
  };

  // Semver simplificado: 1.0.1-beta < 1.0.1. Devuelve 1 si a > b.
  const compareVersions = (a, b) => {
    const va = parseVersion(a);
    const vb = parseVersion(b);
    if (!va || !vb) {
      const sa = String(a || "").replace(/^[vV]/, "");
      const sb = String(b || "").replace(/^[vV]/, "");
      if (sa === sb) return 0;
      return sa > sb ? 1 : -1;
    }
    for (let i = 0; i < 3; i += 1) {
      if (va.parts[i] !== vb.parts[i]) return va.parts[i] > vb.parts[i] ? 1 : -1;
    }
    if (!va.pre.length && !vb.pre.length) return 0;
    if (!va.pre.length) return 1;
    if (!vb.pre.length) return -1;
    const total = Math.max(va.pre.length, vb.pre.length);
    for (let i = 0; i < total; i += 1) {
      const x = va.pre[i];
      const y = vb.pre[i];
      if (x === undefined) return -1;
      if (y === undefined) return 1;
      const nx = Number(x);
      const ny = Number(y);
      const xNum = Number.isFinite(nx);
      const yNum = Number.isFinite(ny);
      if (xNum && yNum) {
        if (nx !== ny) return nx > ny ? 1 : -1;
      } else if (xNum !== yNum) {
        return xNum ? -1 : 1;
      } else if (x !== y) {
        return x > y ? 1 : -1;
      }
    }
    return 0;
  };

  /* ------------------------------------------------------------
     Consulta de actualizaciones
     ------------------------------------------------------------ */

  const fetchJson = async (paths, timeoutMs = CHECK_TIMEOUT_MS) => {
    let lastError = null;
    for (const path of paths) {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(path, { cache: "no-store", signal: controller.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        window.clearTimeout(timer);
        return data;
      } catch (err) {
        window.clearTimeout(timer);
        lastError = err;
      }
    }
    throw lastError || new Error("sin conexión");
  };

  // El changelog vive en el backend de WaverNote, el mismo que usa la
  // biblioteca. API_BASE lo define core.js; el fallback cubre el caso de que
  // el script se cargue aislado.
  const apiBase = () => {
    try {
      if (typeof API_BASE === "string" && API_BASE) return API_BASE;
    } catch (err) {
      /* noop */
    }
    return "https://owsdatabase.onrender.com";
  };

  // Changelog estructurado de una versión concreta. Si la versión no está
  // publicada todavía, devuelve null y se usan las notas de la release.
  const fetchChangelog = async (version) => {
    const wanted = String(version || "").trim().replace(/^[vV]/, "");
    if (!wanted) return null;

    const url = `${apiBase()}/ows-store/projects/${CHANGELOG_PROJECT}/changelogs?limit=${CHANGELOG_LIMIT}`;
    const data = await fetchJson([url], CHANGELOG_TIMEOUT_MS);
    const list = Array.isArray(data?.changelogs) ? data.changelogs : [];
    const match = list.find(
      (entry) => String(entry?.version || "").trim().replace(/^[vV]/, "") === wanted
    );
    return match || null;
  };

  const checkWindows = async (localVersion) => {
    const meta = await withTimeout(invoke("plugin:updater|check", {}), CHECK_TIMEOUT_MS);
    if (!meta || typeof meta !== "object") return null;

    const version = String(meta.version || "").trim().replace(/^[vV]/, "");
    if (!version) return null;
    const current = String(meta.currentVersion || localVersion || "")
      .trim()
      .replace(/^[vV]/, "");
    if (compareVersions(version, current) <= 0) return null;

    return {
      version,
      currentVersion: current,
      notes: String(meta.body || ""),
      date: String(meta.date || ""),
      platform: "windows",
    };
  };

  const checkAndroid = async (localVersion) => {
    const manifest = await fetchJson([
      `${RAW_BASE}wavernote-android-update.json`,
      `${CDN_BASE}wavernote-android-update.json`,
    ]);
    const version = String(manifest?.version_name || "").trim();
    const apkUrl = String(manifest?.apk_url || "").trim();
    if (!version || !apkUrl) return null;

    // El APK tiene que ser de WaverNote y traer hash: sin eso no se instala
    // nada, aunque el manifiesto venga de nuestro repo.
    const packageId = String(manifest?.package_id || "").trim();
    if (packageId && packageId !== "com.oceanwildstudios.wavernote") {
      throw new Error("El manifiesto de Android pertenece a otra app.");
    }
    const sha256 = String(manifest?.sha256 || "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      throw new Error("El manifiesto de Android no tiene un SHA-256 válido.");
    }
    if (compareVersions(version, localVersion) <= 0) return null;

    return {
      version,
      currentVersion: localVersion,
      notes: String(manifest.release_notes || ""),
      date: String(manifest.published_at || ""),
      url: apkUrl,
      sha256,
      sizeBytes: Number(manifest.size_bytes) || 0,
      fileName: `WaverNote_${version}_universal.apk`,
      platform: "android",
    };
  };

  const checkForUpdate = async (options = {}) => {
    if (state.checking || state.busy) return state.update;
    if (state.platform !== "windows" && state.platform !== "android") {
      state.status = "idle";
      state.message =
        state.platform === "web"
          ? "Abrí WaverNote desde su versión instalada para recibir actualizaciones."
          : "Este dispositivo no admite actualizaciones automáticas.";
      paint();
      return null;
    }

    state.checking = true;
    state.status = "checking";
    state.message = options.silent ? "" : "Buscando actualizaciones…";
    paint();

    try {
      const localVersion = state.localVersion || (await loadLocalVersion());
      state.localVersion = localVersion;
      const update =
        state.platform === "windows"
          ? await checkWindows(localVersion)
          : await checkAndroid(localVersion);

      state.checkedAt = Date.now();
      if (update) {
        state.update = update;
        state.status = "available";
        state.message = `Hay una versión nueva disponible: v${update.version}.`;
        if (shouldNotify(update.version)) notifyAvailable(update);

        // Changelog de esa versión: va en el panel de actualizaciones y, si
        // todavía no se mostró en este arranque, se abre solo en un modal.
        state.changelog = null;
        try {
          state.changelog = await fetchChangelog(update.version);
        } catch (err) {
          state.changelog = null;
        }
        maybeShowChangelogModal();
      } else {
        state.update = null;
        state.changelog = null;
        state.status = "current";
        state.message = "Estás usando la última versión.";
        if (options.silent) state.message = "";
      }
    } catch (err) {
      state.update = null;
      state.status = options.silent ? "idle" : "error";
      state.message = options.silent ? "" : friendlyUpdateError(err);
    } finally {
      state.checking = false;
      paint();
    }
    return state.update;
  };

  const shouldNotify = (version) => {
    try {
      if (localStorage.getItem(NOTIFIED_KEY) === String(version)) return false;
      localStorage.setItem(NOTIFIED_KEY, String(version));
      return true;
    } catch (err) {
      return true;
    }
  };

  const notifyAvailable = (update) => {
    if (typeof toast !== "function") return;
    const where = update.platform === "android" ? "Android" : "Windows";
    toast(`WaverNote v${update.version} disponible para ${where}. Abrí Actualizaciones para instalarla.`);
  };

  /* ------------------------------------------------------------
     Aplicar la actualización
     ------------------------------------------------------------ */

  const applyUpdate = async () => {
    if (state.busy) return;
    if (!state.update && state.platform !== "windows") {
      await checkForUpdate();
      if (!state.update) return;
    }

    state.busy = true;
    state.status = "downloading";
    state.progress = 0;
    state.message = "Preparando la descarga…";
    paint();

    try {
      if (state.platform === "windows") await applyWindowsUpdate();
      else if (state.platform === "android") await applyAndroidUpdate();
      else throw new Error("Las actualizaciones se aplican desde la app instalada.");
    } catch (err) {
      state.status = "error";
      state.message = friendlyUpdateError(err);
    } finally {
      state.busy = false;
      paint();
    }
  };

  const applyWindowsUpdate = async () => {
    // El `rid` del check es un recurso de esta sesión: se pide uno fresco
    // justo antes de descargar para no reusar un recurso viejo.
    const meta = await withTimeout(invoke("plugin:updater|check", {}), CHECK_TIMEOUT_MS);
    if (!meta || !meta.version) throw new Error("No hay una actualización disponible.");
    const version = String(meta.version).replace(/^[vV]/, "");
    const current = String(meta.currentVersion || state.localVersion || "").replace(/^[vV]/, "");
    if (compareVersions(version, current) <= 0) throw new Error("Ya estás en la última versión.");

    const core = getCore();
    if (!core || typeof core.Channel !== "function") {
      throw new Error("Esta versión de la app no admite el progreso de descarga.");
    }

    let total = 0;
    let done = 0;
    let lastPaint = 0;
    const channel = new core.Channel();
    channel.onmessage = (message) => {
      const event = message?.event || "";
      const data = message?.data || {};
      if (event === "Started") {
        total = Number(data.contentLength) || 0;
        done = 0;
        state.progress = 0;
        state.message = "Descargando la actualización…";
        paint();
      } else if (event === "Progress") {
        done += Number(data.chunkLength) || 0;
        state.progress = total > 0 ? Math.min(99, (done / total) * 100) : 0;
        state.message =
          total > 0
            ? `Descargando… ${formatMB(done)} de ${formatMB(total)}`
            : `Descargando… ${formatMB(done)}`;
        const now = Date.now();
        if (now - lastPaint >= 200) {
          lastPaint = now;
          paint();
        }
      } else if (event === "Finished") {
        state.progress = 100;
        state.message = "Descarga completa. Verificando la firma…";
        paint();
      }
    };

    state.message = "Descargando la actualización…";
    paint();

    const bytesRid = await invoke("plugin:updater|download", {
      rid: meta.rid,
      onEvent: channel,
    });

    state.progress = 100;
    state.status = "ready";
    state.message = "Instalando la actualización…";
    paint();

    // En Windows este comando cierra la app y abre el instalador firmado.
    await invoke("plugin:updater|install", {
      updateRid: meta.rid,
      bytesRid,
      restartAfterInstall: true,
    });
  };

  const applyAndroidUpdate = async () => {
    const update = state.update;
    if (!update) throw new Error("No hay una actualización disponible.");

    const core = getCore();
    if (!core || typeof core.Channel !== "function") {
      throw new Error("Esta versión de la app no admite el progreso de descarga.");
    }

    let total = update.sizeBytes || 0;
    let done = 0;
    let lastPaint = 0;
    const channel = new core.Channel();
    channel.onmessage = (message) => {
      const event = message?.event || "";
      const data = message?.data || {};
      if (event === "Started") {
        total = Number(data.contentLength) || total;
        done = 0;
        state.progress = 0;
        paint();
      } else if (event === "Progress") {
        done += Number(data.chunkLength) || 0;
        state.progress = total > 0 ? Math.min(99, (done / total) * 100) : 0;
        state.message =
          total > 0
            ? `Descargando el APK… ${formatMB(done)} de ${formatMB(total)}`
            : `Descargando el APK… ${formatMB(done)}`;
        const now = Date.now();
        if (now - lastPaint >= 200) {
          lastPaint = now;
          paint();
        }
      } else if (event === "Finished") {
        state.progress = 100;
        state.message = "APK verificado con SHA-256. Abriendo el instalador…";
        paint();
      }
    };

    state.message = "Descargando el APK…";
    paint();

    const path = await invoke("apk_download", {
      url: update.url,
      sha256: update.sha256 || "",
      sizeBytes: update.sizeBytes || 0,
      fileName: update.fileName || "",
      onEvent: channel,
    });

    state.progress = 100;
    state.status = "ready";
    state.message = "Abriendo el instalador de Android…";
    paint();

    await invoke("apk_install", { path });
    state.message = "Seguí los pasos del instalador para terminar la actualización.";
    paint();
  };

  /* ------------------------------------------------------------
     Textos y UI
     ------------------------------------------------------------ */

  const formatMB = (bytes) => {
    const value = Number(bytes) || 0;
    if (value <= 0) return "0 KB";
    if (value < 1024 * 1024) return `${Math.max(1, Math.round(value / 1024))} KB`;
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  };

  const clampPercent = (value) => Math.max(0, Math.min(100, Number(value) || 0));

  const friendlyUpdateError = (err) => {
    const message = String(err?.message || err || "").trim();
    if (!message) return "No se pudo comprobar la actualización.";
    if (/timeout|timed out|aborted/i.test(message)) {
      return "La consulta tardó demasiado. Revisá tu conexión y probá de nuevo.";
    }
    if (/failed to fetch|networkerror|load failed|error sending request|dns|connect/i.test(message)) {
      return "No se pudo conectar con el servidor de actualizaciones. Revisá tu conexión.";
    }
    if (/not initialized|not allowed|command .* not found|WebView sin puente/i.test(message)) {
      return "Esta versión de la app todavía no incluye el actualizador. Instalá la próxima release una vez de forma manual.";
    }
    return message;
  };

  const platformLabel = () =>
    ({
      windows: "App de Windows · actualización automática",
      android: "App de Android · APK firmado",
      web: "Versión web",
      other: "App de escritorio",
    })[state.platform] || "";

  const statusText = () => {
    if (state.message) return state.message;
    if (state.platform === "web") {
      return "Abrí WaverNote desde su versión instalada (Windows o Android) para recibir actualizaciones.";
    }
    if (state.platform === "other") {
      return "Este dispositivo no admite actualizaciones automáticas.";
    }
    if (state.status === "available" && state.update) {
      return `Hay una versión nueva disponible: v${state.update.version}.`;
    }
    if (state.status === "current") return "Estás usando la última versión.";
    return "Buscá actualizaciones para ver si hay una versión nueva.";
  };

  const paintVersionNodes = () => {
    document.querySelectorAll("[data-wavernote-version]").forEach((node) => {
      node.textContent = state.localVersion ? `v${state.localVersion}` : "v—";
    });
    document.querySelectorAll("[data-wavernote-update]").forEach((node) => {
      node.classList.toggle("has-update", Boolean(state.update));
      node.title = state.update
        ? `Actualización disponible: v${state.update.version}`
        : "Buscar actualizaciones";
    });
  };

  const paint = () => {
    paintVersionNodes();

    const status = document.getElementById("updStatus");
    if (status) status.textContent = statusText();

    const bar = document.getElementById("updBar");
    if (bar) {
      // Solo visible mientras se descarga o cuando ya está listo para instalar.
      // Si una descarga falla o se vuelve a comprobar, se oculta en vez de
      // quedarse congelada con el último porcentaje.
      const visible = state.busy || state.status === "ready";
      bar.hidden = !visible;
      bar.setAttribute("aria-hidden", visible ? "false" : "true");
    }
    const fill = document.getElementById("updBarFill");
    if (fill) fill.style.width = `${clampPercent(state.progress)}%`;

    const notes = document.getElementById("updNotes");
    if (notes) {
      notes.textContent = state.update?.notes || "";
      notes.hidden = !state.update?.notes;
    }

    // Changelog estructurado de la versión disponible. Si la versión no tiene
    // changelog publicado, se queda solo con las notas de la release.
    const changelog = document.getElementById("updChangelog");
    if (changelog) {
      const html = state.changelog ? changelogHTML(state.changelog) : "";
      changelog.innerHTML = html;
      changelog.hidden = !html;
    }

    const version = document.getElementById("updVersion");
    if (version) version.textContent = state.localVersion ? `v${state.localVersion}` : "v—";

    const checkBtn = document.getElementById("updCheckBtn");
    if (checkBtn) checkBtn.disabled = state.checking || state.busy;

    const installBtn = document.getElementById("updInstallBtn");
    if (installBtn) {
      installBtn.hidden = !state.update || state.busy;
      installBtn.disabled = state.busy || state.checking;
    }
  };

  /* ------------------------------------------------------------
     Changelog de la actualización
     ------------------------------------------------------------ */

  const CHANGELOG_SECTIONS = [
    { key: "adiciones", label: "Novedades", icon: "sparkles" },
    { key: "mejoras", label: "Mejoras", icon: "arrow-right" },
    { key: "arreglos", label: "Arreglos", icon: "check" },
    { key: "rendimiento", label: "Rendimiento", icon: "wave" },
    { key: "otros", label: "Otros", icon: "plus" },
  ];

  const changelogLines = (value) =>
    (Array.isArray(value) ? value : [])
      .map((line) => String(line || "").trim())
      .filter(Boolean);

  // Renderiza el changelog estructurado. Si la versión todavía no tiene
  // changelog publicado, se muestra el texto de notas de la release.
  const changelogHTML = (entry) => {
    const sections = CHANGELOG_SECTIONS.map((section) => {
      const lines = changelogLines(entry?.[section.key]);
      if (!lines.length) return "";
      return `
        <section class="changelog__section">
          <h4 class="changelog__title">${icon(section.icon)}<span>${escapeHTML(
            section.label
          )}</span></h4>
          <ul class="changelog__list">
            ${lines.map((line) => `<li>${escapeHTML(line)}</li>`).join("")}
          </ul>
        </section>`;
    }).join("");

    if (sections) return sections;

    const notes = String(state.update?.notes || "").trim();
    if (!notes) return "";
    return `<p class="changelog__plain">${escapeHTML(notes)}</p>`;
  };

  const openChangelogModal = () => {
    const update = state.update;
    if (!update || !state.changelog) return;
    if (typeof openModal !== "function") return;

    openModal({
      title: `WaverNote v${update.version}`,
      eyebrow: "Actualización disponible",
      body: `
        <div class="changelog">
          <p class="changelog__intro">Estos son los cambios de la versión ${escapeHTML(
            update.version
          )}. Podés instalarla cuando quieras desde Actualizaciones.</p>
          ${changelogHTML(state.changelog)}
        </div>
        <div class="modal__actions">
          <button class="btn btn--ghost" data-action="close-modal">Ahora no</button>
          <button class="btn btn--primary" data-action="open-updates">Ver actualización</button>
        </div>`,
    });
  };

  // El changelog se muestra solo una vez por arranque de la app: al reiniciar
  // vuelve a aparecer si la actualización sigue pendiente.
  const maybeShowChangelogModal = () => {
    if (state.changelogShown) return;
    if (!state.update || !state.changelog) return;
    if (!isAppReady()) return;

    state.changelogShown = true;
    // Si ya hay otro modal abierto (por ejemplo, el panel de actualizaciones),
    // el changelog queda a la vista ahí y no se encima otro.
    if (document.getElementById("modal")?.classList.contains("is-open")) return;
    openChangelogModal();
  };

  // Mientras la pantalla de acceso esté tapando la app no tiene sentido abrir
  // el modal: se reintenta cuando el usuario entra.
  const isAppReady = () => {
    const gate = document.getElementById("authGate");
    if (!gate) return true;
    return gate.hidden === true;
  };

  const openPanel = () => {
    if (typeof openModal !== "function") return;
    const canUpdate = state.platform === "windows" || state.platform === "android";
    openModal({
      title: "Actualizaciones",
      eyebrow: "WaverNote",
      body: `
        <div class="updater">
          <div class="updater__head">
            <span class="updater__icon">${icon("cloud")}</span>
            <div>
              <strong>WaverNote <span id="updVersion">${escapeHTML(
                state.localVersion ? `v${state.localVersion}` : "v—"
              )}</span></strong>
              <small>${escapeHTML(platformLabel())}</small>
            </div>
          </div>
          <p class="updater__status" id="updStatus">${escapeHTML(statusText())}</p>
          <div class="updater__bar" id="updBar" hidden aria-hidden="true">
            <span id="updBarFill" style="width:${clampPercent(state.progress)}%"></span>
          </div>
          <div class="updater__notes" id="updNotes" hidden></div>
          <div class="updater__changelog" id="updChangelog" hidden></div>
          <div class="modal__actions">
            <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
            ${
              canUpdate
                ? `<button class="btn btn--ghost" id="updCheckBtn" data-action="updates-check">Buscar actualizaciones</button>
                   <button class="btn btn--primary" id="updInstallBtn" data-action="updates-install" hidden>Descargar e instalar</button>`
                : ""
            }
          </div>
        </div>`,
    });
    paint();

    // Al abrir la ventana, refrescar en silencio si el último chequeo fue hace
    // más de un minuto (o si nunca se hizo). Si ya hay una descarga en curso,
    // no se toca nada.
    if (canUpdate && !state.busy && !state.checking && Date.now() - state.checkedAt > 60000) {
      checkForUpdate({ silent: true });
    }
  };

  const accountSectionHTML = () => {
    const canUpdate = state.platform === "windows" || state.platform === "android";
    const badge = state.update
      ? `<span class="account-update__badge">v${escapeHTML(state.update.version)}</span>`
      : "";
    const hint = state.update
      ? `Actualización disponible: v${escapeHTML(state.update.version)}`
      : state.status === "current"
      ? "Estás al día"
      : canUpdate
      ? "Buscar actualizaciones"
      : "Se aplican desde la app instalada";
    return `
      <button class="account-update" type="button" data-action="open-updates">
        <span class="account-update__icon">${icon("cloud")}</span>
        <span class="account-update__meta">
          <strong>WaverNote <span data-wavernote-version>${escapeHTML(
            state.localVersion ? `v${state.localVersion}` : "v—"
          )}</span>${badge}</strong>
          <small>${hint}</small>
        </span>
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-chevron-right"></use></svg>
      </button>`;
  };

  const init = async () => {
    state.platform = detectPlatform();
    state.localVersion = await loadLocalVersion();
    paintVersionNodes();

    if (state.platform === "windows" || state.platform === "android") {
      window.setTimeout(() => {
        checkForUpdate({ silent: true }).catch(() => {});
      }, AUTO_CHECK_DELAY_MS);
    }
  };

  window.WaverNoteUpdater = {
    state,
    init,
    openPanel,
    accountSectionHTML,
    checkNow: () => checkForUpdate(),
    applyNow: applyUpdate,
    maybeShowChangelogModal,
    refresh: paint,
  };
})();
