/* ============================================================
   WaverNote · interacción
   Sesión Surface, subidas, playlists, modales y arranque real.
   ============================================================ */

const searchInput = $("#searchInput");
const scrim = $("#scrim");
const authGate = $("#authGate");
const authForm = $("#authForm");
const authErrorEl = $("#authError");
const authSubmit = $("#authSubmit");
const modal = $("#modal");
const modalBody = $("#modalBody");
const modalTitle = $("#modalTitle");
const modalEyebrow = $("#modalEyebrow");

let authMode = "login";
let pendingFiles = [];

const SCAN_CONSENT_KEY = "wavernote.scanConsent.v1";
const SCAN_FILE_LIMIT = 400;
// En Android el WebView no entiende `webkitdirectory` ni tiene File System
// Access: el selector se abría y no devolvía nada. Ahí se eligen canciones
// con el selector del sistema (SAF), que no pide permisos y presta solo los
// archivos elegidos.
const IS_ANDROID = /Android/i.test(navigator.userAgent || "");
const AUDIO_ACCEPT = "audio/*,.mp3,.wav,.ogg,.m4a,.aac,.flac,.opus,.webm";

let uploadMode = "manual";
let scanItems = [];
let scanPhase = "gate";
let scanFolder = "";
let scanTruncated = false;
let scanRunId = 0;
let scanCoverUrls = [];
let pendingCoverPreviewUrl = "";
let scanConsent = readJSON(SCAN_CONSENT_KEY, null);

const isOverlay = () => window.matchMedia("(max-width: 1279px)").matches;

const friendlyError = (err) => {
  const message = String(err?.message || "").trim();
  if (!message || /failed to fetch|networkerror|load failed/i.test(message)) {
    return "No se pudo conectar con el servidor. Revisá tu conexión.";
  }
  return message;
};

/* ------------------------------------------------------------
   Sesión y datos de usuario
   ------------------------------------------------------------ */

const renderUserUI = () => {
  const user = state.user;
  const username = user?.username || "Tu cuenta";
  const initial = username.charAt(0).toUpperCase() || "W";

  const sideAvatar = $("#sideAvatar");
  const topAvatar = $("#topAvatar");
  const sideUsername = $("#sideUsername");
  const topUsername = $("#topUsername");
  const sideUserSub = $("#sideUserSub");

  if (sideAvatar) sideAvatar.textContent = initial;
  if (topAvatar) topAvatar.textContent = initial;
  if (sideUsername) sideUsername.textContent = username;
  if (topUsername) topUsername.textContent = user ? `@${username}` : username;
  if (sideUserSub) sideUserSub.textContent = user ? "Cuenta Surface" : "Sin sesión";
};

const renderSidebarPlaylists = () => {
  const nav = $("#playlistNav");
  if (!nav) return;

  if (!state.playlists.length) {
    nav.innerHTML = `<p class="side-empty">Todavía no hay playlists.</p>`;
    return;
  }

  nav.innerHTML = state.playlists
    .map(
      (playlist) => `<button class="side-playlist" data-action="open-playlist" data-id="${playlist.id}" title="${escapeHTML(playlist.name)}">
        <span class="side-playlist__art">${coverHTML({ title: playlist.name })}</span>
        <span class="side-playlist__name">${escapeHTML(playlist.name)}</span>
      </button>`
    )
    .join("");
};

const showAuth = (mode = "login") => {
  setAuthMode(mode);
  authGate.hidden = false;
  authGate.removeAttribute("aria-hidden");
  $("#app")?.setAttribute("aria-hidden", "true");
  requestAnimationFrame(() => $("#authUser")?.focus({ preventScroll: true }));
};

const hideAuth = () => {
  authGate.hidden = true;
  authGate.setAttribute("aria-hidden", "true");
  $("#app")?.removeAttribute("aria-hidden");
};

const setAuthError = (message) => {
  if (!authErrorEl) return;
  authErrorEl.textContent = message || "";
  authErrorEl.classList.toggle("is-visible", Boolean(message));
};

const setAuthMode = (mode) => {
  authMode = mode === "register" ? "register" : "login";
  const isRegister = authMode === "register";

  $$(".auth__tab").forEach((tab) => {
    const active = tab.dataset.authTab === authMode;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
  });

  if (authSubmit) {
    const label = authSubmit.querySelector("span");
    if (label) label.textContent = isRegister ? "Crear cuenta" : "Entrar";
    authSubmit.disabled = false;
  }

  const pass = $("#authPass");
  if (pass) pass.setAttribute("autocomplete", isRegister ? "new-password" : "current-password");

  const hint = $("#authHint");
  if (hint) {
    hint.textContent = isRegister
      ? "Se crea una cuenta nueva en Surface. Si ya tenés una, entrá desde la pestaña de al lado."
      : "Usá tu cuenta de Surface. Si todavía no tenés una, creala desde la pestaña de al lado.";
  }

  setAuthError("");
};

const setAuthBusy = (busy, label = "Conectando…") => {
  if (!authSubmit) return;
  authSubmit.disabled = busy;
  const span = authSubmit.querySelector("span");
  if (span) span.textContent = busy ? label : authMode === "register" ? "Crear cuenta" : "Entrar";
};

const enterApp = async (user) => {
  state.user = user || getStoredUser();
  saveSession(getToken(), state.user);

  try {
    await refreshLibrary();
  } catch (err) {
    if (err.status === 401) {
      clearSession();
      showAuth("login");
      setAuthError("Tu sesión expiró. Entrá de nuevo con tu cuenta Surface.");
      return;
    }
    toast(friendlyError(err), "error");
  }

  state.ready = true;
  hideAuth();
  renderUserUI();
  renderSidebarPlaylists();
  resetNavigation();
  renderView();
  updateNowPlaying();
  updateVolumeUI();
  updateNavUI();
  setupMediaSession();
  startUiLoop();
};

const bootAuth = async () => {
  const token = getToken();
  if (!token) {
    showAuth("login");
    return;
  }

  setAuthBusy(true);
  try {
    const session = await validateSurfaceSession();
    saveSession(session.token, session.user);
    await enterApp(session.user);
  } catch (err) {
    clearSession();
    showAuth("login");
    if (err.status !== 401) setAuthError(friendlyError(err));
  } finally {
    setAuthBusy(false);
  }
};

const doLogout = () => {
  engine.stop();
  closeModal(true);
  closePanel();
  clearSession();

  state.user = null;
  state.ready = false;
  state.tracks = [];
  state.playlists = [];
  state.liked = new Set();
  state.recent = [];
  state.plays = {};
  state.recommendations = null;
  state.queue = [];
  state.queueIndex = -1;
  state.currentTrackId = null;
  state.duration = 0;
  state.currentTime = 0;
  state.isPlaying = false;
  state.shuffle = false;
  state.repeat = "off";
  state.panelOpen = false;
  rebuildIndexes();

  authForm?.reset();
  renderUserUI();
  renderSidebarPlaylists();
  resetNavigation();
  renderView();
  updateNowPlaying();
  updateVolumeUI();
  updateNavUI();
  showAuth("login");
  toast("Sesión cerrada");
};

/* ------------------------------------------------------------
   Modales
   ------------------------------------------------------------ */

const closeModal = (force = false) => {
  if (state.uploading && !force) {
    toast("Esperá a que terminen las subidas.");
    return;
  }
  scanRunId += 1;
  releaseScanArtwork();
  modal.classList.remove("is-open");
  modal.setAttribute("aria-hidden", "true");
  document.body.classList.remove("modal-open");
  modalBody.innerHTML = "";
  modal.querySelector(".modal__panel")?.classList.remove("modal__panel--upload");
};

const openModal = ({ title, eyebrow = "WaverNote", body }) => {
  modalTitle.textContent = title;
  modalEyebrow.textContent = eyebrow;
  modalBody.innerHTML = body;
  modal.classList.add("is-open");
  modal.setAttribute("aria-hidden", "false");
  document.body.classList.add("modal-open");

  requestAnimationFrame(() => {
    const target =
      modalBody.querySelector("[data-autofocus]") ||
      modalBody.querySelector("input:not([type='file']), button, select, textarea");
    target?.focus({ preventScroll: true });
  });
};

/* ------------------------------------------------------------
   Subida de música
   ------------------------------------------------------------ */

const formatBytes = (bytes) => {
  const size = Number(bytes) || 0;
  if (size <= 0) return "";
  if (size < 1024 * 1024) return `${Math.max(1, Math.round(size / 1024))} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
};

const releaseScanArtwork = () => {
  scanCoverUrls.forEach((url) => {
    try {
      URL.revokeObjectURL(url);
    } catch (err) {
      /* noop */
    }
  });
  scanCoverUrls = [];

  if (pendingCoverPreviewUrl) {
    try {
      URL.revokeObjectURL(pendingCoverPreviewUrl);
    } catch (err) {
      /* noop */
    }
    pendingCoverPreviewUrl = "";
  }
};

const scanConsentNote = () => {
  if (scanConsent?.grantedAt) {
    return `Ya nos diste permiso el ${dateLabel(scanConsent.grantedAt)}. Te lo volvemos a pedir por las dudas; si tu dispositivo ya lo recordaba, no va a repetir su propio aviso.`;
  }
  return "Te lo pedimos siempre, incluso si el sistema dice que no hace falta. Si el dispositivo muestra su propio aviso de Permitir, respondelo una vez y no vuelve a aparecer.";
};

const autoPaneHTML = () => {
  const gate = IS_ANDROID
    ? {
        title: "Elegir canciones para escanear",
        lead:
          "En Android elegís los archivos con el selector del sistema y WaverNote lee sus etiquetas sola: " +
          "título, artista, álbum, portada y duración. No modificamos ni borramos nada.",
        items: [
          "Tocá <strong>Elegir canciones</strong> y marcá todo lo que quieras agregar. Para elegir varias, mantené presionada una canción y sumá el resto.",
          "No hace falta dar permiso de almacenamiento: el selector presta solo los archivos que elegís.",
          "Las canciones se acumulan: podés repetir la selección y al final subir todo de una sola vez."
        ],
        action: `
          <label class="btn btn--primary scan-gate__btn scan-gate__btn--picker">
            <input type="file" id="androidScanInput" class="scan-gate__input" accept="audio/*" multiple />
            ${icon("search")} <span>Elegir canciones</span>
          </label>`,
        note:
          "Android no permite leer la carpeta Música completa desde la app. Elegí una tanda y después sumá " +
          "las que falten con <strong>Agregar más canciones</strong>."
      }
    : {
        title: "Permiso para escanear tu música",
        lead:
          "Para armar la biblioteca sola necesitamos leer los archivos de audio de tu carpeta <strong>Música</strong>. " +
          "Solo miramos títulos, artistas, portadas y duración: no modificamos ni borramos nada.",
        items: [
          "Elegís la carpeta <strong>Música</strong> del dispositivo.",
          "Si el sistema muestra su propio aviso de <strong>Permitir</strong>, respondelo una vez.",
          "Después te mostramos lo encontrado y elegís qué canciones subir."
        ],
        action: `
          <button type="button" class="btn btn--primary scan-gate__btn" data-scan-action="grant">
            ${icon("search")} <span>Permitir y escanear</span>
          </button>`,
        note: scanConsentNote()
      };

  const secondaryLabel = IS_ANDROID ? "Elegir otras canciones" : "Elegir otra carpeta";

  return `
  <div class="scan-gate" id="scanGate">
    <div class="scan-gate__head">
      <span class="scan-gate__icon">${icon("lock")}</span>
      <div>
        <h3>${gate.title}</h3>
        <p>${gate.lead}</p>
      </div>
    </div>

    <ul class="scan-gate__list">
      ${gate.items.map((item) => `<li>${item}</li>`).join("")}
    </ul>

    ${gate.action}
    <p class="scan-gate__note" id="scanGateNote">${gate.note}</p>
  </div>

  <div class="scan-loading" id="scanLoading" hidden>
    <div class="scan-loading__head">
      <span class="scan-loading__spinner" aria-hidden="true"></span>
      <div class="scan-loading__copy">
        <strong>Escaneando tu Música…</strong>
        <small id="scanLoadingLabel">Preparando la lectura de archivos…</small>
      </div>
    </div>
    <div class="scan-progress"><span class="scan-progress__bar" id="scanProgressBar"></span></div>
  </div>

  <div class="scan-error" id="scanError" hidden>
    <span class="scan-error__icon">${icon("x")}</span>
    <div class="scan-error__copy">
      <strong>No pudimos escanear</strong>
      <p id="scanErrorText"></p>
    </div>
    <button type="button" class="btn btn--soft btn--small" data-scan-action="rescan">Reintentar</button>
  </div>

  <div class="scan-results" id="scanResults" hidden>
    <div class="scan-results__head">
      <div>
        <strong id="scanSummaryTitle"></strong>
        <span id="scanSummaryMeta"></span>
      </div>
      <div class="scan-results__bulk">
        <button type="button" class="link-btn" data-scan-action="all">Todas</button>
        <button type="button" class="link-btn" data-scan-action="none">Ninguna</button>
      </div>
    </div>
    <div class="scan-list" id="scanList"></div>
    <p class="scan-limit" id="scanLimitNote" hidden>
      ${IS_ANDROID
        ? "Llegaste al límite de 400 canciones por carga: subí estas y después agregá el resto."
        : "Mostramos las primeras 400 canciones. Si falta alguna, elegí una carpeta más específica."}
    </p>
    ${IS_ANDROID
      ? `<div class="scan-results__actions">
          <label class="btn btn--primary btn--small scan-gate__btn--picker">
            <input type="file" id="androidScanMoreInput" class="scan-gate__input" accept="audio/*" multiple />
            ${icon("plus")} <span>Agregar más canciones</span>
          </label>
          <button type="button" class="btn btn--ghost btn--small" data-scan-action="reset">
            ${icon("folder")} <span>Empezar de nuevo</span>
          </button>
        </div>
        <p class="scan-gate__note">Las que ya elegiste quedan marcadas: sumá todas las tandas que quieras y subilas juntas.</p>`
      : `<button type="button" class="btn btn--ghost btn--small scan-rescan" data-scan-action="rescan">
          ${icon("folder")} <span>${secondaryLabel}</span>
        </button>`}
  </div>

  <div class="scan-empty" id="scanEmpty" hidden>
    <span class="scan-empty__icon">${icon("music")}</span>
    <strong>${IS_ANDROID ? "No encontramos audio en lo que elegiste" : "No encontramos audio en esa carpeta"}</strong>
    <p>${
      IS_ANDROID
        ? "Probá de nuevo eligiendo canciones con el selector. Formatos: MP3, WAV, OGG, M4A, AAC, FLAC, OPUS o WEBM."
        : "Probá con la carpeta Música o con otra que tenga tus archivos. Formatos: MP3, WAV, OGG, M4A, AAC, FLAC, OPUS o WEBM."
    }</p>
    <button type="button" class="btn btn--soft btn--small" data-scan-action="rescan">
      ${icon("folder")} <span>${secondaryLabel}</span>
    </button>
  </div>
`;
};

const uploadModalHTML = () => `
  <form class="form upload-form" id="uploadForm" novalidate>
    <div class="upload-mode" role="tablist" aria-label="Cómo agregar música">
      <button type="button" class="upload-mode__btn is-active" data-upload-mode="manual" role="tab" aria-selected="true">
        <span class="upload-mode__icon">${icon("edit")}</span>
        <span class="upload-mode__copy">
          <strong>Manual</strong>
          <small>Elegís archivo, portada y datos</small>
        </span>
      </button>
      <button type="button" class="upload-mode__btn" data-upload-mode="auto" role="tab" aria-selected="false">
        <span class="upload-mode__icon">${icon("sparkles")}</span>
        <span class="upload-mode__copy">
          <strong>Automático</strong>
          <small>Escanea Música y detecta todo</small>
        </span>
      </button>
    </div>

    <section class="upload-pane" id="manualPane" aria-label="Carga manual">
      <label class="dropzone" id="dropzone" tabindex="0">
        <input id="uploadFiles" type="file" accept="audio/*,.mp3,.wav,.ogg,.m4a,.aac,.flac,.opus,.webm" multiple hidden />
        <span class="dropzone__icon">${icon("upload")}</span>
        <strong>Elegí archivos o arrastralos acá</strong>
        <span class="dropzone__hint">MP3, WAV, OGG, M4A, AAC, FLAC u OPUS · hasta 50 MB por archivo</span>
      </label>

      <div class="upload-list" id="uploadList" hidden></div>

      <div class="form-grid upload-fields">
        <label class="field">
          <span>Título</span>
          <input id="uploadTitle" name="title" maxlength="160" placeholder="Sale del nombre si lo dejás vacío" />
        </label>
        <label class="field">
          <span>Artista</span>
          <input id="uploadArtist" name="artist" maxlength="120" placeholder="Opcional" />
        </label>
        <label class="field">
          <span>Álbum</span>
          <input id="uploadAlbum" name="album" maxlength="120" placeholder="Opcional" />
        </label>
        <label class="field">
          <span>Género</span>
          <input id="uploadGenre" name="genre" maxlength="60" placeholder="Opcional" />
        </label>
        <div class="upload-cover">
          <label class="field">
            <span>Miniatura / portada</span>
            <input id="uploadCover" type="file" accept="image/jpeg,image/png,image/webp" />
            <small class="field__hint" id="uploadCoverHint">JPG, PNG o WEBP · una canción a la vez.</small>
          </label>
          <div class="cover-preview" id="uploadCoverPreview" hidden>
            <img alt="Vista previa de la portada" />
            <span>Así se va a ver.</span>
          </div>
        </div>
      </div>

      <p class="form__hint">
        En manual elegís todo: archivo, miniatura, artista, álbum y género. Si no escribís el título,
        sale del nombre del archivo («Artista - Título» se separa solo).
      </p>
    </section>

    <section class="upload-pane" id="autoPane" aria-label="Carga automática" hidden>
      ${autoPaneHTML()}
    </section>

    <div class="upload-progress" id="uploadProgress" hidden>
      <div class="upload-progress__track"><span class="upload-progress__bar"></span></div>
      <span class="upload-progress__label"></span>
    </div>

    <div class="modal__actions">
      <button type="button" class="btn btn--ghost" data-action="close-modal">Cancelar</button>
      <button type="submit" class="btn btn--primary" id="uploadSubmit" disabled>
        ${icon("upload")} <span>Subir</span>
      </button>
    </div>
  </form>`;

const setPendingFiles = (files) => {
  const incoming = Array.from(files || []);
  const tooBig = incoming.filter((file) => file.size > 50 * 1024 * 1024);
  const accepted = incoming.filter((file) => file.size <= 50 * 1024 * 1024 && !tooBig.includes(file));

  if (tooBig.length) toast(`${plural(tooBig.length, "archivo supera", "archivos superan")} los 50 MB.`, "error");
  pendingFiles = accepted.slice(0, 30);
  if (accepted.length > 30) toast("Se agregaron los primeros 30 archivos.");

  renderPendingFiles();
};

const updateUploadSubmitState = () => {
  const submit = $("#uploadSubmit");
  if (!submit) return;

  if (state.uploading) {
    submit.disabled = true;
    return;
  }

  const label = submit.querySelector("span");

  if (uploadMode === "auto") {
    const selected = scanItems.filter((item) => item.selected && !item.duplicate).length;
    submit.disabled = scanPhase !== "results" || selected === 0;
    if (label) {
      label.textContent =
        selected === 0
          ? "Agregar a mi biblioteca"
          : selected === 1
            ? "Agregar canción"
            : `Agregar ${selected} canciones`;
    }
    return;
  }

  submit.disabled = !pendingFiles.length;
  if (label) {
    label.textContent =
      pendingFiles.length === 0
        ? "Subir"
        : pendingFiles.length === 1
          ? "Subir canción"
          : `Subir ${pendingFiles.length} canciones`;
  }
};

const renderPendingFiles = () => {
  const list = $("#uploadList");
  const input = $("#uploadFiles");
  const cover = $("#uploadCover");
  const title = $("#uploadTitle");
  const coverHint = $("#uploadCoverHint");
  const preview = $("#uploadCoverPreview");

  if (input) input.value = "";

  if (list) {
    list.hidden = !pendingFiles.length;
    list.innerHTML = pendingFiles
      .map(
        (file, index) => `<div class="upload-file">
          <span class="upload-file__icon">${icon("music")}</span>
          <span class="upload-file__meta">
            <strong>${escapeHTML(file.name)}</strong>
            <small>${formatBytes(file.size)}</small>
          </span>
          <button class="icon-btn icon-btn--tiny" type="button" data-remove-file="${index}" aria-label="Quitar ${escapeHTML(file.name)}">${icon("x")}</button>
        </div>`
      )
      .join("");
  }

  const single = pendingFiles.length === 1;

  if (cover) {
    cover.disabled = !single;
    if (!single && cover.value) cover.value = "";
  }
  if (title) title.disabled = pendingFiles.length > 1;
  if (coverHint) {
    coverHint.textContent = single
      ? "JPG, PNG o WEBP · se aplica a esta canción."
      : "Solo para una canción a la vez.";
  }
  if (preview && !single) preview.hidden = true;

  updateUploadSubmitState();

  const zone = $("#dropzone");
  if (zone) zone.classList.toggle("has-files", pendingFiles.length > 0);
};

const updateCoverPreview = () => {
  const input = $("#uploadCover");
  const preview = $("#uploadCoverPreview");

  if (pendingCoverPreviewUrl) {
    try {
      URL.revokeObjectURL(pendingCoverPreviewUrl);
    } catch (err) {
      /* noop */
    }
    pendingCoverPreviewUrl = "";
  }

  if (!preview) return;

  const file = input?.files?.[0];
  if (!file || pendingFiles.length !== 1) {
    preview.hidden = true;
    const oldImage = preview.querySelector("img");
    if (oldImage) oldImage.removeAttribute("src");
    return;
  }

  pendingCoverPreviewUrl = URL.createObjectURL(file);
  const image = preview.querySelector("img");
  if (image) image.src = pendingCoverPreviewUrl;
  preview.hidden = false;
};

const SCAN_PHASES = {
  gate: "scanGate",
  scanning: "scanLoading",
  results: "scanResults",
  empty: "scanEmpty",
  error: "scanError"
};

const setAutoPhase = (phase) => {
  scanPhase = SCAN_PHASES[phase] ? phase : "gate";

  Object.entries(SCAN_PHASES).forEach(([key, id]) => {
    const node = document.getElementById(id);
    if (node) node.hidden = key !== scanPhase;
  });

  updateUploadSubmitState();
};

const setScanError = (message) => {
  const text = $("#scanErrorText");
  if (text) text.textContent = message || "Probá de nuevo en unos segundos.";
  setAutoPhase("error");
};

const updateScanProgress = (ratio, label) => {
  const bar = $("#scanProgressBar");
  const text = $("#scanLoadingLabel");
  if (bar) bar.style.width = `${Math.round(clamp(ratio, 0, 1) * 100)}%`;
  if (text) text.textContent = label || "Preparando la lectura de archivos…";
};

const setUploadMode = (mode) => {
  uploadMode = mode === "auto" ? "auto" : "manual";

  $$("[data-upload-mode]", modalBody).forEach((button) => {
    const active = button.dataset.uploadMode === uploadMode;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
  });

  const manualPane = $("#manualPane");
  const autoPane = $("#autoPane");
  if (manualPane) manualPane.hidden = uploadMode !== "manual";
  if (autoPane) autoPane.hidden = uploadMode !== "auto";

  setAutoPhase(scanPhase);
  updateUploadSubmitState();
};

const setUploadModeLocked = (locked) => {
  $$("[data-upload-mode]", modalBody).forEach((button) => {
    button.disabled = locked;
  });
};

const setUploadProgress = (ratio, label) => {
  const wrap = $("#uploadProgress");
  if (!wrap) return;
  wrap.hidden = false;
  const bar = wrap.querySelector(".upload-progress__bar");
  const text = wrap.querySelector(".upload-progress__label");
  if (bar) bar.style.width = `${Math.round(clamp(ratio, 0, 1) * 100)}%`;
  if (text) text.textContent = label || `${Math.round(clamp(ratio, 0, 1) * 100)}%`;
};

const scanItemById = (id) => scanItems.find((item) => item.id === id) || null;

const isTrackAlreadyInLibrary = (item) => {
  const title = normalize(item.title);
  const artist = normalize(item.artist);

  return state.tracks.some((track) => {
    if (normalize(track.title) !== title) return false;
    if (normalize(track.artist || "") !== artist) return false;
    const duration = Number(track.duration) || 0;
    return !item.duration || !duration || Math.abs(duration - item.duration) <= 3;
  });
};

const scanTrackHTML = (item) => `
  <label class="scan-track${item.selected ? " is-selected" : ""}${item.duplicate ? " is-duplicate" : ""}" data-scan-id="${item.id}">
    <input
      type="checkbox"
      data-scan-select="${item.id}"
      ${item.selected ? "checked" : ""}
      ${item.duplicate ? "disabled" : ""}
      aria-label="Agregar ${escapeHTML(item.title)}"
    />
    <span class="scan-track__art">${coverHTML({ title: item.title, coverUrl: item.coverUrl })}</span>
    <span class="scan-track__info">
      <strong title="${escapeHTML(item.title)}">${escapeHTML(item.title)}</strong>
      <small>${escapeHTML(item.artist || "Artista desconocido")}${item.album ? ` · ${escapeHTML(item.album)}` : ""}</small>
      <span class="scan-track__tags">
        <em class="${item.hasTags ? "tag--ok" : ""}">${item.hasTags ? "Etiquetas" : "Nombre del archivo"}</em>
        ${item.duration ? `<em>${formatTime(item.duration)}</em>` : ""}
        <em>${formatBytes(item.file.size)}</em>
        ${item.duplicate ? `<em class="tag--warn">Ya en tu biblioteca</em>` : ""}
      </span>
    </span>
  </label>`;

const applyScanArtFallback = (image) => {
  const art = image.closest(".scan-track__art");
  if (!art) return;
  const row = art.closest(".scan-track");
  const item = row ? scanItemById(row.dataset.scanId) : null;
  art.innerHTML = coverHTML({ title: item?.title || "WaverNote" });
};

const updateScanSummary = () => {
  const title = $("#scanSummaryTitle");
  const meta = $("#scanSummaryMeta");
  const total = scanItems.length;
  const selected = scanItems.filter((item) => item.selected && !item.duplicate).length;
  const duplicates = scanItems.filter((item) => item.duplicate).length;

  if (title) {
    const found = plural(total, "canción encontrada", "canciones encontradas");
    title.textContent = scanFolder ? `${found} en ${scanFolder}` : found;
  }
  if (meta) {
    const parts = [plural(selected, "seleccionada", "seleccionadas")];
    if (duplicates) parts.push(`${plural(duplicates, "ya estaba", "ya estaban")} en tu biblioteca`);
    meta.textContent = parts.join(" · ");
  }

  updateUploadSubmitState();
};

const renderScanResults = () => {
  const list = $("#scanList");
  if (!list) return;
  list.innerHTML = scanItems.map(scanTrackHTML).join("");
  const limit = $("#scanLimitNote");
  if (limit) limit.hidden = !scanTruncated;
  updateScanSummary();
};

const collectMusicFiles = async (directory, output, depth = 0) => {
  if (output.length >= SCAN_FILE_LIMIT) return true;
  if (depth > 8) return false;

  for await (const entry of directory.values()) {
    if (output.length >= SCAN_FILE_LIMIT) return true;
    if (String(entry.name || "").startsWith(".")) continue;

    if (entry.kind === "file") {
      if (!WNMetadata.isAudioFile(entry.name)) continue;
      try {
        output.push(await entry.getFile());
      } catch (err) {
        /* archivo ilegible, seguimos con el resto */
      }
    } else if (entry.kind === "directory") {
      if (await collectMusicFiles(entry, output, depth + 1)) return true;
    }
  }

  return false;
};

const pickFolderWithInput = () =>
  new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    // Android ignora `webkitdirectory` y con el atributo puesto el selector
    // no devolvía nada. Ahí se usa el picker normal (SAF) con varias
    // canciones; en escritorio se mantiene la carpeta completa.
    input.accept = IS_ANDROID ? "audio/*" : AUDIO_ACCEPT;
    if (!IS_ANDROID) {
      input.setAttribute("webkitdirectory", "");
      input.setAttribute("directory", "");
    }
    input.tabIndex = -1;
    input.style.position = "fixed";
    input.style.left = "-9999px";
    input.style.opacity = "0";

    let settled = false;
    let focusTimer = 0;

    const cleanup = () => {
      window.clearTimeout(focusTimer);
      window.removeEventListener("focus", handleFocus);
      input.remove();
    };

    const finish = (files, canceled = false) => {
      if (settled) return;
      settled = true;

      const audio = Array.from(files || []).filter((file) => WNMetadata.isAudioFile(file));
      const first = audio[0];
      const relative = first?.webkitRelativePath || "";
      cleanup();
      resolve({
        files: audio,
        folderName: relative ? relative.split("/")[0] : "",
        canceled: canceled && !audio.length,
        truncated: audio.length > SCAN_FILE_LIMIT
      });
    };

    const handleFocus = () => {
      window.clearTimeout(focusTimer);
      focusTimer = window.setTimeout(() => {
        if (settled) return;
        const files = input.files;
        finish(files, !files?.length);
      }, 1200);
    };

    input.addEventListener("change", () => finish(input.files), { once: true });
    input.addEventListener("cancel", () => finish([], true), { once: true });

    document.body.appendChild(input);
    window.addEventListener("focus", handleFocus);
    input.click();
  });

const openDirectoryHandle = async () => {
  try {
    return await window.showDirectoryPicker({ id: "wavernote-music", mode: "read", startIn: "music" });
  } catch (err) {
    if (err?.name === "AbortError") throw err;
    if (err?.name === "TypeError") return window.showDirectoryPicker({ mode: "read" });
    throw err;
  }
};

const chooseMusicFolder = async () => {
  const supportsPicker =
    !IS_ANDROID && typeof window.showDirectoryPicker === "function" && window.isSecureContext;

  if (supportsPicker) {
    try {
      const directory = await openDirectoryHandle();
      const files = [];
      const truncated = await collectMusicFiles(directory, files);
      return { files, folderName: directory.name || "", canceled: false, truncated };
    } catch (err) {
      if (err?.name === "AbortError") throw err;
      console.warn("WaverNote: el selector de carpetas no respondió, probando el selector clásico.", err);
    }
  }

  return pickFolderWithInput();
};

const scanFileKey = (file) => `${file.name}|${file.size}|${file.lastModified}`;

const startScan = async (preselectedFiles = null, options = {}) => {
  if (state.uploading) return;

  // En Android las canciones se acumulan: si ya hay resultados, elegir otra
  // tanda las suma en vez de reemplazarlas (permite subir todo de una vez).
  const append = Boolean(options.append) && IS_ANDROID && scanItems.length > 0;
  const runId = ++scanRunId;

  setAutoPhase("scanning");
  updateScanProgress(
    0,
    append ? "Sumando canciones…" : IS_ANDROID ? "Leyendo tus canciones…" : "Abriendo la carpeta Música…"
  );

  let picked;

  if (Array.isArray(preselectedFiles)) {
    // Android: los archivos llegan directo del selector del sistema.
    picked = {
      files: preselectedFiles,
      folderName: "",
      canceled: preselectedFiles.length === 0,
      truncated: preselectedFiles.length > SCAN_FILE_LIMIT
    };
  } else {
    try {
      picked = await chooseMusicFolder();
    } catch (err) {
      if (runId !== scanRunId) return;
      if (err?.name === "AbortError") {
        setAutoPhase(append ? "results" : "gate");
        return;
      }
      setScanError(friendlyError(err));
      return;
    }
  }

  if (runId !== scanRunId) return;

  if (picked.canceled) {
    // Si estaba sumando, cancelar no debe borrar lo que ya había.
    setAutoPhase(append ? "results" : "gate");
    return;
  }

  const previous = append ? scanItems.slice() : [];
  const seen = new Set(previous.map((item) => scanFileKey(item.file)));
  const incoming = (picked.files || []).filter((file) => WNMetadata.isAudioFile(file));
  const fresh = [];
  let repeated = 0;
  let overflow = false;

  for (const file of incoming) {
    const key = scanFileKey(file);
    if (seen.has(key)) {
      repeated += 1;
      continue;
    }
    if (previous.length + fresh.length >= SCAN_FILE_LIMIT) {
      overflow = true;
      break;
    }
    seen.add(key);
    fresh.push(file);
  }

  if (!append) {
    releaseScanArtwork();
    scanItems = [];
    scanFolder = picked.folderName || "";
    scanTruncated = Boolean(picked.truncated) || overflow;
  } else if (overflow) {
    scanTruncated = true;
  }

  scanConsent = { grantedAt: scanConsent?.grantedAt || new Date().toISOString(), folder: scanFolder };
  writeJSON(SCAN_CONSENT_KEY, scanConsent);
  const consentNote = $("#scanGateNote");
  if (consentNote) consentNote.textContent = scanConsentNote();

  if (!fresh.length) {
    if (append) {
      setAutoPhase("results");
      if (repeated) toast("Esas canciones ya estaban en la lista.");
      if (overflow) toast("Llegaste al límite de 400 canciones por carga.");
    } else {
      setAutoPhase("empty");
    }
    return;
  }

  const items = [];

  for (let index = 0; index < fresh.length; index += 1) {
    if (runId !== scanRunId) return;

    const file = fresh[index];
    const label = append ? "Sumando" : "Leyendo";
    updateScanProgress(index / fresh.length, `${label} ${index + 1} de ${fresh.length}: ${file.name}`);

    let metadata;
    try {
      metadata = await WNMetadata.readTrackMetadata(file);
    } catch (err) {
      metadata = WNMetadata.fallbackMetadata(file);
    }

    if (runId !== scanRunId) return;

    const item = {
      id: `scan-${Date.now()}-${index}`,
      file,
      title: metadata.title,
      artist: metadata.artist,
      album: metadata.album,
      genre: metadata.genre,
      year: metadata.year,
      duration: metadata.duration,
      hasTags: metadata.hasTags,
      coverBlob: metadata.coverBlob,
      coverUrl: "",
      duplicate: false,
      selected: true
    };

    if (metadata.coverBlob) {
      item.coverUrl = URL.createObjectURL(metadata.coverBlob);
      scanCoverUrls.push(item.coverUrl);
    }

    item.duplicate = isTrackAlreadyInLibrary(item);
    if (item.duplicate) item.selected = false;

    items.push(item);
  }

  if (runId !== scanRunId) return;

  scanItems = previous.concat(items);
  renderScanResults();
  setAutoPhase("results");

  if (append) {
    toast(`${plural(items.length, "canción sumada", "canciones sumadas")}.`);
    if (repeated) toast("Las repetidas no se agregaron otra vez.");
  }
};

const handleScanAction = (action) => {
  if (action === "grant" || action === "rescan") {
    startScan().catch((err) => {
      console.error(err);
      setScanError(friendlyError(err));
    });
    return;
  }

  if (action === "reset") {
    // Vuelve al inicio sin abrir el selector ni perder el modal abierto.
    scanRunId += 1;
    releaseScanArtwork();
    scanItems = [];
    scanTruncated = false;
    setAutoPhase("gate");
    return;
  }

  if (action === "all" || action === "none") {
    const select = action === "all";
    scanItems.forEach((item) => {
      if (!item.duplicate) item.selected = select;
    });

    $$("#scanList .scan-track").forEach((row) => {
      const item = scanItemById(row.dataset.scanId);
      if (!item) return;
      row.classList.toggle("is-selected", item.selected);
      const checkbox = row.querySelector("input[type='checkbox']");
      if (checkbox) checkbox.checked = item.selected;
    });

    updateScanSummary();
  }
};

const openUpload = () => {
  if (!state.user) {
    showAuth("login");
    return;
  }

  pendingFiles = [];
  scanItems = [];
  scanFolder = "";
  scanTruncated = false;
  scanPhase = "gate";
  uploadMode = "manual";
  scanRunId += 1;

  releaseScanArtwork();
  openModal({ title: "Agregar música", eyebrow: "Tu biblioteca", body: uploadModalHTML() });
  modal.querySelector(".modal__panel")?.classList.add("modal__panel--upload");

  $$("[data-upload-mode]", modalBody).forEach((button) => {
    button.addEventListener("click", () => setUploadMode(button.dataset.uploadMode));
  });

  const input = $("#uploadFiles");
  const coverInput = $("#uploadCover");
  const dropzone = $("#dropzone");
  const form = $("#uploadForm");
  const list = $("#uploadList");

  input?.addEventListener("change", () => setPendingFiles(input.files));

  // Android: el selector del sistema entrega las canciones elegidas y el
  // escaneo sigue igual que con una carpeta.
  const androidScanInput = $("#androidScanInput");
  androidScanInput?.addEventListener("change", () => {
    const files = Array.from(androidScanInput.files || []);
    androidScanInput.value = "";
    if (!files.length) return;
    startScan(files).catch((err) => {
      console.error(err);
      setScanError(friendlyError(err));
    });
  });

  // Sumar otra tanda desde los resultados sin perder lo ya elegido.
  const androidScanMoreInput = $("#androidScanMoreInput");
  androidScanMoreInput?.addEventListener("change", () => {
    const files = Array.from(androidScanMoreInput.files || []);
    androidScanMoreInput.value = "";
    if (!files.length) {
      setAutoPhase("results");
      return;
    }
    startScan(files, { append: true }).catch((err) => {
      console.error(err);
      setScanError(friendlyError(err));
    });
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    dropzone?.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    dropzone?.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.remove("is-dragging");
    });
  });
  dropzone?.addEventListener("drop", (event) => {
    if (event.dataTransfer?.files?.length) setPendingFiles(event.dataTransfer.files);
  });
  dropzone?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input?.click();
    }
  });

  list?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-file]");
    if (!button) return;
    pendingFiles.splice(Number(button.dataset.removeFile), 1);
    renderPendingFiles();
  });

  coverInput?.addEventListener("change", updateCoverPreview);

  $("#autoPane")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-scan-action]");
    if (!button) return;
    handleScanAction(button.dataset.scanAction);
  });

  $("#scanList")?.addEventListener("change", (event) => {
    const checkbox = event.target.closest("[data-scan-select]");
    if (!checkbox) return;
    const item = scanItemById(checkbox.dataset.scanSelect);
    if (!item || item.duplicate) return;
    item.selected = checkbox.checked;
    const row = checkbox.closest(".scan-track");
    if (row) row.classList.toggle("is-selected", item.selected);
    updateScanSummary();
  });

  $("#scanList")?.addEventListener(
    "error",
    (event) => {
      const image = event.target;
      if (image instanceof HTMLImageElement) applyScanArtFallback(image);
    },
    true
  );

  form?.addEventListener("submit", (event) => {
    event.preventDefault();
    runUpload();
  });

  setUploadMode("manual");
};

const finishUpload = async ({ uploaded, failures }) => {
  state.uploading = false;
  setUploadModeLocked(false);
  setUploadProgress(1, "Actualizando tu biblioteca…");

  try {
    await refreshLibrary();
    renderSidebarPlaylists();
    renderView({ resetScroll: false });

    if (!state.currentTrackId && state.tracks.length) {
      const first = state.tracks[state.tracks.length - 1];
      state.queue = state.tracks.map((track) => track.id);
      state.queueIndex = Math.max(0, state.queue.indexOf(first.id));
      state.currentTrackId = first.id;
      state.duration = Number(first.duration) || 0;
      state.currentTime = 0;
      state.isPlaying = false;
      updateNowPlaying();
    }
  } catch (err) {
    toast(`Las canciones se subieron, pero no se pudo refrescar la biblioteca: ${friendlyError(err)}`, "error");
  }

  closeModal(true);

  if (uploaded && !failures.length) {
    toast(`${plural(uploaded, "canción agregada", "canciones agregadas")} a tu biblioteca.`);
  } else if (uploaded && failures.length) {
    toast(`${uploaded} subieron; ${failures.length} fallaron. ${failures[0].name}: ${failures[0].message}`, "error");
  } else {
    toast(failures[0]?.message || "No se pudo subir ningún archivo.", "error");
  }
};

const runAutoUpload = async () => {
  const items = scanItems.filter((item) => item.selected && !item.duplicate);

  if (!items.length) {
    toast("Elegí al menos una canción para agregar.", "error");
    return;
  }

  state.uploading = true;
  setUploadModeLocked(true);
  updateUploadSubmitState();
  setUploadProgress(0, "Preparando tus canciones…");

  const submit = $("#uploadSubmit");
  const label = submit?.querySelector("span");
  if (label) label.textContent = "Subiendo…";

  let uploaded = 0;
  const failures = [];

  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    setUploadProgress(index / items.length, `Preparando ${index + 1} de ${items.length}: ${item.title}`);

    const duration = item.duration || (await readAudioDuration(item.file));

    let cover = null;
    try {
      cover = await WNMetadata.prepareCoverForUpload(item.coverBlob, item.file.name);
    } catch (err) {
      cover = null;
    }

    try {
      await uploadTrackFile({
        file: item.file,
        cover,
        fields: {
          title: item.title,
          artist: item.artist,
          album: item.album,
          genre: item.genre,
          duration
        },
        onProgress: (ratio) => {
          const total = (index + ratio) / items.length;
          setUploadProgress(total, `Subiendo ${index + 1} de ${items.length}: ${item.title} · ${Math.round(ratio * 100)}%`);
        }
      });
      uploaded += 1;
    } catch (err) {
      failures.push({ name: item.title, message: friendlyError(err) });
    }
  }

  await finishUpload({ uploaded, failures });
};

const runUpload = async () => {
  if (state.uploading) return;

  if (uploadMode === "auto") {
    await runAutoUpload();
    return;
  }

  const files = pendingFiles.slice();
  if (!files.length) {
    toast("Elegí al menos un archivo.", "error");
    return;
  }

  const title = files.length === 1 ? $("#uploadTitle")?.value.trim() || "" : "";
  const artist = $("#uploadArtist")?.value.trim() || "";
  const album = $("#uploadAlbum")?.value.trim() || "";
  const genre = $("#uploadGenre")?.value.trim() || "";
  const coverInput = $("#uploadCover");
  const cover = files.length === 1 && coverInput?.files?.[0] ? coverInput.files[0] : null;

  state.uploading = true;
  setUploadModeLocked(true);
  updateUploadSubmitState();
  const submit = $("#uploadSubmit");
  if (submit) {
    submit.disabled = true;
    const span = submit.querySelector("span");
    if (span) span.textContent = "Subiendo…";
  }

  let uploaded = 0;
  const failures = [];

  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    setUploadProgress(index / files.length, `Preparando ${index + 1} de ${files.length}…`);

    const duration = await readAudioDuration(file);
    try {
      await uploadTrackFile({
        file,
        cover,
        fields: { title, artist, album, genre, duration },
        onProgress: (ratio) => {
          const total = (index + ratio) / files.length;
          setUploadProgress(total, `Subiendo ${index + 1} de ${files.length}… ${Math.round(ratio * 100)}%`);
        }
      });
      uploaded += 1;
    } catch (err) {
      failures.push({ name: file.name, message: friendlyError(err) });
    }
  }

  await finishUpload({ uploaded, failures });
};

/* ------------------------------------------------------------
   Menú y edición de canciones
   ------------------------------------------------------------ */

const openTrackMenu = (trackId, playlistId = "") => {
  const track = trackById(trackId);
  if (!track) return;

  const liked = isLiked(track.id);
  openModal({
    title: track.title,
    eyebrow: `${track.artist || "Artista desconocido"} · ${albumNameOf(track)}`,
    body: `
      <div class="menu-list">
        <button class="menu-item" data-action="menu-play" data-id="${track.id}">
          ${icon("play")} <span>Reproducir</span>
        </button>
        <button class="menu-item" data-action="menu-queue" data-id="${track.id}">
          ${icon("plus")} <span>Agregar a la cola</span>
        </button>
        <button class="menu-item" data-action="menu-like" data-id="${track.id}">
          ${icon("heart")} <span>${liked ? "Quitar de Me gusta" : "Agregar a Me gusta"}</span>
        </button>
        <button class="menu-item" data-action="menu-add-playlist" data-id="${track.id}">
          ${icon("library")} <span>Agregar a una playlist</span>
        </button>
        ${playlistId
          ? `<button class="menu-item" data-action="menu-remove-playlist" data-id="${track.id}" data-playlist="${playlistId}">
              ${icon("x")} <span>Quitar de esta playlist</span>
            </button>`
          : ""}
        <button class="menu-item" data-action="menu-edit" data-id="${track.id}">
          ${icon("edit")} <span>Editar detalles</span>
        </button>
        <button class="menu-item menu-item--danger" data-action="menu-delete" data-id="${track.id}">
          ${icon("trash")} <span>Eliminar de mi biblioteca</span>
        </button>
      </div>`
  });
};

const openTrackEdit = (trackId) => {
  const track = trackById(trackId);
  if (!track) return;

  openModal({
    title: "Editar canción",
    eyebrow: "Detalles",
    body: `
      <form class="form" id="editForm">
        <label class="field">
          <span>Título</span>
          <input name="title" maxlength="160" value="${escapeHTML(track.title)}" required data-autofocus />
        </label>
        <div class="form-grid">
          <label class="field">
            <span>Artista</span>
            <input name="artist" maxlength="120" value="${escapeHTML(track.artist)}" />
          </label>
          <label class="field">
            <span>Álbum</span>
            <input name="album" maxlength="120" value="${escapeHTML(track.album)}" />
          </label>
          <label class="field">
            <span>Género</span>
            <input name="genre" maxlength="60" value="${escapeHTML(track.genre)}" />
          </label>
        </div>
        <div class="modal__actions">
          <button type="button" class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          <button type="submit" class="btn btn--primary">${icon("check")} Guardar</button>
        </div>
      </form>`
  });

  $("#editForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const title = form.title.value.trim();
    if (!title) {
      toast("La canción necesita un título.", "error");
      return;
    }

    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;

    try {
      await api(`/wavernote/tracks/${track.id}`, {
        method: "PATCH",
        body: {
          title,
          artist: form.artist.value.trim(),
          album: form.album.value.trim(),
          genre: form.genre.value.trim()
        }
      });
      await refreshLibrary();
      renderSidebarPlaylists();
      renderView({ resetScroll: false });
      updateNowPlaying();
      closeModal(true);
      toast("Canción actualizada.");
    } catch (err) {
      toast(friendlyError(err), "error");
      if (submit) submit.disabled = false;
    }
  });
};

const openDeleteTrack = (trackId) => {
  const track = trackById(trackId);
  if (!track) return;

  openModal({
    title: "Eliminar canción",
    eyebrow: "Confirmar",
    body: `
      <p class="modal__text">«${escapeHTML(track.title)}» se va a borrar de tu biblioteca y de tus playlists. El archivo también se elimina del almacenamiento.</p>
      <div class="modal__actions">
        <button class="btn btn--ghost" data-action="close-modal">Cancelar</button>
        <button class="btn btn--danger" data-action="confirm-delete-track" data-id="${track.id}">${icon("trash")} Eliminar</button>
      </div>`
  });
};

/* ------------------------------------------------------------
   Playlists
   ------------------------------------------------------------ */

const openPlaylistForm = ({ playlist = null, trackId = null } = {}) => {
  openModal({
    title: playlist ? "Editar playlist" : "Nueva playlist",
    eyebrow: "Playlists",
    body: `
      <form class="form" id="playlistForm">
        <label class="field">
          <span>Nombre</span>
          <input name="name" maxlength="80" value="${escapeHTML(playlist?.name || "")}" placeholder="Mi playlist" required data-autofocus />
        </label>
        <label class="field">
          <span>Descripción</span>
          <textarea name="description" maxlength="300" rows="3" placeholder="Opcional">${escapeHTML(playlist?.description || "")}</textarea>
        </label>
        <div class="modal__actions">
          <button type="button" class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          <button type="submit" class="btn btn--primary">${icon("check")} ${playlist ? "Guardar" : "Crear playlist"}</button>
        </div>
      </form>`
  });

  $("#playlistForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const name = form.name.value.trim();
    if (!name) {
      toast("La playlist necesita un nombre.", "error");
      return;
    }

    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;

    try {
      if (playlist) {
        await api(`/wavernote/playlists/${playlist.id}`, {
          method: "PATCH",
          body: { name, description: form.description.value.trim() }
        });
      } else {
        const created = await api("/wavernote/playlists", {
          method: "POST",
          body: { name, description: form.description.value.trim() }
        });
        if (trackId && created?.playlist?.id) {
          await api(`/wavernote/playlists/${created.playlist.id}/tracks`, {
            method: "POST",
            body: { trackId }
          });
        }
      }

      await refreshLibrary();
      renderSidebarPlaylists();
      renderView({ resetScroll: false });
      closeModal(true);
      toast(playlist ? "Playlist actualizada." : "Playlist creada.");
    } catch (err) {
      toast(friendlyError(err), "error");
      if (submit) submit.disabled = false;
    }
  });
};

const openAddToPlaylist = (trackId) => {
  const track = trackById(trackId);
  if (!track) return;

  const items = state.playlists
    .map(
      (playlist) => `<button class="menu-item menu-item--playlist" data-action="playlist-add-track" data-id="${track.id}" data-playlist="${playlist.id}">
        <span class="menu-item__art">${coverHTML({ title: playlist.name })}</span>
        <span class="menu-item__info">
          <strong>${escapeHTML(playlist.name)}</strong>
          <small>${plural(playlist.trackIds.length, "pista", "pistas")}</small>
        </span>
        ${icon("plus")}
      </button>`
    )
    .join("");

  openModal({
    title: "Agregar a playlist",
    eyebrow: escapeHTML(track.title),
    body: `
      <div class="menu-list">
        ${items || `<p class="modal__text">Todavía no tenés playlists. Creá una y la canción se agrega sola.</p>`}
        <button class="menu-item" data-action="playlist-create" data-id="${track.id}">
          ${icon("plus")} <span>Nueva playlist</span>
        </button>
      </div>`
  });
};

const openDeletePlaylist = (playlistId) => {
  const playlist = playlistById(playlistId);
  if (!playlist) return;

  openModal({
    title: "Eliminar playlist",
    eyebrow: "Confirmar",
    body: `
      <p class="modal__text">«${escapeHTML(playlist.name)}» se va a eliminar. Las canciones siguen en tu biblioteca.</p>
      <div class="modal__actions">
        <button class="btn btn--ghost" data-action="close-modal">Cancelar</button>
        <button class="btn btn--danger" data-action="confirm-delete-playlist" data-id="${playlist.id}">${icon("trash")} Eliminar</button>
      </div>`
  });
};

/* ------------------------------------------------------------
   Cuenta
   ------------------------------------------------------------ */

const openAccount = () => {
  if (!state.user) {
    showAuth("login");
    return;
  }

  const username = state.user.username || "tu cuenta";
  const initial = username.charAt(0).toUpperCase();
  const albums = allAlbums();

  openModal({
    title: "Tu cuenta",
    eyebrow: "Surface",
    body: `
      <div class="account-card">
        <span class="avatar avatar--large">${escapeHTML(initial)}</span>
        <div>
          <strong>@${escapeHTML(username)}</strong>
          <small>Cuenta Surface · sesión compartida con OWS</small>
        </div>
      </div>
      <div class="account-facts">
        <div><strong>${state.tracks.length}</strong><span>canciones</span></div>
        <div><strong>${albums.length}</strong><span>álbumes</span></div>
        <div><strong>${state.playlists.length}</strong><span>playlists</span></div>
        <div><strong>${likedTracks().length}</strong><span>favoritos</span></div>
      </div>
      <div class="modal__actions">
        <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
        <button class="btn btn--danger" data-action="logout">${icon("logout")} Cerrar sesión</button>
      </div>`
  });
};

/* ------------------------------------------------------------
   Acciones de reproducción
   ------------------------------------------------------------ */

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
    window.setTimeout(() => panel?.classList.remove("is-focused"), 1000);
    return;
  }
  state.panelOpen = true;
  els.app?.classList.add("np-open");
  updatePanelButtons();
  window.setTimeout(() => $("#npClose")?.focus({ preventScroll: true }), 180);
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

const playRow = (row) => {
  const id = Number(row.dataset.id);
  if (!state.trackById.has(id)) return;

  if (id === Number(state.currentTrackId)) {
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
   Acciones
   ------------------------------------------------------------ */

const handleAction = async (actionEl) => {
  const action = actionEl.dataset.action;
  const id = Number(actionEl.dataset.id) || actionEl.dataset.id;
  const playlistId = Number(actionEl.dataset.playlist) || 0;

  switch (action) {
    case "nav-home":
      closePanel();
      navigate({ view: "home" });
      break;
    case "nav-search":
      closePanel();
      goSearch();
      break;
    case "nav-recommendations":
      closePanel();
      navigate({ view: "recommendations" });
      break;
    case "nav-trends":
      closePanel();
      navigate({ view: "trends" });
      break;
    case "nav-library":
      closePanel();
      navigate({ view: "library" });
      break;
    case "open-library": {
      closePanel();
      closeModal();
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
      closeModal();
      closePanel();
      navigate({ view: "album", id: String(actionEl.dataset.id || "") });
      break;
    case "open-playlist":
      if (!playlistById(actionEl.dataset.id)) return;
      closeModal();
      closePanel();
      navigate({ view: "playlist", id: String(actionEl.dataset.id) });
      break;
    case "play-row": {
      const row = actionEl.closest("[data-track-row]");
      if (row) playRow(row);
      break;
    }
    case "play-rec-section": {
      const section = actionEl.dataset.section || "mix";
      const ids = recommendationTrackIds(section);
      if (!ids.length) return;
      if (actionEl.dataset.shuffle === "true") {
        startQueue(ids, { shuffle: true, randomStart: true });
      } else {
        startQueue(ids, { startIndex: 0 });
      }
      break;
    }
    case "play-rec-track": {
      const section = actionEl.dataset.section || "mix";
      const ids = recommendationTrackIds(section);
      const target = Number(actionEl.dataset.id);
      const index = ids.indexOf(target);
      if (!ids.length) return;
      startQueue(ids, { startIndex: index < 0 ? 0 : index });
      break;
    }
    case "play-trends": {
      const ids = trendTrackIds();
      if (ids.length) startQueue(ids, { startIndex: 0 });
      break;
    }
    case "play-trend": {
      const ids = trendTrackIds();
      const target = Number(actionEl.dataset.id);
      const index = ids.indexOf(target);
      if (!ids.length) return;
      startQueue(ids, { startIndex: index < 0 ? 0 : index });
      break;
    }
    case "play-album": {
      const tracks = albumTracks(String(actionEl.dataset.id || "")).map((track) => track.id);
      if (tracks.length) startQueue(tracks, { startIndex: 0 });
      break;
    }
    case "shuffle-album": {
      const tracks = albumTracks(String(actionEl.dataset.id || "")).map((track) => track.id);
      if (tracks.length) startQueue(tracks, { shuffle: true, randomStart: true });
      break;
    }
    case "queue-album": {
      const album = allAlbums().find((item) => item.id === actionEl.dataset.id);
      if (album) queueCollection(album.tracks.map((track) => track.id), album.title);
      break;
    }
    case "play-playlist": {
      const playlist = playlistById(actionEl.dataset.id);
      if (playlist?.trackIds.length) startQueue(playlist.trackIds, { startIndex: 0 });
      break;
    }
    case "shuffle-playlist": {
      const playlist = playlistById(actionEl.dataset.id);
      if (playlist?.trackIds.length) startQueue(playlist.trackIds, { shuffle: true, randomStart: true });
      break;
    }
    case "queue-playlist": {
      const playlist = playlistById(actionEl.dataset.id);
      if (playlist) queueCollection(playlist.trackIds, playlist.name);
      break;
    }
    case "play-liked":
      startQueue(likedTracks().map((track) => track.id), { startIndex: 0 });
      break;
    case "play-all":
      startQueue(state.tracks.map((track) => track.id), { startIndex: 0 });
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
      await toggleLike(actionEl.dataset.id);
      break;
    case "like-current":
      await toggleLike(state.currentTrackId);
      break;
    case "library-tab":
      state.libraryTab = actionEl.dataset.tab || "songs";
      if (state.route.view !== "library") navigate({ view: "library" });
      else renderView({ resetScroll: true });
      updateNavUI();
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
    case "open-upload":
      openUpload();
      break;
    case "close-modal":
      closeModal();
      break;
    case "open-account":
      openAccount();
      break;
    case "logout":
      doLogout();
      break;
    case "track-menu":
      openTrackMenu(actionEl.dataset.id, actionEl.dataset.playlist || "");
      break;
    case "menu-play":
      closeModal(true);
      startQueue([Number(actionEl.dataset.id)], { startIndex: 0 });
      break;
    case "menu-queue":
      addToQueue(actionEl.dataset.id);
      closeModal(true);
      break;
    case "menu-like":
      await toggleLike(actionEl.dataset.id);
      closeModal(true);
      break;
    case "menu-add-playlist":
      openAddToPlaylist(actionEl.dataset.id);
      break;
    case "menu-edit":
      openTrackEdit(actionEl.dataset.id);
      break;
    case "menu-delete":
      openDeleteTrack(actionEl.dataset.id);
      break;
    case "menu-remove-playlist": {
      await api(`/wavernote/playlists/${playlistId}/tracks/${id}`, { method: "DELETE" });
      await refreshLibrary();
      renderSidebarPlaylists();
      renderView({ resetScroll: false });
      updateNowPlaying();
      closeModal(true);
      toast("Canción quitada de la playlist.");
      break;
    }
    case "confirm-delete-track": {
      await api(`/wavernote/tracks/${id}`, { method: "DELETE" });
      if (Number(state.currentTrackId) === Number(id)) {
        engine.stop();
        state.isPlaying = false;
        state.currentTrackId = null;
        state.duration = 0;
        state.currentTime = 0;
      }
      state.queue = state.queue.filter((trackId) => Number(trackId) !== Number(id));
      state.queueIndex = Math.min(state.queueIndex, Math.max(0, state.queue.length - 1));
      await refreshLibrary();
      renderSidebarPlaylists();
      renderView({ resetScroll: false });
      updateNowPlaying();
      closeModal(true);
      toast("Canción eliminada de tu biblioteca.");
      break;
    }
    case "playlist-create":
      openPlaylistForm({ trackId: actionEl.dataset.id ? Number(actionEl.dataset.id) : null });
      break;
    case "playlist-edit":
      openPlaylistForm({ playlist: playlistById(actionEl.dataset.id) });
      break;
    case "playlist-delete":
      openDeletePlaylist(actionEl.dataset.id);
      break;
    case "confirm-delete-playlist": {
      await api(`/wavernote/playlists/${id}`, { method: "DELETE" });
      await refreshLibrary();
      renderSidebarPlaylists();
      if (state.route.view === "playlist" && String(state.route.id) === String(id)) {
        state.libraryTab = "playlists";
        navigate({ view: "library" });
      } else {
        renderView({ resetScroll: false });
      }
      closeModal(true);
      toast("Playlist eliminada.");
      break;
    }
    case "playlist-add-track": {
      await api(`/wavernote/playlists/${playlistId}/tracks`, {
        method: "POST",
        body: { trackId: Number(id) }
      });
      await refreshLibrary();
      renderSidebarPlaylists();
      if (state.route.view === "playlist") renderView({ resetScroll: false });
      closeModal(true);
      toast("Canción agregada a la playlist.");
      break;
    }
    default:
      break;
  }
};

/* ------------------------------------------------------------
   Eventos
   ------------------------------------------------------------ */

document.addEventListener("click", (event) => {
  const actionEl = event.target.closest("[data-action]");
  if (!actionEl) return;
  if (actionEl.matches('a[href="#"]')) event.preventDefault();

  handleAction(actionEl).catch((err) => {
    console.error(err);
    toast(friendlyError(err), "error");
  });
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

$$(".auth__tab").forEach((tab) => {
  tab.addEventListener("click", () => setAuthMode(tab.dataset.authTab));
});

authForm?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = $("#authUser")?.value.trim() || "";
  const password = $("#authPass")?.value || "";

  if (!username || !password) {
    setAuthError("Completá usuario y contraseña.");
    return;
  }
  if (authMode === "register" && password.length < 4) {
    setAuthError("La contraseña necesita al menos 4 caracteres.");
    return;
  }

  setAuthError("");
  setAuthBusy(true, authMode === "register" ? "Creando cuenta…" : "Entrando…");

  try {
    const session =
      authMode === "register"
        ? await registerInSurface(username, password)
        : await loginWithSurface(username, password);

    saveSession(session.token, session.user);
    await enterApp(session.user);
    const pass = $("#authPass");
    if (pass) pass.value = "";
  } catch (err) {
    setAuthError(friendlyError(err));
  } finally {
    setAuthBusy(false);
  }
});

/* ------------------------------------------------------------
   Controles del reproductor
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
      const results = searchLibrary(state.search);
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

window.addEventListener("dragover", (event) => event.preventDefault());
window.addEventListener("drop", (event) => {
  if (!event.target.closest(".dropzone")) event.preventDefault();
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
  const modalOpen = modal.classList.contains("is-open");

  if (key === "Escape") {
    if (modalOpen) {
      closeModal();
      return;
    }
    if (state.panelOpen) {
      closePanel();
      return;
    }
    searchInput?.blur();
    return;
  }

  if (modalOpen) return;

  if ((event.ctrlKey || event.metaKey) && key.toLowerCase() === "k") {
    event.preventDefault();
    goSearch();
    return;
  }

  if (typing) return;

  const nativeControl =
    target instanceof HTMLElement && target.closest("button, a, input, select, textarea, [role='button']");

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

  if (key.toLowerCase() === "u") {
    event.preventDefault();
    openUpload();
    return;
  }

  if (key === "/") {
    event.preventDefault();
    goSearch();
  }
});

/* ------------------------------------------------------------
   Inicio
   ------------------------------------------------------------ */

const init = () => {
  engine.setVolume(state.volume);
  engine.setMuted(state.muted);

  if (els.seek) {
    els.seek.min = "0";
    els.seek.max = "1000";
  }
  if (els.volume) els.volume.value = String(Math.round(state.volume * 100));

  renderUserUI();
  renderSidebarPlaylists();
  updateVolumeUI();
  updateNowPlaying();
  updateNavUI();
  updatePanelButtons();
  renderView({ resetScroll: true });

  document.documentElement.classList.add("is-ready");
  bootAuth();
};

init();
