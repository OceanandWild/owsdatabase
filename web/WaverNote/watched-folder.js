/* ------------------------------------------------------------
   WaverNote · carpeta vigilada

   La app no descarga música de ninguna plataforma. Este módulo solo
   mira una carpeta que el usuario elige, reconoce los archivos que
   completan canciones pendientes y los sube con el mismo endpoint que
   usa una subida manual.

   Windows: comandos nativos de Tauri (elegir, escanear y leer).
   Android: puente WaverNoteAndroid (SAF, etiquetas y subida nativa).
   Web: la tarjeta no se muestra; la función es exclusiva de la app.
   ------------------------------------------------------------ */

(function () {
  "use strict";

  const Core = window.WaverNoteWatchCore;
  if (!Core) return;

  const STORAGE_PREFIX = "wavernote.watchedFolder.v2";
  const SCAN_INTERVAL_MS = 5 * 60 * 1000;
  const MIN_SCAN_GAP_MS = 30 * 1000;
  const MAX_UPLOADS_PER_SCAN = 25;
  const MAX_TAG_FILES_ANDROID = 120;
  const MAX_TAG_FILES_DESKTOP = 12;
  const MAX_TAG_BYTES_DESKTOP = 40 * 1024 * 1024;
  const FAILURE_RETRY_MS = 30 * 60 * 1000;
  const MAX_KNOWN = 4000;
  const MAX_FAILURES = 300;
  const MAX_NOTIFICATIONS = 60;
  const MAX_REPORT_ITEMS = 400;
  const MAX_REPORT_COVERS = 32;
  const MAX_REPORT_COVER_BYTES = 2 * 1024 * 1024;
  const MAX_PENDING_ADDS_PER_RUN = 50;
  const READ_CHUNK_BYTES = 4 * 1024 * 1024;

  const IS_ANDROID = /Android/i.test(navigator.userAgent || "");
  const bridge = () => window.WaverNoteFolder || null;
  const tauriCore = () => window.__TAURI__?.core || null;
  const canUseNative = () =>
    IS_ANDROID ? Boolean(bridge()) : Boolean(tauriCore()?.invoke);

  const runtime = {
    supported: canUseNative(),
    started: false,
    userId: 0,
    config: null,
    scanning: false,
    phase: "idle",
    timer: null,
    scanTimer: null,
    lastScanStarted: 0,
    pickWaiter: null,
    scanWaiter: null,
    uploadSeq: 0,
    uploads: new Map(),
    tagChecked: new Set(),
    coverCache: new Map(),
    coverHydration: 0,
    pendingAdding: false,
    pendingProgress: "",
    pendingSignature: "",
    notificationsOpen: false,
    cardQueued: false
  };

  /* ------------------------------------------------------------
     Configuración por cuenta
     ------------------------------------------------------------ */

  const emptyConfig = () => ({
    folder: null,
    enabled: true,
    permissionLost: false,
    folderMissing: false,
    known: {},
    failures: {},
    notifications: [],
    lastReport: null,
    addedAt: 0,
    lastScanAt: 0,
    lastResult: null
  });

  const storageKey = (userId) => `${STORAGE_PREFIX}.${Number(userId) || 0}`;

  const normalizeConfig = (raw) => {
    const base = emptyConfig();
    if (!raw || typeof raw !== "object") return base;

    const folder = raw.folder;
    return {
      ...base,
      ...raw,
      folder:
        folder && (folder.value || folder.uri)
          ? {
              kind: folder.kind === "tree" ? "tree" : "path",
              value: String(folder.value || folder.uri || ""),
              label: String(folder.label || "Carpeta de música")
            }
          : null,
      enabled: raw.enabled !== false,
      permissionLost: Boolean(raw.permissionLost),
      folderMissing: Boolean(raw.folderMissing),
      known: raw.known && typeof raw.known === "object" ? raw.known : {},
      failures: raw.failures && typeof raw.failures === "object" ? raw.failures : {},
      notifications: Array.isArray(raw.notifications)
        ? raw.notifications.filter((item) => item && item.id).slice(0, MAX_NOTIFICATIONS)
        : [],
      lastReport:
        raw.lastReport && typeof raw.lastReport === "object" ? raw.lastReport : null,
      addedAt: Number(raw.addedAt) || 0,
      lastScanAt: Number(raw.lastScanAt) || 0,
      lastResult: raw.lastResult && typeof raw.lastResult === "object" ? raw.lastResult : null
    };
  };

  const trimEntryMap = (map, limit) => {
    const entries = Object.entries(map || {})
      .filter(([, value]) => value && typeof value === "object")
      .sort((a, b) => (Number(b[1].at) || 0) - (Number(a[1].at) || 0))
      .slice(0, limit);
    return Object.fromEntries(entries);
  };

  const saveConfig = () => {
    if (!runtime.config) return;
    runtime.config.known = trimEntryMap(runtime.config.known, MAX_KNOWN);
    runtime.config.failures = trimEntryMap(runtime.config.failures, MAX_FAILURES);
    runtime.config.notifications = Array.isArray(runtime.config.notifications)
      ? runtime.config.notifications.filter((item) => item && item.id).slice(0, MAX_NOTIFICATIONS)
      : [];
    const report = runtime.config.lastReport;
    const serializable =
      report && Array.isArray(report.items)
        ? {
            ...runtime.config,
            // Las portadas leídas del archivo viven solo mientras la app está
            // abierta (blob:). Se descartan al guardar para no dejar enlaces
            // muertos en el próximo inicio; se vuelven a leer si hacen falta.
            lastReport: {
              ...report,
              items: report.items.map((item) => ({
                ...item,
                coverUrl: /^blob:/i.test(String(item?.coverUrl || "")) ? "" : item?.coverUrl
              }))
            }
          }
        : runtime.config;
    try {
      writeJSON(storageKey(runtime.userId), serializable);
    } catch (err) {
      /* modo privado o almacenamiento lleno */
    }
  };

  const loadConfig = (userId) => {
    let raw = null;
    try {
      raw = readJSON(storageKey(userId), null);
    } catch (err) {
      raw = null;
    }
    return normalizeConfig(raw);
  };

  /* ------------------------------------------------------------
     Utilidades de presentación
     ------------------------------------------------------------ */

  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  const timeAgo = (value) => {
    const time = Number(value) || 0;
    if (!time) return "";
    const diff = Date.now() - time;
    if (diff < 45 * 1000) return "recién";
    if (diff < 60 * 60 * 1000) return `hace ${Math.max(1, Math.round(diff / 60000))} min`;
    if (diff < 24 * 60 * 60 * 1000) return `hace ${Math.round(diff / 3600000)} h`;

    const date = new Date(time);
    return date.toLocaleDateString("es", {
      day: "2-digit",
      month: "short"
    });
  };

  const shortLabel = (value) => {
    const text = String(value || "").split(/[\\/]/).filter(Boolean).pop() || String(value || "");
    return text.length > 46 ? `${text.slice(0, 43)}…` : text;
  };

  const layoutHint = (result) => {
    const kind = result?.kind;
    if (kind === "empty") {
      return "No encontramos audio en esta carpeta. Probá con la carpeta principal donde guardás tu música.";
    }
    if (kind === "single-file") {
      return "La carpeta elegida tiene un solo archivo. Si querés completar más pendientes, cambiá a la carpeta principal de música.";
    }
    if (kind === "large" || result?.truncated) {
      return "La carpeta tiene muchísimos archivos. Revisamos una parte; si falta una canción, elegí una carpeta más específica (por ejemplo, la del artista).";
    }
    if (kind === "too-deep" || result?.depthLimited) {
      return "Hay subcarpetas más profundas de las que revisamos. Movelas un nivel arriba o elegí directamente esa carpeta.";
    }
    if (kind === "artist-tree") {
      return "Detectamos una carpeta de artista. También buscamos dentro de cada canción y en todas sus subcarpetas.";
    }
    if (kind === "deep-tree") {
      return "La carpeta tiene varias subcarpetas: revisamos cada nivel y usamos el nombre del archivo, la carpeta y las etiquetas para reconocer la canción.";
    }
    return "";
  };

  const statusInfo = () => {
    const config = runtime.config;
    if (!config?.folder) return { label: "Sin carpeta", tone: "paused" };
    if (config.permissionLost) return { label: "Permiso vencido", tone: "warning" };
    if (config.folderMissing) return { label: "No disponible", tone: "warning" };
    if (!config.enabled) return { label: "Pausada", tone: "paused" };
    if (runtime.scanning) return { label: "Revisando", tone: "busy" };
    return { label: "Activa", tone: "active" };
  };

  const button = (action, label, iconName, className = "btn btn--small btn--ghost", extra = "") =>
    `<button class="${className}" data-action="${action}" ${extra}>${icon(iconName)}${label ? ` <span>${label}</span>` : ""}</button>`;

  const legalNote = () =>
    `<p class="watch-card__legal">${icon("lock")} Solo se suben archivos que coinciden con canciones pendientes. No descargamos música de Spotify ni de otras plataformas.</p>`;

  /* ------------------------------------------------------------
     Notificaciones del header
     ------------------------------------------------------------ */

  const notificationElements = () => ({
    root: document.getElementById("notifRoot"),
    badge: document.getElementById("notifBadge"),
    button: document.getElementById("notifButton"),
    panel: document.getElementById("notifPanel"),
    list: document.getElementById("notifList"),
    summary: document.getElementById("notifSummary")
  });

  const notificationList = () =>
    Array.isArray(runtime.config?.notifications) ? runtime.config.notifications : [];

  const notificationItemHTML = (entry) => `
    <button class="notif__item ${entry.read ? "" : "is-unread"}" type="button" data-action="notif-open" data-id="${escapeHTML(entry.id)}">
      <span class="notif__art">${coverHTML(entry)}</span>
      <span class="notif__copy">
        <strong>${escapeHTML(entry.title || "Canción completada")}</strong>
        <small>${escapeHTML(entry.artist || "Artista desconocido")}</small>
        <span class="notif__meta">${icon("check")} ${escapeHTML(timeAgo(entry.at) || "recién")} · desde tu carpeta</span>
      </span>
      ${entry.read ? "" : `<span class="notif__dot" aria-label="Sin leer"></span>`}
    </button>`;

  const renderNotifications = () => {
    const els = notificationElements();
    if (!els.root) return;

    const available = runtime.supported && Boolean(runtime.config?.folder);
    els.root.hidden = !available;
    if (!available) {
      if (els.panel) els.panel.hidden = true;
      runtime.notificationsOpen = false;
      return;
    }

    const list = notificationList();
    const unread = list.filter((item) => !item.read).length;

    if (els.badge) {
      els.badge.hidden = unread === 0;
      els.badge.textContent = unread > 99 ? "99+" : String(unread);
    }
    if (els.button) {
      els.button.classList.toggle("has-unread", unread > 0);
      els.button.setAttribute(
        "aria-label",
        unread ? `Notificaciones, ${unread} sin leer` : "Notificaciones"
      );
    }
    if (els.summary) {
      els.summary.textContent = list.length
        ? unread
          ? `${plural(unread, "nueva", "nuevas")} sin leer · ${plural(list.length, "aviso", "avisos")}`
          : `Todo leído · ${plural(list.length, "aviso", "avisos")}`
        : "Avisos de la carpeta vigilada";
    }
    if (els.list) {
      els.list.innerHTML = list.length
        ? list.map(notificationItemHTML).join("")
        : `<div class="notif__empty">
            <span class="notif__empty-icon">${icon("bell")}</span>
            <strong>Todavía no hay avisos</strong>
            <p>Cuando la carpeta vigilada complete una canción nueva, vas a verla acá sin interrumpir lo que estés escuchando.</p>
          </div>`;
    }

    const markRead = els.panel?.querySelector('[data-action="notifications-clear"]');
    if (markRead) markRead.hidden = unread === 0;
  };

  const openNotifications = () => {
    const els = notificationElements();
    if (!els.root || els.root.hidden || !els.panel) return;
    renderNotifications();
    els.panel.hidden = false;
    els.root.classList.add("is-open");
    els.button?.setAttribute("aria-expanded", "true");
    runtime.notificationsOpen = true;
    els.list?.scrollTo?.({ top: 0 });
  };

  const closeNotifications = () => {
    const els = notificationElements();
    if (!els.panel) return;
    els.panel.hidden = true;
    els.root?.classList.remove("is-open");
    els.button?.setAttribute("aria-expanded", "false");
    runtime.notificationsOpen = false;
  };

  const toggleNotifications = () => {
    if (runtime.notificationsOpen) closeNotifications();
    else openNotifications();
  };

  const markAllNotificationsRead = () => {
    if (!runtime.config) return;
    let changed = false;
    notificationList().forEach((item) => {
      if (!item.read) {
        item.read = true;
        changed = true;
      }
    });
    if (!changed) return;
    saveConfig();
    renderNotifications();
  };

  const markNotificationRead = (id) => {
    let changed = false;
    notificationList().forEach((item) => {
      if (item.id === id && !item.read) {
        item.read = true;
        changed = true;
      }
    });
    if (!changed) return;
    saveConfig();
    renderNotifications();
  };

  const addUploadNotifications = (entries) => {
    if (!runtime.config || !entries.length) return;
    const at = Date.now();
    const additions = entries.map((entry, index) => ({
      id: `wn-${at}-${index}-${Math.random().toString(36).slice(2, 7)}`,
      at: Number(entry.at) || at,
      read: false,
      trackId: Number(entry.trackId) || 0,
      title: String(entry.title || "Canción completada").slice(0, 180),
      artist: String(entry.artist || "").slice(0, 180),
      album: String(entry.album || "").slice(0, 180),
      coverUrl: String(entry.coverUrl || ""),
      fileName: String(entry.fileName || "").slice(0, 220)
    }));
    runtime.config.notifications = [...additions, ...notificationList()].slice(
      0,
      MAX_NOTIFICATIONS
    );
    saveConfig();
    renderNotifications();
  };

  const openNotification = (id) => {
    const entry = notificationList().find((item) => item.id === id);
    if (!entry) return;

    markNotificationRead(id);
    closeNotifications();

    const trackId = Number(entry.trackId) || 0;
    const track = trackId ? state.trackById?.get(trackId) : null;
    const title = track?.title || entry.title || "Canción completada";
    const artist = track?.artist || entry.artist || "Artista desconocido";
    const album = track?.album || entry.album || "";

    openModal({
      title: "Canción completada",
      eyebrow: "Carpeta vigilada",
      body: `
        <div class="notif-detail">
          <span class="notif-detail__art">${coverHTML(track || entry)}</span>
          <div class="notif-detail__copy">
            <strong>${escapeHTML(title)}</strong>
            <span>${escapeHTML(artist)}</span>
            ${album ? `<small>${escapeHTML(album)}</small>` : ""}
            <p>${icon("check")} WaverNote encontró este archivo en tu carpeta y lo agregó a tu biblioteca ${escapeHTML(timeAgo(entry.at) || "recién")}.</p>
            ${entry.fileName ? `<code>${escapeHTML(entry.fileName)}</code>` : ""}
          </div>
        </div>
        <div class="modal__actions">
          ${track ? `<button class="btn btn--primary" data-action="notif-play" data-id="${track.id}">${icon("play")} Reproducir</button>` : ""}
          ${track ? `<button class="btn btn--ghost" data-action="notif-view" data-id="${track.id}">${icon("library")} Ver en biblioteca</button>` : ""}
          <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
        </div>`
    });
  };

  /* ------------------------------------------------------------
     Reporte del escaneo
     ------------------------------------------------------------ */

  const REPORT_STATUS = {
    uploaded: { label: "Completada", tone: "ok" },
    added: { label: "En pendientes", tone: "wait" },
    library: { label: "Ya en tu biblioteca", tone: "soft" },
    known: { label: "Ya procesada", tone: "soft" },
    queued: { label: "En espera", tone: "wait" },
    ambiguous: { label: "Para revisar", tone: "warn" },
    failed: { label: "No se pudo subir", tone: "error" },
    skipped: { label: "Omitido", tone: "muted" },
    duplicate: { label: "Copia repetida", tone: "soft" },
    empty: { label: "Archivo vacío", tone: "error" },
    unmatched: { label: "Sin coincidencia", tone: "muted" },
    "no-pending": { label: "Sin pendientes", tone: "muted" }
  };

  const REPORT_ORDER = [
    "uploaded",
    "added",
    "queued",
    "ambiguous",
    "failed",
    "skipped",
    "duplicate",
    "library",
    "known",
    "empty",
    "unmatched",
    "no-pending"
  ];

  const reportDetail = (item) => {
    const pending = item.pendingTitle ? `«${item.pendingTitle}»` : "";
    const metaLine = [item.artist, item.album, item.genre].filter(Boolean).join(" · ");
    switch (item.status) {
      case "uploaded":
        return metaLine
          ? `${metaLine} · agregada a tu biblioteca`
          : "Agregada a tu biblioteca";
      case "added":
        return pending
          ? `Agregada a pendientes como ${pending}`
          : "Agregada a pendientes con los datos de este archivo";
      case "library":
        return metaLine
          ? `${metaLine} · ya estaba en tu biblioteca`
          : "Ya estaba en tu biblioteca";
      case "known":
        return "Ya la habíamos subido antes desde esta carpeta";
      case "queued":
        return pending
          ? `Coincide con ${pending}; queda para el próximo escaneo`
          : "Queda para el próximo escaneo";
      case "ambiguous":
        return "Coincide con más de una canción pendiente; no se subió para no elegir mal";
      case "failed":
        return item.detail || "No se pudo subir; se reintenta más adelante";
      case "skipped":
        return item.detail || "No se procesó en este escaneo";
      case "duplicate":
        return item.detail || "Otra copia de esta canción ya se estaba subiendo";
      case "empty":
        return "El archivo está vacío";
      case "no-pending":
        return (
          item.detail ||
          (metaLine
            ? `${metaLine} · lista para agregar a pendientes`
            : "No hay canciones pendientes; podés agregar este archivo desde acá")
        );
      default:
        return (
          item.detail ||
          metaLine ||
          "No coincide con ninguna canción pendiente"
        );
    }
  };

  const canAddToPending = (item) =>
    Boolean(item) &&
    (item.status === "unmatched" || item.status === "no-pending") &&
    Number(item.size) > 0 &&
    !item.addedToPending;

  const reportActionHTML = (item, index) => {
    if (canAddToPending(item)) {
      return `<button class="scan-report__add" type="button" data-action="watched-add-pending" data-index="${index}" title="Agregar a pendientes con sus datos y portada" aria-label="Agregar ${escapeHTML(item.title || item.name)} a pendientes">${icon("plus")}<span>Pendientes</span></button>`;
    }
    return "";
  };

  const reportRowHTML = (item, index) => {
    const meta = REPORT_STATUS[item.status] || REPORT_STATUS.unmatched;
    return `
      <div class="scan-report__row scan-report__row--${meta.tone}" data-report-index="${index}">
        <span class="scan-report__art">${coverHTML(item)}</span>
        <span class="scan-report__main">
          <strong>${escapeHTML(item.title || item.name)}</strong>
          <small title="${escapeHTML(item.relative || item.name)}">${escapeHTML(item.relative || item.name)}</small>
          <span class="scan-report__detail">${escapeHTML(reportDetail(item))}</span>
        </span>
        <span class="scan-report__status scan-report__status--${meta.tone}">${meta.label}</span>
        <span class="scan-report__action">${reportActionHTML(item, index)}</span>
      </div>`;
  };

  const reportSummaryHTML = (counts = {}) =>
    [
      ["uploaded", "completadas"],
      ["added", "en pendientes"],
      ["library", "ya en tu biblioteca"],
      ["known", "ya procesadas"],
      ["queued", "en espera"],
      ["ambiguous", "para revisar"],
      ["failed", "con error"],
      ["skipped", "omitidos"],
      ["duplicate", "copias repetidas"],
      ["empty", "vacíos"],
      ["unmatched", "sin coincidencia"],
      ["no-pending", "sin pendientes"]
    ]
      .filter(([key]) => Number(counts[key]) > 0)
      .map(
        ([key, label]) =>
          `<span class="scan-report__stat scan-report__stat--${REPORT_STATUS[key].tone}"><strong>${Number(counts[key])}</strong>${label}</span>`
      )
      .join("");

  const syncReportSummary = (report) => {
    const summary = document.querySelector("[data-report-summary]");
    if (!summary) return;
    const html = reportSummaryHTML(report.counts || {});
    summary.innerHTML = html;
    summary.hidden = !html;
  };

  const reportTotalText = (report) =>
    `${plural(Number(report.files) || 0, "archivo revisado", "archivos revisados")} · ${plural(Number(report.pending) || 0, "canción pendiente", "canciones pendientes")} en tu lista`;

  const syncReportTotal = (report) => {
    const total = document.querySelector("[data-report-total]");
    if (total) total.textContent = reportTotalText(report);
  };

  const syncReportItem = (report, index) => {
    const row = document.querySelector(
      `.scan-report__row[data-report-index="${Number(index)}"]`
    );
    const item = report?.items?.[Number(index)];
    if (!row || !item) return;

    const meta = REPORT_STATUS[item.status] || REPORT_STATUS.unmatched;
    row.className = `scan-report__row scan-report__row--${meta.tone}`;

    const art = row.querySelector(".scan-report__art");
    if (art) art.innerHTML = coverHTML(item);

    const title = row.querySelector(".scan-report__main strong");
    if (title) title.textContent = item.title || item.name || "";

    const detail = row.querySelector(".scan-report__detail");
    if (detail) detail.textContent = reportDetail(item);

    const status = row.querySelector(".scan-report__status");
    if (status) {
      status.className = `scan-report__status scan-report__status--${meta.tone}`;
      status.textContent = meta.label;
    }

    const action = row.querySelector(".scan-report__action");
    if (action) action.innerHTML = reportActionHTML(item, index);
  };

  const pendingBulkLabel = (count) => {
    const total = Number(count) || 0;
    const batch = Math.min(total, MAX_PENDING_ADDS_PER_RUN);
    return total > batch
      ? `Agregar ${batch} de ${total} archivos`
      : `Agregar ${plural(total, "archivo", "archivos")}`;
  };

  const syncReportBulk = (report) => {
    const bar = document.querySelector("[data-report-pending-bar]");
    if (!bar) return;

    const pendingCount = report.items.filter(canAddToPending).length;
    if (!pendingCount) {
      bar.remove();
      return;
    }

    const button = bar.querySelector('[data-action="watched-add-pending-all"]');
    if (button) {
      button.disabled = runtime.pendingAdding;
      button.innerHTML = runtime.pendingAdding
        ? `${icon("clock")} Agregando…`
        : `${icon("plus")} ${pendingBulkLabel(pendingCount)} a pendientes`;
    }
    const copy = bar.querySelector("[data-report-pending-text]");
    if (copy) {
      copy.textContent = runtime.pendingAdding
        ? runtime.pendingProgress || "Agregando canciones con sus datos y portada…"
        : `${plural(pendingCount, "archivo puede", "archivos pueden")} sumarse a pendientes con sus datos y portada.`;
    }
  };

  // En Android las etiquetas llegan sin la portada para no cruzar varios
  // megabytes por el puente durante el escaneo. Cuando el usuario abre el
  // reporte, las portadas se leen de a una para no bloquear la interfaz.
  const hydrateAndroidCovers = (report) => {
    if (!IS_ANDROID) return;
    const token = ++runtime.coverHydration;
    const queue = report.items
      .map((item, index) => ({ item, index }))
      .filter(
        ({ item }) =>
          item?.uri &&
          !item.coverUrl &&
          (item.status === "unmatched" || item.status === "no-pending")
      )
      .slice(0, MAX_REPORT_COVERS);
    if (!queue.length) return;

    const step = () => {
      if (token !== runtime.coverHydration) return;
      const entry = queue.shift();
      if (!entry) return;

      const row = document.querySelector(
        `.scan-report__row[data-report-index="${entry.index}"]`
      );
      if (!row) return; // El reporte se cerró: se retoma al abrirlo de nuevo.

      try {
        const blob = androidCoverBlob(entry.item.uri);
        if (blob) {
          const key = Core.fileKeys(reportItemFile(entry.item)).contentKey;
          const url = rememberCover(key, blob);
          if (url) {
            entry.item.coverUrl = url;
            const art = row.querySelector(".scan-report__art");
            if (art) art.innerHTML = coverHTML(entry.item);
          }
        }
      } catch (err) {
        /* una portada ilegible no rompe el reporte */
      }

      window.requestAnimationFrame(step);
    };

    window.requestAnimationFrame(step);
  };

  const openReport = (report = runtime.config?.lastReport) => {
    if (!report || !Array.isArray(report.items)) {
      toast("Todavía no hay un escaneo para mostrar.");
      return;
    }

    const counts = report.counts || {};
    const chips = reportSummaryHTML(counts);
    const pendingCount = report.items.filter(canAddToPending).length;

    const omitted = Number(report.omitted) || 0;
    const list = report.items.map(reportRowHTML).join("");
    const folder = report.folder || "Tu carpeta";
    const meta = [
      `${icon("folder")} ${escapeHTML(folder)}`,
      `${icon("clock")} ${escapeHTML(timeAgo(report.at) || "recién")}`,
      escapeHTML(report.manual ? "Escaneo manual" : "Escaneo automático")
    ].join("");

    openModal({
      title: "Resultado del escaneo",
      eyebrow: "Carpeta vigilada",
      body: `
        <div class="scan-report">
          <p class="scan-report__meta">${meta}</p>
          <div class="scan-report__summary" data-report-summary ${chips ? "" : "hidden"}>${chips}</div>
          <p class="scan-report__total" data-report-total>${reportTotalText(report)}</p>
          ${report.hint ? `<p class="scan-report__hint">${escapeHTML(report.hint)}</p>` : ""}
          ${
            pendingCount
              ? `<div class="scan-report__pending-bar" data-report-pending-bar>
                  <p data-report-pending-text>${plural(pendingCount, "archivo puede", "archivos pueden")} sumarse a pendientes con sus datos y portada.</p>
                  <button class="btn btn--small btn--primary" data-action="watched-add-pending-all" ${runtime.pendingAdding ? "disabled" : ""}>${icon("plus")} ${pendingBulkLabel(pendingCount)} a pendientes</button>
                </div>`
              : ""
          }
          ${
            list
              ? `<div class="scan-report__list">${list}</div>`
              : `<p class="scan-report__empty">No encontramos archivos de audio en esta carpeta.</p>`
          }
          ${omitted ? `<p class="scan-report__note">Mostramos los primeros ${MAX_REPORT_ITEMS} archivos. Los otros ${omitted} se resumieron en los contadores.</p>` : ""}
          <div class="modal__actions">
            <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
            <button class="btn btn--primary" data-action="watched-rescan">${icon("search")} Escanear otra vez</button>
          </div>
        </div>`
    });
    hydrateAndroidCovers(report);
  };

  const inviteCardHTML = () => `
    <section class="watch-card watch-card--invite">
      <span class="watch-card__icon">${icon("folder")}</span>
      <div class="watch-card__body">
        <div class="watch-card__head">
          <div>
            <h3 class="watch-card__title">Completá pendientes sin buscar archivo por archivo</h3>
            <p class="watch-card__copy">Elegí la carpeta donde guardás tu música. Cuando aparezca un archivo que coincide con una canción pendiente, WaverNote lo sube sola con tus datos y portada.</p>
          </div>
          <span class="watch-pill watch-pill--paused">Opcional</span>
        </div>
        <p class="watch-card__meta">Windows y Android · funciona con subcarpetas · no toca ni borra tus archivos</p>
        <div class="watch-card__actions">
          ${button("watched-pick", "Elegir carpeta", "folder", "btn btn--small btn--primary")}
          ${button("watched-help", "Cómo funciona", "sparkles")}
        </div>
        ${legalNote()}
      </div>
    </section>`;

  const cardHTML = () => {
    if (!runtime.supported) return "";

    const config = runtime.config;
    if (!config?.folder) return inviteCardHTML();

    const status = statusInfo();
    const result = config.lastResult;
    const pendingCount = Array.isArray(state.pending) ? state.pending.length : 0;
    const folderLabel = escapeHTML(config.folder.label || shortLabel(config.folder.value));

    const stats = [];
    if (pendingCount) stats.push(`${plural(pendingCount, "canción pendiente", "canciones pendientes")}`);
    if (result?.files) stats.push(`${plural(result.files, "archivo revisado", "archivos revisados")}`);
    if (result?.uploaded) stats.push(`${plural(result.uploaded, "completada", "completadas")}`);
    if (result?.ambiguous) stats.push(`${result.ambiguous} para revisar`);

    const metaParts = [];
    if (config.lastScanAt) metaParts.push(`Último escaneo ${timeAgo(config.lastScanAt)}`);
    if (stats.length) metaParts.push(stats.join(" · "));

    const ambiguity =
      result?.ambiguous > 0
        ? `<p class="watch-card__ambiguity">${icon("x")} ${plural(result.ambiguous, "archivo coincide", "archivos coinciden")} con más de una canción pendiente y quedó sin subir. Usá ${icon("upload")} en la fila para elegir vos.</p>`
        : "";

    const permission = config.permissionLost
      ? `<p class="watch-card__warning">${icon("lock")} Android dejó de dar acceso a esta carpeta. Volvé a elegirla para que WaverNote pueda leerla otra vez.</p>`
      : config.folderMissing
        ? `<p class="watch-card__warning">${icon("folder")} No encontramos la carpeta en este equipo. Si la moviste, cambiaste el nombre o desconectaste el disco, elegí la nueva ubicación.</p>`
        : "";

    return `
      <section class="watch-card watch-card--configured">
        <span class="watch-card__icon">${icon("folder")}</span>
        <div class="watch-card__body">
          <div class="watch-card__head">
            <div class="watch-card__head-main">
              <p class="watch-card__eyebrow">Carpeta vigilada</p>
              <h3 class="watch-card__folder" title="${escapeHTML(config.folder.value)}">${folderLabel}</h3>
            </div>
            <span class="watch-pill watch-pill--${status.tone}">${status.label}</span>
          </div>

          <p class="watch-card__copy">${
            config.permissionLost
              ? "Necesitamos permiso para leer la carpeta. Tus archivos siguen donde están."
              : config.folderMissing
                ? "La carpeta ya no está en la ubicación guardada. Tus archivos siguen donde los dejaste."
                : config.enabled
                  ? "Revisamos esta carpeta al abrir la app, al volver a ella y cada pocos minutos. Solo subimos lo que completa un pendiente."
                  : "La vigilancia está en pausa. Las canciones pendientes siguen esperando su archivo."
          }</p>

          ${metaParts.length ? `<p class="watch-card__meta">${escapeHTML(metaParts.join(" · "))}</p>` : ""}
          ${permission}
          ${ambiguity}
          ${!config.permissionLost && !config.folderMissing && result ? `<p class="watch-card__hint">${escapeHTML(layoutHint(result))}</p>` : ""}

          <div class="watch-card__actions">
            ${config.permissionLost || config.folderMissing ? "" : button("watched-scan", runtime.scanning ? "Revisando…" : "Escanear ahora", "search", "btn btn--small btn--primary", runtime.scanning ? "disabled" : "")}
            ${config.lastReport ? button("watched-report", "Ver último escaneo", "list") : ""}
            ${config.folderMissing ? "" : button("watched-toggle", config.enabled ? "Pausar" : "Activar", config.enabled ? "pause" : "play")}
            ${button("watched-pick", config.permissionLost || config.folderMissing ? "Volver a elegir" : "Cambiar", "folder")}
            ${button("watched-help", "", "sparkles", "icon-btn icon-btn--tiny watch-card__help", 'aria-label="Cómo funciona la carpeta vigilada" title="Cómo funciona"')}
            ${button("watched-forget", "", "trash", "icon-btn icon-btn--tiny watch-card__forget", 'aria-label="Olvidar esta carpeta" title="Olvidar esta carpeta"')}
          </div>
          ${legalNote()}
        </div>
      </section>`;
  };

  /* ------------------------------------------------------------
     Native bridge
     ------------------------------------------------------------ */

  const parsePayload = (value) => {
    if (!value) return null;
    if (typeof value === "object") return value;
    try {
      return JSON.parse(String(value));
    } catch (err) {
      return null;
    }
  };

  const desktopInvoke = (command, args = {}) => {
    const core = tauriCore();
    if (!core?.invoke) return Promise.reject(new Error("El puente de la app no está disponible."));
    return core.invoke(command, args);
  };

  const waitForPick = () =>
    new Promise((resolve, reject) => {
      if (runtime.pickWaiter) runtime.pickWaiter.reject(new Error("Ya hay un selector abierto."));
      const timer = window.setTimeout(() => {
        if (runtime.pickWaiter?.timer === timer) runtime.pickWaiter = null;
        reject(new Error("El selector de carpetas no respondió."));
      }, 5 * 60 * 1000);
      runtime.pickWaiter = { resolve, reject, timer };
    });

  const waitForScan = () =>
    new Promise((resolve, reject) => {
      if (runtime.scanWaiter) runtime.scanWaiter.reject(new Error("Ya hay un escaneo en curso."));
      const timer = window.setTimeout(() => {
        if (runtime.scanWaiter?.timer === timer) runtime.scanWaiter = null;
        reject(new Error("El escaneo de la carpeta tardó demasiado."));
      }, 4 * 60 * 1000);
      runtime.scanWaiter = { resolve, reject, timer };
    });

  const settlePick = (payload) => {
    const waiter = runtime.pickWaiter;
    if (!waiter) return;
    runtime.pickWaiter = null;
    window.clearTimeout(waiter.timer);
    const data = parsePayload(payload);
    if (!data) {
      waiter.reject(new Error("No se pudo leer la carpeta elegida."));
      return;
    }
    if (data.ok === false) {
      if (data.cancelled) {
        waiter.resolve(null);
        return;
      }
      const error = new Error(data.error || "No se pudo abrir la carpeta.");
      error.permissionLost = Boolean(data.permission);
      waiter.reject(error);
      return;
    }
    waiter.resolve({
      kind: data.kind === "tree" ? "tree" : "path",
      value: String(data.value || data.uri || ""),
      label: String(data.label || "Carpeta de música")
    });
  };

  const settleScan = (payload) => {
    const waiter = runtime.scanWaiter;
    if (!waiter) return;
    runtime.scanWaiter = null;
    window.clearTimeout(waiter.timer);
    const data = parsePayload(payload);
    if (!data) {
      waiter.reject(new Error("No se pudo leer el resultado del escaneo."));
      return;
    }
    if (data.ok === false || data.permissionLost) {
      const error = new Error(data.error || "No se pudo revisar la carpeta.");
      error.permissionLost = Boolean(data.permission || data.permissionLost);
      waiter.reject(error);
      return;
    }
    waiter.resolve(data);
  };

  const settleUpload = (payload) => {
    const data = parsePayload(payload);
    if (!data?.requestId) return;
    const waiter = runtime.uploads.get(String(data.requestId));
    if (!waiter) return;
    runtime.uploads.delete(String(data.requestId));
    if (data.ok === false) {
      const error = new Error(data.error || "No se pudo subir el archivo.");
      error.status = Number(data.status) || 0;
      waiter.reject(error);
      return;
    }
    waiter.resolve(data.track || null);
  };

  const onNativeFolderPicked = (payload) => settlePick(payload);
  const onNativeScan = (payload) => settleScan(payload);

  const nativePick = async () => {
    if (IS_ANDROID) {
      const api = bridge();
      if (!api?.pickWatchedFolder) throw new Error("El selector de Android no está disponible.");
      const promise = waitForPick();
      api.pickWatchedFolder();
      return promise;
    }

    const picked = await desktopInvoke("watched_pick_folder");
    if (!picked) return null;
    return {
      kind: "path",
      value: String(picked),
      label: shortLabel(picked)
    };
  };

  const normalizeFile = (raw) => {
    const relative = String(raw?.relative || raw?.name || "").replace(/\\/g, "/");
    const segments = relative.split("/").filter(Boolean);
    return {
      path: String(raw?.path || raw?.uri || ""),
      uri: String(raw?.uri || ""),
      name: String(raw?.name || segments[segments.length - 1] || ""),
      relative,
      parent: segments.length >= 2 ? segments[segments.length - 2] : "",
      grandparent: segments.length >= 3 ? segments[segments.length - 3] : "",
      size: Math.max(0, Number(raw?.size) || 0),
      modified: Math.max(0, Number(raw?.modified) || 0)
    };
  };

  const nativeScan = async (folder) => {
    if (IS_ANDROID) {
      const api = bridge();
      if (!api?.scanWatchedFolder) throw new Error("El escaneo de Android no está disponible.");
      const promise = waitForScan();
      api.scanWatchedFolder(folder.value);
      return promise;
    }

    const result = await desktopInvoke("watched_scan_folder", {
      root: folder.value,
      maxFiles: 20000,
      maxDepth: 12
    });
    return result || {};
  };

  const chunkBytes = (value) => {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    if (Array.isArray(value)) return Uint8Array.from(value);
    return new Uint8Array(0);
  };

  const mimeFor = (name) => {
    const extension = String(name || "").split(".").pop().toLowerCase();
    const map = {
      mp3: "audio/mpeg",
      wav: "audio/wav",
      ogg: "audio/ogg",
      oga: "audio/ogg",
      opus: "audio/ogg",
      m4a: "audio/mp4",
      mp4: "audio/mp4",
      aac: "audio/aac",
      flac: "audio/flac",
      webm: "audio/webm"
    };
    return map[extension] || "application/octet-stream";
  };

  const readDesktopFile = async (file) => {
    const size = Number(file.size) || 0;
    if (!size) throw new Error("El archivo está vacío.");

    const chunks = [];
    let offset = 0;
    while (offset < size) {
      const length = Math.min(READ_CHUNK_BYTES, size - offset);
      const part = await desktopInvoke("watched_read_chunk", {
        path: file.path,
        offset,
        length
      });
      const bytes = chunkBytes(part);
      if (!bytes.byteLength) break;
      chunks.push(bytes);
      offset += bytes.byteLength;
    }

    if (offset < size) throw new Error("El archivo cambió mientras lo leíamos.");
    return new File(chunks, file.name, {
      type: mimeFor(file.name),
      lastModified: file.modified || Date.now()
    });
  };

  const rememberCover = (key, blob) => {
    if (!key || !blob?.size) return "";
    // Una portada enorme no entra en el reporte: se descarta en vez de
    // ocupar memoria durante toda la sesión.
    if (Number(blob.size) > MAX_REPORT_COVER_BYTES) return "";
    const cached = runtime.coverCache.get(key);
    if (cached) {
      // Mantenerlo como el más reciente dentro del límite.
      runtime.coverCache.delete(key);
      runtime.coverCache.set(key, cached);
      return cached;
    }

    let url = "";
    try {
      url = URL.createObjectURL(blob);
    } catch (err) {
      return "";
    }

    runtime.coverCache.set(key, url);
    while (runtime.coverCache.size > MAX_REPORT_COVERS) {
      const oldest = runtime.coverCache.keys().next().value;
      if (!oldest) break;
      const stale = runtime.coverCache.get(oldest);
      runtime.coverCache.delete(oldest);
      try {
        if (stale) URL.revokeObjectURL(stale);
      } catch (err) {
        /* noop */
      }
    }
    return url;
  };

  const clearCoverCache = () => {
    runtime.coverHydration += 1;
    runtime.coverCache.forEach((url) => {
      try {
        URL.revokeObjectURL(url);
      } catch (err) {
        /* noop */
      }
    });
    runtime.coverCache.clear();
  };

  const desktopMetadata = async (file) => {
    if (Number(file.size) > MAX_TAG_BYTES_DESKTOP) return null;
    if (typeof WNMetadata === "undefined" || !WNMetadata.readTrackMetadata) return null;
    try {
      const object = await readDesktopFile(file);
      const metadata = await WNMetadata.readTrackMetadata(object);
      return {
        title: metadata.title,
        artist: metadata.artist,
        album: metadata.album,
        genre: metadata.genre,
        duration: metadata.duration,
        coverUrl: rememberCover(
          Core.fileKeys(file).contentKey,
          metadata.coverBlob
        )
      };
    } catch (err) {
      return null;
    }
  };

  const androidMetadata = async (files) => {
    const api = bridge();
    if (!api?.readWatchedTags || !files.length) return new Map();
    try {
      const payload = files.map((file) => ({
        uri: file.uri,
        name: file.name,
        size: file.size
      }));
      const raw = api.readWatchedTags(JSON.stringify(payload));
      const parsed = parsePayload(raw);
      const map = new Map();
      (Array.isArray(parsed) ? parsed : []).forEach((entry) => {
        if (!entry?.uri) return;
        map.set(String(entry.uri), {
          title: String(entry.title || ""),
          artist: String(entry.artist || ""),
          album: String(entry.album || ""),
          genre: String(entry.genre || ""),
          duration: Number(entry.duration) || 0
        });
      });
      return map;
    } catch (err) {
      return null;
    }
  };

  const androidCoverBlob = (uri) => {
    const api = bridge();
    if (!api?.readWatchedCover || !uri) return null;
    try {
      const data = parsePayload(api.readWatchedCover(JSON.stringify({ uri })));
      if (!data?.ok || !data?.data) return null;
      const binary = atob(String(data.data));
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return new Blob([bytes], {
        type: String(data.mime || "image/jpeg")
      });
    } catch (err) {
      return null;
    }
  };

  const androidUpload = (file, fields) =>
    new Promise((resolve, reject) => {
      const api = bridge();
      if (!api?.uploadWatchedFile) {
        reject(new Error("La subida de Android no está disponible."));
        return;
      }

      runtime.uploadSeq += 1;
      const requestId = `watch-${Date.now()}-${runtime.uploadSeq}`;
      const timer = window.setTimeout(() => {
        runtime.uploads.delete(requestId);
        reject(new Error("La subida tardó demasiado."));
      }, 6 * 60 * 1000);

      runtime.uploads.set(requestId, {
        resolve: (track) => {
          window.clearTimeout(timer);
          resolve(track);
        },
        reject: (err) => {
          window.clearTimeout(timer);
          reject(err);
        }
      });

      try {
        api.uploadWatchedFile(
          JSON.stringify({
            requestId,
            uri: file.uri,
            name: file.name,
            fields,
            token: getToken(),
            apiBase: API_BASE
          })
        );
      } catch (err) {
        runtime.uploads.delete(requestId);
        window.clearTimeout(timer);
        reject(err);
      }
    });

  /* ------------------------------------------------------------
     Búsqueda de coincidencias
     ------------------------------------------------------------ */

  const recentFailure = (config, contentKey) => {
    const failure = config.failures?.[contentKey];
    if (!failure) return false;
    if (Date.now() - (Number(failure.at) || 0) < FAILURE_RETRY_MS) return true;
    delete config.failures[contentKey];
    return false;
  };

  const planMatches = (files, pending, config, libraryTracks = []) => {
    const index = Core.buildPendingIndex(pending);
    const libraryIndex = Core.buildPendingIndex(
      (Array.isArray(libraryTracks) ? libraryTracks : []).filter(
        (track) => track && Number(track.id)
      )
    );
    const usedPending = new Set();
    const matchedFiles = new Set();
    const matches = [];
    const ambiguous = [];
    const records = new Map();
    const metadata = new Map();

    files.forEach((file) => {
      const keys = Core.fileKeys(file);
      records.set(file.path, {
        file,
        status: file.size > 0 ? "unmatched" : "empty",
        detail: file.size > 0 ? "" : "El archivo está vacío.",
        contentKey: keys.contentKey,
        knownEntry: config.known?.[keys.contentKey] || null,
        title: Core.fileStem(file.name || file.relative || ""),
        artist: "",
        album: "",
        genre: "",
        duration: 0,
        coverUrl: "",
        pendingTitle: "",
        pendingArtist: "",
        trackId: 0
      });
    });

    const consider = (file, tags = null) => {
      const record = records.get(file.path);
      if (!record) return;

      // En Android no hay conversión nativa de video: se omite para no subir
      // el archivo tal cual. Desde la carga manual sí se convierte y se le
      // toma la portada.
      if (IS_ANDROID && typeof WNVideo !== "undefined" && WNVideo.isVideoFile(file)) {
        record.status = "skipped";
        record.detail = "Los videos se agregan desde la carga manual.";
        matchedFiles.add(file.path);
        return;
      }

      const result = Core.matchPendingForFile(file, index, tags);

      if (result?.ambiguous) {
        if (!matchedFiles.has(file.path)) {
          matchedFiles.add(file.path);
          ambiguous.push({ file, result });
        }
        record.status = "ambiguous";
        record.detail = "Coincide con más de una canción pendiente.";
        const first = result.alternatives?.[0]?.pending;
        if (first) {
          record.title = first.title || record.title;
          record.artist = first.artist || "";
          record.album = first.album || "";
          record.coverUrl = first.coverUrl || "";
          record.pendingTitle = first.title || "";
          record.pendingArtist = first.artist || "";
        }
        return;
      }

      if (!result) return;

      const keys = Core.fileKeys(file);
      const pendingItem = result.pending || {};
      record.title = pendingItem.title || record.title;
      record.artist = pendingItem.artist || "";
      record.album = pendingItem.album || "";
      record.coverUrl = pendingItem.coverUrl || "";
      record.pendingTitle = pendingItem.title || "";
      record.pendingArtist = pendingItem.artist || "";

      if (config.known?.[keys.contentKey]) {
        record.status = "known";
        record.detail = "Ya la subimos antes desde esta carpeta.";
        return;
      }

      if (recentFailure(config, keys.contentKey)) {
        record.status = "failed";
        record.detail = "El último intento falló; se reintenta más adelante.";
        return;
      }

      const pendingId = Number(pendingItem.id) || 0;
      if (!pendingId || usedPending.has(pendingId)) {
        record.status = "duplicate";
        record.detail = "Otra copia de esta canción ya está en la lista de subida.";
        return;
      }

      usedPending.add(pendingId);
      matchedFiles.add(file.path);
      record.status = "matched";
      record.trackId = 0;
      matches.push({
        file,
        pending: pendingItem,
        contentKey: keys.contentKey,
        pathKey: keys.pathKey,
        record,
        tags
      });
    };

    files.forEach((file) => consider(file));

    const unmatched = files.filter(
      (file) => !matchedFiles.has(file.path) && file.size > 0
    );
    return {
      index,
      libraryIndex,
      matches,
      ambiguous,
      unmatched,
      consider,
      records,
      metadata
    };
  };

  const applyFileMetadata = (plan, file, tags) => {
    const record = plan.records.get(file.path);
    if (!record || record.status !== "unmatched" || !tags) return;
    record.title = tags.title || record.title;
    record.artist = tags.artist || record.artist;
    record.album = tags.album || record.album;
    record.genre = tags.genre || record.genre;
    record.duration = Number(tags.duration) || record.duration;
    if (tags.coverUrl && !record.coverUrl) record.coverUrl = tags.coverUrl;
  };

  const addMetadataMatches = async (plan, config) => {
    if (!plan.unmatched.length) return;

    // Las etiquetas son el último recurso: leerlas cuesta más que comparar
    // nombres. Priorizamos los archivos más recientes y no repetimos la
    // lectura de un archivo que ya revisamos en esta sesión. También sirven
    // para mostrar los datos reales en el reporte y al agregarlo a pendientes.
    const fresh = plan.unmatched
      .filter((file) => file.size > 0)
      .filter((file) => !runtime.tagChecked.has(Core.fileKeys(file).contentKey))
      .sort((a, b) => (Number(b.modified) || 0) - (Number(a.modified) || 0));

    if (IS_ANDROID) {
      const candidates = fresh.slice(0, MAX_TAG_FILES_ANDROID);
      if (!candidates.length) return;
      const metadata = await androidMetadata(candidates);
      if (!metadata) return;
      candidates.forEach((file) => {
        runtime.tagChecked.add(Core.fileKeys(file).contentKey);
        const tags = metadata.get(file.uri);
        if (!tags) return;
        plan.metadata.set(file.path, tags);
        plan.consider(file, tags);
        applyFileMetadata(plan, file, tags);
      });
      return;
    }

    const candidates = fresh
      .filter((file) => file.size <= MAX_TAG_BYTES_DESKTOP)
      .slice(0, MAX_TAG_FILES_DESKTOP);
    for (const file of candidates) {
      const tags = await desktopMetadata(file);
      if (!tags) continue;
      runtime.tagChecked.add(Core.fileKeys(file).contentKey);
      plan.metadata.set(file.path, tags);
      plan.consider(file, tags);
      applyFileMetadata(plan, file, tags);
    }
  };

  const uploadMatch = async (match, pending) => {
    const fields = {
      pendingId: pending.id,
      title: pending.title,
      artist: pending.artist,
      album: pending.album,
      duration: pending.duration,
      genre: match.tags?.genre || pending.genre || ""
    };

    if (IS_ANDROID) {
      return androidUpload(match.file, fields);
    }

    const file = await readDesktopFile(match.file);
    let metadata = null;
    try {
      if (typeof WNMetadata !== "undefined" && WNMetadata.readTrackMetadata) {
        metadata = await WNMetadata.readTrackMetadata(file);
      }
    } catch (err) {
      metadata = null;
    }

    let cover = null;
    if (metadata?.coverBlob) {
      try {
        cover = await WNMetadata.prepareCoverForUpload(metadata.coverBlob, file.name);
      } catch (err) {
        cover = null;
      }
    }

    // La carpeta vigilada también puede encontrar un video con el mismo
    // nombre que una canción pendiente. Se convierte a MP3 y se le toma la
    // miniatura, igual que en la carga manual, en vez de subirlo tal cual.
    let uploadFile = file;
    let duration = fields.duration || metadata?.duration || 0;

    if (typeof WNVideo !== "undefined" && WNVideo.isVideoFile(file)) {
      if (!cover) {
        try {
          cover = await WNVideo.extractThumbnail(file);
        } catch (err) {
          cover = null;
        }
      }

      const converted = await WNVideo.convertToMp3(file);
      uploadFile = converted.file;
      duration = converted.duration || duration;
    }

    return uploadTrackFile({
      file: uploadFile,
      fields: {
        ...fields,
        title: fields.title || metadata?.title || "",
        artist: fields.artist || metadata?.artist || "",
        album: fields.album || metadata?.album || "",
        genre: fields.genre || metadata?.genre || "",
        duration
      },
      cover,
      onProgress: () => {}
    });
  };

  /* ------------------------------------------------------------
     Agregar archivos del reporte a pendientes
     ------------------------------------------------------------ */

  const reportItemFile = (item) =>
    normalizeFile({
      path: item?.path,
      uri: item?.uri,
      name: item?.name,
      relative: item?.relative,
      size: item?.size,
      modified: item?.modified
    });

  const itemFallbackMetadata = (item) => ({
    title: item?.title || Core.fileStem(item?.name || ""),
    artist: item?.artist || "",
    album: item?.album || "",
    genre: item?.genre || "",
    duration: Number(item?.duration) || 0,
    cover: null
  });

  const readItemMetadata = async (item) => {
    const fallback = itemFallbackMetadata(item);
    if (typeof WNMetadata === "undefined") return fallback;

    if (IS_ANDROID) {
      const file = reportItemFile(item);
      if (!file.uri) return fallback;
      let tags = null;
      try {
        const metadata = await androidMetadata([file]);
        tags = metadata?.get(file.uri) || null;
      } catch (err) {
        tags = null;
      }

      let cover = null;
      try {
        const blob = androidCoverBlob(file.uri);
        if (blob) cover = await WNMetadata.prepareCoverForUpload(blob, file.name);
      } catch (err) {
        cover = null;
      }

      return {
        ...fallback,
        ...(tags || {}),
        cover
      };
    }

    const file = reportItemFile(item);
    if (!file.path) return fallback;
    // Los archivos muy grandes se agregan igual, pero con los datos que ya
    // tenía el reporte: cargarlos enteros para leer etiquetas puede agotar
    // la memoria de la app.
    if (file.size > MAX_TAG_BYTES_DESKTOP) return fallback;
    try {
      const object = await readDesktopFile(file);
      const metadata = await WNMetadata.readTrackMetadata(object);
      let cover = null;
      if (metadata.coverBlob) {
        try {
          cover = await WNMetadata.prepareCoverForUpload(metadata.coverBlob, file.name);
        } catch (err) {
          cover = null;
        }
      }
      return {
        title: metadata.title || fallback.title,
        artist: metadata.artist || fallback.artist,
        album: metadata.album || fallback.album,
        genre: metadata.genre || fallback.genre,
        duration: metadata.duration || fallback.duration,
        cover
      };
    } catch (err) {
      // Si el archivo se movió o el permiso venció, los datos que ya
      // teníamos en el reporte siguen sirviendo para crear el pendiente.
      return fallback;
    }
  };

  const uploadPendingCover = async (cover) => {
    if (!cover?.size) return "";
    try {
      const form = new FormData();
      form.append("cover", cover, cover.name || "cover.jpg");
      const headers = {};
      const token = getToken();
      if (token) headers.Authorization = `Bearer ${token}`;

      const response = await fetch(`${API_BASE}/wavernote/pending/cover`, {
        method: "POST",
        headers,
        body: form
      });
      const text = await response.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch (err) {
        data = null;
      }

      if (!response.ok) {
        throw new Error(
          apiErrorMessage(
            response.status,
            data?.error || text,
            `No se pudo subir la portada (${response.status}).`
          )
        );
      }

      const coverUrl = String(data?.coverUrl || "");
      return /^https?:\/\//i.test(coverUrl) ? coverUrl : "";
    } catch (err) {
      // La portada es opcional: si falla, la canción igual queda pendiente
      // con sus datos y la carpeta vigilada puede completarla después.
      console.warn("[WaverNote] pending cover:", err);
      return "";
    }
  };

  const rememberPending = (pending) => {
    const id = Number(pending?.id) || 0;
    if (!id || !Array.isArray(state.pending)) return;
    if (state.pending.some((entry) => Number(entry.id) === id)) return;
    state.pending = [pending, ...state.pending];
  };

  const createPendingFromItem = async (item) => {
    const metadata = await readItemMetadata(item);
    const title = String(metadata.title || item.title || Core.fileStem(item.name || ""))
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 160);
    if (!title) throw new Error("El archivo no tiene un título que se pueda usar.");

    const payload = {
      title,
      artist: String(metadata.artist || "").replace(/\s+/g, " ").trim().slice(0, 120),
      album: String(metadata.album || "").replace(/\s+/g, " ").trim().slice(0, 120),
      genre: String(metadata.genre || "").replace(/\s+/g, " ").trim().slice(0, 60),
      duration: Math.min(Math.max(Number(metadata.duration) || 0, 0), 6 * 60 * 60),
      coverUrl: await uploadPendingCover(metadata.cover)
    };

    const data = await api("/wavernote/pending/import", {
      method: "POST",
      body: {
        source: "Carpeta vigilada",
        tracks: [payload]
      }
    });

    const pending = Array.isArray(data?.pending) ? data.pending[0] : null;
    if (Number(data?.imported) > 0 && pending) {
      return {
        status: "added",
        created: true,
        pending,
        coverUrl: pending.coverUrl || payload.coverUrl || "",
        detail: "Agregada a pendientes con los datos del archivo."
      };
    }

    const skipped = data?.skipped || {};
    if (Number(skipped.alreadyPending) > 0 || Number(skipped.duplicated) > 0) {
      const existing = (state.pending || []).find((entry) => Core.samePendingSong(entry, payload));
      return {
        status: "added",
        created: false,
        pending: existing || null,
        coverUrl: "",
        detail: "Ya estaba en pendientes."
      };
    }
    if (Number(skipped.inLibrary) > 0) {
      return {
        status: "library",
        created: false,
        pending: null,
        coverUrl: "",
        detail: "Ya estaba en tu biblioteca."
      };
    }

    throw new Error("El servidor no guardó la canción pendiente.");
  };

  const updateReportCounts = (report, fromStatus, toStatus) => {
    if (!report) return;
    if (!report.counts || typeof report.counts !== "object") report.counts = {};
    if (fromStatus) {
      report.counts[fromStatus] = Math.max(
        0,
        (Number(report.counts[fromStatus]) || 0) - 1
      );
    }
    if (toStatus) {
      report.counts[toStatus] = (Number(report.counts[toStatus]) || 0) + 1;
    }
  };

  const applyPendingResult = (
    report,
    index,
    result,
    { refresh = true, save = true } = {}
  ) => {
    const item = report?.items?.[index];
    if (!item || !result) return;

    const previous = item.status;
    item.status = result.status;
    item.pendingTitle = result.pending?.title || item.pendingTitle || item.title;
    item.pendingArtist = result.pending?.artist || item.pendingArtist || item.artist;
    item.pendingId = Number(result.pending?.id) || 0;
    item.coverUrl = result.coverUrl || item.coverUrl || "";
    item.detail = result.detail || "";
    item.addedToPending = result.status === "added";
    item.addedAt = Date.now();

    if (result.created && previous !== "added") {
      report.pending = (Number(report.pending) || 0) + 1;
    }

    if (result.pending) {
      rememberPending({
        ...result.pending,
        coverUrl: result.pending.coverUrl || result.coverUrl || ""
      });
    }

    updateReportCounts(report, previous, result.status);
    if (save) saveConfig();
    syncReportItem(report, index);
    syncReportSummary(report);
    syncReportTotal(report);
    syncReportBulk(report);
    if (refresh && result.status === "added") refreshPendingView();
  };

  const addToPendingByIndex = async (index) => {
    const report = runtime.config?.lastReport;
    const item = report?.items?.[Number(index)];
    if (!report || !item || !canAddToPending(item)) return;

    if (runtime.pendingAdding) {
      toast("Esperá a que termine de agregar las canciones.");
      return;
    }

    runtime.pendingAdding = true;
    const button = document.querySelector(
      `[data-action="watched-add-pending"][data-index="${Number(index)}"]`
    );
    if (button) button.disabled = true;

    try {
      const result = await createPendingFromItem(item);
      applyPendingResult(report, Number(index), result);
      const label = item.pendingTitle || item.title;
      if (result.status === "library") {
        toast(`«${label}» ya está en tu biblioteca.`);
      } else if (result.created) {
        toast(`«${label}» agregada a pendientes.`);
      } else {
        toast(`«${label}» ya estaba en pendientes.`);
      }
    } catch (err) {
      toast(String(err?.message || "No se pudo agregar a pendientes."), "error");
    } finally {
      runtime.pendingAdding = false;
      syncReportItem(report, Number(index));
      syncReportBulk(report);
    }
  };

  const addAllToPending = async () => {
    const report = runtime.config?.lastReport;
    if (!report?.items?.length) return;

    if (runtime.pendingAdding) {
      toast("Ya se están agregando canciones a pendientes.");
      return;
    }

    const actionable = report.items
      .map((item, index) => ({ item, index }))
      .filter(({ item }) => canAddToPending(item))
      .slice(0, MAX_PENDING_ADDS_PER_RUN);

    if (!actionable.length) {
      toast("No quedan archivos para agregar.");
      return;
    }

    runtime.pendingAdding = true;
    runtime.pendingProgress = `Agregando 1 de ${actionable.length}…`;
    syncReportBulk(report);

    let created = 0;
    let already = 0;
    let library = 0;
    let failed = 0;

    for (let position = 0; position < actionable.length; position += 1) {
      const index = actionable[position].index;
      const item = report.items[index];
      if (!canAddToPending(item)) continue;

      runtime.pendingProgress = `Agregando ${position + 1} de ${actionable.length}…`;
      syncReportBulk(report);

      try {
        const result = await createPendingFromItem(item);
        applyPendingResult(report, index, result, { refresh: false, save: false });
        if (result.status === "library") library += 1;
        else if (result.created) created += 1;
        else already += 1;
      } catch (err) {
        failed += 1;
        item.detail = String(err?.message || "No se pudo agregar.").slice(0, 200);
        syncReportItem(report, index);
      }
    }

    runtime.pendingAdding = false;
    runtime.pendingProgress = "";
    saveConfig();
    syncReportSummary(report);
    syncReportBulk(report);
    if (created) refreshPendingView();

    const remaining = report.items.filter(canAddToPending).length;
    if (created && !failed) {
      toast(`${plural(created, "canción agregada", "canciones agregadas")} a pendientes.`);
    } else if (created && failed) {
      toast(`${created} agregadas a pendientes; ${failed} no se pudieron agregar.`, "error");
    } else if (failed && (already || library)) {
      toast(
        `${plural(failed, "archivo no se pudo agregar", "archivos no se pudieron agregar")}; el resto ya estaba en tu biblioteca o en pendientes.`,
        "error"
      );
    } else if (already || library) {
      toast("Todas las canciones ya estaban en tu biblioteca o en pendientes.");
    } else if (failed) {
      toast("No se pudo agregar ninguna canción a pendientes.", "error");
    }

    if (remaining && created) {
      toast(
        `${plural(remaining, "archivo quedó", "archivos quedaron")} para la próxima tanda.`
      );
    }
  };

  /* ------------------------------------------------------------
     Flujo de escaneo
     ------------------------------------------------------------ */

  const removePendingLocally = (pendingId) => {
    if (!Array.isArray(state.pending)) return;
    state.pending = state.pending.filter((item) => Number(item.id) !== Number(pendingId));
  };

  const markKnown = (contentKey, pendingId, trackId) => {
    if (!runtime.config?.folder) return;
    runtime.config.known[contentKey] = {
      at: Date.now(),
      pendingId: Number(pendingId) || 0,
      trackId: Number(trackId) || 0
    };
  };

  const refreshPendingView = () => {
    if (!runtime.started) return;
    if (typeof renderView !== "function") return;
    if (state.route?.view !== "library" || state.libraryTab !== "pending") return;
    try {
      renderView({ resetScroll: false });
    } catch (err) {
      /* la vista pudo haberse cerrado mientras subía */
    }
  };

  const queueCardRefresh = () => {
    if (runtime.cardQueued) return;
    runtime.cardQueued = true;
    window.requestAnimationFrame(() => {
      runtime.cardQueued = false;
      refreshPendingView();
    });
  };

  const refreshPendingBeforeScan = async () => {
    // La lista de pendientes puede haber cambiado desde el último escaneo
    // (importaciones nuevas, canciones borradas o subidas desde otro equipo).
    // Se refresca antes de comparar para no dejar archivos sin reconocer.
    try {
      await refreshLibrary({ silent: true, retry: true });
    } catch (err) {
      /* sin red o sin caché: seguimos con la lista que ya tenemos */
    }

    const pending = Array.isArray(state.pending) ? state.pending : [];
    const signature = pending
      .map(
        (item) =>
          `${Number(item.id) || 0}:${Core.normalizeTitle(item.title)}:${Core.normalizeText(
            item.artist
          )}`
      )
      .sort()
      .join("|");

    if (signature !== runtime.pendingSignature) {
      runtime.tagChecked.clear();
      runtime.pendingSignature = signature;
    }
  };

  const finalizeRecords = (plan) => {
    plan.records.forEach((record) => {
      if (record.status !== "unmatched") return;

      if (record.knownEntry) {
        record.status = "known";
        record.detail = "Ya la subimos antes desde esta carpeta.";
        return;
      }

      const tags = plan.metadata.get(record.file.path) || null;
      const libraryMatch = Core.matchPendingForFile(
        record.file,
        plan.libraryIndex,
        tags
      );

      if (libraryMatch && !libraryMatch.ambiguous && libraryMatch.pending) {
        record.status = "library";
        record.title = libraryMatch.pending.title || record.title;
        record.artist = libraryMatch.pending.artist || "";
        record.album = libraryMatch.pending.album || "";
        record.coverUrl = libraryMatch.pending.coverUrl || "";
        record.trackId = Number(libraryMatch.pending.id) || 0;
        record.detail = "Ya estaba en tu biblioteca.";
        return;
      }

      if (libraryMatch?.ambiguous) {
        record.status = "library";
        record.detail = "Ya hay canciones con ese nombre en tu biblioteca.";
      }
    });
  };

  const reportStatusOf = (plan, record) => {
    if (record.status === "matched") return "queued";
    if (record.status === "unmatched" && !plan.index.items.length) {
      return "no-pending";
    }
    return record.status;
  };

  const buildReport = (plan, params) => {
    finalizeRecords(plan);

    const counts = {
      uploaded: 0,
      added: 0,
      library: 0,
      known: 0,
      queued: 0,
      ambiguous: 0,
      failed: 0,
      duplicate: 0,
      empty: 0,
      unmatched: 0,
      "no-pending": 0
    };

    const ordered = params.files
      .map((file, index) => ({
        record: plan.records.get(file.path),
        index
      }))
      .filter((entry) => entry.record)
      .sort((a, b) => {
        const left = reportStatusOf(plan, a.record);
        const right = reportStatusOf(plan, b.record);
        const byStatus =
          REPORT_ORDER.indexOf(left) - REPORT_ORDER.indexOf(right);
        return byStatus || a.index - b.index;
      });

    const items = [];
    let omitted = 0;

    ordered.forEach(({ record }) => {
      const status = reportStatusOf(plan, record);
      counts[status] = (counts[status] || 0) + 1;

      if (items.length >= MAX_REPORT_ITEMS) {
        omitted += 1;
        return;
      }

      items.push({
        name: record.file.name,
        relative: record.file.relative,
        path: record.file.path,
        uri: record.file.uri,
        size: Number(record.file.size) || 0,
        modified: Number(record.file.modified) || 0,
        status,
        detail: record.detail || "",
        title: record.title || Core.fileStem(record.file.name || ""),
        artist: record.artist || "",
        album: record.album || "",
        genre: record.genre || "",
        duration: Number(record.duration) || 0,
        coverUrl: record.coverUrl || "",
        pendingTitle: record.pendingTitle || "",
        pendingArtist: record.pendingArtist || "",
        trackId: Number(record.trackId) || 0
      });
    });

    return {
      at: Date.now(),
      manual: Boolean(params.manual),
      folder: params.config.folder?.label || shortLabel(params.config.folder?.value || ""),
      kind: params.kind || "ok",
      files: Number(params.files) || 0,
      pending: plan.index.items.length,
      matched: Number(params.matched) || 0,
      counts,
      items,
      omitted,
      truncated: Boolean(params.truncated),
      depthLimited: Boolean(params.depthLimited),
      hint: layoutHint({
        kind: params.kind,
        truncated: params.truncated,
        depthLimited: params.depthLimited
      })
    };
  };

  const finishScan = (result, report = null) => {
    if (!runtime.config?.folder) return;
    runtime.config.lastScanAt = Date.now();
    runtime.config.lastResult = {
      at: Date.now(),
      kind: result.kind || "ok",
      files: Number(result.files) || 0,
      matched: Number(result.matched) || 0,
      uploaded: Number(result.uploaded) || 0,
      ambiguous: Number(result.ambiguous) || 0,
      failed: Number(result.failed) || 0,
      skipped: Number(result.skipped) || 0,
      truncated: Boolean(result.truncated),
      depthLimited: Boolean(result.depthLimited)
    };
    if (report) runtime.config.lastReport = report;
    saveConfig();
    renderNotifications();
    queueCardRefresh();
  };

  const runScan = async ({ manual = false } = {}) => {
    const config = runtime.config;
    if (!config?.folder || runtime.scanning) return;
    if (!navigator.onLine) {
      if (manual) {
        toast("Sin conexión: la carpeta vigilada se revisa cuando vuelvas a estar en línea.", "error");
      }
      return;
    }
    if (state.uploading) {
      if (manual) toast("Terminá la subida manual y revisamos la carpeta.");
      else scheduleScan(30 * 1000);
      return;
    }

    runtime.scanning = true;
    runtime.phase = "scanning";
    runtime.lastScanStarted = Date.now();
    queueCardRefresh();

    let uploaded = 0;
    let failed = 0;
    let skipped = 0;
    let matched = 0;
    let ambiguous = 0;
    let scanned = 0;
    let kind = "ok";
    let truncated = false;
    let depthLimited = false;
    let plan = null;
    let files = [];
    const uploadedTracks = [];

    try {
      const raw = await nativeScan(config.folder);
      files = (Array.isArray(raw.files) ? raw.files : [])
        .map(normalizeFile)
        .filter((file) => file.path);
      scanned = files.length;
      truncated = Boolean(raw.truncated);
      depthLimited = Boolean(raw.depthLimited);

      const described = Core.describeFolder({ files, truncated, depthLimited });
      kind = described.kind;

      if (config.permissionLost || config.folderMissing) {
        config.permissionLost = false;
        config.folderMissing = false;
        saveConfig();
      }

      await refreshPendingBeforeScan();

      const pending = Array.isArray(state.pending) ? state.pending.slice() : [];
      plan = planMatches(files, pending, config, state.tracks);
      await addMetadataMatches(plan, config);
      matched = plan.matches.length;
      ambiguous = plan.ambiguous.length;

      const batch = plan.matches.slice(0, MAX_UPLOADS_PER_SCAN);
      skipped += plan.matches.length - batch.length;
      plan.matches.slice(MAX_UPLOADS_PER_SCAN).forEach((match) => {
        match.record.status = "queued";
        match.record.detail = "Queda para el próximo escaneo.";
      });

      if (batch.length) {
        toast(
          `Carpeta vigilada: ${plural(batch.length, "canción coincide", "canciones coinciden")}. Subiendo…`
        );

        const pendingById = new Map(pending.map((item) => [Number(item.id), item]));

        for (let index = 0; index < batch.length; index += 1) {
          const match = batch[index];
          const current = pendingById.get(Number(match.pending.id));
          if (!current) {
            skipped += 1;
            match.record.status = "queued";
            match.record.detail = "La canción pendiente ya no estaba disponible.";
            continue;
          }

          runtime.phase = `uploading:${index + 1}:${batch.length}`;
          queueCardRefresh();

          try {
            const track = await uploadMatch(match, current);
            markKnown(match.contentKey, current.id, track?.id);
            delete config.failures[match.contentKey];
            removePendingLocally(current.id);
            uploaded += 1;

            match.record.status = "uploaded";
            match.record.trackId = Number(track?.id) || 0;
            match.record.coverUrl = String(track?.coverUrl || match.record.coverUrl || "");
            uploadedTracks.push({
              at: Date.now(),
              trackId: Number(track?.id) || 0,
              title: String(track?.title || current.title || "").trim(),
              artist: String(track?.artist || current.artist || "").trim(),
              album: String(track?.album || current.album || "").trim(),
              coverUrl: String(track?.coverUrl || current.coverUrl || ""),
              fileName: match.file.name
            });
          } catch (err) {
            const message = String(err?.message || err || "Error de subida").slice(0, 200);
            config.failures[match.contentKey] = {
              at: Date.now(),
              message
            };
            failed += 1;
            match.record.status = "failed";
            match.record.detail = message;
          }

          saveConfig();
        }
      }

      if (uploaded) {
        try {
          await refreshLibrary({ silent: true, retry: true });
          if (typeof renderSidebarPlaylists === "function") renderSidebarPlaylists();
          queueCardRefresh();
        } catch (err) {
          /* la subida ya terminó; la próxima apertura reconcilia la biblioteca */
        }
      }

      if (uploaded && !failed) {
        toast(`${plural(uploaded, "canción completada", "canciones completadas")} desde tu carpeta.`);
      } else if (uploaded && failed) {
        toast(`${uploaded} completadas; ${failed} no se pudieron subir. Reintentamos más tarde.`, "error");
      } else if (failed && !uploaded) {
        toast("No se pudo subir ningún archivo de la carpeta vigilada. Revisá la conexión.", "error");
      }
    } catch (err) {
      if (err?.permissionLost) {
        config.permissionLost = true;
        config.enabled = false;
        saveConfig();
        toast("Android pidió permiso otra vez para la carpeta vigilada. Volvé a elegirla.", "error");
      } else if (!navigator.onLine) {
        /* sin conexión: se reintenta en el próximo ciclo */
      } else {
        console.error("[WaverNote] watched folder:", err);
        // En Windows un error de lectura suele significar que la carpeta se
        // movió, cambió de nombre o el disco ya no está conectado. Pausamos
        // para no repetir el aviso cada cinco minutos.
        if (!IS_ANDROID) {
          config.folderMissing = true;
          config.enabled = false;
          saveConfig();
          queueCardRefresh();
        }
        toast(`Carpeta vigilada: ${err?.message || "no se pudo revisar la carpeta."}`, "error");
      }
    } finally {
      runtime.scanning = false;
      runtime.phase = "idle";

      if (plan) {
        plan.records.forEach((record) => {
          if (record.status === "matched") {
            record.status = "queued";
            record.detail = "El escaneo terminó antes de subir este archivo.";
          }
        });
      }

      const report = plan
        ? buildReport(plan, {
            config,
            files,
            manual,
            kind,
            matched,
            uploaded,
            ambiguous,
            failed,
            skipped,
            truncated,
            depthLimited
          })
        : null;

      finishScan(
        {
          kind,
          files: scanned,
          matched,
          uploaded,
          ambiguous,
          failed,
          skipped,
          truncated,
          depthLimited
        },
        report
      );

      if (uploadedTracks.length) addUploadNotifications(uploadedTracks);
      if (report && manual) openReport(report);

      if (runtime.started && config.enabled && !config.permissionLost && !config.folderMissing) {
        scheduleScan(SCAN_INTERVAL_MS);
      }
    }
  };

  const scheduleScan = (delay) => {
    if (!runtime.started) return;
    if (runtime.scanTimer) window.clearTimeout(runtime.scanTimer);
    runtime.scanTimer = window.setTimeout(() => {
      runtime.scanTimer = null;
      requestScan({ force: true });
    }, Math.max(1000, Number(delay) || SCAN_INTERVAL_MS));
  };

  const requestScan = ({ force = false, manual = false } = {}) => {
    const config = runtime.config;
    if (!runtime.supported || !runtime.started || !config?.folder) return;
    if ((!config.enabled && !manual) || config.permissionLost || config.folderMissing) return;
    if (runtime.scanning) return;
    if (state.uploading) {
      scheduleScan(30 * 1000);
      return;
    }
    if (!force && Date.now() - runtime.lastScanStarted < MIN_SCAN_GAP_MS) return;
    runScan({ manual });
  };

  /* ------------------------------------------------------------
     Acciones de la tarjeta
     ------------------------------------------------------------ */

  const pickFolder = async () => {
    if (!runtime.supported) {
      toast("La carpeta vigilada está disponible en la app de Windows y Android.", "error");
      return;
    }
    if (runtime.scanning) {
      toast("Esperá a que termine el escaneo actual.");
      return;
    }

    try {
      const picked = await nativePick();
      if (!picked?.value) return;

      const config = runtime.config || emptyConfig();
      const changed = config.folder?.value !== picked.value;
      config.folder = picked;
      config.enabled = true;
      config.permissionLost = false;
      config.folderMissing = false;
      config.lastScanAt = 0;
      config.lastResult = null;
      if (changed) {
        config.known = {};
        config.failures = {};
        config.lastReport = null;
        runtime.tagChecked.clear();
        clearCoverCache();
      }
      if (!config.addedAt) config.addedAt = Date.now();
      runtime.config = config;
      saveConfig();
      renderNotifications();
      queueCardRefresh();
      toast(`Carpeta vigilada: ${shortLabel(picked.label || picked.value)}.`);
      runScan({ manual: true });
    } catch (err) {
      toast(err?.message || "No se pudo elegir la carpeta.", "error");
    }
  };

  const scanNow = () => {
    if (!runtime.config?.folder || runtime.config.folderMissing) {
      pickFolder();
      return;
    }
    if (runtime.scanning) {
      toast("Ya estamos revisando la carpeta.");
      return;
    }
    if (state.uploading) {
      toast("Terminá la subida manual y revisamos la carpeta.");
      return;
    }
    requestScan({ force: true, manual: true });
  };

  const toggleEnabled = () => {
    if (!runtime.config) return;
    if (runtime.config.folderMissing) {
      pickFolder();
      return;
    }
    runtime.config.enabled = !runtime.config.enabled;
    runtime.config.permissionLost = false;
    saveConfig();
    queueCardRefresh();
    if (runtime.config.enabled) {
      toast("Carpeta vigilada activada.");
      requestScan({ force: true });
    } else {
      toast("Carpeta vigilada en pausa.");
    }
  };

  const forget = () => {
    if (!runtime.config) return;
    runtime.config = emptyConfig();
    runtime.userId = Number(state.user?.id) || 0;
    runtime.pendingSignature = "";
    runtime.tagChecked.clear();
    clearCoverCache();
    try {
      localStorage.removeItem(storageKey(runtime.userId));
    } catch (err) {
      /* noop */
    }
    closeNotifications();
    renderNotifications();
    closeModal(true);
    queueCardRefresh();
    toast("WaverNote dejó de vigilar la carpeta.");
  };

  const openForget = () => {
    if (!runtime.config?.folder) return;
    openModal({
      title: "Dejar de vigilar",
      eyebrow: "Carpeta vigilada",
      body: `
        <div class="watch-help">
          <p>WaverNote va a dejar de revisar <strong>${escapeHTML(runtime.config.folder.label || shortLabel(runtime.config.folder.value))}</strong>. No se borra ningún archivo de tu dispositivo ni canción de tu biblioteca.</p>
          <p class="watch-help__muted">Las canciones que sigan pendientes van a esperar a que subas su archivo a mano.</p>
          <div class="watch-help__actions">
            <button class="btn btn--danger" data-action="watched-forget-confirm">${icon("trash")} Dejar de vigilar</button>
            <button class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          </div>
        </div>`
    });
  };

  const openHelp = () => {
    openModal({
      title: "Carpeta vigilada",
      eyebrow: "Cómo funciona",
      body: `
        <div class="watch-help">
          <p><strong>WaverNote no descarga música de Spotify.</strong> La carpeta vigilada solo mira archivos que ya tenés en tu dispositivo y sube los que completan una canción pendiente de tu lista.</p>
          <ul>
            <li>Elegí la carpeta principal de tu música. También sirve una carpeta de artista: buscamos en todas sus subcarpetas.</li>
            <li>Revisamos al abrir la app, al volver a ella y cada pocos minutos mientras esté abierta.</li>
            <li>Reconocemos el nombre del archivo, las carpetas (Artista/Álbum/01 - Canción) y, si hace falta, las etiquetas del audio.</li>
            <li>Las versiones en vivo, remixes, instrumentales y acústicas se tratan como canciones distintas.</li>
            <li>Un escaneo manual muestra el detalle de cada archivo. Los escaneos automáticos no abren ventanas: las canciones nuevas aparecen en la campana de arriba.</li>
            <li>Si dos canciones pendientes se parecen demasiado, no adivinamos: el archivo queda para que lo subas vos desde su fila.</li>
            <li>No modificamos, movemos ni borramos tus archivos. Tampoco subimos canciones que no estén pendientes.</li>
          </ul>
          <p class="watch-help__muted">${
            IS_ANDROID
              ? "En Android el acceso se guarda con el permiso del selector del sistema. Si el sistema lo retira, te pedimos elegir la carpeta otra vez."
              : "En Windows la carpeta se lee directamente desde tu equipo. Si la movés o la desconectás, elegí la nueva ubicación."
          }</p>
          <div class="watch-help__actions">
            <button class="btn btn--primary" data-action="watched-pick">${icon("folder")} Elegir carpeta</button>
            <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
          </div>
        </div>`
    });
  };

  /* ------------------------------------------------------------
     Ciclo de vida
     ------------------------------------------------------------ */

  const start = () => {
    if (!runtime.supported) return;
    const userId = Number(state.user?.id) || 0;
    if (!userId) return;

    if (runtime.started && runtime.userId === userId) {
      renderNotifications();
      requestScan();
      return;
    }

    runtime.userId = userId;
    runtime.config = loadConfig(userId);
    runtime.started = true;
    runtime.lastScanStarted = 0;
    runtime.pendingSignature = "";

    if (runtime.timer) window.clearInterval(runtime.timer);
    runtime.timer = window.setInterval(() => requestScan(), SCAN_INTERVAL_MS);

    renderNotifications();
    queueCardRefresh();
    if (
      runtime.config.folder &&
      runtime.config.enabled &&
      !runtime.config.permissionLost &&
      !runtime.config.folderMissing
    ) {
      scheduleScan(2500);
    }
  };

  const stop = () => {
    runtime.started = false;
    runtime.scanning = false;
    runtime.phase = "idle";
    runtime.userId = 0;
    runtime.config = null;
    runtime.lastScanStarted = 0;

    if (runtime.timer) window.clearInterval(runtime.timer);
    if (runtime.scanTimer) window.clearTimeout(runtime.scanTimer);
    runtime.timer = null;
    runtime.scanTimer = null;
    runtime.tagChecked.clear();
    clearCoverCache();

    if (runtime.pickWaiter) {
      window.clearTimeout(runtime.pickWaiter.timer);
      runtime.pickWaiter = null;
    }
    if (runtime.scanWaiter) {
      window.clearTimeout(runtime.scanWaiter.timer);
      runtime.scanWaiter = null;
    }
    runtime.uploads.forEach((waiter) => waiter.reject(new Error("Sesión cerrada.")));
    runtime.uploads.clear();

    closeNotifications();
    renderNotifications();
  };

  const onVisible = () => {
    if (document.visibilityState === "visible") requestScan();
  };

  if (runtime.supported) {
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("focus", onVisible);
  }

  document.addEventListener("click", (event) => {
    if (!runtime.notificationsOpen) return;
    const root = document.getElementById("notifRoot");
    if (root?.contains(event.target)) return;
    closeNotifications();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && runtime.notificationsOpen) closeNotifications();
  });

  window.WaverNoteWatched = {
    addAllToPending,
    addToPending: addToPendingByIndex,
    cardHTML,
    closeNotifications,
    forget,
    markNotificationsRead: markAllNotificationsRead,
    onNativeFolderPicked,
    onNativeScan,
    onNativeUpload: settleUpload,
    openForget,
    openHelp,
    openNotification,
    openReport,
    pickFolder,
    requestScan,
    scanNow,
    start,
    stop,
    toggleEnabled,
    toggleNotifications
  };
})();
