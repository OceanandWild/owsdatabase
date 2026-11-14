/* ------------------------------------------------------------
   Importador de listas (Spotify, Apple Music, CSV/JSON genérico)

   El parseo vive en import-core.js y tiene tests con Node. Este archivo
   solo arma el modal, la vista previa y llama a la API de pendientes.
   ------------------------------------------------------------ */

(function () {
  "use strict";

  const Core = window.WaverNoteImportCore;
  const MAX_FILE_BYTES = 8 * 1024 * 1024;
  const PREVIEW_LIMIT = 120;

  const importState = {
    text: "",
    fileName: "",
    link: "",
    typedSource: "",
    source: "",
    preview: null,
    busy: false
  };

  const STATUS_META = {
    new: { label: "Nueva", className: "is-new" },
    library: { label: "Ya en tu biblioteca", className: "is-library" },
    pending: { label: "Ya está pendiente", className: "is-pending" },
    duplicate: { label: "Repetida", className: "is-duplicate" }
  };

  const resetState = () => {
    importState.text = "";
    importState.fileName = "";
    importState.link = "";
    importState.typedSource = "";
    importState.source = "";
    importState.preview = null;
    importState.busy = false;
  };

  const showError = (message) => {
    const box = document.getElementById("importError");
    if (!box) {
      toast(message, "error");
      return;
    }
    box.textContent = message;
    box.hidden = false;
  };

  const hideError = () => {
    const box = document.getElementById("importError");
    if (box) box.hidden = true;
  };

  const showLinkError = (message) => {
    const box = document.getElementById("importLinkError");
    if (!box) {
      showError(message);
      return;
    }
    box.textContent = message;
    box.hidden = false;
  };

  const hideLinkError = () => {
    const box = document.getElementById("importLinkError");
    if (box) box.hidden = true;
  };

  const readFileText = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(reader.error || new Error("No se pudo leer el archivo."));
      reader.readAsText(file, "utf-8");
    });

  const sourceValue = (fallback = "Importada") => {
    const input = document.getElementById("importSource");
    const typed = String(input?.value || "").trim();
    if (typed) return typed;
    if (importState.fileName) return importState.fileName.replace(/\.[^.]+$/, "");
    return fallback;
  };

  const renderFileChip = () => {
    const chip = document.getElementById("importFileChip");
    if (!chip) return;

    if (!importState.fileName) {
      chip.hidden = true;
      chip.innerHTML = "";
      return;
    }

    chip.hidden = false;
    chip.innerHTML = `<span class="import-file__name">${escapeHTML(importState.fileName)}</span>
      <button class="icon-btn icon-btn--tiny" type="button" data-action="import-file-clear" aria-label="Quitar archivo">${icon("x")}</button>`;
  };

  const clearFile = () => {
    const input = document.getElementById("importFile");
    if (input) input.value = "";
    importState.fileName = "";
    importState.text = "";
    renderFileChip();
    hideError();
  };

  const inputBody = () => `
    <div class="import">
      <p class="import-lead">
        Pegá el link de una <strong>canción, álbum o playlist de Spotify</strong> y traemos
        el título, artista, portada y duración. Quedan como <strong>pendientes</strong> hasta
        que subas el audio: WaverNote no descarga música de Spotify.
      </p>

      <div class="import-spotify">
        <label class="field">
          <span>Link de Spotify</span>
          <div class="import-link-row">
            <input id="importLink" type="url" maxlength="500" placeholder="https://open.spotify.com/playlist/..." autocomplete="off" spellcheck="false" />
            <button class="btn btn--primary btn--small" type="button" data-action="import-link">
              ${icon("link")} Traer canciones
            </button>
          </div>
        </label>
        <p class="import-hint">Canción, álbum, playlist o artista · hasta 100 canciones por lista.</p>
        <div class="import-status" id="importLinkStatus" hidden>
          <span>Leyendo Spotify y las portadas… puede tardar unos segundos.</span>
        </div>
        <div class="import-error" id="importLinkError" hidden></div>
      </div>

      <div class="import-divider"><span>o importá un archivo o texto</span></div>

      <ol class="import-steps">
        <li>Exportá tu playlist (por ejemplo con Exportify) o prepará un CSV con título y artista.</li>
        <li>Pegá el contenido o elegí el archivo.</li>
        <li>Revisá la vista previa e importá.</li>
      </ol>

      <label class="field">
        <span>Nombre de la lista (opcional)</span>
        <input id="importSource" type="text" maxlength="60" placeholder="Ej. Favoritas de Spotify" autocomplete="off" />
      </label>

      <div class="import-file-row">
        <label class="btn btn--ghost btn--small import-file-btn">
          ${icon("folder")} Elegir archivo
          <input id="importFile" type="file" accept=".csv,.tsv,.txt,.json,text/csv,text/tab-separated-values,application/json" hidden />
        </label>
        <span class="import-file-hint">CSV, TSV o JSON · hasta 8 MB</span>
      </div>
      <div class="import-file" id="importFileChip" hidden></div>

      <label class="field">
        <span>O pegá el contenido</span>
        <textarea id="importText" rows="7" placeholder="Track Name,Artist Name(s),Album Name,Duration (ms)&#10;Canción,Artista,Álbum,215000"></textarea>
      </label>

      <div class="import-error" id="importError" hidden></div>

      <div class="modal__actions">
        <button class="btn btn--ghost" data-action="close-modal">Cancelar</button>
        <button class="btn btn--primary" data-action="import-analyze">Analizar archivo</button>
      </div>
    </div>`;

  const bindInputs = () => {
    const linkInput = document.getElementById("importLink");
    linkInput?.addEventListener("input", hideLinkError);
    linkInput?.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      analyzeLink();
    });

    const fileInput = document.getElementById("importFile");
    fileInput?.addEventListener("change", async () => {
      const file = fileInput.files?.[0];
      if (!file) return;

      if (file.size > MAX_FILE_BYTES) {
        showError("El archivo supera los 8 MB. Probá con una lista más chica.");
        fileInput.value = "";
        return;
      }

      try {
        importState.text = await readFileText(file);
        importState.fileName = file.name;
        const area = document.getElementById("importText");
        if (area) area.value = "";
        renderFileChip();
        hideError();
      } catch (err) {
        showError("No se pudo leer el archivo. Probá pegando el contenido.");
      }
    });

    const textarea = document.getElementById("importText");
    textarea?.addEventListener("input", () => {
      if (!importState.fileName) return;
      importState.fileName = "";
      importState.text = "";
      renderFileChip();
      hideError();
    });
  };

  const open = () => {
    resetState();
    openModal({ title: "Importar lista", eyebrow: "Pendientes", body: inputBody() });
    bindInputs();
  };

  const collectionTypeLabel = (type) =>
    ({
      track: "Canción de Spotify",
      album: "Álbum de Spotify",
      playlist: "Playlist de Spotify",
      artist: "Lo más escuchado de"
    })[type] || "Spotify";

  const setLinkBusy = (busy) => {
    const button = document.querySelector('[data-action="import-link"]');
    const input = document.getElementById("importLink");
    const status = document.getElementById("importLinkStatus");

    if (input) input.disabled = busy;

    if (button) {
      if (busy) {
        if (!button.dataset.original) button.dataset.original = button.innerHTML;
        button.textContent = "Leyendo…";
        button.disabled = true;
      } else {
        if (button.dataset.original) {
          button.innerHTML = button.dataset.original;
          delete button.dataset.original;
        }
        button.disabled = false;
      }
    }

    if (status) status.hidden = !busy;
  };

  const analyzeLink = async () => {
    hideLinkError();
    hideError();

    const input = document.getElementById("importLink");
    const raw = String(input?.value || "").trim();
    if (!raw) {
      showLinkError("Pegá el link de Spotify.");
      return;
    }

    const links = Core.extractSpotifyLinks(raw);
    if (!links.length) {
      showLinkError("Ese link no parece de Spotify. Copialo desde Compartir → Copiar link.");
      return;
    }
    if (links.length > 1) {
      showLinkError("Pegá un solo link a la vez. Para varias canciones, importá un CSV.");
      return;
    }

    const link = links[0];
    setLinkBusy(true);

    try {
      const data = await api("/wavernote/spotify/resolve", {
        method: "POST",
        body: { url: link.url }
      });

      const rows = Array.isArray(data?.tracks) ? data.tracks : [];
      if (!rows.length) throw new Error("Spotify no devolvió canciones para ese link.");

      const collection =
        data?.collection && typeof data.collection === "object" ? data.collection : null;
      const typedSource = String(document.getElementById("importSource")?.value || "").trim();
      const source =
        typedSource ||
        (collection?.type === "track" ? "Spotify" : collection?.name) ||
        "Spotify";
      const normalized = rows.map((row) => ({ ...row, source }));

      importState.link = link.url;
      importState.typedSource = typedSource;
      importState.text = "";
      importState.fileName = "";
      renderFileChip();

      openPreview(Core.buildPreview(normalized, state.tracks, state.pending), source, {
        ...(collection || {}),
        warnings: Array.isArray(data?.warnings) ? data.warnings : []
      });
    } catch (err) {
      showLinkError(friendlyError(err));
    } finally {
      setLinkBusy(false);
    }
  };

  const openPreview = (preview, source, collection = null) => {
    importState.preview = preview;
    importState.source = source || "Importada";

    const visible = preview.rows.slice(0, PREVIEW_LIMIT);
    const hidden = preview.total - visible.length;

    const rowsHTML = visible
      .map((row) => {
        const meta = STATUS_META[row.status] || STATUS_META.new;
        return `<div class="import-row ${meta.className}">
          <span class="import-row__art">${coverHTML({ title: row.title, coverUrl: row.coverUrl })}</span>
          <span class="import-row__state">${escapeHTML(meta.label)}</span>
          <span class="import-row__main">
            <strong>${escapeHTML(row.title)}</strong>
            <small>${escapeHTML(row.artist || "Artista desconocido")}</small>
          </span>
          <span class="import-row__album">${escapeHTML(row.album || "—")}</span>
          <span class="import-row__time">${row.duration ? formatTime(row.duration) : "—"}</span>
        </div>`;
      })
      .join("");

    const stats = [
      ["new", preview.fresh, "nuevas"],
      ["library", preview.inLibrary, "ya en tu biblioteca"],
      ["pending", preview.alreadyPending, "ya pendientes"],
      ["duplicate", preview.duplicates, "repetidas"]
    ]
      .filter(([, count]) => count > 0)
      .map(
        ([kind, count, label]) =>
          `<div class="import-stat import-stat--${kind}"><strong>${count}</strong><span>${escapeHTML(label)}</span></div>`
      )
      .join("");

    const collectionName = collection?.name || source || "Spotify";
    const collectionBlock = collection
      ? `<div class="import-collection">
          <span class="import-collection__art">${coverHTML({
            title: collectionName,
            coverUrl: collection.coverUrl
          })}</span>
          <span class="import-collection__main">
            <span class="import-collection__type">${escapeHTML(collectionTypeLabel(collection.type))}</span>
            <strong>${escapeHTML(collectionName)}</strong>
            <small>${plural(Number(collection.total) || preview.total, "canción", "canciones")}</small>
          </span>
        </div>`
      : "";

    const warnings = Array.isArray(collection?.warnings)
      ? collection.warnings.filter(Boolean)
      : [];
    const warningBlock = warnings.length
      ? `<p class="import-warning">${escapeHTML(warnings.join(" "))}</p>`
      : "";

    const nothingNew = preview.fresh === 0;

    openModal({
      title: "Vista previa",
      eyebrow: "Importar lista",
      body: `<div class="import">
        ${collectionBlock}
        <div class="import-summary">${stats}</div>
        <p class="import-lead">${
          nothingNew
            ? "No hay canciones nuevas para importar: todo lo del archivo ya está en tu biblioteca o en pendientes."
            : `Se van a agregar <strong>${plural(preview.fresh, "canción", "canciones")}</strong> a pendientes. Después subí los archivos cuando quieras.`
        }</p>
        ${warningBlock}

        <div class="import-preview">${rowsHTML}</div>
        ${hidden > 0 ? `<p class="import-more">Y ${plural(hidden, "canción más", "canciones más")} sin mostrar.</p>` : ""}

        <div class="modal__actions">
          <button class="btn btn--ghost" data-action="import-reset">Volver</button>
          <button class="btn btn--primary" data-action="import-submit" ${nothingNew ? "disabled" : ""}>
            Importar ${plural(preview.fresh, "canción", "canciones")}
          </button>
        </div>
      </div>`
    });
  };

  const analyze = async () => {
    hideError();
    hideLinkError();

    const textarea = document.getElementById("importText");
    const text = importState.text || String(textarea?.value || "");
    const trimmed = text.trim();
    if (!trimmed) {
      showError("Pegá el contenido o elegí un archivo para analizar.");
      return;
    }

    // Si pegaron el link en el cuadro de texto, se resuelve igual que en el
    // campo de Spotify. Un CSV con links de Spotify sigue el camino normal.
    if (Core.parseSpotifyLink(trimmed)) {
      const linkInput = document.getElementById("importLink");
      if (linkInput) linkInput.value = trimmed;
      await analyzeLink();
      return;
    }

    let parsed;
    try {
      parsed = Core.parseImportText(text, { source: sourceValue() });
    } catch (err) {
      showError(err?.message || "No se pudo leer la lista.");
      return;
    }

    const source = sourceValue();
    const preview = Core.buildPreview(parsed.rows, state.tracks, state.pending);
    importState.text = text;
    importState.link = "";
    importState.typedSource = String(document.getElementById("importSource")?.value || "").trim();
    openPreview(preview, source);
  };

  const reset = () => {
    const { text, fileName, link, typedSource } = importState;
    open();
    // Al volver desde la vista previa se conserva lo que el usuario cargó.
    importState.text = text;
    importState.fileName = fileName;
    importState.link = link;
    importState.typedSource = typedSource;
    const textarea = document.getElementById("importText");
    if (textarea && text && !fileName) textarea.value = text;
    const linkInput = document.getElementById("importLink");
    if (linkInput && link) linkInput.value = link;
    const sourceInput = document.getElementById("importSource");
    if (sourceInput && typedSource) sourceInput.value = typedSource;
    renderFileChip();
  };

  const setSubmitting = (busy) => {
    const button = document.querySelector('[data-action="import-submit"]');
    if (!button) return;

    if (busy) {
      button.dataset.label = button.textContent;
      button.textContent = "Importando…";
      button.disabled = true;
    } else {
      if (button.dataset.label) button.textContent = button.dataset.label;
      button.disabled = false;
    }
  };

  const submit = async () => {
    const preview = importState.preview;
    if (!preview || importState.busy) return;

    const rows = preview.rows
      .filter((row) => row.status === "new")
      .map((row) => ({
        title: row.title,
        artist: row.artist,
        album: row.album,
        duration: row.duration,
        coverUrl: row.coverUrl,
        isrc: row.isrc,
        source: row.source || importState.source
      }));

    if (!rows.length) {
      toast("No hay canciones nuevas para importar.");
      return;
    }

    importState.busy = true;
    setSubmitting(true);

    try {
      const data = await api("/wavernote/pending/import", {
        method: "POST",
        body: { source: importState.source, tracks: rows }
      });

      await refreshLibrary();

      state.libraryTab = "pending";
      if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");

      closeModal(true);
      if (state.route.view === "library") renderView({ resetScroll: true });
      else navigate({ view: "library" });

      const imported = Number(data?.imported) || 0;
      const skipped = Number(data?.skipped?.inLibrary) || 0;
      if (imported) {
        toast(
          skipped
            ? `${plural(imported, "canción agregada", "canciones agregadas")} a pendientes. ${plural(skipped, "ya estaba", "ya estaban")} en tu biblioteca.`
            : `${plural(imported, "canción agregada", "canciones agregadas")} a pendientes.`
        );
      } else {
        toast("Todo lo del archivo ya estaba en tu biblioteca o en pendientes.");
      }

      // Si la carpeta vigilada está activa, revisamos enseguida: las canciones
      // recién importadas pueden tener su archivo esperando ahí.
      if (imported) {
        window.setTimeout(() => window.WaverNoteWatched?.requestScan({ force: true }), 900);
      }
    } catch (err) {
      showError(friendlyError(err));
      setSubmitting(false);
      importState.busy = false;
    }
  };

  const removePending = async (id) => {
    const pendingId = Number(id);
    if (!pendingId) return;

    try {
      await api(`/wavernote/pending/${pendingId}`, { method: "DELETE" });
      state.pending = (state.pending || []).filter((item) => Number(item.id) !== pendingId);
      renderView({ resetScroll: false });
      toast("Canción quitada de pendientes.");
    } catch (err) {
      toast(friendlyError(err), "error");
    }
  };

  const openClearPending = () => {
    const total = (state.pending || []).length;
    if (!total) return;

    openModal({
      title: "Vaciar pendientes",
      eyebrow: "Pendientes",
      body: `<div class="import">
        <p class="import-lead">Se van a quitar ${plural(total, "canción pendiente", "canciones pendientes")}. Los archivos que ya subiste no se tocan.</p>
        <div class="modal__actions">
          <button class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          <button class="btn btn--danger" data-action="pending-clear-confirm">Vaciar lista</button>
        </div>
      </div>`
    });
  };

  const clearPending = async () => {
    try {
      await api("/wavernote/pending", { method: "DELETE" });
      state.pending = [];
      closeModal(true);
      renderView({ resetScroll: false });
      toast("Lista de pendientes vaciada.");
    } catch (err) {
      toast(friendlyError(err), "error");
    }
  };

  window.WaverNoteImport = {
    open,
    reset,
    analyze,
    analyzeLink,
    submit,
    removePending,
    openClearPending,
    clearPending,
    clearFile
  };
})();
