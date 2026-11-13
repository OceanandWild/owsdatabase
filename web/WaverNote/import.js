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

  const readFileText = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(reader.error || new Error("No se pudo leer el archivo."));
      reader.readAsText(file, "utf-8");
    });

  const sourceValue = () => {
    const input = document.getElementById("importSource");
    const typed = String(input?.value || "").trim();
    if (typed) return typed;
    if (importState.fileName) return importState.fileName.replace(/\.[^.]+$/, "");
    return "Importada";
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
        Traé canciones desde <strong>Spotify</strong>, Apple Music o cualquier lista en CSV/JSON.
        Quedan como <strong>pendientes</strong> hasta que subas el archivo de audio: WaverNote no
        descarga música de Spotify.
      </p>

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
        <button class="btn btn--primary" data-action="import-analyze">Analizar</button>
      </div>
    </div>`;

  const bindInputs = () => {
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

  const openPreview = (preview, source) => {
    importState.preview = preview;
    importState.source = source || "Importada";

    const visible = preview.rows.slice(0, PREVIEW_LIMIT);
    const hidden = preview.total - visible.length;

    const rowsHTML = visible
      .map((row) => {
        const meta = STATUS_META[row.status] || STATUS_META.new;
        return `<div class="import-row ${meta.className}">
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

    const nothingNew = preview.fresh === 0;

    openModal({
      title: "Vista previa",
      eyebrow: "Importar lista",
      body: `<div class="import">
        <div class="import-summary">${stats}</div>
        <p class="import-lead">${
          nothingNew
            ? "No hay canciones nuevas para importar: todo lo del archivo ya está en tu biblioteca o en pendientes."
            : `Se van a agregar <strong>${plural(preview.fresh, "canción", "canciones")}</strong> a pendientes. Después subí los archivos cuando quieras.`
        }</p>

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

  const analyze = () => {
    hideError();

    const textarea = document.getElementById("importText");
    const text = importState.text || String(textarea?.value || "");
    if (!text.trim()) {
      showError("Pegá el contenido o elegí un archivo para analizar.");
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
    openPreview(preview, source);
  };

  const reset = () => {
    const { text, fileName, source } = importState;
    open();
    // Al volver desde la vista previa se conserva lo que el usuario cargó.
    importState.text = text;
    importState.fileName = fileName;
    importState.source = source;
    const textarea = document.getElementById("importText");
    if (textarea && text && !fileName) textarea.value = text;
    const sourceInput = document.getElementById("importSource");
    if (sourceInput && source && source !== "Importada") sourceInput.value = source;
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
    submit,
    removePending,
    openClearPending,
    clearPending,
    clearFile
  };
})();
