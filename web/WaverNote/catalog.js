/* ============================================================
   WaverNote · artistas y géneros
   Agrupación de la biblioteca, imágenes propias y edición de
   los nombres (sirve para unificar duplicados como "adele" y
   "Adele", o para ponerle nombre a lo que subiste sin autor).
   ============================================================ */

const CATALOG_STORE_KEY = "wavernote.catalog.v1";
const CATALOG_IMAGE_SIZE = 320;

const CATALOG_KINDS = {
  artist: {
    field: "artist",
    label: "artista",
    plural: "artistas",
    empty: "Sin artista",
    maxLength: 120
  },
  genre: {
    field: "genre",
    label: "género",
    plural: "géneros",
    empty: "Sin género",
    maxLength: 60
  }
};

/* ------------------------------------------------------------
   Créditos: una canción puede tener varios artistas
   "A feat. B", "A & B" y "A, B" cuentan para cada uno. Así el
   detector de artistas y las tendencias no pierden colaboradores.
   ------------------------------------------------------------ */

const ARTIST_SEPARATOR = /\s*(?:,|&|\bfeat\b\.?|\bft\b\.?|\bfeaturing\b)\s*/gi;

const cleanArtistName = (value) =>
  String(value || "")
    .replace(/^[\s([{]+/, "")
    .replace(/[\s)\]},;.-]+$/, "")
    .replace(/\s{2,}/g, " ")
    .trim();

const trackArtists = (track) => {
  const raw = String(track?.artist || "").trim();
  if (!raw) return [];

  const names = [];
  const seen = new Set();

  raw.split(ARTIST_SEPARATOR).forEach((part) => {
    const name = cleanArtistName(part);
    const key = normalize(name);
    if (!key || seen.has(key)) return;
    seen.add(key);
    names.push(name);
  });

  return names;
};

/* ------------------------------------------------------------
   Agrupación de la biblioteca
   ------------------------------------------------------------ */

const catalogGroups = (kind) => {
  const config = CATALOG_KINDS[kind];
  if (!config) return [];

  const groups = new Map();

  state.tracks.forEach((track) => {
    const values =
      kind === "artist"
        ? trackArtists(track)
        : [String(track?.[config.field] || "").trim()];
    const names = values.length ? values : [config.empty];

    names.forEach((name) => {
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(track);
    });
  });

  return Array.from(groups.entries())
    .map(([name, tracks]) => {
      const sorted = tracks.slice().sort((a, b) => Number(a.id) - Number(b.id));
      return {
        kind,
        name,
        key: normalize(name),
        tracks: sorted,
        count: sorted.length,
        duration: sorted.reduce((total, track) => total + (Number(track.duration) || 0), 0),
        coverUrl: sorted.find((track) => track.coverUrl)?.coverUrl || null
      };
    })
    .sort((a, b) => a.name.localeCompare(b.name, "es"));
};

const catalogGroup = (kind, name) =>
  catalogGroups(kind).find((group) => group.name === String(name || "")) || null;

// Al renombrar un artista se respetan los colaboradores del tema:
// "A feat. B" pasa a "Nuevo feat. B" sin perder a B.
const renameTrackArtist = (track, from, to) => {
  const names = trackArtists(track);
  if (!names.length) return to;

  const key = normalize(from);
  const next = [];

  names.forEach((name) => {
    const value = normalize(name) === key ? to : name;
    if (!value) return;
    if (!next.some((item) => normalize(item) === normalize(value))) next.push(value);
  });

  return next.length ? next.join(", ") : to;
};

/* ------------------------------------------------------------
   Imágenes propias
   ------------------------------------------------------------ */

const catalogStore = () => {
  const raw = readJSON(CATALOG_STORE_KEY, {});
  return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
};

const catalogBucket = (store, kind) => {
  const bucket = store[kind];
  return bucket && typeof bucket === "object" ? bucket : {};
};

const catalogImageFor = (kind, name) => {
  const bucket = catalogBucket(catalogStore(), kind);
  const value = bucket[normalize(name)];
  return typeof value === "string" ? value : "";
};

// Devuelve false si el almacenamiento quedó lleno: la app tiene que avisar.
const catalogWrite = (store) => {
  try {
    localStorage.setItem(CATALOG_STORE_KEY, JSON.stringify(store));
    return true;
  } catch (err) {
    return false;
  }
};

const catalogSaveImage = (kind, name, dataUrl) => {
  const store = catalogStore();
  const bucket = catalogBucket(store, kind);
  const key = normalize(name);
  if (dataUrl) bucket[key] = dataUrl;
  else delete bucket[key];
  store[kind] = bucket;
  return catalogWrite(store);
};

// Al renombrar, la imagen sigue con el artista o el género.
const catalogMoveImage = (kind, from, to) => {
  const fromKey = normalize(from);
  const toKey = normalize(to);
  if (fromKey === toKey) return true;

  const store = catalogStore();
  const bucket = catalogBucket(store, kind);
  if (!bucket[fromKey]) return true;
  if (!bucket[toKey]) bucket[toKey] = bucket[fromKey];
  delete bucket[fromKey];
  store[kind] = bucket;
  return catalogWrite(store);
};

// Reduce la imagen antes de guardarla: una foto de 4 MB llenaría el
// almacenamiento del navegador en dos o tres artistas.
const catalogReadImage = (file) =>
  new Promise((resolve, reject) => {
    if (!file || !/^image\//i.test(String(file.type || ""))) {
      reject(new Error("Elegí una imagen (JPG o PNG)."));
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => reject(new Error("No se pudo leer la imagen."));
    reader.onload = () => {
      const image = new Image();
      image.onerror = () => reject(new Error("Esa imagen no se pudo abrir."));
      image.onload = () => {
        const longest = Math.max(Number(image.width) || 0, Number(image.height) || 0);
        if (!longest) {
          reject(new Error("Esa imagen no se pudo abrir."));
          return;
        }
        const ratio = Math.min(1, CATALOG_IMAGE_SIZE / longest);
        const width = Math.max(1, Math.round((Number(image.width) || 1) * ratio));
        const height = Math.max(1, Math.round((Number(image.height) || 1) * ratio));

        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(image, 0, 0, width, height);

        try {
          resolve(canvas.toDataURL("image/jpeg", 0.82));
        } catch (err) {
          reject(new Error("No se pudo preparar la imagen."));
        }
      };
      image.src = String(reader.result || "");
    };
    reader.readAsDataURL(file);
  });

/* ------------------------------------------------------------
   Imágenes de artista y género
   ------------------------------------------------------------ */

// Sin imagen propia se arma un mosaico con las carátulas de sus canciones:
// así el artista o el género se reconoce de un vistazo.
const catalogArt = (group, { ignoreCustom = false } = {}) => {
  if (!group) return "";

  const custom = ignoreCustom ? "" : catalogImageFor(group.kind, group.name);
  if (custom) {
    return `<img class="cover cover--photo catalog-art" src="${escapeHTML(custom)}" alt="" loading="lazy" />`;
  }

  const tiles = group.tracks.slice(0, 4);
  if (!tiles.length) {
    return `<div class="cover catalog-art" style="--c1:#0f6b78;--c2:#06121f;--c3:#6be8d2" aria-hidden="true">
      <span class="cover__wash"></span>
    </div>`;
  }

  return `<span class="mosaic mosaic--${tiles.length}">
    ${tiles
      .map(
        (track) =>
          `<span class="mosaic__cell">${coverHTML({ title: track.title, coverUrl: track.coverUrl })}</span>`
      )
      .join("")}
  </span>`;
};

const catalogArtHTML = (kind, name) => {
  const group = catalogGroup(kind, name);
  return group ? catalogArt(group) : "";
};

// Bajada de un artista o género: cuántas canciones tiene y cuánto duran.
const catalogGroupSubtitle = (kind, name) => {
  const group = catalogGroup(kind, name);
  if (!group) return "";
  const songs = plural(group.count, "canción", "canciones");
  return group.duration ? `${songs} · ${formatTotal(group.duration)}` : songs;
};

/* ------------------------------------------------------------
   Editar artista o género
   ------------------------------------------------------------ */

// "" = la imagen no cambia · dataURL = imagen nueva · null = quitarla.
let catalogPendingImage = "";
let catalogPendingKind = "";
let catalogPendingName = "";

const openCatalogEditor = (kind, name) => {
  const config = CATALOG_KINDS[kind];
  const group = catalogGroup(kind, name);
  if (!config || !group) return;

  catalogPendingImage = "";
  catalogPendingKind = kind;
  catalogPendingName = group.name;

  const hasCustom = Boolean(catalogImageFor(kind, group.name));

  openModal({
    title: kind === "artist" ? "Editar artista" : "Editar género",
    eyebrow: group.name,
    body: `
      <form class="form" id="catalogForm">
        <div class="catalog-edit">
          <div class="catalog-edit__art" id="catalogEditArt">${catalogArt(group)}</div>
          <div class="catalog-edit__fields">
            <label class="field">
              <span>Nombre</span>
              <input name="catalogName" maxlength="${config.maxLength}" value="${escapeHTML(group.name)}" required data-autofocus />
            </label>
            <p class="catalog-edit__hint">
              ${plural(group.count, "canción", "canciones")} · ${formatTotal(group.duration)}.
              Si ya existe ${kind === "artist" ? "otro artista" : "otro género"} con ese nombre, se fusionan.
            </p>
            <div class="catalog-edit__actions">
              <label class="btn btn--soft btn--small catalog-edit__pick">
                <input type="file" id="catalogImageInput" accept="image/*" class="catalog-edit__input" />
                ${icon("upload")} <span>Elegir imagen</span>
              </label>
              ${hasCustom ? `<button type="button" class="btn btn--ghost btn--small" data-action="catalog-image-clear">Quitar la imagen</button>` : ""}
            </div>
            <p class="catalog-edit__note">La imagen se guarda en este navegador y se usa también en Tendencias.</p>
          </div>
        </div>
        <div class="modal__actions">
          <button type="button" class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          <button type="submit" class="btn btn--primary">${icon("check")} Guardar</button>
        </div>
      </form>`
  });

  const form = $("#catalogForm");
  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    const nextName = String(form.catalogName?.value || "").trim();
    if (!nextName) {
      toast(`El ${config.label} necesita un nombre.`, "error");
      return;
    }
    if (submit) submit.disabled = true;

    const renamed = nextName !== catalogPendingName;
    const tracks = catalogGroup(kind, catalogPendingName)?.tracks || [];

    try {
      // La imagen primero: si no entra en el almacenamiento, mejor avisar
      // antes de tocar las canciones.
      if (catalogPendingImage === null) {
        catalogSaveImage(kind, nextName, "");
        if (renamed) catalogSaveImage(kind, catalogPendingName, "");
      } else if (catalogPendingImage) {
        const saved = catalogSaveImage(kind, nextName, catalogPendingImage);
        if (!saved) {
          throw new Error("No hay lugar guardado para la imagen. Probá con una más chica.");
        }
        if (renamed) catalogSaveImage(kind, catalogPendingName, "");
      } else if (renamed) {
        catalogMoveImage(kind, catalogPendingName, nextName);
      }

      if (renamed && tracks.length) {
        for (let index = 0; index < tracks.length; index += 1) {
          const track = tracks[index];
          await api(`/wavernote/tracks/${track.id}`, {
            method: "PATCH",
            body: {
              [config.field]:
                kind === "artist"
                  ? renameTrackArtist(track, catalogPendingName, nextName)
                  : nextName
            }
          });
          if (submit) {
            submit.innerHTML = `${icon("check")} ${index + 1} de ${tracks.length}`;
          }
        }
      }

      await refreshLibrary();
      renderSidebarPlaylists();
      renderView({ resetScroll: false });
      updateNowPlaying();
      closeModal(true);
      toast(renamed ? `Ahora se llama «${nextName}».` : `${config.label[0].toUpperCase()}${config.label.slice(1)} actualizado.`);
    } catch (err) {
      toast(friendlyError(err), "error");
      if (submit) submit.disabled = false;
    }
  });

  const input = $("#catalogImageInput");
  input?.addEventListener("change", async () => {
    const file = input.files?.[0];
    if (!file) return;
    try {
      const dataUrl = await catalogReadImage(file);
      catalogPendingImage = dataUrl;
      const art = $("#catalogEditArt");
      if (art) {
        art.innerHTML = `<img class="cover cover--photo catalog-art" src="${escapeHTML(dataUrl)}" alt="" />`;
      }
    } catch (err) {
      toast(friendlyError(err), "error");
    }
  });
};

const catalogClearImage = () => {
  const kind = catalogPendingKind;
  const name = catalogPendingName;
  if (!kind || !name) return;

  // null = borrar la imagen guardada (distinto de "" = no tocar nada).
  catalogPendingImage = null;
  const art = $("#catalogEditArt");
  const group = catalogGroup(kind, name);
  if (art && group) art.innerHTML = catalogArt(group, { ignoreCustom: true });
  toast("Imagen quitada: vuelve el mosaico de las canciones.");
};

const catalogPlayGroup = (kind, name) => {
  const group = catalogGroup(kind, name);
  if (!group || !group.tracks.length) return;
  const ids = group.tracks.map((track) => track.id);
  const index = Math.max(
    0,
    ids.findIndex((id) => id === Number(state.currentTrackId))
  );
  startQueue(ids, { startIndex: index });
};

/* ------------------------------------------------------------
   Aviso de artistas sin canciones nuevas
   Se toma la canción más reciente de cada artista y se cuentan
   siete días desde ahí. Los vencimientos cercanos se agrupan en
   un solo aviso para no preguntar varias veces por semana.
   ------------------------------------------------------------ */

const ARTIST_REMINDER_KEY = "wavernote.artistReminders.v1";
const ARTIST_REMINDER_DAYS = 7;
const ARTIST_REMINDER_DAY_MS = 86400000;
// Si otro artista vence dentro de este margen, conviene esperarlo para
// mostrarlo junto al resto en un único aviso.
const ARTIST_REMINDER_BATCH_MS = ARTIST_REMINDER_DAY_MS;

const artistReminderStore = () => {
  const raw = readJSON(ARTIST_REMINDER_KEY, {});
  return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
};

const artistReminderSave = (store) => {
  try {
    localStorage.setItem(ARTIST_REMINDER_KEY, JSON.stringify(store));
    return true;
  } catch (err) {
    return false;
  }
};

const artistLastAdditions = () => {
  const map = new Map();

  state.tracks.forEach((track) => {
    const at = new Date(track.createdAt || 0).getTime();
    if (!Number.isFinite(at) || at <= 0) return;

    trackArtists(track).forEach((name) => {
      const key = normalize(name);
      if (!key) return;

      const current = map.get(key);
      if (!current) {
        map.set(key, { key, name, lastAddedAt: at });
        return;
      }

      current.name = name;
      if (at > current.lastAddedAt) current.lastAddedAt = at;
    });
  });

  return map;
};

const artistReminderDue = (item) => item.lastAddedAt + ARTIST_REMINDER_DAYS * ARTIST_REMINDER_DAY_MS;

const artistReminderPending = (now = Date.now()) => {
  const store = artistReminderStore();
  const all = Array.from(artistLastAdditions().values());

  const isPending = (item) => {
    if (now < artistReminderDue(item)) return false;
    const entry = store[item.key];
    return !entry || Number(entry.lastAddedAt) !== item.lastAddedAt;
  };

  const pending = all.filter(isPending).sort((a, b) => a.lastAddedAt - b.lastAddedAt);
  if (!pending.length) return [];

  // Espera a que venza el artista que está por cumplir la semana: así el
  // aviso los enumera a todos juntos en lugar de repetirse día por día.
  const wait = all.some((item) => {
    const due = artistReminderDue(item);
    if (due <= now || due - now > ARTIST_REMINDER_BATCH_MS) return false;
    const entry = store[item.key];
    return !entry || Number(entry.lastAddedAt) !== item.lastAddedAt;
  });

  return wait ? [] : pending;
};

const artistReminderAcknowledge = (items) => {
  const store = artistReminderStore();
  const live = artistLastAdditions();
  const now = Date.now();

  items.forEach((item) => {
    store[item.key] = { name: item.name, lastAddedAt: item.lastAddedAt, notifiedAt: now };
  });

  Object.keys(store).forEach((key) => {
    if (!live.has(key)) delete store[key];
  });

  artistReminderSave(store);
};

const openArtistReminder = (items) => {
  const now = Date.now();
  const daysSince = (time) =>
    Math.max(ARTIST_REMINDER_DAYS, Math.floor((now - time) / ARTIST_REMINDER_DAY_MS));

  openModal({
    title: "¿Sumamos música nueva?",
    eyebrow: "Tu biblioteca",
    body: `
      <div class="artist-reminder">
        <p class="artist-reminder__lead">Hace más de una semana que no agregás canciones de ${
          items.length === 1 ? "este artista" : "estos artistas"
        }:</p>
        <ul class="artist-reminder__list">
          ${items
            .map(
              (item) => `<li>
                <strong>${escapeHTML(item.name)}</strong>
                <span>Última canción: ${escapeHTML(dateLabel(item.lastAddedAt))} · hace ${plural(
                  daysSince(item.lastAddedAt),
                  "día",
                  "días"
                )}</span>
              </li>`
            )
            .join("")}
        </ul>
        <p class="artist-reminder__note">El aviso solo te informa que no subiste canciones nuevas en más de una semana. Podés cerrarlo cuando quieras.</p>
      </div>
      <div class="modal__actions">
        <button class="btn btn--ghost" data-action="close-modal">Cerrar</button>
        <button class="btn btn--primary" data-action="artist-reminder-upload">${icon("upload")} Subir música</button>
      </div>`
  });
};

let artistReminderShown = false;

const maybeShowArtistReminder = () => {
  if (artistReminderShown) return;
  if (!state.ready || !state.tracks.length) return;
  if (document.getElementById("modal")?.classList.contains("is-open")) return;

  const items = artistReminderPending();
  if (!items.length) return;

  artistReminderShown = true;
  artistReminderAcknowledge(items);
  openArtistReminder(items);
};

window.WaverNoteArtistReminder = { maybeShow: maybeShowArtistReminder };
