/* ============================================================
   WaverNote · modo sin conexión
   Guarda una copia de la biblioteca y las canciones descargadas
   en IndexedDB. Así la app abre y reproduce sin internet, y al
   volver la conexión se sincroniza otra vez con la cuenta.
   ============================================================ */

const WA_OFFLINE_DB = "wavernote-offline";
const WA_OFFLINE_DB_VERSION = 1;
const WA_OFFLINE_AUDIO_STORE = "audio";
const WA_OFFLINE_META_STORE = "meta";
// Tope absoluto de descargas. Si el navegador informa menos espacio
// disponible, se usa la mitad de la cuota real como margen de seguridad.
const WA_OFFLINE_MAX_BYTES = 4 * 1024 * 1024 * 1024;
const WA_OFFLINE_COVER_MAX_BYTES = 512 * 1024;
const WA_OFFLINE_COVER_TIMEOUT_MS = 8000;
const WA_OFFLINE_DOWNLOAD_TIMEOUT_MS = 180000;

const waOffline = {
  dbPromise: null,
  userId: 0,
  ready: false,
  persistAsked: false,
  downloads: new Map(),
  audioUrls: new Map(),
  coverUrls: new Map()
};

const offlineSupported = () => typeof indexedDB !== "undefined";

const offlineOpenDB = () => {
  if (!offlineSupported()) {
    return Promise.reject(new Error("Este dispositivo no permite guardar descargas."));
  }
  if (waOffline.dbPromise) return waOffline.dbPromise;

  waOffline.dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(WA_OFFLINE_DB, WA_OFFLINE_DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(WA_OFFLINE_AUDIO_STORE)) {
        db.createObjectStore(WA_OFFLINE_AUDIO_STORE);
      }
      if (!db.objectStoreNames.contains(WA_OFFLINE_META_STORE)) {
        db.createObjectStore(WA_OFFLINE_META_STORE);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error || new Error("No se pudo abrir el almacenamiento local."));
  }).catch((err) => {
    waOffline.dbPromise = null;
    throw err;
  });

  return waOffline.dbPromise;
};

const offlineGet = async (store, key) => {
  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const request = db.transaction(store, "readonly").objectStore(store).get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
};

const offlinePut = async (store, key, value) => {
  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("No se pudo guardar."));
  });
};

const offlineDelete = async (store, key) => {
  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("No se pudo borrar."));
  });
};

// Las descargas se guardan de a una ficha. Antes toda la lista vivía en un
// único registro: si esa escritura fallaba o la app se cerraba a mitad, las
// canciones quedaban con su audio pero sin ficha, y al abrir sin conexión
// aparecían como "no descargadas". Estos helpers permiten leer y reparar las
// fichas en una sola transacción.
const offlineGetMany = async (store, keys) => {
  const unique = Array.from(new Set((keys || []).map((key) => String(key)).filter(Boolean)));
  const found = new Map();
  if (!unique.length) return found;

  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const objectStore = tx.objectStore(store);
    let pending = unique.length;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      resolve(found);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };

    unique.forEach((key) => {
      const request = objectStore.get(key);
      request.onsuccess = () => {
        if (request.result != null) found.set(key, request.result);
        pending -= 1;
        if (pending <= 0) finish();
      };
      request.onerror = () => fail(request.error);
    });
    tx.onerror = () => fail(tx.error);
  });
};

const offlineGetAllKeys = async (store) => {
  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const request = db.transaction(store, "readonly").objectStore(store).getAllKeys();
    request.onsuccess = () => resolve(Array.isArray(request.result) ? request.result : []);
    request.onerror = () => reject(request.error);
  });
};

const offlinePutMany = async (store, entries) => {
  const list = (entries || []).filter((entry) => Array.isArray(entry) && entry[0] != null);
  if (!list.length) return true;

  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    const objectStore = tx.objectStore(store);
    list.forEach(([key, value]) => objectStore.put(value, key));
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("No se pudo guardar."));
  });
};

const offlineDeleteMany = async (store, keys) => {
  const list = Array.from(new Set((keys || []).map((key) => String(key)).filter(Boolean)));
  if (!list.length) return true;

  const db = await offlineOpenDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    const objectStore = tx.objectStore(store);
    list.forEach((key) => objectStore.delete(key));
    tx.oncomplete = () => resolve(true);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error("No se pudo borrar."));
  });
};

const offlineLibraryKey = (userId) => `library:${Number(userId) || 0}`;
// Clave vieja: la lista entera de descargas vivía en un solo registro. Se
// mantiene solo para migrar lo que ya estaba guardado en 1.2.4.
const offlineDownloadsKey = (userId) => `downloads:${Number(userId) || 0}`;
const offlineDownloadEntryKey = (userId, trackId) =>
  `download:${Number(userId) || 0}:${Number(trackId) || 0}`;
const offlineAudioKey = (userId, trackId) =>
  `${Number(userId) || 0}:${Number(trackId) || 0}`;

/* ------------------------------------------------------------
   Audio local: tipo de archivo
   ------------------------------------------------------------ */

const OFFLINE_AUDIO_MIME = {
  mp3: "audio/mpeg",
  mp2: "audio/mpeg",
  wav: "audio/wav",
  ogg: "audio/ogg",
  oga: "audio/ogg",
  opus: "audio/ogg",
  m4a: "audio/mp4",
  mp4: "audio/mp4",
  aac: "audio/aac",
  flac: "audio/flac",
  webm: "audio/webm",
  aiff: "audio/aiff",
  aif: "audio/aiff",
  wma: "audio/x-ms-wma"
};

const offlineExtensionOf = (value) => {
  try {
    const clean = String(value || "").split(/[?#]/)[0];
    const name = clean.split("/").pop() || "";
    const dot = name.lastIndexOf(".");
    return dot >= 0 ? name.slice(dot + 1).toLowerCase() : "";
  } catch (err) {
    return "";
  }
};

const offlineMimeIsGeneric = (type) => {
  const value = String(type || "").trim().toLowerCase();
  return (
    !value ||
    value === "application/octet-stream" ||
    value === "binary/octet-stream" ||
    value === "application/unknown" ||
    value === "text/plain"
  );
};

const offlineMimeFromName = (value) => OFFLINE_AUDIO_MIME[offlineExtensionOf(value)] || "";

const offlineAudioTypeHint = (track, record) => {
  const stored = String(record?.mime || "").trim();
  if (stored && !offlineMimeIsGeneric(stored)) return stored;

  const fromUrl = offlineMimeFromName(track?.audioUrl || record?.track?.audioUrl || "");
  if (fromUrl) return fromUrl;

  const title = String(track?.title || record?.track?.title || "");
  return offlineMimeFromName(title) || "";
};

// Último respaldo: si la URL no dice el formato y el servidor no mandó un tipo
// útil, se mira el encabezado del archivo. Evita que Android rechace una
// descarga válida solo porque el blob quedó como "application/octet-stream".
const offlineSniffAudioMime = async (blob) => {
  if (!blob || typeof blob.slice !== "function") return "";
  try {
    const bytes = new Uint8Array(await blob.slice(0, 12).arrayBuffer());
    if (bytes.length < 4) return "";
    const head = String.fromCharCode(...bytes.subarray(0, 4));
    if (head === "OggS") return "audio/ogg";
    if (head === "fLaC") return "audio/flac";
    if (head === "RIFF") return "audio/wav";
    if (head.startsWith("ID3")) return "audio/mpeg";
    if (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0) {
      // ADTS (AAC) no usa los bits de capa; los frames MP3 sí.
      return (bytes[1] & 0x06) === 0 ? "audio/aac" : "audio/mpeg";
    }
    if (bytes.length >= 8 && String.fromCharCode(...bytes.subarray(4, 8)) === "ftyp") {
      const brand = String.fromCharCode(...bytes.subarray(8, 12));
      if (/^(M4A|M4B|mp4|iso|dash)/i.test(brand)) return "audio/mp4";
    }
  } catch (err) {
    /* sin acceso a los bytes: se usa el tipo original */
  }
  return "";
};

// Android WebView decide qué decodificador usar según el MIME del blob. Si
// Cloudinary responde "application/octet-stream" o sin tipo, algunos formatos
// (M4A/AAC/FLAC) no abren aunque el archivo esté completo. El blob se vuelve a
// envolver con el tipo correcto sin copiar ni recodificar el audio.
const offlineNormalizeAudioBlob = (blob, typeHint) => {
  if (!blob) return null;
  let source = blob;

  if (!(source instanceof Blob)) {
    try {
      source = new Blob([source], { type: String(typeHint || "") });
    } catch (err) {
      return null;
    }
  }

  const current = String(source.type || "").trim().toLowerCase();
  const hint = String(typeHint || "").trim().toLowerCase();
  const next = offlineMimeIsGeneric(current) && hint && !offlineMimeIsGeneric(hint) ? hint : current;
  if (!next || next === current) return source;

  try {
    return new Blob([source], { type: next });
  } catch (err) {
    return source;
  }
};

/* ------------------------------------------------------------
   Biblioteca guardada
   ------------------------------------------------------------ */

const offlineSaveLibrary = async (userId, data) => {
  const id = Number(userId) || 0;
  if (!id || !data) return false;

  try {
    await offlinePut(WA_OFFLINE_META_STORE, offlineLibraryKey(id), {
      savedAt: Date.now(),
      data: {
        tracks: Array.isArray(data.tracks) ? data.tracks : [],
        pending: Array.isArray(data.pending) ? data.pending : [],
        playlists: Array.isArray(data.playlists) ? data.playlists : [],
        likes: Array.isArray(data.likes) ? data.likes : []
      }
    });
    return true;
  } catch (err) {
    // Sin IndexedDB la app sigue funcionando online, solo pierde la copia.
    return false;
  }
};

const offlineReadLibrary = async (userId) => {
  const id = Number(userId) || 0;
  if (!id) return null;

  try {
    const saved = await offlineGet(WA_OFFLINE_META_STORE, offlineLibraryKey(id));
    return saved?.data && typeof saved.data === "object" ? saved.data : null;
  } catch (err) {
    return null;
  }
};

/* ------------------------------------------------------------
   Descargas de audio
   ------------------------------------------------------------ */

const offlineHas = (trackId) => waOffline.downloads.has(Number(trackId) || 0);

const offlineHasDownloads = () => waOffline.downloads.size > 0;

const offlineCoverURL = (trackId) => waOffline.coverUrls.get(Number(trackId) || 0) || "";

const offlineDownloadedTracks = () => Array.from(waOffline.downloads.values());

const offlineSummary = () => {
  let bytes = 0;
  waOffline.downloads.forEach((entry) => {
    bytes += Math.max(0, Number(entry?.size) || 0);
  });
  return { count: waOffline.downloads.size, bytes };
};

const offlineEntryFromRecord = (trackId, record) => {
  const id = Number(trackId) || 0;
  const track = record?.track && typeof record.track === "object" ? record.track : {};
  return {
    id,
    size: Math.max(0, Number(record?.size) || Number(record?.blob?.size) || 0),
    savedAt: Number(record?.savedAt) || Date.now(),
    title: String(track.title || ""),
    artist: String(track.artist || ""),
    album: String(track.album || ""),
    genre: String(track.genre || ""),
    duration: Number(track.duration) || 0,
    cover: ""
  };
};

const offlineReadDownloadEntries = async (userId) => {
  const prefix = `download:${Number(userId) || 0}:`;
  const keys = (await offlineGetAllKeys(WA_OFFLINE_META_STORE))
    .map((key) => String(key))
    .filter((key) => key.startsWith(prefix));
  if (!keys.length) return [];

  const values = await offlineGetMany(WA_OFFLINE_META_STORE, keys);
  return keys
    .filter((key) => values.has(key))
    .map((key) => {
      const entry = values.get(key);
      const trackId = Number(entry?.id) || Number(key.slice(prefix.length)) || 0;
      return trackId ? { ...entry, id: trackId } : null;
    })
    .filter(Boolean);
};

// 1.2.4 guardaba todas las fichas en un solo registro. Se pasan a fichas
// individuales para que una escritura grande no pueda perder varias descargas.
const offlineMigrateLegacyDownloads = async (userId) => {
  const legacyKey = offlineDownloadsKey(userId);
  const saved = await offlineGet(WA_OFFLINE_META_STORE, legacyKey);
  if (!Array.isArray(saved)) return;

  const entries = [];
  saved.forEach((entry) => {
    const trackId = Number(entry?.id);
    if (!trackId) return;
    entries.push([offlineDownloadEntryKey(userId, trackId), { ...entry, id: trackId }]);
  });

  if (entries.length) await offlinePutMany(WA_OFFLINE_META_STORE, entries);
  await offlineDelete(WA_OFFLINE_META_STORE, legacyKey);
};

const offlineAudioTrackIds = async (userId) => {
  const prefix = `${Number(userId) || 0}:`;
  return (await offlineGetAllKeys(WA_OFFLINE_AUDIO_STORE))
    .map((key) => String(key))
    .filter((key) => key.startsWith(prefix))
    .map((key) => Number(key.slice(prefix.length)) || 0)
    .filter(Boolean);
};

// El audio es la fuente de verdad. Si una ficha no llegó a guardarse, se
// reconstruye desde el registro del audio; si la ficha existe pero el audio ya
// no está, se quita para no mostrar como descargada una canción que no va a
// sonar sin conexión.
const offlineReconcileDownloads = async (userId) => {
  const audioIds = await offlineAudioTrackIds(userId);
  const audioSet = new Set(audioIds);

  const missing = audioIds.filter((trackId) => !waOffline.downloads.has(trackId));
  if (missing.length) {
    const records = await offlineGetMany(
      WA_OFFLINE_AUDIO_STORE,
      missing.map((trackId) => offlineAudioKey(userId, trackId))
    );
    const recovered = [];
    missing.forEach((trackId) => {
      const record = records.get(offlineAudioKey(userId, trackId));
      if (!record?.blob) return;
      const entry = offlineEntryFromRecord(trackId, record);
      waOffline.downloads.set(trackId, entry);
      if (entry.cover) waOffline.coverUrls.set(trackId, entry.cover);
      recovered.push([offlineDownloadEntryKey(userId, trackId), entry]);
    });
    if (recovered.length) await offlinePutMany(WA_OFFLINE_META_STORE, recovered);
  }

  const stale = [];
  waOffline.downloads.forEach((entry, trackId) => {
    if (audioSet.has(trackId)) return;
    waOffline.downloads.delete(trackId);
    waOffline.coverUrls.delete(trackId);
    stale.push(offlineDownloadEntryKey(userId, trackId));
  });
  if (stale.length) await offlineDeleteMany(WA_OFFLINE_META_STORE, stale);
};

const offlineSaveDownloadEntry = async (entry) => {
  const trackId = Number(entry?.id);
  if (!trackId || !waOffline.userId) return false;
  try {
    await offlinePut(
      WA_OFFLINE_META_STORE,
      offlineDownloadEntryKey(waOffline.userId, trackId),
      { ...entry, id: trackId }
    );
    return true;
  } catch (err) {
    // El audio ya quedó guardado: al próximo arranque se reconstruye la ficha.
    return false;
  }
};

const offlineInit = async (userId) => {
  const id = Number(userId) || 0;
  if (waOffline.ready && waOffline.userId === id) return;

  offlineReset();
  waOffline.userId = id;

  if (!id || !offlineSupported()) {
    waOffline.ready = true;
    return;
  }

  try {
    await offlineMigrateLegacyDownloads(id);
  } catch (err) {
    /* si la migración falla, se intenta leer lo que ya esté guardado */
  }

  try {
    const entries = await offlineReadDownloadEntries(id);
    entries.forEach((entry) => {
      const trackId = Number(entry?.id);
      if (!trackId) return;
      waOffline.downloads.set(trackId, entry);
      if (entry.cover) waOffline.coverUrls.set(trackId, entry.cover);
    });
  } catch (err) {
    /* fichas ilegibles: la reconciliación puede recuperarlas del audio */
  }

  try {
    await offlineReconcileDownloads(id);
  } catch (err) {
    /* el audio ya está guardado; se reintenta en el próximo arranque */
  }

  waOffline.ready = true;
};

const offlineReset = () => {
  waOffline.audioUrls.forEach((url) => {
    try {
      URL.revokeObjectURL(url);
    } catch (err) {
      /* noop */
    }
  });
  waOffline.audioUrls.clear();
  waOffline.coverUrls.clear();
  waOffline.downloads.clear();
  waOffline.userId = 0;
  waOffline.ready = false;
  waOffline.persistAsked = false;
};

// Devuelve la URL local de una canción descargada, o "" si no está.
// Se guarda en memoria para no leer el blob de IndexedDB en cada play.
const offlinePlaybackURL = async (track) => {
  const trackId = Number(track?.id);
  if (!trackId || !waOffline.downloads.has(trackId)) return "";

  const memo = waOffline.audioUrls.get(trackId);
  if (memo) return memo;

  try {
    const record = await offlineGet(
      WA_OFFLINE_AUDIO_STORE,
      offlineAudioKey(waOffline.userId, trackId)
    );
    let hint = offlineAudioTypeHint(track, record);
    if (!hint) hint = await offlineSniffAudioMime(record?.blob);
    const blob = offlineNormalizeAudioBlob(record?.blob, hint);
    if (!blob?.size) {
      // La ficha quedó sin audio (por ejemplo, una descarga cortada). Se
      // descarta para que la canción no figure como disponible sin conexión.
      waOffline.downloads.delete(trackId);
      waOffline.coverUrls.delete(trackId);
      try {
        await offlineDelete(
          WA_OFFLINE_META_STORE,
          offlineDownloadEntryKey(waOffline.userId, trackId)
        );
      } catch (err) {
        /* se reintenta en el próximo arranque */
      }
      return "";
    }

    const url = URL.createObjectURL(blob);
    waOffline.audioUrls.set(trackId, url);
    return url;
  } catch (err) {
    return "";
  }
};

const offlineBlobToDataURL = (blob) =>
  new Promise((resolve) => {
    try {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => resolve("");
      reader.readAsDataURL(blob);
    } catch (err) {
      resolve("");
    }
  });

// La portada es opcional: si tarda o falla, la copia se guarda igual sin ella.
const offlineFetchCover = async (url) => {
  if (!url) return "";

  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  let timer = 0;
  const timedOut = new Promise((resolve) => {
    timer = setTimeout(() => {
      try {
        controller?.abort();
      } catch (err) {
        /* el fetch se corta solo */
      }
      resolve(null);
    }, WA_OFFLINE_COVER_TIMEOUT_MS);
  });

  try {
    const response = await Promise.race([
      fetch(url, { mode: "cors", signal: controller?.signal }),
      timedOut
    ]);
    if (!response?.ok) return "";

    const blob = await Promise.race([response.blob(), timedOut]);
    if (!blob?.size || blob.size > WA_OFFLINE_COVER_MAX_BYTES) return "";
    return await offlineBlobToDataURL(blob);
  } catch (err) {
    return "";
  } finally {
    clearTimeout(timer);
  }
};

const offlineFetchBlob = (url, onProgress) =>
  new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("GET", url, true);
    request.responseType = "blob";
    request.timeout = WA_OFFLINE_DOWNLOAD_TIMEOUT_MS;

    request.onprogress = (event) => {
      if (!event.lengthComputable || !event.total || typeof onProgress !== "function") return;
      onProgress(Math.min(1, Math.max(0, event.loaded / event.total)));
    };

    request.onload = () => {
      if (request.status >= 200 && request.status < 300 && request.response) {
        resolve(request.response);
        return;
      }
      reject(new Error(`No se pudo guardar la copia sin conexión (${request.status || "sin respuesta"}).`));
    };

    request.onerror = () =>
      reject(new Error("No se pudo guardar la copia sin conexión. Revisá tu conexión."));
    request.ontimeout = () => reject(new Error("La copia tardó demasiado. Probá de nuevo."));
    request.send();
  });

const offlineStorageLimit = async () => {
  try {
    const estimate = await navigator.storage?.estimate?.();
    const quota = Number(estimate?.quota) || 0;
    if (quota > 0) {
      return Math.max(256 * 1024 * 1024, Math.min(WA_OFFLINE_MAX_BYTES, quota * 0.5));
    }
  } catch (err) {
    /* el navegador no informa cuota */
  }
  return WA_OFFLINE_MAX_BYTES;
};

const offlineAskPersistence = async () => {
  if (waOffline.persistAsked) return;
  waOffline.persistAsked = true;
  try {
    if (navigator.storage?.persist) await navigator.storage.persist();
  } catch (err) {
    /* el navegador decide igual */
  }
};

// Guarda un audio que ya está en memoria (descarga o archivo del dispositivo)
// y devuelve la misma forma que usa el menú: { already, size }.
const offlineStoreTrackBlob = async (track, blob, { cover = "", savedAt = Date.now() } = {}) => {
  const trackId = Number(track?.id);
  const userId = waOffline.userId;

  if (!trackId || !userId) throw new Error("Iniciá sesión para guardar canciones.");
  if (waOffline.downloads.has(trackId)) {
    return { already: true, size: Number(waOffline.downloads.get(trackId)?.size) || 0 };
  }
  if (!blob?.size) throw new Error("La canción llegó vacía. Probá de nuevo.");
  if (!offlineSupported()) {
    throw new Error("Este dispositivo no permite guardar copias sin conexión.");
  }

  // El archivo del dispositivo suele traer el tipo correcto; se prioriza sobre
  // la URL, que a veces no tiene extensión o viene como "octet-stream".
  const blobType = String(blob.type || "").trim();
  const hint =
    (!offlineMimeIsGeneric(blobType) ? blobType : "") ||
    offlineAudioTypeHint(track, null) ||
    (await offlineSniffAudioMime(blob));
  const normalized = offlineNormalizeAudioBlob(blob, hint);
  if (!normalized?.size) throw new Error("La canción llegó vacía. Probá de nuevo.");

  const limit = await offlineStorageLimit();
  let usage = 0;
  try {
    const estimate = await navigator.storage?.estimate?.();
    usage = Number(estimate?.usage) || 0;
  } catch (err) {
    usage = 0;
  }

  if (usage + normalized.size > limit) {
    throw new Error(
      "No hay espacio suficiente para esta copia sin conexión. Quitá algunas canciones guardadas y probá de nuevo."
    );
  }

  const snapshot = {
    id: trackId,
    title: track.title || "",
    artist: track.artist || "",
    album: track.album || "",
    genre: track.genre || "",
    duration: Number(track.duration) || 0,
    coverUrl: track.coverUrl || "",
    audioUrl: track.audioUrl || ""
  };
  const entry = {
    id: trackId,
    size: normalized.size,
    savedAt,
    ...snapshot,
    cover
  };

  // El registro de audio guarda su propia ficha. Así, aunque falle la escritura
  // de metadatos, al abrir sin conexión la copia se puede reconstruir.
  await offlinePut(WA_OFFLINE_AUDIO_STORE, offlineAudioKey(userId, trackId), {
    blob: normalized,
    size: normalized.size,
    savedAt,
    mime: String(normalized.type || ""),
    track: snapshot
  });

  waOffline.downloads.set(trackId, entry);
  if (cover) waOffline.coverUrls.set(trackId, cover);
  await offlineSaveDownloadEntry(entry);

  return { already: false, size: normalized.size };
};

const offlineDownloadTrack = async (track, onProgress) => {
  const trackId = Number(track?.id);
  const userId = waOffline.userId;

  if (!trackId || !userId) throw new Error("Iniciá sesión para guardar canciones.");
  if (waOffline.downloads.has(trackId)) {
    return { already: true, size: Number(waOffline.downloads.get(trackId)?.size) || 0 };
  }
  if (!track.audioUrl) throw new Error("Esta canción no tiene un archivo para guardar sin conexión.");
  if (navigator.onLine === false) {
    throw new Error("Sin conexión: no se puede guardar la copia ahora.");
  }
  if (!offlineSupported()) {
    throw new Error("Este dispositivo no permite guardar copias sin conexión.");
  }

  await offlineAskPersistence();

  const fetched = await offlineFetchBlob(track.audioUrl, onProgress);
  if (!fetched.size) throw new Error("La canción llegó vacía. Probá de nuevo.");

  const cover = await offlineFetchCover(track.coverUrl);
  return offlineStoreTrackBlob(track, fetched, { cover });
};

// Al subir un archivo desde el dispositivo ya tenemos el audio en la mano: se
// guarda esa misma copia en vez de pedirle al usuario que lo "descargue" otra
// vez. Si no hay espacio o el almacenamiento no está disponible, la subida
// igual queda bien y la copia se puede guardar después desde el menú.
const offlineSaveUploadedTrack = async (track, file, { cover: coverFile = null } = {}) => {
  try {
    const trackId = Number(track?.id);
    if (!trackId || !file?.size) return { already: false, size: 0, skipped: true };
    if (!waOffline.userId || !offlineSupported()) {
      return { already: false, size: 0, skipped: true };
    }
    if (waOffline.downloads.has(trackId)) {
      return { already: true, size: Number(waOffline.downloads.get(trackId)?.size) || 0 };
    }

    await offlineAskPersistence();

    let cover = "";
    const hasCoverFile = coverFile instanceof Blob && coverFile.size > 0;
    if (hasCoverFile && coverFile.size <= WA_OFFLINE_COVER_MAX_BYTES) {
      cover = await offlineBlobToDataURL(coverFile);
    }
    // Solo se busca la portada en la red cuando la subida no trajo ninguna:
    // así el guardado no espera una descarga extra que no hace falta.
    if (!hasCoverFile) cover = await offlineFetchCover(track.coverUrl);

    return await offlineStoreTrackBlob(track, file, { cover });
  } catch (err) {
    return { already: false, size: 0, skipped: true, error: String(err?.message || err || "") };
  }
};

const offlineRemoveTrack = async (trackId) => {
  const id = Number(trackId);
  if (!id || !waOffline.userId) return false;

  const memo = waOffline.audioUrls.get(id);
  if (memo) {
    try {
      URL.revokeObjectURL(memo);
    } catch (err) {
      /* noop */
    }
    waOffline.audioUrls.delete(id);
  }

  waOffline.downloads.delete(id);
  waOffline.coverUrls.delete(id);

  try {
    await offlineDelete(WA_OFFLINE_AUDIO_STORE, offlineAudioKey(waOffline.userId, id));
  } catch (err) {
    /* si ya no estaba, igual limpiamos la lista */
  }

  try {
    await offlineDelete(
      WA_OFFLINE_META_STORE,
      offlineDownloadEntryKey(waOffline.userId, id)
    );
  } catch (err) {
    /* la ficha vieja se descarta en la próxima reconciliación */
  }

  return true;
};

// Si todavía no hay una copia de la biblioteca (por ejemplo, la primera
// apertura sin conexión después de actualizar), las descargas alcanzan
// para armar una biblioteca mínima que se pueda reproducir.
const offlineLibraryFromDownloads = () => {
  const tracks = offlineDownloadedTracks()
    .map((entry) => ({
      id: Number(entry.id),
      title: entry.title || "Canción sin título",
      artist: entry.artist || "Artista desconocido",
      album: entry.album || "Sin álbum",
      genre: entry.genre || "",
      duration: Number(entry.duration) || 0,
      coverUrl: "",
      audioUrl: "",
      createdAt: entry.savedAt ? new Date(entry.savedAt).toISOString() : null
    }))
    .filter((track) => track.id);

  return { tracks, playlists: [], likes: [], pending: [] };
};

/* ------------------------------------------------------------
   API que usa el resto de la app
   ------------------------------------------------------------ */

// Las funciones de arriba trabajan sobre `waOffline`; este bloque las deja
// accesibles como métodos para que app.js, core.js y el reproductor puedan
// llamarlas a través del mismo objeto.
Object.assign(waOffline, {
  init: offlineInit,
  reset: offlineReset,
  summary: offlineSummary,
  has: offlineHas,
  hasDownloads: offlineHasDownloads,
  coverURL: offlineCoverURL,
  playbackURL: offlinePlaybackURL,
  readLibrary: offlineReadLibrary,
  saveLibrary: offlineSaveLibrary,
  libraryFromDownloads: offlineLibraryFromDownloads,
  downloadTrack: offlineDownloadTrack,
  saveUploadedTrack: offlineSaveUploadedTrack,
  removeTrack: offlineRemoveTrack
});
