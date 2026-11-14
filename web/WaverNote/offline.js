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

const offlineLibraryKey = (userId) => `library:${Number(userId) || 0}`;
const offlineDownloadsKey = (userId) => `downloads:${Number(userId) || 0}`;
const offlineAudioKey = (userId, trackId) =>
  `${Number(userId) || 0}:${Number(trackId) || 0}`;

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
    const saved = await offlineGet(WA_OFFLINE_META_STORE, offlineDownloadsKey(id));
    const list = Array.isArray(saved) ? saved : [];
    list.forEach((entry) => {
      const trackId = Number(entry?.id);
      if (!trackId) return;
      waOffline.downloads.set(trackId, entry);
      if (entry.cover) waOffline.coverUrls.set(trackId, entry.cover);
    });
  } catch (err) {
    /* almacenamiento no disponible: seguimos solo online */
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
    if (!record?.blob) return "";
    const url = URL.createObjectURL(record.blob);
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

const offlineFetchCover = async (url) => {
  if (!url) return "";
  try {
    const response = await fetch(url, { mode: "cors" });
    if (!response.ok) return "";
    const blob = await response.blob();
    if (!blob.size || blob.size > WA_OFFLINE_COVER_MAX_BYTES) return "";
    return await offlineBlobToDataURL(blob);
  } catch (err) {
    return "";
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
      reject(new Error(`No se pudo descargar la canción (${request.status || "sin respuesta"}).`));
    };

    request.onerror = () =>
      reject(new Error("No se pudo descargar la canción. Revisá tu conexión."));
    request.ontimeout = () => reject(new Error("La descarga tardó demasiado. Probá de nuevo."));
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

const offlineSaveDownloads = async () => {
  try {
    await offlinePut(
      WA_OFFLINE_META_STORE,
      offlineDownloadsKey(waOffline.userId),
      Array.from(waOffline.downloads.values())
    );
  } catch (err) {
    /* la descarga ya está en audio; se recompone al volver a abrir */
  }
};

const offlineDownloadTrack = async (track, onProgress) => {
  const trackId = Number(track?.id);
  const userId = waOffline.userId;

  if (!trackId || !userId) throw new Error("Iniciá sesión para guardar canciones.");
  if (waOffline.downloads.has(trackId)) {
    return { already: true, size: Number(waOffline.downloads.get(trackId)?.size) || 0 };
  }
  if (!track.audioUrl) throw new Error("Esta canción no tiene un archivo descargable.");
  if (navigator.onLine === false) {
    throw new Error("Sin conexión: no se puede descargar ahora.");
  }
  if (!offlineSupported()) {
    throw new Error("Este dispositivo no permite guardar descargas.");
  }

  await offlineAskPersistence();

  const blob = await offlineFetchBlob(track.audioUrl, onProgress);
  if (!blob.size) throw new Error("La canción llegó vacía. Probá de nuevo.");

  const limit = await offlineStorageLimit();
  let usage = 0;
  try {
    const estimate = await navigator.storage?.estimate?.();
    usage = Number(estimate?.usage) || 0;
  } catch (err) {
    usage = 0;
  }

  if (usage + blob.size > limit) {
    throw new Error(
      "No hay espacio suficiente para esta descarga. Quitá algunas canciones guardadas y probá de nuevo."
    );
  }

  const cover = await offlineFetchCover(track.coverUrl);
  const entry = {
    id: trackId,
    size: blob.size,
    savedAt: Date.now(),
    title: track.title || "",
    artist: track.artist || "",
    album: track.album || "",
    genre: track.genre || "",
    duration: Number(track.duration) || 0,
    cover
  };

  await offlinePut(WA_OFFLINE_AUDIO_STORE, offlineAudioKey(userId, trackId), {
    blob,
    size: blob.size,
    savedAt: entry.savedAt,
    mime: blob.type || ""
  });

  waOffline.downloads.set(trackId, entry);
  if (cover) waOffline.coverUrls.set(trackId, cover);
  await offlineSaveDownloads();

  return { already: false, size: blob.size };
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

  await offlineSaveDownloads();
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
  removeTrack: offlineRemoveTrack
});
