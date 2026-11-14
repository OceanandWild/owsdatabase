/* ------------------------------------------------------------
   WaverNote · carpeta vigilada (lógica pura)

   Este archivo no toca el DOM ni el puente nativo: solo normaliza
   nombres, arma candidatos a partir de la ruta y decide qué archivo
   corresponde a cada canción pendiente. Así se puede probar con Node
   (tests/watched-folder.test.cjs) y watched-folder.js queda para la UI,
   el puente con Windows/Android y las subidas.
   ------------------------------------------------------------ */

(function (root) {
  "use strict";

  const AUDIO_EXTENSIONS = new Set([
    "mp3",
    "wav",
    "ogg",
    "oga",
    "m4a",
    "mp4",
    "aac",
    "flac",
    "opus",
    "webm"
  ]);

  // Mismos sufijos que ya reconoce el backend al comparar canciones.
  const VERSION_WORDS = new Set([
    "slowed",
    "super",
    "ultra",
    "reverb",
    "sped",
    "speed",
    "up",
    "nightcore",
    "bass",
    "boost",
    "boosted",
    "8d",
    "extended",
    "mix",
    "version",
    "edit",
    "radio",
    "official",
    "audio",
    "video",
    "music",
    "lyric",
    "lyrics",
    "visualizer",
    "remaster",
    "remastered",
    "deluxe",
    "edition",
    "bonus",
    "track",
    "tiktok"
  ]);

  const VERSION_FILLER = new Set(["and", "y", "e", "with", "the", "plus"]);

  const ARTIST_SEPARATORS =
    /\s*(?:,|&|\/|\\|;|\+|\||×|\bfeat\b\.?|\bft\b\.?|\bfeaturing\b|\bvs\b\.?)\s*/i;

  // Carpetas que no aportan un artista ni un título. Se ignoran cuando
  // aparecen como nombre de carpeta, pero no cuando son el nombre del archivo.
  const GENERIC_FOLDERS = new Set([
    "music",
    "musica",
    "mi musica",
    "my music",
    "downloads",
    "descargas",
    "songs",
    "canciones",
    "audio",
    "albums",
    "albumes",
    "various artists",
    "varios artistas",
    "artistas",
    "artists"
  ]);

  const MATCH_THRESHOLD = 90;
  const AMBIGUITY_GAP = 15;

  const stripDiacritics = (value) =>
    String(value ?? "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "");

  const normalizeText = (value) =>
    stripDiacritics(value)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, " ")
      .trim();

  const isVersionSegment = (value) => {
    const words = normalizeText(value).split(" ").filter(Boolean);
    if (!words.length) return false;

    let hasTag = false;
    for (const word of words) {
      if (VERSION_WORDS.has(word)) {
        hasTag = true;
        continue;
      }
      if (VERSION_FILLER.has(word) || /^\d{4}$/.test(word)) continue;
      return false;
    }
    return hasTag;
  };

  const stripVersionSegments = (value) => {
    let output = value.replace(/\s*[\(\[]([^)\]]*)[\)\]]/g, (match, inner) =>
      isVersionSegment(inner) ? " " : match
    );

    for (let pass = 0; pass < 3; pass += 1) {
      const next = output.replace(/\s*[-–—]\s*([^-–—]+)$/, (match, tail) =>
        isVersionSegment(tail) ? " " : match
      );
      if (next === output) break;
      output = next;
    }

    return output;
  };

  const normalizeTitle = (value) =>
    stripVersionSegments(
      stripDiacritics(value)
        .toLowerCase()
        .replace(/\s*[\(\[]\s*(?:feat\.?|ft\.?|featuring)\s+[^)\]]*[\)\]]/g, " ")
        .replace(/\s*-\s*(?:feat\.?|ft\.?|featuring)\s+.*$/g, " ")
    )
      .replace(/[^a-z0-9]+/g, " ")
      .trim();

  const artistTokens = (value) => {
    const tokens = new Set();
    String(value ?? "")
      .split(ARTIST_SEPARATORS)
      .forEach((part) => {
        const token = normalizeText(part);
        if (token) tokens.add(token);
      });
    return tokens;
  };

  const artistsOverlap = (left, right) => {
    if (!left?.size || !right?.size) return false;
    for (const token of left) {
      if (right.has(token)) return true;
    }
    return false;
  };

  const fileExtension = (name) => {
    const clean = String(name || "").split(/[\\/]/).pop();
    const dot = clean.lastIndexOf(".");
    return dot > 0 ? clean.slice(dot + 1).toLowerCase() : "";
  };

  const isAudioName = (name) => AUDIO_EXTENSIONS.has(fileExtension(name));

  const fileStem = (name) => {
    const clean = String(name || "").split(/[\\/]/).pop();
    const dot = clean.lastIndexOf(".");
    return (dot > 0 ? clean.slice(0, dot) : clean).trim();
  };

  const cleanSegment = (value) =>
    String(value ?? "")
      .replace(/[\\/]+/g, " ")
      .replace(/_+/g, " ")
      .replace(/\s+/g, " ")
      .trim();

  const isGenericFolder = (value) => {
    const key = normalizeText(value);
    return !key || GENERIC_FOLDERS.has(key);
  };

  // "01 - Canción", "01. Canción", "01_ Canción" y "[01] Canción" son
  // números de pista, no parte del título. "99 Problems" no se toca porque
  // el número no está separado por guion, punto, paréntesis o corchete.
  const stripTrackNumber = (value) =>
    cleanSegment(value)
      .replace(/^\s*\[?\d{1,3}\]?\s*[-._)]\s*/, "")
      .replace(/^\s*\[\d{1,3}\]\s+/, "")
      .trim();

  const folderArtist = (value) => {
    const clean = stripTrackNumber(value);
    return isGenericFolder(clean) ? "" : clean;
  };

  const pushCandidate = (list, seen, candidate) => {
    const title = stripTrackNumber(candidate.title);
    if (!title || isGenericFolder(title)) return;

    const artist = cleanSegment(candidate.artist);
    const album = cleanSegment(candidate.album);
    const key = `${normalizeTitle(title)}|${normalizeText(artist)}|${normalizeText(album)}`;
    if (seen.has(key)) return;

    seen.add(key);
    list.push({
      title,
      artist,
      album,
      weight: Number(candidate.weight) || 0,
      source: String(candidate.source || "")
    });
  };

  /**
   * Candidatos "título + artista" que se pueden deducir de una ruta.
   * Cubre las organizaciones más comunes:
   *   Artista/Canción/canción.mp3
   *   Artista/Álbum/01 - canción.mp3
   *   Artista - Canción.mp3
   *   Lista/Artista - Canción.mp3
   *   Música/canción.mp3
   */
  const candidatesForFile = (file, metadata = null) => {
    const relative = String(file?.relative || file?.name || "");
    const segments = relative
      .split("/")
      .map((segment) => cleanSegment(segment))
      .filter(Boolean);

    const name = cleanSegment(fileStem(file?.name || relative));
    const parent = cleanSegment(file?.parent || segments[segments.length - 2] || "");
    const grandparent = cleanSegment(
      file?.grandparent || segments[segments.length - 3] || ""
    );
    const fileAlbum = cleanSegment(file?.album || "");
    const metadataAlbum = cleanSegment(metadata?.album || "");

    const list = [];
    const seen = new Set();
    const add = (title, artist, weight, source, album) =>
      pushCandidate(list, seen, {
        title,
        artist: folderArtist(artist),
        weight,
        source,
        album: album || fileAlbum
      });

    // Nombre del archivo solo. Sirve cuando la carpeta no aporta nada.
    add(name, "", 12, "filename");

    // "Artista - Canción" o "Canción - Artista".
    const split = name.match(/^(.{1,90}?)\s+-\s+(.{1,150})$/);
    if (split) {
      add(split[2], split[1], 16, "filename-split");
      add(split[1], split[2], 4, "filename-reverse");
    }

    // Artista/Canción/canción.mp3: la carpeta es el título y la de arriba
    // el artista. También funciona si eligieron la carpeta del artista.
    if (parent && !isGenericFolder(parent)) {
      add(parent, grandparent, 14, "parent-title");
      add(parent, "", 8, "parent-title-no-artist");
    }

    // Artista/Álbum/01 - canción.mp3: el nombre del archivo es el título y
    // la carpeta de arriba del álbum es el artista.
    if (grandparent && !isGenericFolder(grandparent)) {
      add(name, grandparent, 13, "grandparent-artist");
      add(parent, grandparent, 10, "grandparent-artist-parent");
    }

    // La carpeta inmediata como posible artista si el nombre no lo trae.
    if (parent && !isGenericFolder(parent)) {
      add(name, parent, 7, "filename-parent-artist");
    }

    // Etiquetas del archivo: pesan más que la ruta, pero no la reemplazan.
    if (metadata) {
      add(metadata.title, metadata.artist, 22, "tags", metadataAlbum);
      add(metadata.title, "", 10, "tags-title", metadataAlbum);
    }

    return list;
  };

  const buildPendingIndex = (pending) => {
    const items = (Array.isArray(pending) ? pending : [])
      .filter((item) => item && String(item.title || "").trim())
      .map((item) => ({
        item,
        id: Number(item.id) || 0,
        titleKey: normalizeTitle(item.title),
        artistTokens: artistTokens(item.artist),
        albumKey: normalizeText(item.album)
      }));

    const byTitle = new Map();
    items.forEach((entry) => {
      if (!entry.titleKey) return;
      const bucket = byTitle.get(entry.titleKey);
      if (bucket) bucket.push(entry);
      else byTitle.set(entry.titleKey, [entry]);
    });

    return { items, byTitle };
  };

  const scoreCandidate = (entry, candidate) => {
    const titleKey = normalizeTitle(candidate.title);
    if (!titleKey || titleKey !== entry.titleKey) return null;

    const candidateArtists = artistTokens(candidate.artist);
    let artistScore = 10;
    let artistPenalty = 0;

    if (entry.artistTokens.size && candidateArtists.size) {
      if (artistsOverlap(entry.artistTokens, candidateArtists)) artistScore = 45;
      else artistPenalty = 45;
    }

    let albumScore = 0;
    if (entry.albumKey) {
      const candidateAlbum = normalizeText(candidate.album);
      if (candidateAlbum && candidateAlbum === entry.albumKey) albumScore = 10;
      else if (
        candidateAlbum &&
        (candidateAlbum.includes(entry.albumKey) || entry.albumKey.includes(candidateAlbum))
      ) {
        albumScore = 5;
      }
    }

    return {
      score: 100 + artistScore + albumScore + (Number(candidate.weight) || 0) - artistPenalty,
      candidate,
      artistScore,
      albumScore
    };
  };

  const samePendingSong = (left, right) => {
    if (normalizeTitle(left?.title) !== normalizeTitle(right?.title)) return false;
    const a = artistTokens(left?.artist);
    const b = artistTokens(right?.artist);
    if (!a.size || !b.size) return true;
    return artistsOverlap(a, b);
  };

  /**
   * Devuelve la canción pendiente que corresponde a un archivo, o null.
   * Si dos pendientes distintos empatan (mismo título, artistas diferentes)
   * devuelve `ambiguous: true` para no subir el archivo equivocado.
   */
  const matchPendingForFile = (file, index, metadata = null) => {
    if (!index || !Array.isArray(index.items) || !index.items.length) return null;

    const candidates = candidatesForFile(file, metadata);
    // Una carpeta con artista claro (Artista/Canción/..., Artista - Canción,
    // etiquetas) manda sobre el nombre suelto. Si esa señal contradice al
    // pendiente, no se sube: evita completar "MONTAGEM ROYAL" con el archivo
    // de otro artista que se llama igual.
    const strongArtistCandidates = candidates.filter(
      (candidate) => candidate.weight >= 10 && artistTokens(candidate.artist).size > 0
    );
    const matches = [];

    for (const candidate of candidates) {
      const titleKey = normalizeTitle(candidate.title);
      if (!titleKey) continue;
      const bucket = index.byTitle.get(titleKey);
      if (!bucket || !bucket.length) continue;

      for (const entry of bucket) {
        if (entry.artistTokens.size && strongArtistCandidates.length) {
          const artistConfirmed = strongArtistCandidates.some((strong) =>
            artistsOverlap(entry.artistTokens, artistTokens(strong.artist))
          );
          if (!artistConfirmed) continue;
        }

        const result = scoreCandidate(entry, candidate);
        if (!result || result.score < MATCH_THRESHOLD) continue;
        matches.push({
          pending: entry.item,
          score: result.score,
          candidate,
          artistScore: result.artistScore,
          albumScore: result.albumScore
        });
      }
    }

    if (!matches.length) return null;

    matches.sort((a, b) => b.score - a.score);
    const top = matches[0];
    const second = matches[1];

    if (second && top.score - second.score < AMBIGUITY_GAP) {
      const sameSong = samePendingSong(top.pending, second.pending);
      if (!sameSong) {
        return {
          ambiguous: true,
          pending: null,
          score: top.score,
          alternatives: matches.slice(0, 3).map((match) => ({
            pending: match.pending,
            score: match.score
          }))
        };
      }
    }

    return {
      ambiguous: false,
      pending: top.pending,
      score: top.score,
      candidate: top.candidate,
      alternatives: matches.slice(0, 3).map((match) => ({
        pending: match.pending,
        score: match.score
      }))
    };
  };

  const describeFolder = (scan) => {
    const files = Array.isArray(scan?.files) ? scan.files : [];
    const depths = files.map(
      (file) => String(file?.relative || "").split("/").filter(Boolean).length - 1
    );
    const maxDepth = depths.length ? Math.max(...depths) : -1;
    const topFolders = new Set(
      files
        .map((file) => String(file?.relative || "").split("/").filter(Boolean)[0])
        .filter(Boolean)
    );

    const truncated = Boolean(scan?.truncated);
    const depthLimited = Boolean(scan?.depthLimited);

    let kind = "ok";
    if (!files.length) kind = "empty";
    else if (truncated) kind = "large";
    else if (depthLimited) kind = "too-deep";
    else if (files.length === 1 && maxDepth === 0) kind = "single-file";
    else if (topFolders.size === 1 && maxDepth >= 2) kind = "artist-tree";
    else if (maxDepth >= 2) kind = "deep-tree";

    return {
      kind,
      audioCount: files.length,
      maxDepth,
      topFolders: Array.from(topFolders).slice(0, 8),
      truncated,
      depthLimited
    };
  };

  const fileKeys = (file) => {
    const path = String(file?.path || file?.uri || file?.relative || file?.name || "");
    const size = Number(file?.size) || 0;
    const modified = Number(file?.modified) || 0;
    const name = normalizeText(fileStem(file?.name || file?.relative || ""));
    const content = modified > 0 ? `${size}|${modified}` : `${size}|${name}`;

    return {
      pathKey: `${path}|${size}|${modified}`,
      contentKey: content
    };
  };

  root.WaverNoteWatchCore = {
    artistTokens,
    artistsOverlap,
    buildPendingIndex,
    candidatesForFile,
    cleanSegment,
    describeFolder,
    fileKeys,
    fileStem,
    isAudioName,
    matchPendingForFile,
    normalizeText,
    normalizeTitle,
    samePendingSong,
    stripTrackNumber
  };
})(typeof window !== "undefined" ? window : globalThis);
