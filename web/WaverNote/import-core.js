/* ------------------------------------------------------------
   Importación de listas (Spotify, Apple Music, CSV/JSON genérico)

   Este archivo solo hace parsing y normalización: no toca el DOM.
   Así se puede probar con Node (tests/import-core.test.cjs) y la UI
   (import.js) queda fina.

   Formatos aceptados:
   - CSV de Exportify (Track Name, Artist Name(s), Album Name, ...).
   - CSV/TSV genérico con encabezados conocidos.
   - JSON de la API de Spotify (items[].track con artists[]).
   - JSON del export de playlists de Spotify (playlists[].items[].track).
   - JSON propio: [{ title, artist, album, duration, coverUrl, isrc }].
   ------------------------------------------------------------ */

(function (root) {
  "use strict";

  const MAX_DURATION = 6 * 60 * 60;
  const MAX_TITLE = 160;
  const MAX_ARTIST = 120;
  const MAX_ALBUM = 120;
  const MAX_ISRC = 32;
  const MAX_SOURCE = 60;
  const MAX_COVER = 500;

  const FIELD_ALIASES = {
    title: ["track name", "title", "titulo", "name", "song", "song name", "track", "cancion", "tema"],
    artist: [
      "artist name s",
      "artist name",
      "artist names",
      "artists",
      "artist",
      "artista",
      "artistas",
      "interpret"
    ],
    album: ["album name", "album", "álbum", "disco"],
    duration: [
      "duration ms",
      "duration",
      "duration_ms",
      "duration ms",
      "duracion",
      "duración",
      "length",
      "length ms",
      "time"
    ],
    isrc: ["isrc", "isrc code", "isrc code s"],
    cover: ["cover", "cover url", "image", "image url", "artwork", "album image", "album image url"],
    source: ["playlist", "playlist name", "source", "origen", "lista"],
    url: ["track uri", "uri", "url", "spotify url", "link"]
  };

  const stripBOM = (value) => String(value || "").replace(/^\uFEFF/, "");

  const stripDiacritics = (value) =>
    String(value || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "");

  const cleanText = (value, maxLength = 500) =>
    String(value == null ? "" : value)
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, maxLength);

  const normalizeHeader = (value) =>
    stripDiacritics(value).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

  const ALIAS_TO_FIELD = new Map();
  Object.entries(FIELD_ALIASES).forEach(([field, aliases]) => {
    aliases.forEach((alias) => {
      const key = normalizeHeader(alias);
      if (!ALIAS_TO_FIELD.has(key)) ALIAS_TO_FIELD.set(key, field);
    });
  });

  /* ------------------------------------------------------------
     Normalización y clave de coincidencia
     ------------------------------------------------------------ */

  const normalizeText = (value) =>
    stripDiacritics(value).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

  // Los créditos de artista varían mucho entre plataformas: "A, B",
  // "A/B", "A & B", "A feat. B"... Guardamos cada nombre por separado para
  // que dos canciones coincidan si comparten al menos un artista.
  const ARTIST_SEPARATORS =
    /\s*(?:,|&|\/|\\|;|\+|\||×|\bfeat\b\.?|\bft\b\.?|\bfeaturing\b|\bvs\b\.?)\s*/i;

  const artistTokens = (value) => {
    const tokens = new Set();
    String(value || "")
      .split(ARTIST_SEPARATORS)
      .forEach((part) => {
        const token = normalizeText(part);
        if (token) tokens.add(token);
      });
    return tokens;
  };

  const primaryArtist = (value) => String(value || "").split(ARTIST_SEPARATORS)[0].trim();

  // Etiquetas que no cambian la canción: slowed/sped up/nightcore/remaster,
  // etc. "(Live)", "(Acústico)", "(Remix)" e "(Instrumental)" sí son otra
  // versión y se conservan.
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

  const isVersionSegment = (segment) => {
    const words = normalizeText(segment).split(" ").filter(Boolean);
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

  // Quita "(Slowed + Reverb)", "[Official Audio]" y sufijos "- Sped Up"
  // solamente cuando el segmento entero es una etiqueta de versión.
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

  const matchKey = (title, artist) =>
    `${normalizeTitle(title)}|${normalizeText(primaryArtist(artist))}`;

  const createTitleIndex = () => new Map();

  const addToTitleIndex = (index, title, artist) => {
    const key = normalizeTitle(title);
    if (!key) return;
    const tokens = artistTokens(artist);
    const bucket = index.get(key);
    if (bucket) bucket.push(tokens);
    else index.set(key, [tokens]);
  };

  const buildTitleIndex = (items) => {
    const index = createTitleIndex();
    (Array.isArray(items) ? items : []).forEach((item) =>
      addToTitleIndex(index, item?.title, item?.artist)
    );
    return index;
  };

  const titleIndexHas = (index, title, artist) => {
    const bucket = index.get(normalizeTitle(title));
    if (!bucket || !bucket.length) return false;

    const tokens = artistTokens(artist);
    return bucket.some((other) => {
      if (!tokens.size || !other.size) return true;
      for (const token of tokens) {
        if (other.has(token)) return true;
      }
      return false;
    });
  };

  const sameSong = (a, b) => {
    if (normalizeTitle(a?.title) !== normalizeTitle(b?.title)) return false;
    const left = artistTokens(a?.artist);
    const right = artistTokens(b?.artist);
    if (!left.size || !right.size) return true;
    for (const token of left) {
      if (right.has(token)) return true;
    }
    return false;
  };

  /* ------------------------------------------------------------
     Valores
     ------------------------------------------------------------ */

  const parseDuration = (value, isMs = false) => {
    const raw = String(value == null ? "" : value).trim();
    if (!raw) return 0;

    const clock = raw.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
    if (clock) {
      const a = Number(clock[1]) || 0;
      const b = Number(clock[2]) || 0;
      const c = clock[3] === undefined ? null : Number(clock[3]) || 0;
      const seconds = c === null ? a * 60 + b : a * 3600 + b * 60 + c;
      return Math.min(Math.max(seconds, 0), MAX_DURATION);
    }

    const numeric = Number(raw.replace(/[^\d.,-]/g, "").replace(",", "."));
    if (!Number.isFinite(numeric) || numeric <= 0) return 0;
    const seconds = isMs || numeric > 10000 ? numeric / 1000 : numeric;
    return Math.min(Math.max(seconds, 0), MAX_DURATION);
  };

  const sanitizeCover = (value) => {
    const raw = cleanText(value, MAX_COVER);
    return /^https?:\/\//i.test(raw) ? raw : "";
  };

  const makeRow = (fields) => {
    const title = cleanText(fields.title, MAX_TITLE);
    if (!title) return null;

    const artist = cleanText(fields.artist, MAX_ARTIST);
    const album = cleanText(fields.album, MAX_ALBUM);
    const row = {
      title,
      artist,
      album,
      duration: parseDuration(fields.duration, Boolean(fields.durationIsMs)),
      coverUrl: sanitizeCover(fields.coverUrl),
      isrc: cleanText(fields.isrc, MAX_ISRC).toUpperCase(),
      source: cleanText(fields.source, MAX_SOURCE),
      sourceUrl: cleanText(fields.sourceUrl, MAX_COVER)
    };
    row.matchKey = matchKey(row.title, row.artist);
    return row;
  };

  /* ------------------------------------------------------------
     CSV
     ------------------------------------------------------------ */

  const detectDelimiter = (text) => {
    const firstLine = String(text || "").split(/\r?\n/).find((line) => line.trim()) || "";
    let best = ",";
    let bestCount = -1;

    [",", ";", "\t"].forEach((delimiter) => {
      let count = 0;
      let quoted = false;
      for (let i = 0; i < firstLine.length; i += 1) {
        const ch = firstLine[i];
        if (ch === '"') quoted = !quoted;
        else if (ch === delimiter && !quoted) count += 1;
      }
      if (count > bestCount) {
        best = delimiter;
        bestCount = count;
      }
    });

    return best;
  };

  const parseDelimited = (text, delimiter) => {
    const rows = [];
    let row = [];
    let cell = "";
    let quoted = false;

    for (let i = 0; i < text.length; i += 1) {
      const ch = text[i];
      if (quoted) {
        if (ch === '"') {
          if (text[i + 1] === '"') {
            cell += '"';
            i += 1;
          } else {
            quoted = false;
          }
        } else {
          cell += ch;
        }
      } else if (ch === '"') {
        quoted = true;
      } else if (ch === delimiter) {
        row.push(cell);
        cell = "";
      } else if (ch === "\n") {
        row.push(cell);
        rows.push(row);
        row = [];
        cell = "";
      } else if (ch !== "\r") {
        cell += ch;
      }
    }

    if (cell.length || row.length) {
      row.push(cell);
      rows.push(row);
    }

    return rows.filter((cells) => cells.some((value) => String(value).trim() !== ""));
  };

  const parseCSV = (text, options = {}) => {
    const delimiter = detectDelimiter(text);
    const matrix = parseDelimited(text, delimiter);
    if (!matrix.length) throw new Error("El archivo no tiene filas.");

    const headers = matrix[0].map(normalizeHeader);
    const fields = headers.map((header) => ALIAS_TO_FIELD.get(header) || "");
    if (!fields.includes("title")) {
      throw new Error(
        "No encontramos una columna de título. Se esperan encabezados como “Track Name” o “Title”."
      );
    }

    const durationIsMs = headers.some(
      (header, index) => fields[index] === "duration" && /(^| )ms($| )|millisecond/.test(header)
    );

    const rows = [];
    for (let i = 1; i < matrix.length; i += 1) {
      const cells = matrix[i];
      const values = {};
      fields.forEach((field, index) => {
        if (!field) return;
        if (values[field] === undefined) values[field] = cells[index];
      });

      const row = makeRow({
        title: values.title,
        artist: values.artist,
        album: values.album,
        duration: values.duration,
        durationIsMs,
        coverUrl: values.cover,
        isrc: values.isrc,
        source: values.source || options.source,
        sourceUrl: values.url
      });
      if (row) rows.push(row);
    }

    return rows;
  };

  /* ------------------------------------------------------------
     JSON
     ------------------------------------------------------------ */

  const pick = (object, key) => (object && typeof object === "object" ? object[key] : undefined);

  const firstString = (...values) => {
    for (const value of values) {
      if (typeof value === "string" && value.trim()) return value;
    }
    return "";
  };

  const artistNames = (value) => {
    if (Array.isArray(value)) {
      return value
        .map((item) => (typeof item === "string" ? item : firstString(pick(item, "name"))))
        .filter(Boolean)
        .join(", ");
    }
    if (typeof value === "string") return value;
    return firstString(pick(value, "name"));
  };

  const coverFromAlbum = (album) => {
    if (!album || typeof album !== "object") return "";
    if (Array.isArray(album.images) && album.images.length) {
      return firstString(pick(album.images[0], "url"));
    }
    return firstString(pick(album, "coverUrl"), pick(album, "image"));
  };

  const rowFromObject = (node, context = {}) => {
    if (!node || typeof node !== "object" || Array.isArray(node)) return null;

    // Objeto tipo API de Spotify: name + artists[] + album{}.
    if (typeof node.name === "string" && (Array.isArray(node.artists) || node.album)) {
      const album = node.album && typeof node.album === "object" ? node.album : null;
      const externalIds = node.external_ids && typeof node.external_ids === "object" ? node.external_ids : null;
      return makeRow({
        title: node.name,
        artist: artistNames(node.artists),
        album: album ? firstString(album.name) : firstString(node.albumName),
        duration: node.duration_ms !== undefined ? node.duration_ms : node.duration,
        durationIsMs: node.duration_ms !== undefined,
        coverUrl: coverFromAlbum(album) || firstString(node.coverUrl, node.image),
        isrc: firstString(pick(externalIds, "isrc"), node.isrc),
        source: context.source || firstString(node.source, node.playlist),
        sourceUrl: firstString(pick(node.external_urls, "spotify"), node.uri, node.url)
      });
    }

    // Export de playlists de Spotify: trackName / artistName / albumName.
    if (typeof node.trackName === "string" || typeof node.track_name === "string") {
      return makeRow({
        title: firstString(node.trackName, node.track_name),
        artist: firstString(node.artistName, node.artist_name, artistNames(node.artists)),
        album: firstString(node.albumName, node.album_name),
        duration: node.durationMs !== undefined ? node.durationMs : node.duration,
        durationIsMs: node.durationMs !== undefined,
        coverUrl: firstString(node.coverUrl, node.image, node.cover),
        isrc: firstString(node.isrc),
        source: context.source || firstString(node.playlist, node.source),
        sourceUrl: firstString(node.trackUri, node.track_uri, node.uri)
      });
    }

    // JSON genérico con claves conocidas.
    const title = firstString(
      node.title,
      node.track,
      node.song,
      typeof node.name === "string" ? node.name : ""
    );
    const artist = firstString(
      node.artist,
      node.artists,
      node.artistName,
      node.artist_name,
      artistNames(node.artists)
    );
    if (!title || !artist) return null;

    return makeRow({
      title,
      artist,
      album: firstString(node.album, node.albumName, node.album_name),
      duration: node.duration_ms !== undefined ? node.duration_ms : node.duration,
      durationIsMs: node.duration_ms !== undefined,
      coverUrl: firstString(node.coverUrl, node.cover, node.image, node.artwork),
      isrc: firstString(node.isrc, pick(node.external_ids, "isrc")),
      source: context.source || firstString(node.playlist, node.source),
      sourceUrl: firstString(node.uri, node.url, pick(node.external_urls, "spotify"))
    });
  };

  const CONTAINER_KEYS = ["items", "tracks", "songs", "data", "library", "savedTracks", "saved_tracks"];

  const walkJSON = (node, context, out, depth = 0) => {
    if (!node || depth > 14) return;

    if (Array.isArray(node)) {
      node.forEach((item) => walkJSON(item, context, out, depth + 1));
      return;
    }
    if (typeof node !== "object") return;

    // Export de playlists: cada playlist aporta su nombre como origen.
    if (Array.isArray(node.playlists)) {
      node.playlists.forEach((playlist) => {
        const name = firstString(pick(playlist, "name"));
        walkJSON(playlist, name ? { ...context, source: name } : context, out, depth + 1);
      });
      return;
    }

    if (node.track && typeof node.track === "object") {
      walkJSON(node.track, context, out, depth + 1);
      return;
    }

    const row = rowFromObject(node, context);
    if (row) {
      out.push(row);
      return;
    }

    CONTAINER_KEYS.forEach((key) => {
      if (Array.isArray(node[key])) walkJSON(node[key], context, out, depth + 1);
    });
  };

  const parseJSON = (text, options = {}) => {
    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      throw new Error("El JSON no es válido.");
    }

    const rows = [];
    walkJSON(data, { source: options.source || "" }, rows);
    return rows;
  };

  /* ------------------------------------------------------------
     Entrada principal + vista previa
     ------------------------------------------------------------ */

  const parseImportText = (text, options = {}) => {
    const raw = stripBOM(String(text || "")).trim();
    if (!raw) throw new Error("Pegá el contenido del archivo o elegí uno.");

    const source = cleanText(options.source, MAX_SOURCE);
    const looksJSON = raw.startsWith("{") || raw.startsWith("[");
    const rows = looksJSON
      ? parseJSON(raw, { source })
      : parseCSV(raw, { source: source || "" });

    if (!rows.length) {
      throw new Error("No encontramos canciones con título en ese archivo.");
    }

    return {
      format: looksJSON ? "json" : "csv",
      rows,
      total: rows.length
    };
  };

  /**
   * Marca cada fila como:
   * - "new": no está en la biblioteca, ni pendiente, ni repetida en el archivo.
   * - "library": ya hay una canción con la misma clave.
   * - "pending": ya está en la lista de pendientes.
   * - "duplicate": aparece más de una vez en el archivo.
   */
  const buildPreview = (rows, tracks, pending = []) => {
    const list = Array.isArray(rows) ? rows : [];
    const libraryIndex = buildTitleIndex(tracks);
    const pendingIndex = buildTitleIndex(pending);
    const seen = new Set();
    const seenIndex = createTitleIndex();
    let fresh = 0;
    let inLibrary = 0;
    let alreadyPending = 0;
    let duplicates = 0;

    const annotated = list.map((row) => {
      const key = row.matchKey || matchKey(row.title, row.artist);
      let status = "new";

      if (seen.has(key) || titleIndexHas(seenIndex, row.title, row.artist)) {
        status = "duplicate";
        duplicates += 1;
      } else if (titleIndexHas(libraryIndex, row.title, row.artist)) {
        status = "library";
        inLibrary += 1;
      } else if (titleIndexHas(pendingIndex, row.title, row.artist)) {
        status = "pending";
        alreadyPending += 1;
      } else {
        fresh += 1;
      }

      seen.add(key);
      addToTitleIndex(seenIndex, row.title, row.artist);
      return { ...row, matchKey: key, status };
    });

    return {
      rows: annotated,
      total: annotated.length,
      fresh,
      inLibrary,
      alreadyPending,
      duplicates
    };
  };

  root.WaverNoteImportCore = {
    parseImportText,
    parseCSV,
    parseJSON,
    buildPreview,
    matchKey,
    sameSong,
    artistTokens,
    normalizeTitle,
    normalizeText,
    primaryArtist,
    parseDuration,
    parseDelimited,
    detectDelimiter,
    normalizeHeader
  };
})(typeof window !== "undefined" ? window : globalThis);
