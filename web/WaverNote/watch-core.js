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

  // Créditos de producción: van entre paréntesis o después de un guion,
  // pero no forman parte del título de la canción.
  const PRODUCTION_CREDIT =
    /^(?:prod(?:uced|ucer)?(?:\s+by)?|beat(?:s)?\s+by|mixed\s+by|mastered\s+by)\b/i;

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
    "artists",
    "favoritas",
    "favoritos",
    "favorites",
    "favourites",
    "playlist",
    "playlists",
    "mi lista",
    "mis listas",
    "lista",
    "listas",
    "recientes",
    "recent",
    "nuevos",
    "nuevas",
    "new",
    "todos",
    "todas",
    "all",
    "sin clasificar",
    "unsorted",
    "varios",
    "varias",
    "various",
    "otros",
    "otras",
    "misc",
    "mixes",
    "seleccion",
    "selecciones",
    "recomendadas",
    "recomendados",
    "top",
    "hits",
    "exitos"
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
      // \p{L} conserva letras de cualquier alfabeto (cirílico, griego,
      // japonés…), no solo las latinas. Antes un título como «Нада Кведо»
      // quedaba vacío y nunca podía coincidir.
      .replace(/[^\p{L}\p{N}]+/gu, " ")
      .trim();

  const isDiscFolder = (value) => {
    const key = normalizeText(value);
    return /^(?:cd|disc|disk|vol|volume)\s*\d{0,3}$/.test(key);
  };

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
      isVersionSegment(inner) || PRODUCTION_CREDIT.test(String(inner).trim()) ? " " : match
    );

    // «Canción prod. Artista» sin paréntesis: el crédito se descarta.
    output = output.replace(/\s+(?:prod\.?|produced\s+by|beat\s+by)\s+.*$/i, " ");

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
        .replace(/\s*[-\u2013\u2014]\s*(?:feat\.?|ft\.?|featuring)\s+.*$/g, " ")
    )
      .replace(/[^\p{L}\p{N}]+/gu, " ")
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
    if (!key) return true;
    if (GENERIC_FOLDERS.has(key)) return true;
    if (isDiscFolder(value)) return true;
    // «Música 2025», «Favoritas 2024» y similares.
    const head = key.replace(/\s+\d{1,4}$/, "");
    return head !== key && GENERIC_FOLDERS.has(head);
  };

  const isPlausibleArtist = (value) => {
    const clean = stripTrackNumber(value);
    if (!clean || isGenericFolder(clean)) return false;
    // Un número de pista («01») o una carpeta vacía no son un artista.
    return /\p{L}/u.test(clean);
  };

  // "01 - Canción", "01. Canción", "01_ Canción" y "[01] Canción" son
  // números de pista, no parte del título. "99 Problems" no se toca porque
  // el número no está separado por guion, punto, paréntesis o corchete.
  const stripTrackNumber = (value) =>
    cleanSegment(value)
      .replace(/^\s*\[?\d{1,3}\]?\s*[-._–—)]\s*/, "")
      .replace(/^\s*\[\d{1,3}\]\s+/, "")
      .trim();

  const folderArtist = (value) => {
    const clean = stripTrackNumber(value);
    return isPlausibleArtist(clean) ? clean : "";
  };

  const pushCandidate = (list, seen, candidate) => {
    const title = stripTrackNumber(candidate.title);
    if (!title || isGenericFolder(title)) return;

    const artist = folderArtist(candidate.artist);
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
   *   Canción - Artista.mp3
   *   Lista/Artista - Canción.mp3
   *   Artista/Álbum/CD1/01 - canción.mp3
   *   Música/canción.mp3
   */
  const candidatesForFile = (file, metadata = null) => {
    const relative = String(file?.relative || file?.name || "");
    const segments = relative
      .split("/")
      .map((segment) => cleanSegment(segment))
      .filter(Boolean);

    const name = stripTrackNumber(cleanSegment(fileStem(file?.name || relative)));

    // Carpetas desde la más cercana al archivo hasta la raíz. Así una
    // estructura Artista/Álbum/CD1/01 - Canción reconoce al artista aunque
    // haya dos niveles de álbum y disco en el medio.
    const folders = segments
      .slice(0, -1)
      .reverse()
      .map((segment) => cleanSegment(segment))
      .filter(Boolean);
    const fallbackFolders = [file?.parent, file?.grandparent]
      .map((value) => cleanSegment(value))
      .filter(Boolean);
    const ancestors = (folders.length ? folders : fallbackFolders).slice(0, 4);

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

    // "Artista - Canción" o "Canción - Artista". Se aceptan guion común,
    // en dash y em dash, que son los que suelen traer los archivos.
    const split = name.match(/^(.{1,90}?)\s+[-–—]\s+(.{1,150})$/);
    if (split) {
      add(split[2], split[1], 16, "filename-split");
      add(split[1], split[2], 12, "filename-reverse");
    }

    // Artista/Canción/canción.mp3: la carpeta es el título y la de arriba
    // el artista. También funciona si eligieron la carpeta del artista.
    const nearest = ancestors[0] || "";
    if (nearest && !isGenericFolder(nearest)) {
      add(nearest, ancestors[1] || "", 14, "parent-title");
      add(nearest, "", 8, "parent-title-no-artist");
    }

    // Cada carpeta de la ruta puede ser el artista. La carpeta inmediata
    // pesa menos porque muchas veces es el álbum o el título; las de más
    // arriba pesan más y también sirven para vetar artistas equivocados.
    const artistWeights = [7, 13, 12, 11];
    ancestors.forEach((folder, index) => {
      if (!isPlausibleArtist(folder)) return;
      add(name, folder, artistWeights[index] || 10, `ancestor-artist-${index}`);
    });

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

    // Cada candidato que declara un artista afirma que ese artista interpreta
    // ese título. Al comparar un pendiente concreto solo cuentan las
    // afirmaciones sobre *su* título: así «Canción - Otro Artista.mp3» no se
    // acepta solo porque una carpeta más arriba diga el artista correcto,
    // mientras que un título con guion interno («Canción - Parte 2») sigue
    // coincidiendo completo. Si ninguna pista declara artista, se acepta el
    // nombre del archivo (y las filas con el mismo título quedan ambiguas).
    const artistClaims = new Map();
    candidates.forEach((candidate) => {
      // La carpeta inmediata (peso 7) suele ser el álbum o el título, no el
      // artista: suma para puntuar, pero no alcanza para vetar. Los nombres
      // con guion, las etiquetas y las carpetas de más arriba sí deciden.
      if (Number(candidate.weight) < 10) return;
      // «Nada Quedo - Slowed» genera un candidato con «Slowed» como artista.
      // Un sufijo de versión no es un artista y no debe vetar la carpeta que
      // sí lo declara.
      if (isVersionSegment(candidate.artist)) return;
      const tokens = artistTokens(candidate.artist);
      if (!tokens.size) return;
      const key = normalizeTitle(candidate.title);
      if (!key) return;
      const claim = artistClaims.get(key);
      if (claim) tokens.forEach((token) => claim.add(token));
      else artistClaims.set(key, tokens);
    });

    const matches = [];

    for (const candidate of candidates) {
      const titleKey = normalizeTitle(candidate.title);
      if (!titleKey) continue;
      const bucket = index.byTitle.get(titleKey);
      if (!bucket || !bucket.length) continue;

      for (const entry of bucket) {
        if (entry.artistTokens.size) {
          const claim = artistClaims.get(entry.titleKey);
          if (claim?.size && !artistsOverlap(entry.artistTokens, claim)) continue;
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
