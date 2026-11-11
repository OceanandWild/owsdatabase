/* ============================================================
   WaverNote · metadatos de audio
   Lee etiquetas y portadas embebidas de los archivos locales
   sin librerías externas: MP3 (ID3v1/ID3v2), FLAC, M4A/MP4,
   OGG/OPUS y WAV (RIFF INFO + ID3).
   ============================================================ */

const WNMetadata = (() => {
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

  const SUPPORTED_COVER_MIME = new Set(["image/jpeg", "image/png", "image/webp"]);

  const decoderUtf8 = new TextDecoder("utf-8");
  const decoderLatin1 = new TextDecoder("windows-1252");
  const decoderUtf16le = new TextDecoder("utf-16le");
  let decoderUtf16be = null;
  try {
    decoderUtf16be = new TextDecoder("utf-16be");
  } catch (err) {
    decoderUtf16be = null;
  }

  const ID3_GENRES = (
    "Blues|Classic Rock|Country|Dance|Disco|Funk|Grunge|Hip-Hop|Jazz|Metal|New Age|Oldies|Other|Pop|R&B|Rap|Reggae|Rock|Techno|Industrial|Alternative|Ska|Death Metal|Pranks|Soundtrack|Euro-Techno|Ambient|Trip-Hop|Vocal|Jazz+Funk|Fusion|Trance|Classical|Instrumental|Acid|House|Game|Sound Clip|Gospel|Noise|AlternRock|Bass|Soul|Punk|Space|Meditative|Instrumental Pop|Instrumental Rock|Ethnic|Gothic|Darkwave|Techno-Industrial|Electronic|Pop-Folk|Eurodance|Dream|Southern Rock|Comedy|Cult|Gangsta|Top 40|Christian Rap|Pop/Funk|Jungle|Native American|Cabaret|New Wave|Psychadelic|Rave|Showtunes|Trailer|Lo-Fi|Tribal|Acid Punk|Acid Jazz|Polka|Retro|Musical|Rock & Roll|Hard Rock|Folk|Folk-Rock|National Folk|Swing|Fast Fusion|Bebob|Latin|Revival|Celtic|Bluegrass|Avantgarde|Gothic Rock|Progressive Rock|Psychedelic Rock|Symphonic Rock|Slow Rock|Big Band|Chorus|Easy Listening|Acoustic|Humour|Speech|Chanson|Opera|Chamber Music|Sonata|Symphony|Booty Bass|Primus|Porn Groove|Satire|Slow Jam|Club|Tango|Samba|Folklore|Ballad|Power Ballad|Rhythmic Soul|Freestyle|Duet|Punk Rock|Drum Solo|A Capella|Euro-House|Dance Hall"
  ).split("|");

  /* ------------------------------------------------------------
     Lectura de bytes
     ------------------------------------------------------------ */

  const u16 = (bytes, offset) => (bytes[offset] << 8) | bytes[offset + 1];
  const u24 = (bytes, offset) => (bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2];
  const u32 = (bytes, offset) =>
    ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
  const u32le = (bytes, offset) =>
    (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
  const u64 = (bytes, offset) => u32(bytes, offset) * 2 ** 32 + u32(bytes, offset + 4);
  const syncSafe = (bytes, offset) =>
    ((bytes[offset] & 0x7f) << 21) |
    ((bytes[offset + 1] & 0x7f) << 14) |
    ((bytes[offset + 2] & 0x7f) << 7) |
    (bytes[offset + 3] & 0x7f);

  const ascii = (bytes, start, end) => {
    let text = "";
    const safeEnd = Math.min(end, bytes.length);
    for (let i = start; i < safeEnd; i += 1) text += String.fromCharCode(bytes[i]);
    return text;
  };

  const latin1 = (bytes, start = 0, end = bytes.length) =>
    decoderLatin1.decode(bytes.subarray(start, Math.min(end, bytes.length)));

  const utf8 = (bytes, start = 0, end = bytes.length) =>
    decoderUtf8.decode(bytes.subarray(start, Math.min(end, bytes.length)));

  const utf16le = (bytes) => decoderUtf16le.decode(bytes);
  const utf16be = (bytes) => {
    if (decoderUtf16be) return decoderUtf16be.decode(bytes);
    let text = "";
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      text += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return text;
  };

  const findByte = (bytes, target, start = 0, end = bytes.length) => {
    const safeEnd = Math.min(end, bytes.length);
    for (let i = Math.max(0, start); i < safeEnd; i += 1) {
      if (bytes[i] === target) return i;
    }
    return -1;
  };

  const indexOfBytes = (haystack, needle) => {
    if (!needle.length || haystack.length < needle.length) return -1;
    outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
      for (let j = 0; j < needle.length; j += 1) {
        if (haystack[i + j] !== needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  };

  const byteSequence = (text) => {
    const bytes = new Uint8Array(text.length);
    for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i) & 0xff;
    return bytes;
  };

  const extensionOf = (name) => {
    const clean = String(name || "").split(/[\\/]/).pop();
    const dot = clean.lastIndexOf(".");
    return dot > 0 ? clean.slice(dot + 1).toLowerCase() : "";
  };

  const isAudioFile = (file) => {
    const name = typeof file === "string" ? file : file?.name || "";
    const type = typeof file === "string" ? "" : file?.type || "";
    return AUDIO_EXTENSIONS.has(extensionOf(name)) || /^audio\//i.test(type);
  };

  const guessFromFilename = (originalName) => {
    const fileName = String(originalName || "").split(/[\\/]/).pop();
    const dot = fileName.lastIndexOf(".");
    const base = (dot > 0 ? fileName.slice(0, dot) : fileName)
      .replace(/_+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 180);

    if (!base) return { title: "Sin título", artist: "" };

    const split = base.match(/^(.{1,90}?)\s+-\s+(.{1,150})$/);
    if (split) return { artist: cleanValue(split[1]), title: cleanValue(split[2]) };
    return { title: cleanValue(base) || "Sin título", artist: "" };
  };

  const readSlice = async (file, start, end) => {
    const safeStart = Math.max(0, Math.min(file.size, start));
    const safeEnd = Math.max(safeStart, Math.min(file.size, end));
    if (safeEnd === safeStart) return new Uint8Array(0);
    return new Uint8Array(await file.slice(safeStart, safeEnd).arrayBuffer());
  };

  /* ------------------------------------------------------------
     Texto y valores
     ------------------------------------------------------------ */

  function cleanValue(value) {
    return String(value ?? "")
      .replace(/\u0000/g, " ")
      .replace(/[\u0001-\u001f\u007f]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  const decodeTextBytes = (bytes, encoding) => {
    if (!bytes.length) return "";
    if (encoding === 0) return latin1(bytes);
    if (encoding === 1) {
      if (bytes[0] === 0xff && bytes[1] === 0xfe) return utf16le(bytes.subarray(2));
      if (bytes[0] === 0xfe && bytes[1] === 0xff) return utf16be(bytes.subarray(2));
      return utf16le(bytes);
    }
    if (encoding === 2) return utf16be(bytes);
    return utf8(bytes);
  };

  const decodeTextFrame = (data) => {
    if (!data || data.length < 2) return "";
    const encoding = data[0];
    let text = decodeTextBytes(data.subarray(1), encoding);
    const nullIndex = text.indexOf("\u0000");
    if (nullIndex >= 0) text = text.slice(0, nullIndex);
    return cleanValue(text);
  };

  const findTextTerminator = (bytes, start, encoding) => {
    if (encoding === 0 || encoding === 3) return findByte(bytes, 0, start);
    for (let i = start; i + 1 < bytes.length; i += 2) {
      if (bytes[i] === 0 && bytes[i + 1] === 0) return i;
    }
    return -1;
  };

  const genreFromIndex = (value) => {
    const index = Number(value);
    if (!Number.isInteger(index) || index < 0 || index >= ID3_GENRES.length) return "";
    return ID3_GENRES[index];
  };

  const parseGenre = (raw) => {
    const value = cleanValue(raw);
    if (!value) return "";
    const parenthesis = value.match(/^\((\d{1,3})\)\s*(.*)$/);
    if (parenthesis) return cleanValue(parenthesis[2]) || genreFromIndex(parenthesis[1]);
    if (/^\d{1,3}$/.test(value)) return genreFromIndex(value);
    return value.replace(/^\(\d{1,3}\)/, "").trim();
  };

  const normalizeImageMime = (mime, bytes) => {
    if (bytes && bytes.length >= 4) {
      if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
      if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
      if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) {
        if (bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return "image/webp";
      }
      if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return "image/gif";
      if (bytes[0] === 0x42 && bytes[1] === 0x4d) return "image/bmp";
    }
    const declared = String(mime || "").toLowerCase().trim();
    if (!declared) return "image/jpeg";
    if (declared === "image/jpg") return "image/jpeg";
    return declared.startsWith("image/") ? declared : "image/jpeg";
  };

  const decodeBase64 = (value) => {
    try {
      const clean = String(value || "").replace(/\s+/g, "");
      if (!clean) return null;
      const binary = atob(clean);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch (err) {
      return null;
    }
  };

  /* ------------------------------------------------------------
     ID3v2 / ID3v1 (MP3)
     ------------------------------------------------------------ */

  const parseApicFrame = (data, version) => {
    if (!data || data.length < 8) return null;
    const encoding = data[0];
    let pos = 1;
    let mime = "image/jpeg";

    if (version === 2) {
      const format = ascii(data, pos, pos + 3).toUpperCase();
      pos += 3;
      mime = format === "PNG" ? "image/png" : "image/jpeg";
    } else {
      const mimeEnd = findByte(data, 0, pos);
      if (mimeEnd < 0) return null;
      mime = latin1(data, pos, mimeEnd);
      pos = mimeEnd + 1;
    }

    if (pos >= data.length) return null;
    const pictureType = data[pos];
    pos += 1;

    const descEnd = findTextTerminator(data, pos, encoding);
    if (descEnd < 0) return null;
    pos = descEnd + (encoding === 0 || encoding === 3 ? 1 : 2);

    const pictureData = data.subarray(pos);
    if (pictureData.length < 32) return null;

    return { mime: normalizeImageMime(mime, pictureData), picType: pictureType, data: pictureData };
  };

  const parseId3v2 = (bytes) => {
    if (bytes.length < 10 || ascii(bytes, 0, 3) !== "ID3") return null;

    const version = bytes[3];
    const flags = bytes[5];
    if (flags & 0x40 && version === 2) return null;

    const tagSize = syncSafe(bytes, 6);
    const bodyEnd = Math.min(bytes.length, 10 + tagSize);
    let pos = 10;

    if (flags & 0x40) {
      if (version >= 4) pos += Math.max(0, syncSafe(bytes, pos));
      else pos += 4 + u32(bytes, pos);
    }

    const tags = {};
    let picture = null;
    const headerSize = version === 2 ? 6 : 10;

    while (pos + headerSize <= bodyEnd) {
      const idLength = version === 2 ? 3 : 4;
      const id = ascii(bytes, pos, pos + idLength);
      if (!/^[A-Z0-9]{3,4}$/.test(id)) break;

      const size =
        version === 2
          ? u24(bytes, pos + 3)
          : version === 4
            ? syncSafe(bytes, pos + 4)
            : u32(bytes, pos + 4);

      const dataStart = pos + headerSize;
      const dataEnd = dataStart + size;
      if (size <= 0 || dataStart > bodyEnd) break;

      const frame = bytes.subarray(dataStart, Math.min(dataEnd, bodyEnd));

      if (id === "APIC" || id === "PIC") {
        const parsed = parseApicFrame(frame, version);
        if (parsed && (!picture || parsed.picType === 3 || picture.picType !== 3)) picture = parsed;
      } else {
        const key = {
          TIT2: "title",
          TT2: "title",
          TPE1: "artist",
          TP1: "artist",
          TPE2: "albumArtist",
          TP2: "albumArtist",
          TALB: "album",
          TAL: "album",
          TCON: "genre",
          TCO: "genre",
          TYER: "year",
          TYE: "year",
          TDRC: "year",
          TRCK: "track",
          TRK: "track"
        }[id];

        if (key && !tags[key]) tags[key] = decodeTextFrame(frame);
      }

      pos = dataEnd;
    }

    if (tags.genre) tags.genre = parseGenre(tags.genre);
    if (tags.artist && !tags.albumArtist) tags.albumArtist = "";
    return { tags, picture };
  };

  const parseId3v1 = (bytes) => {
    if (bytes.length < 128 || ascii(bytes, 0, 3) !== "TAG") return { tags: {}, picture: null };
    const pick = (start, length) =>
      cleanValue(latin1(bytes, start, start + length).replace(/\u0000/g, ""));

    const genreIndex = bytes[127];
    const tags = {
      title: pick(3, 30),
      artist: pick(33, 30),
      album: pick(63, 30),
      year: pick(93, 4),
      genre: genreFromIndex(genreIndex)
    };

    Object.keys(tags).forEach((key) => {
      if (!tags[key]) delete tags[key];
    });

    return { tags, picture: null };
  };

  const readMp3 = async (file) => {
    let result = { tags: {}, picture: null };

    const header = await readSlice(file, 0, Math.min(file.size, 10));
    if (header.length >= 10 && ascii(header, 0, 3) === "ID3") {
      const tagSize = syncSafe(header, 6);
      const footer = header[5] & 0x10 ? 10 : 0;
      const tagBytes = await readSlice(file, 0, Math.min(file.size, 10 + tagSize + footer));
      const parsed = parseId3v2(tagBytes);
      if (parsed) result = parsed;
    }

    if (!result.tags.title || !result.tags.artist || !result.tags.album) {
      if (file.size >= 128) {
        const tail = await readSlice(file, file.size - 128, file.size);
        const legacy = parseId3v1(tail);
        Object.keys(legacy.tags).forEach((key) => {
          if (!result.tags[key]) result.tags[key] = legacy.tags[key];
        });
      }
    }

    return result;
  };

  /* ------------------------------------------------------------
     FLAC + comentarios Vorbis
     ------------------------------------------------------------ */

  const parseFlacPicture = (data) => {
    if (!data || data.length < 32) return null;
    let pos = 0;

    const pictureType = u32(data, pos);
    pos += 4;

    const mimeLength = u32(data, pos);
    pos += 4;
    if (pos + mimeLength > data.length) return null;
    const mime = latin1(data, pos, pos + mimeLength);
    pos += mimeLength;

    const descriptionLength = u32(data, pos);
    pos += 4 + descriptionLength;
    if (pos + 16 + 4 > data.length) return null;

    pos += 16; // ancho, alto, profundidad y colores
    const dataLength = u32(data, pos);
    pos += 4;

    const pictureData = data.subarray(pos, Math.min(pos + dataLength, data.length));
    if (pictureData.length < 32) return null;

    return {
      mime: normalizeImageMime(mime, pictureData),
      picType: Number(pictureType) || 0,
      data: pictureData
    };
  };

  const parseVorbisComments = (data) => {
    const entries = {};
    if (!data || data.length < 8) return entries;

    let pos = 0;
    const vendorLength = u32le(data, pos);
    pos += 4 + vendorLength;
    if (pos + 4 > data.length) return entries;

    const count = u32le(data, pos);
    pos += 4;
    const safeCount = Math.min(count, 512);

    for (let i = 0; i < safeCount && pos + 4 <= data.length; i += 1) {
      const length = u32le(data, pos);
      pos += 4;
      if (length < 0 || pos + length > data.length) break;
      const entry = utf8(data, pos, pos + length);
      pos += length;

      const equals = entry.indexOf("=");
      if (equals <= 0) continue;
      const key = entry.slice(0, equals).toUpperCase().trim();
      const value = entry.slice(equals + 1);
      if (!entries[key]) entries[key] = value;
    }

    return entries;
  };

  const vorbisPicture = (comments) => {
    const raw = comments.METADATA_BLOCK_PICTURE;
    if (raw) {
      const bytes = decodeBase64(raw);
      const parsed = parseFlacPicture(bytes);
      if (parsed) return parsed;
    }

    if (comments.COVERART) {
      const bytes = decodeBase64(comments.COVERART);
      if (bytes && bytes.length > 32) {
        return {
          mime: normalizeImageMime(comments.COVERARTMIME, bytes),
          picType: 3,
          data: bytes
        };
      }
    }

    return null;
  };

  const tagsFromVorbis = (comments) => ({
    title: cleanValue(comments.TITLE),
    artist: cleanValue(comments.ARTIST || comments.ALBUMARTIST),
    album: cleanValue(comments.ALBUM),
    genre: cleanValue(comments.GENRE),
    year: cleanValue(comments.DATE || comments.YEAR)
  });

  const readFlac = async (file) => {
    const bytes = await readSlice(file, 0, Math.min(file.size, 16 * 1024 * 1024));
    let pos = 0;

    if (bytes.length >= 10 && ascii(bytes, 0, 3) === "ID3") {
      const size = syncSafe(bytes, 6);
      const footer = bytes[5] & 0x10 ? 10 : 0;
      pos = 10 + size + footer;
    }

    if (ascii(bytes, pos, pos + 4) !== "fLaC") return { tags: {}, picture: null };
    pos += 4;

    let tags = {};
    let picture = null;

    while (pos + 4 <= bytes.length) {
      const header = bytes[pos];
      const isLast = Boolean(header & 0x80);
      const type = header & 0x7f;
      const length = u24(bytes, pos + 1);
      const start = pos + 4;
      const end = start + length;
      if (end > bytes.length) break;

      if (type === 4) {
        const comments = parseVorbisComments(bytes.subarray(start, end));
        tags = tagsFromVorbis(comments);
        const cover = vorbisPicture(comments);
        if (cover) picture = cover;
      }

      if (type === 6 && !picture) {
        const parsed = parseFlacPicture(bytes.subarray(start, end));
        if (parsed) picture = parsed;
      }

      pos = end;
      if (isLast) break;
    }

    return { tags, picture };
  };

  /* ------------------------------------------------------------
     M4A / MP4 (átomos ilst)
     ------------------------------------------------------------ */

  const atomType = (bytes, offset) =>
    String.fromCharCode(bytes[offset] || 0, bytes[offset + 1] || 0, bytes[offset + 2] || 0, bytes[offset + 3] || 0);

  const forEachAtom = async (file, start, end, callback) => {
    let pos = start;
    while (pos + 8 <= end) {
      const header = await readSlice(file, pos, Math.min(pos + 16, end));
      if (header.length < 8) break;

      let size = u32(header, 0);
      const type = atomType(header, 4);
      let headerSize = 8;

      if (size === 1) {
        if (header.length < 16) break;
        size = u64(header, 8);
        headerSize = 16;
      } else if (size === 0) {
        size = end - pos;
      }

      if (size < headerSize || !Number.isFinite(size)) break;

      const atomEnd = Math.min(pos + size, end);
      await callback(type, pos + headerSize, atomEnd);
      pos = atomEnd;
    }
  };

  const readMp4 = async (file) => {
    let moov = null;
    await forEachAtom(file, 0, file.size, async (type, start, end) => {
      if (type === "moov") moov = { start, end };
    });
    if (!moov) return { tags: {}, picture: null };

    let ilst = null;

    const visitMeta = async (start, end) => {
      await forEachAtom(file, start + 4, end, async (type, childStart, childEnd) => {
        if (type === "ilst") ilst = { start: childStart, end: childEnd };
      });
    };

    await forEachAtom(file, moov.start, moov.end, async (type, start, end) => {
      if (type === "udta") {
        await forEachAtom(file, start, end, async (childType, childStart, childEnd) => {
          if (childType === "meta") await visitMeta(childStart, childEnd);
          if (childType === "ilst") ilst = { start: childStart, end: childEnd };
        });
      }
      if (type === "meta") await visitMeta(start, end);
      if (type === "ilst") ilst = { start, end };
    });

    if (!ilst) return { tags: {}, picture: null };

    const tags = {};
    let picture = null;

    await forEachAtom(file, ilst.start, ilst.end, async (type, start, end) => {
      await forEachAtom(file, start, end, async (dataType, dataStart, dataEnd) => {
        if (dataType !== "data" || dataEnd - dataStart < 8) return;

        const raw = await readSlice(file, dataStart, dataEnd);
        if (raw.length < 8) return;

        const typeCode = u32(raw, 0) & 0x00ffffff;
        const payload = raw.subarray(8);

        if (type === "\u00A9nam") tags.title = cleanValue(utf8(payload));
        else if (type === "\u00A9ART") tags.artist = cleanValue(utf8(payload));
        else if (type === "aART") tags.albumArtist = cleanValue(utf8(payload));
        else if (type === "\u00A9alb") tags.album = cleanValue(utf8(payload));
        else if (type === "\u00A9gen") tags.genre = cleanValue(utf8(payload));
        else if (type === "\u00A9day") tags.year = cleanValue(utf8(payload)).slice(0, 4);
        else if (type === "gnre" && payload.length >= 2) {
          const index = u16(payload, 0) - 1;
          tags.genre = genreFromIndex(index);
        } else if (type === "covr" && payload.length > 32 && !picture) {
          picture = {
            mime: typeCode === 14 ? "image/png" : normalizeImageMime("", payload),
            picType: 3,
            data: payload
          };
        }
      });
    });

    return { tags, picture };
  };

  /* ------------------------------------------------------------
     OGG / OPUS
     ------------------------------------------------------------ */

  const readOgg = async (file) => {
    const bytes = await readSlice(file, 0, Math.min(file.size, 12 * 1024 * 1024));
    let start = -1;

    const opusStart = indexOfBytes(bytes, byteSequence("OpusTags"));
    if (opusStart >= 0) start = opusStart + 8;

    if (start < 0) {
      const vorbisStart = indexOfBytes(bytes, byteSequence("\u0003vorbis"));
      if (vorbisStart >= 0) start = vorbisStart + 7;
    }

    if (start < 0) return { tags: {}, picture: null };

    const comments = parseVorbisComments(bytes.subarray(start));
    return { tags: tagsFromVorbis(comments), picture: vorbisPicture(comments) };
  };

  /* ------------------------------------------------------------
     WAV (RIFF INFO + chunk ID3)
     ------------------------------------------------------------ */

  const parseWavInfo = (bytes, start, end) => {
    const tags = {};
    const mapping = {
      INAM: "title",
      IART: "artist",
      IPRD: "album",
      IGNR: "genre",
      ICRD: "year"
    };

    let pos = start + 4;
    while (pos + 8 <= end) {
      const id = ascii(bytes, pos, pos + 4);
      const size = u32le(bytes, pos + 4);
      const valueStart = pos + 8;
      const valueEnd = Math.min(valueStart + size, end);
      const key = mapping[id];
      if (key) tags[key] = cleanValue(latin1(bytes, valueStart, valueEnd));
      pos = valueStart + size + (size % 2);
      if (size <= 0) break;
    }

    return tags;
  };

  const readWav = async (file) => {
    const bytes = await readSlice(file, 0, Math.min(file.size, 8 * 1024 * 1024));
    if (ascii(bytes, 0, 4) !== "RIFF" || ascii(bytes, 8, 12) !== "WAVE") {
      return { tags: {}, picture: null };
    }

    const tags = {};
    let picture = null;
    let pos = 12;

    while (pos + 8 <= bytes.length) {
      const id = ascii(bytes, pos, pos + 4);
      const size = u32le(bytes, pos + 4);
      const start = pos + 8;
      const end = Math.min(start + size, bytes.length);

      if (id === "LIST" && ascii(bytes, start, start + 4) === "INFO") {
        Object.assign(tags, parseWavInfo(bytes, start, end));
      } else if (id === "id3 " || id === "ID3 ") {
        const parsed = parseId3v2(bytes.subarray(start, end));
        if (parsed) {
          Object.assign(tags, parsed.tags);
          if (parsed.picture) picture = parsed.picture;
        }
      }

      pos = start + size + (size % 2);
      if (size <= 0) break;
    }

    if (tags.genre) tags.genre = parseGenre(tags.genre);
    return { tags, picture };
  };

  /* ------------------------------------------------------------
     Duración y portadas
     ------------------------------------------------------------ */

  const readDuration = (file) =>
    new Promise((resolve) => {
      let url = "";
      let settled = false;
      const audio = document.createElement("audio");

      const finish = (value) => {
        if (settled) return;
        settled = true;
        if (url) URL.revokeObjectURL(url);
        audio.removeAttribute("src");
        try {
          audio.load();
        } catch (err) {
          /* noop */
        }
        const duration = Number(value);
        resolve(Number.isFinite(duration) && duration > 0 ? Math.round(duration) : 0);
      };

      try {
        url = URL.createObjectURL(file);
      } catch (err) {
        resolve(0);
        return;
      }

      audio.preload = "metadata";
      audio.addEventListener("loadedmetadata", () => finish(audio.duration), { once: true });
      audio.addEventListener("error", () => finish(0), { once: true });
      window.setTimeout(() => finish(audio.duration || 0), 8000);
      audio.src = url;
    });

  const convertCoverToJpeg = (blob) =>
    new Promise((resolve) => {
      const url = URL.createObjectURL(blob);
      const image = new Image();

      const done = (value) => {
        URL.revokeObjectURL(url);
        resolve(value);
      };

      image.onload = () => {
        try {
          const max = 1200;
          const ratio = Math.min(1, max / Math.max(image.naturalWidth || 1, image.naturalHeight || 1));
          const canvas = document.createElement("canvas");
          canvas.width = Math.max(1, Math.round((image.naturalWidth || 1) * ratio));
          canvas.height = Math.max(1, Math.round((image.naturalHeight || 1) * ratio));
          const context = canvas.getContext("2d");
          context.fillStyle = "#0a101c";
          context.fillRect(0, 0, canvas.width, canvas.height);
          context.drawImage(image, 0, 0, canvas.width, canvas.height);
          canvas.toBlob((output) => done(output), "image/jpeg", 0.9);
        } catch (err) {
          done(null);
        }
      };

      image.onerror = () => done(null);
      image.src = url;
    });

  const coverExtension = (mime) => {
    if (mime === "image/png") return "png";
    if (mime === "image/webp") return "webp";
    return "jpg";
  };

  const safeCoverName = (baseName, extension) => {
    const base = String(baseName || "cover")
      .replace(/\.[^.]+$/, "")
      .slice(0, 60)
      .replace(/[^\w.-]+/g, "-")
      .replace(/^-+|-+$/g, "");
    return `${base || "cover"}.${extension}`;
  };

  const prepareCoverForUpload = async (blob, baseName) => {
    if (!blob || !blob.size) return null;
    const type = normalizeImageMime(blob.type);

    if (SUPPORTED_COVER_MIME.has(type) && blob.size <= 6 * 1024 * 1024) {
      return new File([blob], safeCoverName(baseName, coverExtension(type)), { type });
    }

    const converted = await convertCoverToJpeg(blob);
    if (!converted) {
      if (SUPPORTED_COVER_MIME.has(type)) {
        return new File([blob], safeCoverName(baseName, coverExtension(type)), { type });
      }
      return null;
    }

    return new File([converted], safeCoverName(baseName, "jpg"), { type: "image/jpeg" });
  };

  const fallbackMetadata = (file) => {
    const guessed = guessFromFilename(file?.name);
    return {
      title: guessed.title,
      artist: guessed.artist,
      album: "",
      genre: "",
      year: "",
      duration: 0,
      coverBlob: null,
      hasTags: false
    };
  };

  const readTrackMetadata = async (file) => {
    const extension = extensionOf(file.name);
    const mime = String(file.type || "").toLowerCase();
    let parsed = { tags: {}, picture: null };

    try {
      if (extension === "mp3" || mime.includes("mpeg")) {
        parsed = await readMp3(file);
      } else if (extension === "flac" || mime.includes("flac")) {
        parsed = await readFlac(file);
      } else if (["m4a", "mp4", "aac"].includes(extension) || mime.includes("mp4") || mime.includes("aac")) {
        parsed = await readMp4(file);
      } else if (["ogg", "oga", "opus"].includes(extension) || mime.includes("ogg") || mime.includes("opus")) {
        parsed = await readOgg(file);
      } else if (extension === "wav" || mime.includes("wav") || mime.includes("wave")) {
        parsed = await readWav(file);
      }
    } catch (err) {
      parsed = { tags: {}, picture: null };
    }

    const tags = parsed.tags || {};
    const guessed = guessFromFilename(file.name);
    const duration = await readDuration(file);

    let coverBlob = null;
    if (parsed.picture?.data?.length > 32) {
      try {
        coverBlob = new Blob([parsed.picture.data], { type: normalizeImageMime(parsed.picture.mime, parsed.picture.data) });
      } catch (err) {
        coverBlob = null;
      }
    }

    return {
      title: cleanValue(tags.title) || guessed.title,
      artist: cleanValue(tags.artist) || guessed.artist,
      album: cleanValue(tags.album),
      genre: cleanValue(tags.genre),
      year: cleanValue(tags.year),
      duration,
      coverBlob,
      hasTags: Boolean(cleanValue(tags.title) || cleanValue(tags.artist) || cleanValue(tags.album))
    };
  };

  return {
    isAudioFile,
    guessFromFilename,
    fallbackMetadata,
    readTrackMetadata,
    prepareCoverForUpload
  };
})();
