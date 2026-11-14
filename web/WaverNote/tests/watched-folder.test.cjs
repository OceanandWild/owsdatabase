const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "watch-core.js"), "utf8");
const sandbox = { console };
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const core = sandbox.WaverNoteWatchCore;

const pending = (id, title, artist, album = "") => ({
  id,
  title,
  artist,
  album,
  duration: 0
});

const file = (name, relative, extra = {}) => {
  const segments = String(relative || name).split("/");
  return {
    name,
    relative: relative || name,
    parent: segments.length >= 2 ? segments[segments.length - 2] : "",
    grandparent: segments.length >= 3 ? segments[segments.length - 3] : "",
    size: 5 * 1024 * 1024,
    modified: 1_700_000_000_000,
    ...extra
  };
};

test("normaliza títulos igual que el backend e ignora sufijos de versión", () => {
  assert.equal(core.normalizeTitle("MONTAGEM APARIÇÃO - Slowed"), "montagem aparicao");
  assert.equal(core.normalizeTitle("MONTAGEM APARICAO (Super Slowed + Reverb)"), "montagem aparicao");
  assert.equal(core.normalizeTitle("Canción (feat. Otro)"), "cancion");
  assert.equal(core.normalizeTitle("Song - Live"), "song live");
  assert.equal(core.normalizeTitle("Song - Remix"), "song remix");
});

test("separa artistas con los mismos separadores que el backend", () => {
  const tokens = core.artistTokens("CHAXZER/DJ FKU & NUEKI feat. DJ AMI");
  assert.ok(tokens.has("chaxzer"));
  assert.ok(tokens.has("dj fku"));
  assert.ok(tokens.has("nueki"));
  assert.ok(tokens.has("dj ami"));
});

test("reconoce la estructura Artista/Canción/canción.mp3", () => {
  const index = core.buildPendingIndex([pending(26, "MONTAGEM APARIÇÃO", "DJ AMI")]);
  const match = core.matchPendingForFile(
    file("MONTAGEM APARIÇÃO.mp3", "DJ AMI/MONTAGEM APARIÇÃO/MONTAGEM APARIÇÃO.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(match.ambiguous, false);
  assert.equal(Number(match.pending.id), 26);
});

test("reconoce Artista/Álbum/01 - canción.mp3", () => {
  const index = core.buildPendingIndex([pending(7, "Nada Quedo", "Eternxlkz")]);
  const match = core.matchPendingForFile(
    file("01 - Nada Quedo.mp3", "Eternxlkz/Arcade/01 - Nada Quedo.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(match.ambiguous, false);
  assert.equal(Number(match.pending.id), 7);
});

test("reconoce Artista - Canción.mp3 suelto en una carpeta de lista", () => {
  const index = core.buildPendingIndex([pending(8, "MONTAGEM ECLIPSE - Slowed", "DJ FKU")]);
  const match = core.matchPendingForFile(
    file("DJ FKU - MONTAGEM ECLIPSE - Slowed.mp3", "Favoritas/DJ FKU - MONTAGEM ECLIPSE - Slowed.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(match.ambiguous, false);
  assert.equal(Number(match.pending.id), 8);
});

test("usa las etiquetas cuando el nombre del archivo no alcanza", () => {
  const index = core.buildPendingIndex([pending(9, "MONTAGEM ROYAL", "NUEKI")]);
  const match = core.matchPendingForFile(
    file("track01.mp3", "Descargas/track01.mp3"),
    index,
    { title: "MONTAGEM ROYAL", artist: "NUEKI", album: "MONTAGEM ROYAL" }
  );

  assert.ok(match);
  assert.equal(match.ambiguous, false);
  assert.equal(Number(match.pending.id), 9);
});

test("no completa una canción si el artista claramente es otro", () => {
  const index = core.buildPendingIndex([pending(10, "MONTAGEM ROYAL", "NUEKI")]);
  const match = core.matchPendingForFile(
    file("MONTAGEM ROYAL.mp3", "Otro Artista/MONTAGEM ROYAL/MONTAGEM ROYAL.mp3"),
    index
  );

  assert.equal(match, null);
});

test("no confunde una versión en vivo con el tema original", () => {
  const index = core.buildPendingIndex([pending(11, "MONTAGEM ROYAL", "NUEKI")]);
  const match = core.matchPendingForFile(
    file("MONTAGEM ROYAL - Live.mp3", "NUEKI/MONTAGEM ROYAL - Live/MONTAGEM ROYAL - Live.mp3"),
    index
  );

  assert.equal(match, null);
});

test("marca como ambigua una canción con el mismo título y artistas distintos", () => {
  const index = core.buildPendingIndex([
    pending(12, "MONTAGEM ROYAL", "NUEKI"),
    pending(13, "MONTAGEM ROYAL", "Otro Artista")
  ]);
  const match = core.matchPendingForFile(
    file("MONTAGEM ROYAL.mp3", "MONTAGEM ROYAL.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(match.ambiguous, true);
});

test("las filas repetidas de la misma canción no cuentan como ambigüedad", () => {
  const index = core.buildPendingIndex([
    pending(14, "MONTAGEM ROYAL", "NUEKI"),
    pending(15, "MONTAGEM ROYAL", "NUEKI/DJ FKU")
  ]);
  const match = core.matchPendingForFile(
    file("MONTAGEM ROYAL.mp3", "NUEKI/MONTAGEM ROYAL/MONTAGEM ROYAL.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(match.ambiguous, false);
});

test("la huella de contenido sobrevive a renombrar o mover el archivo", () => {
  const original = core.fileKeys(file("song.mp3", "Artista/song.mp3"));
  const renamed = core.fileKeys({
    ...file("song.mp3", "Artista/song.mp3"),
    name: "otro nombre.mp3",
    relative: "Otra carpeta/otro nombre.mp3"
  });

  assert.equal(original.contentKey, renamed.contentKey);
  assert.notEqual(original.pathKey, renamed.pathKey);
});

test("describe la carpeta para poder guiar al usuario", () => {
  const empty = core.describeFolder({ files: [] });
  assert.equal(empty.kind, "empty");

  const single = core.describeFolder({
    files: [file("song.mp3", "song.mp3")]
  });
  assert.equal(single.kind, "single-file");

  const artistTree = core.describeFolder({
    files: [
      file("song.mp3", "Artista/Cancion/song.mp3"),
      file("otra.mp3", "Artista/Otra Cancion/otra.mp3")
    ]
  });
  assert.equal(artistTree.kind, "artist-tree");

  const large = core.describeFolder({
    files: [file("song.mp3", "song.mp3")],
    truncated: true
  });
  assert.equal(large.kind, "large");
});

test("reconoce los formatos de audio que puede subir la app", () => {
  assert.equal(core.isAudioName("song.mp3"), true);
  assert.equal(core.isAudioName("SONG.FLAC"), true);
  assert.equal(core.isAudioName("portada.jpg"), false);
  assert.equal(core.isAudioName("notas.txt"), false);
});
