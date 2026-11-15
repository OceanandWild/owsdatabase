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

test("un sufijo de versión no se toma como artista al vetar", () => {
  const index = core.buildPendingIndex([pending(12, "Nada Quedo", "Eternxlkz")]);

  const slowed = core.matchPendingForFile(
    file("Nada Quedo - Slowed.mp3", "Eternxlkz/Nada Quedo - Slowed.mp3"),
    index
  );
  assert.ok(slowed);
  assert.equal(Number(slowed.pending.id), 12);

  const sped = core.matchPendingForFile(
    file("Nada Quedo - Sped Up.mp3", "Eternxlkz/Nada Quedo - Sped Up.mp3"),
    index
  );
  assert.ok(sped);
  assert.equal(Number(sped.pending.id), 12);

  const live = core.matchPendingForFile(
    file("Nada Quedo - Live.mp3", "Eternxlkz/Nada Quedo - Live.mp3"),
    index
  );
  assert.equal(live, null);
});

test("reconoce el número de pista cuando la carpeta es el artista", () => {
  const index = core.buildPendingIndex([pending(20, "Nada Quedo", "Eternxlkz")]);
  const match = core.matchPendingForFile(
    file("01 - Nada Quedo.mp3", "Eternxlkz/01 - Nada Quedo.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(match.ambiguous, false);
  assert.equal(Number(match.pending.id), 20);
});

test("reconoce Canción - Artista.mp3 con el orden invertido", () => {
  const index = core.buildPendingIndex([pending(21, "Nada Quedo", "Eternxlkz")]);
  const match = core.matchPendingForFile(
    file("Nada Quedo - Eternxlkz.mp3", "Nada Quedo - Eternxlkz.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(Number(match.pending.id), 21);
});

test("también reconoce la canción si eligen la carpeta del artista o del álbum", () => {
  const artistFolder = core.buildPendingIndex([pending(30, "MONTAGEM APARIÇÃO", "DJ AMI")]);
  const byArtist = core.matchPendingForFile(
    file("MONTAGEM APARIÇÃO.mp3", "MONTAGEM APARIÇÃO/MONTAGEM APARIÇÃO.mp3"),
    artistFolder
  );
  assert.ok(byArtist);
  assert.equal(Number(byArtist.pending.id), 30);

  const albumFolder = core.buildPendingIndex([pending(31, "Nada Quedo", "Eternxlkz")]);
  const byAlbum = core.matchPendingForFile(
    file("01 - Nada Quedo.mp3", "Arcade/01 - Nada Quedo.mp3"),
    albumFolder
  );
  assert.ok(byAlbum);
  assert.equal(Number(byAlbum.pending.id), 31);
});

test("busca el artista más arriba cuando hay álbum y carpeta de disco", () => {
  const index = core.buildPendingIndex([pending(22, "Nada Quedo", "Eternxlkz")]);
  const match = core.matchPendingForFile(
    file("01 - Nada Quedo.mp3", "Eternxlkz/Arcade/CD1/01 - Nada Quedo.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(Number(match.pending.id), 22);
});

test("acepta guiones largos, títulos en cirílico y créditos de producción", () => {
  const dash = core.buildPendingIndex([pending(23, "Nada Quedo", "Eternxlkz")]);
  assert.ok(
    core.matchPendingForFile(
      file("Eternxlkz – Nada Quedo.mp3", "Eternxlkz – Nada Quedo.mp3"),
      dash
    )
  );

  const cyrillic = core.buildPendingIndex([pending(24, "Нада Кведо", "Артист")]);
  const cyrillicMatch = core.matchPendingForFile(
    file("Нада Кведо.mp3", "Артист/Нада Кведо.mp3"),
    cyrillic
  );
  assert.ok(cyrillicMatch);
  assert.equal(Number(cyrillicMatch.pending.id), 24);

  const prod = core.buildPendingIndex([pending(25, "Nada Quedo", "Eternxlkz")]);
  const prodMatch = core.matchPendingForFile(
    file(
      "Nada Quedo (Prod. Eternxlkz).mp3",
      "Eternxlkz/Nada Quedo (Prod. Eternxlkz).mp3"
    ),
    prod
  );
  assert.ok(prodMatch);
  assert.equal(Number(prodMatch.pending.id), 25);
});

test("un título con guion interno coincide completo", () => {
  const index = core.buildPendingIndex([
    pending(26, "Nada Quedo - Parte 2", "Eternxlkz")
  ]);
  const match = core.matchPendingForFile(
    file("Nada Quedo - Parte 2.mp3", "Eternxlkz/Nada Quedo - Parte 2.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(Number(match.pending.id), 26);
});

test("no acepta un archivo que declara otro artista aunque la carpeta diga el correcto", () => {
  const index = core.buildPendingIndex([pending(27, "Nada Quedo", "Eternxlkz")]);
  const match = core.matchPendingForFile(
    file("Nada Quedo - Otro Artista.mp3", "Eternxlkz/Nada Quedo - Otro Artista.mp3"),
    index
  );

  assert.equal(match, null);
});

test("no confunde un número que forma parte del título con un número de pista", () => {
  const index = core.buildPendingIndex([pending(28, "99 Problems", "JAY-Z")]);
  const match = core.matchPendingForFile(
    file("99 Problems.mp3", "JAY-Z/99 Problems.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(Number(match.pending.id), 28);
});

test("un año o una carpeta genérica no se toma como artista", () => {
  const index = core.buildPendingIndex([pending(29, "Nada Quedo", "Eternxlkz")]);
  const match = core.matchPendingForFile(
    file("01 - Nada Quedo.mp3", "Música 2024/01 - Nada Quedo.mp3"),
    index
  );

  assert.ok(match);
  assert.equal(Number(match.pending.id), 29);
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
