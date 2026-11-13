const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "import-core.js"), "utf8");
const sandbox = { console };
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const core = sandbox.WaverNoteImportCore;

const exportifyCSV = [
  "\uFEFFTrack URI,Track Name,Album Name,Artist Name(s),Release Date,Duration (ms),Popularity,Explicit,Added At",
  'spotify:track:1,"Song, With Comma",Album One,"Artist A, Artist B",2024-01-01,215000,50,false,2024-02-01',
  'spotify:track:2,"Say ""Hello""",Album Two,Artist C,2023-05-05,180500,40,false,2024-02-02'
].join("\r\n");

test("parsea CSV de Exportify con comas y comillas escapadas", () => {
  const result = core.parseImportText(exportifyCSV);
  assert.equal(result.format, "csv");
  assert.equal(result.rows.length, 2);

  const [first, second] = result.rows;
  assert.equal(first.title, "Song, With Comma");
  assert.equal(first.artist, "Artist A, Artist B");
  assert.equal(first.album, "Album One");
  assert.equal(first.duration, 215);
  assert.equal(first.sourceUrl, "spotify:track:1");

  assert.equal(second.title, 'Say "Hello"');
  assert.equal(second.duration, 180.5);
});

test("detecta punto y coma y encabezados en español", () => {
  const csv = ["Título;Artista;Álbum;Duración", "Otra canción;Solista;Disco;3:45"].join("\n");
  const result = core.parseImportText(csv);
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].title, "Otra canción");
  assert.equal(result.rows[0].duration, 225);
});

test("detecta tabulaciones", () => {
  const csv = ["title\tartist\talbum", "Uno\tDos\tTres"].join("\n");
  assert.equal(core.detectDelimiter(csv), "\t");
  assert.equal(core.parseImportText(csv).rows[0].artist, "Dos");
});

test("duración: ms, segundos y reloj", () => {
  assert.equal(core.parseDuration("215000", true), 215);
  assert.equal(core.parseDuration("215", false), 215);
  assert.equal(core.parseDuration("215000", false), 215);
  assert.equal(core.parseDuration("3:45"), 225);
  assert.equal(core.parseDuration("1:02:03"), 3723);
  assert.equal(core.parseDuration(""), 0);
});

test("JSON tipo API de Spotify", () => {
  const json = JSON.stringify({
    items: [
      {
        added_at: "2024-01-01T00:00:00Z",
        track: {
          name: "Canción API",
          duration_ms: 201000,
          external_ids: { isrc: "USABC1234567" },
          external_urls: { spotify: "https://open.spotify.com/track/x" },
          artists: [{ name: "Artista Uno" }, { name: "Artista Dos" }],
          album: {
            name: "Álbum API",
            images: [{ url: "https://i.scdn.co/image/abc" }]
          }
        }
      }
    ]
  });

  const result = core.parseImportText(json);
  assert.equal(result.format, "json");
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].title, "Canción API");
  assert.equal(result.rows[0].artist, "Artista Uno, Artista Dos");
  assert.equal(result.rows[0].album, "Álbum API");
  assert.equal(result.rows[0].duration, 201);
  assert.equal(result.rows[0].isrc, "USABC1234567");
  assert.equal(result.rows[0].coverUrl, "https://i.scdn.co/image/abc");
});

test("JSON del export de playlists usa el nombre de la playlist como origen", () => {
  const json = JSON.stringify({
    playlists: [
      {
        name: "Mis favoritas",
        items: [
          { track: { trackName: "Tema Uno", artistName: "Artista", albumName: "Disco", trackUri: "spotify:track:1" } },
          { track: { trackName: "Tema Dos", artistName: "Otro", albumName: "Disco 2" } }
        ]
      }
    ]
  });

  const result = core.parseImportText(json);
  assert.equal(result.rows.length, 2);
  assert.equal(result.rows[0].source, "Mis favoritas");
  assert.equal(result.rows[1].title, "Tema Dos");
});

test("JSON genérico con arreglo simple", () => {
  const json = JSON.stringify([
    { title: "Simple", artist: "Alguien", album: "Casa", duration: 199 },
    { title: "Sin artista" }
  ]);
  const result = core.parseImportText(json);
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].title, "Simple");
});

test("clave de coincidencia tolera acentos, feat. y remaster", () => {
  assert.equal(
    core.matchKey("Canción (feat. Otro)", "Artista Principal"),
    core.matchKey("Cancion", "Artista Principal & Invitado")
  );
  assert.equal(
    core.matchKey("Tema - Remastered 2011", "Banda"),
    core.matchKey("Tema", "Banda")
  );
  assert.notEqual(core.matchKey("Tema (Live)", "Banda"), core.matchKey("Tema", "Banda"));
});

test("vista previa separa nuevas, ya en biblioteca, pendientes y repetidas", () => {
  const rows = [
    { title: "Nueva", artist: "A", matchKey: core.matchKey("Nueva", "A") },
    { title: "Existente", artist: "B", matchKey: core.matchKey("Existente", "B") },
    { title: "Nueva", artist: "A", matchKey: core.matchKey("Nueva", "A") },
    { title: "Pendiente", artist: "P", matchKey: core.matchKey("Pendiente", "P") },
    { title: "Otra", artist: "C", matchKey: core.matchKey("Otra", "C") }
  ];
  const preview = core.buildPreview(
    rows,
    [{ title: "Existente", artist: "B" }],
    [{ title: "Pendiente", artist: "P" }]
  );

  assert.equal(preview.total, 5);
  assert.equal(preview.fresh, 2);
  assert.equal(preview.inLibrary, 1);
  assert.equal(preview.alreadyPending, 1);
  assert.equal(preview.duplicates, 1);
  assert.deepEqual(
    preview.rows.map((row) => row.status),
    ["new", "library", "duplicate", "pending", "new"]
  );
});

test("rechaza archivos sin columna de título", () => {
  assert.throws(
    () => core.parseImportText("foo,bar\n1,2"),
    /columna de título/i
  );
  assert.throws(() => core.parseImportText("   "), /Pegá el contenido/i);
  assert.throws(() => core.parseImportText("{ roto"), /JSON no es válido/i);
});
