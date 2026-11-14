const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "..", "import-core.js"), "utf8");
const sandbox = { console, URL };
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

test("artistas con / & ; + y feat comparten tokens", () => {
  assert.equal(
    core.sameSong(
      { title: "MONTAGEM ASSOMBRADA", artist: "CHAXZER/DJ FKU" },
      { title: "MONTAGEM ASSOMBRADA", artist: "CHAXZER" }
    ),
    true
  );
  assert.equal(
    core.sameSong(
      { title: "MONTAGEM GLORIA", artist: "Rushex/Avenxir/MONTAGEM" },
      { title: "MONTAGEM GLORIA", artist: "Avenxir" }
    ),
    true
  );
  assert.equal(
    core.sameSong(
      { title: "SPOOKY 2", artist: "fennecxx/DJ ALEX/Dj Samir" },
      { title: "SPOOKY 2", artist: "DJ ALEX & Dj Samir" }
    ),
    true
  );
  assert.equal(
    core.sameSong(
      { title: "Tema", artist: "Artista A" },
      { title: "Tema", artist: "Artista B" }
    ),
    false
  );
});

test("slowed, sped up y reverb no crean una canción distinta", () => {
  assert.equal(
    core.matchKey("MONTAGEM ECLIPSE - Slowed", "DJ FKU"),
    core.matchKey("MONTAGEM ECLIPSE", "DJ FKU")
  );
  assert.equal(
    core.matchKey("MONTAGEM EMPIRE - slowed", "NUEKI"),
    core.matchKey("MONTAGEM EMPIRE", "NUEKI")
  );
  assert.equal(
    core.matchKey("MTG DIABÓLICA (Slowed + Reverb)", "DJ SXD/notdjfake"),
    core.matchKey("MTG DIABÓLICA", "DJ SXD")
  );
  assert.equal(
    core.matchKey("Nerves [Sped Up]", "Eternxlkz"),
    core.matchKey("Nerves", "Eternxlkz")
  );
  assert.equal(
    core.matchKey("Tema - Ultra Slowed + Reverb", "Banda"),
    core.matchKey("Tema", "Banda")
  );
  assert.equal(
    core.matchKey("Tema (Official Audio)", "Banda"),
    core.matchKey("Tema", "Banda")
  );
});

test("live, remix e instrumental siguen siendo versiones distintas", () => {
  assert.notEqual(core.matchKey("Tema (Live)", "Banda"), core.matchKey("Tema", "Banda"));
  assert.notEqual(core.matchKey("Tema - Live", "Banda"), core.matchKey("Tema", "Banda"));
  assert.notEqual(core.matchKey("Tema (Remix)", "Banda"), core.matchKey("Tema", "Banda"));
  assert.notEqual(core.matchKey("Tema (Acústico)", "Banda"), core.matchKey("Tema", "Banda"));
  assert.notEqual(core.matchKey("Tema (Instrumental)", "Banda"), core.matchKey("Tema", "Banda"));
});

test("la vista previa reconoce biblioteca aunque el crédito cambie", () => {
  const library = [
    { title: "MONTAGEM ASSOMBRADA", artist: "CHAXZER/DJ FKU" },
    { title: "MONTAGEM ECLIPSE - Slowed", artist: "DJ FKU" },
    { title: "MONTAGEM EMPIRE - slowed", artist: "NUEKI" },
    { title: "MONTAGEM GLORIA - Slowed", artist: "Rushex/Avenxir/MONTAGEM" },
    { title: "MTG DIABÓLICA - Slowed", artist: "DJ SXD/notdjfake" },
    { title: "Nerves - Slowed", artist: "Eternxlkz" },
    { title: "SPOOKY 2", artist: "fennecxx/DJ ALEX/Dj Samir" }
  ];
  const rows = [
    { title: "MONTAGEM ASSOMBRADA", artist: "CHAXZER" },
    { title: "MONTAGEM ECLIPSE", artist: "DJ FKU" },
    { title: "MONTAGEM EMPIRE", artist: "NUEKI" },
    { title: "MONTAGEM GLORIA", artist: "Rushex" },
    { title: "MTG DIABÓLICA (Slowed + Reverb)", artist: "DJ SXD" },
    { title: "Nerves (Sped Up)", artist: "Eternxlkz" },
    { title: "SPOOKY 2", artist: "fennecxx" }
  ];
  const preview = core.buildPreview(rows, library, []);

  assert.equal(preview.fresh, 0);
  assert.equal(preview.inLibrary, rows.length);
  assert.deepEqual(
    preview.rows.map((row) => row.status),
    rows.map(() => "library")
  );
});

test("la vista previa detecta pendientes y repetidas con metadatos distintos", () => {
  const rows = [
    { title: "MONTAGEM ECLIPSE", artist: "DJ FKU" },
    { title: "MONTAGEM ECLIPSE - Slowed", artist: "DJ FKU" },
    { title: "Tema", artist: "CHAXZER" },
    { title: "Tema - Sped Up", artist: "CHAXZER/DJ FKU" }
  ];
  const preview = core.buildPreview(
    rows,
    [],
    [{ title: "MONTAGEM ECLIPSE - Slowed", artist: "DJ FKU" }]
  );

  assert.equal(preview.alreadyPending, 1);
  assert.equal(preview.duplicates, 2);
  assert.equal(preview.fresh, 1);
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

test("reconoce links de Spotify de canción, álbum y playlist", () => {
  const track = core.parseSpotifyLink(
    "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT?si=abc123"
  );
  assert.equal(track.type, "track");
  assert.equal(track.id, "4cOdK2wGLETKBW3PvgPWqT");
  assert.equal(track.url, "https://open.spotify.com/track/4cOdK2wGLETKBW3PvgPWqT");

  const intl = core.parseSpotifyLink(
    "https://open.spotify.com/intl-es/album/1DFixLWuPkv3KT3TnV35m3"
  );
  assert.equal(intl.type, "album");
  assert.equal(intl.id, "1DFixLWuPkv3KT3TnV35m3");

  const uri = core.parseSpotifyLink("spotify:playlist:37i9dQZF1DXcBWIGoYBM5M");
  assert.equal(uri.type, "playlist");

  const short = core.parseSpotifyLink("https://spotify.link/abc123");
  assert.equal(short.type, "short");
});

test("extrae links de Spotify dentro de un texto y descarta otros hosts", () => {
  const links = core.extractSpotifyLinks(
    "Mirá esta lista: https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M y este tema spotify:track:4cOdK2wGLETKBW3PvgPWqT"
  );
  assert.equal(links.length, 2);
  assert.deepEqual(
    Array.from(links).map((link) => link.type),
    ["playlist", "track"]
  );

  assert.equal(core.parseSpotifyLink("https://example.com/track/4cOdK2wGLETKBW3PvgPWqT"), null);
  assert.equal(core.parseSpotifyLink("https://open.spotify.com/track/corto"), null);
  assert.equal(core.isSpotifyLink("https://open.spotify.com/album/1DFixLWuPkv3KT3TnV35m3"), true);
});
