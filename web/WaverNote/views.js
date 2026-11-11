/* ============================================================
   WaverNote · vistas
   Portada, búsqueda, biblioteca y detalles de álbum / playlist.
   ============================================================ */

let activeQuery = "";

const highlight = (text) => {
  const safe = escapeHTML(text);
  if (!activeQuery) return safe;
  const term = escapeRegExp(escapeHTML(activeQuery));
  if (!term) return safe;
  return safe.replace(new RegExp(`(${term})`, "ig"), "<mark>$1</mark>");
};

const albumCard = (album) => `
  <article class="album-card">
    <div class="album-card__art">
      <button class="album-card__open" data-action="open-album" data-id="${album.id}" aria-label="Abrir ${escapeHTML(album.title)}">
        ${coverHTML(album)}
      </button>
      <button class="card-play" data-action="play-album" data-id="${album.id}" aria-label="Reproducir ${escapeHTML(album.title)}">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="album-card__info">
      <button class="album-card__title" data-action="open-album" data-id="${album.id}">${escapeHTML(album.title)}</button>
      <p>${escapeHTML(album.artist)}</p>
    </div>
  </article>`;

const albumGrid = (albums) => `<div class="album-grid">${albums.map(albumCard).join("")}</div>`;

const playlistCard = (playlist) => `
  <article class="playlist-card">
    <div class="playlist-card__art">
      <button class="playlist-card__open" data-action="open-playlist" data-id="${playlist.id}" aria-label="Abrir ${escapeHTML(playlist.name)}">
        ${coverHTML(playlist)}
      </button>
      <button class="card-play" data-action="play-playlist" data-id="${playlist.id}" aria-label="Reproducir ${escapeHTML(playlist.name)}">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="album-card__info">
      <button class="album-card__title" data-action="open-playlist" data-id="${playlist.id}">${escapeHTML(playlist.name)}</button>
      <p>${plural(playlist.tracks.length, "pista", "pistas")} · ${escapeHTML(playlist.description)}</p>
    </div>
  </article>`;

const playlistStrip = (playlist) => `
  <div class="playlist-row" role="button" tabindex="0" data-action="open-playlist" data-id="${playlist.id}" aria-label="Abrir playlist ${escapeHTML(playlist.name)}">
    <span class="playlist-row__art">${coverHTML(playlist)}</span>
    <span class="playlist-row__info">
      <strong>${escapeHTML(playlist.name)}</strong>
      <span>${plural(playlist.tracks.length, "pista", "pistas")} · ${formatTotal(playlistDuration(playlist))}</span>
    </span>
    <span class="playlist-row__chev">${icon("chevron-right")}</span>
  </div>`;

const trackRows = (ids, { showAlbum = true, context = "" } = {}) => {
  const valid = ids.filter((id) => TRACK_BY_ID.has(id));
  return `<div class="tracklist ${showAlbum ? "" : "tracklist--no-album"}" data-list-context="${escapeHTML(context)}">
    <div class="tracklist__head">
      <span>#</span>
      <span>Título</span>
      ${showAlbum ? "<span>Álbum</span>" : ""}
      <span>Reproducciones</span>
      <span class="tracklist__right">Duración</span>
      <span></span>
      <span></span>
    </div>
    <div class="tracklist__rows">
      ${valid
        .map((id, index) => {
          const track = TRACK_BY_ID.get(id);
          const album = albumOf(track);
          const current = state.currentTrackId === id;
          const playing = current && state.isPlaying;
          const liked = isLiked(id);
          return `<div class="track-row ${current ? "is-current" : ""} ${playing ? "is-playing" : ""}" data-track-row="${id}" data-action="play-row" data-id="${id}" role="button" tabindex="0" aria-label="Reproducir ${escapeHTML(track.title)} de ${escapeHTML(album.artist)}">
            <span class="track-row__index">
              <span class="track-row__num">${String(index + 1).padStart(2, "0")}</span>
              <span class="track-row__play">${icon("play", "icon--fill")}</span>
              <span class="track-row__eq" aria-hidden="true"><i></i><i></i><i></i></span>
            </span>
            <span class="track-row__main">
              <span class="track-row__title">${highlight(track.title)}</span>
              <span class="track-row__artist">${escapeHTML(album.artist)}</span>
            </span>
            ${showAlbum ? `<button class="track-row__album" data-action="open-album" data-id="${album.id}" title="Abrir ${escapeHTML(album.title)}">${escapeHTML(album.title)}</button>` : ""}
            <span class="track-row__plays">${track.plays}</span>
            <span class="track-row__duration">${formatTime(track.duration)}</span>
            <button class="row-like ${liked ? "is-liked" : ""}" data-action="like" data-id="${id}" data-like-id="${id}" aria-label="${liked ? "Quitar de me gusta" : "Agregar a me gusta"}" aria-pressed="${liked}">${icon("heart")}</button>
            <button class="row-add" data-action="queue-add" data-id="${id}" aria-label="Agregar a la cola" title="Agregar a la cola">${icon("plus")}</button>
          </div>`;
        })
        .join("")}
    </div>
  </div>`;
};

const emptyState = (title, text, actionHTML = "") => `
  <div class="empty">
    <span class="empty__icon">${icon("wave")}</span>
    <h3>${escapeHTML(title)}</h3>
    <p>${escapeHTML(text)}</p>
    ${actionHTML}
  </div>`;

/* ------------------------------------------------------------
   Portada
   ------------------------------------------------------------ */

const viewHome = () => {
  const featured = ALBUM_BY_ID.get(WN_FEATURED_ALBUM);
  const featuredTracks = albumTracks(featured.id);
  const sessionTotal = WN_HOME_SESSION.reduce(
    (total, id) => total + (TRACK_BY_ID.get(id)?.duration || 0),
    0
  );

  return `
    <section class="page-head">
      <div>
        <p class="eyebrow">${todayLabel()}</p>
        <h1>${greeting()}<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">Una marea de sonido para acompañar lo que estés haciendo hoy.</p>
      </div>
      <button class="btn btn--soft" data-action="play-session">
        ${icon("play", "icon--fill")} Reproducir sesión
      </button>
    </section>

    <section class="hero" style="--p1:${featured.palette[0]};--p2:${featured.palette[1]};--p3:${featured.palette[2]}">
      <span class="hero__glow hero__glow--one"></span>
      <span class="hero__glow hero__glow--two"></span>
      <div class="hero__copy">
        <span class="pill">${icon("sparkles")} Álbum del día</span>
        <h2>${escapeHTML(featured.title)}</h2>
        <p class="hero__by">${escapeHTML(featured.artist)} <span>·</span> ${escapeHTML(featured.genre)} <span>·</span> ${featured.year}</p>
        <p class="hero__desc">${escapeHTML(featured.description)}</p>
        <div class="hero__actions">
          <button class="btn btn--primary" data-action="play-album" data-id="${featured.id}">
            ${icon("play", "icon--fill")} Reproducir
          </button>
          <button class="btn btn--ghost" data-action="open-album" data-id="${featured.id}">
            Ver álbum ${icon("arrow-right")}
          </button>
        </div>
        <p class="hero__note">${icon("disc")} ${plural(featuredTracks.length, "pista", "pistas")} · ${formatTotal(albumDuration(featured.id))} · pista destacada «Medianoche azul»</p>
      </div>
      <div class="hero__art">
        ${coverHTML(featured, "cover--hero")}
        <span class="hero__sticker">${icon("wave")} Audio generado en vivo</span>
      </div>
      <svg class="hero__tide" viewBox="0 0 1200 240" preserveAspectRatio="none" aria-hidden="true">
        <path d="M0 150 C 150 100 260 200 420 150 S 700 90 860 150 S 1080 200 1200 140" fill="none" stroke="var(--p3)" stroke-width="1" opacity=".26"/>
        <path d="M0 180 C 180 130 300 220 480 170 S 760 120 940 180 S 1120 220 1200 170" fill="none" stroke="var(--p3)" stroke-width=".8" opacity=".16"/>
        <path d="M0 210 C 200 170 360 250 560 200 S 840 160 1020 210 S 1140 230 1200 205" fill="none" stroke="var(--p3)" stroke-width=".6" opacity=".1"/>
      </svg>
    </section>

    <section class="section">
      <div class="section__head">
        <div>
          <h2>Recién llegados</h2>
          <p class="section__sub">Seis paisajes para descubrir.</p>
        </div>
        <button class="link-btn" data-action="open-library" data-tab="albums">Ver todo ${icon("arrow-right")}</button>
      </div>
      ${albumGrid(WN_ALBUMS)}
    </section>

    <section class="section">
      <div class="section__head">
        <div>
          <h2>La sesión de hoy</h2>
          <p class="section__sub">${plural(WN_HOME_SESSION.length, "pista", "pistas")} · ${formatTotal(sessionTotal)} · elegidas para esta hora.</p>
        </div>
        <button class="btn btn--small btn--soft" data-action="play-session">
          ${icon("play", "icon--fill")} Reproducir
        </button>
      </div>
      ${trackRows(WN_HOME_SESSION, { context: "home-session" })}
    </section>

    <section class="section">
      <div class="section__head">
        <div>
          <h2>Playlists para ahora</h2>
          <p class="section__sub">Según el momento, no según el algoritmo.</p>
        </div>
        <button class="link-btn" data-action="open-library" data-tab="playlists">Ver todo ${icon("arrow-right")}</button>
      </div>
      <div class="playlist-strip">${WN_PLAYLISTS.map(playlistStrip).join("")}</div>
    </section>

    <footer class="page-foot">
      <span class="page-foot__mark">W</span>
      <p>WaverNote es un prototipo de producto. Las pistas son ficticias y se sintetizan en tiempo real en tu navegador con Web Audio API.</p>
    </footer>`;
};

/* ------------------------------------------------------------
   Buscar
   ------------------------------------------------------------ */

const viewSearch = () => {
  const query = state.search.trim();
  const results = searchCatalog(query);

  if (!query) {
    return `
      <section class="page-head page-head--compact">
        <div>
          <p class="eyebrow">Buscar</p>
          <h1>¿Qué querés escuchar?</h1>
          <p class="page-head__sub">Buscá por canción, álbum, artista o simplemente por cómo te sentís.</p>
        </div>
      </section>
      <div class="mood-chips">
        ${WN_MOODS.map(
          (mood) =>
            `<button class="chip" data-action="apply-mood" data-query="${mood.query}">${icon("wave")} ${mood.label}</button>`
        ).join("")}
      </div>
      <section class="section">
        <div class="section__head">
          <h2>Explorar álbumes</h2>
          <p class="section__sub">Todo el catálogo del prototipo.</p>
        </div>
        ${albumGrid(WN_ALBUMS)}
      </section>`;
  }

  if (!results.total) {
    return `
      <section class="page-head page-head--compact">
        <div>
          <p class="eyebrow">Buscar</p>
          <h1>Sin resultados<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">No encontramos nada para «${escapeHTML(query)}». Probá con otro título, artista o mood.</p>
        </div>
      </section>
      ${emptyState("La marea está tranquila", "Quizá te sirva empezar por uno de estos moods.", `<div class="empty__actions">${WN_MOODS.slice(0, 4)
        .map((mood) => `<button class="chip" data-action="apply-mood" data-query="${mood.query}">${mood.label}</button>`)
        .join("")}</div>`)}`;
  }

  return `
    <section class="page-head page-head--compact">
      <div>
        <p class="eyebrow">Buscar</p>
        <h1>Resultados<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">${plural(results.total, "resultado", "resultados")} para «${escapeHTML(query)}».</p>
      </div>
    </section>

    ${results.tracks.length ? `<section class="section section--tight">
      <div class="section__head">
        <h2>Canciones</h2>
        <span class="count-label">${plural(results.tracks.length, "pista", "pistas")}</span>
      </div>
      ${trackRows(results.tracks.map((track) => track.id), { context: "search" })}
    </section>` : ""}

    ${results.albums.length ? `<section class="section">
      <div class="section__head">
        <h2>Álbumes</h2>
        <span class="count-label">${plural(results.albums.length, "álbum", "álbumes")}</span>
      </div>
      ${albumGrid(results.albums)}
    </section>` : ""}

    ${results.playlists.length ? `<section class="section">
      <div class="section__head">
        <h2>Playlists</h2>
        <span class="count-label">${plural(results.playlists.length, "playlist", "playlists")}</span>
      </div>
      <div class="playlist-grid">${results.playlists.map(playlistCard).join("")}</div>
    </section>` : ""}`;
};

/* ------------------------------------------------------------
   Biblioteca
   ------------------------------------------------------------ */

const libraryTabs = [
  ["songs", "Canciones"],
  ["albums", "Álbumes"],
  ["playlists", "Playlists"],
];

const viewLibrary = () => {
  const likedTracks = WN_TRACKS.filter((track) => isLiked(track.id));
  const likedTotal = likedTracks.reduce((total, track) => total + track.duration, 0);
  const recentIds = state.recent.filter((id) => TRACK_BY_ID.has(id)).slice(0, 8);

  let content = "";

  if (state.libraryTab === "albums") {
    content = `<section class="section section--tight">
      <div class="section__head">
        <h2>Todos los álbumes</h2>
        <span class="count-label">${plural(WN_ALBUMS.length, "álbum", "álbumes")}</span>
      </div>
      ${albumGrid(WN_ALBUMS)}
    </section>`;
  } else if (state.libraryTab === "playlists") {
    content = `<section class="section section--tight">
      <div class="section__head">
        <h2>Tus playlists</h2>
        <span class="count-label">${plural(WN_PLAYLISTS.length, "playlist", "playlists")}</span>
      </div>
      <div class="playlist-grid">${WN_PLAYLISTS.map(playlistCard).join("")}</div>
    </section>`;
  } else {
    content = `
      <section class="section section--tight">
        <div class="section__head">
          <div>
            <h2>Me gusta</h2>
            <p class="section__sub">${likedTracks.length ? `${plural(likedTracks.length, "canción", "canciones")} · ${formatTotal(likedTotal)}` : "Tu colección personal, guardada en este navegador."}</p>
          </div>
          ${likedTracks.length ? `<button class="btn btn--small btn--soft" data-action="play-liked">${icon("play", "icon--fill")} Reproducir</button>` : ""}
        </div>
        ${likedTracks.length
          ? trackRows(likedTracks.map((track) => track.id), { context: "liked" })
          : emptyState("Todavía no hay favoritos", "Tocá el corazón de una canción y va a aparecer acá.", `<div class="empty__actions"><button class="btn btn--primary" data-action="nav-home">${icon("compass")} Explorar música</button></div>`)}
      </section>

      ${recentIds.length ? `<section class="section">
        <div class="section__head">
          <div>
            <h2>Escuchado hace poco</h2>
            <p class="section__sub">Tu rastro de esta sesión.</p>
          </div>
        </div>
        ${trackRows(recentIds, { context: "recent" })}
      </section>` : ""}`;
  }

  return `
    <section class="page-head page-head--compact">
      <div>
        <p class="eyebrow">Tu biblioteca</p>
        <h1>Lo que es tuyo<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">Favoritos, álbumes y playlists. Todo vive localmente en este prototipo.</p>
      </div>
      <div class="library-stats">
        <div><strong>${likedTracks.length}</strong><span>favoritos</span></div>
        <div><strong>${state.recent.length}</strong><span>recientes</span></div>
        <div><strong>${WN_ALBUMS.length}</strong><span>álbumes</span></div>
      </div>
    </section>
    <div class="tabs" role="tablist" aria-label="Secciones de la biblioteca">
      ${libraryTabs
        .map(
          ([id, label]) =>
            `<button class="tab ${state.libraryTab === id ? "is-active" : ""}" role="tab" aria-selected="${state.libraryTab === id}" data-action="library-tab" data-tab="${id}">${label}</button>`
        )
        .join("")}
    </div>
    ${content}`;
};

/* ------------------------------------------------------------
   Detalle de álbum y playlist
   ------------------------------------------------------------ */

const viewAlbum = (id) => {
  const album = ALBUM_BY_ID.get(id);
  if (!album) return viewNotFound();

  const tracks = albumTracks(id);
  const total = tracks.reduce((sum, track) => sum + track.duration, 0);

  return `
    <div class="detail" style="--p1:${album.palette[0]};--p2:${album.palette[1]};--p3:${album.palette[2]}">
      <span class="detail__aura"></span>
      <button class="back-link" data-action="history-back">${icon("chevron-left")} Volver</button>
      <div class="detail__head">
        <div class="detail__cover">
          ${coverHTML(album, "cover--detail")}
        </div>
        <div class="detail__info">
          <p class="eyebrow">Álbum · ${album.year}</p>
          <h1>${escapeHTML(album.title)}</h1>
          <p class="detail__line">
            <span>${escapeHTML(album.artist)}</span>
            <span class="detail__sep">·</span>
            <span>${escapeHTML(album.genre)}</span>
            <span class="detail__sep">·</span>
            <span>${plural(tracks.length, "pista", "pistas")}, ${formatTotal(total)}</span>
          </p>
          <p class="detail__desc">${escapeHTML(album.description)}</p>
          <div class="detail__actions">
            <button class="btn btn--primary" data-action="play-album" data-id="${album.id}">
              ${icon("play", "icon--fill")} Reproducir
            </button>
            <button class="btn btn--soft" data-action="shuffle-album" data-id="${album.id}">
              ${icon("shuffle")} Aleatorio
            </button>
            <button class="icon-btn icon-btn--line" data-action="queue-album" data-id="${album.id}" title="Agregar a la cola" aria-label="Agregar álbum a la cola">
              ${icon("plus")}
            </button>
          </div>
          <p class="detail__sonic">${icon("wave")} ${album.sonic.bpm} BPM · ${escapeHTML(album.sonic.key)} · ${escapeHTML(album.sonic.mood)}</p>
        </div>
      </div>
      ${trackRows(tracks.map((track) => track.id), { showAlbum: false, context: `album:${album.id}` })}
      <p class="detail__foot">Álbum ficticio del prototipo · sintetizado en vivo, sin archivos de audio.</p>
    </div>`;
};

const viewPlaylist = (id) => {
  const playlist = PLAYLIST_BY_ID.get(id);
  if (!playlist) return viewNotFound();

  const tracks = playlistTracks(playlist);
  const total = playlistDuration(playlist);

  return `
    <div class="detail" style="--p1:${playlist.palette[0]};--p2:${playlist.palette[1]};--p3:${playlist.palette[2]}">
      <span class="detail__aura"></span>
      <button class="back-link" data-action="history-back">${icon("chevron-left")} Volver</button>
      <div class="detail__head">
        <div class="detail__cover detail__cover--stack">
          <span class="detail__sheet detail__sheet--two"></span>
          <span class="detail__sheet detail__sheet--one"></span>
          ${coverHTML(playlist, "cover--detail")}
        </div>
        <div class="detail__info">
          <p class="eyebrow">Playlist</p>
          <h1>${escapeHTML(playlist.name)}</h1>
          <p class="detail__line">
            <span>WaverNote</span>
            <span class="detail__sep">·</span>
            <span>${plural(tracks.length, "pista", "pistas")}, ${formatTotal(total)}</span>
          </p>
          <p class="detail__desc">${escapeHTML(playlist.description)}</p>
          <div class="detail__actions">
            <button class="btn btn--primary" data-action="play-playlist" data-id="${playlist.id}">
              ${icon("play", "icon--fill")} Reproducir
            </button>
            <button class="btn btn--soft" data-action="shuffle-playlist" data-id="${playlist.id}">
              ${icon("shuffle")} Aleatorio
            </button>
            <button class="icon-btn icon-btn--line" data-action="queue-playlist" data-id="${playlist.id}" title="Agregar a la cola" aria-label="Agregar playlist a la cola">
              ${icon("plus")}
            </button>
          </div>
        </div>
      </div>
      ${trackRows(tracks.map((track) => track.id), { context: `playlist:${playlist.id}` })}
      <p class="detail__foot">Playlist curada del prototipo · sintetizada en vivo, sin archivos de audio.</p>
    </div>`;
};

const viewNotFound = () => `
  <section class="page-head page-head--compact">
    <div>
      <p class="eyebrow">404</p>
      <h1>Esa ola no existe<span class="dot-accent">.</span></h1>
      <p class="page-head__sub">La página que buscás se fue con la marea.</p>
    </div>
  </section>
  ${emptyState("Volvamos a la costa", "Probá de nuevo desde el inicio.", `<div class="empty__actions"><button class="btn btn--primary" data-action="nav-home">${icon("compass")} Ir al inicio</button></div>`)}`;

/* ------------------------------------------------------------
   Render + navegación visual
   ------------------------------------------------------------ */

const renderView = ({ resetScroll = true } = {}) => {
  const route = state.route;
  activeQuery = route.view === "search" ? state.search.trim() : "";

  let content = "";
  switch (route.view) {
    case "home":
      content = viewHome();
      break;
    case "search":
      content = viewSearch();
      break;
    case "library":
      content = viewLibrary();
      break;
    case "album":
      content = viewAlbum(route.id);
      break;
    case "playlist":
      content = viewPlaylist(route.id);
      break;
    default:
      content = viewHome();
  }

  const view = $("#view");
  if (!view) return;
  const scrollTop = view.scrollTop;
  view.innerHTML = `<div class="view-inner">${content}</div>`;
  view.scrollTop = resetScroll ? 0 : scrollTop;

  if (typeof updateHighlights === "function") updateHighlights();
  updateHistoryButtons();
};

const updateNavUI = () => {
  const route = state.route;
  const active =
    route.view === "search" ? "search" : route.view === "library" ? "library" : route.view === "home" ? "home" : "";

  $$(".nav__item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.nav === active);
  });

  $$(".mobile-nav__item").forEach((item) => {
    const nav = item.dataset.mobileNav;
    item.classList.toggle("is-active", nav === active);
  });

  $$(".side-playlist").forEach((item) => {
    item.classList.toggle("is-active", route.view === "playlist" && item.dataset.id === route.id);
  });

  updateHistoryButtons();
};
