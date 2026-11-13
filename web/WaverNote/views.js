/* ============================================================
   WaverNote · vistas
   Inicio, búsqueda, biblioteca y detalles. Todo sale de la
   biblioteca real del usuario: si está vacía, no hay contenido.
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
  <article class="album-card" data-card="album" data-id="${escapeHTML(album.id)}">
    <div class="album-card__art">
      <button class="album-card__open" data-action="open-album" data-id="${escapeHTML(album.id)}" aria-label="Abrir ${escapeHTML(album.title)}">
        ${coverHTML(album)}
      </button>
      <button class="card-queue" data-action="queue-album" data-id="${escapeHTML(album.id)}" title="Agregar a continuación" aria-label="Agregar ${escapeHTML(album.title)} a continuación">
        ${icon("queue-add")}
      </button>
      <button class="card-play" data-action="play-album" data-id="${escapeHTML(album.id)}" aria-label="Reproducir ${escapeHTML(album.title)}">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="album-card__info">
      <button class="album-card__title" data-action="open-album" data-id="${escapeHTML(album.id)}">${escapeHTML(album.title)}</button>
      <p>${escapeHTML(album.artist)} · ${plural(album.tracks.length, "pista", "pistas")}</p>
    </div>
  </article>`;

const albumGrid = (albums) => `<div class="album-grid">${albums.map(albumCard).join("")}</div>`;

const playlistCard = (playlist) => {
  const total = playlistDuration(playlist);
  return `
  <article class="playlist-card" data-card="playlist" data-id="${playlist.id}">
    <div class="playlist-card__art">
      <button class="playlist-card__open" data-action="open-playlist" data-id="${playlist.id}" aria-label="Abrir ${escapeHTML(playlist.name)}">
        ${coverHTML(playlistCover(playlist))}
      </button>
      <button class="card-queue" data-action="queue-playlist" data-id="${playlist.id}" title="Agregar a continuación" aria-label="Agregar ${escapeHTML(playlist.name)} a continuación">
        ${icon("queue-add")}
      </button>
      <button class="card-play" data-action="play-playlist" data-id="${playlist.id}" aria-label="Reproducir ${escapeHTML(playlist.name)}">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="album-card__info">
      <button class="album-card__title" data-action="open-playlist" data-id="${playlist.id}">${escapeHTML(playlist.name)}</button>
      <p>${plural(playlist.trackIds.length, "pista", "pistas")}${total ? ` · ${formatTotal(total)}` : ""}</p>
    </div>
  </article>`;
};

const playlistStrip = (playlist) => `
  <div class="playlist-row" role="button" tabindex="0" data-action="open-playlist" data-id="${playlist.id}" aria-label="Abrir playlist ${escapeHTML(playlist.name)}">
    <span class="playlist-row__art">${coverHTML(playlistCover(playlist))}</span>
    <span class="playlist-row__info">
      <strong>${escapeHTML(playlist.name)}</strong>
      <span>${plural(playlist.trackIds.length, "pista", "pistas")} · ${formatTotal(playlistDuration(playlist))}</span>
    </span>
    <span class="playlist-row__chev">${icon("chevron-right")}</span>
  </div>`;

const trackRows = (ids, { showAlbum = true, context = "", playlistId = null, reasons = null, showCover = true } = {}) => {
  const tracks = (ids || []).map((id) => trackById(id)).filter(Boolean);

  return `<div class="tracklist ${showAlbum ? "" : "tracklist--no-album"}" data-list-context="${escapeHTML(context)}">
    <div class="tracklist__head">
      <span>#</span>
      <span>Título</span>
      ${showAlbum ? "<span>Álbum</span>" : ""}
      <span>Género</span>
      <span class="tracklist__right">Duración</span>
      <span></span>
      <span></span>
    </div>
    <div class="tracklist__rows">
      ${tracks
        .map((track, index) => {
          const album = albumByTrack(track);
          const current = Number(state.currentTrackId) === Number(track.id);
          const playing = current && state.isPlaying;
          const liked = isLiked(track.id);
          const why = reasons?.[track.id] || "";
          return `<div class="track-row ${current ? "is-current" : ""} ${playing ? "is-playing" : ""}" data-track-row="${track.id}" data-playlist="${playlistId || ""}" data-action="play-row" data-id="${track.id}" role="button" tabindex="0" aria-label="Reproducir ${escapeHTML(track.title)} de ${escapeHTML(track.artist || "artista desconocido")}">
            <span class="track-row__index">
              <span class="track-row__num">${String(index + 1).padStart(2, "0")}</span>
              <span class="track-row__play">${icon("play", "icon--fill")}</span>
              <span class="track-row__eq" aria-hidden="true"><i></i><i></i><i></i></span>
            </span>
            <span class="track-row__main${showCover ? " track-row__main--cover" : ""}">
              ${showCover ? `<span class="track-row__art">${coverHTML(track)}</span>` : ""}
              <span class="track-row__copy">
                <span class="track-row__title">${highlight(track.title)}</span>
                <span class="track-row__sub">
                  <span class="track-row__artist">${escapeHTML(track.artist || "Artista desconocido")}</span>
                  ${why ? `<span class="track-row__why">${icon("sparkles")}${escapeHTML(why)}</span>` : ""}
                </span>
              </span>
            </span>
            ${showAlbum ? `<button class="track-row__album" data-action="open-album" data-id="${escapeHTML(album.id)}" title="Abrir ${escapeHTML(album.title)}">${escapeHTML(album.title)}</button>` : ""}
            <span class="track-row__plays">${escapeHTML(track.genre || "—")}</span>
            <span class="track-row__duration">${formatTime(track.duration)}</span>
            <button class="row-like ${liked ? "is-liked" : ""}" data-action="like" data-id="${track.id}" data-like-id="${track.id}" aria-label="${liked ? "Quitar de me gusta" : "Agregar a me gusta"}" aria-pressed="${liked}">${icon("heart")}</button>
            <button class="row-add row-more" data-action="track-menu" data-id="${track.id}" data-playlist="${playlistId || ""}" aria-label="Más opciones de ${escapeHTML(track.title)}" title="Más opciones">${icon("list")}</button>
          </div>`;
        })
        .join("")}
    </div>
  </div>`;
};

const emptyState = (title, text, actionHTML = "", iconName = "wave") => `
  <div class="empty">
    <span class="empty__icon">${icon(iconName)}</span>
    <h3>${escapeHTML(title)}</h3>
    <p>${escapeHTML(text)}</p>
    ${actionHTML}
  </div>`;

const uploadAction = (label = "Subir música", extraClass = "") => `
  <button class="btn btn--primary ${extraClass}" data-action="open-upload">
    ${icon("upload")} ${escapeHTML(label)}
  </button>`;

/* ------------------------------------------------------------
   Inicio
   ------------------------------------------------------------ */

const viewHome = () => {
  const tracks = state.tracks;
  const userName = state.user?.username ? `, ${state.user.username}` : "";

  if (!tracks.length) {
    return `
      <section class="page-head">
        <div>
          <p class="eyebrow">${todayLabel()}</p>
          <h1>${greeting()}${escapeHTML(userName)}<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">Tu biblioteca está lista para recibir tu música.</p>
        </div>
        ${uploadAction()}
      </section>

      <section class="first-run">
        <div class="first-run__art" aria-hidden="true">
          <span class="first-run__ring first-run__ring--one"></span>
          <span class="first-run__ring first-run__ring--two"></span>
          <span class="first-run__wave">${icon("wave")}</span>
        </div>
        <div class="first-run__copy">
          <p class="eyebrow">Empezamos de cero</p>
          <h2>Acá todavía no hay nada<span class="dot-accent">.</span></h2>
          <p>Subí tus propios archivos y van a quedar guardados en tu cuenta Surface. Sin canciones de ejemplo ni audio generado: solo lo que vos agregues.</p>
          <div class="empty__actions">
            ${uploadAction("Subir mis archivos")}
            <button class="btn btn--ghost" data-action="nav-library">Ver mi biblioteca ${icon("arrow-right")}</button>
          </div>
        </div>
      </section>

      <section class="section">
        <div class="section__head">
          <div>
            <h2>Cómo funciona</h2>
            <p class="section__sub">Tres pasos y tu música queda disponible.</p>
          </div>
        </div>
        <div class="steps">
          <article class="step">
            <span class="step__num">01</span>
            <h3>Subí</h3>
            <p>MP3, WAV, OGG, M4A, AAC, FLAC u OPUS. Hasta 50 MB por archivo.</p>
          </article>
          <article class="step">
            <span class="step__num">02</span>
            <h3>Se guarda</h3>
            <p>El audio y la portada quedan asociados a tu cuenta, no a este navegador.</p>
          </article>
          <article class="step">
            <span class="step__num">03</span>
            <h3>Escuchá</h3>
            <p>Armá playlists, marcá favoritos y escuchá desde cualquier navegador.</p>
          </article>
        </div>
      </section>

      <footer class="page-foot">
        <span class="page-foot__mark">W</span>
        <p>WaverNote usa tu cuenta Surface. Tu biblioteca arranca vacía y crece solo con lo que subís.</p>
      </footer>`;
  }

  const latest = tracks[0];
  const latestAlbum = albumByTrack(latest);
  const albums = allAlbums();
  const playlists = state.playlists;
  const palette = paletteFor(latest.title);
  const total = tracks.reduce((sum, track) => sum + (Number(track.duration) || 0), 0);
  const trends = trendItems();
  const recentAdditions = recentlyAddedTracks();

  return `
    <section class="page-head">
      <div>
        <p class="eyebrow">${todayLabel()}</p>
        <h1>${greeting()}${escapeHTML(userName)}<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">${plural(tracks.length, "canción", "canciones")} · ${plural(albums.length, "álbum", "álbumes")} · ${formatTotal(total)} en tu biblioteca.</p>
      </div>
      ${uploadAction()}
    </section>

    <section class="hero" style="--p1:${palette[0]};--p2:${palette[1]};--p3:${palette[2]}">
      <span class="hero__glow hero__glow--one"></span>
      <span class="hero__glow hero__glow--two"></span>
      <div class="hero__copy">
        <span class="pill">${icon("sparkles")} Última subida</span>
        <h2>${escapeHTML(latest.title)}</h2>
        <p class="hero__by">${escapeHTML(latest.artist || "Artista desconocido")} <span>·</span> ${escapeHTML(albumNameOf(latest))}</p>
        <p class="hero__desc">Agregada el ${escapeHTML(dateLabel(latest.createdAt))}${latest.genre ? ` · ${escapeHTML(latest.genre)}` : ""}.</p>
        <div class="hero__actions">
          <button class="btn btn--primary" data-action="play-album" data-id="${escapeHTML(latestAlbum.id)}">
            ${icon("play", "icon--fill")} Reproducir
          </button>
          <button class="btn btn--ghost" data-action="open-album" data-id="${escapeHTML(latestAlbum.id)}">
            Ver álbum ${icon("arrow-right")}
          </button>
        </div>
        <p class="hero__note">${icon("disc")} ${plural(tracks.length, "pista", "pistas")} · ${formatTotal(total)} · tu música, en tu cuenta</p>
      </div>
      <div class="hero__art">
        ${coverHTML(latest, "cover--hero")}
        <span class="hero__sticker">${icon("cloud")} Guardada en tu cuenta</span>
      </div>
      <svg class="hero__tide" viewBox="0 0 1200 240" preserveAspectRatio="none" aria-hidden="true">
        <path d="M0 150 C 150 100 260 200 420 150 S 700 90 860 150 S 1080 200 1200 140" fill="none" stroke="var(--p3)" stroke-width="1" opacity=".26"/>
        <path d="M0 180 C 180 130 300 220 480 170 S 760 120 940 180 S 1120 220 1200 170" fill="none" stroke="var(--p3)" stroke-width=".8" opacity=".16"/>
        <path d="M0 210 C 200 170 360 250 560 200 S 840 160 1020 210 S 1140 230 1200 205" fill="none" stroke="var(--p3)" stroke-width=".6" opacity=".1"/>
      </svg>
    </section>

    ${trends.length
      ? `<section class="section">
          <div class="section__head">
            <div>
              <p class="eyebrow">Tendencias</p>
              <h2>Lo que está en llamas</h2>
              <p class="section__sub">Una canción por categoría, elegida por tu forma de escuchar.</p>
            </div>
            <button class="link-btn" data-action="nav-trends">Ver tendencias ${icon("arrow-right")}</button>
          </div>
          <div class="trend-strip">
            ${trends.slice(0, 6).map((item) => trendCard(item, { compact: true })).join("")}
          </div>
        </section>`
      : ""}

    <section class="section">
      <div class="section__head">
        <div>
          <div class="section__title">
            <h2>Recién agregadas</h2>
            <span class="section__range" title="Rango: últimos 7 días">7D</span>
          </div>
          <p class="section__sub">Recién agregadas en los últimos 7 días.</p>
        </div>
        <button class="link-btn" data-action="open-library" data-tab="songs">Ver todo ${icon("arrow-right")}</button>
      </div>
      ${recentAdditions.length
        ? trackRows(recentAdditions.slice(0, 6).map((track) => track.id), { context: "recent-additions" })
        : `<div class="section-empty">
            ${icon("sparkles")}
            <p>No agregaste canciones en los últimos 7 días.</p>
            ${uploadAction("Subir música", "btn--small")}
          </div>`}
    </section>

    <section class="section">
      <div class="section__head">
        <div>
          <h2>Tus álbumes</h2>
          <p class="section__sub">Agrupados por el álbum que escribiste al subir.</p>
        </div>
        <button class="link-btn" data-action="open-library" data-tab="albums">Ver todo ${icon("arrow-right")}</button>
      </div>
      ${albumGrid(albums.slice(0, 6))}
    </section>

    ${playlists.length
      ? `<section class="section">
          <div class="section__head">
            <div>
              <h2>Tus playlists</h2>
              <p class="section__sub">Colecciones armadas por vos.</p>
            </div>
            <button class="link-btn" data-action="open-library" data-tab="playlists">Ver todo ${icon("arrow-right")}</button>
          </div>
          <div class="playlist-strip">${playlists.slice(0, 4).map(playlistStrip).join("")}</div>
        </section>`
      : ""}

    <footer class="page-foot">
      <span class="page-foot__mark">W</span>
      <p>Biblioteca personal de ${escapeHTML(state.user?.username || "tu cuenta")} · ${plural(tracks.length, "archivo", "archivos")} guardados en tu cuenta Surface.</p>
    </footer>`;
};

/* ------------------------------------------------------------
   Buscar
   ------------------------------------------------------------ */

const viewSearch = () => {
  const query = state.search.trim();
  const results = searchLibrary(query);

  if (!state.tracks.length) {
    return `
      <section class="page-head page-head--compact">
        <div>
          <p class="eyebrow">Buscar</p>
          <h1>Tu música empieza acá<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">Cuando subas canciones vas a poder buscarlas por título, artista, álbum o género.</p>
        </div>
      </section>
      ${emptyState(
        "Todavía no hay nada para buscar",
        "Subí tu primer archivo y la búsqueda se activa sola.",
        `<div class="empty__actions">${uploadAction()}</div>`,
        "search"
      )}`;
  }

  if (!query) {
    return `
      <section class="page-head page-head--compact">
        <div>
          <p class="eyebrow">Buscar</p>
          <h1>¿Qué querés escuchar?<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">Buscá por canción, álbum, artista o género dentro de tu biblioteca.</p>
        </div>
      </section>
      <section class="section section--tight">
        <div class="section__head">
          <h2>Tus álbumes</h2>
          <span class="count-label">${plural(allAlbums().length, "álbum", "álbumes")}</span>
        </div>
        ${albumGrid(allAlbums())}
      </section>
      ${state.playlists.length
        ? `<section class="section">
            <div class="section__head">
              <h2>Tus playlists</h2>
              <span class="count-label">${plural(state.playlists.length, "playlist", "playlists")}</span>
            </div>
            <div class="playlist-grid">${state.playlists.map(playlistCard).join("")}</div>
          </section>`
        : ""}`;
  }

  if (!results.total) {
    return `
      <section class="page-head page-head--compact">
        <div>
          <p class="eyebrow">Buscar</p>
          <h1>Sin resultados<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">No encontramos nada para «${escapeHTML(query)}» en tu biblioteca.</p>
        </div>
      </section>
      ${emptyState(
        "La marea está tranquila",
        "Probá con otro título, artista, álbum o género.",
        `<div class="empty__actions"><button class="btn btn--soft" data-action="clear-search">Limpiar búsqueda</button>${uploadAction("Subir más música")}</div>`,
        "search"
      )}`;
  }

  return `
    <section class="page-head page-head--compact">
      <div>
        <p class="eyebrow">Buscar</p>
        <h1>Resultados<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">${plural(results.total, "resultado", "resultados")} para «${escapeHTML(query)}».</p>
      </div>
    </section>

    ${results.tracks.length
      ? `<section class="section section--tight">
          <div class="section__head">
            <h2>Canciones</h2>
            <span class="count-label">${plural(results.tracks.length, "pista", "pistas")}</span>
          </div>
          ${trackRows(results.tracks.map((track) => track.id), { context: "search" })}
        </section>`
      : ""}

    ${results.albums.length
      ? `<section class="section">
          <div class="section__head">
            <h2>Álbumes</h2>
            <span class="count-label">${plural(results.albums.length, "álbum", "álbumes")}</span>
          </div>
          ${albumGrid(results.albums)}
        </section>`
      : ""}

    ${results.playlists.length
      ? `<section class="section">
          <div class="section__head">
            <h2>Playlists</h2>
            <span class="count-label">${plural(results.playlists.length, "playlist", "playlists")}</span>
          </div>
          <div class="playlist-grid">${results.playlists.map(playlistCard).join("")}</div>
        </section>`
      : ""}`;
};

/* ------------------------------------------------------------
   Biblioteca
   ------------------------------------------------------------ */

const libraryTabs = [
  ["songs", "Canciones"],
  ["most-played", "Más escuchadas"],
  ["albums", "Álbumes"],
  ["playlists", "Playlists"]
];

const mostPlayedIndicator = ({ iconName = "wave", title, text, action = "" }) => `
  <div class="plays-indicator" role="status">
    <span class="plays-indicator__beacon" aria-hidden="true">${icon(iconName)}<i></i></span>
    <div class="plays-indicator__copy">
      <strong>${escapeHTML(title)}</strong>
      <p>${escapeHTML(text)}</p>
    </div>
    <span class="plays-indicator__zero" aria-label="0 reproducciones">
      <strong>0</strong>
      <span>reproducciones</span>
    </span>
    ${action}
  </div>`;

const mostPlayedCard = (entry, index, topCount) => {
  const { track, count } = entry;
  const rank = index + 1;
  const podium = count > 0 && rank <= 3 ? ` plays-card--podium plays-card--${rank}` : "";
  const share = topCount > 0 ? Math.round((count / topCount) * 100) : 0;
  const playsLabel = plural(count, "reproducción", "reproducciones");
  const rankLabel = count > 0 ? String(rank).padStart(2, "0") : "—";
  const addedAt = track.createdAt ? `Agregada el ${dateLabel(track.createdAt)}` : "";
  const current = Number(state.currentTrackId) === Number(track.id);
  const playing = current && state.isPlaying;

  return `<article class="plays-card${podium}${count ? "" : " is-unplayed"}${current ? " is-current" : ""}" data-plays-card="${track.id}">
    <div class="plays-card__art">
      <button class="plays-card__open" data-action="play-most" data-id="${track.id}" aria-label="Reproducir ${escapeHTML(track.title)}">
        ${coverHTML(track)}
        <span class="plays-card__rank" aria-hidden="true">${rankLabel}</span>
      </button>
      ${
        current
          ? `<span class="plays-card__now">
              <span class="eq ${playing ? "is-running" : ""}" aria-hidden="true"><i></i><i></i><i></i></span>
              <span>${playing ? "Sonando" : "En pausa"}</span>
            </span>`
          : ""
      }
      <button class="plays-card__play" data-action="play-most" data-id="${track.id}" tabindex="-1" aria-label="Reproducir ${escapeHTML(track.title)}">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="plays-card__meta">
      <strong class="plays-card__title" title="${escapeHTML(track.title)}">${escapeHTML(track.title)}</strong>
      <span class="plays-card__artist" title="${escapeHTML(track.artist || "Artista desconocido")}">${escapeHTML(track.artist || "Artista desconocido")}</span>
      <span class="plays-card__row">
        <span class="plays-card__count">${count ? playsLabel : "Sin reproducciones"}</span>
        <span class="plays-card__share">${count ? `${share}%` : "—"}</span>
      </span>
      <span class="plays-card__meter" aria-hidden="true"><span style="width:${count ? Math.max(share, 4) : 0}%"></span></span>
      <span class="plays-card__since">${count ? addedAt || "En tu ranking" : "Todavía no la escuchaste"}</span>
    </div>
  </article>`;
};

const mostPlayedSection = () => {
  const entries = mostPlayedTracks();
  const played = entries.filter((entry) => entry.count > 0);
  const topCount = played[0]?.count || 0;
  const total = totalPlayCount();
  const hasPlays = played.length > 0;

  const head = `<div class="section__head">
    <div>
      <p class="eyebrow">Ranking personal</p>
      <h2>Las que más escuchás</h2>
      <p class="section__sub">${
        hasPlays
          ? `${plural(entries.length, "canción", "canciones")} ordenadas por reproducciones desde que las agregaste.`
          : "El ranking arranca con la primera reproducción y se ordena solo."
      }</p>
    </div>
    ${
      hasPlays
        ? `<div class="plays-head-actions">
            <div class="plays-summary">
              <div><strong data-plays-total>${total}</strong><span>reproducciones</span></div>
              <div><strong data-plays-ranked>${played.length}</strong><span>en el ranking</span></div>
            </div>
            <button class="btn btn--small btn--soft" data-action="play-most">${icon("play", "icon--fill")} Reproducir ranking</button>
          </div>`
        : ""
    }
  </div>`;

  let body = "";
  if (!state.tracks.length) {
    body = mostPlayedIndicator({
      iconName: "music",
      title: "Todavía no hay canciones",
      text: "Subí tu primera canción y las reproducciones van a empezar a contar desde ese momento.",
      action: `<button class="btn btn--primary btn--small" data-action="open-upload">${icon("upload")} Subir música</button>`
    });
  } else if (!hasPlays) {
    body = mostPlayedIndicator({
      iconName: "wave",
      title: "El ranking está en silencio",
      text: "Todavía no hay reproducciones en tu biblioteca. Dale play a cualquier canción y el grid aparece acá, ordenado por lo que más escuchás.",
      action: `<button class="btn btn--soft btn--small" data-action="play-all">${icon("play", "icon--fill")} Reproducir todo</button>`
    });
  } else {
    body = `<div class="plays-grid">${entries
      .map((entry, index) => mostPlayedCard(entry, index, topCount))
      .join("")}</div>
      <p class="plays-foot">${icon("wave")} Reproducciones contadas desde que agregaste cada canción · <span data-plays-foot-total>${plural(total, "reproducción", "reproducciones")}</span> en total</p>`;
  }

  return `<section class="section section--tight plays-section">
    ${head}
    ${body}
  </section>`;
};

const viewLibrary = () => {
  const albums = allAlbums();
  const favorites = likedTracks();
  const favoritesTotal = favorites.reduce((total, track) => total + (Number(track.duration) || 0), 0);
  const recent = recentTracks().slice(0, 8);

  let content = "";

  if (state.libraryTab === "most-played") {
    content = mostPlayedSection();
  } else if (!state.tracks.length) {
    content = `<section class="section section--tight">
      ${emptyState(
        "Tu biblioteca está vacía",
        "Subí tus propios archivos para empezar. No hay contenido de ejemplo.",
        `<div class="empty__actions">${uploadAction()}<button class="btn btn--ghost" data-action="nav-home">Volver al inicio</button></div>`,
        "library"
      )}
    </section>`;
  } else if (state.libraryTab === "albums") {
    content = `<section class="section section--tight">
      <div class="section__head">
        <h2>Todos los álbumes</h2>
        <span class="count-label">${plural(albums.length, "álbum", "álbumes")}</span>
      </div>
      ${albums.length ? albumGrid(albums) : emptyState("Sin álbumes todavía", "Escribí el nombre del álbum al subir una canción para agruparla.", `<div class="empty__actions">${uploadAction()}</div>`, "disc")}
    </section>`;
  } else if (state.libraryTab === "playlists") {
    content = `<section class="section section--tight">
      <div class="section__head">
        <div>
          <h2>Tus playlists</h2>
          <p class="section__sub">${state.playlists.length ? "Colecciones guardadas en tu cuenta." : "Armá una colección con tus propias canciones."}</p>
        </div>
        <button class="btn btn--small btn--soft" data-action="playlist-create">${icon("plus")} Nueva playlist</button>
      </div>
      ${state.playlists.length
        ? `<div class="playlist-grid">${state.playlists.map(playlistCard).join("")}</div>`
        : emptyState("Todavía no hay playlists", "Creá una y agregale canciones de tu biblioteca.", `<div class="empty__actions"><button class="btn btn--primary" data-action="playlist-create">${icon("plus")} Crear playlist</button></div>`, "list")}
    </section>`;
  } else {
    content = `
      <section class="section section--tight">
        <div class="section__head">
          <div>
            <h2>Me gusta</h2>
            <p class="section__sub">${favorites.length ? `${plural(favorites.length, "canción", "canciones")} · ${formatTotal(favoritesTotal)}` : "Marcá el corazón de una canción para guardarla acá."}</p>
          </div>
          ${favorites.length ? `<button class="btn btn--small btn--soft" data-action="play-liked">${icon("play", "icon--fill")} Reproducir</button>` : ""}
        </div>
        ${favorites.length
          ? trackRows(favorites.map((track) => track.id), { context: "liked" })
          : emptyState("Todavía no hay favoritos", "Tocá el corazón de una canción y va a aparecer en esta sección.", "", "heart")}
      </section>

      <section class="section">
        <div class="section__head">
          <div>
            <h2>Todas tus canciones</h2>
            <p class="section__sub">${plural(state.tracks.length, "archivo", "archivos")} en tu biblioteca.</p>
          </div>
          <button class="btn btn--small btn--soft" data-action="play-all">${icon("play", "icon--fill")} Reproducir todo</button>
        </div>
        ${trackRows(state.tracks.map((track) => track.id), { context: "all" })}
      </section>

      ${recent.length
        ? `<section class="section">
            <div class="section__head">
              <div>
                <h2>Escuchado hace poco</h2>
                <p class="section__sub">Tu rastro reciente en este navegador.</p>
              </div>
            </div>
            ${trackRows(recent.map((track) => track.id), { context: "recent" })}
          </section>`
        : ""}`;
  }

  return `
    <section class="page-head page-head--compact">
      <div>
        <p class="eyebrow">Tu biblioteca</p>
        <h1>Lo que es tuyo<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">Favoritos, álbumes y playlists guardados en tu cuenta Surface.</p>
      </div>
      <div class="library-stats">
        <div><strong>${state.tracks.length}</strong><span>canciones</span></div>
        <div><strong>${favorites.length}</strong><span>favoritos</span></div>
        <div><strong>${albums.length}</strong><span>álbumes</span></div>
        <div><strong>${state.playlists.length}</strong><span>playlists</span></div>
      </div>
    </section>
    <div class="tabs tabs--library" role="tablist" aria-label="Secciones de la biblioteca">
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
  const tracks = albumTracks(id);
  if (!tracks.length) return viewNotFound();

  const album = allAlbums().find((item) => item.id === id) || albumByTrack(tracks[0]);
  const total = tracks.reduce((sum, track) => sum + (Number(track.duration) || 0), 0);
  const palette = paletteFor(album.title);

  return `
    <div class="detail" style="--p1:${palette[0]};--p2:${palette[1]};--p3:${palette[2]}">
      <span class="detail__aura"></span>
      <button class="back-link" data-action="history-back">${icon("chevron-left")} Volver</button>
      <div class="detail__head">
        <div class="detail__cover">
          ${coverHTML(album, "cover--detail")}
        </div>
        <div class="detail__info">
          <p class="eyebrow">Álbum${album.year ? ` · ${album.year}` : ""}</p>
          <h1>${escapeHTML(album.title)}</h1>
          <p class="detail__line">
            <span>${escapeHTML(album.artist)}</span>
            ${album.genre ? `<span class="detail__sep">·</span><span>${escapeHTML(album.genre)}</span>` : ""}
            <span class="detail__sep">·</span>
            <span>${plural(tracks.length, "pista", "pistas")}, ${formatTotal(total)}</span>
          </p>
          <div class="detail__actions">
            <button class="btn btn--primary" data-action="play-album" data-id="${escapeHTML(album.id)}">
              ${icon("play", "icon--fill")} Reproducir
            </button>
            <button class="btn btn--soft" data-action="shuffle-album" data-id="${escapeHTML(album.id)}">
              ${icon("shuffle")} Aleatorio
            </button>
            <button class="icon-btn icon-btn--line" data-action="queue-album" data-id="${escapeHTML(album.id)}" title="Agregar a la cola" aria-label="Agregar álbum a la cola">
              ${icon("plus")}
            </button>
          </div>
          <p class="detail__sonic">${icon("cloud")} ${plural(tracks.length, "archivo", "archivos")} de tu biblioteca · guardados en tu cuenta</p>
        </div>
      </div>
      ${trackRows(tracks.map((track) => track.id), { showAlbum: false, context: `album:${album.id}` })}
      <p class="detail__foot">Álbum generado a partir de tus archivos · ${escapeHTML(state.user?.username || "tu cuenta")}</p>
    </div>`;
};

const viewPlaylist = (id) => {
  const playlist = playlistById(id);
  if (!playlist) return viewNotFound();

  const tracks = playlistTracks(playlist);
  const total = playlistDuration(playlist);
  const palette = paletteFor(playlist.name);

  return `
    <div class="detail" style="--p1:${palette[0]};--p2:${palette[1]};--p3:${palette[2]}">
      <span class="detail__aura"></span>
      <button class="back-link" data-action="history-back">${icon("chevron-left")} Volver</button>
      <div class="detail__head">
        <div class="detail__cover detail__cover--stack">
          <span class="detail__sheet detail__sheet--two"></span>
          <span class="detail__sheet detail__sheet--one"></span>
          ${coverHTML(playlistCover(playlist), "cover--detail")}
        </div>
        <div class="detail__info">
          <p class="eyebrow">Playlist</p>
          <h1>${escapeHTML(playlist.name)}</h1>
          <p class="detail__line">
            <span>${escapeHTML(state.user?.username || "WaverNote")}</span>
            <span class="detail__sep">·</span>
            <span>${plural(tracks.length, "pista", "pistas")}, ${formatTotal(total)}</span>
          </p>
          ${playlist.description ? `<p class="detail__desc">${escapeHTML(playlist.description)}</p>` : ""}
          <div class="detail__actions">
            <button class="btn btn--primary" data-action="play-playlist" data-id="${playlist.id}" ${tracks.length ? "" : "disabled"}>
              ${icon("play", "icon--fill")} Reproducir
            </button>
            <button class="btn btn--soft" data-action="shuffle-playlist" data-id="${playlist.id}" ${tracks.length ? "" : "disabled"}>
              ${icon("shuffle")} Aleatorio
            </button>
            <button class="icon-btn icon-btn--line" data-action="queue-playlist" data-id="${playlist.id}" title="Agregar a la cola" aria-label="Agregar playlist a la cola">
              ${icon("plus")}
            </button>
            <button class="icon-btn icon-btn--line" data-action="playlist-edit" data-id="${playlist.id}" title="Editar playlist" aria-label="Editar playlist">
              ${icon("edit")}
            </button>
            <button class="icon-btn icon-btn--line icon-btn--danger" data-action="playlist-delete" data-id="${playlist.id}" title="Eliminar playlist" aria-label="Eliminar playlist">
              ${icon("trash")}
            </button>
          </div>
        </div>
      </div>
      ${tracks.length
        ? trackRows(tracks.map((track) => track.id), { context: `playlist:${playlist.id}`, playlistId: playlist.id })
        : emptyState(
            "Esta playlist está vacía",
            "Agregale canciones desde tu biblioteca.",
            `<div class="empty__actions"><button class="btn btn--primary" data-action="open-library" data-tab="songs">${icon("music")} Ir a mis canciones</button></div>`,
            "list"
          )}
      <p class="detail__foot">Playlist guardada en tu cuenta Surface · ${plural(tracks.length, "pista", "pistas")}</p>
    </div>`;
};

/* ------------------------------------------------------------
   Tendencias
   ------------------------------------------------------------ */

const trendCard = (item, { compact = false } = {}) => {
  // Las tendencias de artista y género muestran su propia imagen (o el
  // mosaico de sus canciones) en vez de la carátula de un tema suelto.
  const isGroup = Boolean(item.subject);
  const playAttrs = isGroup
    ? `data-action="catalog-play" data-kind="${escapeHTML(item.kind || "artist")}" data-name="${escapeHTML(item.subject)}"`
    : `data-action="play-trend" data-id="${item.track.id}"`;
  const playLabel = escapeHTML(isGroup ? item.subject : item.track.title);

  return `
  <article class="trend-card${compact ? " trend-card--compact" : ""}${isGroup ? " trend-card--group" : ""}">
    <div class="trend-card__art">
      <button class="trend-card__open" ${playAttrs} aria-label="Reproducir ${playLabel}">
        ${item.art || coverHTML(item.track)}
      </button>
      <span class="trend-flame">${icon("fire", "icon--fill")} En llamas</span>
      <button class="trend-card__play" ${playAttrs} aria-label="Reproducir ${playLabel}" tabindex="-1">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="trend-card__meta">
      <span class="trend-card__label">${icon("fire", "icon--fill")} <span>${escapeHTML(item.label)}</span></span>
      <strong class="trend-card__title">${escapeHTML(item.subject || item.track.title)}</strong>
      <span class="trend-card__artist">${escapeHTML(
        isGroup ? item.subtitle || "" : item.track.artist || "Artista desconocido"
      )}</span>
      <p class="trend-card__reason">${escapeHTML(item.reason)}</p>
      <span class="trend-card__count">${plural(item.count, "reproducción", "reproducciones")}</span>
    </div>
  </article>`;
};

const viewTrends = () => {
  if (!state.tracks.length) {
    return `
      <section class="page-head">
        <div>
          <p class="eyebrow">Tendencias</p>
          <h1>El fuego empieza con tu música<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">Subí canciones y escuchalas: cada reproducción alimenta tus tendencias personales, una por categoría.</p>
        </div>
        ${uploadAction()}
      </section>
      ${emptyState(
        "Todavía no hay nada en llamas",
        "Cuando escuches tus canciones, acá vas a ver la más repetida, el artista que no soltás y muchos patrones más.",
        `<div class="empty__actions">${uploadAction("Subir mi primera canción")}</div>`,
        "fire"
      )}`;
  }

  const items = trendItems();
  const summary = trendSummary();
  const lead = items.length
    ? `${plural(items.length, "categoría encendida", "categorías encendidas")} con ${plural(summary.total, "reproducción", "reproducciones")} registradas en ${plural(summary.days, "día", "días")}. Cada una muestra lo que manda en ese patrón: la canción, o la imagen del artista o del género.`
    : "Todavía no hay suficientes reproducciones para encender una categoría. Dale play a lo que más te guste y volvé en un rato.";

  return `
    <section class="page-head">
      <div>
        <p class="eyebrow">${todayLabel()} · Tendencias</p>
        <h1>Lo que está en llamas<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">Tus patrones de escucha, canción por canción: la más repetida, tu artista del momento y mucho más.</p>
      </div>
      <div class="page-head__actions">
        <button class="btn btn--primary" data-action="play-trends" ${items.length ? "" : "disabled"}>${icon("play", "icon--fill")} Reproducir tendencias</button>
      </div>
    </section>

    <section class="trends-hero">
      <div class="trends-hero__copy">
        <span class="pill">${icon("fire", "icon--fill")} Tu mapa de calor</span>
        <h2>Todo lo que repite tu oído</h2>
        <p class="trends-hero__lead">${lead}</p>
        <div class="trends-hero__stats">
          <div><strong>${items.length}</strong><span>en llamas</span></div>
          <div><strong>${summary.total}</strong><span>reproducciones</span></div>
          <div><strong>${summary.artists}</strong><span>artistas</span></div>
        </div>
      </div>
      <div class="trends-hero__art" aria-hidden="true">
        <span class="trends-hero__ring trends-hero__ring--one"></span>
        <span class="trends-hero__ring trends-hero__ring--two"></span>
        <span class="trends-hero__flame">${icon("fire", "icon--fill")}</span>
        <span class="trends-hero__badge">${icon("fire", "icon--fill")} ${plural(items.length, "canción elegida", "canciones elegidas")}</span>
      </div>
    </section>

    ${items.length
      ? `<section class="section">
          <div class="section__head">
            <div>
              <h2>Lo que está mandando en cada categoría</h2>
              <p class="section__sub">Los artistas y los géneros usan su propia imagen; el resto muestra el tema que mejor representa la tendencia.</p>
            </div>
            <span class="count-label">${plural(items.length, "tendencia", "tendencias")}</span>
          </div>
          <div class="trends-grid">${items.map((item) => trendCard(item)).join("")}</div>
        </section>`
      : `<section class="section">
          <div class="trends-note">${icon("fire")}<span><strong>Todavía no hay categorías encendidas.</strong> Necesitamos al menos dos reproducciones de una canción, artista, álbum o género para marcar una tendencia. Seguí escuchando.</span></div>
        </section>`}

    <footer class="trends-foot">
      ${icon("fire", "icon--fill")}
      <p>Las tendencias son tuyas: se calculan con tus reproducciones guardadas en este navegador y se renuevan con cada play.</p>
    </footer>`;
};

/* ------------------------------------------------------------
   Artistas y géneros
   ------------------------------------------------------------ */

const catalogCard = (group) => `
  <article class="catalog-card" data-card="catalog" data-kind="${group.kind}" data-name="${escapeHTML(group.name)}">
    <div class="catalog-card__art">
      <button class="catalog-card__open" data-action="catalog-edit" data-kind="${group.kind}" data-name="${escapeHTML(group.name)}" aria-label="Editar ${escapeHTML(group.name)}">
        ${catalogArt(group)}
      </button>
      <button class="card-queue" data-action="queue-catalog" data-kind="${group.kind}" data-name="${escapeHTML(group.name)}" title="Agregar a continuación" aria-label="Agregar ${escapeHTML(group.name)} a continuación">
        ${icon("queue-add")}
      </button>
      <button class="card-play" data-action="catalog-play" data-kind="${group.kind}" data-name="${escapeHTML(group.name)}" aria-label="Reproducir ${escapeHTML(group.name)}">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="album-card__info">
      <button class="album-card__title" data-action="catalog-edit" data-kind="${group.kind}" data-name="${escapeHTML(group.name)}">${escapeHTML(group.name)}</button>
      <p>${plural(group.count, "canción", "canciones")}${group.duration ? ` · ${formatTotal(group.duration)}` : ""}</p>
    </div>
  </article>`;

const viewCatalog = () => {
  const kind = state.catalogTab === "genre" ? "genre" : "artist";
  const groups = catalogGroups(kind);
  const artists = catalogGroups("artist").length;
  const genres = catalogGroups("genre").length;

  return `
    <section class="page-head page-head--compact">
      <div>
        <p class="eyebrow">Tu música</p>
        <h1>Artistas y géneros<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">Renombrá, unificá y poné una imagen a los artistas y los géneros de tu biblioteca.</p>
      </div>
      <div class="library-stats">
        <div><strong>${artists}</strong><span>artistas</span></div>
        <div><strong>${genres}</strong><span>géneros</span></div>
      </div>
    </section>

    <div class="tabs" role="tablist" aria-label="Artistas o géneros">
      <button class="tab ${kind === "artist" ? "is-active" : ""}" role="tab" aria-selected="${kind === "artist"}" data-action="catalog-tab" data-tab="artist">Artistas</button>
      <button class="tab ${kind === "genre" ? "is-active" : ""}" role="tab" aria-selected="${kind === "genre"}" data-action="catalog-tab" data-tab="genre">Géneros</button>
    </div>

    ${
      groups.length
        ? `<section class="section section--tight">
            <div class="section__head">
              <div>
                <h2>${kind === "artist" ? "Tus artistas" : "Tus géneros"}</h2>
                <p class="section__sub">Tocá cualquiera para renombrarlo, unificarlo con otro o ponerle una imagen propia.</p>
              </div>
              <span class="count-label">${plural(groups.length, kind === "artist" ? "artista" : "género", kind === "artist" ? "artistas" : "géneros")}</span>
            </div>
            <div class="catalog-grid">${groups.map(catalogCard).join("")}</div>
          </section>`
        : `<section class="section section--tight">
            ${emptyState(
              "Todavía no hay música",
              "Subí canciones y acá vas a ver a tus artistas y a tus géneros, listos para renombrar y para ponerle imagen.",
              `<div class="empty__actions">${uploadAction()}</div>`,
              "music"
            )}
          </section>`
    }`;
};

/* ------------------------------------------------------------
   Recomendaciones
   ------------------------------------------------------------ */

const recTrackCard = (track, section) => `
  <article class="rec-card">
    <div class="rec-card__art">
      <button class="rec-card__open" data-action="play-rec-track" data-section="${section.id}" data-id="${track.id}" aria-label="Reproducir ${escapeHTML(track.title)}">
        ${coverHTML(track)}
      </button>
      <button class="rec-card__play" data-action="play-rec-track" data-section="${section.id}" data-id="${track.id}" aria-label="Reproducir ${escapeHTML(track.title)}" tabindex="-1">
        ${icon("play", "icon--fill")}
      </button>
    </div>
    <div class="rec-card__meta">
      <strong class="rec-card__title">${escapeHTML(track.title)}</strong>
      <span class="rec-card__artist">${escapeHTML(track.artist || "Artista desconocido")}</span>
      <span class="rec-card__why">${escapeHTML(section.reasons[track.id] || "Para tu día")}</span>
    </div>
  </article>`;

const recReplayRow = (track, section) => {
  const info = playInfoOf(track);
  const plays = info.count === 0 ? "Sin reproducciones" : plural(info.count, "reproducción", "reproducciones");
  return `<button class="rec-replay__row" data-action="play-rec-track" data-section="${section.id}" data-id="${track.id}">
    <span class="rec-replay__art">${coverHTML(track)}</span>
    <span class="rec-replay__info">
      <strong>${escapeHTML(track.title)}</strong>
      <small>${escapeHTML(track.artist || "Artista desconocido")} · ${escapeHTML(albumNameOf(track))}</small>
    </span>
    <span class="rec-replay__meta">
      <span class="rec-replay__plays">${plays}</span>
      <span class="rec-replay__why">${escapeHTML(section.reasons[track.id] || "La escuchaste poco")}</span>
    </span>
    <span class="rec-replay__play">${icon("play", "icon--fill")}</span>
  </button>`;
};

const recommendationSectionHTML = (section) => {
  let body = "";

  if (section.layout === "cards") {
    body = `<div class="rec-grid">${section.tracks.map((track) => recTrackCard(track, section)).join("")}</div>`;
  } else if (section.layout === "replay") {
    body = `<div class="rec-replay">${section.tracks.map((track) => recReplayRow(track, section)).join("")}</div>`;
  } else {
    body = trackRows(section.tracks.map((track) => track.id), {
      context: `rec:${section.id}`,
      reasons: section.reasons
    });
  }

  return `<section class="section rec-section rec-section--${section.id}">
    <div class="section__head">
      <div>
        <p class="eyebrow">${escapeHTML(section.eyebrow)}</p>
        <h2>${escapeHTML(section.title)}</h2>
        <p class="section__sub">${escapeHTML(section.subtitle)}</p>
      </div>
      <button class="link-btn" data-action="play-rec-section" data-section="${section.id}">${icon("play", "icon--fill")} Reproducir</button>
    </div>
    ${body}
  </section>`;
};

const viewRecommendations = () => {
  if (!state.tracks.length) {
    return `
      <section class="page-head">
        <div>
          <p class="eyebrow">Recomendaciones</p>
          <h1>Tu mezcla empieza con tu música<span class="dot-accent">.</span></h1>
          <p class="page-head__sub">Subí algunas canciones y el algoritmo va a armar una selección diaria con lo que más escuchás, lo que agregás y lo que todavía no descubriste.</p>
        </div>
        ${uploadAction()}
      </section>
      ${emptyState(
        "Todavía no hay nada para recomendar",
        "La mezcla se arma sola cuando tengas canciones en tu biblioteca.",
        `<div class="empty__actions">${uploadAction("Subir mi primera canción")}</div>`,
        "sparkles"
      )}`;
  }

  const rec = buildRecommendations();
  const mixTracks = rec.mix.map((entry) => entry.track);
  const mixReasons = rec.mix.reduce((map, entry) => {
    map[entry.track.id] = entry.reason;
    return map;
  }, {});
  const covers = mixTracks.slice(0, 4);
  const hasReplay = rec.sections.some((section) => section.id === "replay");
  const lead = rec.stats.plays
    ? `${plural(mixTracks.length, "canción", "canciones")} elegidas entre tus ${plural(state.tracks.length, "pista", "pistas")}, con ${plural(rec.stats.plays, "reproducción", "reproducciones")} registradas.`
    : "Todavía no registramos reproducciones: la mezcla arranca por lo que agregaste y por los artistas con más presencia en tu biblioteca.";

  return `
    <section class="page-head">
      <div>
        <p class="eyebrow">${todayLabel()} · Recomendaciones</p>
        <h1>Pensado para hoy<span class="dot-accent">.</span></h1>
        <p class="page-head__sub">Una mezcla que cambia cada día según lo que escuchás, lo que agregás y los artistas que más te gustan.</p>
      </div>
      <div class="page-head__actions">
        <button class="btn btn--primary" data-action="play-rec-section" data-section="mix">${icon("play", "icon--fill")} Reproducir mezcla</button>
        <button class="btn btn--ghost btn--shuffle" data-action="play-rec-section" data-section="mix" data-shuffle="true" aria-label="Reproducir la mezcla en aleatorio" title="Aleatorio">${icon("shuffle")}</button>
      </div>
    </section>

    <section class="rec-hero">
      <div class="rec-hero__copy">
        <span class="pill">${icon("sparkles")} Mezcla del día</span>
        <h2>Olas para hoy</h2>
        <p class="rec-hero__lead">${lead}</p>
        <div class="rec-hero__stats">
          <div><strong>${state.tracks.length}</strong><span>pistas</span></div>
          <div><strong>${rec.stats.artists}</strong><span>artistas</span></div>
          <div><strong>${rec.stats.unheard}</strong><span>sin escuchar</span></div>
        </div>
        <ul class="rec-picks">
          ${rec.mix
            .slice(0, 3)
            .map(
              (entry, index) => `<li>
                <button class="rec-pick" data-action="play-rec-track" data-section="mix" data-id="${entry.track.id}">
                  <span class="rec-pick__num">0${index + 1}</span>
                  <span class="rec-pick__art">${coverHTML(entry.track)}</span>
                  <span class="rec-pick__info">
                    <strong>${escapeHTML(entry.track.title)}</strong>
                    <small>${escapeHTML(entry.track.artist || "Artista desconocido")}</small>
                  </span>
                  <span class="rec-pick__why">${escapeHTML(entry.reason)}</span>
                </button>
              </li>`
            )
            .join("")}
        </ul>
      </div>
      <div class="rec-hero__art ${covers.length === 1 ? "rec-hero__art--solo" : ""}">
        ${covers
          .map(
            (track, index) => `<button class="rec-hero__cover rec-hero__cover--${index + 1}" data-action="play-rec-track" data-section="mix" data-id="${track.id}" aria-label="Reproducir ${escapeHTML(track.title)}">
              ${coverHTML(track)}
            </button>`
          )
          .join("")}
        <span class="rec-hero__badge">${icon("wave")} ${plural(mixTracks.length, "pista", "pistas")} para hoy</span>
      </div>
    </section>

    <section class="section rec-section rec-section--mix">
      <div class="section__head">
        <div>
          <p class="eyebrow">Mezcla completa</p>
          <h2>Tu mezcla de hoy</h2>
          <p class="section__sub">Cada canción tiene un motivo: lo que escuchaste, lo que agregaste o lo que todavía te falta descubrir.</p>
        </div>
        <span class="count-label">${plural(mixTracks.length, "canción", "canciones")}</span>
      </div>
      ${trackRows(
        mixTracks.map((track) => track.id),
        { context: "rec:mix", reasons: mixReasons }
      )}
    </section>

    ${rec.sections.map(recommendationSectionHTML).join("")}

    ${hasReplay ? "" : `<p class="rec-note">${icon("clock")}<span><strong>Vuelve a escuchar</strong> va a aparecer cuando tus canciones tengan al menos un día en la biblioteca y pocas reproducciones.</span></p>`}

    <footer class="rec-foot">
      ${icon("sparkles")}
      <p>La mezcla se renueva cada día. Cuanto más escuches y agregues, más precisa se vuelve.</p>
    </footer>`;
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
    case "recommendations":
      content = viewRecommendations();
      break;
    case "trends":
      content = viewTrends();
      break;
    case "catalog":
      content = viewCatalog();
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
    route.view === "search"
      ? "search"
      : route.view === "recommendations"
        ? "recommendations"
        : route.view === "trends"
          ? "trends"
          : route.view === "catalog"
            ? "catalog"
            : route.view === "library"
              ? "library"
              : route.view === "home"
                ? "home"
                : "";

  $$(".nav__item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.nav === active);
  });

  $$(".mobile-nav__item").forEach((item) => {
    const nav = item.dataset.mobileNav;
    if (!nav) return;
    const moreActive = nav === "more" && (active === "catalog" || active === "recommendations");
    item.classList.toggle("is-active", nav === active || moreActive);
  });

  $$(".side-playlist").forEach((item) => {
    item.classList.toggle("is-active", route.view === "playlist" && item.dataset.id === route.id);
  });

  updateHistoryButtons();
};
