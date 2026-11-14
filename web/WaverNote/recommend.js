/* ============================================================
   WaverNote · recomendaciones
   Mezcla diaria determinista construida con lo que el usuario
   escucha, lo que agrega, sus artistas y sus canciones pendientes.
   ============================================================ */

const REC_VERSION = "v1";
const REC_DAY_MS = 86400000;

const localDateKey = (date = new Date()) => {
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
};

const seededRandom = (seed) => {
  let value = seed >>> 0;
  return () => {
    value += 0x6d2b79f5;
    let t = value;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
};

const daysBetween = (value, now = Date.now()) => {
  const time = new Date(value).getTime();
  if (!Number.isFinite(time)) return 999;
  return Math.max(0, (now - time) / REC_DAY_MS);
};

const playInfoOf = (track) => {
  const saved = state.plays?.[String(track.id)] || null;
  const count = Math.max(0, Number(saved?.count) || 0);
  const lastPlayedAt = saved?.lastPlayedAt || null;
  return {
    count,
    lastPlayedAt,
    daysSincePlayed: lastPlayedAt ? daysBetween(lastPlayedAt) : null
  };
};

const artistLabelOf = (track) => (track?.artist || "").trim() || "Artista desconocido";

const buildRecommendations = () => {
  const tracks = state.tracks.slice();
  const dateKey = localDateKey();
  const seed = hashString(`${state.user?.id || 0}|${dateKey}|${REC_VERSION}`);
  const random = seededRandom(seed);
  const jitter = new Map(tracks.map((track) => [track.id, random()]));

  const infos = new Map();
  const artists = new Map();

  tracks.forEach((track) => {
    const plays = playInfoOf(track);
    const info = {
      ...plays,
      daysAdded: daysBetween(track.createdAt),
      liked: isLiked(track.id),
      artist: artistLabelOf(track)
    };
    infos.set(track.id, info);

    const key = info.artist.toLowerCase();
    if (!artists.has(key)) {
      artists.set(key, { name: info.artist, tracks: [], plays: 0, likes: 0 });
    }
    const bucket = artists.get(key);
    bucket.tracks.push(track);
    bucket.plays += plays.count;
    if (info.liked) bucket.likes += 1;
  });

  const artistList = Array.from(artists.values()).sort(
    (a, b) =>
      b.plays - a.plays ||
      b.likes - a.likes ||
      b.tracks.length - a.tracks.length ||
      a.name.localeCompare(b.name, "es")
  );
  const topArtist = artistList[0] || null;
  const topArtistPlays = artistList.reduce((max, item) => Math.max(max, item.plays), 0);

  const reasonFor = (track) => {
    const info = infos.get(track.id);
    if (info.count === 0) return info.daysAdded <= 10 ? "Recién agregada" : "Todavía no la escuchaste";
    if (info.liked) return "De tus favoritas";
    if (topArtistPlays > 0 && info.artist.toLowerCase() === topArtist?.name.toLowerCase()) {
      return `Más de ${info.artist}`;
    }
    if (info.daysAdded <= 7) return "Nueva en tu biblioteca";
    if (info.daysSincePlayed !== null && info.daysSincePlayed >= 14) return "Hace tiempo que no suena";
    return "Para tu día";
  };

  const scoreOf = (track) => {
    const info = infos.get(track.id);
    const bucket = artists.get(info.artist.toLowerCase());
    const affinity = topArtistPlays > 0 && bucket ? bucket.plays / topArtistPlays : 0;

    let score = affinity * 34;
    if (info.liked) score += 10;
    score += Math.log1p(info.count) * 7;
    score += Math.max(0, 16 - info.daysAdded) * 1.4;
    if (info.count === 0) score += 16;
    if (info.daysSincePlayed !== null && info.daysSincePlayed >= 14) score += 6;
    score += (jitter.get(track.id) || 0) * 9;
    return score;
  };

  const ranked = tracks
    .map((track) => ({ track, score: scoreOf(track) }))
    .sort((a, b) => b.score - a.score || a.track.id - b.track.id);

  const mixEntries = ranked.slice(0, 8).map(({ track }) => ({ track, reason: reasonFor(track) }));

  // En bibliotecas chicas permitimos que las secciones repitan la mezcla
  // para que la página no quede vacía; en bibliotecas grandes priorizamos variedad.
  const avoidRepeats = tracks.length > 8;
  const used = new Set(avoidRepeats ? mixEntries.map((entry) => entry.track.id) : []);
  const pick = (list, limit = 6) => {
    const fresh = list.filter((track) => !used.has(track.id));
    const pool = fresh.length >= Math.min(3, limit) ? fresh : list;
    const chosen = pool.slice(0, limit);
    chosen.forEach((track) => used.add(track.id));
    return chosen;
  };

  const reasonMap = (list, fallback) => {
    const map = {};
    list.forEach((track) => {
      map[track.id] = fallback ? fallback(track) : reasonFor(track);
    });
    return map;
  };

  const artistTracks = topArtist
    ? topArtist.tracks.slice().sort((a, b) => scoreOf(b) - scoreOf(a) || a.id - b.id)
    : [];
  const artistPick = pick(artistTracks, 6);

  const recentPick = pick(
    tracks
      .slice()
      .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0) || b.id - a.id),
    5
  );

  const discoverPick = pick(
    ranked.filter(({ track }) => infos.get(track.id).count === 0).map(({ track }) => track),
    5
  );

  const replayPick = tracks
    .filter((track) => {
      const info = infos.get(track.id);
      return info.daysAdded >= 1 && info.count <= 1;
    })
    .sort((a, b) => {
      const infoA = infos.get(a.id);
      const infoB = infos.get(b.id);
      return (
        infoA.count - infoB.count ||
        (jitter.get(a.id) || 0) - (jitter.get(b.id) || 0) ||
        infoB.daysAdded - infoA.daysAdded
      );
    })
    .slice(0, 8);

  // Con muy pocas pistas la mezcla ya las muestra todas: evitar secciones
  // que repitan exactamente el mismo contenido.
  const showExtras = tracks.length >= 4;

  const sections = [
    showExtras && artistPick.length
      ? {
          id: "artist",
          eyebrow: topArtistPlays > 0 ? "Por artista" : "De tu biblioteca",
          title:
            topArtistPlays > 0 ? `Porque escuchaste a ${topArtist.name}` : `Un poco más de ${topArtist.name}`,
          subtitle:
            topArtistPlays > 0
              ? `${plural(topArtistPlays, "reproducción", "reproducciones")} de este artista.`
              : "Uno de los artistas que ya tenés en tu biblioteca.",
          tracks: artistPick,
          reasons: reasonMap(artistPick, () =>
            topArtistPlays > 0 ? `Más de ${topArtist.name}` : "De tu biblioteca"
          ),
          layout: "rows"
        }
      : null,
    showExtras && recentPick.length
      ? {
          id: "recent",
          eyebrow: "Novedades",
          title: "Recién agregadas",
          subtitle: "Lo último que sumaste, para escucharlo mientras está fresco.",
          tracks: recentPick,
          reasons: reasonMap(recentPick, (track) =>
            infos.get(track.id).daysAdded <= 3 ? "Recién agregada" : "Nueva en tu biblioteca"
          ),
          layout: "cards"
        }
      : null,
    showExtras && discoverPick.length
      ? {
          id: "discover",
          eyebrow: "Para descubrir",
          title: "Todavía no las escuchaste",
          subtitle: "Canciones de tu biblioteca que siguen esperando su primera reproducción.",
          tracks: discoverPick,
          reasons: reasonMap(discoverPick, () => "Sin reproducciones"),
          layout: "cards"
        }
      : null,
    replayPick.length
      ? {
          id: "replay",
          eyebrow: "Cada tanto",
          title: "Vuelve a escuchar",
          subtitle: "Las que menos escuchaste desde que las agregaste. Rotan cada día.",
          tracks: replayPick,
          reasons: reasonMap(replayPick, (track) =>
            infos.get(track.id).count === 0 ? "Nunca la escuchaste" : "La escuchaste una vez"
          ),
          layout: "replay"
        }
      : null
  ].filter(Boolean);

  const result = {
    dateKey,
    seed,
    topArtist: topArtist?.name || "",
    stats: {
      plays: tracks.reduce((sum, track) => sum + (infos.get(track.id)?.count || 0), 0),
      unheard: tracks.filter((track) => (infos.get(track.id)?.count || 0) === 0).length,
      artists: artistList.length
    },
    mix: mixEntries,
    sections
  };

  state.recommendations = result;
  return result;
};

const recommendationTrackIds = (sectionId = "mix") => {
  const rec = state.recommendations || buildRecommendations();
  if (sectionId === "mix") return rec.mix.map((entry) => entry.track.id);
  const section = rec.sections.find((item) => item.id === sectionId);
  return section ? section.tracks.map((track) => track.id) : [];
};

const recommendationSection = (sectionId) => {
  const rec = state.recommendations || buildRecommendations();
  return rec.sections.find((item) => item.id === sectionId) || null;
};

/* ------------------------------------------------------------
   Aviso semanal: canciones que hace tiempo no suenan
   Se muestra como maximo una vez cada siete dias por usuario y
   solo cuando hay al menos tres candidatas, para no insistir.
   ------------------------------------------------------------ */

const LISTEN_REMINDER_PREFIX = "wavernote.listenReminder.v1.";
const LISTEN_REMINDER_DAYS = 7;
const LISTEN_REMINDER_DAY_MS = 86400000;
const LISTEN_REMINDER_MIN = 3;
const LISTEN_REMINDER_MAX = 6;
const LISTEN_REMINDER_UNPLAYED_DAYS = 14;
const LISTEN_REMINDER_SILENT_DAYS = 21;

const listenReminderStorageKey = () => `${LISTEN_REMINDER_PREFIX}${state.user?.id || "local"}`;

const listenReminderLastShown = () => {
  const saved = readJSON(listenReminderStorageKey(), null);
  const time = Number(saved?.lastShownAt) || 0;
  return Number.isFinite(time) ? time : 0;
};

const listenReminderMarkShown = () => {
  writeJSON(listenReminderStorageKey(), { lastShownAt: Date.now() });
};

const listenReminderCandidates = () => {
  const now = Date.now();

  return state.tracks
    .map((track) => {
      const stats = playStatsOf(track);
      const addedTime = new Date(track.createdAt || 0).getTime();
      const lastPlayedAt = stats.lastPlayedAt ? new Date(stats.lastPlayedAt).getTime() : 0;
      const daysAdded =
        track.createdAt && Number.isFinite(addedTime)
          ? Math.max(0, (now - addedTime) / LISTEN_REMINDER_DAY_MS)
          : 0;
      const daysSincePlayed = lastPlayedAt
        ? Math.max(0, (now - lastPlayedAt) / LISTEN_REMINDER_DAY_MS)
        : null;

      const quiet =
        stats.count === 0
          ? daysAdded >= LISTEN_REMINDER_UNPLAYED_DAYS
          : daysSincePlayed !== null && daysSincePlayed >= LISTEN_REMINDER_SILENT_DAYS;

      return { track, stats, quiet, daysAdded, daysSincePlayed };
    })
    .filter((item) => item.quiet)
    .sort((a, b) => {
      const quietA = a.stats.count === 0 ? a.daysAdded : a.daysSincePlayed || 0;
      const quietB = b.stats.count === 0 ? b.daysAdded : b.daysSincePlayed || 0;
      return quietB - quietA || a.track.id - b.track.id;
    })
    .slice(0, LISTEN_REMINDER_MAX);
};

const listenReminderStatus = (item) => {
  if (item.stats.count === 0) {
    return `Nunca la escuchaste · hace ${plural(
      Math.max(1, Math.floor(item.daysAdded)),
      "día",
      "días"
    )} que está en tu biblioteca`;
  }
  return `Hace ${plural(
    Math.max(1, Math.floor(item.daysSincePlayed || 0)),
    "día",
    "días"
  )} que no suena`;
};

const openListenReminder = (items) => {
  const ids = items.map((item) => item.track.id).join(",");

  openModal({
    title: "¿Volvemos a escucharlas?",
    eyebrow: "Tu música",
    body: `
      <div class="listen-reminder">
        <p class="listen-reminder__lead">Estas canciones hace tiempo que no aparecen por acá. ¿Les damos otra vuelta?</p>
        <ul class="listen-reminder__list">
          ${items
            .map(
              (item) => `<li class="listen-reminder__item">
                <span class="listen-reminder__art">${coverHTML(item.track)}</span>
                <span class="listen-reminder__copy">
                  <strong>${escapeHTML(item.track.title)}</strong>
                  <small>${escapeHTML(item.track.artist || "Artista desconocido")}</small>
                  <em>${escapeHTML(listenReminderStatus(item))}</em>
                </span>
                <button class="listen-reminder__play" type="button" data-action="listen-reminder-play" data-id="${item.track.id}" aria-label="Reproducir «${escapeHTML(item.track.title)}» ahora">
                  ${icon("play", "icon--fill")}
                </button>
              </li>`
            )
            .join("")}
        </ul>
        <p class="listen-reminder__note">Te avisamos una vez por semana. Podés cerrarlo cuando quieras.</p>
      </div>
      <div class="modal__actions">
        <button class="btn btn--ghost" data-action="close-modal">Ahora no</button>
        <button class="btn btn--soft" data-action="listen-reminder-queue" data-ids="${ids}">${icon("queue-add")} Sumar a la cola</button>
        <button class="btn btn--primary" data-action="listen-reminder-play-all" data-ids="${ids}" data-autofocus>${icon("play", "icon--fill")} Reproducir ahora</button>
      </div>`
  });
};

let listenReminderShown = false;

const maybeShowListenReminder = () => {
  if (listenReminderShown) return;
  if (!state.ready || state.tracks.length < 3) return;
  if (document.getElementById("modal")?.classList.contains("is-open")) return;

  const now = Date.now();
  if (now - listenReminderLastShown() < LISTEN_REMINDER_DAYS * LISTEN_REMINDER_DAY_MS) return;

  const items = listenReminderCandidates();
  if (items.length < LISTEN_REMINDER_MIN) return;

  listenReminderShown = true;
  listenReminderMarkShown();
  openListenReminder(items);
};

window.WaverNoteListenReminder = { maybeShow: maybeShowListenReminder };
