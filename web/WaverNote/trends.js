/* ============================================================
   WaverNote · tendencias
   Una canción por categoría, elegida con el historial real
   de reproducciones del usuario. Cada categoría muestra un
   único tema y el motivo por el que está en llamas.
   ============================================================ */

const TREND_DAY_MS = 86400000;
const TREND_STREAK_GAP = 20 * 60 * 1000;

const trendDateKey = (time) => {
  const date = new Date(time);
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
};

// La semana arranca el lunes a las 00:00 y se renueva sola: las categorías
// solo cuentan las reproducciones de la semana en curso.
const trendWeekStart = (time = Date.now()) => {
  const date = new Date(time);
  date.setHours(0, 0, 0, 0);
  const day = date.getDay();
  date.setDate(date.getDate() - ((day + 6) % 7));
  return date.getTime();
};

const trendWeekRange = (time = Date.now()) => {
  const startDate = new Date(trendWeekStart(time));
  const endDate = new Date(startDate);
  // Sumar días con setDate respeta los cambios de horario de verano.
  endDate.setDate(endDate.getDate() + 7);
  return { start: startDate.getTime(), end: endDate.getTime() };
};

const trendWeekKey = (range = trendWeekRange()) => trendDateKey(range.start);

const trendWeekLabel = (range = trendWeekRange()) => {
  const start = new Date(range.start);
  const end = new Date(range.end - 1);
  const day = (date) => new Intl.DateTimeFormat("es", { day: "numeric" }).format(date);
  const month = (date) => new Intl.DateTimeFormat("es", { month: "long" }).format(date);

  if (start.getMonth() === end.getMonth() && start.getFullYear() === end.getFullYear()) {
    return `${day(start)} al ${day(end)} de ${month(start)}`;
  }
  return `${day(start)} de ${month(start)} al ${day(end)} de ${month(end)}`;
};

const trendLatestOf = (info) => {
  const time = new Date(info?.lastPlayedAt || 0).getTime();
  return Number.isFinite(time) && time > 0 ? time : 0;
};

const trendPlayEntries = () => {
  const entries = [];
  Object.entries(state.plays || {}).forEach(([id, info]) => {
    const track = trackById(id);
    const count = Math.max(0, Number(info?.count) || 0);
    if (!track || !count) return;
    entries.push({ track, info, count });
  });
  return entries;
};

const trendEvents = () => {
  const events = [];
  trendPlayEntries().forEach(({ track, info }) => {
    const list = Array.isArray(info?.events) ? info.events : [];
    list.forEach((value) => {
      const at = cleanPlayEvent(value);
      if (at) events.push({ track, at });
    });
  });
  return events.sort((a, b) => a.at - b.at);
};

const trendEventsInRange = (range = trendWeekRange()) =>
  trendEvents().filter(({ at }) => at >= range.start && at < range.end);

const trendEntriesFromEvents = (events) => {
  const buckets = new Map();

  events.forEach(({ track, at }) => {
    let bucket = buckets.get(track.id);
    if (!bucket) {
      bucket = { track, count: 0, lastAt: at };
      buckets.set(track.id, bucket);
    }
    bucket.count += 1;
    if (at > bucket.lastAt) bucket.lastAt = at;
  });

  return Array.from(buckets.values()).map(({ track, count, lastAt }) => ({
    track,
    count,
    info: { count, lastPlayedAt: new Date(lastAt).toISOString() }
  }));
};

const trendTopEntry = (entries) =>
  entries
    .slice()
    .sort(
      (a, b) =>
        b.count - a.count ||
        trendLatestOf(b.info) - trendLatestOf(a.info) ||
        String(a.track.title).localeCompare(String(b.track.title), "es")
    )[0] || null;

const trendGroupBy = (entries, keyOf) => {
  const groups = new Map();

  entries.forEach((entry) => {
    // Un tema puede tener varios artistas: la reproducción suma para cada
    // uno sin contar dos veces al mismo colaborador.
    const raw = keyOf(entry.track);
    const keys = (Array.isArray(raw) ? raw : [raw])
      .map((value) => String(value || "").trim())
      .filter(Boolean);
    const seen = new Set();

    keys.forEach((key) => {
      const keyId = normalize(key);
      if (!keyId || seen.has(keyId)) return;
      seen.add(keyId);

      let group = groups.get(key);
      if (!group) {
        group = { key, total: 0, tracks: [], lastAt: 0 };
        groups.set(key, group);
      }

      group.total += entry.count;
      group.tracks.push(entry);
      group.lastAt = Math.max(group.lastAt, trendLatestOf(entry.info));
    });
  });

  return Array.from(groups.values());
};

const trendTopGroup = (groups) =>
  groups
    .slice()
    .sort(
      (a, b) =>
        b.total - a.total ||
        b.lastAt - a.lastAt ||
        a.key.localeCompare(b.key, "es")
    )[0] || null;

const trendTopOfEvents = (events) => {
  const groups = new Map();

  events.forEach(({ track, at }) => {
    let group = groups.get(track.id);
    if (!group) {
      group = { track, count: 0, at };
      groups.set(track.id, group);
    }
    group.count += 1;
    if (at > group.at) group.at = at;
  });

  return (
    Array.from(groups.values()).sort((a, b) => b.count - a.count || b.at - a.at)[0] || null
  );
};

const trendPeakDay = (events) => {
  const buckets = new Map();

  events.forEach(({ track, at }) => {
    const key = `${track.id}|${trendDateKey(at)}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { track, count: 0, at };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (at > bucket.at) bucket.at = at;
  });

  return (
    Array.from(buckets.values()).sort((a, b) => b.count - a.count || b.at - a.at)[0] || null
  );
};

const trendStreak = (events) => {
  let best = null;
  let run = null;

  events.forEach(({ track, at }) => {
    if (run && run.track.id === track.id && at - run.lastAt <= TREND_STREAK_GAP) {
      run.count += 1;
      run.lastAt = at;
    } else {
      run = { track, count: 1, lastAt: at };
    }

    if (!best || run.count > best.count || (run.count === best.count && run.lastAt > best.lastAt)) {
      best = { track: run.track, count: run.count, lastAt: run.lastAt };
    }
  });

  return best;
};

const trendItems = (range = trendWeekRange()) => {
  const events = trendEventsInRange(range);
  const entries = trendEntriesFromEvents(events);
  if (!entries.length) return [];

  const now = Date.now();
  const items = [];

  const add = (id, label, reason, track, count, at = now, extra = {}) => {
    if (!track) return;
    items.push({
      id,
      label,
      reason,
      track,
      count: Math.max(1, Number(count) || 1),
      at,
      ...extra
    });
  };

  const overall = trendTopEntry(entries);
  if (overall) {
    add(
      "top",
      "La más escuchada",
      `Escuchada ${plural(overall.count, "vez", "veces")} esta semana.`,
      overall.track,
      overall.count,
      trendLatestOf(overall.info)
    );
  }

  const artist = trendTopGroup(trendGroupBy(entries, (track) => trackArtists(track)));
  if (artist && artist.total >= 2) {
    const best = trendTopEntry(artist.tracks);
    add(
      "artist",
      "Artista del momento",
      `${plural(artist.total, "reproducción", "reproducciones")} de ${artist.key} esta semana.`,
      best?.track,
      artist.total,
      artist.lastAt,
      {
        kind: "artist",
        subject: artist.key,
        subtitle: catalogGroupSubtitle("artist", artist.key),
        art: catalogArtHTML("artist", artist.key)
      }
    );
  }

  const album = trendTopGroup(trendGroupBy(entries, (track) => (track.album || "").trim()));
  if (album && album.total >= 2) {
    const best = trendTopEntry(album.tracks);
    add(
      "album",
      "El álbum que no soltás",
      `${plural(album.total, "reproducción", "reproducciones")} de «${album.key}» esta semana.`,
      best?.track,
      album.total,
      album.lastAt
    );
  }

  const genre = trendTopGroup(trendGroupBy(entries, (track) => (track.genre || "").trim()));
  if (genre && genre.total >= 2) {
    const best = trendTopEntry(genre.tracks);
    add(
      "genre",
      "El género que domina",
      `${plural(genre.total, "reproducción", "reproducciones")} de ${genre.key} esta semana.`,
      best?.track,
      genre.total,
      genre.lastAt,
      {
        kind: "genre",
        subject: genre.key,
        subtitle: catalogGroupSubtitle("genre", genre.key),
        art: catalogArtHTML("genre", genre.key)
      }
    );
  }

  // Comparar con la semana anterior da una categoría propia: cuál creció más
  // en vez de repetir la más escuchada.
  const previousStart = new Date(range.start);
  previousStart.setDate(previousStart.getDate() - 7);
  const previousRange = { start: previousStart.getTime(), end: range.start };
  const previousCounts = new Map();
  trendEventsInRange(previousRange).forEach(({ track }) => {
    const id = Number(track.id);
    previousCounts.set(id, (previousCounts.get(id) || 0) + 1);
  });
  const growth = entries
    .map((entry) => {
      const previous = previousCounts.get(Number(entry.track.id)) || 0;
      return { ...entry, previous, gain: entry.count - previous };
    })
    .filter((entry) => entry.count >= 2 && entry.gain > 0)
    .sort(
      (a, b) =>
        b.gain - a.gain ||
        b.count - a.count ||
        trendLatestOf(b.info) - trendLatestOf(a.info)
    )[0];
  if (growth) {
    add(
      "week",
      "La que más subió",
      `${plural(growth.count, "reproducción", "reproducciones")} esta semana y ${growth.gain} más que la semana pasada.`,
      growth.track,
      growth.count,
      trendLatestOf(growth.info)
    );
  }

  if (events.length >= 2) {
    const night = trendTopOfEvents(
      events.filter(({ at }) => {
        const hour = new Date(at).getHours();
        return hour >= 22 || hour < 6;
      })
    );
    if (night && night.count >= 2) {
      add(
        "night",
        "La reina de la noche",
        `${plural(night.count, "reproducción", "reproducciones")} de noche esta semana.`,
        night.track,
        night.count,
        night.at
      );
    }

    const weekend = trendTopOfEvents(
      events.filter(({ at }) => {
        const day = new Date(at).getDay();
        return day === 0 || day === 6;
      })
    );
    if (weekend && weekend.count >= 2) {
      add(
        "weekend",
        "La favorita del finde",
        `${plural(weekend.count, "reproducción", "reproducciones")} de fin de semana.`,
        weekend.track,
        weekend.count,
        weekend.at
      );
    }

    const peak = trendPeakDay(events);
    if (peak && peak.count >= 2) {
      add(
        "peak",
        "La de un solo día",
        `${plural(peak.count, "reproducción", "reproducciones")} el ${dateLabel(peak.at)}.`,
        peak.track,
        peak.count,
        peak.at
      );
    }

    const streak = trendStreak(events);
    if (streak && streak.count >= 3) {
      add(
        "streak",
        "Racha encendida",
        `${plural(streak.count, "reproducción seguida", "reproducciones seguidas")} esta semana.`,
        streak.track,
        streak.count,
        streak.lastAt
      );
    }
  }

  const favorite = trendTopEntry(entries.filter(({ track }) => isLiked(track.id)));
  if (favorite && favorite.count >= 2) {
    add(
      "favorite",
      "La consentida",
      `${plural(favorite.count, "reproducción", "reproducciones")} esta semana y la marcaste con corazón.`,
      favorite.track,
      favorite.count,
      trendLatestOf(favorite.info)
    );
  }

  const fresh = entries.filter(({ track }) => {
    const created = new Date(track.createdAt || 0).getTime();
    return created > 0 && now - created <= 30 * TREND_DAY_MS;
  });
  const freshTop = trendTopEntry(fresh);
  if (freshTop && freshTop.count >= 2) {
    add(
      "fresh",
      "La revelación",
      `La subiste el ${dateLabel(freshTop.track.createdAt)} y ya lleva ${plural(
        freshTop.count,
        "reproducción",
        "reproducciones"
      )} esta semana.`,
      freshTop.track,
      freshTop.count,
      trendLatestOf(freshTop.info)
    );
  }

  return items;
};

const trendTrackIds = () => {
  const seen = new Set();
  return trendItemsForSet()
    .map((item) => item.track?.id)
    .filter(Boolean)
    .filter((id) => {
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
};

const trendSummary = (range = trendWeekRange()) => {
  const events = trendEventsInRange(range);
  const days = new Set(events.map(({ at }) => trendDateKey(at)));
  const artists = new Set();

  events.forEach(({ track }) => {
    trackArtists(track).forEach((name) => artists.add(name));
  });

  return {
    total: events.length,
    days: days.size,
    artists: artists.size
  };
};

/* ------------------------------------------------------------
   Sets de tendencias y marcos
   ------------------------------------------------------------ */

const TREND_FRAME_OPTIONS = [
  { value: "none", label: "Sin marco" },
  { value: "ocean", label: "Océano" },
  { value: "mint", label: "Verde" },
  { value: "sun", label: "Dorado" },
  { value: "coral", label: "Coral" },
  { value: "violet", label: "Violeta" },
  { value: "rainbow", label: "Arcoíris" },
  { value: "custom", label: "Personalizado" }
];
const TREND_FRAME_VALUES = new Set(TREND_FRAME_OPTIONS.map((option) => option.value));
const TREND_FRAME_DEFAULT_COLOR = "#4aa8ff";

const TREND_CATEGORY_OPTIONS = [
  { value: "top", label: "La más escuchada" },
  { value: "artist", label: "Artista del momento" },
  { value: "album", label: "El álbum que no soltás" },
  { value: "genre", label: "El género que domina" },
  { value: "week", label: "La que más subió" },
  { value: "night", label: "La reina de la noche" },
  { value: "weekend", label: "La favorita del finde" },
  { value: "peak", label: "La de un solo día" },
  { value: "streak", label: "Racha encendida" },
  { value: "favorite", label: "La consentida" },
  { value: "fresh", label: "La revelación" }
];
const TREND_CATEGORY_VALUES = new Set(TREND_CATEGORY_OPTIONS.map((option) => option.value));
const TREND_ALL_CATEGORIES = TREND_CATEGORY_OPTIONS.map((option) => option.value);
const TREND_SET_LIMIT = 24;
const TREND_SET_TRACK_LIMIT = 60;

const TREND_PRESET_SETS = [
  {
    id: "all",
    name: "Panorama completo",
    hint: "Todas las categorías",
    frame: "rainbow",
    categories: TREND_ALL_CATEGORIES,
    preset: true
  },
  {
    id: "songs",
    name: "Solo canciones",
    hint: "Sin artistas ni álbumes",
    frame: "ocean",
    categories: ["top", "week", "night", "weekend", "peak", "streak", "favorite", "fresh"],
    preset: true
  },
  {
    id: "groups",
    name: "Por nombre",
    hint: "Artistas, álbumes y géneros",
    frame: "mint",
    categories: ["artist", "album", "genre"],
    preset: true
  },
  {
    id: "night",
    name: "Modo noche",
    hint: "Lo que suena después de las 22",
    frame: "violet",
    categories: ["night", "streak", "peak", "top"],
    preset: true
  },
  {
    id: "weekend",
    name: "Fin de semana",
    hint: "Sábados y domingos",
    frame: "sun",
    categories: ["weekend", "week", "top", "favorite"],
    preset: true
  },
  {
    id: "discover",
    name: "Para redescubrir",
    hint: "Nuevas, consentidas y de un solo día",
    frame: "coral",
    categories: ["fresh", "favorite", "peak", "album", "top"],
    preset: true
  }
];
const TREND_PRESET_IDS = new Set(TREND_PRESET_SETS.map((set) => set.id));

const normalizeTrendFrame = (value) => {
  const key = String(value ?? "");
  return TREND_FRAME_VALUES.has(key) ? key : "none";
};

// El color propio se guarda como hex de 6 dígitos para poder pasarlo directo
// a las variables CSS del marco. Acepta también la forma corta (#abc).
const normalizeTrendColor = (value) => {
  const raw = String(value ?? "").trim().toLowerCase();
  const short = /^#?([0-9a-f]{3})$/.exec(raw);
  if (short) {
    const [r, g, b] = short[1];
    return `#${r}${r}${g}${g}${b}${b}`;
  }
  const long = /^#?([0-9a-f]{6})$/.exec(raw);
  return long ? `#${long[1]}` : TREND_FRAME_DEFAULT_COLOR;
};

const trendColorRgb = (color) => {
  const hex = normalizeTrendColor(color).slice(1);
  return [0, 2, 4].map((index) => parseInt(hex.slice(index, index + 2), 16)).join(", ");
};

const trendFrameStyle = (frame, color) =>
  normalizeTrendFrame(frame) === "custom"
    ? ` style="--frame-color:${normalizeTrendColor(color)};--frame-rgb:${trendColorRgb(color)}"`
    : "";

const normalizeTrendCategories = (value) => {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item)).filter((item) => TREND_CATEGORY_VALUES.has(item)))];
};

const normalizeTrendTrackIds = (value) => {
  if (!Array.isArray(value)) return [];
  return [
    ...new Set(value.map(Number).filter((id) => Number.isFinite(id) && id > 0))
  ].slice(0, TREND_SET_TRACK_LIMIT);
};

const normalizeTrendSet = (value) => {
  if (!value || typeof value !== "object") return null;
  const id = String(value.id || "").trim();
  const name = String(value.name || "").trim().slice(0, 48);
  if (!id || !name || TREND_PRESET_IDS.has(id)) return null;
  const categories = normalizeTrendCategories(value.categories);
  const tracks = normalizeTrendTrackIds(value.tracks);
  if (!categories.length && !tracks.length) return null;
  return {
    id,
    name,
    frame: normalizeTrendFrame(value.frame),
    color: normalizeTrendColor(value.color),
    categories,
    tracks,
    preset: false
  };
};

const trendAllSets = () => [...TREND_PRESET_SETS, ...state.trendSets];

const trendSetById = (id) => trendAllSets().find((set) => set.id === String(id || "")) || null;

const trendActiveSet = () => trendSetById(state.trendActiveSet) || TREND_PRESET_SETS[0];

const trendSetsSnapshot = () =>
  state.trendSets.map((set) => ({
    id: set.id,
    name: set.name,
    frame: set.frame,
    color: set.color,
    categories: [...set.categories],
    tracks: [...set.tracks]
  }));

const trendActiveSetId = () => trendActiveSet().id;

const trendItemsForSet = (set = trendActiveSet(), allItems = null) => {
  const source = allItems || trendItems();
  const categories = new Set(set?.categories || []);
  const items = categories.size ? source.filter((item) => categories.has(item.id)) : [];
  // Una elección manual solo se descarta si otra tarjeta ya muestra esa misma
  // canción. Los artistas, álbumes y géneros muestran su propio nombre, así
  // que la canción elegida sigue teniendo su lugar.
  const seenTracks = new Set(
    items
      .filter((item) => item.track && !item.subject)
      .map((item) => Number(item.track.id))
  );
  const manual = [];

  (set?.tracks || []).forEach((id) => {
    const track = trackById(id);
    if (!track) return;
    const trackId = Number(track.id);
    if (seenTracks.has(trackId)) return;
    seenTracks.add(trackId);

    const info = state.plays?.[track.id] || state.plays?.[String(track.id)] || {};
    const count = Math.max(1, Number(info?.count) || 0);
    manual.push({
      id: `pick-${track.id}`,
      label: "Tu elección",
      reason:
        count > 1
          ? `Elegida por vos · ${plural(count, "reproducción", "reproducciones")}.`
          : "Elegida por vos para este set.",
      track,
      count,
      at: trendLatestOf(info) || Date.now(),
      manual: true
    });
  });

  return [...items, ...manual];
};

const trendRankedItems = (items) =>
  items
    .slice()
    .sort(
      (a, b) =>
        b.count - a.count ||
        b.at - a.at ||
        String(a.subject || a.track?.title || "").localeCompare(
          String(b.subject || b.track?.title || ""),
          "es"
        )
    )
    .map((item, index) => ({ ...item, rank: index + 1 }));

const trendTrackRanking = (limit = 5, range = trendWeekRange()) =>
  trendEntriesFromEvents(trendEventsInRange(range))
    .sort(
      (a, b) =>
        b.count - a.count ||
        trendLatestOf(b.info) - trendLatestOf(a.info) ||
        String(a.track.title).localeCompare(String(b.track.title), "es")
    )
    .slice(0, limit)
    .map((entry, index) => ({ ...entry, rank: index + 1 }));

const trendSetCount = (set, allItems = null) => trendItemsForSet(set, allItems).length;

const createTrendSetId = () =>
  `set-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

const loadTrendSettings = () => {
  const saved = readJSON(STORAGE.trends, null);
  const sets = Array.isArray(saved?.sets)
    ? saved.sets.map(normalizeTrendSet).filter(Boolean)
    : [];
  const seen = new Set();
  state.trendSets = sets.filter((set) => {
    if (seen.has(set.id)) return false;
    seen.add(set.id);
    return true;
  });
  const active = String(saved?.active || "all");
  state.trendActiveSet = trendSetById(active) ? active : "all";
};

const saveTrendSettings = () => {
  writeJSON(STORAGE.trends, {
    active: state.trendActiveSet,
    sets: trendSetsSnapshot()
  });
  if (typeof scheduleCloudSync === "function") scheduleCloudSync("settings");
};

const applyTrendSettings = (settings) => {
  if (!settings || typeof settings !== "object") return;
  if (Array.isArray(settings.trendSets)) {
    const seen = new Set();
    state.trendSets = settings.trendSets
      .map(normalizeTrendSet)
      .filter((set) => {
        if (!set || seen.has(set.id)) return false;
        seen.add(set.id);
        return true;
      });
  }
  const active = String(settings.trendActiveSet || "");
  state.trendActiveSet = active && trendSetById(active) ? active : "all";
  writeJSON(STORAGE.trends, {
    active: state.trendActiveSet,
    sets: trendSetsSnapshot()
  });
  if (state.ready && typeof renderView === "function") renderView({ resetScroll: false });
};

const selectTrendSet = (id) => {
  if (!trendSetById(id)) return false;
  state.trendActiveSet = String(id);
  saveTrendSettings();
  return true;
};

const saveTrendSet = (value) => {
  const set = normalizeTrendSet({ ...value, preset: false });
  if (!set) return null;
  const index = state.trendSets.findIndex((item) => item.id === set.id);
  if (index >= 0) {
    state.trendSets[index] = set;
  } else {
    if (state.trendSets.length >= TREND_SET_LIMIT) return null;
    state.trendSets.push(set);
  }
  saveTrendSettings();
  return set;
};

const deleteTrendSet = (id) => {
  const before = state.trendSets.length;
  state.trendSets = state.trendSets.filter((set) => set.id !== String(id));
  if (state.trendSets.length === before) return false;
  if (state.trendActiveSet === String(id)) state.trendActiveSet = "all";
  saveTrendSettings();
  return true;
};

const trendFrameClass = (frame) => `trend-frame--${normalizeTrendFrame(frame)}`;

/* ------------------------------------------------------------
   Editor de sets propios
   ------------------------------------------------------------ */

const trendEditorTrackRow = (track, selected) => `
  <button type="button" class="trend-pick${selected ? " is-selected" : ""}" data-trend-track="${track.id}" aria-pressed="${selected}">
    <span class="trend-pick__art">${coverHTML(track)}</span>
    <span class="trend-pick__copy">
      <strong>${escapeHTML(track.title)}</strong>
      <small>${escapeHTML(track.artist || "Artista desconocido")}</small>
    </span>
    <span class="trend-pick__check">${selected ? icon("check") : icon("plus")}</span>
  </button>`;

const trendEditorPickList = (draft, query = "") => {
  const term = normalize(query);
  const matches = state.tracks.filter((track) => {
    if (!term) return true;
    const haystack = normalize(
      `${track.title || ""} ${track.artist || ""} ${track.album || ""} ${track.genre || ""}`
    );
    return haystack.includes(term);
  });

  const selected = state.tracks.filter((track) => draft.tracks.has(Number(track.id)));
  const selectedIds = new Set(selected.map((track) => Number(track.id)));
  const list = [
    ...selected,
    ...matches.filter((track) => !selectedIds.has(Number(track.id)))
  ].slice(0, 40);

  if (!list.length) {
    return `<p class="trend-pick-empty">${icon("search")} No hay canciones con esa búsqueda.</p>`;
  }

  return list
    .map((track) => trendEditorTrackRow(track, draft.tracks.has(Number(track.id))))
    .join("");
};

const openTrendSetEditor = (setId = "") => {
  const existing = setId ? trendSetById(setId) : null;
  const base = existing && !existing.preset ? existing : null;
  const draft = {
    id: base?.id || "",
    name: base?.name || (existing ? `${existing.name} propio` : ""),
    frame: base?.frame || existing?.frame || "ocean",
    color: normalizeTrendColor(base?.color || existing?.color),
    categories: new Set(base?.categories || (existing ? existing.categories : ["top", "week", "favorite"])),
    tracks: new Set(base?.tracks || []),
    preset: false
  };

  const frameOptions = TREND_FRAME_OPTIONS.map((option) => {
    const active = option.value === draft.frame;
    const customStyle = option.value === "custom" ? trendFrameStyle("custom", draft.color) : "";
    return `<button type="button" class="trend-frame-option ${trendFrameClass(option.value)}${active ? " is-active" : ""}" data-trend-frame="${option.value}" role="radio" aria-checked="${active}" title="${escapeHTML(option.label)}"${customStyle}>
      <span class="trend-frame-option__swatch" aria-hidden="true"></span>
      <span>${escapeHTML(option.label)}</span>
    </button>`;
  }).join("");

  const categoryOptions = TREND_CATEGORY_OPTIONS.map((option) => {
    const active = draft.categories.has(option.value);
    return `<button type="button" class="trend-category${active ? " is-active" : ""}" data-trend-category="${option.value}" aria-pressed="${active}">
      ${icon("check")}<span>${escapeHTML(option.label)}</span>
    </button>`;
  }).join("");

  openModal({
    title: existing ? (existing.preset ? "Crear set a partir de este" : "Editar set") : "Nuevo set de tendencias",
    eyebrow: "Tendencias",
    body: `
      <form class="form trend-editor" id="trendSetForm">
        <div class="trend-editor__preview ${trendFrameClass(draft.frame)}"${trendFrameStyle(draft.frame, draft.color)} id="trendEditorPreview">
          <span class="trend-editor__preview-copy">
            <strong id="trendEditorName">${escapeHTML(draft.name || "Tu set")}</strong>
            <small id="trendEditorMeta">${draft.categories.size + draft.tracks.size} elegidas</small>
          </span>
        </div>

        <label class="field">
          <span>Nombre</span>
          <input name="name" maxlength="48" value="${escapeHTML(draft.name)}" placeholder="Mi set de los viernes" required data-autofocus />
        </label>

        <div class="field">
          <span>Marco</span>
          <div class="trend-frames" role="radiogroup" aria-label="Marco del set">
            ${frameOptions}
          </div>
        </div>

        <div class="field trend-editor__color" id="trendColorField"${draft.frame === "custom" ? "" : " hidden"}>
          <span>Color del marco</span>
          <div class="trend-color">
            <input type="color" id="trendFrameColor" value="${draft.color}" aria-label="Elegir color del marco" />
            <input type="text" class="trend-color__hex" id="trendFrameColorHex" value="${draft.color}" maxlength="7" spellcheck="false" autocomplete="off" aria-label="Código de color" />
          </div>
        </div>

        <div class="field">
          <span>Categorías</span>
          <div class="trend-categories" role="group" aria-label="Categorías del set">
            ${categoryOptions}
          </div>
        </div>

        <div class="field">
          <span>Canciones elegidas <small id="trendPickCount">${draft.tracks.size ? `${draft.tracks.size} elegidas` : ""}</small></span>
          <label class="trend-pick-search">
            ${icon("search")}
            <input type="search" id="trendPickSearch" placeholder="Buscar en tu biblioteca…" autocomplete="off" spellcheck="false" />
          </label>
          <div class="trend-pick-list" id="trendPickList">${trendEditorPickList(draft)}</div>
        </div>

        <div class="modal__actions">
          <button type="button" class="btn btn--ghost" data-action="close-modal">Cancelar</button>
          <button type="submit" class="btn btn--primary">${icon("check")} ${draft.id ? "Guardar set" : "Crear set"}</button>
        </div>
      </form>`
  });

  const body = $("#modalBody");
  const form = body?.querySelector("#trendSetForm");
  if (!body || !form) return;

  const syncEditor = () => {
    body.querySelectorAll("[data-trend-frame]").forEach((button) => {
      const active = button.dataset.trendFrame === draft.frame;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-checked", String(active));
    });

    body.querySelectorAll("[data-trend-category]").forEach((button) => {
      const active = draft.categories.has(button.dataset.trendCategory);
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });

    body.querySelectorAll("[data-trend-track]").forEach((button) => {
      const active = draft.tracks.has(Number(button.dataset.trendTrack));
      button.classList.toggle("is-selected", active);
      button.setAttribute("aria-pressed", String(active));
      const check = button.querySelector(".trend-pick__check");
      if (check) check.innerHTML = active ? icon("check") : icon("plus");
    });

    const customButton = body.querySelector('[data-trend-frame="custom"]');
    if (customButton) {
      customButton.style.setProperty("--frame-color", draft.color);
      customButton.style.setProperty("--frame-rgb", trendColorRgb(draft.color));
    }

    const preview = body.querySelector("#trendEditorPreview");
    if (preview) {
      preview.className = `trend-editor__preview ${trendFrameClass(draft.frame)}`;
      if (normalizeTrendFrame(draft.frame) === "custom") {
        preview.style.setProperty("--frame-color", draft.color);
        preview.style.setProperty("--frame-rgb", trendColorRgb(draft.color));
      } else {
        preview.style.removeProperty("--frame-color");
        preview.style.removeProperty("--frame-rgb");
      }
    }

    const colorField = body.querySelector("#trendColorField");
    if (colorField) colorField.hidden = normalizeTrendFrame(draft.frame) !== "custom";
    const colorInput = body.querySelector("#trendFrameColor");
    if (colorInput && colorInput.value.toLowerCase() !== draft.color) colorInput.value = draft.color;
    const colorHex = body.querySelector("#trendFrameColorHex");
    if (colorHex && document.activeElement !== colorHex) colorHex.value = draft.color;

    const name = body.querySelector("#trendEditorName");
    if (name) name.textContent = draft.name || "Tu set";
    const meta = body.querySelector("#trendEditorMeta");
    if (meta) {
      const total = draft.categories.size + draft.tracks.size;
      meta.textContent = total
        ? `${total} ${total === 1 ? "elegida" : "elegidas"}`
        : "Elegí categorías o canciones";
    }
    const pickCount = body.querySelector("#trendPickCount");
    if (pickCount) {
      pickCount.textContent = draft.tracks.size
        ? `${draft.tracks.size} ${draft.tracks.size === 1 ? "elegida" : "elegidas"}`
        : "";
    }
  };

  // El formulario se reemplaza en cada apertura del modal: el listener no se
  // acumula como pasaría si colgara del cuerpo fijo del modal.
  form.addEventListener("click", (event) => {
    const frameButton = event.target.closest("[data-trend-frame]");
    if (frameButton) {
      draft.frame = normalizeTrendFrame(frameButton.dataset.trendFrame);
      syncEditor();
      return;
    }

    const categoryButton = event.target.closest("[data-trend-category]");
    if (categoryButton) {
      const value = categoryButton.dataset.trendCategory;
      if (!TREND_CATEGORY_VALUES.has(value)) return;
      if (draft.categories.has(value)) draft.categories.delete(value);
      else draft.categories.add(value);
      syncEditor();
      return;
    }

    const trackButton = event.target.closest("[data-trend-track]");
    if (trackButton) {
      const id = Number(trackButton.dataset.trendTrack);
      if (!state.trackById.has(id)) return;
      if (draft.tracks.has(id)) {
        draft.tracks.delete(id);
      } else {
        if (draft.tracks.size >= TREND_SET_TRACK_LIMIT) {
          toast(`Un set puede tener hasta ${TREND_SET_TRACK_LIMIT} canciones elegidas.`, "error");
          return;
        }
        draft.tracks.add(id);
      }
      syncEditor();
    }
  });

  form.name?.addEventListener("input", () => {
    draft.name = form.name.value;
    const name = body.querySelector("#trendEditorName");
    if (name) name.textContent = draft.name || "Tu set";
  });

  const search = body.querySelector("#trendPickSearch");
  search?.addEventListener("input", () => {
    const list = body.querySelector("#trendPickList");
    if (list) list.innerHTML = trendEditorPickList(draft, search.value);
  });
  // Buscar no es guardar: Enter en el buscador no debe enviar el formulario.
  search?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") event.preventDefault();
  });

  const colorInput = body.querySelector("#trendFrameColor");
  const colorHex = body.querySelector("#trendFrameColorHex");

  colorInput?.addEventListener("input", () => {
    draft.color = normalizeTrendColor(colorInput.value);
    if (colorHex) colorHex.value = draft.color;
    syncEditor();
  });

  colorHex?.addEventListener("input", () => {
    const value = colorHex.value.trim();
    if (!/^#?(?:[0-9a-f]{3}|[0-9a-f]{6})$/i.test(value)) return;
    draft.color = normalizeTrendColor(value);
    syncEditor();
  });

  colorHex?.addEventListener("blur", () => {
    colorHex.value = draft.color;
  });

  // El código de color tampoco debe enviar el formulario con Enter.
  colorHex?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") event.preventDefault();
  });

  syncEditor();

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    draft.name = String(form.name?.value || "").trim();
    if (!draft.name) {
      toast("Poné un nombre al set.", "error");
      form.name?.focus();
      return;
    }
    if (!draft.categories.size && !draft.tracks.size) {
      toast("Elegí al menos una categoría o una canción.", "error");
      return;
    }

    const saved = saveTrendSet({
      id: draft.id || createTrendSetId(),
      name: draft.name,
      frame: draft.frame,
      color: draft.color,
      categories: [...draft.categories],
      tracks: [...draft.tracks]
    });
    if (!saved) {
      toast(`No se pudo guardar el set. Podés tener hasta ${TREND_SET_LIMIT}.`, "error");
      return;
    }

    state.trendActiveSet = saved.id;
    saveTrendSettings();
    closeModal(true);
    renderView({ resetScroll: false });
    haptic(8);
    toast(draft.id ? "Set actualizado." : "Set creado.");
  });
};

const confirmTrendSetDelete = (id) => {
  const set = state.trendSets.find((item) => item.id === String(id));
  if (!set) return;
  openModal({
    title: "Eliminar set",
    eyebrow: "Tendencias",
    body: `
      <p class="modal__text">«${escapeHTML(set.name)}» se elimina de tus sets. Las canciones y las reproducciones no se tocan.</p>
      <div class="modal__actions">
        <button class="btn btn--ghost" type="button" data-action="close-modal">Cancelar</button>
        <button class="btn btn--danger" type="button" data-action="trend-set-delete-confirm" data-id="${escapeHTML(set.id)}">${icon("trash")} Eliminar</button>
      </div>`
  });
};

// El estado de tendencias se lee al cargar el script: la vista ya encuentra
// los sets listos, sin esperar a la nube.
loadTrendSettings();
