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

const trendItems = () => {
  const entries = trendPlayEntries();
  if (!entries.length) return [];

  const now = Date.now();
  const events = trendEvents();
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
      `Escuchada ${plural(overall.count, "vez", "veces")} en total.`,
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
      `${plural(artist.total, "reproducción", "reproducciones")} de ${artist.key}.`,
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
      `${plural(album.total, "reproducción", "reproducciones")} de «${album.key}».`,
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
      `${plural(genre.total, "reproducción", "reproducciones")} de ${genre.key}.`,
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

  if (events.length >= 2) {
    const week = trendTopOfEvents(events.filter(({ at }) => at >= now - 7 * TREND_DAY_MS));
    if (week && week.count >= 2) {
      add(
        "week",
        "En llamas esta semana",
        `${plural(week.count, "reproducción", "reproducciones")} en los últimos 7 días.`,
        week.track,
        week.count,
        week.at
      );
    }

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
        `${plural(night.count, "reproducción", "reproducciones")} de noche.`,
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
        `${plural(streak.count, "reproducción seguida", "reproducciones seguidas")}.`,
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
      `${plural(favorite.count, "reproducción", "reproducciones")} y la marcaste con corazón.`,
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
      )}.`,
      freshTop.track,
      freshTop.count,
      trendLatestOf(freshTop.info)
    );
  }

  return items;
};

const trendTrackIds = () => {
  const seen = new Set();
  return trendItems()
    .map((item) => item.track.id)
    .filter((id) => {
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
};

const trendSummary = () => {
  const entries = trendPlayEntries();
  const events = trendEvents();
  const days = new Set(events.map(({ at }) => trendDateKey(at)));

  if (!days.size) {
    entries.forEach(({ info }) => {
      [info?.firstPlayedAt, info?.lastPlayedAt].forEach((value) => {
        const time = new Date(value || 0).getTime();
        if (Number.isFinite(time) && time > 0) days.add(trendDateKey(time));
      });
    });
  }

  const artists = new Set(
    entries.map(({ track }) => (track.artist || "").trim()).filter(Boolean)
  );

  return {
    total: entries.reduce((sum, entry) => sum + entry.count, 0),
    days: days.size,
    artists: artists.size
  };
};
