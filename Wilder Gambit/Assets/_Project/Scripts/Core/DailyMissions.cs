using System;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    public enum MissionScope { Daily, Weekly }

    /// <summary>Qué contador alimenta el progreso de la misión.</summary>
    public enum MissionMetric
    {
        MatchesPlayed,
        MatchesWon,
        MatchesWonHard,
        PrecisionGames,
        Captures,
        PuzzlesSolved,
        NoQueenLossWins,
        LancerWins,
        NecroWins,
        FastMates,
        DailyChallenge,
        WinStreak3,
        // Semanales
        WeekMatchesWon,
        WeekPuzzlesSolved,
        WeekDailyMissions,
    }

    /// <summary>Definición de una misión (el progreso se evalúa contra los contadores del día/semana).</summary>
    public class MissionDef
    {
        public string id;
        public string title;
        public string desc;
        public string icon;
        public int target;
        public int payout;
        public MissionMetric metric;
        public MissionScope scope = MissionScope.Daily;

        /// <summary>Descripción con el objetivo relleno («Captura 10 piezas»).</summary>
        public string Description => desc.Replace("{t}", target.ToString());
    }

    /// <summary>Contadores del día. Se reinician al cambiar de fecha.</summary>
    [Serializable]
    public class DailyCounters
    {
        public int matchesPlayed;
        public int matchesWon;
        public int matchesWonHard;
        public int precisionGames;
        public int captures;
        public int puzzlesSolved;
        public int noQueenLossWins;
        public int lancerWins;
        public int necroWins;
        public int fastMates;
        public int dailyChallenge;
        public int bestWinStreak;
    }

    [Serializable]
    public class DailyMissionState
    {
        public string day = "";
        public string[] ids = new string[3];
        public bool[] claimed = new bool[3];
        public bool rerollUsed;
        public DailyCounters counters = new DailyCounters();
    }

    /// <summary>
    /// Las 3 misiones diarias: se eligen de forma determinista por fecha (misma selección
    /// para todos los jugadores ese día), se progresan jugando y se cobran a mano.
    /// Completar las 3 llena el segmento del día en la barra semanal.
    /// </summary>
    public static class DailyMissions
    {
        public const int Slots = 3;
        private const string PREF_KEY = "WG_DailyMissions";

        /// <summary>Catálogo completo de misiones diarias.</summary>
        public static readonly MissionDef[] Pool =
        {
            new MissionDef { id = "play_matches",    title = "Calentar motores", desc = "Juega {t} partidas",                              icon = "♟",  target = 3,  payout = 30, metric = MissionMetric.MatchesPlayed },
            new MissionDef { id = "win_matches",     title = "Victorias del día", desc = "Gana {t} partidas",                              icon = "🏆", target = 2,  payout = 55, metric = MissionMetric.MatchesWon },
            new MissionDef { id = "win_hard",        title = "Sangre fría", desc = "Gana 1 partida en Caballero o superior",                icon = "⚔️", target = 1,  payout = 75, metric = MissionMetric.MatchesWonHard },
            new MissionDef { id = "precision",       title = "Cirujano", desc = "Termina una partida con 80% de precisión o más",            icon = "🎯", target = 1,  payout = 65, metric = MissionMetric.PrecisionGames },
            new MissionDef { id = "captures",        title = "Cazador", desc = "Captura {t} piezas en total",                           icon = "🗡️", target = 10, payout = 45, metric = MissionMetric.Captures },
            new MissionDef { id = "puzzle_solve",    title = "Mente táctica", desc = "Resuelve {t} puzzles",                               icon = "🧩", target = 3,  payout = 45, metric = MissionMetric.PuzzlesSolved },
            new MissionDef { id = "no_queen_loss",   title = "Corona intacta", desc = "Gana una partida sin perder la dama",              icon = "👑", target = 1,  payout = 75, metric = MissionMetric.NoQueenLossWins },
            new MissionDef { id = "lancer_win",      title = "Filas del Atelier", desc = "Gana con el Peón Lancero equipado",           icon = "⚑",  target = 1,  payout = 90, metric = MissionMetric.LancerWins },
            new MissionDef { id = "necro_win",       title = "Legión espectral", desc = "Gana con el Alfil Nigromante equipado",        icon = "☠️", target = 1,  payout = 90, metric = MissionMetric.NecroWins },
            new MissionDef { id = "fast_mate",       title = "Mate exprés", desc = "Da mate en 25 jugadas o menos",                       icon = "⚡", target = 1,  payout = 80, metric = MissionMetric.FastMates },
            new MissionDef { id = "daily_challenge", title = "Devoción", desc = "Completa el desafío diario",                             icon = "🔮", target = 1,  payout = 55, metric = MissionMetric.DailyChallenge },
            new MissionDef { id = "streak_3",        title = "En racha", desc = "Logra 3 victorias seguidas",                            icon = "🔥", target = 1,  payout = 80, metric = MissionMetric.WinStreak3 },
        };

        /// <summary>Misiones «siempre posibles»: al menos una entra cada día.</summary>
        private static readonly string[] EasyTrio = { "play_matches", "win_matches", "puzzle_solve" };

        private static DailyMissionState _state;

        /// <summary>Cierre de día en curso: evita que un cobro vuelva a entrar en EnsureToday.</summary>
        private static bool _closingDay;

        public static string TodayKey => DateTime.Now.ToString("yyyy-MM-dd");

        public static DailyMissionState State
        {
            get
            {
                EnsureToday();
                return _state;
            }
        }

        /// <summary>Las 3 misiones de hoy.</summary>
        public static IEnumerable<MissionDef> TodaysMissions
        {
            get
            {
                var s = State;
                for (int i = 0; i < Slots; i++)
                {
                    var def = Find(s.ids[i]);
                    if (def != null) yield return def;
                }
            }
        }

        public static MissionDef GetAt(int slot)
        {
            var s = State;
            if (slot < 0 || slot >= Slots) return null;
            return Find(s.ids[slot]);
        }

        public static int Progress(int slot)
        {
            var def = GetAt(slot);
            return def == null ? 0 : Mathf.Clamp(Evaluate(def.metric), 0, def.target);
        }

        public static bool IsComplete(int slot)
        {
            var def = GetAt(slot);
            return def != null && Evaluate(def.metric) >= def.target;
        }

        public static bool IsClaimed(int slot)
        {
            var s = State;
            return slot >= 0 && slot < Slots && s.claimed[slot];
        }

        public static int CompletedCount
        {
            get
            {
                int n = 0;
                for (int i = 0; i < Slots; i++) if (IsComplete(i)) n++;
                return n;
            }
        }

        public static bool AllComplete => CompletedCount >= Slots;

        public static bool CanReroll => !State.rerollUsed;

        public static string TimeToResetText()
        {
            var now = DateTime.Now;
            var next = now.Date.AddDays(1);
            var span = next - now;
            return $"{(int)span.TotalHours} h {span.Minutes:00} m";
        }

        // ── Cobro ─────────────────────────────────────────────────────────────

        /// <summary>Cobra una misión completada. Devuelve el pago efectivo.</summary>
        public static GambitPayout Claim(int slot)
        {
            var payout = new GambitPayout();
            var def = GetAt(slot);
            if (def == null || !IsComplete(slot) || IsClaimed(slot)) return payout;

            payout = GambitEconomy.Earn(def.payout, GambitSource.DailyMission, meta: def.id, note: def.title);
            _state.claimed[slot] = true;
            Save();
            if (payout.granted > 0) SeasonProgress.NoteMissionClaimed();
            return payout;
        }

        /// <summary>Cambia una misión por otra que no esté en el día (1 gratis al día).</summary>
        public static bool Reroll(int slot)
        {
            var s = State;
            if (s.rerollUsed || slot < 0 || slot >= Slots) return false;

            var used = new List<string>(s.ids);
            var candidates = new List<MissionDef>();
            foreach (var def in Pool)
                if (!used.Contains(def.id) && IsMissionAvailable(def)) candidates.Add(def);

            if (candidates.Count == 0) return false;

            // Determinista por día + slot para que no dependa del azar del frame
            int seed = TodayKey.GetHashCode() * 31 + slot + 7;
            var rng = new System.Random(seed);
            var pick = candidates[rng.Next(candidates.Count)];

            s.ids[slot] = pick.id;
            s.claimed[slot] = false;
            s.rerollUsed = true;
            Save();
            Debug.Log($"[DailyMissions] Misión cambiada: {pick.title}");
            return true;
        }

        // ── Progreso (lo llama GambitProgress desde los eventos de juego) ─────

        public static void NoteMatch(MatchSummary summary)
        {
            var c = State.counters;
            c.matchesPlayed++;
            if (summary.outcome == MatchOutcome.Victory)
            {
                c.matchesWon++;
                if ((int)summary.level >= (int)WilderGambit.AI.DifficultyLevel.Knight) c.matchesWonHard++;
                if (!summary.lostQueen) c.noQueenLossWins++;
                if (summary.usedLancer) c.lancerWins++;
                if (summary.usedNecromancer) c.necroWins++;
                if (summary.totalTurns <= 25) c.fastMates++;
            }
            if (summary.accuracy >= 80f) c.precisionGames++;

            int streak = WilderGambit.AI.DynamicDifficultyManager.WinStreak;
            if (streak > c.bestWinStreak) c.bestWinStreak = streak;

            Save();
        }

        public static void NoteCaptures(int count)
        {
            if (count <= 0) return;
            State.counters.captures += count;
            Save();
        }

        public static void NotePuzzleSolved()
        {
            State.counters.puzzlesSolved++;
            Save();
        }

        public static void NoteDailyChallenge()
        {
            State.counters.dailyChallenge++;
            Save();
        }

        // ── Internos ──────────────────────────────────────────────────────────

        /// <summary>
        /// Cuenta actual de la métrica. Lee el estado ya cargado y NO pasa por <see cref="State"/>:
        /// State → EnsureToday → cobro del día anterior → Evaluate → State era un ciclo que se
        /// comía la pila (StackOverflow) cada vez que cambiaba el día.
        /// </summary>
        private static int Evaluate(MissionMetric metric, DailyMissionState state = null)
        {
            var s = state ?? _state;
            if (s == null || s.counters == null) return 0;

            var c = s.counters;
            switch (metric)
            {
                case MissionMetric.MatchesPlayed:   return c.matchesPlayed;
                case MissionMetric.MatchesWon:      return c.matchesWon;
                case MissionMetric.MatchesWonHard:  return c.matchesWonHard;
                case MissionMetric.PrecisionGames:  return c.precisionGames;
                case MissionMetric.Captures:        return c.captures;
                case MissionMetric.PuzzlesSolved:   return c.puzzlesSolved;
                case MissionMetric.NoQueenLossWins: return c.noQueenLossWins;
                case MissionMetric.LancerWins:      return c.lancerWins;
                case MissionMetric.NecroWins:       return c.necroWins;
                case MissionMetric.FastMates:       return c.fastMates;
                case MissionMetric.DailyChallenge:  return c.dailyChallenge;
                case MissionMetric.WinStreak3:      return c.bestWinStreak >= 3 ? 1 : 0;
                default:                            return 0;
            }
        }

        private static MissionDef Find(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            foreach (var def in Pool)
                if (def.id == id) return def;
            return null;
        }

        private static void EnsureToday()
        {
            if (_state == null) Load();

            if (_state.day == TodayKey) return;
            if (_closingDay) return;   // ya se está cerrando el día anterior

            _closingDay = true;
            try
            {
                var anterior = _state;

                // El día avanza ANTES de pagar lo del anterior: si el cobro vuelve a pedir
                // State, ya encuentra el día nuevo y no vuelve a cerrarlo (antes se llamaban
                // entre sí en bucle hasta reventar la pila).
                _state = NewStateFor(TodayKey);
                Save();

                // Día nuevo: cobrar lo completado y no reclamado para no perderlo
                if (!string.IsNullOrEmpty(anterior.day))
                    AutoClaimPending(anterior);

                Debug.Log($"[DailyMissions] Nuevas misiones para {_state.day}.");
            }
            finally
            {
                _closingDay = false;
            }
        }

        /// <summary>Cobra lo completado y no reclamado del día que se cierra.</summary>
        private static void AutoClaimPending(DailyMissionState dia)
        {
            if (dia == null || dia.ids == null) return;

            for (int i = 0; i < Slots; i++)
            {
                var def = Find(dia.ids[i]);
                if (def == null || dia.claimed[i]) continue;
                if (Evaluate(def.metric, dia) < def.target) continue;

                // Se marca antes de pagar: si el pago vuelve a pasar por aquí, ya está cobrada
                dia.claimed[i] = true;
                var payout = GambitEconomy.Earn(def.payout, GambitSource.DailyMission, meta: def.id, note: $"{def.title} (cierre del día)");
                Debug.Log($"[DailyMissions] Cobro automático al cerrar el día: {def.title} +{payout.granted}G");
                if (payout.granted > 0) SeasonProgress.NoteMissionClaimed();
            }
        }

        private static DailyMissionState NewStateFor(string dayKey)
        {
            var state = new DailyMissionState { day = dayKey, counters = new DailyCounters() };

            int seed = dayKey.GetHashCode();
            var rng = new System.Random(seed);

            // 1) Una misión fácil garantizada (rota entre las 3 según el día)
            string easy = EasyTrio[Mathf.Abs(seed) % EasyTrio.Length];
            state.ids[0] = easy;

            // 2) Dos más del resto del catálogo, sin repetir y solo jugables:
            // lancer_win / necro_win exigen variantes que el jugador quizá no tiene.
            var rest = new List<MissionDef>();
            foreach (var def in Pool)
                if (def.id != easy && IsMissionAvailable(def)) rest.Add(def);

            for (int i = 1; i < Slots && rest.Count > 0; i++)
            {
                int pick = rng.Next(rest.Count);
                state.ids[i] = rest[pick].id;
                rest.RemoveAt(pick);
            }
            return state;
        }

        /// <summary>
        /// Una misión solo entra al día (o al reroll) si el jugador puede completarla:
        /// lancer_win exige el Lancero y necro_win el Nigromante.
        /// </summary>
        private static bool IsMissionAvailable(MissionDef def)
        {
            if (def.id == "lancer_win" && !PieceLoadoutManager.IsLancerOwned()) return false;
            if (def.id == "necro_win" && !PieceLoadoutManager.IsNecroOwned()) return false;
            return true;
        }

        private static void Load()
        {
            string json = PlayerPrefs.GetString(PREF_KEY, "");
            if (!string.IsNullOrEmpty(json))
            {
                try { _state = JsonUtility.FromJson<DailyMissionState>(json); }
                catch (Exception e) { Debug.LogWarning("[DailyMissions] JSON inválido, se reinicia: " + e.Message); }
            }
            if (_state == null) _state = NewStateFor(TodayKey);
            if (_state.ids == null || _state.ids.Length != Slots) _state.ids = new string[Slots];
            if (_state.claimed == null || _state.claimed.Length != Slots) _state.claimed = new bool[Slots];
            if (_state.counters == null) _state.counters = new DailyCounters();
        }

        private static void Save()
        {
            if (_state == null) return;
            PlayerPrefs.SetString(PREF_KEY, JsonUtility.ToJson(_state));
            PlayerPrefs.Save();
        }

        /// <summary>Solo para el panel de depuración.</summary>
        public static void DebugResetToday()
        {
            _state = NewStateFor(TodayKey);
            Save();
        }

        /// <summary>
        /// Solo para probar el cofre a mano: deja las 3 misiones de hoy completadas para que
        /// <c>WeeklyProgress.SyncToday</c> no vacíe el segmento de hoy al repintar PROGRESO
        /// (sin esto la semana se queda en 6/7 y el botón COBRAR COFRE sigue bloqueado).
        /// No las cobra: siguen pendientes hasta que el jugador las reclame.
        /// </summary>
        public static void DebugCompleteToday()
        {
            var s = State;
            if (s.counters == null) s.counters = new DailyCounters();
            var c = s.counters;
            c.matchesPlayed = Mathf.Max(c.matchesPlayed, 3);
            c.matchesWon = Mathf.Max(c.matchesWon, 2);
            c.matchesWonHard = Mathf.Max(c.matchesWonHard, 1);
            c.precisionGames = Mathf.Max(c.precisionGames, 1);
            c.captures = Mathf.Max(c.captures, 10);
            c.puzzlesSolved = Mathf.Max(c.puzzlesSolved, 3);
            c.noQueenLossWins = Mathf.Max(c.noQueenLossWins, 1);
            c.lancerWins = Mathf.Max(c.lancerWins, 1);
            c.necroWins = Mathf.Max(c.necroWins, 1);
            c.fastMates = Mathf.Max(c.fastMates, 1);
            c.dailyChallenge = Mathf.Max(c.dailyChallenge, 1);
            c.bestWinStreak = Mathf.Max(c.bestWinStreak, 3);
            Save();
            Debug.Log("[DailyMissions] Depuración: misiones de hoy completadas (3/3) sin cobrar.");
        }
    }
}
