using System;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    public enum AchievementMetric
    {
        TotalWins,
        WinsNovice,
        WinsApprentice,
        WinsKnight,
        WinsMaster,
        WinsGrandMaster,
        MatchesPlayed,
        FastMate20,
        PerfectAccuracyWins,
        PuzzleRating,
        PerfectWeeks,
        FirstVariant,
    }

    public class AchievementDef
    {
        public string id;
        public string title;
        public string desc;
        public string icon;
        public AchievementMetric metric;
        public int target = 1;
        public int payout;
    }

    [Serializable]
    public class AchievementStats
    {
        public int matchesPlayed;
        public int wins;
        public int winsNovice;
        public int winsApprentice;
        public int winsKnight;
        public int winsMaster;
        public int winsGrandMaster;
        public int fastMate20;
        public int perfectAccuracyWins;
        public int puzzleRating = 1000;
        public int perfectWeeks;
        public int variantsOwned;

        /// <summary>Ids ya cobrados.</summary>
        public List<string> unlocked = new List<string>();
    }

    /// <summary>
    /// Logros: hitos de una sola vez que se cobran solos en cuanto se cumplen
    /// (y avisan por toast). Son la parte "coleccionista" de la economía.
    /// </summary>
    public static class Achievements
    {
        private const string PREF_KEY = "WG_Achievements";

        public static readonly AchievementDef[] All =
        {
            new AchievementDef { id = "first_win",        title = "Primera sangre",         desc = "Gana tu primera partida",                      icon = "🏆", metric = AchievementMetric.TotalWins,         target = 1,    payout = 50 },
            new AchievementDef { id = "win_novice",       title = "Aprendiendo el oficio",  desc = "Gana a Principiante",                          icon = "♟",  metric = AchievementMetric.WinsNovice,        target = 1,    payout = 50 },
            new AchievementDef { id = "win_apprentice",   title = "Aprendiz aventajado",    desc = "Gana a Aprendiz",                              icon = "♞",  metric = AchievementMetric.WinsApprentice,    target = 1,    payout = 75 },
            new AchievementDef { id = "win_knight",       title = "Caballero",              desc = "Gana a Caballero",                             icon = "♝",  metric = AchievementMetric.WinsKnight,        target = 1,    payout = 100 },
            new AchievementDef { id = "win_master",       title = "Maestro",                desc = "Gana a Maestro",                               icon = "♜",  metric = AchievementMetric.WinsMaster,        target = 1,    payout = 150 },
            new AchievementDef { id = "win_gm",           title = "Gran Maestro",           desc = "Gana a Gran Maestro",                          icon = "♛",  metric = AchievementMetric.WinsGrandMaster,   target = 1,    payout = 250 },
            new AchievementDef { id = "games_10",         title = "Diez batallas",          desc = "Juega 10 partidas",                            icon = "⚔️", metric = AchievementMetric.MatchesPlayed,     target = 10,   payout = 75 },
            new AchievementDef { id = "games_50",         title = "Veterano del Atelier",   desc = "Juega 50 partidas",                            icon = "🛡️", metric = AchievementMetric.MatchesPlayed,     target = 50,   payout = 200 },
            new AchievementDef { id = "games_100",        title = "Leyenda del Atelier",    desc = "Juega 100 partidas",                           icon = "👑", metric = AchievementMetric.MatchesPlayed,     target = 100,  payout = 400 },
            new AchievementDef { id = "fast_mate_20",     title = "Mate exprés",            desc = "Da mate en 20 jugadas o menos",                icon = "⚡", metric = AchievementMetric.FastMate20,        target = 1,    payout = 150 },
            new AchievementDef { id = "perfect_accuracy", title = "Precisión quirúrgica",   desc = "Gana una partida con 100% de precisión",       icon = "🎯", metric = AchievementMetric.PerfectAccuracyWins,target = 1,    payout = 300 },
            new AchievementDef { id = "puzzle_1200",      title = "Táctica en ascenso",     desc = "Alcanza 1200 de rating en puzzles",            icon = "🧩", metric = AchievementMetric.PuzzleRating,      target = 1200, payout = 150 },
            new AchievementDef { id = "puzzle_1400",      title = "Ojo de halcón",          desc = "Alcanza 1400 de rating en puzzles",            icon = "🦅", metric = AchievementMetric.PuzzleRating,      target = 1400, payout = 250 },
            new AchievementDef { id = "puzzle_1600",      title = "Visionario",             desc = "Alcanza 1600 de rating en puzzles",            icon = "🔮", metric = AchievementMetric.PuzzleRating,      target = 1600, payout = 400 },
            new AchievementDef { id = "perfect_week",     title = "Semana Perfecta",        desc = "Completa los 7 días de la barra semanal",      icon = "🗓️", metric = AchievementMetric.PerfectWeeks,      target = 1,    payout = 500 },
            new AchievementDef { id = "first_variant",    title = "Coleccionista",          desc = "Consigue tu primera variante de pieza",        icon = "⚑",  metric = AchievementMetric.FirstVariant,      target = 1,    payout = 100 },
        };

        private static AchievementStats _stats;

        public static AchievementStats Stats
        {
            get
            {
                if (_stats == null) Load();
                return _stats;
            }
        }

        public static int TotalCount => All.Length;
        public static int UnlockedCount => Stats.unlocked?.Count ?? 0;

        public static bool IsUnlocked(AchievementDef def) => Stats.unlocked != null && Stats.unlocked.Contains(def.id);

        /// <summary>Progreso actual (para la barra de cada logro).</summary>
        public static int Progress(AchievementDef def)
        {
            var s = Stats;
            switch (def.metric)
            {
                case AchievementMetric.TotalWins:          return s.wins;
                case AchievementMetric.WinsNovice:         return s.winsNovice;
                case AchievementMetric.WinsApprentice:     return s.winsApprentice;
                case AchievementMetric.WinsKnight:         return s.winsKnight;
                case AchievementMetric.WinsMaster:         return s.winsMaster;
                case AchievementMetric.WinsGrandMaster:    return s.winsGrandMaster;
                case AchievementMetric.MatchesPlayed:      return s.matchesPlayed;
                case AchievementMetric.FastMate20:         return s.fastMate20;
                case AchievementMetric.PerfectAccuracyWins:return s.perfectAccuracyWins;
                case AchievementMetric.PuzzleRating:       return s.puzzleRating;
                case AchievementMetric.PerfectWeeks:       return s.perfectWeeks;
                case AchievementMetric.FirstVariant:       return s.variantsOwned;
                default:                                   return 0;
            }
        }

        // ── Progreso ──────────────────────────────────────────────────────────

        public static void NoteMatch(MatchSummary summary)
        {
            var s = Stats;
            s.matchesPlayed++;

            if (summary.outcome == MatchOutcome.Victory)
            {
                s.wins++;
                switch (summary.level)
                {
                    case WilderGambit.AI.DifficultyLevel.Novice:      s.winsNovice++; break;
                    case WilderGambit.AI.DifficultyLevel.Apprentice:  s.winsApprentice++; break;
                    case WilderGambit.AI.DifficultyLevel.Knight:      s.winsKnight++; break;
                    case WilderGambit.AI.DifficultyLevel.Master:      s.winsMaster++; break;
                    case WilderGambit.AI.DifficultyLevel.GrandMaster: s.winsGrandMaster++; break;
                }
                if (summary.totalTurns <= 20) s.fastMate20++;
                if (summary.accuracy >= 100f) s.perfectAccuracyWins++;
            }

            Evaluate();
        }

        public static void NotePuzzleRating(int rating)
        {
            Stats.puzzleRating = Mathf.Max(Stats.puzzleRating, rating);
            Evaluate();
        }

        public static void NotePerfectWeek(int perfectWeeks)
        {
            Stats.perfectWeeks = Mathf.Max(Stats.perfectWeeks, perfectWeeks);
            Evaluate();
        }

        public static void NoteVariantsOwned(int count)
        {
            Stats.variantsOwned = Mathf.Max(Stats.variantsOwned, count);
            Evaluate();
        }

        /// <summary>Cobra los logros recién cumplidos (una sola vez cada uno).</summary>
        public static void Evaluate()
        {
            var s = Stats;
            if (s.unlocked == null) s.unlocked = new List<string>();

            foreach (var def in All)
            {
                if (s.unlocked.Contains(def.id)) continue;
                if (Progress(def) < def.target) continue;

                s.unlocked.Add(def.id);
                Save();

                var payout = GambitEconomy.Earn(def.payout, GambitSource.Achievement, meta: def.id, note: $"Logro: {def.title}");
                Debug.Log($"[Achievements] Desbloqueado «{def.title}» +{payout.granted}G");
            }
        }

        private static void Load()
        {
            string json = PlayerPrefs.GetString(PREF_KEY, "");
            if (!string.IsNullOrEmpty(json))
            {
                try { _stats = JsonUtility.FromJson<AchievementStats>(json); }
                catch (Exception e) { Debug.LogWarning("[Achievements] JSON inválido, se reinicia: " + e.Message); }
            }
            if (_stats == null) _stats = new AchievementStats();
            if (_stats.unlocked == null) _stats.unlocked = new List<string>();
        }

        private static void Save()
        {
            if (_stats == null) return;
            PlayerPrefs.SetString(PREF_KEY, JsonUtility.ToJson(_stats));
            PlayerPrefs.Save();
        }

        public static void DebugReset()
        {
            _stats = new AchievementStats();
            Save();
        }
    }
}
