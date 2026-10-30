using System;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Misiones de la velada de Halloween. Dos familias, un mismo motor:
    ///
    ///  · <b>Vía Luna (diarias)</b> — 3 misiones por jornada, elegidas de forma
    ///    determinista por fecha de un pool de 25. Progreso por contadores del
    ///    DÍA y cobro a mano. Al cerrar el día lo completado y sin cobrar se paga
    ///    solo, para que nadie pierda una misión terminada.
    ///
    ///  · <b>Exclusivas de la Vía Sangre</b> — 10 misiones para toda la edición:
    ///    5 <b>libres</b> (abiertas a cualquiera) y 5 <b>premium</b> (piden la Vía
    ///    Sangre abierta con Dulces). Progreso por contadores del EVENTO (no se
    ///    reinician cada día) y cobro único. La selección sale de dos pools de 10
    ///    misiones cada uno, fijada por edición y guardada en el estado: la velada
    ///    reparte 5 de cada bolsa y cada año cambia la mano.
    ///
    /// Cada misión paga XP de la velada (HalloweenProgress) + Dulces
    /// (HalloweenCurrency). Las claves son propias y por año: ni la temporada T1
    /// ni las misiones diarias del menú se tocan.
    /// </summary>
    public static class HalloweenMissions
    {
        /// <summary>Misiones diarias de la Vía Luna.</summary>
        public const int Slots = 3;

        /// <summary>Exclusivas de Sangre abiertas a todos.</summary>
        public const int SangreFreeSlots = 5;

        /// <summary>Exclusivas de Sangre que piden la vía premium.</summary>
        public const int SangrePaidSlots = 5;

        /// <summary>Total de exclusivas de Sangre de la edición.</summary>
        public const int SangreSlots = SangreFreeSlots + SangrePaidSlots;

        // ── Recompensas ──────────────────────────────────────────────────

        /// <summary>Pago de una misión diaria de la Vía Luna.</summary>
        public const int XpReward = 20;
        public const int DulcesReward = 2;

        /// <summary>Pago de una exclusiva de Sangre libre.</summary>
        public const int SangreFreeXp = 30;
        public const int SangreFreeDulces = 4;

        /// <summary>Pago de una exclusiva de Sangre premium.</summary>
        public const int SangrePaidXp = 45;
        public const int SangrePaidDulces = 6;

        /// <summary>Ruta de la tanda del año; las diarias guardan su día dentro.</summary>
        private static string PrefKey => "WG_HalloweenMissions_" + HalloweenEvent.Year;

        /// <summary>Clave antigua (sin sufijo de año): se limpia al hacer reset.</summary>
        private const string LegacyPrefKey = "WG_HalloweenMissions";

        // ── Catálogo ─────────────────────────────────────────────────────

        /// <summary>Vía a la que pertenece una misión.</summary>
        public enum HwLane
        {
            Luna = 0,
            Sangre = 1,
        }

        /// <summary>Qué contador alimenta el progreso de la misión.</summary>
        public enum HwMetric
        {
            MatchesPlayed,
            MatchesWon,
            MatchesWonHard,
            MatchesWonMaster,
            Precision80,
            Precision95,
            NoBlunderGames,
            FlawlessWins,
            NoQueenLossWins,
            FastMates,
            QuickWins,
            LongGames,
            Captures,
            QueenCaptures,
            PuzzlesSolved,
            DailyChallenge,
            WinStreak3,
            WinStreak5,
        }

        /// <summary>Definición de una misión de la velada.</summary>
        public class HwMissionDef
        {
            public string id;
            public string title;
            public string desc;
            public string icon;
            public int target;
            public HwMetric metric;
            public HwLane lane = HwLane.Luna;
            public bool premium;
            public int xp;
            public int dulces;

            /// <summary>Descripción con el objetivo relleno («Captura 8 piezas»).</summary>
            public string Description => desc.Replace("{t}", target.ToString());

            /// <summary>«DIARIA», «SANGRE LIBRE» o «SANGRE PREMIUM».</summary>
            public string LaneLabel =>
                lane == HwLane.Luna ? "DIARIA"
                : premium ? "SANGRE PREMIUM"
                : "SANGRE LIBRE";

            /// <summary>Línea de premio: «+20 XP · +2 🍬».</summary>
            public string RewardText =>
                $"+{xp} XP · +{dulces} {HalloweenCurrency.Icon}";
        }

        private static HwMissionDef Luna(string id, string title, string desc, string icon,
            int target, HwMetric metric) => new HwMissionDef
        {
            id = id, title = title, desc = desc, icon = icon, target = target, metric = metric,
            lane = HwLane.Luna, premium = false, xp = XpReward, dulces = DulcesReward,
        };

        private static HwMissionDef SangreFree(string id, string title, string desc, string icon,
            int target, HwMetric metric) => new HwMissionDef
        {
            id = id, title = title, desc = desc, icon = icon, target = target, metric = metric,
            lane = HwLane.Sangre, premium = false, xp = SangreFreeXp, dulces = SangreFreeDulces,
        };

        private static HwMissionDef SangrePaid(string id, string title, string desc, string icon,
            int target, HwMetric metric) => new HwMissionDef
        {
            id = id, title = title, desc = desc, icon = icon, target = target, metric = metric,
            lane = HwLane.Sangre, premium = true, xp = SangrePaidXp, dulces = SangrePaidDulces,
        };

        /// <summary>
        /// Pool de las misiones diarias de la Vía Luna (25). Todas se juegan solo
        /// con el juego normal: sin variantes ni compras.
        /// </summary>
        public static readonly HwMissionDef[] LunaPool =
        {
            Luna("hw_play",        "Ronda nocturna",     "Juega {t} partidas",                              "♟",  2,  HwMetric.MatchesPlayed),
            Luna("hw_play4",       "Noche larga",        "Juega {t} partidas",                              "🕯",  4,  HwMetric.MatchesPlayed),
            Luna("hw_win",         "Triunfo en la niebla", "Gana {t} partidas",                             "🏆", 2,  HwMetric.MatchesWon),
            Luna("hw_win3",        "Vencedor",           "Gana {t} partidas",                              "🥇", 3,  HwMetric.MatchesWon),
            Luna("hw_puzzles",     "Ritual táctico",     "Resuelve {t} puzzles",                            "🧩", 2,  HwMetric.PuzzlesSolved),
            Luna("hw_puzzles4",    "Velas y trampas",    "Resuelve {t} puzzles",                            "🕸",  4,  HwMetric.PuzzlesSolved),
            Luna("hw_hard",        "Sangre fría",        "Gana 1 partida en Caballero o superior",          "⚔️", 1,  HwMetric.MatchesWonHard),
            Luna("hw_hard2",       "Duelo de caballeros", "Gana 2 partidas en Caballero o superior",        "🛡",  2,  HwMetric.MatchesWonHard),
            Luna("hw_master",      "Mano del destino",   "Gana 1 partida en Maestro o superior",            "🎩", 1,  HwMetric.MatchesWonMaster),
            Luna("hw_precision",   "Manos firmes",       "Termina una partida con 80% de precisión",        "🎯", 1,  HwMetric.Precision80),
            Luna("hw_precision2",  "Dos veces firme",    "Termina 2 partidas con 80% de precisión",         "📐", 2,  HwMetric.Precision80),
            Luna("hw_precision95", "Pulso de cirujano",  "Termina una partida con 95% de precisión",        "🔬", 1,  HwMetric.Precision95),
            Luna("hw_no_blunder",  "Sin fisuras",        "Termina una partida sin errores graves",          "🧠", 1,  HwMetric.NoBlunderGames),
            Luna("hw_flawless",    "Intacto",            "Gana una partida sin perder piezas",              "🛡",  1,  HwMetric.FlawlessWins),
            Luna("hw_no_queen",    "Corona intacta",     "Gana una partida sin perder la dama",             "👑", 1,  HwMetric.NoQueenLossWins),
            Luna("hw_fast",        "Mate relámpago",     "Da mate en 25 jugadas o menos",                   "⚡", 1,  HwMetric.FastMates),
            Luna("hw_quick",       "Golpe seco",         "Gana en 20 jugadas propias o menos",              "🌪",  1,  HwMetric.QuickWins),
            Luna("hw_long",        "Vigilia",            "Termina una partida de 60 jugadas o más",         "🕰",  1,  HwMetric.LongGames),
            Luna("hw_captures",    "Cosecha de almas",   "Captura {t} piezas",                              "🗡️", 8,  HwMetric.Captures),
            Luna("hw_captures15",  "Sangre en el tablero", "Captura {t} piezas",                            "🩸", 15, HwMetric.Captures),
            Luna("hw_queen_hunt",  "Cacería real",       "Captura la dama rival",                           "♛",  1,  HwMetric.QueenCaptures),
            Luna("hw_challenge",   "Ofrenda diaria",     "Completa el desafío diario",                      "🔮", 1,  HwMetric.DailyChallenge),
            Luna("hw_streak3",     "En racha",           "Logra 3 victorias seguidas",                      "🔥", 1,  HwMetric.WinStreak3),
            Luna("hw_streak5",     "Imparable",          "Logra 5 victorias seguidas",                      "💀", 1,  HwMetric.WinStreak5),
            Luna("hw_master2",     "Cima de la torre",   "Gana 2 partidas en Maestro o superior",           "🗼", 2,  HwMetric.MatchesWonMaster),
        };

        /// <summary>Pool de las exclusivas de Sangre LIBRES (10): exigentes pero jugables sin la vía.</summary>
        public static readonly HwMissionDef[] SangreFreePool =
        {
            SangreFree("sg_win3",       "Sed de victoria",   "Gana {t} partidas",                            "🏆", 3,  HwMetric.MatchesWon),
            SangreFree("sg_hard2",      "Cacería nocturna",  "Gana 2 partidas en Caballero o superior",      "⚔️", 2,  HwMetric.MatchesWonHard),
            SangreFree("sg_captures25", "Rastro de sangre",  "Captura {t} piezas",                           "🗡️", 25, HwMetric.Captures),
            SangreFree("sg_queen2",     "Dos coronas",       "Captura {t} damas rivales",                    "♛",  2,  HwMetric.QueenCaptures),
            SangreFree("sg_puzzles4",   "Grimorio",          "Resuelve {t} puzzles",                         "📖", 4,  HwMetric.PuzzlesSolved),
            SangreFree("sg_precision2", "Ojo de la luna",    "Termina 2 partidas con 80% de precisión",      "🎯", 2,  HwMetric.Precision80),
            SangreFree("sg_flawless",   "Cuerpo sin heridas", "Gana 2 partidas sin perder piezas",           "🛡",  2,  HwMetric.FlawlessWins),
            SangreFree("sg_no_queen2",  "Guardia de la reina", "Gana 2 partidas sin perder la dama",         "👑", 2,  HwMetric.NoQueenLossWins),
            SangreFree("sg_long2",      "Vigilia de sangre", "Termina 2 partidas de 60 jugadas o más",       "🕰",  2,  HwMetric.LongGames),
            SangreFree("sg_challenge",  "Vela perpetua",     "Completa el desafío diario",                   "🔮", 1,  HwMetric.DailyChallenge),
        };

        /// <summary>Pool de las exclusivas de Sangre PREMIUM (10): el techo de la velada.</summary>
        public static readonly HwMissionDef[] SangrePaidPool =
        {
            SangrePaid("sg_master2",    "Trono de ceniza",   "Gana 2 partidas en Maestro o superior",        "🎩", 2,  HwMetric.MatchesWonMaster),
            SangrePaid("sg_streak5",    "Sangre imparable",  "Logra 5 victorias seguidas",                   "🔥", 1,  HwMetric.WinStreak5),
            SangrePaid("sg_fast2",      "Guadaña",           "Da mate en 25 jugadas o menos (2 veces)",      "💀", 2,  HwMetric.FastMates),
            SangrePaid("sg_perfect2",   "Sin una gota",      "Termina 2 partidas con 95% de precisión",      "🔬", 2,  HwMetric.Precision95),
            SangrePaid("sg_no_blunder2","Mente de acero",    "Termina 2 partidas sin errores graves",        "🧠", 2,  HwMetric.NoBlunderGames),
            SangrePaid("sg_hard5",      "Carnicería",        "Gana 5 partidas en Caballero o superior",      "⚔️", 5,  HwMetric.MatchesWonHard),
            SangrePaid("sg_win6",       "Sed insaciable",    "Gana {t} partidas",                            "🏆", 6,  HwMetric.MatchesWon),
            SangrePaid("sg_queen3",     "Tres coronas",      "Captura {t} damas rivales",                    "♛",  3,  HwMetric.QueenCaptures),
            SangrePaid("sg_captures40", "Festín de almas",   "Captura {t} piezas",                           "🩸", 40, HwMetric.Captures),
            SangrePaid("sg_long3",      "Noche eterna",      "Termina 3 partidas de 60 jugadas o más",       "🌑", 3,  HwMetric.LongGames),
        };

        /// <summary>Misiones «siempre posibles»: al menos una entra cada día.</summary>
        private static readonly string[] EasyTrio = { "hw_play", "hw_win", "hw_puzzles" };

        /// <summary>Tamaño de los pools, para las notas del modal.</summary>
        public static int LunaPoolCount => LunaPool.Length;
        public static int SangreFreePoolCount => SangreFreePool.Length;
        public static int SangrePaidPoolCount => SangrePaidPool.Length;
        public static int SangrePoolCount => SangreFreePool.Length + SangrePaidPool.Length;

        // ── Contadores ───────────────────────────────────────────────────

        /// <summary>
        /// Contadores que alimentan el progreso. Las diarias usan una copia que se
        /// reinicia cada jornada; las de Sangre usan la del evento completo.
        /// </summary>
        [Serializable]
        public class HwCounters
        {
            public int matchesPlayed;
            public int matchesWon;
            public int matchesWonHard;
            public int matchesWonMaster;
            public int precision80;
            public int precision95;
            public int noBlunderGames;
            public int flawlessWins;
            public int noQueenLossWins;
            public int fastMates;
            public int quickWins;
            public int longGames;
            public int captures;
            public int queenCaptures;
            public int puzzlesSolved;
            public int dailyChallenge;
            public int bestWinStreak;
        }

        /// <summary>Estado persistente de la edición.</summary>
        [Serializable]
        public class HwMissionState
        {
            /// <summary>Día de la tanda de la Vía Luna (yyyy-MM-dd).</summary>
            public string day = "";

            /// <summary>Año de la edición con la que se eligieron las misiones de Sangre.</summary>
            public int edition;

            public string[] ids = new string[Slots];
            public bool[] claimed = new bool[Slots];
            public HwCounters counters = new HwCounters();

            public string[] sangreIds = new string[SangreSlots];
            public bool[] sangreClaimed = new bool[SangreSlots];
            public HwCounters total = new HwCounters();
        }

        private static HwMissionState _state;

        /// <summary>Cierre de día en curso: evita que un cobro vuelva a entrar en EnsureCurrent.</summary>
        private static bool _closingDay;

        public static string TodayKey => DateTime.Now.ToString("yyyy-MM-dd");

        public static HwMissionState State
        {
            get
            {
                EnsureCurrent();
                return _state;
            }
        }

        // ── Consultas de la Vía Luna (diarias) ───────────────────────────

        /// <summary>Las misiones de hoy (vacío fuera de la ventana de la velada).</summary>
        public static IEnumerable<HwMissionDef> TodaysMissions
        {
            get
            {
                var s = State;
                for (int i = 0; i < Slots; i++)
                {
                    var def = Find(s.ids != null && i < s.ids.Length ? s.ids[i] : null);
                    if (def != null) yield return def;
                }
            }
        }

        public static HwMissionDef GetAt(int slot)
        {
            var s = State;
            if (slot < 0 || slot >= Slots || s.ids == null || slot >= s.ids.Length) return null;
            return Find(s.ids[slot]);
        }

        public static int Progress(int slot)
        {
            var def = GetAt(slot);
            if (def == null) return 0;
            return Mathf.Clamp(Evaluate(def.metric, State.counters), 0, def.target);
        }

        public static bool IsComplete(int slot)
        {
            var def = GetAt(slot);
            return def != null && Evaluate(def.metric, State.counters) >= def.target;
        }

        public static bool IsClaimed(int slot)
        {
            var s = State;
            return slot >= 0 && slot < Slots && s.claimed != null && slot < s.claimed.Length && s.claimed[slot];
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

        public static int PendingClaimsCount
        {
            get
            {
                int n = 0;
                for (int i = 0; i < Slots; i++)
                    if (IsComplete(i) && !IsClaimed(i)) n++;
                return n;
            }
        }

        // ── Consultas de la Vía Sangre (exclusivas de la edición) ────────

        /// <summary>Definición de la exclusiva de Sangre del índice (0-9), o null.</summary>
        public static HwMissionDef SangreGetAt(int index)
        {
            var s = State;
            if (index < 0 || index >= SangreSlots || s.sangreIds == null || index >= s.sangreIds.Length)
                return null;
            return FindSangre(s.sangreIds[index]);
        }

        /// <summary>Premium = pide la Vía Sangre abierta.</summary>
        public static bool SangreIsPremium(int index)
        {
            var def = SangreGetAt(index);
            return def != null && def.premium;
        }

        /// <summary>¿La exclusiva está cerrada por no tener la Vía Sangre?</summary>
        public static bool SangreLocked(int index) =>
            SangreIsPremium(index) && !HalloweenLanes.SangreUnlocked;

        public static int SangreProgress(int index)
        {
            var def = SangreGetAt(index);
            if (def == null) return 0;
            return Mathf.Clamp(Evaluate(def.metric, State.total), 0, def.target);
        }

        public static bool SangreIsComplete(int index)
        {
            var def = SangreGetAt(index);
            return def != null && Evaluate(def.metric, State.total) >= def.target;
        }

        public static bool SangreIsClaimed(int index)
        {
            var s = State;
            return index >= 0 && index < SangreSlots && s.sangreClaimed != null
                   && index < s.sangreClaimed.Length && s.sangreClaimed[index];
        }

        /// <summary>Exclusivas completadas de una bolsa («libres» o «premium»).</summary>
        public static int SangreCompletedCount(bool premium)
        {
            int n = 0;
            int from = premium ? SangreFreeSlots : 0;
            int to = premium ? SangreSlots : SangreFreeSlots;
            for (int i = from; i < to; i++) if (SangreIsComplete(i)) n++;
            return n;
        }

        public static int SangrePendingClaimsCount => SangrePendingCount(false) + SangrePendingCount(true);

        /// <summary>Cobros pendientes de una bolsa de Sangre («libres» o «premium»).</summary>
        public static int SangrePendingCount(bool premium)
        {
            int n = 0;
            int from = premium ? SangreFreeSlots : 0;
            int to = premium ? SangreSlots : SangreFreeSlots;
            for (int i = from; i < to; i++)
                if (SangreIsComplete(i) && !SangreIsClaimed(i) && !SangreLocked(i)) n++;
            return n;
        }

        public static int SangreClaimedCount
        {
            get
            {
                int n = 0;
                for (int i = 0; i < SangreSlots; i++) if (SangreIsClaimed(i)) n++;
                return n;
            }
        }

        /// <summary>Cobros pendientes de la velada (Luna + Sangre), para las chapas de la UI.</summary>
        public static int TotalPendingClaims => PendingClaimsCount + SangrePendingClaimsCount;

        /// <summary>Cuenta atrás de la próxima tanda diaria («8 h 12 m»).</summary>
        public static string TimeToResetText() => DailyMissions.TimeToResetText();

        // ── Cobro ────────────────────────────────────────────────────────

        /// <summary>Cobra una misión diaria completada (XP del evento + Dulces).</summary>
        public static bool Claim(int slot)
        {
            if (!HalloweenEvent.IsActiveNow) return false;

            var def = GetAt(slot);
            if (def == null || !IsComplete(slot) || IsClaimed(slot)) return false;

            // Se marca antes de pagar: si el pago vuelve a pasar por aquí, ya está cobrada.
            _state.claimed[slot] = true;
            Save();

            Pay(def, "misión diaria");
            return true;
        }

        /// <summary>Cobra una exclusiva de Sangre completada (y con la vía abierta si es premium).</summary>
        public static bool SangreClaim(int index)
        {
            if (!HalloweenEvent.IsActiveNow) return false;

            var def = SangreGetAt(index);
            if (def == null || SangreLocked(index) || SangreIsClaimed(index) || !SangreIsComplete(index))
                return false;

            _state.sangreClaimed[index] = true;
            Save();

            Pay(def, def.premium ? "misión de Sangre premium" : "misión de Sangre libre");
            return true;
        }

        private static void Pay(HwMissionDef def, string why)
        {
            HalloweenProgress.AddXp(def.xp);
            HalloweenCurrency.Earn(def.dulces, $"halloween_mission_{def.id}");
            Debug.Log($"[HalloweenMissions] Cobrada «{def.title}» ({why}): +{def.xp} XP · +{def.dulces} {HalloweenCurrency.Label}");
        }

        // ── Progreso (lo llama GambitProgress desde los eventos de juego) ─

        public static void NoteMatch(MatchSummary summary)
        {
            if (!HalloweenEvent.IsActiveNow) return;

            var s = State;
            Bump(s.counters, summary);
            Bump(s.total, summary);
            Save();
        }

        /// <summary>Una captura tuya (solo blancas; el tablero del jugador es el blanco).</summary>
        public static void NoteCapture(PieceType capturedType)
        {
            if (!HalloweenEvent.IsActiveNow) return;

            var s = State;
            s.counters.captures++;
            s.total.captures++;
            if (capturedType == PieceType.Queen)
            {
                s.counters.queenCaptures++;
                s.total.queenCaptures++;
            }
            Save();
        }

        /// <summary>Compatibilidad: suma capturas sin tipo de pieza.</summary>
        public static void NoteCaptures(int count)
        {
            if (count <= 0 || !HalloweenEvent.IsActiveNow) return;

            var s = State;
            s.counters.captures += count;
            s.total.captures += count;
            Save();
        }

        public static void NotePuzzleSolved()
        {
            if (!HalloweenEvent.IsActiveNow) return;

            var s = State;
            s.counters.puzzlesSolved++;
            s.total.puzzlesSolved++;
            Save();
        }

        public static void NoteDailyChallenge()
        {
            if (!HalloweenEvent.IsActiveNow) return;

            var s = State;
            s.counters.dailyChallenge++;
            s.total.dailyChallenge++;
            Save();
        }

        private static void Bump(HwCounters c, MatchSummary summary)
        {
            if (c == null) return;

            c.matchesPlayed++;
            if (summary.outcome == MatchOutcome.Victory)
            {
                c.matchesWon++;
                if ((int)summary.level >= (int)WilderGambit.AI.DifficultyLevel.Knight) c.matchesWonHard++;
                if ((int)summary.level >= (int)WilderGambit.AI.DifficultyLevel.Master) c.matchesWonMaster++;
                if (!summary.lostQueen) c.noQueenLossWins++;
                if (summary.playerLosses <= 0) c.flawlessWins++;
                if (summary.totalTurns <= 25) c.fastMates++;
                if (summary.playerTurns <= 20) c.quickWins++;
            }
            if (summary.accuracy >= 80f) c.precision80++;
            if (summary.accuracy >= 95f) c.precision95++;
            if (summary.totalTurns >= 60) c.longGames++;
            // Solo cuenta con analíticas reales (sin ellas la precisión llega en 0
            // y cualquier partida parecería limpia).
            if (summary.blunders <= 0 && summary.accuracy > 0f && summary.totalTurns > 0)
                c.noBlunderGames++;

            int streak = WilderGambit.AI.DynamicDifficultyManager.WinStreak;
            if (streak > c.bestWinStreak) c.bestWinStreak = streak;
        }

        // ── Internos ─────────────────────────────────────────────────────

        /// <summary>
        /// Cuenta actual de la métrica. Lee el estado ya cargado y NUNCA pasa por
        /// <see cref="State"/>: State → EnsureCurrent → cobro del día anterior →
        /// Evaluate → State era un ciclo que se comía la pila.
        /// </summary>
        private static int Evaluate(HwMetric metric, HwCounters c)
        {
            if (c == null) return 0;

            switch (metric)
            {
                case HwMetric.MatchesPlayed:    return c.matchesPlayed;
                case HwMetric.MatchesWon:       return c.matchesWon;
                case HwMetric.MatchesWonHard:   return c.matchesWonHard;
                case HwMetric.MatchesWonMaster: return c.matchesWonMaster;
                case HwMetric.Precision80:      return c.precision80;
                case HwMetric.Precision95:      return c.precision95;
                case HwMetric.NoBlunderGames:   return c.noBlunderGames;
                case HwMetric.FlawlessWins:     return c.flawlessWins;
                case HwMetric.NoQueenLossWins:  return c.noQueenLossWins;
                case HwMetric.FastMates:        return c.fastMates;
                case HwMetric.QuickWins:        return c.quickWins;
                case HwMetric.LongGames:        return c.longGames;
                case HwMetric.Captures:         return c.captures;
                case HwMetric.QueenCaptures:    return c.queenCaptures;
                case HwMetric.PuzzlesSolved:    return c.puzzlesSolved;
                case HwMetric.DailyChallenge:   return c.dailyChallenge;
                case HwMetric.WinStreak3:       return c.bestWinStreak >= 3 ? 1 : 0;
                case HwMetric.WinStreak5:       return c.bestWinStreak >= 5 ? 1 : 0;
                default:                        return 0;
            }
        }

        private static HwMissionDef Find(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            foreach (var def in LunaPool)
                if (def.id == id) return def;
            return null;
        }

        private static HwMissionDef FindSangre(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            foreach (var def in SangreFreePool)
                if (def.id == id) return def;
            foreach (var def in SangrePaidPool)
                if (def.id == id) return def;
            return null;
        }

        /// <summary>Rota la tanda del día y conserva la selección de Sangre de la edición.</summary>
        private static void EnsureCurrent()
        {
            if (_state == null) Load();
            EnsureSangreSelection();

            if (_state.day == TodayKey && !NeedsReselect()) return;
            if (_closingDay) return;   // ya se está cerrando el día anterior

            _closingDay = true;
            try
            {
                var anterior = _state;

                // El día avanza ANTES de pagar lo del anterior: si el cobro vuelve a pedir
                // State, ya encuentra el día nuevo y no vuelve a cerrarlo.
                _state = NewStateFor(TodayKey, anterior);
                Save();

                // Día nuevo: cobrar lo completado y no reclamado para no perderlo.
                if (anterior != null && !string.IsNullOrEmpty(anterior.day))
                    AutoClaimPending(anterior, "cierre del día");

                Debug.Log($"[HalloweenMissions] Velada: nueva tanda para {_state.day}.");
            }
            finally
            {
                _closingDay = false;
            }
        }

        /// <summary>
        /// La tanda guardada del día quedó sin misiones válidas y el día ya
        /// pertenece a la ventana (p. ej. la QA tocó el estado antes de forzar
        /// ACTIVO, o el día se creó en pretemporada): hay que volver a sortearla.
        /// </summary>
        private static bool NeedsReselect()
        {
            if (_state.ids == null) return true;
            for (int i = 0; i < Slots; i++)
                if (Find(i < _state.ids.Length ? _state.ids[i] : null) != null) return false;
            return DayKeyWithinEvent(_state.day);
        }

        /// <summary>
        /// Asegura las 10 exclusivas de Sangre de la edición. Si el estado viene de
        /// otra edición (o de una versión anterior sin exclusivas), se vuelve a
        /// repartir: 5 libres + 5 premium de sus pools.
        /// </summary>
        private static void EnsureSangreSelection()
        {
            if (_state == null) return;

            bool ok = _state.edition == HalloweenEvent.Year
                      && _state.sangreIds != null && _state.sangreIds.Length == SangreSlots
                      && _state.sangreClaimed != null && _state.sangreClaimed.Length == SangreSlots;
            if (ok)
            {
                for (int i = 0; i < SangreSlots && ok; i++)
                    if (FindSangre(_state.sangreIds[i]) == null) ok = false;
            }
            if (ok) return;

            PickSangre(_state);
            Save();
            Debug.Log($"[HalloweenMissions] Vía Sangre: repartidas {SangreSlots} exclusivas de la edición {HalloweenEvent.Year}.");
        }

        /// <summary>Cobra lo completado del día que se cierra (solo la tanda de la Vía Luna).</summary>
        private static void AutoClaimPending(HwMissionState dia, string why)
        {
            if (dia == null || dia.ids == null) return;
            if (!DayKeyWithinEvent(dia.day)) return;   // tandas fuera de la velada no pagan

            for (int i = 0; i < Slots; i++)
            {
                var def = Find(i < dia.ids.Length ? dia.ids[i] : null);
                if (def == null || (dia.claimed != null && i < dia.claimed.Length && dia.claimed[i])) continue;
                if (Evaluate(def.metric, dia.counters) < def.target) continue;

                if (dia.claimed != null && i < dia.claimed.Length) dia.claimed[i] = true;
                HalloweenProgress.AddXpForced(def.xp);
                HalloweenCurrency.Earn(def.dulces, $"halloween_mission_auto_{def.id}");
                Debug.Log($"[HalloweenMissions] Cobro automático ({why}): «{def.title}» +{def.xp} XP · +{def.dulces} {HalloweenCurrency.Label}");
            }
        }

        private static bool DayKeyWithinEvent(string dayKey)
        {
            if (string.IsNullOrEmpty(dayKey)) return false;
            try
            {
                var day = DateTime.ParseExact(dayKey, "yyyy-MM-dd",
                    System.Globalization.CultureInfo.InvariantCulture);
                return HalloweenEvent.DayWithinEvent(day);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Tanda nueva del día sin perder las exclusivas de Sangre ya repartidas.</summary>
        private static HwMissionState NewStateFor(string dayKey, HwMissionState previous)
        {
            var state = new HwMissionState
            {
                day = dayKey,
                counters = new HwCounters(),
                total = previous?.total ?? new HwCounters(),
                edition = previous?.edition ?? 0,
                sangreIds = previous?.sangreIds ?? new string[SangreSlots],
                sangreClaimed = previous?.sangreClaimed ?? new bool[SangreSlots],
            };

            if (!DayKeyWithinEvent(dayKey)) return state;   // fuera de la velada: tanda vacía

            int seed = StableHash(dayKey);
            var rng = new System.Random(seed);

            // 1) Una misión fácil garantizada (rota entre las 3 según el día)
            string easy = EasyTrio[Mathf.Abs(seed) % EasyTrio.Length];
            state.ids[0] = easy;

            // 2) Dos más del resto del catálogo, sin repetir.
            var rest = new List<HwMissionDef>();
            foreach (var def in LunaPool)
                if (def.id != easy) rest.Add(def);

            for (int i = 1; i < Slots && rest.Count > 0; i++)
            {
                int pick = rng.Next(rest.Count);
                state.ids[i] = rest[pick].id;
                rest.RemoveAt(pick);
            }
            return state;
        }

        /// <summary>Reparte 5 libres + 5 premium del pool de Sangre; la mano cambia cada edición.</summary>
        private static void PickSangre(HwMissionState state)
        {
            state.edition = HalloweenEvent.Year;
            state.sangreIds = new string[SangreSlots];
            state.sangreClaimed = new bool[SangreSlots];
            state.total = new HwCounters();

            var rng = new System.Random(StableHash("sangre-" + HalloweenEvent.Year));
            PickUnique(SangreFreePool, SangreFreeSlots, 0, state.sangreIds, rng);
            PickUnique(SangrePaidPool, SangrePaidSlots, SangreFreeSlots, state.sangreIds, rng);
        }

        private static void PickUnique(HwMissionDef[] pool, int count, int offset, string[] ids,
            System.Random rng)
        {
            if (pool == null || ids == null) return;

            var bag = new List<HwMissionDef>(pool);
            for (int i = 0; i < count && bag.Count > 0; i++)
            {
                int pick = rng.Next(bag.Count);
                ids[offset + i] = bag[pick].id;
                bag.RemoveAt(pick);
            }
        }

        /// <summary>FNV-1a: el hash de string de .NET no es estable entre plataformas.</summary>
        private static int StableHash(string text)
        {
            unchecked
            {
                uint hash = 2166136261u;
                if (!string.IsNullOrEmpty(text))
                {
                    foreach (char ch in text)
                    {
                        hash ^= ch;
                        hash *= 16777619u;
                    }
                }
                return (int)(hash & 0x7FFFFFFF);
            }
        }

        private static void Load()
        {
            string json = PlayerPrefs.GetString(PrefKey, "");
            if (!string.IsNullOrEmpty(json))
            {
                try { _state = JsonUtility.FromJson<HwMissionState>(json); }
                catch (Exception e) { Debug.LogWarning("[HalloweenMissions] JSON inválido, se reinicia: " + e.Message); }
            }
            if (_state == null) _state = new HwMissionState();
            if (_state.ids == null || _state.ids.Length != Slots) _state.ids = new string[Slots];
            if (_state.claimed == null || _state.claimed.Length != Slots) _state.claimed = new bool[Slots];
            if (_state.counters == null) _state.counters = new HwCounters();
            if (_state.sangreIds == null || _state.sangreIds.Length != SangreSlots) _state.sangreIds = new string[SangreSlots];
            if (_state.sangreClaimed == null || _state.sangreClaimed.Length != SangreSlots) _state.sangreClaimed = new bool[SangreSlots];
            if (_state.total == null) _state.total = new HwCounters();
        }

        private static void Save()
        {
            if (_state == null) return;
            PlayerPrefs.SetString(PrefKey, JsonUtility.ToJson(_state));
            PlayerPrefs.Save();
        }

        // ── Depuración (menú Wilder Gambit › Halloween) ──────────────────

        /// <summary>Solo para el menú de depuración: completa la tanda diaria.</summary>
        public static void DebugCompleteToday()
        {
            var s = State;
            if (s.counters == null) s.counters = new HwCounters();
            var c = s.counters;
            c.matchesPlayed = Mathf.Max(c.matchesPlayed, 4);
            c.matchesWon = Mathf.Max(c.matchesWon, 3);
            c.matchesWonHard = Mathf.Max(c.matchesWonHard, 2);
            c.matchesWonMaster = Mathf.Max(c.matchesWonMaster, 2);
            c.precision80 = Mathf.Max(c.precision80, 2);
            c.precision95 = Mathf.Max(c.precision95, 2);
            c.noBlunderGames = Mathf.Max(c.noBlunderGames, 2);
            c.flawlessWins = Mathf.Max(c.flawlessWins, 2);
            c.noQueenLossWins = Mathf.Max(c.noQueenLossWins, 2);
            c.fastMates = Mathf.Max(c.fastMates, 2);
            c.quickWins = Mathf.Max(c.quickWins, 1);
            c.longGames = Mathf.Max(c.longGames, 2);
            c.captures = Mathf.Max(c.captures, 15);
            c.queenCaptures = Mathf.Max(c.queenCaptures, 1);
            c.puzzlesSolved = Mathf.Max(c.puzzlesSolved, 4);
            c.dailyChallenge = Mathf.Max(c.dailyChallenge, 1);
            c.bestWinStreak = Mathf.Max(c.bestWinStreak, 5);
            Save();
            Debug.Log("[HalloweenMissions] Depuración: misiones diarias completadas sin cobrar.");
        }

        /// <summary>Solo para el menú de depuración: completa las exclusivas de Sangre.</summary>
        public static void DebugCompleteSangre()
        {
            var s = State;
            if (s.total == null) s.total = new HwCounters();
            var c = s.total;
            c.matchesPlayed = Mathf.Max(c.matchesPlayed, 10);
            c.matchesWon = Mathf.Max(c.matchesWon, 8);
            c.matchesWonHard = Mathf.Max(c.matchesWonHard, 6);
            c.matchesWonMaster = Mathf.Max(c.matchesWonMaster, 3);
            c.precision80 = Mathf.Max(c.precision80, 4);
            c.precision95 = Mathf.Max(c.precision95, 3);
            c.noBlunderGames = Mathf.Max(c.noBlunderGames, 4);
            c.flawlessWins = Mathf.Max(c.flawlessWins, 3);
            c.noQueenLossWins = Mathf.Max(c.noQueenLossWins, 3);
            c.fastMates = Mathf.Max(c.fastMates, 3);
            c.quickWins = Mathf.Max(c.quickWins, 2);
            c.longGames = Mathf.Max(c.longGames, 3);
            c.captures = Mathf.Max(c.captures, 40);
            c.queenCaptures = Mathf.Max(c.queenCaptures, 3);
            c.puzzlesSolved = Mathf.Max(c.puzzlesSolved, 5);
            c.dailyChallenge = Mathf.Max(c.dailyChallenge, 2);
            c.bestWinStreak = Mathf.Max(c.bestWinStreak, 5);
            Save();
            Debug.Log($"[HalloweenMissions] Depuración: exclusivas de Sangre completadas "
                      + $"({SangreCompletedCount(false)}/{SangreFreeSlots} libres · "
                      + $"{SangreCompletedCount(true)}/{SangrePaidSlots} premium) sin cobrar.");
        }

        public static void DebugReset()
        {
            _state = null;
            PlayerPrefs.DeleteKey(PrefKey);
            PlayerPrefs.DeleteKey(LegacyPrefKey);
            PlayerPrefs.Save();
        }
    }
}
