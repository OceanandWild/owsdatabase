using System;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>Estado visual de un segmento de la barra semanal.</summary>
    public enum SegmentState
    {
        Future,   // día por llegar
        Today,    // día en curso (puede estar a medias)
        Complete, // 3/3 completadas
        Missed,   // día pasado sin completar
    }

    /// <summary>Foto de un segmento para pintarlo.</summary>
    public struct WeekSegment
    {
        public int index;             // 0 = lunes
        public string dayInitial;     // L M X J V S D
        public string dayNumber;      // 21
        public int missionsDone;      // 0..3
        public float fill;            // 0..1
        public int reward;
        public bool paid;
        public SegmentState state;
    }

    [Serializable]
    public class WeekData
    {
        public string weekKey = "";
        public string[] dayDates = new string[7];
        public int[] dayMissionsDone = new int[7];
        public bool[] dayPaid = new bool[7];
        public bool chestClaimed;
        public bool[] weeklyClaimed = new bool[3];

        public int missionsCompleted;   // misiones diarias completadas esta semana
        public int matchesWon;
        public int puzzlesSolved;
        public int perfectWeeks;        // semanas perfectas consecutivas previas

        public void EnsureArrays()
        {
            if (dayDates == null || dayDates.Length != WeeklyProgress.SegmentCount) dayDates = new string[WeeklyProgress.SegmentCount];
            if (dayMissionsDone == null || dayMissionsDone.Length != WeeklyProgress.SegmentCount) dayMissionsDone = new int[WeeklyProgress.SegmentCount];
            if (dayPaid == null || dayPaid.Length != WeeklyProgress.SegmentCount) dayPaid = new bool[WeeklyProgress.SegmentCount];
            if (weeklyClaimed == null || weeklyClaimed.Length != 3) weeklyClaimed = new bool[3];
        }
    }

    /// <summary>
    /// Barra del Atelier: 7 segmentos (lunes a domingo). Completar las 3 misiones diarias
    /// llena el segmento de ese día y paga su recompensa; los 7 segmentos desbloquean el
    /// cofre. Cada semana perfecta consecutiva sube el cofre (+200, tope 1.600).
    /// </summary>
    public static class WeeklyProgress
    {
        public const int SegmentCount = 7;
        private const string PREF_KEY = "WG_WeeklyProgress";

        /// <summary>Recompensa de cada segmento, de lunes a domingo.</summary>
        public static readonly int[] SegmentRewards = { 50, 60, 70, 80, 90, 110, 150 };

        public const int ChestBase = 1000;
        public const int ChestStep = 200;
        public const int ChestCap = 1600;

        private static readonly string[] DayInitials = { "L", "M", "X", "J", "V", "S", "D" };
        private static readonly string[] DayNames = { "Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo" };

        /// <summary>Misiones semanales fijas (se reinician el lunes).</summary>
        public static readonly MissionDef[] WeeklyMissions =
        {
            new MissionDef { id = "week_wins",     title = "Victorias de la semana", desc = "Gana {t} partidas",                  icon = "🏆", target = 10, payout = 250, metric = MissionMetric.WeekMatchesWon,     scope = MissionScope.Weekly },
            new MissionDef { id = "week_puzzles",  title = "Mente incansable",       desc = "Resuelve {t} puzzles",               icon = "🧩", target = 20, payout = 250, metric = MissionMetric.WeekPuzzlesSolved, scope = MissionScope.Weekly },
            new MissionDef { id = "week_missions", title = "Constancia",             desc = "Completa {t} misiones diarias",      icon = "📜", target = 15, payout = 350, metric = MissionMetric.WeekDailyMissions, scope = MissionScope.Weekly },
        };

        private static WeekData _data;

        // ── Semana actual ─────────────────────────────────────────────────────

        public static DateTime WeekStart
        {
            get
            {
                var today = DateTime.Now.Date;
                int mondayBased = ((int)today.DayOfWeek + 6) % 7; // lunes = 0 … domingo = 6
                return today.AddDays(-mondayBased);
            }
        }

        public static string WeekKey => WeekStart.ToString("yyyy-MM-dd");
        public static int TodayIndex => ((int)DateTime.Now.DayOfWeek + 6) % 7;

        public static WeekData Data
        {
            get
            {
                EnsureCurrentWeek();
                return _data;
            }
        }

        public static int FilledCount
        {
            get
            {
                var d = Data;
                int n = 0;
                for (int i = 0; i < SegmentCount; i++)
                    if (d.dayMissionsDone[i] >= DailyMissions.Slots) n++;
                return n;
            }
        }

        /// <summary>Gambits que paga el cofre esta semana (sube con la racha de semanas perfectas).</summary>
        public static int ChestAmount => Mathf.Min(ChestCap, ChestBase + ChestStep * Mathf.Max(0, Data.perfectWeeks));

        public static int PerfectWeeks => Data.perfectWeeks;

        public static bool CanClaimChest
        {
            get
            {
                var d = Data;
                return !d.chestClaimed && FilledCount >= SegmentCount;
            }
        }

        public static WeekSegment GetSegment(int index)
        {
            var d = Data;
            index = Mathf.Clamp(index, 0, SegmentCount - 1);
            int done = Mathf.Clamp(d.dayMissionsDone[index], 0, DailyMissions.Slots);
            bool isToday = index == TodayIndex;
            bool complete = done >= DailyMissions.Slots;

            var state = complete ? SegmentState.Complete
                      : isToday ? SegmentState.Today
                      : index < TodayIndex ? SegmentState.Missed
                      : SegmentState.Future;

            return new WeekSegment
            {
                index = index,
                dayInitial = DayInitials[index],
                dayNumber = d.dayDates[index] != null && d.dayDates[index].Length >= 10
                    ? d.dayDates[index].Substring(8, 2)
                    : (WeekStart.AddDays(index).Day.ToString("00")),
                missionsDone = done,
                fill = done / (float)DailyMissions.Slots,
                reward = SegmentRewards[index],
                paid = d.dayPaid[index],
                state = state,
            };
        }

        public static string DayName(int index) => DayNames[Mathf.Clamp(index, 0, 6)];

        public static string TimeToWeekResetText()
        {
            var now = DateTime.Now;
            var nextMonday = WeekStart.AddDays(7);
            var span = nextMonday - now;
            return $"{(int)span.TotalDays} d {span.Hours} h";
        }

        // ── Progreso ──────────────────────────────────────────────────────────

        /// <summary>
        /// Sincroniza el día de hoy con las misiones diarias completadas. Paga el segmento
        /// la primera vez que el día llega a 3/3 y alimenta la misión semanal de constancia.
        /// </summary>
        public static void SyncToday(int missionsDoneToday)
        {
            var d = Data;
            int i = TodayIndex;
            string todayKey = DailyMissions.TodayKey;

            if (d.dayDates[i] != todayKey)
            {
                // Primera sincronización de este día (o el día cambió bajo nuestros pies)
                d.dayDates[i] = todayKey;
                d.dayMissionsDone[i] = 0;
                d.dayPaid[i] = false;
            }

            int done = Mathf.Clamp(missionsDoneToday, 0, DailyMissions.Slots);
            int previous = d.dayMissionsDone[i];
            if (done == previous && d.dayDates[i] == todayKey) return;

            // Constancia semanal: cuenta cada misión diaria que se completa (no se pierde
            // al reiniciar el juego porque se apoya en el progreso persistido del día)
            if (done > previous) d.missionsCompleted += done - previous;
            d.dayMissionsDone[i] = done;
            Save();

            if (done >= DailyMissions.Slots && !d.dayPaid[i])
            {
                d.dayPaid[i] = true;
                Save();
                SeasonProgress.NoteSegmentPerfect();

                var payout = GambitEconomy.Earn(
                    SegmentRewards[i],
                    GambitSource.WeeklySegment,
                    meta: $"day{i + 1}",
                    note: $"Día perfecto ({DayNames[i]})");

                Debug.Log($"[WeeklyProgress] {DayNames[i]} perfecto: +{payout.granted}G ({FilledCount}/7).");
            }
        }

        public static void NoteMatch(MatchSummary summary)
        {
            if (summary.outcome != MatchOutcome.Victory) return;
            Data.matchesWon++;
            Save();
        }

        public static void NotePuzzleSolved()
        {
            Data.puzzlesSolved++;
            Save();
        }

        public static void NoteDailyChallenge()
        {
            // El desafío diario también cuenta como constancia del día
            SyncToday(DailyMissions.CompletedCount);
        }

        // ── Misiones semanales ────────────────────────────────────────────────

        public static int WeeklyProgressValue(int index)
        {
            if (index < 0 || index >= WeeklyMissions.Length) return 0;
            var def = WeeklyMissions[index];
            var d = Data;
            switch (def.metric)
            {
                case MissionMetric.WeekMatchesWon:     return Mathf.Clamp(d.matchesWon, 0, def.target);
                case MissionMetric.WeekPuzzlesSolved:  return Mathf.Clamp(d.puzzlesSolved, 0, def.target);
                case MissionMetric.WeekDailyMissions:  return Mathf.Clamp(d.missionsCompleted, 0, def.target);
                default:                               return 0;
            }
        }

        public static bool IsWeeklyComplete(int index)
        {
            if (index < 0 || index >= WeeklyMissions.Length) return false;
            return WeeklyProgressValue(index) >= WeeklyMissions[index].target;
        }

        public static bool IsWeeklyClaimed(int index)
        {
            var d = Data;
            return index >= 0 && index < d.weeklyClaimed.Length && d.weeklyClaimed[index];
        }

        public static int WeeklyCompletedCount
        {
            get
            {
                int n = 0;
                for (int i = 0; i < WeeklyMissions.Length; i++) if (IsWeeklyComplete(i)) n++;
                return n;
            }
        }

        public static GambitPayout ClaimWeekly(int index)
        {
            var payout = new GambitPayout();
            if (index < 0 || index >= WeeklyMissions.Length) return payout;
            if (!IsWeeklyComplete(index) || IsWeeklyClaimed(index)) return payout;

            var def = WeeklyMissions[index];
            payout = GambitEconomy.Earn(def.payout, GambitSource.WeeklyMission, meta: def.id, note: def.title);
            Data.weeklyClaimed[index] = true;
            Save();
            if (payout.granted > 0) SeasonProgress.NoteMissionClaimed(weekly: true);
            return payout;
        }

        // ── Cofre ─────────────────────────────────────────────────────────────

        public static GambitPayout ClaimChest()
        {
            var payout = new GambitPayout();
            if (!CanClaimChest) return payout;

            int amount = ChestAmount;
            payout = GambitEconomy.Earn(amount, GambitSource.WeeklyChest, meta: WeekKey, note: "Semana perfecta");
            Data.chestClaimed = true;
            Save();
            Debug.Log($"[WeeklyProgress] ¡Cofre reclamado! +{payout.granted}G de {amount}G.");
            return payout;
        }

        // ── Persistencia y reinicio de semana ─────────────────────────────────

        private static void EnsureCurrentWeek()
        {
            if (_data == null) Load();
            if (_data.weekKey == WeekKey) return;

            bool previousPerfect = false;
            var old = _data;

            // Si la semana pasada quedó perfecta, se cuenta como racha (el cofre sube)
            if (old != null)
            {
                int filled = 0;
                for (int i = 0; i < SegmentCount; i++)
                    if (old.dayMissionsDone != null && i < old.dayMissionsDone.Length &&
                        old.dayMissionsDone[i] >= DailyMissions.Slots) filled++;
                previousPerfect = filled >= SegmentCount;

                // Nunca se pierde un cofre ganado: se cobra al cerrar la semana
                if (previousPerfect && !old.chestClaimed)
                {
                    int amount = Mathf.Min(ChestCap, ChestBase + ChestStep * Mathf.Max(0, old.perfectWeeks));
                    var payout = GambitEconomy.Earn(amount, GambitSource.WeeklyChest, meta: old.weekKey, note: "Cierre de semana perfecta");
                    old.chestClaimed = true;
                    Debug.Log($"[WeeklyProgress] Cofre de la semana {old.weekKey} cobrado al cerrar: +{payout.granted}G");
                }
            }

            int perfectWeeks = previousPerfect ? (old?.perfectWeeks ?? 0) + 1 : 0;

            _data = new WeekData
            {
                weekKey = WeekKey,
                perfectWeeks = perfectWeeks,
            };
            _data.EnsureArrays();
            for (int i = 0; i < SegmentCount; i++)
                _data.dayDates[i] = WeekStart.AddDays(i).ToString("yyyy-MM-dd");
            Save();

            Debug.Log($"[WeeklyProgress] Nueva semana {_data.weekKey} (semanas perfectas seguidas: {perfectWeeks}).");
        }

        private static void Load()
        {
            string json = PlayerPrefs.GetString(PREF_KEY, "");
            if (!string.IsNullOrEmpty(json))
            {
                try { _data = JsonUtility.FromJson<WeekData>(json); }
                catch (Exception e) { Debug.LogWarning("[WeeklyProgress] JSON inválido, se reinicia: " + e.Message); }
            }
            if (_data == null)
            {
                _data = new WeekData { weekKey = WeekKey };
                for (int i = 0; i < SegmentCount; i++)
                    _data.dayDates[i] = WeekStart.AddDays(i).ToString("yyyy-MM-dd");
            }
            _data.EnsureArrays();
        }

        private static void Save()
        {
            if (_data == null) return;
            PlayerPrefs.SetString(PREF_KEY, JsonUtility.ToJson(_data));
            PlayerPrefs.Save();
        }

        // ── Depuración ────────────────────────────────────────────────────────

        /// <summary>Marca días perfectos a mano (panel de depuración).</summary>
        public static void DebugFillDays(int count)
        {
            var d = Data;
            for (int i = 0; i < SegmentCount && i < count; i++)
            {
                d.dayMissionsDone[i] = DailyMissions.Slots;
                d.dayPaid[i] = true;
            }
            d.missionsCompleted = Mathf.Max(d.missionsCompleted, count * DailyMissions.Slots);
            Save();
            Debug.Log($"[WeeklyProgress] Depuración: {count}/7 días rellenados.");
        }

        public static void DebugResetWeek()
        {
            _data = new WeekData { weekKey = WeekKey };
            _data.EnsureArrays();
            for (int i = 0; i < SegmentCount; i++)
                _data.dayDates[i] = WeekStart.AddDays(i).ToString("yyyy-MM-dd");
            Save();
        }

        /// <summary>
        /// Solo para probar el cofre a mano: lo deja sin cobrar para que el botón
        /// COBRAR COFRE quede habilitado tras rellenar la semana (si ya se cobró,
        /// rellenar días no basta porque <c>CanClaimChest</c> seguiría en falso).
        /// </summary>
        public static void DebugResetChest()
        {
            var d = Data;
            d.chestClaimed = false;
            Save();
            Debug.Log("[WeeklyProgress] Depuración: cofre marcado como pendiente de cobro.");
        }

        public static void DebugAddWeeklyCounter(int matchesWon, int puzzlesSolved)
        {
            var d = Data;
            d.matchesWon += matchesWon;
            d.puzzlesSolved += puzzlesSolved;
            Save();
        }
    }
}
