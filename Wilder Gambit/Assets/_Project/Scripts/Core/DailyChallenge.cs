using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Un puzzle único por día (elegido con semilla de la fecha) con racha de días seguidos:
    /// 50/60/70/80/100 Gambits según cuántos días lleves completándolo. Se paga por
    /// GambitEconomy, así que respeta los topes diarios.
    /// </summary>
    public class DailyChallenge : MonoBehaviour
    {
        public static DailyChallenge Instance { get; private set; }

        private const string LAST_COMPLETED_KEY = "DailyChallengeLastCompleted";
        private const string STREAK_KEY = "DailyChallengeStreak";

        /// <summary>Pago según la racha: día 1, 2, 3, 4 y 5+.</summary>
        private static readonly int[] StreakRewards = { 50, 60, 70, 80, 100 };

        /// <summary>Día local (el mismo que usan misiones y barra semanal).</summary>
        public static string TodayKey => System.DateTime.Now.ToString("yyyy-MM-dd");

        public bool IsCompletedToday => PlayerPrefs.GetString(LAST_COMPLETED_KEY, "") == TodayKey;
        public bool IsAvailable => !IsCompletedToday;

        /// <summary>Días seguidos completándolo (los previos; se incrementa al completar).</summary>
        public int Streak => PlayerPrefs.GetInt(STREAK_KEY, 0);

        /// <summary>Lo que pagaría completarlo ahora mismo.</summary>
        public int PendingReward
        {
            get
            {
                int next = NextStreakValue();
                return StreakRewards[Mathf.Clamp(next - 1, 0, StreakRewards.Length - 1)];
            }
        }

        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("DailyChallenge");
            go.AddComponent<DailyChallenge>();
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            EnsureStreakIsCurrent();
        }

        /// <summary>
        /// Semilla estable a partir de la fecha. El hash de un string no es igual entre
        /// ejecuciones/runtimes, y el «reto de hoy» tiene que ser el mismo todo el día.
        /// </summary>
        private static int SeedFor(string dayKey)
        {
            string digits = dayKey.Replace("-", "");
            return int.TryParse(digits, out int value) ? value : dayKey.Length * 7919;
        }

        /// <summary>Gets today's daily challenge puzzle.</summary>
        public Puzzle GetDailyPuzzle()
        {
            var rng = new System.Random(SeedFor(TodayKey));

            // Mate en 1, todas comprobadas con el Stockfish del proyecto
            // (Tools/audit_puzzle_solutions.py). Si se toca una posición hay que
            // volver a verificar que su jugada sigue siendo mate.
            string[] dailyFens = new[]
            {
                "6k1/5ppp/8/8/8/8/5PPP/4R1K1 w - - 0 1",
                "7k/5ppp/8/8/8/8/5PPP/4R1K1 w - - 0 1",
                "6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1",
                "7k/8/6K1/8/8/8/8/R7 w - - 0 1",
                "6k1/4Qppp/8/8/8/8/5PPP/6K1 w - - 0 1",
                "6k1/5ppp/8/8/8/8/8/2Q3K1 w - - 0 1",
                "6k1/5ppp/8/8/8/8/5PPP/3Q2RK w - - 0 1",
                "6k1/5ppp/8/8/8/8/4QPPP/6K1 w - - 0 1",
                "2k5/8/2K5/8/8/8/8/7R w - - 0 1",
                "7k/R7/1R6/8/8/8/8/6K1 w - - 0 1",
                "6rk/6pp/7N/8/8/8/8/6K1 w - - 0 1",
                "r1bqkb1r/pppp1ppp/2n2n2/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR w KQkq - 0 1",
            };

            string[] dailySolutions = new[]
            {
                "e1e8",   // torre a la 8ª
                "e1e8",   // igual pero con el rey en h8
                "a1a8",   // torre desde a1
                "a1a8",   // rey pegado al rincón
                "e7e8",   // dama a la 8ª (también vale e7d8)
                "c1c8",   // dama por la columna abierta
                "d1d8",   // dama apoyada por la torre
                "e2e8",   // dama + peones de rey
                "h1h8",   // torre y rey en el centro
                "b6b8",   // mate de escalera
                "h6f7",   // mate ahogado con caballo
                "h5f7",   // mate del pastor
            };

            int idx = rng.Next(dailyFens.Length);

            return new Puzzle
            {
                id = "daily_" + TodayKey,
                fen = dailyFens[idx],
                solutionMoves = new[] { dailySolutions[idx] },
                difficulty = 2,
                theme = "daily",
                description = "🎯 Desafío Diario: mate en 1. ¡Encuentra el remate!",
            };
        }

        /// <summary>Marca el reto de hoy como completado y paga la racha correspondiente.</summary>
        public int CompleteDailyChallenge()
        {
            if (IsCompletedToday) return 0;

            EnsureStreakIsCurrent();
            int nextStreak = NextStreakValue();
            PlayerPrefs.SetInt(STREAK_KEY, nextStreak);
            PlayerPrefs.SetString(LAST_COMPLETED_KEY, TodayKey);
            PlayerPrefs.Save();

            int amount = StreakRewards[Mathf.Clamp(nextStreak - 1, 0, StreakRewards.Length - 1)];
            var payout = GambitEconomy.Earn(amount, GambitSource.DailyChallenge, meta: TodayKey, note: $"racha {nextStreak} días");

            Debug.Log($"[DailyChallenge] Completado (racha {nextStreak} días): +{payout.granted}G");

            GameEvents.RaiseDailyChallengeCompleted(GetDailyPuzzle());
            return payout.granted;
        }

        /// <summary>Premio máximo de la escalera (día 5 en adelante).</summary>
        public static int MaxReward => StreakRewards[StreakRewards.Length - 1];

        /// <summary>
        /// Estado del reto en una sola línea: qué se paga hoy y cómo va la racha.
        /// El importe se dice una sola vez para que la fila no se lea repetida.
        /// </summary>
        public string StreakText
        {
            get
            {
                string days = $"{Streak} día{(Streak == 1 ? "" : "s")}";

                if (IsCompletedToday) return $"✓ Completado hoy · racha: {days} · vuelve mañana";

                if (Streak > 0)
                {
                    // La racha que se enseña es la de antes de hoy: hay que decir a qué día se
                    // llega si se completa, o parece que el premio de hoy fuera el del día 1.
                    return $"Premio de hoy: {PendingReward} Gambits · racha: {days} · hoy sería el día {NextStreakValue()}";
                }

                return $"Premio de hoy: {PendingReward} Gambits · cada día seguido sube el premio (hasta {MaxReward})";
            }
        }

        // ── Internos ──────────────────────────────────────────────────────────

        private int NextStreakValue()
        {
            string last = PlayerPrefs.GetString(LAST_COMPLETED_KEY, "");
            if (string.IsNullOrEmpty(last)) return 1;

            // Si el último completado fue ayer (o hoy), la racha sigue; si no, se reinicia
            if (last == TodayKey) return Mathf.Max(1, Streak);
            if (last == System.DateTime.Now.AddDays(-1).ToString("yyyy-MM-dd")) return Streak + 1;
            return 1;
        }

        /// <summary>Si se saltó un día sin completarlo, la racha se pierde.</summary>
        private void EnsureStreakIsCurrent()
        {
            string last = PlayerPrefs.GetString(LAST_COMPLETED_KEY, "");
            if (string.IsNullOrEmpty(last)) return;

            bool today = last == TodayKey;
            bool yesterday = last == System.DateTime.Now.AddDays(-1).ToString("yyyy-MM-dd");
            if (!today && !yesterday && Streak != 0)
            {
                PlayerPrefs.SetInt(STREAK_KEY, 0);
                PlayerPrefs.Save();
                Debug.Log("[DailyChallenge] Racha reiniciada (día perdido).");
            }
        }

        public void DebugResetStreak()
        {
            PlayerPrefs.SetInt(STREAK_KEY, 0);
            PlayerPrefs.DeleteKey(LAST_COMPLETED_KEY);
            PlayerPrefs.Save();
        }
    }
}
