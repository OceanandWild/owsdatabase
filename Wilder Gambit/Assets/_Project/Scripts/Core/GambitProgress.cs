using UnityEngine;
using WilderGambit.AI;

namespace WilderGambit.Core
{
    /// <summary>
    /// Puente entre el juego y la economía: escucha los eventos de partida/puzzle y los
    /// traduce en progreso de misiones diarias, barra semanal y logros. Lo inicializan
    /// GameManager y MainMenuController (es idempotente).
    /// </summary>
    public static class GambitProgress
    {
        private static bool _initialized;

        /// <summary>Se llama cuando cambia cualquier progreso (la UI se repinta).</summary>
        public static event System.Action OnChanged;

        public static void Init()
        {
            if (_initialized) return;
            _initialized = true;

            GameEvents.OnPieceCaptured += HandleCapture;
            GameEvents.OnMatchFinished += HandleMatch;
            GameEvents.OnPuzzleSolved += HandlePuzzleSolved;
            GameEvents.OnDailyChallengeCompleted += HandleDailyChallenge;

            // Red de seguridad: si el juego se cierra, se pausa o pierde el foco, el progreso
            // local se vuelca a disco (la partida puede morir sin pasar por ningún guardado).
            ProgressAutosave.EnsureExists();

            // El mundo cambió al entrar en Play: sincronizar lo persistido
            WeeklyProgress.SyncToday(DailyMissions.CompletedCount);
            SyncVariantsOwned();
            Achievements.NotePuzzleRating(CurrentPuzzleRating);

            // Si el pase de temporada aún no arrancó, el XP en crudo se limpia:
            // el contador tiene que empezar en 0 el día del inicio.
            SeasonProgress.PurgeXpIfPreSeason();

            // La velada de Halloween tiene su propio contador: misma política.
            HalloweenProgress.PurgeIfNotStarted();

            UnityEngine.Debug.Log("[GambitProgress] Listo (misiones, barra semanal y logros activos).");
        }

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.SubsystemRegistration)]
        private static void ResetStatics()
        {
            _initialized = false;
            OnChanged = null;
        }

        // ── Eventos ───────────────────────────────────────────────────────────

        private static void HandleCapture(CaptureInfo info)
        {
            if (info.byColor == TeamColor.White)
            {
                DailyMissions.NoteCaptures(1);
                // Velada de Halloween (no-op fuera de la ventana del evento).
                // Se pasa el tipo de pieza: las misiones de Sangre cuentan damas.
                HalloweenMissions.NoteCapture(info.type);
                HalloweenProgress.NoteCapture();
            }

            NotifyChanged();
        }

        private static void HandleMatch(MatchSummary summary)
        {
            DailyMissions.NoteMatch(summary);
            WeeklyProgress.NoteMatch(summary);
            Achievements.NoteMatch(summary);
            // Una partida terminada siempre es real: las sesiones de práctica son de
            // entrenamiento táctico y nunca llegan aquí (no disparan fin de partida).
            SeasonProgress.NoteMatch(summary.outcome == MatchOutcome.Victory, false);
            // Velada de Halloween: XP del evento y misiones (no-op fuera de la ventana).
            HalloweenProgress.NoteMatch(summary.outcome == MatchOutcome.Victory);
            HalloweenMissions.NoteMatch(summary);

            WeeklyProgress.SyncToday(DailyMissions.CompletedCount);
            if (WeeklyProgress.FilledCount >= WeeklyProgress.SegmentCount)
                Achievements.NotePerfectWeek(1);
            SyncVariantsOwned();

            NotifyChanged();
        }

        private static void HandlePuzzleSolved(Puzzle puzzle, bool clean)
        {
            DailyMissions.NotePuzzleSolved();
            WeeklyProgress.NotePuzzleSolved();
            Achievements.NotePuzzleRating(CurrentPuzzleRating);
            SeasonProgress.NotePuzzleSolved();
            HalloweenProgress.NotePuzzleSolved();
            HalloweenMissions.NotePuzzleSolved();

            WeeklyProgress.SyncToday(DailyMissions.CompletedCount);
            NotifyChanged();
        }

        private static void HandleDailyChallenge(Puzzle puzzle)
        {
            DailyMissions.NoteDailyChallenge();
            WeeklyProgress.NoteDailyChallenge();
            Achievements.NotePuzzleRating(CurrentPuzzleRating);
            HalloweenProgress.NoteDailyChallenge();
            HalloweenMissions.NoteDailyChallenge();

            WeeklyProgress.SyncToday(DailyMissions.CompletedCount);
            NotifyChanged();
        }

        // ── Consultas para la UI ──────────────────────────────────────────────

        /// <summary>Cobros disponibles ahora mismo (misiones, semanales y cofre).</summary>
        public static int PendingClaimsCount
        {
            get
            {
                int n = 0;
                for (int i = 0; i < DailyMissions.Slots; i++)
                    if (DailyMissions.IsComplete(i) && !DailyMissions.IsClaimed(i)) n++;

                for (int i = 0; i < WeeklyProgress.WeeklyMissions.Length; i++)
                    if (WeeklyProgress.IsWeeklyComplete(i) && !WeeklyProgress.IsWeeklyClaimed(i)) n++;

                if (WeeklyProgress.CanClaimChest) n += 1;
                return n;
            }
        }

        public static bool HasPendingClaims => PendingClaimsCount > 0;

        /// <summary>Variantes en propiedad (Lancero + Jinete + Nigromante + Fragua + Vampira).</summary>
        public static int OwnedVariants
        {
            get
            {
                int n = PieceLoadoutManager.IsLancerOwned() ? 1 : 0;
                if (PieceLoadoutManager.IsRiderOwned()) n++;
                if (PieceLoadoutManager.IsNecroOwned()) n++;
                if (PieceLoadoutManager.IsFraguaOwned()) n++;
                if (PieceLoadoutManager.IsVampireOwned()) n++;
                return n;
            }
        }

        public static int CurrentPuzzleRating => PuzzleManager.Instance != null ? PuzzleManager.Instance.PlayerRating : 1000;

        public static void SyncVariantsOwned()
        {
            Achievements.NoteVariantsOwned(OwnedVariants);
        }

        public static void NotifyChanged() => OnChanged?.Invoke();

        // ── Depuración (útil para probar la barra sin jugar 7 días) ───────────

        public static class Debug
        {
            public static void AddGambits(int amount)
            {
                // Herramienta de depuración: puede dar varias veces al día
                GambitEconomy.Earn(amount, GambitSource.Bonus, meta: "dev", note: "depuración", ignorePaymentLimit: true);
                NotifyChanged();
            }

            public static void FillWeek(int days)
            {
                WeeklyProgress.DebugFillDays(days);
                Achievements.NotePerfectWeek(WeeklyProgress.FilledCount >= WeeklyProgress.SegmentCount ? 1 : 0);
                NotifyChanged();
            }

            public static void AddWeeklyCounters(int wins, int puzzles)
            {
                WeeklyProgress.DebugAddWeeklyCounter(wins, puzzles);
                NotifyChanged();
            }

            public static void ResetDay()
            {
                GambitLedger.DebugResetToday();
                DailyMissions.DebugResetToday();
                NotifyChanged();
            }

            public static void ResetWeek()
            {
                WeeklyProgress.DebugResetWeek();
                NotifyChanged();
            }

            public static void ResetAchievements()
            {
                Achievements.DebugReset();
                NotifyChanged();
            }

            public static void ResetEverything()
            {
                PlayerPrefs.DeleteKey("WG_GambitLedger");
                PlayerPrefs.DeleteKey("WG_DailyMissions");
                PlayerPrefs.DeleteKey("WG_WeeklyProgress");
                PlayerPrefs.DeleteKey("WG_Achievements");
                PlayerPrefs.Save();
                NotifyChanged();
                UnityEngine.Debug.Log("[GambitProgress] Progreso de Gambits reiniciado por completo.");
            }
        }
    }
}
