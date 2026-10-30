using UnityEngine;

namespace WilderGambit.AI
{
    /// <summary>
    /// Sistema de escalado dinámico de dificultad. Rastrea rachas de victorias/derrotas
    /// y sugiere subir o bajar la dificultad cuando el jugador domina o sufre.
    /// Persistido en PlayerPrefs.
    /// </summary>
    public static class DynamicDifficultyManager
    {
        private const string PREF_WIN_STREAK  = "WG_WinStreak";
        private const string PREF_LOSS_STREAK = "WG_LossStreak";
        private const string PREF_GAMES_PLAYED = "WG_GamesPlayed";
        private const string PREF_SUGGESTED_LEVEL = "WG_SuggestedLevel";
        private const string PREF_LAST_LEVEL = "WG_LastDifficulty";
        private const string PREF_DISMISSED_SUGGESTION = "WG_DismissedSuggestion";
        private const string PREF_WINS_PREFIX = "WG_Wins_";
        private const string PREF_LOSSES_PREFIX = "WG_Losses_";
        private const string PREF_DRAWS_PREFIX = "WG_Draws_";
        private const string PREF_STREAK_LEVEL = "WG_StreakLevel";
        private const int STREAK_THRESHOLD = 3;

        public static int WinStreak
        {
            get { EnsureStreakBelongsToLevel(); return PlayerPrefs.GetInt(PREF_WIN_STREAK, 0); }
        }

        public static int LossStreak
        {
            get { EnsureStreakBelongsToLevel(); return PlayerPrefs.GetInt(PREF_LOSS_STREAK, 0); }
        }

        /// <summary>
        /// Migración de datos antiguos: la racha era global (acumulaba victorias de
        /// cualquier nivel) mientras que la tarjeta muestra el récord de un solo nivel,
        /// por lo que el banner podía decir "Racha de 4" con la tarjeta en "3V".
        /// Ahora la racha es por nivel; este ajuste una sola vez limita la racha heredada
        /// al récord del nivel actual para que nunca la supere.
        /// </summary>
        private static void EnsureStreakBelongsToLevel()
        {
            if (PlayerPrefs.HasKey(PREF_STREAK_LEVEL)) return;

            // Se fija primero el nivel para evitar reentrada desde los getters de racha
            PlayerPrefs.SetInt(PREF_STREAK_LEVEL, (int)LastDifficulty);
            var rec = GetRecord(LastDifficulty);
            PlayerPrefs.SetInt(PREF_WIN_STREAK,
                Mathf.Min(PlayerPrefs.GetInt(PREF_WIN_STREAK, 0), rec.wins));
            PlayerPrefs.SetInt(PREF_LOSS_STREAK,
                Mathf.Min(PlayerPrefs.GetInt(PREF_LOSS_STREAK, 0), rec.losses));
            PlayerPrefs.Save();
        }

        public static int GamesPlayed => PlayerPrefs.GetInt(PREF_GAMES_PLAYED, 0);

        public static DifficultyLevel LastDifficulty
        {
            get
            {
                int v = PlayerPrefs.GetInt(PREF_LAST_LEVEL, (int)DifficultyLevel.Knight);
                return (DifficultyLevel)Mathf.Clamp(v, (int)DifficultyLevel.Novice, (int)DifficultyLevel.GrandMaster);
            }
            set
            {
                PlayerPrefs.SetInt(PREF_LAST_LEVEL, (int)value);
                PlayerPrefs.Save();
            }
        }

        public static void RecordResult(bool isWin, bool isDraw, DifficultyLevel playedLevel)
        {
            // La racha es por nivel: si el nivel jugado cambia, la racha anterior se
            // reinicia para que "Racha de N" del banner coincida con la tarjeta de ese nivel
            EnsureStreakBelongsToLevel();
            if (PlayerPrefs.GetInt(PREF_STREAK_LEVEL, (int)playedLevel) != (int)playedLevel)
            {
                PlayerPrefs.SetInt(PREF_WIN_STREAK, 0);
                PlayerPrefs.SetInt(PREF_LOSS_STREAK, 0);
                PlayerPrefs.SetInt(PREF_STREAK_LEVEL, (int)playedLevel);
            }

            LastDifficulty = playedLevel;
            int games = GamesPlayed + 1;
            PlayerPrefs.SetInt(PREF_GAMES_PLAYED, games);

            if (isDraw)
            {
                // Tablas resetean ambas rachas pero no cuentan como derrota
                PlayerPrefs.SetInt(PREF_WIN_STREAK, 0);
                PlayerPrefs.SetInt(PREF_LOSS_STREAK, 0);
            }
            else if (isWin)
            {
                int ws = WinStreak + 1;
                PlayerPrefs.SetInt(PREF_WIN_STREAK, ws);
                PlayerPrefs.SetInt(PREF_LOSS_STREAK, 0);
                Debug.Log($"[DynamicDifficulty] Victoria! Racha victorias: {ws}");
            }
            else
            {
                int ls = LossStreak + 1;
                PlayerPrefs.SetInt(PREF_LOSS_STREAK, ls);
                PlayerPrefs.SetInt(PREF_WIN_STREAK, 0);
                Debug.Log($"[DynamicDifficulty] Derrota. Racha derrotas: {ls}");
            }

            // Récord por nivel (V-E-D) para las tarjetas del selector de rival
            string recordPref = (isWin ? PREF_WINS_PREFIX : (isDraw ? PREF_DRAWS_PREFIX : PREF_LOSSES_PREFIX)) + (int)playedLevel;
            PlayerPrefs.SetInt(recordPref, PlayerPrefs.GetInt(recordPref, 0) + 1);

            // Limpiar flag de dismiss al registrar nuevo resultado
            PlayerPrefs.DeleteKey(PREF_DISMISSED_SUGGESTION);
            PlayerPrefs.Save();

            // Evaluar sugerencia
            EvaluateSuggestion(playedLevel);
        }

        private static void EvaluateSuggestion(DifficultyLevel playedLevel)
        {
            if (WinStreak >= STREAK_THRESHOLD && playedLevel < DifficultyLevel.GrandMaster)
            {
                var suggested = (DifficultyLevel)((int)playedLevel + 1);
                PlayerPrefs.SetInt(PREF_SUGGESTED_LEVEL, (int)suggested);
                PlayerPrefs.Save();
                Debug.Log($"[DynamicDifficulty] Sugerencia: SUBIR a {suggested} (racha {WinStreak} victorias)");
            }
            else if (LossStreak >= STREAK_THRESHOLD && playedLevel > DifficultyLevel.Novice)
            {
                var suggested = (DifficultyLevel)((int)playedLevel - 1);
                PlayerPrefs.SetInt(PREF_SUGGESTED_LEVEL, (int)suggested);
                PlayerPrefs.Save();
                Debug.Log($"[DynamicDifficulty] Sugerencia: BAJAR a {suggested} (racha {LossStreak} derrotas)");
            }
            else
            {
                PlayerPrefs.DeleteKey(PREF_SUGGESTED_LEVEL);
                PlayerPrefs.Save();
            }
        }

        public static bool TryGetSuggestedLevel(out DifficultyLevel suggested)
        {
            suggested = DifficultyLevel.Knight;
            if (PlayerPrefs.HasKey(PREF_DISMISSED_SUGGESTION)) return false;
            if (!PlayerPrefs.HasKey(PREF_SUGGESTED_LEVEL)) return false;
            int v = PlayerPrefs.GetInt(PREF_SUGGESTED_LEVEL, -1);
            if (v == -1) return false;
            suggested = (DifficultyLevel)v;
            return true;
        }

        public static bool ShouldSuggestHarder(DifficultyLevel current)
        {
            return WinStreak >= STREAK_THRESHOLD && current < DifficultyLevel.GrandMaster;
        }

        public static bool ShouldSuggestEasier(DifficultyLevel current)
        {
            return LossStreak >= STREAK_THRESHOLD && current > DifficultyLevel.Novice;
        }

        public static DifficultyLevel GetHarder(DifficultyLevel current)
        {
            if (current >= DifficultyLevel.GrandMaster) return DifficultyLevel.GrandMaster;
            return (DifficultyLevel)((int)current + 1);
        }

        public static DifficultyLevel GetEasier(DifficultyLevel current)
        {
            if (current <= DifficultyLevel.Novice) return DifficultyLevel.Novice;
            return (DifficultyLevel)((int)current - 1);
        }

        public static void DismissSuggestion()
        {
            PlayerPrefs.SetInt(PREF_DISMISSED_SUGGESTION, 1);
            PlayerPrefs.Save();
            Debug.Log("[DynamicDifficulty] Sugerencia descartada.");
        }

        public static void AcceptSuggestion()
        {
            if (PlayerPrefs.HasKey(PREF_SUGGESTED_LEVEL))
            {
                int v = PlayerPrefs.GetInt(PREF_SUGGESTED_LEVEL, (int)LastDifficulty);
                LastDifficulty = (DifficultyLevel)v;
            }
            PlayerPrefs.DeleteKey(PREF_SUGGESTED_LEVEL);
            PlayerPrefs.DeleteKey(PREF_DISMISSED_SUGGESTION);
            PlayerPrefs.SetInt(PREF_WIN_STREAK, 0);
            PlayerPrefs.SetInt(PREF_LOSS_STREAK, 0);
            PlayerPrefs.Save();
            Debug.Log("[DynamicDifficulty] Sugerencia aceptada. Rachas reseteadas.");
        }

        public static (int wins, int losses, int draws) GetRecord(DifficultyLevel level)
        {
            int n = (int)level;
            return (
                PlayerPrefs.GetInt(PREF_WINS_PREFIX + n, 0),
                PlayerPrefs.GetInt(PREF_LOSSES_PREFIX + n, 0),
                PlayerPrefs.GetInt(PREF_DRAWS_PREFIX + n, 0));
        }

        public static void ResetAll()
        {
            for (int i = (int)DifficultyLevel.Novice; i <= (int)DifficultyLevel.GrandMaster; i++)
            {
                PlayerPrefs.DeleteKey(PREF_WINS_PREFIX + i);
                PlayerPrefs.DeleteKey(PREF_LOSSES_PREFIX + i);
                PlayerPrefs.DeleteKey(PREF_DRAWS_PREFIX + i);
            }
            PlayerPrefs.DeleteKey(PREF_WIN_STREAK);
            PlayerPrefs.DeleteKey(PREF_LOSS_STREAK);
            PlayerPrefs.DeleteKey(PREF_STREAK_LEVEL);
            PlayerPrefs.DeleteKey(PREF_GAMES_PLAYED);
            PlayerPrefs.DeleteKey(PREF_SUGGESTED_LEVEL);
            PlayerPrefs.DeleteKey(PREF_DISMISSED_SUGGESTION);
            PlayerPrefs.Save();
        }

        public static string GetStreakText()
        {
            if (WinStreak >= 2) return $"🔥 Racha: {WinStreak} victorias";
            if (LossStreak >= 2) return $"❄️ Racha: {LossStreak} derrotas";
            if (GamesPlayed == 0) return "¡Primera partida!";
            return $"Partidas: {GamesPlayed}";
        }
    }
}
