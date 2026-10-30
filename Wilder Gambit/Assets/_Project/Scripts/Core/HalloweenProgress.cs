using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// XP de la velada de Halloween: mini-pase de 30 niveles × 60 XP (1.800 en total).
    /// Monotónico y por año, pero SOLO suma dentro de la ventana; la primera lectura
    /// antes del arranque purga el XP viejo para que el contador empiece en 0 el 20/10
    /// (misma política que SeasonProgress). Claves propias: no toca el XP de la T1.
    /// </summary>
    public static class HalloweenProgress
    {
        public const int TierCount = 30;
        public const int XpPerTier = 60;
        public const int MaxXp = TierCount * XpPerTier;

        // Raciones de XP de la velada (más generosas que la temporada: la velada dura 14 jornadas).
        public const int MatchXp = 10;       // terminar una partida real
        public const int VictoryXp = 15;     // y ganarla (victoria = 25)
        public const int PuzzleXp = 8;       // puzzle resuelto
        public const int CaptureXp = 1;      // por captura tuya
        public const int ChallengeXp = 30;   // desafío diario
        public const int MissionXp = 20;     // misión de la velada cobrada

        private const string KeyPrefix = "WG_Halloween_XP_";
        private const string KeyPurgedPrefix = "WG_Halloween_XP_Purged_";

        public static string Key => KeyPrefix + HalloweenEvent.Year;

        public static int Xp
        {
            get
            {
                PurgeIfNotStarted();
                return PlayerPrefs.GetInt(Key, 0);
            }
            private set
            {
                PlayerPrefs.SetInt(Key, Mathf.Clamp(value, 0, MaxXp));
                PlayerPrefs.Save();
            }
        }

        public static int CurrentLevel => LevelFor(Xp);

        public static void AddXp(int amount)
        {
            if (amount <= 0 || !HalloweenEvent.IsActiveNow) return;
            Xp = Xp + amount;
            GambitProgress.NotifyChanged();
        }

        /// <summary>Suma sin compuerta de fechas: cobros automáticos al cierre y QA.</summary>
        public static void AddXpForced(int amount)
        {
            if (amount <= 0) return;
            Xp = Xp + amount;
            GambitProgress.NotifyChanged();
        }

        public static int LevelFor(int xp)
        {
            return Mathf.Clamp(xp / XpPerTier, 0, TierCount);
        }

        // ── Ganchos de juego (los llama GambitProgress desde los eventos) ──────

        public static void NoteMatch(bool victory) => AddXp(victory ? MatchXp + VictoryXp : MatchXp);
        public static void NoteCapture() => AddXp(CaptureXp);
        public static void NotePuzzleSolved() => AddXp(PuzzleXp);
        public static void NoteDailyChallenge() => AddXp(ChallengeXp);
        public static void NoteMissionClaimed() => AddXp(MissionXp);

        /// <summary>Antes del arranque el XP en crudo se limpia una vez por año.</summary>
        public static void PurgeIfNotStarted()
        {
            if (!HalloweenEvent.IsNotStartedNow) return;
            string flag = KeyPurgedPrefix + HalloweenEvent.Year;
            if (PlayerPrefs.GetInt(flag, 0) == 1) return;
            PlayerPrefs.SetInt(flag, 1);
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.Save();
        }

        /// <summary>Solo para depuración (Editor): suma XP sin tocar la UI ni los eventos.</summary>
        public static void DebugAddXp(int amount)
        {
            if (amount <= 0) return;
            PlayerPrefs.SetInt(Key, Mathf.Clamp(PlayerPrefs.GetInt(Key, 0) + amount, 0, MaxXp));
            PlayerPrefs.Save();
        }

        public static void DebugReset()
        {
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.DeleteKey(KeyPurgedPrefix + HalloweenEvent.Year);
            PlayerPrefs.Save();
        }
    }
}
