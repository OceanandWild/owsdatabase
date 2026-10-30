using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// XP acumulativo de la temporada vigente (monotónico: nunca baja con el
    /// reseteo semanal). Clave por temporada: al rotar, la nueva empieza en 0.
    /// Ritmo objetivo (~1.800 XP en la T1 de 47 días: 30 niveles × 60 XP): misión +25,
    /// segmento +25, semanal +30, victoria +15, partida +5, puzzle +4.
    ///
    /// <b>Antes del arranque</b> de la temporada (<see cref="SeasonCalendar.IsPreSeason"/>)
    /// no se suma nada: el pase está en pretemporada y el contador arranca en 0 el
    /// día del inicio. Además, la primera lectura durante la pretemporada borra el XP
    /// que se acumulaba con el paso anterior (por el bug de pretemporada) y deja un
    /// sello por temporada, para que nadie llegue al día 1 con niveles regalados.
    /// </summary>
    public static class SeasonProgress
    {
        public const int MissionXp = 25;
        public const int SegmentXp = 25;
        public const int WeeklyMissionXp = 30;
        public const int VictoryXp = 15;
        public const int MatchXp = 5;
        public const int PuzzleXp = 4;

        private const string KeyPrefix = "WG_SeasonPass_XP_";

        /// <summary>Sello de «XP de pretemporada ya borrado» (uno por temporada).</summary>
        private const string KeyPurged = "WG_SeasonPass_XP_Purged_";

        public static string Key => KeyPrefix + SeasonCalendar.CurrentId;

        /// <summary>El pase todavía no arrancó: no hay XP ni niveles que mostrar.</summary>
        public static bool IsPreSeason => SeasonCalendar.IsPreSeasonNow;

        public static int Xp
        {
            get
            {
                PurgeXpIfPreSeason();
                return PlayerPrefs.GetInt(Key, 0);
            }
            private set { PlayerPrefs.SetInt(Key, Mathf.Max(0, value)); PlayerPrefs.Save(); }
        }

        public static void AddXp(int amount)
        {
            // Pretemporada: el pase todavía no empezó. Sin XP, sin notify.
            if (amount <= 0 || IsPreSeason) return;
            Xp = Xp + amount;
            GambitProgress.NotifyChanged();
        }

        /// <summary>
        /// Borra (una sola vez por temporada) el XP que se acumuló en pretemporada
        /// con el paso anterior, que contaba como si la temporada ya hubiera
        /// empezado. Es una limpieza, no un cobro: no toca los premios ya
        /// entregados ni el Gambito Real. Se llama al arrancar el juego y en
        /// cada lectura de <see cref="Xp"/>.
        /// </summary>
        public static void PurgeXpIfPreSeason()
        {
            if (!IsPreSeason) return;
            string flag = KeyPurged + SeasonCalendar.CurrentId;
            if (PlayerPrefs.GetInt(flag, 0) == 1) return;
            PlayerPrefs.SetInt(flag, 1);
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.Save();
        }

        /// <summary>XP por cobrar una misión (diaria o semanal).</summary>
        public static void NoteMissionClaimed(bool weekly = false) =>
            AddXp(weekly ? WeeklyMissionXp : MissionXp);

        /// <summary>XP por segmento diario perfecto.</summary>
        public static void NoteSegmentPerfect() => AddXp(SegmentXp);

        /// <summary>XP por partida (las de práctica no cuentan).</summary>
        public static void NoteMatch(bool victory, bool practice)
        {
            if (practice) return;
            AddXp(victory ? VictoryXp + MatchXp : MatchXp);
        }

        /// <summary>XP por puzzle resuelto.</summary>
        public static void NotePuzzleSolved() => AddXp(PuzzleXp);

        /// <summary>Reinicia el XP de la temporada vigente a 0 (limpieza manual / cambio de
        /// fechas del calendario). No toca lo ya cobrado ni el Gambito Real.</summary>
        public static void ResetXp() => Xp = 0;
    }
}