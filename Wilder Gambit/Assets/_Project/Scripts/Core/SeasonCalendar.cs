using System;

namespace WilderGambit.Core
{
    /// <summary>
    /// Calendario de temporadas del pase (mensual).
    /// T1 «El Rey Ígneo» (temporada de lanzamiento): 15/10/2026 → 30/11/2026,
    /// para no quemar días entre el lanzamiento y fin de mes. Desde la T2,
    /// meses calendario (diciembre = T2, enero = T3…).
    /// Antes de la fecha de inicio la temporada vigente está en <b>pretemporada</b>:
    /// el pase se puede ver, pero <b>no arranca</b> — ni XP, ni niveles, ni cobros
    /// (<see cref="IsPreSeason"/>). El contador empieza en 0 el día del arranque.
    /// </summary>
    public static class SeasonCalendar
    {
        public struct SeasonDef
        {
            public string id;
            public string title;
            public DateTime start;
            public DateTime endExclusive;
        }

        private static readonly SeasonDef Season1 = new SeasonDef
        {
            id = "S1",
            title = "TEMPORADA 1 · EL REY ÍGNEO",
            start = new DateTime(2026, 10, 15),
            endExclusive = new DateTime(2026, 12, 1),
        };

        private static SeasonDef MonthSeason(int index, int year, int month)
        {
            var start = new DateTime(year, month, 1);
            return new SeasonDef
            {
                id = $"S{index}",
                title = $"TEMPORADA {index}",
                start = start,
                endExclusive = start.AddMonths(1),
            };
        }

        /// <summary>Temporada vigente para la fecha indicada.</summary>
        public static SeasonDef Current(DateTime now)
        {
            DateTime day = now.Date;
            if (day < Season1.endExclusive) return Season1;

            // T2 = diciembre 2026, T3 = enero 2027…
            int monthsSinceDec2026 = (day.Year - 2026) * 12 + (day.Month - 12);
            int index = monthsSinceDec2026 + 2;
            var first = new DateTime(2026, 12, 1).AddMonths(monthsSinceDec2026);
            return MonthSeason(index, first.Year, first.Month);
        }

        public static SeasonDef CurrentNow => Current(DateTime.Now);
        public static string CurrentId => CurrentNow.id;
        public static string CurrentTitle => CurrentNow.title;

        /// <summary>Arranque de la temporada vigente (día en que se abre el pase).</summary>
        public static DateTime CurrentStart => CurrentNow.start;

        /// <summary>
        /// La temporada vigente todavía no empezó: el pase está en pretemporada.
        /// Mientras lo sea no se acumula XP ni se puede cobrar ninguna recompensa
        /// (<see cref="SeasonProgress"/> y el pase lo consultan antes de conceder nada).
        /// </summary>
        public static bool IsPreSeason(DateTime now) => now < Current(now).start;

        public static bool IsPreSeasonNow => IsPreSeason(DateTime.Now);

        /// <summary>
        /// Texto del temporizador («EMPIEZA EN…» / «TERMINA EN…»).
        /// </summary>
        public static string TimeText(DateTime now)
        {
            SeasonDef season = Current(now);
            if (now < season.start)
            {
                var span = season.start - now;
                return $"Empieza en {(int)span.TotalDays} d {span.Hours} h · el {season.start:dd/MM}";
            }
            var left = season.endExclusive - now;
            if (left.TotalSeconds < 0) left = TimeSpan.Zero;
            return $"Termina en {(int)left.TotalDays} d {left.Hours} h · el XP viene de jugar";
        }

        public static string TimeTextNow => TimeText(DateTime.Now);
    }
}
