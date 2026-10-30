using System;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Calendario de la velada de Halloween: del 20/10 a las 21:00 al 4/11 (la ventana cierra
    /// el 5/11 a las 00:00 locales). Evento independiente de la temporada T1:
    /// claves y contadores propios, no toca SeasonCalendar ni SeasonProgress.
    ///
    /// Tres estados públicos (NotStarted / Active / Ended) más un override de
    /// depuración (PlayerPrefs) para probar estados fuera de fecha desde el menú
    /// «Wilder Gambit › Halloween» del Editor.
    /// </summary>
    public static class HalloweenEvent
    {
        /// <summary>Año de esta edición de la velada (sufijo de todas las claves).</summary>
        public const int Year = 2026;

        /// <summary>Apertura de la velada: 20/10 a las 21:00 locales (martes).</summary>
        public static readonly DateTime Start = new DateTime(Year, 10, 20, 21, 0, 0);

        /// <summary>Cierre exclusivo: la velada vive hasta el 4/11 23:59 y muere a las 00:00 del 5/11.</summary>
        public static readonly DateTime EndExclusive = new DateTime(Year, 11, 5);

        /// <summary>
        /// Último tramo de la velada: desde el 31/10 la Cacería avisa que se va
        /// («SE VA PRONTO!») antes de que las puertas cierren el 4/11.
        /// </summary>
        public static readonly DateTime FinalStretchStart = new DateTime(Year, 10, 31);

        public enum Phase
        {
            NotStarted = 0,
            Active = 1,
            Ended = 2,
        }

        private const string KeyDebugPhase = "WG_Halloween_DebugPhase";
        private const string KeyDebugSeal = "WG_Halloween_DebugSeal";

        /// <summary>0 = fechas reales · 1 = forzar próximamente · 2 = forzar activo · 3 = forzar terminado.</summary>
        public static int DebugPhaseOption
        {
            get => PlayerPrefs.GetInt(KeyDebugPhase, 0);
            set
            {
                PlayerPrefs.SetInt(KeyDebugPhase, Mathf.Clamp(value, 0, 3));
                PlayerPrefs.Save();
            }
        }

        /// <summary>
        /// Muestra el sello «SE VA PRONTO!» fuera de fecha (solo QA): permite
        /// revisar el intro en octubre sin tocar el reloj del sistema.
        /// </summary>
        public static bool DebugForceFinalStretch
        {
            get => PlayerPrefs.GetInt(KeyDebugSeal, 0) == 1;
            set
            {
                PlayerPrefs.SetInt(KeyDebugSeal, value ? 1 : 0);
                PlayerPrefs.Save();
            }
        }

        public static Phase CurrentPhase => PhaseFor(DateTime.Now);
        public static bool IsNotStartedNow => CurrentPhase == Phase.NotStarted;
        public static bool IsActiveNow => CurrentPhase == Phase.Active;
        public static bool IsEndedNow => CurrentPhase == Phase.Ended;

        /// <summary>
        /// ¿Toca avisar que la velada se va? Del 31/10 al cierre (o forzado
        /// desde el menú de QA). El intro de la Cacería lo consulta al abrirse.
        /// </summary>
        public static bool IsFinalStretch(DateTime now)
        {
            if (DebugForceFinalStretch) return true;
            return now >= FinalStretchStart && now < EndExclusive;
        }

        public static bool IsFinalStretchNow => IsFinalStretch(DateTime.Now);

        public static Phase PhaseFor(DateTime now)
        {
            switch (DebugPhaseOption)
            {
                case 1: return Phase.NotStarted;
                case 2: return Phase.Active;
                case 3: return Phase.Ended;
                default: return RealPhase(now);
            }
        }

        private static Phase RealPhase(DateTime now)
        {
            if (now < Start) return Phase.NotStarted;
            if (now < EndExclusive) return Phase.Active;
            return Phase.Ended;
        }

        /// <summary>
        /// ¿El día calendario pertenece a la ventana de juego? Con el override en
        /// «activo» cualquier día vale, para QA fuera de fecha.
        /// </summary>
        public static bool DayWithinEvent(DateTime day)
        {
            if (DebugPhaseOption == 2) return true;
            return day >= Start && day < EndExclusive;
        }

        /// <summary>Cuenta atrás legible («Abre en 12 d 4 h · el 20/10 a las 21:00»).</summary>
        public static string TimeText(DateTime now)
        {
            switch (PhaseFor(now))
            {
                case Phase.NotStarted:
                {
                    TimeSpan span = Start - now;
                    if (span < TimeSpan.Zero) span = TimeSpan.Zero;
                    return $"Abre en {(int)span.TotalDays} d {span.Hours} h · el {Start:dd/MM} a las {Start:HH:mm}";
                }
                case Phase.Active:
                {
                    TimeSpan left = EndExclusive - now;
                    if (left < TimeSpan.Zero) left = TimeSpan.Zero;
                    return $"Termina en {(int)left.TotalDays} d {left.Hours} h · el {EndExclusive.AddDays(-1):dd/MM}";
                }
                default:
                    return $"Las puertas se cerraron el {EndExclusive.AddDays(-1):dd/MM}";
            }
        }

        public static string TimeTextNow => TimeText(DateTime.Now);

        /// <summary>Rango legible de la velada («20/10 → 04/11»).</summary>
        public static string RangeText => $"{Start:dd/MM} → {EndExclusive.AddDays(-1):dd/MM}";
    }
}
