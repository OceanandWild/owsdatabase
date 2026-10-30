using System;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Oferta de Halloween para la tienda común: el <b>Alfil Nigromante</b> baja
    /// un 20% hasta el 31/10 a las 23:59 (hora de Uruguay).
    ///
    /// Reglas de la casa:
    ///  · el precio de lista no cambia: <see cref="PieceLoadoutManager.NECROMANCER_PRICE_GAMBITS"/>;
    ///  · la UI pide el precio final (con descuento) y el de lista, y el cobro usa el final;
    ///  · fuera de la ventana el precio final vuelve a ser el de lista, sin tocar nada más.
    ///
    /// El reloj es el de Uruguay (UYT, UTC-3) y no el del aparato: el cierre es
    /// el mismo instante para todos, sin importar dónde se abra el juego.
    /// </summary>
    public static class HalloweenDiscount
    {
        /// <summary>Porcentaje de descuento del Nigromante durante la velada.</summary>
        public const int NecromancerPercentOff = 20;

        /// <summary>Apertura de la oferta: 20/10 a las 00:00 (hora de Uruguay).</summary>
        public static readonly DateTime StartUruguay = new DateTime(HalloweenEvent.Year, 10, 20, 0, 0, 0);

        /// <summary>
        /// Cierre exclusivo: la oferta vive todo el 31/10 (hasta las 23:59) y
        /// muere a las 00:00 del 1/11.
        /// </summary>
        public static readonly DateTime EndExclusiveUruguay = new DateTime(HalloweenEvent.Year, 11, 1, 0, 0, 0);

        private static TimeZoneInfo _uruguayZone;
        private static bool _uruguayResolved;

        /// <summary>Zona horaria de Uruguay (UYT = UTC-3, sin horario de verano desde 2015).</summary>
        private static TimeZoneInfo UruguayZone
        {
            get
            {
                if (_uruguayResolved) return _uruguayZone;
                _uruguayResolved = true;
                _uruguayZone = ResolveUruguayZone();
                return _uruguayZone;
            }
        }

        private static TimeZoneInfo ResolveUruguayZone()
        {
            // Windows ("Montevideo") y Linux/macOS ("America/Montevideo").
            try { return TimeZoneInfo.FindSystemTimeZoneById("Montevideo"); }
            catch { /* siguiente intento */ }
            try { return TimeZoneInfo.FindSystemTimeZoneById("America/Montevideo"); }
            catch { /* fallback fijo */ }
            // Fallback: UYT fijo (UTC-3). Uruguay no aplica horario de verano desde 2015.
            return TimeZoneInfo.CreateCustomTimeZone("UY", TimeSpan.FromHours(-3), "Uruguay", "Uruguay");
        }

        /// <summary>Ahora mismo, en hora de Uruguay.</summary>
        public static DateTime NowUruguay
        {
            get
            {
                try { return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, UruguayZone); }
                catch { return DateTime.UtcNow.AddHours(-3); }
            }
        }

        /// <summary>¿La oferta está viva ahora mismo?</summary>
        public static bool IsActive
        {
            get
            {
                DateTime now = NowUruguay;
                return now >= StartUruguay && now < EndExclusiveUruguay;
            }
        }

        /// <summary>Precio final del Alfil Nigromante (con descuento si la oferta está viva).</summary>
        public static int NecromancerPrice =>
            IsActive
                ? ApplyPercent(PieceLoadoutManager.NECROMANCER_PRICE_GAMBITS, NecromancerPercentOff)
                : PieceLoadoutManager.NECROMANCER_PRICE_GAMBITS;

        /// <summary>Precio de lista del Alfil Nigromante (sin descuento).</summary>
        public static int NecromancerListPrice => PieceLoadoutManager.NECROMANCER_PRICE_GAMBITS;

        /// <summary>Aplica un porcentaje de descuento a un precio de lista.</summary>
        public static int ApplyPercent(int basePrice, int percentOff)
        {
            if (basePrice <= 0) return basePrice;
            int off = Mathf.Clamp(percentOff, 0, 100);
            if (off <= 0) return basePrice;
            return Mathf.RoundToInt(basePrice * (100 - off) / 100f);
        }

        /// <summary>Rótulo corto de la oferta para las cards («-20% 🎃»).</summary>
        public static string Badge => $"-{NecromancerPercentOff}% 🎃";

        /// <summary>Texto largo de la oferta (para el detalle de la ficha).</summary>
        public static string Note =>
            $"Oferta de Halloween: {NecromancerPrice:N0} Gambits (antes {NecromancerListPrice:N0}) " +
            "hasta el 31/10 a las 23:59 (hora de Uruguay).";

        /// <summary>Cuenta atrás de la oferta («2 d 4 h»); vacío si ya terminó.</summary>
        public static string RemainingText
        {
            get
            {
                if (!IsActive) return string.Empty;
                TimeSpan left = EndExclusiveUruguay - NowUruguay;
                if (left < TimeSpan.Zero) left = TimeSpan.Zero;
                return $"termina en {(int)left.TotalDays} d {left.Hours} h";
            }
        }
    }
}
