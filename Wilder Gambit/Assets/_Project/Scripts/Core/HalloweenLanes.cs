using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Estado de las vías del pase de la velada. La Vía Luna siempre está abierta;
    /// la <b>Vía Sangre</b> se compra con Dulces (la moneda temporal del evento) y
    /// queda abierta durante toda la edición: la comparten el camino de niveles y
    /// las misiones premium, así que vive aquí y no dentro de un modal.
    ///
    /// Clave con sufijo de año, igual que el XP y los Dulces: cada edición de la
    /// velada arranca su propia Vía Sangre.
    /// </summary>
    public static class HalloweenLanes
    {
        /// <summary>Coste de abrir la Vía Sangre en Dulces.</summary>
        public const int SangreUnlockCost = 150;

        private const string KeyPrefix = "WG_Halloween_Sangre_";

        public static string Key => KeyPrefix + HalloweenEvent.Year;

        /// <summary>¿La Vía Sangre de esta edición está abierta?</summary>
        public static bool SangreUnlocked => PlayerPrefs.GetInt(Key, 0) == 1;

        /// <summary>Abre la vía sin cobrar (QA y cobros ya validados).</summary>
        public static void UnlockSangre()
        {
            PlayerPrefs.SetInt(Key, 1);
            PlayerPrefs.Save();
        }

        /// <summary>
        /// Intenta pagar la vía con Dulces. Devuelve false si ya estaba abierta o si
        /// el saldo no alcanza; en ese caso no se descuenta nada.
        /// </summary>
        public static bool TryBuySangre()
        {
            if (SangreUnlocked) return false;
            if (!HalloweenCurrency.Spend(SangreUnlockCost)) return false;
            UnlockSangre();
            return true;
        }

        /// <summary>Solo para depuración: cierra la vía de nuevo.</summary>
        public static void DebugLockSangre()
        {
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.Save();
        }
    }
}
