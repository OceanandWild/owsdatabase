using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Dulces: la moneda temporal de la velada de Halloween. Se gana en las misiones
    /// del evento y en los dos pases (temporada y velada). La gastará la tienda de
    /// la velada que llega después del evento; hasta entonces, abrir la Vía Sangre
    /// es el único gasto. Clave por año: cada edición arranca su propio saldo.
    /// </summary>
    public static class HalloweenCurrency
    {
        public const string Label = "Dulces";
        public const string Icon = "🍬";

        private const string KeyPrefix = "WG_Halloween_Dulces_";

        public static string Key => KeyPrefix + HalloweenEvent.Year;

        public static int Balance
        {
            get => PlayerPrefs.GetInt(Key, 0);
            private set
            {
                PlayerPrefs.SetInt(Key, Mathf.Max(0, value));
                PlayerPrefs.Save();
            }
        }

        /// <summary>Suma Dulces y refresca la UI. Devuelve cuánto entró.</summary>
        public static int Earn(int amount, string note = null)
        {
            if (amount <= 0) return 0;
            Balance += amount;
            GambitProgress.NotifyChanged();
            Debug.Log($"[HalloweenCurrency] +{amount} {Label} ({note ?? "sin nota"}) · saldo {Balance}");
            return amount;
        }

        /// <summary>Gasta Dulces. Devuelve false (y no toca el saldo) si no alcanza.</summary>
        public static bool Spend(int amount)
        {
            if (amount <= 0) return true;
            if (Balance < amount) return false;
            Balance -= amount;
            GambitProgress.NotifyChanged();
            return true;
        }

        public static void DebugReset()
        {
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.Save();
        }

        /// <summary>Solo para depuración (Editor): suma Dulces sin tocar la UI ni los eventos.</summary>
        public static void DebugAdd(int amount)
        {
            if (amount <= 0) return;
            PlayerPrefs.SetInt(Key, Mathf.Max(0, Balance + amount));
            PlayerPrefs.Save();
        }
    }
}
