using System;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>Foto del día: cuánto se ha ganado, cuántas veces y contra quién.</summary>
    [Serializable]
    public class GambitLedgerData
    {
        public string day = "";
        public int totalToday;
        public int[] perSource = new int[(int)GambitSource.Count];
        public int[] paymentsToday = new int[(int)GambitSource.Count];

        /// <summary>Victorias seguidas contra el mismo rival (decaimiento anti-farmeo).</summary>
        public int consecutiveWinsSameLevel;
        public int lastWonLevel = -1;
        public bool firstWinOfDayTaken;

        public void EnsureArrays()
        {
            int n = (int)GambitSource.Count;
            if (perSource == null || perSource.Length != n) Array.Resize(ref perSource, n);
            if (paymentsToday == null || paymentsToday.Length != n) Array.Resize(ref paymentsToday, n);
        }
    }

    /// <summary>
    /// Libro diario de Gambits. Guarda el total del día, lo pagado por cada fuente,
    /// cuántos pagos se han hecho y el estado anti-farmeo. Se reinicia solo al cambiar
    /// de día (hora local).
    /// </summary>
    public static class GambitLedger
    {
        private const string PREF_KEY = "WG_GambitLedger";

        private static GambitLedgerData _data;

        public static string TodayKey => DateTime.Now.ToString("yyyy-MM-dd");

        public static GambitLedgerData Data
        {
            get
            {
                if (_data == null) Load();
                RolloverIfNewDay();
                return _data;
            }
        }

        public static int TotalToday => Data.totalToday;

        public static int SourceToday(GambitSource source)
        {
            int i = (int)source;
            var d = Data;
            return i >= 0 && i < d.perSource.Length ? d.perSource[i] : 0;
        }

        public static int PaymentsToday(GambitSource source)
        {
            int i = (int)source;
            var d = Data;
            return i >= 0 && i < d.paymentsToday.Length ? d.paymentsToday[i] : 0;
        }

        /// <summary>¿Queda margen en esta fuente hoy? (tope de importe o de número de pagos)</summary>
        public static bool HasRoom(GambitSource source, out string reason)
        {
            reason = null;
            var info = GambitSources.Get(source);
            var d = Data;

            if (info.maxPayments > 0 && PaymentsToday(source) >= info.maxPayments)
            {
                reason = $"límite diario de {info.label.ToLowerInvariant()}";
                return false;
            }
            if (info.dailyCap > 0 && SourceToday(source) >= info.dailyCap)
            {
                reason = $"tope diario de {info.label.ToLowerInvariant()}";
                return false;
            }
            return true;
        }

        /// <summary>Apunta un pago (importe ya concedido).</summary>
        public static void RegisterPayment(GambitSource source, int amount)
        {
            var d = Data;
            int i = (int)source;
            if (i < 0 || i >= d.perSource.Length) return;

            d.perSource[i] += amount;
            d.paymentsToday[i]++;
            d.totalToday += amount;
            Save();
        }

        /// <summary>Registra el resultado de una partida para el decaimiento por repetición.</summary>
        public static void NoteMatchResult(int levelIndex, bool isWin)
        {
            var d = Data;
            if (!isWin)
            {
                d.consecutiveWinsSameLevel = 0;
                d.lastWonLevel = levelIndex;
                Save();
                return;
            }

            if (d.lastWonLevel == levelIndex) d.consecutiveWinsSameLevel++;
            else d.consecutiveWinsSameLevel = 1;
            d.lastWonLevel = levelIndex;
            Save();
        }

        /// <summary>Victorias seguidas contra ese rival (1 = la primera).</summary>
        public static int ConsecutiveWinsAgainst(int levelIndex)
        {
            var d = Data;
            if (d.lastWonLevel != levelIndex) return 1;
            return Mathf.Max(1, d.consecutiveWinsSameLevel);
        }

        public static bool FirstWinOfDayTaken
        {
            get => Data.firstWinOfDayTaken;
            set { Data.firstWinOfDayTaken = value; Save(); }
        }

        // ── Persistencia ──────────────────────────────────────────────────────

        private static void Load()
        {
            string json = PlayerPrefs.GetString(PREF_KEY, "");
            if (!string.IsNullOrEmpty(json))
            {
                try { _data = JsonUtility.FromJson<GambitLedgerData>(json); }
                catch (Exception e) { Debug.LogWarning("[GambitLedger] JSON inválido, se reinicia: " + e.Message); }
            }
            if (_data == null) _data = new GambitLedgerData();
            if (string.IsNullOrEmpty(_data.day)) _data.day = TodayKey;
            _data.EnsureArrays();
        }

        private static void Save()
        {
            if (_data == null) return;
            PlayerPrefs.SetString(PREF_KEY, JsonUtility.ToJson(_data));
            PlayerPrefs.Save();
        }

        private static void RolloverIfNewDay()
        {
            if (_data == null || _data.day == TodayKey) return;

            _data.day = TodayKey;
            _data.totalToday = 0;
            _data.firstWinOfDayTaken = false;
            _data.EnsureArrays();
            for (int i = 0; i < _data.perSource.Length; i++)
            {
                _data.perSource[i] = 0;
                _data.paymentsToday[i] = 0;
            }
            Save();
            Debug.Log($"[GambitLedger] Nuevo día {_data.day}: contadores de Gambits reiniciados.");
        }

        /// <summary>Solo para el panel de depuración.</summary>
        public static void DebugResetToday()
        {
            _data = new GambitLedgerData { day = TodayKey };
            _data.EnsureArrays();
            Save();
        }
    }
}
