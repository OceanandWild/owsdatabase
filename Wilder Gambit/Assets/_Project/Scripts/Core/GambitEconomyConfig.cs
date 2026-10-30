using UnityEngine;
using WilderGambit.AI;

namespace WilderGambit.Core
{
    /// <summary>
    /// Números de la economía de Gambits, para tunear sin recompilar.
    /// Si el asset no existe, se usan los valores por defecto de este archivo
    /// (menú de Unity: Wilder Gambit &gt; Crear config de economía).
    /// Las misiones y la barra semanal llevan sus importes junto a su catálogo,
    /// aquí vive lo que más se ajusta: la partida vs IA y los topes diarios.
    /// </summary>
    [CreateAssetMenu(fileName = "GambitEconomyConfig", menuName = "Wilder Gambit/Gambit Economy Config")]
    public class GambitEconomyConfig : ScriptableObject
    {
        private const string RESOURCE_NAME = "GambitEconomyConfig";

        [Header("Pago base por partida (Novice → GrandMaster)")]
        public int[] victoryRewards = { 20, 35, 60, 100, 160 };
        public int[] drawRewards    = { 8, 14, 24, 40, 64 };
        public int[] defeatRewards  = { 4, 6, 10, 15, 24 };

        [Header("Modificadores de partida")]
        [Tooltip("Bonus por precisión ≥85%")]
        public float accuracyBonus = 0.25f;
        [Tooltip("Bonus por precisión ≥92% (reemplaza al anterior)")]
        public float accuracyBonusHigh = 0.50f;
        [Tooltip("Bonus por ganar sin perder ninguna pieza")]
        public float flawlessBonus = 0.40f;
        [Tooltip("Bonus por cada victoria consecutiva")]
        public float winStreakStep = 0.10f;
        [Tooltip("Tope del bonus de racha")]
        public float winStreakMaxBonus = 0.50f;
        [Tooltip("Extra fijo por la primera victoria del día")]
        public int firstWinOfDayBonus = 50;
        [Tooltip("Extra fijo por mate en ≤20 jugadas contra Maestro/Gran Maestro")]
        public int fastMateBonus = 60;
        [Tooltip("Extra fijo por una partida larga (>60 jugadas) ganada")]
        public int epicGameBonus = 30;
        [Tooltip("Jugadas mínimas de la partida para poder cobrar")]
        public int minTurnsToReward = 8;
        [Tooltip("Umbral de jugadas para contar como mate exprés")]
        public int fastMateMaxTurns = 20;

        [Header("Anti-farmeo")]
        [Tooltip("Gambits diarios a partir de los cuales todo paga menos")]
        public int dailySoftCap = 900;
        [Tooltip("Factor que se aplica por encima del tope blando")]
        public float overflowFactor = 0.25f;
        [Tooltip("Gambits diarios máximos (por encima, no se paga)")]
        public int dailyHardCap = 1400;
        [Tooltip("Decaimiento de victorias seguidas contra el mismo rival")]
        public float[] rematchDecay = { 1f, 0.75f, 0.5f, 0.25f };

        private static GambitEconomyConfig _instance;

        public static GambitEconomyConfig Instance
        {
            get
            {
                if (_instance == null)
                {
                    _instance = Resources.Load<GambitEconomyConfig>(RESOURCE_NAME);
                    if (_instance == null)
                    {
                        // Valores por defecto en memoria: la economía funciona sin asset
                        _instance = CreateInstance<GambitEconomyConfig>();
                        _instance.name = RESOURCE_NAME + " (defaults)";
                    }
                }
                return _instance;
            }
        }

        /// <summary>Fuerza recargar (lo usa el editor tras crear el asset).</summary>
        public static void Reload() => _instance = null;

        public int Victory(DifficultyLevel level) => Payout(victoryRewards, level);
        public int Draw(DifficultyLevel level) => Payout(drawRewards, level);
        public int Defeat(DifficultyLevel level) => Payout(defeatRewards, level);

        private static int Payout(int[] table, DifficultyLevel level)
        {
            if (table == null || table.Length == 0) return 0;
            int i = Mathf.Clamp((int)level - 1, 0, table.Length - 1);
            return table[i];
        }

        /// <summary>Decaimiento por N victorias seguidas contra el mismo rival (1ª = índice 0).</summary>
        public float RematchFactor(int consecutiveWinsSameLevel)
        {
            if (rematchDecay == null || rematchDecay.Length == 0) return 1f;
            int i = Mathf.Clamp(consecutiveWinsSameLevel, 0, rematchDecay.Length - 1);
            return rematchDecay[i];
        }
    }
}
