using System.Collections.Generic;
using UnityEngine;
using WilderGambit.AI;

namespace WilderGambit.Core
{
    /// <summary>Cómo terminó la partida contra la IA.</summary>
    public enum MatchOutcome
    {
        Victory,
        Draw,
        Defeat,
    }

    /// <summary>Todo lo que la economía necesita saber de la partida para pagarla.</summary>
    public struct MatchContext
    {
        public DifficultyLevel level;
        public MatchOutcome outcome;
        public int totalTurns;
        public int playerTurns;
        public float accuracy;      // 0-100
        public int blunders;
        public bool flawless;       // no perdió ninguna pieza
        public int winStreak;

        // Los rellena Settle desde el libro diario (anti-farmeo / primera del día)
        internal int consecutiveWinsSameLevel;
        internal bool firstWinOfDay;
    }

    /// <summary>Una línea del desglose que ve el jugador al terminar.</summary>
    public struct MatchRewardLine
    {
        public string label;
        public int amount;
    }

    /// <summary>Desglose completo: lo que se calculó y lo que finalmente se cobró.</summary>
    public class MatchBreakdown
    {
        public readonly List<MatchRewardLine> lines = new List<MatchRewardLine>();
        public int RawTotal;
        public int Granted;
        public int BalanceAfter;
        public bool Limited;
        public string LimitReason;
        public bool TooShort;

        public void Add(string label, int amount)
        {
            if (amount == 0) return;
            lines.Add(new MatchRewardLine { label = label, amount = amount });
        }
    }

    /// <summary>
    /// Tabla de recompensas por partida vs IA: más difícil el rival, más paga, y encima
    /// bonus por cómo jugaste (precisión, sin pérdidas, racha) y por hitos del día
    /// (primera victoria, mate exprés, partida épica). El cobro real lo hace
    /// GambitEconomy, que aplica los topes diarios.
    /// </summary>
    public static class MatchRewards
    {
        public static int ForWin(DifficultyLevel level)  => GambitEconomyConfig.Instance.Victory(level);
        public static int ForDraw(DifficultyLevel level) => GambitEconomyConfig.Instance.Draw(level);
        public static int ForLoss(DifficultyLevel level) => GambitEconomyConfig.Instance.Defeat(level);

        public static int ForOutcome(DifficultyLevel level, MatchOutcome outcome)
        {
            switch (outcome)
            {
                case MatchOutcome.Victory: return ForWin(level);
                case MatchOutcome.Draw:    return ForDraw(level);
                default:                   return ForLoss(level);
            }
        }

        /// <summary>Rótulo corto para las cards de dificultad («60 Gambits por victoria», con icono moneda).</summary>
        public static string CardLabel(DifficultyLevel level) => $"{ForWin(level):N0} Gambits por victoria";

        /// <summary>Detalle para el hint del CTA: lo que se gana en ese modo.</summary>
        public static string Hint(DifficultyLevel level)
        {
            return $"Recompensa: {ForWin(level):N0} por victoria  •  {ForDraw(level):N0} por tablas  •  {ForLoss(level):N0} por derrota";
        }

        /// <summary>Calcula el desglose sin cobrar (lo usa la UI y los tests).</summary>
        public static MatchBreakdown Compute(MatchContext ctx)
        {
            var config = GambitEconomyConfig.Instance;
            var b = new MatchBreakdown();

            // Partida demasiado corta: no se paga (anti-farmeo de mates triviales)
            if (ctx.totalTurns < config.minTurnsToReward)
            {
                b.TooShort = true;
                b.Add("Partida demasiado corta", 0);
                return b;
            }

            int baseAmount = ForOutcome(ctx.level, ctx.outcome);
            bool win = ctx.outcome == MatchOutcome.Victory;
            b.Add($"Base · {ctx.level}", baseAmount);

            // ── Bonus porcentuales sobre la base ──
            float percent = 0f;

            if (ctx.accuracy >= 92f)
            {
                percent += config.accuracyBonusHigh;
                b.Add($"Precisión {ctx.accuracy:F0}%", Mathf.RoundToInt(baseAmount * config.accuracyBonusHigh));
            }
            else if (ctx.accuracy >= 85f)
            {
                percent += config.accuracyBonus;
                b.Add($"Precisión {ctx.accuracy:F0}%", Mathf.RoundToInt(baseAmount * config.accuracyBonus));
            }

            if (win && ctx.flawless)
            {
                percent += config.flawlessBonus;
                b.Add("Sin perder piezas", Mathf.RoundToInt(baseAmount * config.flawlessBonus));
            }

            if (win && ctx.winStreak >= 2)
            {
                float streakBonus = Mathf.Min(config.winStreakMaxBonus, config.winStreakStep * (ctx.winStreak - 1));
                if (streakBonus > 0f)
                {
                    percent += streakBonus;
                    b.Add($"Racha ×{ctx.winStreak}", Mathf.RoundToInt(baseAmount * streakBonus));
                }
            }

            int core = baseAmount + Mathf.RoundToInt(baseAmount * percent);

            // ── Bonus fijos por hitos ──
            if (win && ctx.totalTurns <= config.fastMateMaxTurns &&
                (ctx.level == DifficultyLevel.Master || ctx.level == DifficultyLevel.GrandMaster))
            {
                core += config.fastMateBonus;
                b.Add("Mate exprés", config.fastMateBonus);
            }

            if (win && ctx.totalTurns > 60)
            {
                core += config.epicGameBonus;
                b.Add("Partida épica", config.epicGameBonus);
            }

            // ── Anti-farmeo: repetir rival paga menos ──
            float decay = config.RematchFactor(Mathf.Max(0, ctx.consecutiveWinsSameLevel - 1));
            if (win && decay < 1f)
            {
                int after = Mathf.RoundToInt(core * decay);
                b.Add($"Rival repetido ×{decay:0.##}", after - core);
                core = after;
            }

            // ── Primera victoria del día (fuera del decaimiento) ──
            if (win && ctx.firstWinOfDay)
            {
                core += config.firstWinOfDayBonus;
                b.Add("Primera victoria del día", config.firstWinOfDayBonus);
            }

            b.RawTotal = Mathf.Max(0, core);
            b.Granted = b.RawTotal;
            return b;
        }

        /// <summary>
        /// Calcula y cobra la partida. Deja el resultado en el libro diario (decaimiento
        /// y «primera del día») para la próxima vez.
        /// </summary>
        public static MatchBreakdown Settle(MatchContext ctx)
        {
            bool win = ctx.outcome == MatchOutcome.Victory;
            int levelIndex = (int)ctx.level;

            // Estado anti-farmeo ANTES de registrar este resultado
            ctx.consecutiveWinsSameLevel = win ? GambitLedger.ConsecutiveWinsAgainst(levelIndex) : 1;
            ctx.firstWinOfDay = win && !GambitLedger.FirstWinOfDayTaken;

            MatchBreakdown breakdown = Compute(ctx);

            if (win && ctx.firstWinOfDay) GambitLedger.FirstWinOfDayTaken = true;

            var payout = GambitEconomy.Earn(
                breakdown.RawTotal,
                GambitSource.Match,
                meta: $"{ctx.outcome.ToString().ToLowerInvariant()}_{ctx.level.ToString().ToLowerInvariant()}",
                note: $"{ctx.level} {ctx.outcome}");

            breakdown.Granted = payout.granted;
            breakdown.BalanceAfter = payout.balanceAfter;
            breakdown.Limited = payout.limited;
            breakdown.LimitReason = payout.limitReason;

            GambitLedger.NoteMatchResult(levelIndex, win);
            return breakdown;
        }
    }
}
