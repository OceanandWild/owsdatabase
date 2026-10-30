using System;
using UnityEngine;

namespace WilderGambit.Engine
{
    public enum MoveClassification
    {
        None,
        Book,           // Apertura estándar de libro
        Brilliant,      // 💎 Gran jugada no intuitiva / sacrificio con ventaja
        GreatMove,      // ⭐ Jugada clave salvadora o ganadora
        BestMove,       // ★ Mejor jugada calculada por el motor
        Excellent,      // ✔️ Pérdida mínima (< 0.20 peones)
        Good,           // 👍 Pérdida leve (< 0.50 peones)
        Inaccuracy,     // ⁉️ Imprecisión (0.50 - 1.00 peones)
        Mistake,        // ⚠️ Error (1.00 - 2.00 peones)
        Blunder,        // ❓❓ Grave error (> 2.00 peones o mate)
        MissedWin       // 🚫 Oportunidad de victoria perdida
    }

    public static class MoveEvaluator
    {
        public static MoveClassification ClassifyMove(
            string playedUci,
            StockfishAnalysis beforeMoveAnalysis,
            StockfishAnalysis afterMoveAnalysis,
            bool isCurrentMoveFork = false,
            bool isPieceSacrifice = false,
            bool isBookMove = false)
        {
            if (isBookMove) return MoveClassification.Book;

            // UCI moves can match exactly or with promotion suffix
            bool isBestMoveMatch = !string.IsNullOrEmpty(beforeMoveAnalysis.BestMove) &&
                                  (beforeMoveAnalysis.BestMove.Equals(playedUci, StringComparison.OrdinalIgnoreCase) ||
                                   beforeMoveAnalysis.BestMove.StartsWith(playedUci, StringComparison.OrdinalIgnoreCase));

            // Eval before from perspective of side to move:
            float evalBefore = beforeMoveAnalysis.Centipawns;
            // Eval after is from perspective of the next player (opponent), so negate it to stay in current player's perspective:
            float evalAfter = -afterMoveAnalysis.Centipawns;

            float evalLoss = evalBefore - evalAfter;

            // 1. Coincidencia con la Mejor Jugada calculada por Stockfish:
            if (isBestMoveMatch)
            {
                // Gran jugada si encuentra el único movimiento defensivo o de ventaja en posición comprometida
                if (evalBefore <= -1.2f && evalAfter >= -0.2f)
                {
                    return MoveClassification.GreatMove;
                }
                return MoveClassification.BestMove;
            }

            // 2. GRAVE ERROR (Blunder ❓❓):
            // Pérdida severa de material / evaluación (> 2.20 peones) o conceder mate.
            // Si el jugador regala una pieza limpia o arruina la partida, SIEMPRE es Blunder (incluso si la casilla ataca piezas).
            if (evalLoss >= 2.20f || (afterMoveAnalysis.IsMate && afterMoveAnalysis.MateInMoves > 0))
            {
                return MoveClassification.Blunder;
            }

            // 3. OPORTUNIDAD PERDIDA (Missed Win / Miss 🚫):
            // El jugador tenía una ventaja decisiva (evalBefore >= 2.0 o mate) y desaprovechó la oportunidad
            // con una pérdida sustancial de ventaja (evalLoss >= 1.50).
            if ((evalBefore >= 2.0f || (beforeMoveAnalysis.IsMate && beforeMoveAnalysis.MateInMoves > 0)) &&
                evalLoss >= 1.50f)
            {
                return MoveClassification.MissedWin;
            }

            // 4. ERROR CLARO (Mistake ⚠️):
            // Pérdida de 1.50 a 2.20 peones
            if (evalLoss >= 1.50f)
            {
                return MoveClassification.Mistake;
            }

            // 5. TÁCTICA DE FORK EN WILDER GAMBIT (Brillante 💎 / Gran Jugada ⭐ / Bueno 👍):
            // Mecánica principal del Caballo. Si no es blunder/mistake grave, premia la ejecución del Fork
            if (isCurrentMoveFork)
            {
                // Fork con ventaja táctica notable -> Brillante
                if (evalAfter >= 0.20f && evalLoss <= 0.40f)
                {
                    return MoveClassification.Brilliant;
                }
                // Fork activo que mantiene o busca iniciativa -> Gran Jugada
                if (evalAfter >= -0.80f && evalLoss <= 1.25f)
                {
                    return MoveClassification.GreatMove;
                }
                return MoveClassification.Good;
            }

            // 6. IMPRECISIÓN (Inaccuracy ⁉️):
            // Pérdida de 0.65 a 1.50 peones para jugadas regulares
            if (evalLoss >= 0.65f)
            {
                return MoveClassification.Inaccuracy;
            }

            // 7. Sacrificio Brillante genuino (sacrificio de material que mantiene o gana ventaja):
            if (isPieceSacrifice && evalLoss <= 0.25f && evalAfter >= 0.5f)
            {
                return MoveClassification.Brilliant;
            }

            // 8. Apertura estándar de libro (solo si no hubo pérdida significativa de evaluación):
            if (IsCommonOpeningMove(playedUci) && evalLoss <= 0.40f)
            {
                return MoveClassification.Book;
            }

            // 9. Jugada casi óptima (diferencia mínima con el Best Move):
            if (evalLoss <= 0.08f)
            {
                return MoveClassification.BestMove;
            }

            // 10. Jugada Excelente:
            if (evalLoss <= 0.28f)
            {
                return MoveClassification.Excellent;
            }

            // 11. Jugada Buena:
            return MoveClassification.Good;
        }

        private static bool IsCommonOpeningMove(string uci)
        {
            if (string.IsNullOrEmpty(uci) || uci.Length < 4) return false;
            // Repertorio de aperturas principales y respuestas estándar en ajedrez
            string[] bookMoves = new string[]
            {
                // Blancas (1. y 2. jugadas)
                "e2e4", "d2d4", "c2c4", "g1f3", "b1c3", "g2g3", "f2f4", "b2b3", "c2c3", "d2d3", "e2e3",
                "f1c4", "f1b5", "f1e2", "f1d3", "f1g2", "c1e3", "c1f4", "c1g5", "e1g1",
                // Negras (1. y 2. respuestas)
                "e7e5", "d7d5", "c7c5", "e7e6", "c7c6", "g8f6", "b8c6", "d7d6", "g7g6", "b7b6", "a7a6",
                "f8c5", "f8b4", "f8e7", "f8d6", "f8g7", "c8e6", "c8f5", "c8g4", "e8g8"
            };
            foreach (var m in bookMoves)
            {
                if (uci.StartsWith(m, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static string GetBadgeTextureName(MoveClassification classification)
        {
            switch (classification)
            {
                case MoveClassification.Brilliant:      return "badge_brilliant";
                case MoveClassification.GreatMove:      return "badge_great_move";
                case MoveClassification.BestMove:       return "badge_best_move";
                case MoveClassification.Excellent:      return "badge_excellent";
                case MoveClassification.Good:           return "badge_good";
                case MoveClassification.Book:           return "badge_book";
                case MoveClassification.Inaccuracy:     return "badge_inaccuracy";
                case MoveClassification.Mistake:        return "badge_mistake";
                case MoveClassification.Blunder:        return "badge_blunder";
                case MoveClassification.MissedWin:      return "badge_missed_win";
                default:                                return null;
            }
        }
    }
}
