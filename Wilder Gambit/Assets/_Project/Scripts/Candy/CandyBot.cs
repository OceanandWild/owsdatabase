using System;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Candy
{
    /// <summary>
    /// Bot de la Cacería de Dulces. No usa ChessAI: aquel motor está atado al
    /// jaque mate y al tablero de 8×8. Este elige entre invocar una pieza o
    /// moverla buscando Dulces, capturas y no regalar material.
    /// </summary>
    public static class CandyBot
    {
        public static CandyAction ChooseDeploy(CandyModeBoard board, TeamColor side)
        {
            if (board == null || board.CurrentSide != side || board.DeployedThisTurn) return null;
            if (board.GetReserveTotal(side) <= 0) return null;

            var types = new List<PieceType>();
            for (int i = 0; i < CandyCatalog.DraftOrder.Length; i++)
            {
                PieceType type = CandyCatalog.DraftOrder[i];
                if (board.GetReserve(side, type) > 0) types.Add(type);
            }
            if (types.Count == 0) return null;

            // El rey entra último: no hace falta exponerlo mientras haya otras piezas.
            if (types.Count > 1) types.Remove(PieceType.King);

            PieceType bestType = types[0];
            int bestRow = -1;
            int bestCol = -1;
            float bestScore = float.NegativeInfinity;

            for (int t = 0; t < types.Count; t++)
            {
                PieceType type = types[t];
                for (int r = 0; r < CandyModeBoard.Size; r++)
                {
                    for (int c = 0; c < CandyModeBoard.Size; c++)
                    {
                        if (!board.CanDeploy(side, type, r, c)) continue;

                        float score = 0f;
                        int candy = board.GetCandyAt(r, c);
                        if (candy > 0) score += 20f + candy * 8f;

                        // Un peón invocado en la fila de coronación entra como
                        // dama (misma regla que Deploy), así que vale más.
                        if (type == PieceType.Pawn &&
                            (side == TeamColor.White
                                ? r == CandyModeBoard.Size - 1
                                : r == 0))
                        {
                            score += 35f;
                        }

                        // Centro y avance: el bot quiere piezas activas, no escondidas.
                        score += (6f - Mathf.Abs(5.5f - r)) * 0.8f;
                        score += (6f - Mathf.Abs(5.5f - c)) * 0.35f;
                        score += (side == TeamColor.White ? r : (CandyModeBoard.Size - 1 - r)) * 0.35f;

                        int enemyDistance = NearestEnemyDistance(board, side, r, c);
                        score += Mathf.Min(enemyDistance, 7) * 0.45f;

                        score += CandyCatalog.PieceValue(type) * 0.08f;
                        score += UnityEngine.Random.Range(0f, 0.9f);

                        if (score > bestScore)
                        {
                            bestScore = score;
                            bestType = type;
                            bestRow = r;
                            bestCol = c;
                        }
                    }
                }
            }

            if (bestRow < 0) return null;
            string variant = board.GetLoadout(side).Get(bestType);
            return CandyAction.Deploy(side, bestType, variant, bestRow, bestCol);
        }

        public static CandyAction ChooseMove(CandyModeBoard board, TeamColor side)
        {
            if (board == null || board.CurrentSide != side) return null;

            CandyPiece bestPiece = null;
            Vector2IntCustom bestTo = new Vector2IntCustom(-1, -1);
            float bestScore = float.NegativeInfinity;

            var pieces = board.GetPieces(side);
            for (int p = 0; p < pieces.Count; p++)
            {
                var piece = pieces[p];
                var moves = board.GetLegalMoves(piece);
                for (int m = 0; m < moves.Count; m++)
                {
                    var to = moves[m];
                    var target = board.GetPieceAt(to.Row, to.Col);
                    float score = 0f;

                    int candy = board.GetCandyAt(to.Row, to.Col);
                    if (candy > 0) score += 14f + candy * 10f;

                    if (target != null)
                    {
                        int pieceValue = CandyCatalog.PieceValue(target.type);
                        score += pieceValue;

                        if (target.type == PieceType.King) score += 45f;
                        if (target.type == PieceType.Queen) score += 30f;

                        var attackerVariant = CandyCatalog.Get(piece.type, piece.variantId);
                        if (attackerVariant != null) score += attackerVariant.captureBonus * 7f;
                    }

                    if (piece.type == PieceType.Pawn)
                    {
                        bool promotion = side == TeamColor.White
                            ? to.Row == CandyModeBoard.Size - 1
                            : to.Row == 0;
                        if (promotion) score += 35f;
                    }

                    // No regalar la pieza: vale más la pena si el destino está cubierto.
                    TeamColor rival = side == TeamColor.White ? TeamColor.Black : TeamColor.White;
                    if (board.IsAttackedBy(rival, to.Row, to.Col, piece))
                        score -= CandyCatalog.PieceValue(piece.type) * 0.72f;

                    // Pequeño empujón al centro y a los Dulces cercanos.
                    score += (6f - Mathf.Abs(5.5f - to.Row)) * 0.15f;
                    score += (6f - Mathf.Abs(5.5f - to.Col)) * 0.08f;
                    score += UnityEngine.Random.Range(0f, 0.35f);

                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestPiece = piece;
                        bestTo = to;
                    }
                }
            }

            if (bestPiece == null) return CandyAction.Pass(side);
            return CandyAction.Move(side, bestPiece.id, bestTo.Row, bestTo.Col);
        }

        private static int NearestEnemyDistance(CandyModeBoard board, TeamColor side, int row, int col)
        {
            TeamColor rival = side == TeamColor.White ? TeamColor.Black : TeamColor.White;
            int best = 99;
            var enemies = board.GetPieces(rival);
            for (int i = 0; i < enemies.Count; i++)
            {
                int d = Mathf.Abs(enemies[i].row - row) + Mathf.Abs(enemies[i].col - col);
                if (d < best) best = d;
            }
            return best;
        }
    }
}
