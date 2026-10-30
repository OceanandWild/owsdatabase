using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Peón Lancero — variante del Peón (pasiva «Lanza»).
    /// Además de las reglas base (avance simple, doble y captura diagonal),
    /// puede CAPTURAR HACIA ADELANTE una casilla si hay pieza enemiga.
    /// Mantiene Type = PieceType.Pawn para que FEN, promoción, IA y notación funcionen sin cambios.
    /// </summary>
    public class LancerPawn : Pawn
    {
        private void Awake()
        {
            Type = PieceType.Pawn;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            // Reglas base del peón: avance 1, avance doble (fila inicial) y captura diagonal
            var moves = base.GetValidMoves(board);

            // Pasiva «Lanza»: captura frontal (el peón base solo avanza a casillas vacías,
            // así que esta rama nunca duplica un movimiento ya añadido)
            int direction = (Team == TeamColor.White) ? 1 : -1;
            var forwardPos = new Vector2IntCustom(Position.Row + direction, Position.Col);

            if (board.IsValidSquare(forwardPos.Row, forwardPos.Col))
            {
                ChessPiece piece = board.GetPieceAt(forwardPos);
                if (piece != null && piece.Team != Team)
                {
                    moves.Add(forwardPos);
                }
            }

            return moves;
        }
    }
}
