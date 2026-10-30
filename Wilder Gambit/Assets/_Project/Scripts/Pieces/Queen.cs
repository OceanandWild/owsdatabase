using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    public class Queen : ChessPiece
    {
        private void Awake()
        {
            Type = PieceType.Queen;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            List<Vector2IntCustom> moves = new List<Vector2IntCustom>();

            // Combinación de Torre (4 Ortogonales) y Alfil (4 Diagonales)
            AddLineMoves(board, moves, 1, 0);
            AddLineMoves(board, moves, -1, 0);
            AddLineMoves(board, moves, 0, 1);
            AddLineMoves(board, moves, 0, -1);
            AddLineMoves(board, moves, 1, 1);
            AddLineMoves(board, moves, 1, -1);
            AddLineMoves(board, moves, -1, 1);
            AddLineMoves(board, moves, -1, -1);

            return moves;
        }
    }
}
