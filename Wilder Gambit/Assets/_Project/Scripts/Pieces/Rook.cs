using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    public class Rook : ChessPiece
    {
        private void Awake()
        {
            Type = PieceType.Rook;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            List<Vector2IntCustom> moves = new List<Vector2IntCustom>();

            // 4 Ortogonales
            AddLineMoves(board, moves, 1, 0);
            AddLineMoves(board, moves, -1, 0);
            AddLineMoves(board, moves, 0, 1);
            AddLineMoves(board, moves, 0, -1);

            return moves;
        }
    }
}
