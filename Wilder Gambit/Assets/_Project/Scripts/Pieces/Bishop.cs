using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    public class Bishop : ChessPiece
    {
        private void Awake()
        {
            Type = PieceType.Bishop;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            List<Vector2IntCustom> moves = new List<Vector2IntCustom>();

            // 4 Diagonales
            AddLineMoves(board, moves, 1, 1);
            AddLineMoves(board, moves, 1, -1);
            AddLineMoves(board, moves, -1, 1);
            AddLineMoves(board, moves, -1, -1);

            return moves;
        }
    }
}
