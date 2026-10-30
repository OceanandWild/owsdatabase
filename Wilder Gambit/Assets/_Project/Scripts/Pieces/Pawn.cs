using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    public class Pawn : ChessPiece
    {
        private void Awake()
        {
            Type = PieceType.Pawn;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            List<Vector2IntCustom> moves = new List<Vector2IntCustom>();

            // Dirección del movimiento: Blancas suben (+1), Negras bajan (-1)
            int direction = (Team == TeamColor.White) ? 1 : -1;

            // 1. Avanzar 1 casilla
            int forwardRow = Position.Row + direction;
            int col = Position.Col;

            if (board.IsValidSquare(forwardRow, col) && board.GetPieceAt(new Vector2IntCustom(forwardRow, col)) == null)
            {
                moves.Add(new Vector2IntCustom(forwardRow, col));

                // 2. Avanzar 2 casillas desde la posición inicial
                int startRow = (Team == TeamColor.White) ? 1 : 6;
                if (Position.Row == startRow)
                {
                    int doubleForwardRow = Position.Row + (direction * 2);
                    if (board.IsValidSquare(doubleForwardRow, col) && board.GetPieceAt(new Vector2IntCustom(doubleForwardRow, col)) == null)
                    {
                        moves.Add(new Vector2IntCustom(doubleForwardRow, col));
                    }
                }
            }

            // 3. Captura en diagonal (Izquierda y Derecha)
            int[] diagCols = { col - 1, col + 1 };
            foreach (int c in diagCols)
            {
                if (board.IsValidSquare(forwardRow, c))
                {
                    var targetPos = new Vector2IntCustom(forwardRow, c);
                    ChessPiece piece = board.GetPieceAt(targetPos);
                    if (piece != null && piece.Team != Team)
                    {
                        moves.Add(targetPos);
                    }
                }
            }

            return moves;
        }
    }
}
