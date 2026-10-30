using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    public class King : ChessPiece
    {
        private void Awake()
        {
            Type = PieceType.King;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            List<Vector2IntCustom> moves = new List<Vector2IntCustom>();

            // Las 8 casillas circundantes
            int[] dRows = { -1, -1, -1, 0, 0, 1, 1, 1 };
            int[] dCols = { -1, 0, 1, -1, 1, -1, 0, 1 };

            for (int i = 0; i < 8; i++)
            {
                int r = Position.Row + dRows[i];
                int c = Position.Col + dCols[i];

                if (board.IsValidSquare(r, c))
                {
                    var targetPos = new Vector2IntCustom(r, c);
                    ChessPiece piece = board.GetPieceAt(targetPos);
                    if (piece == null || piece.Team != Team)
                    {
                        moves.Add(targetPos);
                    }
                }
            }

            // ── Enroque (Castling) ──
            if (!HasMoved && !board.IsInCheck(Team))
            {
                // Enroque Corto (Kingside - Columna 7)
                ChessPiece rookK = board.GetPieceAt(new Vector2IntCustom(Position.Row, 7));
                if (rookK != null && rookK.Type == PieceType.Rook && rookK.Team == Team && !rookK.HasMoved)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(Position.Row, 5)) == null &&
                        board.GetPieceAt(new Vector2IntCustom(Position.Row, 6)) == null)
                    {
                        if (!board.IsSquareAttacked(new Vector2IntCustom(Position.Row, 5), Team) &&
                            !board.IsSquareAttacked(new Vector2IntCustom(Position.Row, 6), Team))
                        {
                            moves.Add(new Vector2IntCustom(Position.Row, 6));
                        }
                    }
                }

                // Enroque Largo (Queenside - Columna 0)
                ChessPiece rookQ = board.GetPieceAt(new Vector2IntCustom(Position.Row, 0));
                if (rookQ != null && rookQ.Type == PieceType.Rook && rookQ.Team == Team && !rookQ.HasMoved)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(Position.Row, 1)) == null &&
                        board.GetPieceAt(new Vector2IntCustom(Position.Row, 2)) == null &&
                        board.GetPieceAt(new Vector2IntCustom(Position.Row, 3)) == null)
                    {
                        if (!board.IsSquareAttacked(new Vector2IntCustom(Position.Row, 2), Team) &&
                            !board.IsSquareAttacked(new Vector2IntCustom(Position.Row, 3), Team))
                        {
                            moves.Add(new Vector2IntCustom(Position.Row, 2));
                        }
                    }
                }
            }

            return moves;
        }
    }
}
