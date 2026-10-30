using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    public class Knight : ChessPiece
    {
        private void Awake()
        {
            Type = PieceType.Knight;
        }

        public bool IsTransformed { get; set; } = false;

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            List<Vector2IntCustom> moves = new List<Vector2IntCustom>();

            // Las 8 posibles posiciones en 'L' del Caballo
            int[,] offsets = new int[,]
            {
                { 2, 1 }, { 2, -1 }, { -2, 1 }, { -2, -1 },
                { 1, 2 }, { 1, -2 }, { -1, 2 }, { -1, -2 }
            };

            for (int i = 0; i < 8; i++)
            {
                int r = Position.Row + offsets[i, 0];
                int c = Position.Col + offsets[i, 1];

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

            return moves;
        }

        /// <summary>
        /// Comprueba si desde la casilla dada este Caballo está realizando un Fork
        /// (atacando simultáneamente a 2 o más piezas enemigas).
        /// </summary>
        public bool CheckIsFork(Board board, Vector2IntCustom pos)
        {
            int attackedEnemyCount = 0;
            int[,] offsets = new int[,]
            {
                { 2, 1 }, { 2, -1 }, { -2, 1 }, { -2, -1 },
                { 1, 2 }, { 1, -2 }, { -1, 2 }, { -1, -2 }
            };

            for (int i = 0; i < 8; i++)
            {
                int r = pos.Row + offsets[i, 0];
                int c = pos.Col + offsets[i, 1];
                if (board.IsValidSquare(r, c))
                {
                    ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (piece != null && piece.Team != Team)
                    {
                        attackedEnemyCount++;
                    }
                }
            }

            return attackedEnemyCount >= 2;
        }
    }
}
