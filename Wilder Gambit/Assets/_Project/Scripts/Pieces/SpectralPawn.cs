using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Peón Espectral — versión equilibrada del Peón.
    /// S: sin doble avance, no promociona, frágil (3 turnos de vida) y no genera almas al ser capturado.
    /// El flag IsSpectral indica a BoardView que use el sprite espectral.
    /// </summary>
    public class SpectralPawn : Pawn
    {
        /// <summary>Indica que esta pieza debe renderizarse con el sprite espectral.</summary>
        public bool IsSpectral => true;

        /// <summary>Vida restante en medio-turnos (4 = 2 turnos completos). Al llegar a 0 se desvanece.</summary>
        public int TurnsToFade { get; set; } = 4;

        private void Awake()
        {
            Type = PieceType.Pawn;
            HasMoved = true; //  sin avance doble inicial
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            //  solo avance simple y captura diagonal, sin doble
            var moves = new List<Vector2IntCustom>();
            int dir = (Team == TeamColor.White) ? 1 : -1;
            int fwd = Position.Row + dir;
            int col = Position.Col;
            if (board.IsValidSquare(fwd, col) && board.GetPieceAt(new Vector2IntCustom(fwd, col)) == null)
                moves.Add(new Vector2IntCustom(fwd, col));
            int[] diags = { col - 1, col + 1 };
            foreach (int c in diags)
            {
                if (board.IsValidSquare(fwd, c))
                {
                    var targetPos = new Vector2IntCustom(fwd, c);
                    ChessPiece p = board.GetPieceAt(targetPos);
                    if (p != null && p.Team != Team) moves.Add(targetPos);
                }
            }
            return moves;
        }

        /// <summary>Peón Espectral no promociona.</summary>
        public bool CanPromote => false;
    }
}
