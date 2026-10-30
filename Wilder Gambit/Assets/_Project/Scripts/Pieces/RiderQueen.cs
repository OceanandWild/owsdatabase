using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Dama Jinete — variante de la Dama (pasiva «Cabalgada»).
    /// Además del repertorio completo de la Dama, una vez por partida puede
    /// saltar como un Caballo a una de sus 8 casillas (con captura).
    /// Mantiene Type = PieceType.Queen para que FEN, promoción, IA y notación
    /// funcionen sin cambios. El uso se consume en <see cref="Board.MovePiece"/>
    /// (único punto de paso de jugadas reales; las simulaciones no pasan por ahí)
    /// y viaja en el Undo como riderData (ver GameManager).
    /// </summary>
    public class RiderQueen : Queen
    {
        /// <summary>¿Sigue disponible la Cabalgada en esta partida?</summary>
        public bool RideAvailable { get; set; } = true;

        private static readonly int[,] RideOffsets =
        {
            { 2, 1 }, { 2, -1 }, { -2, 1 }, { -2, -1 },
            { 1, 2 }, { 1, -2 }, { -1, 2 }, { -1, -2 }
        };

        private void Awake()
        {
            Type = PieceType.Queen;
        }

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            // Repertorio clásico de la Dama (rectas + diagonales)
            var moves = base.GetValidMoves(board);

            // Pasiva «Cabalgada»: 8 saltos de caballo (los offsets (1,2)/(2,1)
            // nunca coinciden con rectas ni diagonales: no hay duplicados).
            if (RideAvailable)
            {
                for (int i = 0; i < 8; i++)
                {
                    int r = Position.Row + RideOffsets[i, 0];
                    int c = Position.Col + RideOffsets[i, 1];
                    if (!board.IsValidSquare(r, c)) continue;

                    var targetPos = new Vector2IntCustom(r, c);
                    ChessPiece piece = board.GetPieceAt(targetPos);
                    if (piece == null || piece.Team != Team)
                        moves.Add(targetPos);
                }
            }

            return moves;
        }

        /// <summary>
        /// ¿Es `to` un destino alcanzable SOLO por Cabalgada desde `from`?
        /// (salto de caballo que las rectas/diagonales clásicas no alcanzan).
        /// Se evalúa sobre el tablero previo al movimiento.
        /// </summary>
        public static bool IsRideDestination(Board board, Vector2IntCustom from, Vector2IntCustom to)
        {
            if (board == null) return false;

            bool isKnightJump = false;
            for (int i = 0; i < 8; i++)
            {
                if (from.Row + RideOffsets[i, 0] == to.Row &&
                    from.Col + RideOffsets[i, 1] == to.Col)
                {
                    isKnightJump = true;
                    break;
                }
            }
            if (!isKnightJump) return false;

            // ¿Llega también por vía clásica? Caminar las 8 direcciones desde `from`
            // (la llegada manda sobre el bloqueo: si el camino alcanza `to`, era clásica).
            int[] dR = { 1, -1, 0, 0, 1, 1, -1, -1 };
            int[] dC = { 0, 0, 1, -1, 1, -1, 1, -1 };
            for (int d = 0; d < 8; d++)
            {
                int r = from.Row + dR[d];
                int c = from.Col + dC[d];
                while (board.IsValidSquare(r, c))
                {
                    if (r == to.Row && c == to.Col) return false; // era jugada clásica
                    if (board.GetPieceAt(new Vector2IntCustom(r, c)) != null) break;
                    r += dR[d];
                    c += dC[d];
                }
            }
            return true;
        }

        /// <summary>Gasta la Cabalgada (la llama Board.MovePiece al ejecutarla).</summary>
        public void ConsumeRide()
        {
            RideAvailable = false;
        }
    }
}
