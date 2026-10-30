using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Caballo Fantasma — variante del Caballo de la velada de Halloween (tienda de Dulces).
    ///
    /// Pasiva «Salto de Niebla»: tras capturar, puede desvanecerse y reaparecer en una
    /// casilla libre alcanzable por un salto de caballo (sin capturar). Un uso por caballo
    /// y partida. El rival puede cubrir las casillas de salida.
    ///
    /// Activa «Posesión»: en lugar de moverse, intercambia su casilla con un peón aliado
    /// situado a un salto de caballo. Consume el turno. Un uso por caballo y partida.
    ///
    /// <c>Type = Knight</c> mantiene intactos FEN, notación y evaluación de la IA.
    /// </summary>
    public class GhostKnight : Knight
    {
        private static readonly int[,] JumpOffsets = new int[,]
        {
            { 2, 1 }, { 2, -1 }, { -2, 1 }, { -2, -1 },
            { 1, 2 }, { 1, -2 }, { -1, 2 }, { -1, -2 }
        };

        /// <summary>¿Le queda el Salto de Niebla? Se consume solo al usarlo.</summary>
        public bool MistStepAvailable { get; private set; } = true;

        /// <summary>¿Le queda la Posesión? Se consume al ejecutarla.</summary>
        public bool PossessionAvailable { get; private set; } = true;

        private void Awake()
        {
            // Unity solo invoca el Awake de la clase más derivada:
            // Knight.Awake no se ejecuta en esta subclase.
            Type = PieceType.Knight;
        }

        public void ConsumeMistStep() => MistStepAvailable = false;
        public void ConsumePossession() => PossessionAvailable = false;

        /// <summary>Restaura los dos usos (Undo / nueva partida).</summary>
        public void RestoreAbilities(bool mistStep, bool possession)
        {
            MistStepAvailable = mistStep;
            PossessionAvailable = possession;
        }

        /// <summary>¿Las dos casillas están a un salto de caballo?</summary>
        public static bool IsKnightJump(Vector2IntCustom from, Vector2IntCustom to)
        {
            int dr = Mathf.Abs(to.Row - from.Row);
            int dc = Mathf.Abs(to.Col - from.Col);
            return (dr == 2 && dc == 1) || (dr == 1 && dc == 2);
        }

        /// <summary>
        /// Casillas libres a un salto de caballo que no dejan al Rey propio en jaque.
        /// Devuelve una lista vacía si la pasiva ya se gastó o el caballo está aturdido.
        /// </summary>
        public List<Vector2IntCustom> GetMistStepSquares(Board board)
        {
            var squares = new List<Vector2IntCustom>();
            if (board == null || IsStunned || !MistStepAvailable) return squares;

            for (int i = 0; i < JumpOffsets.GetLength(0); i++)
            {
                int r = Position.Row + JumpOffsets[i, 0];
                int c = Position.Col + JumpOffsets[i, 1];
                if (!board.IsValidSquare(r, c)) continue;

                var target = new Vector2IntCustom(r, c);
                if (board.GetPieceAt(target) != null) continue;
                if (board.WouldBeInCheck(this, target)) continue;
                squares.Add(target);
            }
            return squares;
        }

        /// <summary>
        /// Peones aliados a un salto de caballo con los que la Posesión es legal.
        /// Excluye la fila de coronación: el peón no puede terminar en la última fila
        /// (sería una coronación gratis).
        /// </summary>
        public List<Vector2IntCustom> GetPossessionTargets(Board board)
        {
            var targets = new List<Vector2IntCustom>();
            if (board == null || IsStunned || !PossessionAvailable) return targets;

            int promotionRow = Team == TeamColor.White ? Board.BOARD_SIZE - 1 : 0;
            if (Position.Row == promotionRow) return targets;

            for (int i = 0; i < JumpOffsets.GetLength(0); i++)
            {
                int r = Position.Row + JumpOffsets[i, 0];
                int c = Position.Col + JumpOffsets[i, 1];
                if (!board.IsValidSquare(r, c)) continue;

                var square = new Vector2IntCustom(r, c);
                ChessPiece piece = board.GetPieceAt(square);
                if (piece == null || piece.Team != Team || !(piece is Pawn)) continue;
                if (!IsSwapLegal(board, piece)) continue;
                targets.Add(square);
            }
            return targets;
        }

        /// <summary>Comprueba si el peón indicado puede intercambiar casilla con este caballo.</summary>
        public bool CanPossess(Board board, ChessPiece pawn)
        {
            if (board == null || pawn == null) return false;
            if (IsStunned || !PossessionAvailable) return false;
            if (pawn.Team != Team || !(pawn is Pawn)) return false;
            if (!IsKnightJump(Position, pawn.Position)) return false;

            int promotionRow = Team == TeamColor.White ? Board.BOARD_SIZE - 1 : 0;
            if (Position.Row == promotionRow) return false;

            return IsSwapLegal(board, pawn);
        }

        /// <summary>
        /// Simula el intercambio en el tablero lógico y comprueba que el Rey propio
        /// no queda en jaque. Restaura las posiciones al terminar.
        /// </summary>
        private bool IsSwapLegal(Board board, ChessPiece pawn)
        {
            Vector2IntCustom knightSquare = Position;
            Vector2IntCustom pawnSquare = pawn.Position;

            board.SetPieceAt(knightSquare, pawn);
            board.SetPieceAt(pawnSquare, this);
            bool legal = !board.IsInCheck(Team);
            board.SetPieceAt(knightSquare, this);
            board.SetPieceAt(pawnSquare, pawn);
            return legal;
        }
    }
}
