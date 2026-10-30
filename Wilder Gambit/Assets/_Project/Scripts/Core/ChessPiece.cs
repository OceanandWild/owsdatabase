using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    public abstract class ChessPiece : MonoBehaviour
    {
        public TeamColor Team { get; protected set; }
        public PieceType Type { get; protected set; }
        public Vector2IntCustom Position { get; set; }
        public bool HasMoved { get; set; } = false;

        /// <summary>
        /// Turnos de aturdimiento restantes (Explosión de Calabaza). Mientras sea > 0
        /// la pieza no puede moverse, aunque sus ataques siguen contando para el jaque.
        /// </summary>
        public int StunTurns { get; set; } = 0;

        /// <summary>
        /// Evita que el primer tick de turno descuente el turno en el que se aplicó
        /// el aturdimiento: el capturador pierde exactamente 2 de sus turnos.
        /// </summary>
        public bool StunJustApplied { get; set; } = false;

        public bool IsStunned => StunTurns > 0;

        public virtual void Init(TeamColor team, Vector2IntCustom startPos)
        {
            Team = team;
            Position = startPos;
            HasMoved = false;
            StunTurns = 0;
            StunJustApplied = false;
        }

        /// <summary>Aplica (o refresca) el aturdimiento. El Rey nunca debería llegar aquí.</summary>
        public void ApplyStun(int turns)
        {
            if (turns <= 0) return;
            StunTurns = Mathf.Max(StunTurns, turns);
            StunJustApplied = true;
        }

        /// <summary>
        /// Cambia el bando de la pieza en caliente (Tributo de la Torre Fragua:
        /// la pieza condenada pelea para el condenador y luego vuelve a su ejército).
        /// </summary>
        public void SetTeam(TeamColor team)
        {
            Team = team;
        }

        /// <summary>
        /// Obtiene todas las casillas válidas a las que se puede mover esta pieza (pseudo-legales).
        /// </summary>
        public abstract List<Vector2IntCustom> GetValidMoves(Board board);

        /// <summary>
        /// Filtra los movimientos pseudo-legales para descartar los que dejan al propio Rey en jaque.
        /// </summary>
        public List<Vector2IntCustom> GetLegalMoves(Board board)
        {
            // Aturdido: no puede moverse, pero GetValidMoves sigue usándose para
            // calcular amenazas (IsSquareAttacked), así que sus ataques no desaparecen.
            if (IsStunned) return new List<Vector2IntCustom>();

            List<Vector2IntCustom> candidates = GetValidMoves(board);
            List<Vector2IntCustom> legal = new List<Vector2IntCustom>();

            foreach (var move in candidates)
            {
                if (!board.WouldBeInCheck(this, move))
                    legal.Add(move);
            }

            return legal;
        }

        /// <summary>
        /// Ayudante para agregar movimientos lineales (Torre, Alfil, Reina) en una dirección dada.
        /// </summary>
        protected void AddLineMoves(Board board, List<Vector2IntCustom> moves, int dRow, int dCol)
        {
            int r = Position.Row + dRow;
            int c = Position.Col + dCol;

            while (board.IsValidSquare(r, c))
            {
                var targetPos = new Vector2IntCustom(r, c);
                ChessPiece pieceAtTarget = board.GetPieceAt(targetPos);

                if (pieceAtTarget == null)
                {
                    moves.Add(targetPos);
                }
                else
                {
                    if (pieceAtTarget.Team != this.Team)
                    {
                        moves.Add(targetPos); // Captura
                    }
                    break; // Hay una pieza bloqueando el camino
                }

                r += dRow;
                c += dCol;
            }
        }
    }
}
