using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Alfil Nigromante — variante del Alfil con habilidad de Cosecha de Almas y Alzamiento Menor.
    ///
    /// PASIVA — Cosecha de Almas:
    ///   Cada 3 piezas aliadas capturadas ≈ 1 Carga (0.35 por captura). Requiere 4 cargas para invocar.
    ///
    /// ESPECIAL — Alzamiento Menor:
    ///   Con 4 Cargas, invoca un Peón Espectral en casilla vacía adyacente (≤2 casillas)
    ///   de su diagonal en territorio propio. Consume el turno.
    /// </summary>
    public class NecromancerBishop : ChessPiece
    {
        // ─── Estado interno ─────────────────────────────────────────────────────

        // Acumulación equilibrada: 0.35 por captura aliada (~3 capturas = 1 carga)
        private float _soulChargesRaw = 0f;

        /// <summary>Cargas completas de alma disponibles.</summary>
        public int SoulCharges => Mathf.FloorToInt(_soulChargesRaw);

        /// <summary>Carga máxima para UI.</summary>
        public int MaxCharges => 4;

        /// <summary>Progreso fraccional para barra (0-1).</summary>
        public float SoulProgress => Mathf.Clamp01(_soulChargesRaw / MaxCharges);

        /// <summary>¿Puede invocar un Peón Espectral? requiere 4 cargas)</summary>
        public bool CanResurrect => SoulCharges >= 4;

        /// <summary>¿Está a 1 carga de poder invocar? Para aviso previo.</summary>
        public bool IsAlmostReady => SoulCharges == 3;

        // ─── Inicialización ──────────────────────────────────────────────────────

        private void Awake()
        {
            Type = PieceType.NecromancerBishop;
        }

        // ─── Movimiento (idéntico al Alfil) ─────────────────────────────────────

        public override List<Vector2IntCustom> GetValidMoves(Board board)
        {
            var moves = new List<Vector2IntCustom>();
            AddLineMoves(board, moves,  1,  1);
            AddLineMoves(board, moves,  1, -1);
            AddLineMoves(board, moves, -1,  1);
            AddLineMoves(board, moves, -1, -1);
            return moves;
        }

        // ─── Mecánica: Cosecha de Almas ──────────────────────────────────────────

        /// <summary>
        /// Llamado por GameManager cada vez que una pieza aliada es capturada.
        ///  0.35 por captura (~3 capturas = 1 carga). Espectrales no cuentan.
        /// </summary>
        public void OnAllyCaptured()
        {
            _soulChargesRaw += 0.35f;
            if (_soulChargesRaw > MaxCharges) _soulChargesRaw = MaxCharges;
            Debug.Log($"[NecromancerBishop] Carga acumulada: {_soulChargesRaw:F2} (Cargas: {SoulCharges}/{MaxCharges})");
        }

        /// <summary>
        /// Consume 4 cargas al invocar un Peón Espectral.
        /// </summary>
        public void ConsumeCharges()
        {
            _soulChargesRaw = Mathf.Max(0f, _soulChargesRaw - 4f);
            Debug.Log($"[NecromancerBishop] Cargas restantes: {SoulCharges}/{MaxCharges}");
        }

        /// <summary>Añade carga directa (para debug/tests).</summary>
        public void AddCharges(float amount) => _soulChargesRaw = Mathf.Clamp(_soulChargesRaw + amount, 0f, MaxCharges);

        // ─── Mecánica: Alzamiento Menor ──────────────────────────────────────────

        /// <summary>
        /// Devuelve las casillas vacías en las diagonales del Nigromante dentro del territorio propio,
        /// limitadas a distancia ≤2 y no bajo ataque enemigo ( de alcance).
        /// </summary>
        public List<Vector2IntCustom> GetResurrectionSquares(Board board)
        {
            var squares = new List<Vector2IntCustom>();

            int[] dRows = {  1,  1, -1, -1 };
            int[] dCols = {  1, -1,  1, -1 };

            for (int d = 0; d < 4; d++)
            {
                for (int dist = 1; dist <= 2; dist++)
                {
                    int r = Position.Row + dRows[d] * dist;
                    int c = Position.Col + dCols[d] * dist;
                    if (!board.IsValidSquare(r, c)) break;

                    var sq = new Vector2IntCustom(r, c);
                    // Vacía, en territorio propio y no atacada por el enemigo
                    bool isOwn = (Team == TeamColor.White) ? r <= 3 : r >= 4;
                    bool isAttacked = board.IsSquareAttacked(sq, Team);
                    if (board.GetPieceAt(sq) == null && isOwn && !isAttacked)
                    {
                        squares.Add(sq);
                    }
                    else if (board.GetPieceAt(sq) != null)
                    {
                        // Pieza bloquea la diagonal más allá
                        break;
                    }
                }
            }

            return squares;
        }
    }
}
