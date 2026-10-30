using System;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Candy
{
    /// <summary>
    /// Tablero lógico de la Cacería de Dulces (12×12). Es deliberadamente
    /// independiente del <see cref="Board"/> de ajedrez: aquí no hay jaque,
    /// enroque, promoción FEN ni reyes obligatorios. Sólo piezas, movimientos,
    /// Dulces y capturas.
    ///
    /// La misma secuencia de acciones produce el mismo tablero en los dos
    /// clientes del modo online: el azar de los Dulces sale de una semilla
    /// compartida y de un <see cref="System.Random"/> que sólo avanza al
    /// resolver acciones.
    /// </summary>
    public class CandyModeBoard
    {
        public const int Size = CandyCatalog.BoardSize;

        private CandyPiece[,] _grid = new CandyPiece[Size, Size];
        private int[,] _candies = new int[Size, Size];
        private readonly Dictionary<int, CandyPiece> _pieces = new Dictionary<int, CandyPiece>();
        private readonly Dictionary<PieceType, int>[] _reserves =
        {
            new Dictionary<PieceType, int>(),
            new Dictionary<PieceType, int>()
        };
        private readonly CandyLoadout[] _loadouts = new CandyLoadout[2];

        private System.Random _rng;
        private int _nextPieceId = 1;

        // Pieza invocada en el turno en curso. Una invocación vale por la
        // acción de esa pieza: no puede moverse ni capturar hasta el turno
        // siguiente, así el rival no puede "aparecer" encima de una pieza y
        // comérsela en el acto.
        private int _summonedPieceId;

        public int Seed { get; private set; }
        public TeamColor CurrentSide { get; private set; } = TeamColor.White;
        public bool DeployedThisTurn { get; private set; }
        public int WhiteScore { get; private set; }
        public int BlackScore { get; private set; }
        public int WhiteCaptures { get; private set; }
        public int BlackCaptures { get; private set; }
        public int ActionCount { get; private set; }

        public void Reset(int seed, CandyLoadout whiteLoadout, CandyLoadout blackLoadout)
        {
            Seed = seed;
            _rng = new System.Random(seed);
            _nextPieceId = 1;
            _pieces.Clear();
            _grid = new CandyPiece[Size, Size];
            _candies = new int[Size, Size];

            _loadouts[0] = whiteLoadout ?? CandyLoadout.Default();
            _loadouts[1] = blackLoadout ?? CandyLoadout.Default();
            _loadouts[0].Normalize();
            _loadouts[1].Normalize();

            _reserves[0] = new Dictionary<PieceType, int>();
            _reserves[1] = new Dictionary<PieceType, int>();
            for (int i = 0; i < CandyCatalog.Army.Length; i++)
            {
                var entry = CandyCatalog.Army[i];
                _reserves[0][entry.type] = entry.count;
                _reserves[1][entry.type] = entry.count;
            }

            CurrentSide = TeamColor.White;
            DeployedThisTurn = false;
            _summonedPieceId = 0;
            WhiteScore = 0;
            BlackScore = 0;
            WhiteCaptures = 0;
            BlackCaptures = 0;
            ActionCount = 0;

            SpawnCandies(CandyCatalog.InitialCandies);
        }

        public CandyLoadout GetLoadout(TeamColor side) => _loadouts[Index(side)];

        public bool IsValidSquare(int row, int col)
            => row >= 0 && row < Size && col >= 0 && col < Size;

        public CandyPiece GetPieceAt(int row, int col)
            => IsValidSquare(row, col) ? _grid[row, col] : null;

        public CandyPiece GetPieceById(int id)
            => _pieces.TryGetValue(id, out var piece) ? piece : null;

        public int GetCandyAt(int row, int col)
            => IsValidSquare(row, col) ? _candies[row, col] : 0;

        public int GetReserve(TeamColor side, PieceType type)
        {
            var reserve = _reserves[Index(side)];
            return reserve.TryGetValue(type, out int count) ? count : 0;
        }

        public int GetReserveTotal(TeamColor side)
        {
            int total = 0;
            foreach (var pair in _reserves[Index(side)]) total += pair.Value;
            return total;
        }

        public int GetPieceCount(TeamColor side)
        {
            int total = 0;
            foreach (var pair in _pieces)
            {
                if (pair.Value != null && pair.Value.side == side) total++;
            }
            return total;
        }

        public int GetScore(TeamColor side) => side == TeamColor.White ? WhiteScore : BlackScore;
        public int GetCaptures(TeamColor side) => side == TeamColor.White ? WhiteCaptures : BlackCaptures;
        public int GetCandyCount() => CountCandies();
        public bool IsEliminated(TeamColor side) => GetPieceCount(side) == 0 && GetReserveTotal(side) == 0;

        /// <summary>
        /// Id de la pieza que se invocó en el turno en curso (0 si nadie
        /// invocó). Esa pieza espera al próximo turno para moverse: la
        /// invocación ocupa su acción, igual que en el resto del tablero.
        /// </summary>
        public int SummonedPieceId => _summonedPieceId;

        /// <summary>¿Esta pieza acaba de ser invocada en el turno en curso?</summary>
        public bool IsSummonedThisTurn(CandyPiece piece)
            => piece != null && piece.id == _summonedPieceId;

        public List<CandyPiece> GetPieces(TeamColor side)
        {
            var list = new List<CandyPiece>();
            foreach (var pair in _pieces)
            {
                if (pair.Value != null && pair.Value.side == side) list.Add(pair.Value);
            }
            return list;
        }

        public bool CanDeploy(TeamColor side, PieceType type, int row, int col)
        {
            if (side != CurrentSide || DeployedThisTurn) return false;
            if (!IsValidSquare(row, col) || _grid[row, col] != null) return false;
            return GetReserve(side, type) > 0;
        }

        public CandyActionResult Deploy(TeamColor side, PieceType type, string variantId, int row, int col)
        {
            if (side != CurrentSide) return CandyActionResult.Fail("No es tu turno.");
            if (DeployedThisTurn) return CandyActionResult.Fail("Ya invocaste una pieza este turno.");
            if (!IsValidSquare(row, col)) return CandyActionResult.Fail("Casilla fuera del tablero.");
            if (_grid[row, col] != null) return CandyActionResult.Fail("La casilla está ocupada.");
            if (GetReserve(side, type) <= 0) return CandyActionResult.Fail("No te quedan piezas de ese tipo.");

            if (string.IsNullOrEmpty(variantId))
                variantId = _loadouts[Index(side)].Get(type);
            if (CandyCatalog.Get(type, variantId) == null)
                variantId = CandyCatalog.DefaultVariantFor(type).id;

            var piece = new CandyPiece
            {
                id = _nextPieceId++,
                side = side,
                type = type,
                variantId = variantId,
                row = row,
                col = col
            };

            _grid[row, col] = piece;
            _pieces[piece.id] = piece;
            _summonedPieceId = piece.id;
            _reserves[Index(side)][type] = GetReserve(side, type) - 1;
            DeployedThisTurn = true;
            ActionCount++;

            var result = CandyActionResult.Success();

            // Un peón invocado directamente en la última fila no tendría
            // ningún movimiento legal (los peones no retroceden). Se corona en
            // el acto, igual que si hubiera llegado moviéndose.
            if (piece.type == PieceType.Pawn && IsPromotionRow(side, row))
            {
                piece.type = PieceType.Queen;
                piece.variantId = _loadouts[Index(side)].Get(PieceType.Queen);
                result.promoted = true;
            }

            int candy = CollectCandy(side, row, col);
            result.candyCollected = candy;
            result.scoreGained = candy;
            if (candy > 0) AddScore(side, candy);
            return result;
        }

        public CandyActionResult Move(TeamColor side, int pieceId, int toRow, int toCol)
        {
            if (side != CurrentSide) return CandyActionResult.Fail("No es tu turno.");
            if (!_pieces.TryGetValue(pieceId, out var piece) || piece == null)
                return CandyActionResult.Fail("Esa pieza ya no está en el tablero.");
            if (piece.side != side) return CandyActionResult.Fail("Esa pieza es del rival.");
            if (IsSummonedThisTurn(piece))
                return CandyActionResult.Fail("La invocaste este turno: se mueve a partir del próximo.");
            if (!IsValidSquare(toRow, toCol)) return CandyActionResult.Fail("Casilla fuera del tablero.");
            if (toRow == piece.row && toCol == piece.col) return CandyActionResult.Fail("La pieza ya está ahí.");

            if (!ContainsMove(GetLegalMoves(piece), toRow, toCol))
                return CandyActionResult.Fail("Movimiento ilegal para esa pieza.");

            var result = CandyActionResult.Success();
            int fromRow = piece.row;
            int fromCol = piece.col;
            var target = _grid[toRow, toCol];

            if (target != null)
            {
                if (target.side == side) return CandyActionResult.Fail("No podés capturar tus propias piezas.");

                _grid[toRow, toCol] = null;
                _pieces.Remove(target.id);

                result.capturedType = target.type;
                result.capturedKing = target.type == PieceType.King;
                result.capturedQueen = target.type == PieceType.Queen;

                var attackerVariant = CandyCatalog.Get(piece.type, piece.variantId);
                int variantBonus = attackerVariant != null ? attackerVariant.captureBonus : 0;
                int royaltyBonus = result.capturedKing ? 5 : (result.capturedQueen ? 3 : 0);
                int capturePoints = 1 + variantBonus + royaltyBonus;

                result.captureBonus = capturePoints;
                AddScore(side, capturePoints);
                if (side == TeamColor.White) WhiteCaptures++;
                else BlackCaptures++;
            }

            _grid[fromRow, fromCol] = null;
            piece.row = toRow;
            piece.col = toCol;
            _grid[toRow, toCol] = piece;

            int candy = CollectCandy(side, toRow, toCol);
            result.candyCollected = candy;
            if (candy > 0) AddScore(side, candy);

            if (piece.type == PieceType.Pawn && IsPromotionRow(side, toRow))
            {
                piece.type = PieceType.Queen;
                piece.variantId = _loadouts[Index(side)].Get(PieceType.Queen);
                result.promoted = true;
            }

            result.scoreGained = result.captureBonus + candy;

            SpawnCandies(1);
            EndTurn();
            ActionCount++;
            return result;
        }

        public CandyActionResult Pass(TeamColor side)
        {
            if (side != CurrentSide) return CandyActionResult.Fail("No es tu turno.");
            SpawnCandies(1);
            EndTurn();
            ActionCount++;
            return CandyActionResult.Success();
        }

        public CandyActionResult ApplyAction(CandyAction action)
        {
            if (action == null) return CandyActionResult.Fail("Acción vacía.");
            TeamColor side = action.side == 0 ? TeamColor.White : TeamColor.Black;
            string kind = (action.kind ?? "").ToLowerInvariant();

            if (kind == "deploy")
            {
                if (!Enum.TryParse(action.type, out PieceType type))
                    return CandyActionResult.Fail("Tipo de pieza inválido.");
                return Deploy(side, type, action.variant, action.row, action.col);
            }

            if (kind == "move")
                return Move(side, action.pieceId, action.row, action.col);

            if (kind == "pass")
                return Pass(side);

            return CandyActionResult.Fail("Acción desconocida: " + kind);
        }

        public List<Vector2IntCustom> GetLegalMoves(CandyPiece piece)
        {
            var moves = new List<Vector2IntCustom>();
            if (piece == null) return moves;

            // La pieza recién invocada todavía no puede moverse. Al no ofrecer
            // destinos, el jugador, el bot y la validación de jugadas quedan
            // alineados sin duplicar la regla en cada capa.
            if (IsSummonedThisTurn(piece)) return moves;

            int row = piece.row;
            int col = piece.col;

            switch (piece.type)
            {
                case PieceType.Pawn:
                    AddPawnMoves(piece, moves);
                    break;

                case PieceType.Knight:
                    AddKnightMoves(piece, moves);
                    var ghost = CandyCatalog.Get(piece.type, piece.variantId);
                    if (ghost != null && ghost.ghostSlide)
                    {
                        AddDiagonalSlide(piece, moves, 2);
                    }
                    break;

                case PieceType.Bishop:
                    AddSlidingMoves(piece, moves, true, false);
                    break;

                case PieceType.Rook:
                    AddSlidingMoves(piece, moves, false, true);
                    break;

                case PieceType.Queen:
                    AddSlidingMoves(piece, moves, true, true);
                    break;

                case PieceType.King:
                    AddKingMoves(piece, moves);
                    break;
            }

            return moves;
        }

        public bool HasAnyLegalMove(TeamColor side)
        {
            var pieces = GetPieces(side);
            for (int i = 0; i < pieces.Count; i++)
            {
                if (GetLegalMoves(pieces[i]).Count > 0) return true;
            }
            return false;
        }

        /// <summary>
        /// ¿La casilla (row,col) está cubierta por alguna pieza de <paramref name="attacker"/>?
        /// Se usa para que el bot no regale piezas. El objetivo se evalúa como si
        /// estuviera ocupado por <paramref name="target"/>.
        /// </summary>
        public bool IsAttackedBy(TeamColor attacker, int row, int col, CandyPiece target)
        {
            foreach (var pair in _pieces)
            {
                var piece = pair.Value;
                if (piece == null || piece.side != attacker) continue;
                if (piece.row == row && piece.col == col) continue;

                switch (piece.type)
                {
                    case PieceType.Pawn:
                    {
                        int dir = piece.side == TeamColor.White ? 1 : -1;
                        if (row == piece.row + dir && Mathf.Abs(col - piece.col) == 1)
                        {
                            var targetVariant = target != null
                                ? CandyCatalog.Get(target.type, target.variantId)
                                : null;
                            if (targetVariant == null || !targetVariant.skeletonGuard)
                                return true;
                        }
                        break;
                    }

                    case PieceType.Knight:
                        if (IsKnightOffset(row - piece.row, col - piece.col)) return true;
                        {
                            var variant = CandyCatalog.Get(piece.type, piece.variantId);
                            if (variant != null && variant.ghostSlide && SlideHits(piece, row, col, true, false, 2))
                                return true;
                        }
                        break;

                    case PieceType.Bishop:
                        if (SlideHits(piece, row, col, true, false, Size)) return true;
                        break;

                    case PieceType.Rook:
                        if (SlideHits(piece, row, col, false, true, Size)) return true;
                        break;

                    case PieceType.Queen:
                        if (SlideHits(piece, row, col, true, true, Size)) return true;
                        break;

                    case PieceType.King:
                        if (Mathf.Abs(row - piece.row) <= 1 && Mathf.Abs(col - piece.col) <= 1) return true;
                        break;
                }
            }
            return false;
        }

        private void AddPawnMoves(CandyPiece piece, List<Vector2IntCustom> moves)
        {
            int dir = piece.side == TeamColor.White ? 1 : -1;
            int row = piece.row;
            int col = piece.col;

            int forward = row + dir;
            if (IsValidSquare(forward, col) && _grid[forward, col] == null)
                AddMove(moves, forward, col);

            var variant = CandyCatalog.Get(piece.type, piece.variantId);
            for (int dc = -1; dc <= 1; dc += 2)
            {
                int rr = row + dir;
                int cc = col + dc;
                if (!IsValidSquare(rr, cc)) continue;

                var target = _grid[rr, cc];
                if (target != null)
                {
                    if (target.side == piece.side) continue;
                    var targetVariant = CandyCatalog.Get(target.type, target.variantId);
                    if (targetVariant != null && targetVariant.skeletonGuard) continue;
                    AddMove(moves, rr, cc);
                }
                else if (variant != null && variant.spiderStep)
                {
                    AddMove(moves, rr, cc);
                }
            }
        }

        private void AddKnightMoves(CandyPiece piece, List<Vector2IntCustom> moves)
        {
            int[] dr = { 2, 2, -2, -2, 1, 1, -1, -1 };
            int[] dc = { 1, -1, 1, -1, 2, -2, 2, -2 };

            for (int i = 0; i < dr.Length; i++)
            {
                int rr = piece.row + dr[i];
                int cc = piece.col + dc[i];
                if (CanLand(piece, rr, cc)) AddMove(moves, rr, cc);
            }
        }

        private void AddDiagonalSlide(CandyPiece piece, List<Vector2IntCustom> moves, int maxSteps)
        {
            int[] dr = { 1, 1, -1, -1 };
            int[] dc = { 1, -1, 1, -1 };

            for (int i = 0; i < dr.Length; i++)
            {
                for (int step = 1; step <= maxSteps; step++)
                {
                    int rr = piece.row + dr[i] * step;
                    int cc = piece.col + dc[i] * step;
                    if (!IsValidSquare(rr, cc)) break;

                    var target = _grid[rr, cc];
                    if (target == null)
                    {
                        AddMove(moves, rr, cc);
                        if (_candies[rr, cc] > 0) break;
                        continue;
                    }

                    if (target.side != piece.side) AddMove(moves, rr, cc);
                    break;
                }
            }
        }

        private void AddSlidingMoves(CandyPiece piece, List<Vector2IntCustom> moves, bool diagonals, bool orthogonals)
        {
            if (diagonals)
            {
                AddDirection(piece, moves, 1, 1);
                AddDirection(piece, moves, 1, -1);
                AddDirection(piece, moves, -1, 1);
                AddDirection(piece, moves, -1, -1);
            }
            if (orthogonals)
            {
                AddDirection(piece, moves, 1, 0);
                AddDirection(piece, moves, -1, 0);
                AddDirection(piece, moves, 0, 1);
                AddDirection(piece, moves, 0, -1);
            }
        }

        private void AddDirection(CandyPiece piece, List<Vector2IntCustom> moves, int dr, int dc)
        {
            int rr = piece.row + dr;
            int cc = piece.col + dc;
            while (IsValidSquare(rr, cc))
            {
                var target = _grid[rr, cc];
                if (target == null)
                {
                    AddMove(moves, rr, cc);

                    // El dulce se puede comer pisándolo, pero frena el
                    // deslizamiento: no se atraviesa para capturar más atrás.
                    if (_candies[rr, cc] > 0) break;
                }
                else
                {
                    if (target.side != piece.side) AddMove(moves, rr, cc);
                    break;
                }
                rr += dr;
                cc += dc;
            }
        }

        private void AddKingMoves(CandyPiece piece, List<Vector2IntCustom> moves)
        {
            for (int dr = -1; dr <= 1; dr++)
            {
                for (int dc = -1; dc <= 1; dc++)
                {
                    if (dr == 0 && dc == 0) continue;
                    int rr = piece.row + dr;
                    int cc = piece.col + dc;
                    if (CanLand(piece, rr, cc)) AddMove(moves, rr, cc);
                }
            }
        }

        private bool CanLand(CandyPiece piece, int row, int col)
        {
            if (!IsValidSquare(row, col)) return false;
            var target = _grid[row, col];
            return target == null || target.side != piece.side;
        }

        private static void AddMove(List<Vector2IntCustom> moves, int row, int col)
        {
            for (int i = 0; i < moves.Count; i++)
            {
                if (moves[i].Row == row && moves[i].Col == col) return;
            }
            moves.Add(new Vector2IntCustom(row, col));
        }

        private static bool ContainsMove(List<Vector2IntCustom> moves, int row, int col)
        {
            for (int i = 0; i < moves.Count; i++)
            {
                if (moves[i].Row == row && moves[i].Col == col) return true;
            }
            return false;
        }

        private bool SlideHits(CandyPiece piece, int targetRow, int targetCol, bool diagonals, bool orthogonals, int maxSteps)
        {
            if (diagonals && ScanAttack(piece, targetRow, targetCol, 1, 1, maxSteps)) return true;
            if (diagonals && ScanAttack(piece, targetRow, targetCol, 1, -1, maxSteps)) return true;
            if (diagonals && ScanAttack(piece, targetRow, targetCol, -1, 1, maxSteps)) return true;
            if (diagonals && ScanAttack(piece, targetRow, targetCol, -1, -1, maxSteps)) return true;
            if (orthogonals && ScanAttack(piece, targetRow, targetCol, 1, 0, maxSteps)) return true;
            if (orthogonals && ScanAttack(piece, targetRow, targetCol, -1, 0, maxSteps)) return true;
            if (orthogonals && ScanAttack(piece, targetRow, targetCol, 0, 1, maxSteps)) return true;
            if (orthogonals && ScanAttack(piece, targetRow, targetCol, 0, -1, maxSteps)) return true;
            return false;
        }

        private bool ScanAttack(CandyPiece piece, int targetRow, int targetCol, int dr, int dc, int maxSteps)
        {
            int rr = piece.row + dr;
            int cc = piece.col + dc;
            for (int step = 0; step < maxSteps && IsValidSquare(rr, cc); step++)
            {
                if (rr == targetRow && cc == targetCol) return true;
                if (_grid[rr, cc] != null) return false;

                // Los dulces también tapan la línea de ataque: la pieza de
                // atrás queda protegida hasta que alguien recoja el dulce.
                if (_candies[rr, cc] > 0) return false;
                rr += dr;
                cc += dc;
            }
            return false;
        }

        private static bool IsKnightOffset(int dr, int dc)
        {
            int adr = Mathf.Abs(dr);
            int adc = Mathf.Abs(dc);
            return (adr == 2 && adc == 1) || (adr == 1 && adc == 2);
        }

        private static bool IsPromotionRow(TeamColor side, int row)
        {
            return side == TeamColor.White ? row == Size - 1 : row == 0;
        }

        private int CollectCandy(TeamColor side, int row, int col)
        {
            if (!IsValidSquare(row, col)) return 0;
            int value = _candies[row, col];
            if (value <= 0) return 0;
            _candies[row, col] = 0;
            return value;
        }

        private void AddScore(TeamColor side, int amount)
        {
            if (amount <= 0) return;
            if (side == TeamColor.White) WhiteScore += amount;
            else BlackScore += amount;
        }

        private void EndTurn()
        {
            DeployedThisTurn = false;
            _summonedPieceId = 0;
            CurrentSide = CurrentSide == TeamColor.White ? TeamColor.Black : TeamColor.White;
        }

        private void SpawnCandies(int count)
        {
            if (_rng == null || count <= 0) return;

            for (int i = 0; i < count; i++)
            {
                if (CountCandies() >= CandyCatalog.MaxCandies) return;

                var empties = new List<Vector2IntCustom>();
                for (int r = 0; r < Size; r++)
                {
                    for (int c = 0; c < Size; c++)
                    {
                        if (_grid[r, c] == null && _candies[r, c] == 0)
                            empties.Add(new Vector2IntCustom(r, c));
                    }
                }

                if (empties.Count == 0) return;
                var cell = empties[_rng.Next(empties.Count)];
                int roll = _rng.Next(100);
                _candies[cell.Row, cell.Col] = roll < 55 ? 1 : (roll < 85 ? 2 : 3);
            }
        }

        private int CountCandies()
        {
            int count = 0;
            for (int r = 0; r < Size; r++)
            {
                for (int c = 0; c < Size; c++)
                {
                    if (_candies[r, c] > 0) count++;
                }
            }
            return count;
        }

        private static int Index(TeamColor side) => side == TeamColor.White ? 0 : 1;
    }
}
