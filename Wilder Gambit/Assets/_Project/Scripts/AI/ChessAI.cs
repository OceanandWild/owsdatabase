using System;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.AI
{
    public class ChessAI : MonoBehaviour
    {
        public static ChessAI Instance { get; private set; }

        private AIConfig config;
        private System.Random rng = new System.Random();

        // Registro de historial de movimientos en notación String ("row,col->row,col")
        private List<string> moveHistory = new List<string>();

        // Zobrist Transposition Table Cache
        private Dictionary<long, (int depth, float score, Vector2IntCustom from, Vector2IntCustom to)> transTable =
            new Dictionary<long, (int, float, Vector2IntCustom, Vector2IntCustom)>();

        // Piece-Square Tables (PST) para evaluación posicional
        #region PST Tables
        private static readonly float[,] PawnPST = new float[8, 8] {
            { 0,  0,  0,  0,  0,  0,  0,  0 },
            { 5,  5,  5,  5,  5,  5,  5,  5 },
            { 1,  1,  2,  3,  3,  2,  1,  1 },
            { 0.5f, 0.5f, 1, 2.5f, 2.5f, 1, 0.5f, 0.5f },
            { 0,  0,  0, 2, 2,  0,  0,  0 },
            { 0.5f, -0.5f, -1, 0, 0, -1, -0.5f, 0.5f },
            { 0.5f, 1, 1, -2, -2, 1, 1, 0.5f },
            { 0,  0,  0,  0,  0,  0,  0,  0 }
        };

        private static readonly float[,] KnightPST = new float[8, 8] {
            { -5, -4, -3, -3, -3, -3, -4, -5 },
            { -4, -2,  0,  0,  0,  0, -2, -4 },
            { -3,  0,  1, 1.5f, 1.5f, 1, 0, -3 },
            { -3, 0.5f, 1.5f, 2, 2, 1.5f, 0.5f, -3 },
            { -3,  0, 1.5f, 2, 2, 1.5f,  0, -3 },
            { -3, 0.5f,  1, 1.5f, 1.5f, 1, 0.5f, -3 },
            { -4, -2,  0, 0.5f, 0.5f, 0, -2, -4 },
            { -5, -4, -3, -3, -3, -3, -4, -5 }
        };

        private static readonly float[,] BishopPST = new float[8, 8] {
            { -2, -1, -1, -1, -1, -1, -1, -2 },
            { -1,  0,  0,  0,  0,  0,  0, -1 },
            { -1,  0, 0.5f, 1, 1, 0.5f, 0, -1 },
            { -1, 0.5f, 0.5f, 1, 1, 0.5f, 0.5f, -1 },
            { -1,  0,  1,  1,  1,  1,  0, -1 },
            { -1,  1,  1,  1,  1,  1,  1, -1 },
            { -1, 0.5f,  0,  0,  0,  0, 0.5f, -1 },
            { -2, -1, -1, -1, -1, -1, -1, -2 }
        };

        private static readonly float[,] KingPST = new float[8, 8] {
            { -3, -4, -4, -5, -5, -4, -4, -3 },
            { -3, -4, -4, -5, -5, -4, -4, -3 },
            { -3, -4, -4, -5, -5, -4, -4, -3 },
            { -3, -4, -4, -5, -5, -4, -4, -3 },
            { -2, -3, -3, -4, -4, -3, -3, -2 },
            { -1, -2, -2, -2, -2, -2, -2, -1 },
            {  2,  2,  0,  0,  0,  0,  2,  2 },
            {  2,  3,  1,  0,  0,  1,  3,  2 }
        };

        private static readonly float[,] RookPST = new float[8, 8] {
            {  0,  0,  0,  0.5f,  0.5f,  0,  0,  0 },
            {  0.5f,  1,  1,  1,  1,  1,  1,  0.5f },
            { -0.5f,  0,  0,  0,  0,  0,  0, -0.5f },
            { -0.5f,  0,  0,  0,  0,  0,  0, -0.5f },
            { -0.5f,  0,  0,  0,  0,  0,  0, -0.5f },
            { -0.5f,  0,  0,  0,  0,  0,  0, -0.5f },
            { -0.5f,  0,  0,  0,  0,  0,  0, -0.5f },
            {  0,  0,  0,  0.5f,  0.5f,  0,  0,  0 }
        };

        private static readonly float[,] QueenPST = new float[8, 8] {
            { -2, -1, -1, -0.5f, -0.5f, -1, -1, -2 },
            { -1,  0,  0,  0,  0,  0,  0, -1 },
            { -1,  0,  0.5f,  0.5f,  0.5f,  0.5f,  0, -1 },
            { -0.5f,  0,  0.5f,  0.5f,  0.5f,  0.5f,  0, -0.5f },
            {  0,  0,  0.5f,  0.5f,  0.5f,  0.5f,  0, -0.5f },
            { -1,  0.5f,  0.5f,  0.5f,  0.5f,  0.5f,  0, -1 },
            { -1,  0,  0.5f,  0,  0,  0,  0, -1 },
            { -2, -1, -1, -0.5f, -0.5f, -1, -1, -2 }
        };
        #endregion

        private void Awake()
        {
            if (Instance == null) Instance = this;
            else Destroy(gameObject);
        }

        public void SetDifficulty(DifficultyLevel level)
        {
            config = AIDifficultyPresets.GetConfig(level);
            moveHistory.Clear();
            transTable.Clear();
            Debug.Log($"IA configurada en Dificultad: {config.name}");
        }

        public void RecordMove(Vector2IntCustom from, Vector2IntCustom to)
        {
            moveHistory.Add($"{from.Row},{from.Col}->{to.Row},{to.Col}");
        }

        public (Vector2IntCustom from, Vector2IntCustom to) GetBestMove(Board board)
        {
            if (config == null) SetDifficulty(DifficultyLevel.Master);

            // 1. Intentar movimiento desde el Libro de Aperturas
            if (config.useOpeningBook && OpeningBook.TryGetBookMove(moveHistory, out Vector2IntCustom bFrom, out Vector2IntCustom bTo))
            {
                // Validar que el movimiento del libro es legal en el tablero actual
                ChessPiece p = board.GetPieceAt(bFrom);
                if (p != null && p.Team == TeamColor.Black && p.GetLegalMoves(board).Contains(bTo))
                {
                    Debug.Log($"IA ({config.level}): Jugando movimiento de Apertura ({bFrom.Row},{bFrom.Col} -> {bTo.Row},{bTo.Col})");
                    return (bFrom, bTo);
                }
            }

            // 2. Comportamiento especial: Blunder de Reina (Dificultades bajas y 5% en Master)
            if (config.blunderQueenChance > 0f && (float)rng.NextDouble() < config.blunderQueenChance)
            {
                var blunder = TryGetQueenBlunderMove(board);
                if (blunder.hasMove)
                {
                    Debug.Log($"IA ({config.level}): ¡Cometiendo descuido de Reina impulsivo!");
                    return (blunder.from, blunder.to);
                }
            }

            // 3. Remate inmediato: Master y GrandMaster miran el mate en 1 antes de buscar
            if (config.doubleThreatCounterSkill >= 1)
            {
                // Verificar si hay amenaza a la Reina + otra pieza
                var (isThreatened, queenPos) = CheckQueenDoubleThreat(board, TeamColor.Black);
                if (isThreatened)
                {
                    // Buscar si hay una línea táctica de Jaque Mate silencioso rápido antes de defender la reina
                    var mateMove = FindSilentCheckmate(board, TeamColor.Black);
                    if (mateMove.hasMove)
                    {
                        Debug.Log("IA (GrandMaster): ¡Ignorando la doble amenaza a la reina para asestar JAQUE MATE TRAMPA!");
                        return (mateMove.from, mateMove.to);
                    }
                }
            }

            // 4. Búsqueda Principal Minimax Alpha-Beta
            (Vector2IntCustom bestFrom, Vector2IntCustom bestTo) bestMoveOverall = (new Vector2IntCustom(-1, -1), new Vector2IntCustom(-1, -1));
            float bestValOverall = -999999f;
            float alpha = -999999f;
            float beta = 999999f;

            List<(ChessPiece piece, Vector2IntCustom move)> allMoves = GetAllLegalMovesSorted(board, TeamColor.Black);

            foreach (var (piece, move) in allMoves)
            {
                Vector2IntCustom fromPos = piece.Position;

                // Simular movimiento
                ChessPiece captured = SimulateBoardMove(board, piece, fromPos, move, out MoveUndo undo);
                float eval = Minimax(board, config.maxDepth - 1, alpha, beta, false);
                // Revertir simulación
                RevertBoardMove(board, piece, fromPos, move, captured, undo);

                if (eval > bestValOverall)
                {
                    bestValOverall = eval;
                    bestMoveOverall = (fromPos, move);
                }
                alpha = Mathf.Max(alpha, eval);
            }

            return bestMoveOverall;
        }

        private float Minimax(Board board, int depth, float alpha, float beta, bool isMaximizing)
        {
            if (depth == 0)
            {
                if (config.useQuiescence)
                    return QuiescenceSearch(board, alpha, beta, isMaximizing);
                return EvaluateBoard(board);
            }

            TeamColor currentTeam = isMaximizing ? TeamColor.Black : TeamColor.White;
            long hash = 0L;
            Vector2IntCustom ttFrom = new Vector2IntCustom(-1, -1);
            Vector2IntCustom ttTo = new Vector2IntCustom(-1, -1);
            bool hasTtMove = false;
            if (config.useTranspositionTable)
            {
                hash = ComputeBoardHash(board, isMaximizing);
                if (transTable.TryGetValue(hash, out var entry) && entry.depth >= depth)
                    return entry.score; // Corte por transposición
                if (transTable.TryGetValue(hash, out var hint) && hint.depth > 0)
                {
                    ttFrom = hint.from;
                    ttTo = hint.to;
                    hasTtMove = true;
                }
            }

            List<(ChessPiece piece, Vector2IntCustom move)> moves = GetAllLegalMovesSorted(board, currentTeam, ttFrom, ttTo, hasTtMove);

            if (moves.Count == 0)
            {
                if (board.IsInCheck(currentTeam))
                    return isMaximizing ? -100000f - depth : 100000f + depth; // Jaque Mate
                return 0f; // Tablas
            }

            Vector2IntCustom bestFrom = new Vector2IntCustom(-1, -1);
            Vector2IntCustom bestTo = new Vector2IntCustom(-1, -1);

            if (isMaximizing)
            {
                float maxEval = -999999f;
                foreach (var (piece, move) in moves)
                {
                    Vector2IntCustom fromPos = piece.Position;
                    ChessPiece captured = SimulateBoardMove(board, piece, fromPos, move, out MoveUndo undo);
                    float eval = Minimax(board, depth - 1, alpha, beta, false);
                    RevertBoardMove(board, piece, fromPos, move, captured, undo);

                    if (eval > maxEval)
                    {
                        maxEval = eval;
                        bestFrom = fromPos;
                        bestTo = move;
                    }
                    alpha = Mathf.Max(alpha, eval);
                    if (beta <= alpha) break; // Poda Alpha-Beta
                }
                if (config.useTranspositionTable)
                    transTable[hash] = (depth, maxEval, bestFrom, bestTo);
                return maxEval;
            }
            else
            {
                float minEval = 999999f;
                foreach (var (piece, move) in moves)
                {
                    Vector2IntCustom fromPos = piece.Position;
                    ChessPiece captured = SimulateBoardMove(board, piece, fromPos, move, out MoveUndo undo);
                    float eval = Minimax(board, depth - 1, alpha, beta, true);
                    RevertBoardMove(board, piece, fromPos, move, captured, undo);

                    if (eval < minEval)
                    {
                        minEval = eval;
                        bestFrom = fromPos;
                        bestTo = move;
                    }
                    beta = Mathf.Min(beta, eval);
                    if (beta <= alpha) break; // Poda Alpha-Beta
                }
                if (config.useTranspositionTable)
                    transTable[hash] = (depth, minEval, bestFrom, bestTo);
                return minEval;
            }
        }

        private float QuiescenceSearch(Board board, float alpha, float beta, bool isMaximizing, int qDepth = 0)
        {
            float standPat = EvaluateBoard(board);
            if (qDepth >= 2) return standPat;

            if (isMaximizing)
            {
                if (standPat >= beta) return beta;
                if (standPat > alpha) alpha = standPat;
            }
            else
            {
                if (standPat <= alpha) return alpha;
                if (standPat < beta) beta = standPat;
            }

            TeamColor currentTeam = isMaximizing ? TeamColor.Black : TeamColor.White;
            List<(ChessPiece piece, Vector2IntCustom move)> moves = GetAllCapturesSorted(board, currentTeam);

            foreach (var (piece, move) in moves)
            {
                Vector2IntCustom fromPos = piece.Position;
                ChessPiece victim = board.GetPieceAt(move);
                // Poda delta: ni capturando la pieza se alcanza alpha/beta (+margen de 25)
                float captureValue = victim != null ? GetPieceValue(victim.Type) : 0f;
                if (isMaximizing && standPat + captureValue + 25f < alpha) continue;
                if (!isMaximizing && standPat - captureValue - 25f > beta) continue;

                ChessPiece captured = SimulateBoardMove(board, piece, fromPos, move, out MoveUndo undo);
                float score = QuiescenceSearch(board, alpha, beta, !isMaximizing, qDepth + 1);
                RevertBoardMove(board, piece, fromPos, move, captured, undo);

                if (isMaximizing)
                {
                    if (score >= beta) return beta;
                    if (score > alpha) alpha = score;
                }
                else
                {
                    if (score <= alpha) return alpha;
                    if (score < beta) beta = score;
                }
            }

            return isMaximizing ? alpha : beta;
        }

        // ── Evaluador Posicional Avanzado ─────────────────────────────────────
        private float EvaluateBoard(Board board)
        {
            float totalScore = 0f;

            List<ChessPiece> blackPieces = board.GetAllPieces(TeamColor.Black);
            List<ChessPiece> whitePieces = board.GetAllPieces(TeamColor.White);

            // Material & PST
            foreach (var p in blackPieces)
            {
                totalScore += GetPieceValue(p.Type);
                if (config.usePST) totalScore += GetPSTValue(p, true);
            }
            foreach (var p in whitePieces)
            {
                totalScore -= GetPieceValue(p.Type);
                if (config.usePST) totalScore -= GetPSTValue(p, false);
            }

            // Par de alfiles: bonus por conservar ambos alfiles
            int blackBishops = 0, whiteBishops = 0;
            foreach (var p in blackPieces)
                if (p.Type == PieceType.Bishop || p.Type == PieceType.NecromancerBishop) blackBishops++;
            foreach (var p in whitePieces)
                if (p.Type == PieceType.Bishop || p.Type == PieceType.NecromancerBishop) whiteBishops++;
            if (blackBishops >= 2) totalScore += 3f;
            if (whiteBishops >= 2) totalScore -= 3f;

            // Peones avanzados / amenaza de coronación (la simulación no promociona,
            // así que el peón en 7ª/8ª valdría solo 10 sin este bonus)
            foreach (var p in blackPieces)
            {
                if (p.Type == PieceType.Pawn)
                {
                    if (p.Position.Row <= 1) totalScore += 15f;       // a punto de coronar
                    else if (p.Position.Row <= 3) totalScore += 4f;   // peón pasado/avanzado
                }
            }
            foreach (var p in whitePieces)
            {
                if (p.Type == PieceType.Pawn)
                {
                    if (p.Position.Row >= 6) totalScore -= 15f;
                    else if (p.Position.Row >= 4) totalScore -= 4f;
                }
            }

            // Escudo de peones del rey (barato: peones propios adyacentes al rey)
            totalScore += CountKingShield(board, TeamColor.Black) * 1.5f;
            totalScore -= CountKingShield(board, TeamColor.White) * 1.5f;

            // Agresividad y Ataque al Rey (Niveles 3, 4, 5)
            // Peso reducido (0.2): con 0.8 dominaba al material (~160 pts) y la IA
            // sacrificaba piezas solo por acercarse al rey. Solo piezas con ataque real.
            if (config.aggressiveStyle)
            {
                Vector2IntCustom whiteKingPos = board.FindKing(TeamColor.White);
                if (whiteKingPos.Row != -1)
                {
                    foreach (var p in blackPieces)
                    {
                        if (p.Type == PieceType.Pawn || p.Type == PieceType.King) continue;
                        int dist = Mathf.Abs(p.Position.Row - whiteKingPos.Row) + Mathf.Abs(p.Position.Col - whiteKingPos.Col);
                        totalScore += (14 - dist) * 0.2f;
                    }
                }
            }

            return totalScore;
        }

        private float GetPieceValue(PieceType type)
        {
            switch (type)
            {
                case PieceType.Pawn: return 10f;
                case PieceType.Knight: return 30f;
                case PieceType.Bishop:
                case PieceType.NecromancerBishop: return 32f;
                case PieceType.Rook: return 50f;
                case PieceType.Queen: return 90f;
                case PieceType.King: return 1000f;
                default: return 0f;
            }
        }

        private float GetPSTValue(ChessPiece piece, bool isBlack)
        {
            int r = isBlack ? piece.Position.Row : 7 - piece.Position.Row;
            int c = piece.Position.Col;

            switch (piece.Type)
            {
                case PieceType.Pawn: return PawnPST[r, c];
                case PieceType.Knight: return KnightPST[r, c];
                case PieceType.Bishop:
                case PieceType.NecromancerBishop: return BishopPST[r, c];
                case PieceType.Rook: return RookPST[r, c];
                case PieceType.Queen: return QueenPST[r, c];
                case PieceType.King: return KingPST[r, c];
                default: return 0f;
            }
        }

        /// <summary>Peones propios en las 3 casillas delanteras + laterales del rey.</summary>
        private int CountKingShield(Board board, TeamColor team)
        {
            Vector2IntCustom kingPos = board.FindKing(team);
            if (kingPos.Row == -1) return 0;
            int fwd = (team == TeamColor.White) ? 1 : -1;
            int shield = 0;
            for (int dc = -1; dc <= 1; dc++)
            {
                var sq = new Vector2IntCustom(kingPos.Row + fwd, kingPos.Col + dc);
                if (!board.IsValidSquare(sq.Row, sq.Col)) continue;
                ChessPiece p = board.GetPieceAt(sq);
                if (p != null && p.Team == team && p.Type == PieceType.Pawn) shield++;
            }
            return shield;
        }

        /// <summary>Hash rápido del tablero (para la tabla de transposición).</summary>
        private long ComputeBoardHash(Board board, bool blackToMove)
        {
            unchecked
            {
                long h = blackToMove ? unchecked((long)0x9E3779B97F4A7C15UL) : unchecked((long)0xC2B2AE3D27D4EB4FUL);
                for (int r = 0; r < Board.BOARD_SIZE; r++)
                {
                    for (int c = 0; c < Board.BOARD_SIZE; c++)
                    {
                        ChessPiece p = board.GetPieceAt(new Vector2IntCustom(r, c));
                        if (p == null) continue;
                        long code = ((long)(int)p.Type * 2L + (p.Team == TeamColor.Black ? 1L : 0L)) * 64L + (r * 8L + c);
                        h ^= code + unchecked((long)0x9E3779B97F4A7C15UL) + (h << 6) + (h >> 2);
                    }
                }
                return h;
            }
        }

        private struct MoveUndo
        {
            public bool pieceHadMoved;
            public bool rideConsumed;
            public ChessPiece castleRook;
            public Vector2IntCustom rookFrom;
            public Vector2IntCustom rookTo;
            public bool rookHadMoved;
        }

        /// <summary>
        /// Simula un movimiento guardando todo lo que RevertMove necesita restaurar
        /// (HasMoved, enroque de torre y Cabalgada de Dama Jinete de un solo uso).
        /// Sin esto la búsqueda corrompía el tablero real.
        /// </summary>
        private ChessPiece SimulateBoardMove(Board board, ChessPiece piece, Vector2IntCustom from, Vector2IntCustom to, out MoveUndo undo)
        {
            undo = new MoveUndo
            {
                pieceHadMoved = piece.HasMoved,
                rookFrom = new Vector2IntCustom(-1, -1),
                rookTo = new Vector2IntCustom(-1, -1),
            };
            var rider = piece as WilderGambit.Pieces.RiderQueen;
            undo.rideConsumed = rider != null && rider.RideAvailable
                && WilderGambit.Pieces.RiderQueen.IsRideDestination(board, from, to);

            if (piece.Type == PieceType.King && Mathf.Abs(to.Col - from.Col) == 2)
            {
                int row = from.Row;
                undo.rookFrom = (to.Col == 6) ? new Vector2IntCustom(row, 7) : new Vector2IntCustom(row, 0);
                undo.rookTo = (to.Col == 6) ? new Vector2IntCustom(row, 5) : new Vector2IntCustom(row, 3);
                undo.castleRook = board.GetPieceAt(undo.rookFrom);
                if (undo.castleRook != null) undo.rookHadMoved = undo.castleRook.HasMoved;
            }

            return board.MovePiece(from, to);
        }

        private void RevertBoardMove(Board board, ChessPiece piece, Vector2IntCustom from, Vector2IntCustom to, ChessPiece captured, MoveUndo undo)
        {
            board.SetPieceAt(from, piece);
            board.SetPieceAt(to, captured);
            piece.HasMoved = undo.pieceHadMoved;
            if (undo.rideConsumed && piece is WilderGambit.Pieces.RiderQueen rider)
                rider.RideAvailable = true;
            if (undo.castleRook != null)
            {
                board.SetPieceAt(undo.rookFrom, undo.castleRook);
                // Si la torre quedó pisada en rookTo por el revert genérico, se limpia
                if (board.GetPieceAt(undo.rookTo) == undo.castleRook)
                    board.SetPieceAt(undo.rookTo, null);
                undo.castleRook.HasMoved = undo.rookHadMoved;
            }
        }

        // ── Helpers & Move Ordering ───────────────────────────────────────────
        private List<(ChessPiece piece, Vector2IntCustom move)> GetAllLegalMovesSorted(
            Board board, TeamColor team,
            Vector2IntCustom ttFrom = default, Vector2IntCustom ttTo = default, bool hasTtMove = false)
        {
            List<(ChessPiece, Vector2IntCustom)> sorted = new List<(ChessPiece, Vector2IntCustom)>();
            List<ChessPiece> pieces = board.GetAllPieces(team);

            foreach (var p in pieces)
            {
                List<Vector2IntCustom> legalMoves = p.GetLegalMoves(board);
                foreach (var m in legalMoves)
                {
                    sorted.Add((p, m));
                }
            }

            // Orden: jugada de la tabla hash primero, luego capturas MVV-LVA,
            // luego promociones de peón, luego el resto.
            sorted.Sort((a, b) => MoveOrderScore(board, a.Item1, a.Item2, ttFrom, ttTo, hasTtMove)
                .CompareTo(MoveOrderScore(board, b.Item1, b.Item2, ttFrom, ttTo, hasTtMove)) * -1);

            return sorted;
        }

        private float MoveOrderScore(Board board, ChessPiece attacker, Vector2IntCustom move,
            Vector2IntCustom ttFrom, Vector2IntCustom ttTo, bool hasTtMove)
        {
            if (hasTtMove && attacker.Position == ttFrom && move == ttTo)
                return 100000f; // La mejor jugada conocida se prueba primero (más podas)
            ChessPiece victim = board.GetPieceAt(move);
            float score = 0f;
            if (victim != null)
            {
                // MVV-LVA: víctima valiosa con atacante barato primero
                score += 1000f + GetPieceValue(victim.Type) * 10f - GetPieceValue(attacker.Type);
            }
            // Promoción de peón: bonus alto (coronar decide partidas)
            if (attacker.Type == PieceType.Pawn && (move.Row == 0 || move.Row == 7))
                score += 9000f;
            return score;
        }

        private List<(ChessPiece piece, Vector2IntCustom move)> GetAllCapturesSorted(Board board, TeamColor team)
        {
            List<(ChessPiece, Vector2IntCustom)> captures = new List<(ChessPiece, Vector2IntCustom)>();
            List<ChessPiece> pieces = board.GetAllPieces(team);

            foreach (var p in pieces)
            {
                List<Vector2IntCustom> legalMoves = p.GetLegalMoves(board);
                foreach (var m in legalMoves)
                {
                    if (board.GetPieceAt(m) != null)
                        captures.Add((p, m));
                }
            }

            // Antes se devolvían sin ordenar: la quiescencia examinaba capturas malas
            // primero y casi no podaba. Mismo orden MVV-LVA que la búsqueda principal.
            captures.Sort((a, b) => MoveOrderScore(board, a.Item1, a.Item2, default, default, false)
                .CompareTo(MoveOrderScore(board, b.Item1, b.Item2, default, default, false)) * -1);

            return captures;
        }

        private (bool hasMove, Vector2IntCustom from, Vector2IntCustom to) TryGetQueenBlunderMove(Board board)
        {
            List<ChessPiece> blackPieces = board.GetAllPieces(TeamColor.Black);
            ChessPiece queen = blackPieces.Find(p => p.Type == PieceType.Queen);
            if (queen != null)
            {
                var legalMoves = queen.GetLegalMoves(board);
                foreach (var move in legalMoves)
                {
                    // Si el movimiento la deja en una casilla atacada por el humano
                    if (board.IsSquareAttacked(move, TeamColor.Black))
                    {
                        return (true, queen.Position, move);
                    }
                }
            }
            return (false, new Vector2IntCustom(), new Vector2IntCustom());
        }

        private (bool isThreatened, Vector2IntCustom queenPos) CheckQueenDoubleThreat(Board board, TeamColor team)
        {
            List<ChessPiece> pieces = board.GetAllPieces(team);
            ChessPiece queen = pieces.Find(p => p.Type == PieceType.Queen);
            if (queen == null) return (false, new Vector2IntCustom(-1, -1));

            bool queenAttacked = board.IsSquareAttacked(queen.Position, team);
            if (queenAttacked)
            {
                // Verificar si hay OTRA pieza de valor atacada al mismo tiempo
                int attackedPiecesCount = 0;
                foreach (var p in pieces)
                {
                    if (board.IsSquareAttacked(p.Position, team)) attackedPiecesCount++;
                }

                if (attackedPiecesCount >= 2) return (true, queen.Position);
            }

            return (false, new Vector2IntCustom(-1, -1));
        }

        private (bool hasMove, Vector2IntCustom from, Vector2IntCustom to) FindSilentCheckmate(Board board, TeamColor team)
        {
            // Busca si hay una jugada en 1 paso que resulta en Jaque Mate directo
            var moves = GetAllLegalMovesSorted(board, team);
            foreach (var (piece, move) in moves)
            {
                Vector2IntCustom fromPos = piece.Position;
                ChessPiece captured = SimulateBoardMove(board, piece, fromPos, move, out MoveUndo undo);

                TeamColor enemyTeam = (team == TeamColor.White) ? TeamColor.Black : TeamColor.White;
                bool isMate = board.IsInCheck(enemyTeam) && !board.HasAnyLegalMove(enemyTeam);

                RevertBoardMove(board, piece, fromPos, move, captured, undo);

                if (isMate) return (true, fromPos, move);
            }
            return (false, new Vector2IntCustom(), new Vector2IntCustom());
        }
    }
}
