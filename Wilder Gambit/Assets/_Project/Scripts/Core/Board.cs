using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    public class Board : MonoBehaviour
    {
        public const int BOARD_SIZE = 8;
        private ChessPiece[,] grid = new ChessPiece[BOARD_SIZE, BOARD_SIZE];

        public bool IsValidSquare(int row, int col)
        {
            return row >= 0 && row < BOARD_SIZE && col >= 0 && col < BOARD_SIZE;
        }

        public ChessPiece GetPieceAt(Vector2IntCustom pos)
        {
            if (!IsValidSquare(pos.Row, pos.Col)) return null;
            return grid[pos.Row, pos.Col];
        }

        public void SetPieceAt(Vector2IntCustom pos, ChessPiece piece)
        {
            if (IsValidSquare(pos.Row, pos.Col))
            {
                grid[pos.Row, pos.Col] = piece;
                if (piece != null)
                {
                    piece.Position = pos;
                }
            }
        }

        public ChessPiece MovePiece(Vector2IntCustom from, Vector2IntCustom to)
        {
            ChessPiece movingPiece = GetPieceAt(from);
            ChessPiece targetPiece = GetPieceAt(to);

            // Dama Jinete (pasiva «Cabalgada»): si el destino solo era alcanzable
            // por el salto, se consume el único uso de la partida. Se evalúa ANTES
            // de mover (tablero previo). Las simulaciones (WouldBeInCheck & co.)
            // no pasan por aquí: usan SimulateMove manual, así que un jaque
            // hipotético jamás gasta la Cabalgada de verdad.
            bool riderRide = movingPiece is WilderGambit.Pieces.RiderQueen rider
                && rider.RideAvailable
                && WilderGambit.Pieces.RiderQueen.IsRideDestination(this, from, to);

            if (movingPiece != null)
            {
                // Manejar movimiento de Torre en el Enroque
                if (movingPiece.Type == PieceType.King && Mathf.Abs(to.Col - from.Col) == 2)
                {
                    int row = from.Row;
                    if (to.Col == 6) // Enroque Corto
                    {
                        ChessPiece rook = GetPieceAt(new Vector2IntCustom(row, 7));
                        grid[row, 7] = null;
                        grid[row, 5] = rook;
                        if (rook != null) { rook.Position = new Vector2IntCustom(row, 5); rook.HasMoved = true; }
                    }
                    else if (to.Col == 2) // Enroque Largo
                    {
                        ChessPiece rook = GetPieceAt(new Vector2IntCustom(row, 0));
                        grid[row, 0] = null;
                        grid[row, 3] = rook;
                        if (rook != null) { rook.Position = new Vector2IntCustom(row, 3); rook.HasMoved = true; }
                    }
                }

                grid[from.Row, from.Col] = null;
                grid[to.Row, to.Col] = movingPiece;
                movingPiece.Position = to;
                movingPiece.HasMoved = true;

                if (riderRide)
                    ((WilderGambit.Pieces.RiderQueen)movingPiece).ConsumeRide();
            }

            return targetPiece; // Retorna la pieza capturada (si hubo alguna)
        }

        public Vector2IntCustom FindKing(TeamColor team)
        {
            for (int r = 0; r < BOARD_SIZE; r++)
            {
                for (int c = 0; c < BOARD_SIZE; c++)
                {
                    ChessPiece p = grid[r, c];
                    if (p != null && p.Type == PieceType.King && p.Team == team)
                        return new Vector2IntCustom(r, c);
                }
            }
            return new Vector2IntCustom(-1, -1);
        }

        public bool IsSquareAttacked(Vector2IntCustom targetPos, TeamColor friendlyTeam)
        {
            TeamColor enemyTeam = (friendlyTeam == TeamColor.White) ? TeamColor.Black : TeamColor.White;

            for (int r = 0; r < BOARD_SIZE; r++)
            {
                for (int c = 0; c < BOARD_SIZE; c++)
                {
                    ChessPiece p = grid[r, c];
                    if (p != null && p.Team == enemyTeam)
                    {
                        // 1. Peones: atacantes en diagonal directa
                        if (p.Type == PieceType.Pawn)
                        {
                            int dir = (p.Team == TeamColor.White) ? 1 : -1;
                            if (p.Position.Row + dir == targetPos.Row &&
                                (p.Position.Col - 1 == targetPos.Col || p.Position.Col + 1 == targetPos.Col))
                            {
                                return true;
                            }
                            // Peón Lancero (pasiva «Lanza»): además ataca la casilla frontal
                            if (p is WilderGambit.Pieces.LancerPawn &&
                                p.Position.Row + dir == targetPos.Row &&
                                p.Position.Col == targetPos.Col)
                            {
                                return true;
                            }
                        }
                        // 2. Reyes enemigos: casillas adyacentes directas (Evita llamada recursiva a King.GetValidMoves)
                        else if (p.Type == PieceType.King)
                        {
                            int dRow = Mathf.Abs(p.Position.Row - targetPos.Row);
                            int dCol = Mathf.Abs(p.Position.Col - targetPos.Col);
                            if (dRow <= 1 && dCol <= 1)
                            {
                                return true;
                            }
                        }
                        // 3. Demás piezas (Torre, Alfil, Caballo, Reina)
                        else
                        {
                            List<Vector2IntCustom> moves = p.GetValidMoves(this);
                            if (moves.Contains(targetPos))
                                return true;
                        }
                    }
                }
            }
            return false;
        }

        public bool IsInCheck(TeamColor team)
        {
            Vector2IntCustom kingPos = FindKing(team);
            if (kingPos.Row == -1) return false;
            return IsSquareAttacked(kingPos, team);
        }

        /// <summary>Datos para deshacer una jugada simulada.</summary>
        private struct SimulatedMove
        {
            public ChessPiece piece;
            public ChessPiece captured;
            public ChessPiece castleRook;
            public Vector2IntCustom from;
            public Vector2IntCustom to;
            public Vector2IntCustom rookFrom;
            public Vector2IntCustom rookTo;
            public bool pieceHadMoved;
            public bool rookHadMoved;
        }

        /// <summary>Mueve la pieza en el tablero lógico sin tocar vistas (para pruebas de reglas).</summary>
        private SimulatedMove SimulateMove(ChessPiece piece, Vector2IntCustom to)
        {
            var sim = new SimulatedMove
            {
                piece = piece,
                captured = GetPieceAt(to),
                from = piece.Position,
                to = to,
                pieceHadMoved = piece.HasMoved,
                rookFrom = new Vector2IntCustom(-1, -1),
                rookTo = new Vector2IntCustom(-1, -1),
            };

            Vector2IntCustom from = sim.from;

            // Manejar simulación de torre para enroque
            if (piece.Type == PieceType.King && Mathf.Abs(to.Col - from.Col) == 2)
            {
                int row = from.Row;
                if (to.Col == 6)
                {
                    sim.rookFrom = new Vector2IntCustom(row, 7);
                    sim.rookTo = new Vector2IntCustom(row, 5);
                }
                else if (to.Col == 2)
                {
                    sim.rookFrom = new Vector2IntCustom(row, 0);
                    sim.rookTo = new Vector2IntCustom(row, 3);
                }

                sim.castleRook = GetPieceAt(sim.rookFrom);
                if (sim.castleRook != null)
                {
                    sim.rookHadMoved = sim.castleRook.HasMoved;
                    grid[sim.rookFrom.Row, sim.rookFrom.Col] = null;
                    grid[sim.rookTo.Row, sim.rookTo.Col] = sim.castleRook;
                    sim.castleRook.Position = sim.rookTo;
                    sim.castleRook.HasMoved = true;
                }
            }

            grid[from.Row, from.Col] = null;
            grid[to.Row, to.Col] = piece;
            piece.Position = to;
            piece.HasMoved = true;

            return sim;
        }

        /// <summary>Devuelve el tablero al estado previo a una jugada simulada.</summary>
        private void UndoSimulatedMove(SimulatedMove sim)
        {
            grid[sim.from.Row, sim.from.Col] = sim.piece;
            grid[sim.to.Row, sim.to.Col] = sim.captured;
            sim.piece.Position = sim.from;
            sim.piece.HasMoved = sim.pieceHadMoved;

            if (sim.castleRook != null)
            {
                grid[sim.rookTo.Row, sim.rookTo.Col] = null;
                grid[sim.rookFrom.Row, sim.rookFrom.Col] = sim.castleRook;
                sim.castleRook.Position = sim.rookFrom;
                sim.castleRook.HasMoved = sim.rookHadMoved;
            }
        }

        /// <summary>
        /// Simula mover una pieza a 'to' y devuelve true si el Rey propio quedaría en jaque.
        /// </summary>
        public bool WouldBeInCheck(ChessPiece piece, Vector2IntCustom to)
        {
            SimulatedMove sim = SimulateMove(piece, to);
            bool inCheck = IsInCheck(piece.Team);
            UndoSimulatedMove(sim);
            return inCheck;
        }

        /// <summary>
        /// Simula mover una pieza a 'to' y devuelve true si da JAQUE MATE al rival
        /// (queda en jaque y sin ninguna jugada legal). El tablero queda intacto.
        /// </summary>
        public bool WouldBeCheckmate(ChessPiece piece, Vector2IntCustom to)
        {
            SimulatedMove sim = SimulateMove(piece, to);
            TeamColor rival = piece.Team == TeamColor.White ? TeamColor.Black : TeamColor.White;
            bool mate = IsInCheck(rival) && !HasAnyLegalMove(rival);
            UndoSimulatedMove(sim);
            return mate;
        }

        public List<ChessPiece> GetAllPieces(TeamColor team)
        {
            List<ChessPiece> pieces = new List<ChessPiece>();
            for (int r = 0; r < BOARD_SIZE; r++)
            {
                for (int c = 0; c < BOARD_SIZE; c++)
                {
                    ChessPiece p = grid[r, c];
                    if (p != null && p.Team == team)
                        pieces.Add(p);
                }
            }
            return pieces;
        }

        public bool HasAnyLegalMove(TeamColor team)
        {
            List<ChessPiece> pieces = GetAllPieces(team);
            foreach (var piece in pieces)
            {
                if (piece.GetLegalMoves(this).Count > 0)
                    return true;
            }
            return false;
        }

        public bool IsInsufficientMaterial()
        {
            List<ChessPiece> whitePieces = GetAllPieces(TeamColor.White);
            List<ChessPiece> blackPieces = GetAllPieces(TeamColor.Black);

            // Si hay Peones, Damas o Torres, el material siempre es suficiente para dar mate
            foreach (var p in whitePieces)
            {
                if (p.Type == PieceType.Pawn || p.Type == PieceType.Queen || p.Type == PieceType.Rook) return false;
            }
            foreach (var p in blackPieces)
            {
                if (p.Type == PieceType.Pawn || p.Type == PieceType.Queen || p.Type == PieceType.Rook) return false;
            }

            // K vs K (Rey contra Rey)
            if (whitePieces.Count == 1 && blackPieces.Count == 1)
                return true;

            // K + B vs K ó K + N vs K
            if ((whitePieces.Count == 2 && blackPieces.Count == 1) || (whitePieces.Count == 1 && blackPieces.Count == 2))
                return true;

            // K + B vs K + B (Alfiles en casillas del mismo color)
            if (whitePieces.Count == 2 && blackPieces.Count == 2)
            {
                ChessPiece whiteBishop = whitePieces.Find(p => p.Type == PieceType.Bishop);
                ChessPiece blackBishop = blackPieces.Find(p => p.Type == PieceType.Bishop);
                if (whiteBishop != null && blackBishop != null)
                {
                    bool whiteSquareColor = (whiteBishop.Position.Row + whiteBishop.Position.Col) % 2 == 0;
                    bool blackSquareColor = (blackBishop.Position.Row + blackBishop.Position.Col) % 2 == 0;
                    if (whiteSquareColor == blackSquareColor)
                        return true;
                }
            }

            return false;
        }

        public void ClearBoard()
        {
            for (int r = 0; r < BOARD_SIZE; r++)
            {
                for (int c = 0; c < BOARD_SIZE; c++)
                {
                    grid[r, c] = null;
                }
            }
        }
    }
}
