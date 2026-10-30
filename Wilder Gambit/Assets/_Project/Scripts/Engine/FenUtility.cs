using System.Text;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Engine
{
    public static class FenUtility
    {
        public static string BoardToFen(Board board, TeamColor turn, int halfmoveClock = 0, int fullmoveNumber = 1)
        {
            StringBuilder sb = new StringBuilder();

            // 1. Piece placement (from row 7 down to row 0)
            for (int r = Board.BOARD_SIZE - 1; r >= 0; r--)
            {
                int emptyCount = 0;
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    ChessPiece p = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (p == null)
                    {
                        emptyCount++;
                    }
                    else
                    {
                        if (emptyCount > 0)
                        {
                            sb.Append(emptyCount);
                            emptyCount = 0;
                        }
                        sb.Append(PieceToFenChar(p));
                    }
                }
                if (emptyCount > 0)
                {
                    sb.Append(emptyCount);
                }
                if (r > 0)
                {
                    sb.Append('/');
                }
            }

            // 2. Active color
            sb.Append(' ');
            sb.Append(turn == TeamColor.White ? 'w' : 'b');

            // 3. Castling availability
            sb.Append(' ');
            string castling = GetCastlingRights(board);
            sb.Append(string.IsNullOrEmpty(castling) ? "-" : castling);

            // 4. En passant target square
            sb.Append(' ');
            sb.Append("-");

            // 5. Halfmove clock & Fullmove number
            sb.Append(' ');
            sb.Append(halfmoveClock);
            sb.Append(' ');
            sb.Append(fullmoveNumber);

            return sb.ToString();
        }

        private static char PieceToFenChar(ChessPiece p)
        {
            char c = ' ';
            switch (p.Type)
            {
                case PieceType.Pawn:              c = 'P'; break;
                case PieceType.Knight:            c = 'N'; break;
                case PieceType.Bishop:            c = 'B'; break;
                case PieceType.NecromancerBishop: c = 'B'; break;
                case PieceType.Rook:              c = 'R'; break;
                case PieceType.Queen:             c = 'Q'; break;
                case PieceType.King:              c = 'K'; break;
            }
            return (p.Team == TeamColor.White) ? char.ToUpper(c) : char.ToLower(c);
        }

        private static string GetCastlingRights(Board board)
        {
            StringBuilder sb = new StringBuilder();

            // White King at (0, 4)
            ChessPiece whiteKing = board.GetPieceAt(new Vector2IntCustom(0, 4));
            if (whiteKing != null && whiteKing.Type == PieceType.King && whiteKing.Team == TeamColor.White && !whiteKing.HasMoved)
            {
                ChessPiece h1Rook = board.GetPieceAt(new Vector2IntCustom(0, 7));
                if (h1Rook != null && h1Rook.Type == PieceType.Rook && h1Rook.Team == TeamColor.White && !h1Rook.HasMoved)
                    sb.Append('K');

                ChessPiece a1Rook = board.GetPieceAt(new Vector2IntCustom(0, 0));
                if (a1Rook != null && a1Rook.Type == PieceType.Rook && a1Rook.Team == TeamColor.White && !a1Rook.HasMoved)
                    sb.Append('Q');
            }

            // Black King at (7, 4)
            ChessPiece blackKing = board.GetPieceAt(new Vector2IntCustom(7, 4));
            if (blackKing != null && blackKing.Type == PieceType.King && blackKing.Team == TeamColor.Black && !blackKing.HasMoved)
            {
                ChessPiece h8Rook = board.GetPieceAt(new Vector2IntCustom(7, 7));
                if (h8Rook != null && h8Rook.Type == PieceType.Rook && h8Rook.Team == TeamColor.Black && !h8Rook.HasMoved)
                    sb.Append('k');

                ChessPiece a8Rook = board.GetPieceAt(new Vector2IntCustom(7, 0));
                if (a8Rook != null && a8Rook.Type == PieceType.Rook && a8Rook.Team == TeamColor.Black && !a8Rook.HasMoved)
                    sb.Append('q');
            }

            return sb.ToString();
        }

        public static string SquareToUci(Vector2IntCustom pos)
        {
            char file = (char)('a' + pos.Col);
            int rank = pos.Row + 1;
            return $"{file}{rank}";
        }

        public static string MoveToUci(Vector2IntCustom from, Vector2IntCustom to, string promotion = "")
        {
            return $"{SquareToUci(from)}{SquareToUci(to)}{promotion}";
        }

        public static (Vector2IntCustom from, Vector2IntCustom to) UciToMove(string uci)
        {
            if (string.IsNullOrEmpty(uci) || uci.Length < 4)
                return (new Vector2IntCustom(-1, -1), new Vector2IntCustom(-1, -1));

            int fromCol = uci[0] - 'a';
            int fromRow = uci[1] - '1';
            int toCol = uci[2] - 'a';
            int toRow = uci[3] - '1';

            return (new Vector2IntCustom(fromRow, fromCol), new Vector2IntCustom(toRow, toCol));
        }

        /// <summary>
        /// Carga una posición FEN en el tablero lógico. Crea piezas temporales como GameObjects hijos del Board.
        /// Usado por el sistema de Undo.
        /// </summary>
        public static void LoadPosition(string fen, Board board)
        {
            if (board == null || string.IsNullOrEmpty(fen)) return;

            // Destruir piezas previas hijas del Board (si existen)
            var existing = board.GetComponentsInChildren<ChessPiece>();
            foreach (var p in existing)
            {
                if (p != null) UnityEngine.Object.Destroy(p.gameObject);
            }
            board.ClearBoard();

            string[] parts = fen.Split(' ');
            if (parts.Length == 0) return;
            string placement = parts[0];
            string[] rows = placement.Split('/');
            int currentRow = 7;
            foreach (string rowStr in rows)
            {
                if (currentRow < 0) break;
                int col = 0;
                foreach (char ch in rowStr)
                {
                    if (char.IsDigit(ch))
                    {
                        int empty = ch - '0';
                        col += empty;
                    }
                    else
                    {
                        if (col >= Board.BOARD_SIZE) continue;
                        TeamColor team = char.IsUpper(ch) ? TeamColor.White : TeamColor.Black;
                        char upper = char.ToUpper(ch);
                        var pos = new Vector2IntCustom(currentRow, col);
                        GameObject go = new GameObject($"Undo_{upper}_{currentRow}_{col}");
                        go.transform.SetParent(board.transform);
                        ChessPiece piece = null;
                        switch (upper)
                        {
                            case 'P': piece = go.AddComponent<WilderGambit.Pieces.Pawn>(); break;
                            case 'N': piece = go.AddComponent<WilderGambit.Pieces.Knight>(); break;
                            case 'B': piece = go.AddComponent<WilderGambit.Pieces.Bishop>(); break;
                            case 'R': piece = go.AddComponent<WilderGambit.Pieces.Rook>(); break;
                            case 'Q': piece = go.AddComponent<WilderGambit.Pieces.Queen>(); break;
                            case 'K': piece = go.AddComponent<WilderGambit.Pieces.King>(); break;
                            default: UnityEngine.Object.Destroy(go); break;
                        }
                        if (piece != null)
                        {
                            piece.Init(team, pos);
                            // HasMoved se infiere de derechos de enroque si están disponibles
                            if (parts.Length > 2)
                            {
                                string castling = parts[2];
                                if (piece.Type == PieceType.King && !piece.HasMoved)
                                {
                                    bool isWhiteKing = (team == TeamColor.White && pos.Row == 0 && pos.Col == 4);
                                    bool isBlackKing = (team == TeamColor.Black && pos.Row == 7 && pos.Col == 4);
                                    if ((isWhiteKing && castling.Contains("K") || castling.Contains("Q")) ||
                                        (isBlackKing && castling.Contains("k") || castling.Contains("q")))
                                    {
                                        piece.HasMoved = false;
                                    }
                                    else if ((isWhiteKing || isBlackKing))
                                    {
                                        // Si no hay derechos, asumimos que ya se movió (para evitar enroque ilegal tras undo)
                                        // Pero si está en posición inicial y sin derechos, marcar como movido
                                        if (castling == "-" || (!castling.Contains("K") && !castling.Contains("Q") && team == TeamColor.White) ||
                                            (!castling.Contains("k") && !castling.Contains("q") && team == TeamColor.Black))
                                        {
                                            // Si rey en origen pero sin derechos, marcar movido si no es inicio
                                        }
                                    }
                                }
                            }
                            board.SetPieceAt(pos, piece);
                        }
                        col++;
                    }
                }
                currentRow--;
            }
        }
    }
}
