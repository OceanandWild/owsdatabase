using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Video;
using WilderGambit.AI;
using WilderGambit.Pieces;
using WilderGambit.View;

namespace WilderGambit.Core
{
    public class GameManager : MonoBehaviour
    {
        public static GameManager Instance { get; private set; }

        [Header("References")]
        [SerializeField] private Board board;
        [SerializeField] private BoardView boardView;
        [SerializeField] private CinematicPlayer cinematicPlayer;

        [Header("Cinematics")]
        [Tooltip("Video que se reproduce cuando el Caballo Blanco captura un Peón Negro")]
        [SerializeField] private VideoClip knightTakesPawnClip;
        public bool EnableCinematics { get; set; } = true;

        public TeamColor CurrentTurn { get; private set; } = TeamColor.White;
        public ChessPiece SelectedPiece { get; private set; } = null;
        public List<Vector2IntCustom> ValidMovesForSelected { get; private set; } = new List<Vector2IntCustom>();

        [Header("AI Settings")]
        [SerializeField] private bool vsAI = true;
        [SerializeField] private WilderGambit.AI.DifficultyLevel currentDifficulty = WilderGambit.AI.DifficultyLevel.Knight;

        /// <summary>Modo de tiempo elegido en el selector. Vive aquí (y no en el menú)
        /// para que "Reiniciar partida" mantenga el mismo control de tiempo.</summary>
        private TimeControl _matchTimeControl = TimeControl.None;

        public bool IsGameActive { get; private set; } = true;

        /// <summary>Indica si la partida está pausada por el panel de pausa (ESC).</summary>
        public bool IsPaused { get; private set; } = false;

        private int _halfmoveClock = 0;
        private Dictionary<string, int> _positionHistory = new Dictionary<string, int>();
        private bool _matchRewardPaid = false;

        // ── Métricas de la partida (economía + misiones) ──
        private int _playerCaptures = 0;
        private int _playerLosses = 0;
        private bool _lostQueen = false;

        // ── Entrenamiento táctico (puzzles) ──
        private bool _trainingMode = false;
        private string _trainingPuzzleId = "";

        /// <summary>true mientras se juega una sesión de entrenamiento (sin IA ni final de partida).</summary>
        public bool IsTrainingMode => _trainingMode;

        // ─── Undo System ──────────────────────────────────────────────────────
        private struct UndoState
        {
            public string fen;
            public TeamColor turn;
            public int halfmoveClock;
            // El FEN codifica el Nigromante como Alfil base: guardamos sus casillas y cargas
            public string necroData; // "casilla:cargas,..." con casilla = row*8+col
            // El FEN codifica el Peón Lancero como Peón base: guardamos sus casillas
            public string lancerData; // "casilla,..." con casilla = row*8+col
            // El FEN codifica la Dama Jinete como Dama base: casillas + Cabalgada disponible (1/0)
            public string riderData; // "casilla:disponible,..." con casilla = row*8+col
            // El FEN codifica la Reina Vampira como Dama base: casilla + si ya renació (1/0)
            public string vampireData; // "casilla:renacio,..." con casilla = row*8+col
            // El FEN codifica la Torre Fragua como Torre base: brasas, sentencias,
            // tributos e indultos (ver CaptureFragaData)
            public string fragaData;
            // El FEN codifica las variantes de la tienda de la velada (Peón Calabaza
            // y Caballo Fantasma) como pieza base: casillas + tipo
            public string shopVariantData; // "casilla:tipo[:mist:poss],..." con tipo p/n
            // Aturdimientos de la Explosión de Calabaza: "casilla:turnos:justo,..."
            public string stunData;
            // Cargas de explosión por bando: "blanco:negro" (1 = ya explotó)
            public string pumpkinData;
        }
        private readonly System.Collections.Generic.Stack<UndoState> _undoStack = new System.Collections.Generic.Stack<UndoState>();
        private const int MAX_UNDO = 50;

        // ─── Alfil Nigromante: estado de resurrección ─────────────────────────
        // Si no es null, el jugador ha seleccionado un Nigromante con cargas y espera elegir casilla
        private WilderGambit.Pieces.NecromancerBishop _pendingResurrectionBishop = null;

        // ─── Caballo Fantasma: Salto de Niebla y Posesión ────────────────────
        // Salto de Niebla pendiente: el caballo ya capturó y espera elegir la casilla
        // de salida (o tocar otra casilla para omitir). onFinish cierra la jugada una
        // sola vez, después de resolver el salto.
        private WilderGambit.Pieces.GhostKnight _pendingMistKnight = null;
        private List<Vector2IntCustom> _pendingMistSquares = null;
        private System.Action _pendingMistOnFinish = null;
        // Posesión pendiente: el caballo espera que el jugador elija un peón aliado.
        private WilderGambit.Pieces.GhostKnight _pendingPossessionKnight = null;
        private List<Vector2IntCustom> _pendingPossessionTargets = null;

        // ─── Peón Calabaza: una explosión por bando y partida ────────────────
        private bool _pumpkinExplodedWhite;
        private bool _pumpkinExplodedBlack;

        // ─── Torre Fragua: Sentencia de la Fragua ────────────────────────────
        // Si no es null, el jugador ha seleccionado la Torre Fragua y espera elegir
        // la pieza a condenar (modo sentencia).
        private WilderGambit.Pieces.FraguaRook _pendingCondemnRook = null;
        // Brasas: cargas de Sentencia compartidas por bando (+1 por Dama/Torre
        // capturada por una Torre Fragua, tope MaxSentencias por partida).
        private int _sentenciasWhite;
        private int _sentenciasBlack;
        // Sentencias de quema activas: pieza condenada -> mecha restante + torres condenadoras vivas
        private readonly Dictionary<ChessPiece, SentenceInfo> _sentences = new Dictionary<ChessPiece, SentenceInfo>();
        // Tributos: pieza entregada -> bando beneficiario/original + turnos restantes
        private readonly Dictionary<ChessPiece, LoanInfo> _loans = new Dictionary<ChessPiece, LoanInfo>();
        // Piezas que cumplieron su condena sirviendo el Tributo: inmunidad permanente a nuevas sentencias
        private readonly HashSet<ChessPiece> _indulted = new HashSet<ChessPiece>();

        public const int MaxSentencias = 3;
        private const int SentenceFuse = 5;
        private const int LoanTurns = 3;

        private sealed class SentenceInfo
        {
            public int fuse = SentenceFuse;
            public readonly List<ChessPiece> rooks = new List<ChessPiece>();
        }

        private sealed class LoanInfo
        {
            public TeamColor beneficiary;
            public TeamColor original;
            public int turnsLeft = LoanTurns;
            // El turno en que se creó el Tributo no se descuenta: el beneficiario
            // disfruta 3 turnos completos a partir del siguiente.
            public bool skipFirstTick = true;
        }

        private void Awake()
        {
            if (Instance == null) Instance = this;
            else { Destroy(gameObject); return; }

            if (board == null)     board     = GetComponent<Board>();
            if (boardView == null) boardView = GetComponent<BoardView>();

            // Asegurar que exista CinematicPlayer en la escena
            if (cinematicPlayer == null)
                cinematicPlayer = FindAnyObjectByType<CinematicPlayer>();
            if (cinematicPlayer == null)
            {
                GameObject cpObj = new GameObject("CinematicPlayer");
                cinematicPlayer = cpObj.AddComponent<CinematicPlayer>();
            }

            if (knightTakesPawnClip == null)
                knightTakesPawnClip = Resources.Load<VideoClip>("KnightTakesPawn");

            EnableCinematics = PlayerPrefs.GetInt("EnableCinematics", 1) == 1;

            // El reloj se crea aquí: los modos con tiempo (Bullet/Blitz/Rapid) lo necesitan
            // desde el primer frame y antes no había nada que lo arrancara.
            GameClock.EnsureExists();

            // Asegurar que exista ChessAI en la escena
            if (WilderGambit.AI.ChessAI.Instance == null)
            {
                GameObject aiObj = new GameObject("ChessAI");
                aiObj.AddComponent<WilderGambit.AI.ChessAI>();
            }

            // Asegurar que exista StockfishEngine en la escena
            if (WilderGambit.Engine.StockfishEngine.Instance == null)
            {
                GameObject sfObj = new GameObject("StockfishEngine");
                sfObj.AddComponent<WilderGambit.Engine.StockfishEngine>();
            }

            // Asegurar que exista MoveBadgeView en la escena
            if (WilderGambit.View.MoveBadgeView.Instance == null)
            {
                GameObject badgeObj = new GameObject("MoveBadgeView");
                badgeObj.AddComponent<WilderGambit.View.MoveBadgeView>();
            }

            // Asegurar que exista MusicManager en la escena
            if (WilderGambit.Audio.MusicManager.Instance == null)
            {
                GameObject musicObj = new GameObject("MusicManager");
                musicObj.AddComponent<WilderGambit.Audio.MusicManager>();
            }

            // Verificar que el Menú Principal esté configurado en la escena.
            // Si falta, usa el menú Editor: Wilder Gambit > Setup Main Menu
            if (FindAnyObjectByType<WilderGambit.UI.MainMenuController>() == null)
            {
                Debug.LogWarning(
                    "[GameManager] No se encontró MainMenuController en la escena. " +
                    "Usa el menú Editor: Wilder Gambit > Setup Main Menu para configurarlo.");
            }
        }

        private void Start()
        {
            IsGameActive = false; // Pausar hasta que el jugador seleccione la dificultad
            if (WilderGambit.AI.ChessAI.Instance != null)
            {
                WilderGambit.AI.ChessAI.Instance.SetDifficulty(currentDifficulty);
            }

            // Economía: misiones, barra semanal y logros escuchando los eventos de juego
            PuzzleManager.EnsureExists();
            DailyChallenge.EnsureExists();
            GambitProgress.Init();

            // Reloj de partida: alguien que se quede sin tiempo cierra la partida
            GameClock.EnsureExists();
            GameClock.Instance.OnTimeExpired -= OnTimeExpired;
            GameClock.Instance.OnTimeExpired += OnTimeExpired;
        }

        public void StartGameWithDifficulty(WilderGambit.AI.DifficultyLevel level)
        {
            currentDifficulty = level;
            vsAI = true;
            _trainingMode = false;
            _trainingPuzzleId = "";
            IsGameActive = true;
            _matchRewardPaid = false; // una recompensa por partida
            _playerCaptures = 0;
            _playerLosses = 0;
            _lostQueen = false;
            CurrentTurn = TeamColor.White;
            _halfmoveClock = 0;
            _positionHistory.Clear();
            ResetFraguaState();
            ResetHalloweenAbilityState();

            // Reloj de la partida: se arranca aquí (y no en el menú) para que el reinicio
            // de partida conserve el modo elegido. None deja el reloj apagado.
            GameClock.EnsureExists();
            GameClock.Instance.StartClock(_matchTimeControl);

            if (WilderGambit.AI.ChessAI.Instance != null)
            {
                WilderGambit.AI.ChessAI.Instance.SetDifficulty(currentDifficulty);
            }

            if (WilderGambit.View.MoveBadgeView.Instance != null)
            {
                WilderGambit.View.MoveBadgeView.Instance.ClearBadge();
            }

            if (WilderGambit.Audio.MusicManager.Instance != null)
            {
                WilderGambit.Audio.MusicManager.Instance.PlayBattleMusic();
            }

            Debug.Log($"Juego Iniciado contra la IA en Nivel: {level}");

            // Show game HUD (history panel + undo button)
            if (WilderGambit.UI.PauseMenuController.Instance != null)
                WilderGambit.UI.PauseMenuController.Instance.ShowGameHUD();

            // Clear undo stack and history
            _undoStack.Clear();
            if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                WilderGambit.UI.MoveHistoryPanel.Instance.Clear();

            // Clear analytics for new game
            if (Core.GameAnalytics.Instance != null)
                Core.GameAnalytics.Instance.Clear();

            // Limpiar indicadores persistentes del nigromante
            if (boardView != null)
            {
                boardView.ClearNecromancerIndicators();
                boardView.RefreshNecromancerIndicators(board);
            }
        }

        /// <summary>Fija el modo de tiempo de la próxima partida (lo llama el selector del menú).</summary>
        public void SetTimeControl(TimeControl control)
        {
            _matchTimeControl = control;
        }

        /// <summary>El modo de tiempo con el que se está jugando.</summary>
        public TimeControl MatchTimeControl => _matchTimeControl;

        /// <summary>
        /// Alguien se quedó sin tiempo. Gana el bando contrario: si el jugador (blancas)
        /// es quien agota, es derrota; si es la IA, victoria.
        /// </summary>
        private void OnTimeExpired(TeamColor team)
        {
            // En pausa no se agota nada (el reloj está congelado) y los puzzles van sin reloj.
            if (IsPaused || _trainingMode) return;

            // Ojo: NO se filtra por IsGameActive. Durante una cinemática o la promoción
            // el input está bloqueado (IsGameActive = false) pero la partida sigue viva:
            // si el reloj llega a cero ahí, la partida se cierra igualmente y no queda
            // un reloj muerto con el tablero esperando.
            GameClock.Instance?.Stop();

            bool playerWon = (team == TeamColor.Black);
            DynamicDifficultyManager.RecordResult(isWin: playerWon, isDraw: false, currentDifficulty);

            if (playerWon)
                ShowGameOver("⏰ ¡VICTORIA POR TIEMPO!", "La IA se quedó sin tiempo.",
                             new Color(0.95f, 0.85f, 0.25f), MatchOutcome.Victory);
            else
                ShowGameOver("⏱️ ¡SE TE ACABÓ EL TIEMPO!", "Tu reloj llegó a cero antes que el de la IA.",
                             new Color(0.95f, 0.30f, 0.30f), MatchOutcome.Defeat);
        }

        public void SelectSquare(Vector2IntCustom pos)
        {
            if (!IsGameActive) return;
            // En entrenamiento el jugador mueve siempre el bando que toca (sin IA),
            // aunque la partida anterior hubiera dejado vsAI activado
            if (vsAI && !_trainingMode && CurrentTurn == TeamColor.Black) return;

            // ─── Modo Salto de Niebla pendiente: el jugador elige la casilla ───
            // Cualquier clic que no sea una casilla resaltada omite el salto; el
            // caballo se queda donde capturó y la jugada se cierra igualmente.
            if (_pendingMistKnight != null)
            {
                bool use = _pendingMistSquares != null && _pendingMistSquares.Contains(pos);
                ResolveMistStep(pos, use);
                return;
            }

            // ─── Modo Resurrección activo: el jugador elige casilla de spawn ───
            if (_pendingResurrectionBishop != null)
            {
                var resSqs = _pendingResurrectionBishop.GetResurrectionSquares(board);
                if (resSqs.Contains(pos))
                {
                    TriggerResurrection(_pendingResurrectionBishop, pos);
                }
                else
                {
                    // Click fuera de casilla válida → cancelar modo resurrección
                    _pendingResurrectionBishop = null;
                    boardView.ClearOverlays();
                }
                return;
            }

            ChessPiece clickedPiece = board.GetPieceAt(pos);

            // ─── Modo Posesión activo: el jugador elige un peón aliado ───────
            if (_pendingPossessionKnight != null)
            {
                var targets = _pendingPossessionTargets ?? new List<Vector2IntCustom>();
                if (targets.Contains(pos))
                {
                    TriggerPossession(_pendingPossessionKnight, pos);
                    return;
                }

                bool normalMove = SelectedPiece != null && ValidMovesForSelected != null
                                  && ValidMovesForSelected.Contains(pos);
                bool ownPiece = clickedPiece != null && clickedPiece.Team == CurrentTurn;
                _pendingPossessionKnight = null;
                _pendingPossessionTargets = null;
                boardView?.ClearOverlays();
                WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();

                if (!normalMove && !ownPiece)
                {
                    // Clic fuera de objetivo: cancela la posesión y deselecciona.
                    Deselect();
                    WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
                    return;
                }
                // Movimiento normal del caballo u otra pieza propia: sale del modo
                // y continúa con el flujo de abajo.
            }

            // ─── Modo Sentencia activo: el jugador elige la pieza a condenar ───
            if (_pendingCondemnRook != null)
            {
                var condemnTargets = GetCondemnTargets(_pendingCondemnRook);
                if (condemnTargets.Contains(pos))
                {
                    TriggerCondemn(_pendingCondemnRook, pos);
                    return;
                }
                if (SelectedPiece != null && ValidMovesForSelected.Contains(pos))
                {
                    // Movimiento normal de la propia torre: sale del modo sentencia
                    // y continúa con el flujo de movimiento de abajo.
                    _pendingCondemnRook = null;
                    boardView.ClearOverlays();
                }
                else if (clickedPiece != null && clickedPiece.Team == CurrentTurn)
                {
                    // Otra pieza propia: sale del modo y cae al flujo de selección.
                    _pendingCondemnRook = null;
                }
                else
                {
                    // Clic fuera de objetivo: cancela el modo sentencia.
                    _pendingCondemnRook = null;
                    boardView.ClearOverlays();
                    Deselect();
                    return;
                }
            }

            // Si hay pieza seleccionada y el destino es un movimiento válido → mover
            if (SelectedPiece != null && ValidMovesForSelected.Contains(pos))
            {
                Vector2IntCustom from = SelectedPiece.Position;
                ChessPiece movingPiece = SelectedPiece;
                ChessPiece targetPiece = board.GetPieceAt(pos);

                string fenBefore = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn);
                string playedUci = WilderGambit.Engine.FenUtility.MoveToUci(from, pos);

                // Entrenamiento táctico: la jugada debe ser la solución del puzzle
                if (_trainingMode && !ValidateTrainingMove(playedUci))
                {
                    Deselect();
                    return;
                }

                // Actualizar reloj de 50 movimientos
                if (movingPiece.Type == PieceType.Pawn || targetPiece != null)
                {
                    _halfmoveClock = 0;
                }
                else
                {
                    _halfmoveClock++;
                }

                // Registrar en el historial de la IA
                if (WilderGambit.AI.ChessAI.Instance != null)
                {
                    WilderGambit.AI.ChessAI.Instance.RecordMove(from, pos);
                }

                // ── Detección de Coronación de Peón (Fila 7 para Blancas) ─────
                bool isPawnPromotion = (movingPiece.Type == PieceType.Pawn && !(movingPiece is WilderGambit.Pieces.SpectralPawn) && (pos.Row == 7 || pos.Row == 0));

                if (isPawnPromotion)
                {
                    // Reina Vampira capturada: separar su vista antes de que
                    // MovePieceView destruya la pieza que debe renacer.
                    var promoVampire = targetPiece as WilderGambit.Pieces.VampireQueen;
                    if (promoVampire != null && promoVampire.CanRise)
                        boardView.DetachPieceView(pos);

                    board.MovePiece(from, pos);
                    boardView.MovePieceView(from, pos);
                    WilderGambit.Audio.MusicManager.Instance?.PlayPieceMoveSound();
                    TryRespawnVampire(promoVampire);
                    TryPumpkinExplosion(targetPiece, movingPiece);
                    CheckSpecialTransformations();
                    Deselect();
                    IsGameActive = false; // Pausar input mientras se selecciona pieza

                    // Asegurar que exista PromotionModal
                    if (WilderGambit.UI.PromotionModal.Instance == null)
                    {
                        GameObject modalObj = new GameObject("PromotionModal");
                        modalObj.AddComponent<WilderGambit.UI.PromotionModal>();
                    }

                    WilderGambit.UI.PromotionModal.Instance.Show(CurrentTurn, (selectedType) =>
                    {
                        boardView.PromotePieceView(pos, selectedType, CurrentTurn);

                        string promoChar = "q";
                        switch (selectedType)
                        {
                            case PieceType.Queen:  promoChar = "q"; break;
                            case PieceType.Rook:   promoChar = "r"; break;
                            case PieceType.Bishop: promoChar = "b"; break;
                            case PieceType.Knight: promoChar = "n"; break;
                        }

                        string fullUci = playedUci + promoChar;
                        string fenAfterPromo = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn == TeamColor.White ? TeamColor.Black : TeamColor.White);
                        // Analytics placeholder for promotion (will be updated by Stockfish)
                        string promoNotation = GenerateMoveNotation(movingPiece, from, pos, targetPiece) + "=" + promoChar.ToUpper();
                        if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                            WilderGambit.UI.MoveHistoryPanel.Instance.RecordMove(promoNotation, movingPiece.Team);
                        if (Core.GameAnalytics.Instance != null)
                            Core.GameAnalytics.Instance.RecordMove(promoNotation, movingPiece.Team, MoveQuality.Good, 0f);
                        EvaluateMoveWithStockfish(fenBefore, fenAfterPromo, fullUci, pos, isCurrentMoveFork: false);

                        IsGameActive = true;
                        EndTurn();
                    });
                    return;
                }

                // ── Animación: Caballo Blanco Transformado atacando / capturando pieza ──
                bool isTransformedKnightAttack =
                    movingPiece != null &&
                    movingPiece.Type == PieceType.Knight &&
                    movingPiece.Team == TeamColor.White &&
                   (movingPiece as Knight != null && (movingPiece as Knight).IsTransformed) &&
                    targetPiece != null &&
                    targetPiece.Team != movingPiece.Team;

                if (isTransformedKnightAttack)
                {
                    Vector2IntCustom capturedFrom = from;
                    Vector2IntCustom capturedTo = pos;

                    Deselect();
                    IsGameActive = false; // Bloquear input durante la animación de ataque

                    // Reina Vampira capturada: separar su vista para que el impacto
                    // del Caballo transformado no destruya la pieza que debe renacer.
                    var forkVampire = targetPiece as WilderGambit.Pieces.VampireQueen;
                    if (forkVampire != null && forkVampire.CanRise)
                        boardView.DetachPieceView(capturedTo);

                    board.MovePiece(capturedFrom, capturedTo);
                    TryRespawnVampire(forkVampire);
                    TryPumpkinExplosion(targetPiece, movingPiece);

                    // El FEN debe reflejar la posición DESPUÉS de mover y de las
                    // pasivas (renacimiento / explosión), no la de antes.
                    string fenAfter = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn == TeamColor.White ? TeamColor.Black : TeamColor.White);

                    // Analytics placeholder for fork attack
                    string forkNotation = GenerateMoveNotation(movingPiece, capturedFrom, capturedTo, targetPiece);
                    if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                        WilderGambit.UI.MoveHistoryPanel.Instance.RecordMove(forkNotation, movingPiece.Team);
                    if (Core.GameAnalytics.Instance != null)
                        Core.GameAnalytics.Instance.RecordMove(forkNotation, movingPiece.Team, MoveQuality.Good, 0f);

                    boardView.PlayKnightForkAttack(capturedFrom, capturedTo, () =>
                    {
                        CheckSpecialTransformations();
                        EvaluateMoveWithStockfish(fenBefore, fenAfter, playedUci, capturedTo);
                        IsGameActive = true;
                        EndTurn();
                    });
                    return;
                }

                // ── Cinemático: Caballo Blanco captura Peón Negro ────────────
                // El Caballo Fantasma queda fuera: su captura debe pasar por el
                // flujo normal para poder resolver Salto de Niebla y Undo.
                ChessPiece target = board.GetPieceAt(pos);
                bool isKnightTakesPawn =
                    movingPiece is Knight                    &&
                    !(movingPiece is GhostKnight)            &&
                    movingPiece.Team == TeamColor.White      &&
                    target != null                          &&
                    target.Type == PieceType.Pawn           &&
                    target.Team == TeamColor.Black;

                if (isKnightTakesPawn && EnableCinematics && cinematicPlayer != null && knightTakesPawnClip != null)
                {
                    // Capturar variables locales para el closure
                    Vector2IntCustom capturedFrom = from;
                    Vector2IntCustom capturedTo   = pos;

                    Deselect();
                    IsGameActive = false; // Bloquear input mientras se reproduce el video

                    cinematicPlayer.PlayCinematic(knightTakesPawnClip, () =>
                    {
                        // Callback: ejecutar el movimiento después del video
                        board.MovePiece(capturedFrom, capturedTo);
                        boardView.MovePieceView(capturedFrom, capturedTo);
                        WilderGambit.Audio.MusicManager.Instance?.PlayPieceMoveSound();
                        TryPumpkinExplosion(target, movingPiece);
                        CheckSpecialTransformations();
                        bool isFork = IsMoveAFork(capturedTo);
                        string fenAfter = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn == TeamColor.White ? TeamColor.Black : TeamColor.White);
                        // Analytics placeholder for cinematic
                        ChessPiece movingForNotation = board.GetPieceAt(capturedTo);
                        string cineNotation = GenerateMoveNotation(movingForNotation != null ? movingForNotation : SelectedPiece, capturedFrom, capturedTo, target);
                        if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                            WilderGambit.UI.MoveHistoryPanel.Instance.RecordMove(cineNotation, TeamColor.White);
                        if (Core.GameAnalytics.Instance != null)
                            Core.GameAnalytics.Instance.RecordMove(cineNotation, TeamColor.White, MoveQuality.Good, 0f);
                        EvaluateMoveWithStockfish(fenBefore, fenAfter, playedUci, capturedTo, isCurrentMoveFork: isFork);
                        IsGameActive = true;
                        EndTurn();
                    });
                    return;
                }
                // ─────────────────────────────────────────────────────────────

                // Save undo state before the move
                SaveUndoState();

                // Reina Vampira capturada: su vista se separa antes del movimiento
                // para que MovePieceView no destruya la pieza que debe renacer.
                var capturedVampire = targetPiece as WilderGambit.Pieces.VampireQueen;
                if (capturedVampire != null && capturedVampire.CanRise)
                    boardView.DetachPieceView(pos);

                board.MovePiece(from, pos);
                boardView.MovePieceView(from, pos);
                WilderGambit.Audio.MusicManager.Instance?.PlayPieceMoveSound();

                // Pasiva «No Muerta»: si cae y aún puede, vuelve a su primera fila
                // antes de métricas, notación y cierre de turno.
                TryRespawnVampire(capturedVampire);

                // Pasiva «Explosión de Calabaza»: si la capturada es un Peón Calabaza
                // y su bando conserva la carga, el capturador queda aturdido 2 turnos.
                TryPumpkinExplosion(targetPiece, movingPiece);

                // Pasiva «Salto de Niebla»: el Caballo Fantasma puede resolver su
                // salto ANTES de la notación/analíticas/cierre de turno. El resto de
                // la jugada se ejecuta una sola vez, al elegir casilla u omitir.
                if (TryBeginMistStep(movingPiece, targetPiece != null,
                        () => CompletePlayerMove(movingPiece, from, pos, targetPiece, fenBefore, playedUci)))
                {
                    return;
                }

                CompletePlayerMove(movingPiece, from, pos, targetPiece, fenBefore, playedUci);
                return;
            }

            // Seleccionar pieza del turno actual
            if (clickedPiece != null && clickedPiece.Team == CurrentTurn)
            {
                // ─── Alfil Nigromante con cargas: activar modo resurrección ───
                var necromancer = clickedPiece as WilderGambit.Pieces.NecromancerBishop;
                if (necromancer != null && necromancer.CanResurrect)
                {
                    _pendingResurrectionBishop = necromancer;
                    var resSqs = necromancer.GetResurrectionSquares(board);
                    // Mostrar movimientos normales + casillas de resurrección
                    var normalMoves = clickedPiece.GetLegalMoves(board);
                    boardView.ShowSelection(pos, normalMoves, board);
                    // Resaltar casillas de resurrección con color especial (verde esmeralda)
                    foreach (var sq in resSqs)
                        boardView.ShowResurrectionSquare(sq);
                    // Aura pulsante sobre el Nigromante: señal visual de que el Alzamiento está listo
                    boardView.ShowSoulReadyIndicator(necromancer);
                    SelectedPiece = clickedPiece;
                    ValidMovesForSelected = normalMoves;
                    return;
                }

                // ─── Torre Fragua con Sentencias: activar modo sentencia ───
                var fragua = clickedPiece as WilderGambit.Pieces.FraguaRook;
                if (fragua != null && CanEnterCondemnMode(fragua))
                {
                    EnterCondemnMode(fragua);
                    return;
                }

                SelectedPiece = clickedPiece;
                ValidMovesForSelected = clickedPiece.GetLegalMoves(board);
                boardView.ShowSelection(pos, ValidMovesForSelected, board);
            }
            else
            {
                Deselect();
            }
        }

        /// <summary>
        /// Cierre común de una jugada normal: notación, analíticas, misiones, fork y
        /// fin de turno. Se extrajo para que el Salto de Niebla pueda resolver su
        /// casilla ANTES de registrar la jugada, sin duplicar el pipeline.
        /// </summary>
        private void CompletePlayerMove(ChessPiece movingPiece, Vector2IntCustom from, Vector2IntCustom to,
                                        ChessPiece targetPiece, string fenBefore, string playedUci)
        {
            // Record move in history panel
            string notation = GenerateMoveNotation(movingPiece, from, to, targetPiece);
            if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                WilderGambit.UI.MoveHistoryPanel.Instance.RecordMove(notation, movingPiece.Team);

            // Record analytics
            if (Core.GameAnalytics.Instance != null)
            {
                var quality = targetPiece != null ? Core.MoveQuality.Good : Core.MoveQuality.Good;
                Core.GameAnalytics.Instance.RecordMove(notation, movingPiece.Team, quality, 0f);
            }

            // Si hubo captura, notificar a los Alfil Nigromante aliados (Espectrales no generan almas - )
            if (targetPiece != null && !(targetPiece is WilderGambit.Pieces.SpectralPawn))
                NotifyNecromancerAllyCaptured(movingPiece.Team);

            // ── Torre Fragua (pasiva Brasas): capturar Dama o Torre aviva la fragua ──
            if (targetPiece != null && movingPiece is WilderGambit.Pieces.FraguaRook
                && (targetPiece.Type == PieceType.Queen || targetPiece.Type == PieceType.Rook))
            {
                AddSentencia(movingPiece.Team);
            }

            // Métricas + eventos de captura (misiones de «Cazador», logros, etc.)
            if (targetPiece != null && targetPiece.Team == TeamColor.Black)
            {
                _playerCaptures++;
                GameEvents.RaisePieceCaptured(new CaptureInfo
                {
                    type = targetPiece.Type,
                    capturedColor = targetPiece.Team,
                    byColor = movingPiece.Team,
                });
            }

            CheckSpecialTransformations();
            boardView?.RefreshNecromancerIndicators(board);
            bool wasFork = IsMoveAFork(to);
            string fenAfterMove = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn == TeamColor.White ? TeamColor.Black : TeamColor.White);
            // El badge/FX se ancla a la casilla final de la pieza: con Salto de Niebla
            // puede ser distinta de la casilla donde se hizo la captura.
            Vector2IntCustom badgeSquare = movingPiece != null ? movingPiece.Position : to;
            EvaluateMoveWithStockfish(fenBefore, fenAfterMove, playedUci, badgeSquare, isCurrentMoveFork: wasFork);

            Deselect();
            EndTurn();
        }

        // ─── Caballo Fantasma: Salto de Niebla ───────────────────────────────

        /// <summary>
        /// Si la pieza es un Caballo Fantasma que acaba de capturar y puede saltar,
        /// abre el modo de selección de casilla y guarda la continuación que cierra
        /// la jugada. Devuelve true si la jugada quedó pendiente del salto.
        /// </summary>
        private bool TryBeginMistStep(ChessPiece piece, bool captured, System.Action onFinish)
        {
            GhostKnight knight = piece as GhostKnight;
            if (knight == null || !captured) return false;
            if (!knight.MistStepAvailable || knight.IsStunned || board == null) return false;

            TeamColor opponent = knight.Team == TeamColor.White ? TeamColor.Black : TeamColor.White;
            // Si la captura ya cerró la partida (mate o ahogado), no se retrasa el final.
            if (!board.HasAnyLegalMove(opponent)) return false;

            var squares = knight.GetMistStepSquares(board);
            if (squares.Count == 0) return false;

            Deselect();
            _pendingMistKnight = knight;
            _pendingMistSquares = squares;
            _pendingMistOnFinish = onFinish;

            foreach (var sq in squares) boardView?.ShowMistStepSquare(sq);
            boardView?.ShowMistReadyIndicator(knight);
            boardView?.ShowGhostToast(knight.Position, "SALTO DE NIEBLA: ELIGE CASILLA (OTRA = OMITIR)");
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
            Debug.Log($"[GhostKnight] Salto de Niebla disponible para {knight.Team} en " +
                      $"({knight.Position.Row},{knight.Position.Col}): {squares.Count} casilla(s).");
            return true;
        }

        /// <summary>Resuelve el Salto de Niebla pendiente: mover a la casilla o omitir.</summary>
        private void ResolveMistStep(Vector2IntCustom target, bool use)
        {
            GhostKnight knight = _pendingMistKnight;
            var squares = _pendingMistSquares;
            var onFinish = _pendingMistOnFinish;
            _pendingMistKnight = null;
            _pendingMistSquares = null;
            _pendingMistOnFinish = null;
            boardView?.ClearOverlays();

            if (use && knight != null && squares != null && squares.Contains(target)
                && board != null && board.GetPieceAt(target) == null)
            {
                Vector2IntCustom from = knight.Position;
                board.MovePiece(from, target);
                boardView?.MovePieceView(from, target);
                knight.ConsumeMistStep();
                boardView?.ShowGhostToast(target, "SALTO DE NIEBLA");
                WilderGambit.View.MoveBadgeView.Instance?.ClearBadge();
                Debug.Log($"[GhostKnight] Salto de Niebla: {knight.Team} " +
                          $"({from.Row},{from.Col}) → ({target.Row},{target.Col}).");
            }
            else if (knight != null)
            {
                boardView?.ShowGhostToast(knight.Position, "SALTO DE NIEBLA OMITIDO");
            }

            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();

            if (onFinish != null) onFinish();
            else EndTurn();
        }

        /// <summary>
        /// Salto de Niebla de la IA: tras capturar, prefiere una casilla libre que no
        /// esté atacada por el rival. Se omite si la captura da jaque/mate o si todas
        /// las salidas están cubiertas.
        /// </summary>
        private void TryAiMistStep(ChessPiece piece, bool captured)
        {
            GhostKnight knight = piece as GhostKnight;
            if (knight == null || !captured || !knight.MistStepAvailable || knight.IsStunned) return;

            TeamColor opponent = knight.Team == TeamColor.White ? TeamColor.Black : TeamColor.White;
            if (board.IsInCheck(opponent) || !board.HasAnyLegalMove(opponent)) return;

            var squares = knight.GetMistStepSquares(board);
            if (squares.Count == 0) return;

            Vector2IntCustom chosen = new Vector2IntCustom(-1, -1);
            foreach (var sq in squares)
            {
                if (!board.IsSquareAttacked(sq, knight.Team))
                {
                    chosen = sq;
                    break;
                }
            }
            if (chosen.Row < 0) return;

            Vector2IntCustom from = knight.Position;
            board.MovePiece(from, chosen);
            boardView.MovePieceView(from, chosen);
            knight.ConsumeMistStep();
            // El salto puede abrir/cerrar una bifurcación de un Caballo Blanco.
            CheckSpecialTransformations();
            boardView.ShowGhostToast(chosen, "SALTO DE NIEBLA (RIVAL)");
            WilderGambit.View.MoveBadgeView.Instance?.ClearBadge();
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
            Debug.Log($"[GhostKnight] IA usa Salto de Niebla: " +
                      $"({from.Row},{from.Col}) → ({chosen.Row},{chosen.Col}).");
        }

        // ─── Caballo Fantasma: Posesión ──────────────────────────────────────

        /// <summary>Activa desde el panel la Posesión del Caballo Fantasma.</summary>
        public bool RequestPossession(GhostKnight knight)
        {
            if (knight == null || board == null) return false;
            if (!knight.PossessionAvailable || knight.IsStunned) return false;
            if (knight.Team != CurrentTurn) return false;
            if (!IsGameActive || IsPaused) return false;
            if (_trainingMode) return false;
            if (vsAI && knight.Team != TeamColor.White) return false;
            if (_pendingMistKnight != null || _pendingPossessionKnight != null
                || _pendingResurrectionBishop != null || _pendingCondemnRook != null) return false;

            var targets = knight.GetPossessionTargets(board);
            if (targets.Count == 0) return false;

            _pendingPossessionKnight = knight;
            _pendingPossessionTargets = targets;
            var normalMoves = knight.GetLegalMoves(board);
            boardView.ShowSelection(knight.Position, normalMoves, board);
            foreach (var sq in targets) boardView.ShowPossessionTarget(sq);
            boardView.ShowPossessionReadyIndicator(knight);
            SelectedPiece = knight;
            ValidMovesForSelected = normalMoves;
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
            Debug.Log($"[GhostKnight] Modo Posesión activado para {knight.Team} en " +
                      $"({knight.Position.Row},{knight.Position.Col}): {targets.Count} peón(es).");
            return true;
        }

        public bool IsMistStepPending(GhostKnight knight) => knight != null && _pendingMistKnight == knight;
        public bool IsPossessionPending(GhostKnight knight) => knight != null && _pendingPossessionKnight == knight;

        /// <summary>Peones aliados con los que este caballo puede posesionarse (para el panel).</summary>
        public List<Vector2IntCustom> GetPossessionTargets(GhostKnight knight)
        {
            if (knight == null || board == null) return new List<Vector2IntCustom>();
            return knight.GetPossessionTargets(board);
        }

        /// <summary>Ejecuta el intercambio de casillas entre el caballo y el peón elegido.</summary>
        private void TriggerPossession(GhostKnight knight, Vector2IntCustom pawnPos)
        {
            ChessPiece pawn = board != null ? board.GetPieceAt(pawnPos) : null;
            if (knight == null || pawn == null || !knight.CanPossess(board, pawn))
            {
                CancelPossession();
                return;
            }

            SaveUndoState();

            Vector2IntCustom knightPos = knight.Position;
            _pendingPossessionKnight = null;
            _pendingPossessionTargets = null;
            boardView?.ClearOverlays();
            Deselect();

            // Intercambio lógico: el caballo va a la casilla del peón y el peón a la del caballo.
            board.SetPieceAt(knightPos, pawn);
            board.SetPieceAt(pawnPos, knight);
            knight.HasMoved = true;
            pawn.HasMoved = true;
            knight.ConsumePossession();

            boardView?.SwapPieceViews(knightPos, pawnPos);
            WilderGambit.Audio.MusicManager.Instance?.PlayPieceMoveSound();

            // El peón se movió: la regla de los 50 movimientos se reinicia.
            _halfmoveClock = 0;

            WilderGambit.AI.ChessAI.Instance?.RecordMove(knightPos, pawnPos);

            string notation = GeneratePossessionNotation(knight, pawnPos);
            WilderGambit.UI.MoveHistoryPanel.Instance?.RecordMove(notation, knight.Team);
            Core.GameAnalytics.Instance?.RecordMove(notation, knight.Team, Core.MoveQuality.Good, 0f);

            boardView?.ShowGhostToast(pawnPos, "POSESIÓN: CABALLO Y PEÓN CAMBIAN DE LUGAR");
            WilderGambit.View.MoveBadgeView.Instance?.ClearBadge();
            CheckSpecialTransformations();
            boardView?.RefreshNecromancerIndicators(board);
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();

            Debug.Log($"[GhostKnight] Posesión: {knight.Team} cambia caballo " +
                      $"({knightPos.Row},{knightPos.Col}) con peón ({pawnPos.Row},{pawnPos.Col}).");

            EndTurn();
        }

        private void CancelPossession()
        {
            _pendingPossessionKnight = null;
            _pendingPossessionTargets = null;
            boardView?.ClearOverlays();
            Deselect();
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
        }

        private string GeneratePossessionNotation(GhostKnight knight, Vector2IntCustom pawnSquare)
        {
            string toSquare = FileNames[pawnSquare.Col] + RankNames[pawnSquare.Row];
            string notation = PieceSymbols[(int)knight.Type] + "↔" + toSquare;
            TeamColor nextTeam = knight.Team == TeamColor.White ? TeamColor.Black : TeamColor.White;
            if (board.IsInCheck(nextTeam))
                notation += board.HasAnyLegalMove(nextTeam) ? "+" : "#";
            return notation;
        }

        // ─── Peón Calabaza: Explosión de Calabaza ────────────────────────────

        /// <summary>
        /// Si la pieza capturada es un Peón Calabaza y su bando aún no gastó la
        /// explosión, aturde 2 turnos al capturador. El Rey es inmune, pero la carga
        /// del bando se consume igualmente. Nunca destruye piezas.
        /// </summary>
        private void TryPumpkinExplosion(ChessPiece capturedPiece, ChessPiece capturingPiece)
        {
            if (!(capturedPiece is PumpkinPawn pumpkin) || capturingPiece == null) return;
            if (HasPumpkinExploded(pumpkin.Team)) return;

            if (pumpkin.Team == TeamColor.White) _pumpkinExplodedWhite = true;
            else _pumpkinExplodedBlack = true;

            Vector2IntCustom fxPos = capturingPiece.Position;
            boardView?.PlayPumpkinExplosion(fxPos);

            if (capturingPiece.Type == PieceType.King)
            {
                boardView?.ShowPumpkinToast(fxPos, "EXPLOSIÓN DE CALABAZA: EL REY ES INMUNE");
                WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
                Debug.Log($"[PumpkinPawn] Explosión consumida por {pumpkin.Team}; el Rey capturador es inmune.");
                return;
            }

            capturingPiece.ApplyStun(2);
            boardView?.SetPieceStunned(fxPos, true);
            boardView?.ShowPumpkinToast(fxPos, $"{PieceDisplayName(capturingPiece).ToUpper()} ATURDIDO 2 TURNOS");
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
            Debug.Log($"[PumpkinPawn] Explosión de {pumpkin.Team}: " +
                      $"{PieceDisplayName(capturingPiece)} aturdido 2 turnos.");
        }

        public bool HasPumpkinExploded(TeamColor team) =>
            team == TeamColor.White ? _pumpkinExplodedWhite : _pumpkinExplodedBlack;

        /// <summary>Descuenta los aturdimientos del bando que empieza su turno.</summary>
        private void TickStuns(TeamColor team)
        {
            if (board == null) return;

            bool changed = false;
            foreach (var piece in board.GetAllPieces(team))
            {
                if (piece == null || piece.StunTurns <= 0) continue;

                if (piece.StunJustApplied)
                {
                    // Gracia: el turno en que se aplicó no cuenta.
                    piece.StunJustApplied = false;
                    continue;
                }

                piece.StunTurns--;
                if (piece.StunTurns <= 0)
                {
                    piece.StunTurns = 0;
                    piece.StunJustApplied = false;
                    boardView?.SetPieceStunned(piece.Position, false);
                    boardView?.ShowPumpkinToast(piece.Position, $"{PieceDisplayName(piece).ToUpper()} SE RECUPERA");
                    Debug.Log($"[Stun] {PieceDisplayName(piece)} de {team} se recupera en " +
                              $"({piece.Position.Row},{piece.Position.Col}).");
                }
                changed = true;
            }

            if (changed) WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
        }

        // ─── Halloween: limpieza de modos y estado ───────────────────────────

        /// <summary>Cancela modos pendientes de variantes sin ejecutar su continuación.</summary>
        private void ClearPendingVariantModes()
        {
            _pendingMistKnight = null;
            _pendingMistSquares = null;
            _pendingMistOnFinish = null;
            _pendingPossessionKnight = null;
            _pendingPossessionTargets = null;
            boardView?.ClearOverlays();
        }

        /// <summary>
        /// Estado limpio de las habilidades de Halloween: cargas de explosión por bando,
        /// aturdimientos y usos de los Caballos Fantasma. Se llama al empezar/terminar
        /// partida o entrenamiento.
        /// </summary>
        private void ResetHalloweenAbilityState()
        {
            _pumpkinExplodedWhite = false;
            _pumpkinExplodedBlack = false;
            ClearPendingVariantModes();

            if (board == null) return;

            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (piece == null) continue;

                    piece.StunTurns = 0;
                    piece.StunJustApplied = false;
                    if (piece is GhostKnight ghost) ghost.RestoreAbilities(true, true);
                }

            boardView?.RefreshStunIndicators(board);
        }

        private bool CheckSpecialTransformations()
        {
            bool anyFork = false;
            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    var pos = new Vector2IntCustom(r, c);
                    ChessPiece piece = board.GetPieceAt(pos);
                    if (piece != null && piece.Type == PieceType.Knight && piece.Team == TeamColor.White)
                    {
                        Knight knight = piece as Knight;
                        if (knight != null)
                        {
                            bool isFork = knight.CheckIsFork(board, pos);
                            if (isFork)
                            {
                                anyFork = true;
                                // El Caballo Fantasma no entra en la transformación
                                // clásica: su arte y sus habilidades son propias.
                                if (piece is GhostKnight) continue;
                                if (!knight.IsTransformed)
                                {
                                    knight.IsTransformed = true;
                                    boardView.TriggerKnightForkTransformation(pos);
                                    Debug.Log($"[GameManager] ¡FORK DETECTADO! El Caballo Blanco en ({pos.Row}, {pos.Col}) se ha transformado.");
                                }
                                else
                                {
                                    boardView.TriggerKnightForkTransformation(pos);
                                }
                            }
                            else
                            {
                                if (knight.IsTransformed)
                                {
                                    knight.IsTransformed = false;
                                    boardView.RevertKnightForkTransformation(pos);
                                    Debug.Log($"[GameManager] El Caballo Blanco en ({pos.Row}, {pos.Col}) ya no está en Fork. Vuelve a la normalidad.");
                                }
                            }
                        }
                    }
                }
            }
            return anyFork;
        }

        // ── Algebraic Notation Generator ──────────────────────────────────────

        private static readonly string[] FileNames = { "a", "b", "c", "d", "e", "f", "g", "h" };
        private static readonly string[] RankNames = { "1", "2", "3", "4", "5", "6", "7", "8" };
        private static readonly string[] PieceSymbols = {
            "", "", "N", "B", "R", "Q", "K"
        };

        /// <summary>Generates standard algebraic notation for a move.</summary>
        private string GenerateMoveNotation(ChessPiece piece, Vector2IntCustom from, Vector2IntCustom to, ChessPiece captured)
        {
            if (piece == null) return "?";

            // Castling
            if (piece.Type == PieceType.King && Mathf.Abs(to.Col - from.Col) == 2)
            {
                return to.Col == 6 ? "O-O" : "O-O-O";
            }

            string notation = "";
            string pieceLetter = PieceSymbols[(int)piece.Type];
            string toSquare = FileNames[to.Col] + RankNames[to.Row];

            if (piece.Type == PieceType.Pawn)
            {
                // Pawn capture: include source file
                if (captured != null || to.Col != from.Col)
                {
                    notation = FileNames[from.Col] + "x" + toSquare;
                }
                else
                {
                    notation = toSquare;
                }

                // Promotion
                if (to.Row == 0 || to.Row == 7)
                {
                    notation += "=Q"; // Default promote to queen
                }
            }
            else
            {
                // Disambiguation: check if another piece of same type can reach same square
                string disambig = "";
                bool needFile = false, needRank = false;

                for (int r = 0; r < Board.BOARD_SIZE; r++)
                {
                    for (int c = 0; c < Board.BOARD_SIZE; c++)
                    {
                        if (r == from.Row && c == from.Col) continue;
                        ChessPiece other = board.GetPieceAt(new Vector2IntCustom(r, c));
                        // La propia pieza puede haber cambiado de casilla (Salto de
                        // Niebla): nunca debe contarse como una segunda pieza.
                        if (other != null && other != piece && other.Type == piece.Type && other.Team == piece.Team)
                        {
                            var otherMoves = other.GetLegalMoves(board);
                            if (otherMoves.Contains(to))
                            {
                                if (c != from.Col) needFile = true;
                                else if (r != from.Row) needRank = true;
                                else { needFile = true; needRank = true; }
                            }
                        }
                    }
                }

                if (needFile) disambig += FileNames[from.Col];
                if (needRank) disambig += RankNames[from.Row];

                string capture = captured != null ? "x" : "";
                notation = pieceLetter + disambig + capture + toSquare;
            }

            // Check / Checkmate
            TeamColor nextTeam = (piece.Team == TeamColor.White) ? TeamColor.Black : TeamColor.White;
            if (board.IsInCheck(nextTeam))
            {
                if (!board.HasAnyLegalMove(nextTeam))
                    notation += "#";
                else
                    notation += "+";
            }

            return notation;
        }

        private bool IsMoveAFork(Vector2IntCustom targetSquare)
        {
            ChessPiece piece = board.GetPieceAt(targetSquare);
            if (piece != null && piece.Type == PieceType.Knight)
            {
                Knight knight = piece as Knight;
                if (knight != null)
                {
                    return knight.CheckIsFork(board, targetSquare);
                }
            }
            return false;
        }

        public void Deselect()
        {
            SelectedPiece = null;
            ValidMovesForSelected = null;
            _pendingCondemnRook = null;
            // La Posesión aún no movió nada: cancelarla al deseleccionar es seguro.
            // El Salto de Niebla NO se limpia aquí: su continuación cierra el turno
            // y borrarlo sin ejecutarla dejaría la partida bloqueada.
            _pendingPossessionKnight = null;
            _pendingPossessionTargets = null;
            if (boardView != null) boardView.ClearOverlays();
        }

        private void EndTurn()
        {
            //  Peones Espectrales frágiles — pierden 1 turno de vida cada EndTurn, al llegar a 0 se desvanecen
            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    var sp = board.GetPieceAt(new Vector2IntCustom(r, c)) as WilderGambit.Pieces.SpectralPawn;
                    if (sp != null)
                    {
                        sp.TurnsToFade--;
                        if (sp.TurnsToFade <= 0)
                        {
                            Debug.Log($"[SpectralPawn] Se desvanece en ({r},{c}) por fragilidad");
                            board.SetPieceAt(new Vector2IntCustom(r, c), null);
                            boardView?.RemovePieceView(new Vector2IntCustom(r, c));
                        }
                    }
                }
            }
            // Refrescar vistas si hubo desvanecimientos
            boardView?.RefreshNecromancerIndicators(board);

            // ── Torre Fragua: mechas de Sentencia y cuentas de Tributo ──
            // ANTES del flip: la mecha corre en el turno del bando condenado (CurrentTurn
            // sigue siendo ese) y las quemas deben aplicarse antes de comprobar el
            // jaque/mate del nuevo turno. Va después de RefreshNecromancerIndicators
            // para que los toasts de la Fragua no se borren con los del Nigromante.
            TickFragua();

            CurrentTurn = (CurrentTurn == TeamColor.White) ? TeamColor.Black : TeamColor.White;
            Debug.Log($"Turno de: {CurrentTurn}");

            // Explosión de Calabaza: el aturdimiento del bando que empieza su
            // turno se descuenta antes de comprobar jaque/mate (una pieza
            // aturdida no puede moverse, pero sí sigue amenazando).
            TickStuns(CurrentTurn);

            // El reloj pasa al bando contrario (con incremento si lo tiene).
            // En entrenamiento no hay reloj corriendo, así que el switch es un no-op.
            GameClock.Instance?.SwitchClock();

            // Registrar posición para Triple Repetición
            string currentFen = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn);
            string[] fenParts = currentFen.Split(' ');
            string positionKey = fenParts.Length >= 3 ? $"{fenParts[0]} {fenParts[1]} {fenParts[2]}" : currentFen;
            if (_positionHistory.ContainsKey(positionKey))
                _positionHistory[positionKey]++;
            else
                _positionHistory[positionKey] = 1;

            // ── Entrenamiento táctico: sin IA y sin final de partida ──
            // El turno ya cambió arriba; aquí solo se encadena la réplica guionada
            // del rival o se carga el siguiente puzzle.
            if (_trainingMode)
            {
                HandleTrainingTurn();
                return;
            }

            bool isInCheck = board.IsInCheck(CurrentTurn);
            bool hasLegalMoves = board.HasAnyLegalMove(CurrentTurn);

            // 1. Jaque y Jaque Mate
            if (isInCheck)
            {
                Debug.Log($"¡JAQUE al Rey {CurrentTurn}!");
                Vector2IntCustom kingPos = board.FindKing(CurrentTurn);
                bool eclipseMateCandidate = !hasLegalMoves && boardView != null && boardView.HasEclipseEternoEquipped;
                if (!eclipseMateCandidate && boardView != null) boardView.PlayKingCheckAnimation(kingPos);

                // «Doble Filo»: si dos piezas dan jaque a la vez, FX propio (opt-out).
                if (DoubleCheckFx.CountAttackers(board, kingPos, CurrentTurn) >= 2)
                    DoubleCheckFx.PlayAt(kingPos);

                if (!hasLegalMoves)
                {
                    bool isWhiteWinner = (CurrentTurn == TeamColor.Black);
                    Debug.Log($"¡¡JAQUE MATE!! Ganador: {(isWhiteWinner ? "Blancas (White)" : "Negras (Black)")}");

                    // Dynamic Difficulty: registrar racha
                    DynamicDifficultyManager.RecordResult(isWin: isWhiteWinner, isDraw: false, currentDifficulty);

                    string title = isWhiteWinner ? "🏆 ¡VICTORIA!" : "💀 ¡DERROTA!";
                    string subtitle = isWhiteWinner
                        ? "¡Has vencido a la IA por Jaque Mate!"
                        : "El Rey Blanco ha recibido Jaque Mate.";
                    Color color = isWhiteWinner
                        ? new Color(0.95f, 0.85f, 0.25f)
                        : new Color(0.95f, 0.30f, 0.30f);
                    MatchOutcome outcome = isWhiteWinner ? MatchOutcome.Victory : MatchOutcome.Defeat;

                    // Eclipse Eterno: la muerte del Rey se ve antes del game-over.
                    System.Action showGameOver = () => ShowGameOver(title, subtitle, color, outcome);
                    if (eclipseMateCandidate && boardView.PlayEclipseMateAnimation(kingPos, showGameOver))
                        return;

                    // Si el arte no cargó, cae al jaque normal y cierra la partida ya.
                    if (eclipseMateCandidate && boardView != null)
                        boardView.PlayKingCheckAnimation(kingPos);
                    showGameOver();
                    return;
                }
            }
            // 2. Tablas por Rey Ahogado (Stalemate)
            else if (!hasLegalMoves)
            {
                Debug.Log("¡TABLAS POR REY AHOGADO (Stalemate)! El Rey no está en jaque pero no tiene movimientos legales.");
                DynamicDifficultyManager.RecordResult(isWin: false, isDraw: true, currentDifficulty);
                ShowGameOver("🤝 ¡TABLAS!", "Empate por Rey Ahogado (Stalemate).", new Color(0.45f, 0.75f, 0.95f), MatchOutcome.Draw);
                return;
            }
            // 3. Tablas por Material Insuficiente
            else if (board.IsInsufficientMaterial())
            {
                Debug.Log("¡TABLAS POR MATERIAL INSUFICIENTE! Ningún bando tiene piezas suficientes para forzar el mate.");
                DynamicDifficultyManager.RecordResult(isWin: false, isDraw: true, currentDifficulty);
                ShowGameOver("🤝 ¡TABLAS!", "Empate por Material Insuficiente.", new Color(0.45f, 0.75f, 0.95f), MatchOutcome.Draw);
                return;
            }
            // 4. Tablas por Triple Repetición
            else if (_positionHistory[positionKey] >= 3)
            {
                Debug.Log("¡TABLAS POR TRIPLE REPETICIÓN! La misma posición se ha repetido 3 veces en la partida.");
                DynamicDifficultyManager.RecordResult(isWin: false, isDraw: true, currentDifficulty);
                ShowGameOver("🤝 ¡TABLAS!", "Empate por Triple Repetición de posición.", new Color(0.45f, 0.75f, 0.95f), MatchOutcome.Draw);
                return;
            }
            // 5. Tablas por Regla de los 50 Movimientos
            else if (_halfmoveClock >= 100)
            {
                Debug.Log("¡TABLAS POR REGLA DE LOS 50 MOVIMIENTOS!");
                DynamicDifficultyManager.RecordResult(isWin: false, isDraw: true, currentDifficulty);
                ShowGameOver("🤝 ¡TABLAS!", "Empate por la Regla de los 50 Movimientos.", new Color(0.45f, 0.75f, 0.95f), MatchOutcome.Draw);
                return;
            }

            if (CurrentTurn == TeamColor.Black && IsGameActive)
            {
                StartCoroutine(MakeAIMoveCoroutine());
            }
        }

        private void ShowGameOver(string title, string subtitle, Color color, MatchOutcome outcome)
        {
            // En entrenamiento táctico no hay final de partida: la sesión se cierra sola
            if (_trainingMode)
            {
                Debug.Log("[GameManager] Fin de estado ignorado: sesión de entrenamiento activa.");
                return;
            }

            IsGameActive = false;
            IsPaused = false;

            // Un Salto de Niebla o una Posesión pendientes no deben quedar vivos
            // sobre la pantalla de fin de partida.
            ClearPendingVariantModes();

            // «Ceniza al Viento»: FX de derrota, opt-out (nunca rompe el game-over).
            if (outcome == MatchOutcome.Defeat)
                DefeatFx.PlayDefeat();

            // Stop the clock if running
            if (Core.GameClock.Instance != null)
                Core.GameClock.Instance.Stop();

            // ── Economía: la tabla y los modificadores viven en MatchRewards, el cobro
            //    (con topes diarios) en GambitEconomy. Blindado: una sola vez por partida.
            MatchContext ctx = BuildMatchContext(outcome);
            var breakdown = new MatchBreakdown { BalanceAfter = PieceSkinManager.GetLocalGambits() };
            if (!_matchRewardPaid)
            {
                _matchRewardPaid = true;
                breakdown = MatchRewards.Settle(ctx);
            }

            // Misiones, barra semanal y logros se enteran del resultado
            GameEvents.RaiseMatchFinished(BuildMatchSummary(ctx));
            GambitProgress.NotifyChanged();

            if (WilderGambit.UI.GameOverModal.Instance == null)
            {
                GameObject modalObj = new GameObject("GameOverModal");
                modalObj.AddComponent<WilderGambit.UI.GameOverModal>();
            }

            // Pass analytics if available
            Core.GameAnalytics analytics = null;
            if (Core.GameAnalytics.Instance != null)
                analytics = Core.GameAnalytics.Instance;

            WilderGambit.UI.GameOverModal.Instance.Show(
                title,
                subtitle,
                color,
                onPlayAgain: () => RestartGame(),
                onMainMenu: () => ReturnToMainMenu(),
                analytics: analytics,
                rewardGambits: breakdown.Granted,
                balanceGambits: breakdown.BalanceAfter,
                breakdown: breakdown
            );
        }

        // ─── Economía: contexto y resumen de la partida ──────────────────────

        /// <summary>Todo lo que la economía necesita saber de esta partida.</summary>
        private MatchContext BuildMatchContext(MatchOutcome outcome)
        {
            int turns = TurnsPlayed();
            float accuracy = 0f;
            int blunders = 0;

            if (Core.GameAnalytics.Instance != null)
            {
                Core.GameAnalytics.Instance.ComputeStats();
                accuracy = Core.GameAnalytics.Instance.Accuracy;
                blunders = Core.GameAnalytics.Instance.BlunderCount;
            }

            return new MatchContext
            {
                level = currentDifficulty,
                outcome = outcome,
                totalTurns = turns,
                playerTurns = Mathf.Max(1, turns / 2),
                accuracy = accuracy,
                blunders = blunders,
                flawless = _playerLosses == 0,
                winStreak = WilderGambit.AI.DynamicDifficultyManager.WinStreak,
            };
        }

        /// <summary>Jugadas totales de la partida (ambos bandos).</summary>
        private int TurnsPlayed()
        {
            if (Core.GameAnalytics.Instance != null && Core.GameAnalytics.Instance.TotalMoves > 0)
                return Core.GameAnalytics.Instance.TotalMoves;

            // Sin analíticas: se asume una partida normal para no bloquear el cobro
            return GambitEconomyConfig.Instance.minTurnsToReward;
        }

        /// <summary>Resumen para misiones, barra semanal y logros.</summary>
        private MatchSummary BuildMatchSummary(MatchContext ctx)
        {
            return new MatchSummary
            {
                level = ctx.level,
                outcome = ctx.outcome,
                totalTurns = ctx.totalTurns,
                playerTurns = ctx.playerTurns,
                accuracy = ctx.accuracy,
                blunders = ctx.blunders,
                playerCaptures = _playerCaptures,
                playerLosses = _playerLosses,
                lostQueen = _lostQueen,
                usedLancer = PieceLoadoutManager.UsesLancerPawn(TeamColor.White),
                usedNecromancer = PieceLoadoutManager.UsesNecromancerBishop(TeamColor.White),
            };
        }

        // ─── Entrenamiento táctico y desafío diario ──────────────────────────

        /// <summary>Se dispara al terminar una sesión de entrenamiento.</summary>
        public event System.Action<TrainingSummary> OnTrainingSessionFinished;

        private bool _dailyChallengeRun = false;

        /// <summary>¿La sesión activa es el desafío diario y no un entrenamiento libre?</summary>
        public bool IsDailyChallengeRun => _dailyChallengeRun;

        /// <summary>Arranca una sesión de N puzzles. Devuelve false si no hay puzzles.</summary>
        public bool StartTrainingSession(int count = 5)
        {
            PuzzleManager.EnsureExists();
            var pm = PuzzleManager.Instance;
            if (pm == null)
            {
                Debug.LogWarning("[GameManager] No hay PuzzleManager: no se puede entrenar.");
                return false;
            }

            var first = pm.StartSession(count);
            if (first == null) return false;

            BeginTrainingMode(first, dailyChallenge: false);
            return true;
        }

        /// <summary>Arranca el reto diario (un puzzle, paga racha). False si ya se hizo hoy.</summary>
        public bool StartDailyChallenge()
        {
            DailyChallenge.EnsureExists();
            PuzzleManager.EnsureExists();

            var pm = PuzzleManager.Instance;
            var dc = DailyChallenge.Instance;
            if (pm == null || dc == null || !dc.IsAvailable) return false;

            var puzzle = pm.StartDailyChallengePuzzle(dc.GetDailyPuzzle());
            if (puzzle == null) return false;

            BeginTrainingMode(puzzle, dailyChallenge: true);
            return true;
        }

        /// <summary>Cancela la sesión sin cobrar (el jugador sale al menú).</summary>
        public void AbortTrainingSession()
        {
            if (!_trainingMode) return;

            PuzzleManager.Instance?.StopPuzzleMode();
            _trainingMode = false;
            _dailyChallengeRun = false;
            _trainingPuzzleId = "";
            IsGameActive = false;
            Deselect();

            // Los puzzles se juegan sin reloj
            GameClock.Instance?.Stop();

            // Dejar la arena lista para la próxima partida
            if (boardView != null)
            {
                boardView.ClearOverlays();
                boardView.ResetBoard();
            }
            ResetHalloweenAbilityState();
            WilderGambit.UI.MoveHistoryPanel.Instance?.Clear();
            WilderGambit.View.MoveBadgeView.Instance?.ClearBadge();
            CurrentTurn = TeamColor.White;

            // Igual que al terminar: el HUD no se queda por encima del menú
            WilderGambit.UI.PauseMenuController.Instance?.HideGameHUD();

            // Salir de la partida es el momento típico de cerrar el juego: a disco ya
            Core.ProgressAutosave.Flush();
        }

        private void BeginTrainingMode(Puzzle puzzle, bool dailyChallenge)
        {
            _trainingMode = true;
            _dailyChallengeRun = dailyChallenge;
            _trainingPuzzleId = puzzle.id;
            IsGameActive = true;
            IsPaused = false;

            // Un puzzle no tiene reloj: se apaga el de la partida anterior
            GameClock.Instance?.Stop();

            if (boardView != null) boardView.ClearOverlays();
            if (WilderGambit.UI.PauseMenuController.Instance != null)
                WilderGambit.UI.PauseMenuController.Instance.ShowGameHUD();
            WilderGambit.Audio.MusicManager.Instance?.PlayBattleMusic();

            PrepareTrainingBoard(puzzle);
            Debug.Log($"[GameManager] {(dailyChallenge ? "Reto diario" : "Entrenamiento")} iniciado con {puzzle.id}.");
        }

        /// <summary>Carga la posición del puzzle en el tablero lógico y visual.</summary>
        private void PrepareTrainingBoard(Puzzle puzzle)
        {
            if (puzzle == null || board == null) return;

            WilderGambit.Engine.FenUtility.LoadPosition(puzzle.fen, board);
            CurrentTurn = FenTurn(puzzle.fen);
            _halfmoveClock = 0;
            _positionHistory.Clear();
            ResetFraguaState();
            ResetHalloweenAbilityState();

            if (boardView != null)
            {
                boardView.RebuildFromBoard();
                boardView.ClearOverlays();
            }

            if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                WilderGambit.UI.MoveHistoryPanel.Instance.Clear();

            // Un badge de la partida anterior no pinta nada sobre una posición de puzzle
            WilderGambit.View.MoveBadgeView.Instance?.ClearBadge();

            Deselect();
        }

        private static TeamColor FenTurn(string fen)
        {
            var parts = fen?.Split(' ');
            return parts != null && parts.Length > 1 && parts[1] == "b" ? TeamColor.Black : TeamColor.White;
        }

        /// <summary>
        /// Entrenamiento: la jugada del jugador solo se aplica si es la solución del puzzle.
        /// Un fallo no toca el tablero y avisa con un destello rojo.
        /// </summary>
        private bool ValidateTrainingMove(string playedUci)
        {
            var pm = PuzzleManager.Instance;
            if (pm == null || !pm.IsActive || pm.CurrentPuzzle == null) return false;

            // 1. La jugada que pide el puzzle
            if (pm.IsExpectedMove(playedUci))
            {
                pm.SubmitPlayerMove(playedUci);
                return true;
            }

            // 2. Otro mate también resuelve el puzzle: el objetivo es la posición,
            //    no repetir la línea guionada (si no, encontrar un mate distinto
            //    contaba como fallo y podía dar el reto por perdido)
            if (IsCheckmateMove(playedUci))
            {
                pm.AcceptAlternateSolution(playedUci);
                return true;
            }

            // 3. Fallo
            pm.RegisterWrongMove(playedUci);

            var (_, to) = WilderGambit.Engine.FenUtility.UciToMove(playedUci);
            boardView?.PlayInvalidMoveFlash(to);
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            Deselect();

            // Dos fallos pierden el puzzle: PuzzleManager ya pasó al siguiente
            if (pm.CurrentPuzzle == null) FinishTrainingSession();
            else if (pm.CurrentPuzzle.id != _trainingPuzzleId)
            {
                _trainingPuzzleId = pm.CurrentPuzzle.id;
                PrepareTrainingBoard(pm.CurrentPuzzle);
            }
            return false;
        }

        /// <summary>¿La jugada da jaque mate en la posición actual del tablero?</summary>
        private bool IsCheckmateMove(string playedUci)
        {
            if (board == null) return false;

            var (from, to) = WilderGambit.Engine.FenUtility.UciToMove(playedUci);
            var piece = board.GetPieceAt(from);
            return piece != null && board.WouldBeCheckmate(piece, to);
        }

        /// <summary>
        /// Se llama al final del turno en modo entrenamiento: aplica la réplica guionada
        /// del rival y encadena el siguiente puzzle (o cierra la sesión).
        /// </summary>
        private void HandleTrainingTurn()
        {
            var pm = PuzzleManager.Instance;
            if (!_trainingMode || pm == null || !pm.IsActive)
            {
                FinishTrainingSession();
                return;
            }

            if (pm.AwaitingScriptedReply)
            {
                // Primero se mira la jugada, se juega y solo entonces se avanza el guion:
                // si la réplica no encaja con la posición, el puzzle se descarta en vez de
                // mover una pieza a lo bruto (o de dar por resuelto el puzzle siguiente).
                string reply = pm.GetNextSolutionMove();
                if (!string.IsNullOrEmpty(reply))
                {
                    if (ApplyScriptedReply(reply)) pm.ConsumeScriptedReply();
                    else pm.DiscardCurrentPuzzle($"réplica guionada ilegal ({reply})");
                }
            }

            if (pm.CurrentPuzzle == null)
            {
                FinishTrainingSession();
                return;
            }

            if (pm.CurrentPuzzle.id != _trainingPuzzleId)
            {
                _trainingPuzzleId = pm.CurrentPuzzle.id;
                PrepareTrainingBoard(pm.CurrentPuzzle);
            }
        }

        /// <summary>
        /// Aplica en el tablero la jugada guionada del rival (sin IA). Devuelve false si el
        /// guion no se puede jugar en la posición alcanzada (pieza que no está, le toca al
        /// otro bando, camino bloqueado o deja al rey en jaque).
        /// </summary>
        private bool ApplyScriptedReply(string uciMove)
        {
            var (from, to) = WilderGambit.Engine.FenUtility.UciToMove(uciMove);
            ChessPiece movingPiece = board.GetPieceAt(from);
            if (movingPiece == null)
            {
                Debug.LogWarning($"[GameManager] Réplica guionada imposible: no hay pieza en {uciMove}.");
                return false;
            }

            // El guion del puzzle se escribió para una posición concreta: si no encaja con la
            // que hay en el tablero hay que negarse a jugarla. Sin esta comprobación la pieza
            // se movía igualmente, atravesando lo que tuviera por medio: la dama "salía" de
            // un jaque doble pasando por encima del caballo que la atacaba.
            if (movingPiece.Team != CurrentTurn || !movingPiece.GetLegalMoves(board).Contains(to))
            {
                Debug.LogWarning($"[GameManager] Réplica guionada ilegal ({uciMove}): el guion no encaja con la posición actual.");
                return false;
            }

            ChessPiece targetPiece = board.GetPieceAt(to);
            board.MovePiece(from, to);
            boardView?.MovePieceView(from, to);
            WilderGambit.Audio.MusicManager.Instance?.PlayPieceMoveSound();

            string notation = GenerateMoveNotation(movingPiece, from, to, targetPiece);
            WilderGambit.UI.MoveHistoryPanel.Instance?.RecordMove(notation, movingPiece.Team);
            Core.GameAnalytics.Instance?.RecordMove(notation, movingPiece.Team, Core.MoveQuality.Good, 0f);

            CurrentTurn = movingPiece.Team == TeamColor.White ? TeamColor.Black : TeamColor.White;
            Deselect();
            return true;
        }

        /// <summary>Cierra la sesión, avisa a la UI y deja el tablero como estaba.</summary>
        private void FinishTrainingSession()
        {
            var pm = PuzzleManager.Instance;
            var summary = new TrainingSummary
            {
                dailyChallenge = _dailyChallengeRun && PuzzleManager.Instance != null,
                // Práctica de verdad: se resolvió algo y ni un solo puzzle cayó dentro del cupo
                practice = pm != null && pm.SessionPaidPuzzles == 0 && pm.SessionSolved > 0,
                target = pm != null ? pm.SessionTarget : 0,
                resolved = pm != null ? pm.SessionResolved : 0,
                solved = pm != null ? pm.SessionSolved : 0,
                gambits = pm != null ? pm.SessionGambits : 0,
                rating = pm != null ? pm.PlayerRating : 1000,
                reward = _dailyChallengeRun && DailyChallenge.Instance != null ? DailyChallenge.Instance.PendingReward : 0,
            };

            pm?.StopPuzzleMode();
            _trainingMode = false;
            _dailyChallengeRun = false;
            _trainingPuzzleId = "";
            IsGameActive = false;
            Deselect();

            // Los puzzles no se juegan con reloj
            GameClock.Instance?.Stop();

            // Fuera el HUD de partida: historial, deshacer y HABILIDADES no pintan nada
            // encima del menú (una partida normal ya lo oculta al volver al menú)
            WilderGambit.UI.PauseMenuController.Instance?.HideGameHUD();

            // Dejar la arena lista para la próxima partida
            boardView?.ResetBoard();
            ResetHalloweenAbilityState();
            WilderGambit.UI.MoveHistoryPanel.Instance?.Clear();
            CurrentTurn = TeamColor.White;

            // Al cerrar la sesión, todo lo ganado tiene que estar ya en disco
            Core.ProgressAutosave.Flush();

            Debug.Log($"[GameManager] Sesión terminada: {summary.solved}/{summary.resolved} resueltos · +{summary.gambits}G.");
            OnTrainingSessionFinished?.Invoke(summary);
        }

        // ─── Pausa en partida (panel de pausa / ESC) ─────────────────────────

        public void PauseGame()
        {
            if (IsPaused) return;
            IsPaused = true;
            IsGameActive = false; // Bloquea input del tablero y movimientos de la IA
            GameClock.Instance?.Pause(); // el reloj se congela: la pausa no debe costar tiempo
        }

        public void ResumeGame()
        {
            if (!IsPaused) return;
            IsPaused = false;
            IsGameActive = true;
            GameClock.Instance?.Resume();
        }

        // ── Undo System ──────────────────────────────────────────────────────

        private void SaveUndoState()
        {
            if (_undoStack.Count >= MAX_UNDO)
            {
                // Remove oldest entry (convert to array, skip first, rebuild stack)
                var arr = _undoStack.ToArray();
                _undoStack.Clear();
                for (int i = arr.Length - 1; i >= 1; i--)
                    _undoStack.Push(arr[i]);
            }

            _undoStack.Push(new UndoState
            {
                fen = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn),
                turn = CurrentTurn,
                halfmoveClock = _halfmoveClock,
                necroData = CaptureNecroData(),
                lancerData = CaptureLancerData(),
                riderData = CaptureRiderData(),
                vampireData = CaptureVampireData(),
                fragaData = CaptureFragaData(),
                shopVariantData = CaptureHalloweenShopVariants(),
                stunData = CaptureStunData(),
                pumpkinData = CapturePumpkinData()
            });
        }

        /// <summary>Serializa los Nigromantes del tablero (casilla + cargas de alma) para el Undo.</summary>
        private string CaptureNecroData()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(r, c)) is WilderGambit.Pieces.NecromancerBishop necro)
                    {
                        if (sb.Length > 0) sb.Append(',');
                        sb.Append(r * Board.BOARD_SIZE + c).Append(':').Append(necro.SoulCharges);
                    }
                }
            return sb.ToString();
        }

        /// <summary>
        /// Tras cargar el FEN (que reconstruye Alfiles base), reemplaza las casillas
        /// guardadas por su variante Nigromante y restaura sus cargas de alma.
        /// Crea el GameObject lógico SIN visuals: RebuildFromBoard se encarga del
        /// sprite de variante y de la skin equipada correctos.
        /// </summary>
        private void RestoreNecroVariants(string necroData)
        {
            if (board == null || string.IsNullOrEmpty(necroData)) return;

            foreach (string entry in necroData.Split(','))
            {
                int sep = entry.IndexOf(':');
                if (sep <= 0) continue;
                if (!int.TryParse(entry.Substring(0, sep), out int idx)) continue;
                int charges = 0;
                int.TryParse(entry.Substring(sep + 1), out charges);

                int r = idx / Board.BOARD_SIZE;
                int c = idx % Board.BOARD_SIZE;
                if (r < 0 || r >= Board.BOARD_SIZE || c < 0 || c >= Board.BOARD_SIZE) continue;

                var pos = new Vector2IntCustom(r, c);
                var baseBishop = board.GetPieceAt(pos) as WilderGambit.Pieces.Bishop;
                if (baseBishop == null) continue; // ya es Nigromante u otra pieza

                var go = new GameObject($"Restore_Necro_{r}_{c}");
                go.transform.SetParent(board.transform);
                var necro = go.AddComponent<WilderGambit.Pieces.NecromancerBishop>();
                necro.Init(baseBishop.Team, pos);
                necro.HasMoved = baseBishop.HasMoved;
                if (charges > 0) necro.AddCharges(charges);
                board.SetPieceAt(pos, necro);
                Destroy(baseBishop.gameObject);
            }
        }

        /// <summary>Serializa los Peones Lancero del tablero (casillas) para el Undo.</summary>
        private string CaptureLancerData()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(r, c)) is WilderGambit.Pieces.LancerPawn)
                    {
                        if (sb.Length > 0) sb.Append(',');
                        sb.Append(r * Board.BOARD_SIZE + c);
                    }
                }
            return sb.ToString();
        }

        /// <summary>
        /// Tras cargar el FEN (que reconstruye Peones base), reemplaza las casillas
        /// guardadas por su variante Lancero. Mismo patrón que RestoreNecroVariants:
        /// crea el GameObject lógico SIN visuals; RebuildFromBoard se encarga del sprite.
        /// </summary>
        private void RestoreLancerVariants(string lancerData)
        {
            if (board == null || string.IsNullOrEmpty(lancerData)) return;

            foreach (string entry in lancerData.Split(','))
            {
                if (!int.TryParse(entry, out int idx)) continue;

                int r = idx / Board.BOARD_SIZE;
                int c = idx % Board.BOARD_SIZE;
                if (r < 0 || r >= Board.BOARD_SIZE || c < 0 || c >= Board.BOARD_SIZE) continue;

                var pos = new Vector2IntCustom(r, c);
                var basePawn = board.GetPieceAt(pos) as WilderGambit.Pieces.Pawn;
                if (basePawn == null) continue; // otra pieza
                if (basePawn is WilderGambit.Pieces.LancerPawn) continue; // ya restaurado
                if (basePawn is WilderGambit.Pieces.SpectralPawn) continue; // el Espectral no es Lancero

                var go = new GameObject($"Restore_Lancer_{r}_{c}");
                go.transform.SetParent(board.transform);
                var lancer = go.AddComponent<WilderGambit.Pieces.LancerPawn>();
                lancer.Init(basePawn.Team, pos);
                lancer.HasMoved = basePawn.HasMoved;
                board.SetPieceAt(pos, lancer);
                Destroy(basePawn.gameObject);
            }
        }

        /// <summary>Serializa las Damas Jinete (casilla + Cabalgada disponible) para el Undo.</summary>
        private string CaptureRiderData()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(r, c)) is WilderGambit.Pieces.RiderQueen rider)
                    {
                        if (sb.Length > 0) sb.Append(',');
                        sb.Append(r * Board.BOARD_SIZE + c).Append(':').Append(rider.RideAvailable ? 1 : 0);
                    }
                }
            return sb.ToString();
        }

        /// <summary>
        /// Tras cargar el FEN (que reconstruye Damas base), reemplaza las casillas
        /// guardadas por su variante Jinete con su estado de Cabalgada. Mismo patrón
        /// que RestoreLancerVariants: crea el GameObject lógico SIN visuals;
        /// RebuildFromBoard se encarga del sprite.
        /// </summary>
        private void RestoreRiderVariants(string riderData)
        {
            if (board == null || string.IsNullOrEmpty(riderData)) return;

            foreach (string entry in riderData.Split(','))
            {
                string[] parts = entry.Split(':');
                if (parts.Length != 2 || !int.TryParse(parts[0], out int idx)) continue;

                int r = idx / Board.BOARD_SIZE;
                int c = idx % Board.BOARD_SIZE;
                if (r < 0 || r >= Board.BOARD_SIZE || c < 0 || c >= Board.BOARD_SIZE) continue;

                var pos = new Vector2IntCustom(r, c);
                var baseQueen = board.GetPieceAt(pos) as WilderGambit.Pieces.Queen;
                if (baseQueen == null) continue; // otra pieza
                if (baseQueen is WilderGambit.Pieces.RiderQueen) continue; // ya restaurado

                var go = new GameObject($"Restore_Rider_{r}_{c}");
                go.transform.SetParent(board.transform);
                var rider = go.AddComponent<WilderGambit.Pieces.RiderQueen>();
                rider.Init(baseQueen.Team, pos);
                rider.HasMoved = baseQueen.HasMoved;
                rider.RideAvailable = parts[1] == "1";
                board.SetPieceAt(pos, rider);
                Destroy(baseQueen.gameObject);
            }
        }

        // ─── Reina Vampira: pasiva «No Muerta» ───────────────────────────────

        /// <summary>Orden de renacimiento: centro hacia afuera (d, c, e, b, f, a, g, h).</summary>
        private static readonly int[] VampireRespawnColumns = { 3, 2, 4, 1, 5, 0, 6, 7 };

        /// <summary>
        /// Si la Reina Vampira acaba de ser capturada y todavía puede renacer, la
        /// devuelve a la primera fila de su bando (centro hacia afuera). La vista
        /// debe haberse separado antes con BoardView.DetachPieceView.
        /// La casilla debe estar libre y no puede dar jaque al bando capturador:
        /// esa jugada habría dejado a su propio rey en jaque.
        /// Devuelve true si volvió al tablero.
        /// </summary>
        private bool TryRespawnVampire(WilderGambit.Pieces.VampireQueen vampire)
        {
            if (vampire == null || !vampire.CanRise) return false;

            // El bando que acaba de capturar no puede quedar en jaque: su jugada
            // habría sido ilegal y EndTurn solo valida al bando que mueve después.
            TeamColor capturer = vampire.Team == TeamColor.White ? TeamColor.Black : TeamColor.White;
            int row = vampire.Team == TeamColor.White ? 0 : Board.BOARD_SIZE - 1;
            Vector2IntCustom deathSquare = vampire.Position;
            var spawn = new Vector2IntCustom(-1, -1);
            bool onlyCheckSquares = false;

            foreach (int col in VampireRespawnColumns)
            {
                var sq = new Vector2IntCustom(row, col);
                if (board.GetPieceAt(sq) != null) continue;

                // Prueba la casilla en el tablero lógico y descártala si la
                // vampira daría jaque al capturador desde ahí.
                board.SetPieceAt(sq, vampire);
                bool checksCapturer = board.IsInCheck(capturer);
                board.SetPieceAt(sq, null);
                vampire.Position = deathSquare;

                if (checksCapturer)
                {
                    onlyCheckSquares = true;
                    continue;
                }

                spawn = sq;
                break;
            }

            if (spawn.Row < 0)
            {
                // Sin casilla libre (o todas darían jaque): la No Muerta cae para siempre.
                Debug.Log(onlyCheckSquares
                    ? $"[VampireQueen] Primera fila de {vampire.Team} sin casilla legal (daría jaque): no renace."
                    : $"[VampireQueen] Primera fila de {vampire.Team} llena: no renace.");
                boardView?.DiscardDetachedPieceView(vampire.gameObject);
                boardView?.ShowVampireToast(deathSquare, onlyCheckSquares
                    ? "LA REINA VAMPIRA NO PUEDE RENACER DANDO JAQUE"
                    : "LA REINA VAMPIRA NO ENCUENTRA SANGRE");
                WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
                return false;
            }

            board.SetPieceAt(spawn, vampire);
            vampire.MarkRisen();
            vampire.HasMoved = true;
            boardView?.AttachPieceView(spawn, vampire.gameObject);
            boardView?.ShowVampireToast(spawn, "LA REINA VAMPIRA RENACE");
            Debug.Log($"[VampireQueen] {vampire.Team} renace en ({spawn.Row},{spawn.Col}).");
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
            return true;
        }

        /// <summary>Serializa las Reinas Vampiras (casilla + si ya renació) para el Undo.</summary>
        private string CaptureVampireData()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(r, c)) is WilderGambit.Pieces.VampireQueen vampire)
                    {
                        if (sb.Length > 0) sb.Append(',');
                        sb.Append(r * Board.BOARD_SIZE + c).Append(':').Append(vampire.HasRisen ? 1 : 0);
                    }
                }
            return sb.ToString();
        }

        /// <summary>
        /// Tras cargar el FEN (que reconstruye Damas base), repone las Reinas
        /// Vampiras con su estado de No Muerta. Se llama DESPUÉS de las Jinete:
        /// si datos viejos solaparan ambas variantes en una casilla, gana la Vampira.
        /// </summary>
        private void RestoreVampireVariants(string vampireData)
        {
            if (board == null || string.IsNullOrEmpty(vampireData)) return;

            foreach (string entry in vampireData.Split(','))
            {
                string[] parts = entry.Split(':');
                if (parts.Length != 2 || !int.TryParse(parts[0], out int idx)) continue;

                int r = idx / Board.BOARD_SIZE;
                int c = idx % Board.BOARD_SIZE;
                if (r < 0 || r >= Board.BOARD_SIZE || c < 0 || c >= Board.BOARD_SIZE) continue;

                var pos = new Vector2IntCustom(r, c);
                var baseQueen = board.GetPieceAt(pos) as WilderGambit.Pieces.Queen;
                if (baseQueen == null) continue; // otra pieza
                bool risen = parts[1] == "1";

                if (baseQueen is WilderGambit.Pieces.VampireQueen existing)
                {
                    existing.RestoreState(risen);
                    continue; // ya restaurada
                }

                var go = new GameObject($"Restore_Vampire_{r}_{c}");
                go.transform.SetParent(board.transform);
                var vampire = go.AddComponent<WilderGambit.Pieces.VampireQueen>();
                vampire.Init(baseQueen.Team, pos);
                vampire.HasMoved = baseQueen.HasMoved;
                vampire.RestoreState(risen);
                board.SetPieceAt(pos, vampire);
                Destroy(baseQueen.gameObject);
            }
        }

        /// <summary>
        /// Serializa las variantes de la tienda de la velada que hay en el tablero
        /// (Peón Calabaza y Caballo Fantasma) para el Undo.
        /// Formato: «casilla:tipo,...» con tipo p/n y casilla = row*8+col.
        /// </summary>
        private string CaptureHalloweenShopVariants()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    char kind = '\0';
                    ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (piece is WilderGambit.Pieces.PumpkinPawn) kind = 'p';
                    else if (piece is WilderGambit.Pieces.GhostKnight) kind = 'n';
                    if (kind == '\0') continue;

                    if (sb.Length > 0) sb.Append(',');
                    sb.Append(r * Board.BOARD_SIZE + c).Append(':').Append(kind);

                    // El Caballo Fantasma guarda además sus dos usos (1 = disponible).
                    if (kind == 'n' && piece is WilderGambit.Pieces.GhostKnight ghost)
                    {
                        sb.Append(':').Append(ghost.MistStepAvailable ? 1 : 0)
                          .Append(':').Append(ghost.PossessionAvailable ? 1 : 0);
                    }
                }
            return sb.ToString();
        }

        /// <summary>
        /// Tras cargar el FEN (que reconstruye las piezas base), devuelve a sus casillas
        /// las variantes de la tienda: Peón Calabaza (p) y Caballo Fantasma (n). Mismo
        /// patrón que RestoreLancerVariants: crea el GameObject lógico SIN visuals;
        /// RebuildFromBoard pone el arte y la skin correctos.
        /// Ni el Lancero/Espectral (Peón) ni el Nigromante (Alfil) se pisan.
        /// </summary>
        private void RestoreHalloweenShopVariants(string shopData)
        {
            if (board == null || string.IsNullOrEmpty(shopData)) return;

            foreach (string entry in shopData.Split(','))
            {
                string[] parts = entry.Split(':');
                if (parts.Length < 2 || parts[1].Length == 0) continue;
                if (!int.TryParse(parts[0], out int idx)) continue;

                int r = idx / Board.BOARD_SIZE;
                int c = idx % Board.BOARD_SIZE;
                if (r < 0 || r >= Board.BOARD_SIZE || c < 0 || c >= Board.BOARD_SIZE) continue;

                var pos = new Vector2IntCustom(r, c);
                ChessPiece basePiece = board.GetPieceAt(pos);
                if (basePiece == null) continue;

                // El Caballo Fantasma ya existe (restauración previa): recuperar sus usos.
                if (basePiece is WilderGambit.Pieces.GhostKnight existingGhost && parts[1][0] == 'n')
                {
                    bool mist = parts.Length < 3 || parts[2] == "1";
                    bool poss = parts.Length < 4 || parts[3] == "1";
                    existingGhost.RestoreAbilities(mist, poss);
                    continue;
                }

                // Ya es una variante de la tienda: nada que reponer
                if (basePiece is WilderGambit.Pieces.PumpkinPawn ||
                    basePiece is WilderGambit.Pieces.GhostKnight) continue;

                char kind = parts[1][0];
                string name;
                WilderGambit.Pieces.Pawn basePawn = null;
                WilderGambit.Pieces.Knight baseKnight = null;

                if (kind == 'p')
                {
                    basePawn = basePiece as WilderGambit.Pieces.Pawn;
                    if (basePawn == null) continue;                              // otra pieza
                    if (basePawn is WilderGambit.Pieces.LancerPawn) continue;    // el Lancero manda
                    if (basePawn is WilderGambit.Pieces.SpectralPawn) continue;  // el Espectral manda
                    name = "PumpkinPawn";
                }
                else if (kind == 'n')
                {
                    baseKnight = basePiece as WilderGambit.Pieces.Knight;
                    if (baseKnight == null) continue;                            // otra pieza
                    name = "GhostKnight";
                }
                else continue;

                var go = new GameObject($"Restore_{name}_{r}_{c}");
                go.transform.SetParent(board.transform);

                ChessPiece variant;
                if (basePawn != null)
                {
                    var pumpkin = go.AddComponent<WilderGambit.Pieces.PumpkinPawn>();
                    pumpkin.Init(basePawn.Team, pos);
                    pumpkin.HasMoved = basePawn.HasMoved;
                    variant = pumpkin;
                }
                else if (baseKnight != null)
                {
                    var ghost = go.AddComponent<WilderGambit.Pieces.GhostKnight>();
                    ghost.Init(baseKnight.Team, pos);
                    ghost.HasMoved = baseKnight.HasMoved;
                    // Datos antiguos de dos partes: ambos usos disponibles.
                    bool mist = parts.Length < 3 || parts[2] == "1";
                    bool poss = parts.Length < 4 || parts[3] == "1";
                    ghost.RestoreAbilities(mist, poss);
                    variant = ghost;
                }
                else continue;

                board.SetPieceAt(pos, variant);
                Destroy(basePiece.gameObject);
            }
        }

        /// <summary>Serializa los aturdimientos activos: «casilla:turnos:justo,...».</summary>
        private string CaptureStunData()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (piece == null || piece.StunTurns <= 0) continue;

                    if (sb.Length > 0) sb.Append(',');
                    sb.Append(r * Board.BOARD_SIZE + c).Append(':')
                      .Append(piece.StunTurns).Append(':')
                      .Append(piece.StunJustApplied ? 1 : 0);
                }
            return sb.ToString();
        }

        /// <summary>Restaura los aturdimientos después de reponer las variantes.</summary>
        private void RestoreStunData(string stunData)
        {
            if (board == null || string.IsNullOrEmpty(stunData)) return;

            foreach (string entry in stunData.Split(','))
            {
                string[] parts = entry.Split(':');
                if (parts.Length < 2) continue;
                if (!int.TryParse(parts[0], out int idx)) continue;
                if (!int.TryParse(parts[1], out int turns)) continue;

                int r = idx / Board.BOARD_SIZE;
                int c = idx % Board.BOARD_SIZE;
                if (r < 0 || r >= Board.BOARD_SIZE || c < 0 || c >= Board.BOARD_SIZE) continue;

                ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                if (piece == null) continue;

                piece.StunTurns = Mathf.Max(0, turns);
                piece.StunJustApplied = parts.Length >= 3 && parts[2] == "1";
            }
        }

        /// <summary>Serializa las cargas de explosión por bando: «blanco:negro».</summary>
        private string CapturePumpkinData()
        {
            return (_pumpkinExplodedWhite ? "1" : "0") + ":" + (_pumpkinExplodedBlack ? "1" : "0");
        }

        /// <summary>Restaura las cargas de explosión por bando.</summary>
        private void RestorePumpkinData(string pumpkinData)
        {
            _pumpkinExplodedWhite = false;
            _pumpkinExplodedBlack = false;
            if (string.IsNullOrEmpty(pumpkinData)) return;

            string[] parts = pumpkinData.Split(':');
            if (parts.Length >= 1) _pumpkinExplodedWhite = parts[0] == "1";
            if (parts.Length >= 2) _pumpkinExplodedBlack = parts[1] == "1";
        }

        /// <summary>Undoes the last player move + AI response (2 half-moves).</summary>
        public void UndoLastMove()
        {
            if (!IsGameActive || IsPaused) return;

            // En entrenamiento el deshacer rompería el guión del puzzle
            if (_trainingMode)
            {
                Debug.Log("[GameManager] El entrenamiento táctico no permite deshacer.");
                return;
            }
            if (_undoStack.Count < 2)
            {
                Debug.Log("[GameManager] No hay movimientos para deshacer.");
                return;
            }

            // Un modo de variante pendiente se cancela antes de restaurar.
            ClearPendingVariantModes();

            // Pop AI move state
            _undoStack.Pop();
            // Pop player move state — this is what we restore
            UndoState restore = _undoStack.Pop();

            // Restore board from FEN
            WilderGambit.Engine.FenUtility.LoadPosition(restore.fen, board);
            CurrentTurn = restore.turn;
            _halfmoveClock = restore.halfmoveClock;

            // El FEN no codifica variantes: reponer Nigromantes y sus cargas de alma
            RestoreNecroVariants(restore.necroData);
            // El FEN no codifica variantes: reponer Peones Lancero
            RestoreLancerVariants(restore.lancerData);
            // El FEN no codifica variantes: reponer Damas Jinete y su Cabalgada
            RestoreRiderVariants(restore.riderData);
            // El FEN no codifica variantes: reponer Reinas Vampiras y su No Muerta
            RestoreVampireVariants(restore.vampireData);
            // El FEN no codifica la Fragua: brasas, sentencias, tributos e indultos
            // (reconstruye también las Torres Fragua a partir de las Torres base del FEN)
            RestoreFragaData(restore.fragaData);
            // El FEN no codifica las variantes de la tienda de la velada
            RestoreHalloweenShopVariants(restore.shopVariantData);
            // Aturdimientos de la Explosión de Calabaza y cargas por bando
            RestoreStunData(restore.stunData);
            RestorePumpkinData(restore.pumpkinData);

            // Rebuild visual board from logical state
            if (boardView != null)
            {
                boardView.RebuildFromBoard();
            }

            // Clear selection
            Deselect();
            _positionHistory.Clear();

            // El reloj vuelve al turno restaurado (sin cobrar incremento: la jugada
            // ya se contabilizó al hacerse y deshacer no es una jugada nueva).
            GameClock.Instance?.SyncTurn(CurrentTurn);

            // Refrescar panel de habilidades (evita datos obsoletos tras deshacer)
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();

            Debug.Log($"[GameManager] Movimiento deshecho. Turno: {CurrentTurn}");
        }

        private void SetupPiecesFromBoard()
        {
            // This is a simplified version — ResetBoard already sets up initial pieces
            // For a full undo, we'd need to parse the FEN and place pieces accordingly
            // For now, ResetBoard + re-setup is sufficient for the MVP
        }

        public void RestartGame()
        {
            // Si veníamos de un entrenamiento, cerrarlo antes de empezar partida
            AbortTrainingSession();

            if (boardView != null) boardView.ResetBoard();
            if (WilderGambit.Audio.MusicManager.Instance != null)
            {
                WilderGambit.Audio.MusicManager.Instance.PlayBattleMusic(forceAlternate: true);
            }
            StartGameWithDifficulty(currentDifficulty);
        }

        public void ReturnToMainMenu()
        {
            // Si veníamos de un entrenamiento, cerrarlo (sin cobrar) antes de salir
            AbortTrainingSession();

            IsGameActive = false;
            IsPaused = false;

            // El reloj se apaga al volver al menú: si no, seguiría descontando detrás
            // del menú y saltaría el "se acabó el tiempo" al entrar en la siguiente.
            GameClock.Instance?.Stop();

            // Ocultar el HUD de partida (Historial, Deshacer, HABILIDADES);
            // si no, queda visible encima del menú principal
            WilderGambit.UI.PauseMenuController.Instance?.HideGameHUD();

            if (boardView != null) boardView.ResetBoard();
            ResetHalloweenAbilityState();
            if (WilderGambit.View.MoveBadgeView.Instance != null)
            {
                WilderGambit.View.MoveBadgeView.Instance.ClearBadge();
            }

            if (WilderGambit.Audio.MusicManager.Instance != null)
            {
                WilderGambit.Audio.MusicManager.Instance.StopMusic();
            }

            var menu = FindAnyObjectByType<WilderGambit.UI.MainMenuController>();
            if (menu != null)
            {
                menu.ShowMainMenu();
            }
        }

        private System.Collections.IEnumerator MakeAIMoveCoroutine()
        {
            yield return new WaitForSeconds(0.4f);

            if (WilderGambit.AI.ChessAI.Instance != null && IsGameActive)
            {
                var (from, to) = WilderGambit.AI.ChessAI.Instance.GetBestMove(board);
                if (from.Row != -1 && to.Row != -1)
                {
                    ChessPiece movingPiece = board.GetPieceAt(from);
                    ChessPiece targetPiece = board.GetPieceAt(to);

                    // Actualizar reloj de 50 movimientos para IA
                    if ((movingPiece != null && movingPiece.Type == PieceType.Pawn) || targetPiece != null)
                    {
                        _halfmoveClock = 0;
                    }
                    else
                    {
                        _halfmoveClock++;
                    }

                    string fenBefore = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn);
                    string playedUci = WilderGambit.Engine.FenUtility.MoveToUci(from, to);

                    WilderGambit.AI.ChessAI.Instance.RecordMove(from, to);

                    // Reina Vampira capturada por la IA: separar su vista antes del
                    // movimiento para que no se destruya la pieza que debe renacer.
                    var capturedVampire = targetPiece as WilderGambit.Pieces.VampireQueen;
                    if (capturedVampire != null && capturedVampire.CanRise)
                        boardView.DetachPieceView(to);

                    board.MovePiece(from, to);
                    boardView.MovePieceView(from, to);
                    WilderGambit.Audio.MusicManager.Instance?.PlayPieceMoveSound();

                    // Pasiva «No Muerta» (también para la Vampira negra de la IA)
                    bool vampireRespawned = TryRespawnVampire(capturedVampire);

                    // Pasiva «Explosión de Calabaza»: también aturde a la IA.
                    TryPumpkinExplosion(targetPiece, movingPiece);

                    // Métricas de la partida: piezas que pierde el jugador
                    if (targetPiece != null && targetPiece.Team == TeamColor.White)
                    {
                        _playerLosses++;
                        // La Dama solo cuenta como perdida si no volvió al tablero
                        if (targetPiece.Type == PieceType.Queen && !vampireRespawned) _lostQueen = true;
                    }

                    // Record AI move in history panel
                    string aiNotation = GenerateMoveNotation(movingPiece, from, to, targetPiece);
                    if (WilderGambit.UI.MoveHistoryPanel.Instance != null)
                        WilderGambit.UI.MoveHistoryPanel.Instance.RecordMove(aiNotation, movingPiece.Team);

                    // Record AI analytics
                    if (Core.GameAnalytics.Instance != null)
                    {
                        Core.GameAnalytics.Instance.RecordMove(aiNotation, movingPiece.Team, Core.MoveQuality.Great, 0f);
                    }

                    // Coronación automática para IA a Dama
                    if (movingPiece != null && movingPiece.Type == PieceType.Pawn && (to.Row == 0 || to.Row == 7))
                    {
                        boardView.PromotePieceView(to, PieceType.Queen, CurrentTurn);
                        playedUci += "q";
                    }

                    CheckSpecialTransformations();
                    bool isFork = IsMoveAFork(to);
                    string fenAfter = WilderGambit.Engine.FenUtility.BoardToFen(board, CurrentTurn == TeamColor.White ? TeamColor.Black : TeamColor.White);
                    EvaluateMoveWithStockfish(fenBefore, fenAfter, playedUci, to, isCurrentMoveFork: isFork);

                    // Salto de Niebla de la IA: se resuelve antes de cerrar el turno.
                    TryAiMistStep(movingPiece, targetPiece != null);
                }
            }

            EndTurn();
        }

        private async void EvaluateMoveWithStockfish(
            string fenBefore,
            string fenAfter,
            string playedUci,
            Vector2IntCustom targetSquare,
            bool isCurrentMoveFork = false,
            bool isPieceSacrifice = false)
        {
            if (WilderGambit.Engine.StockfishEngine.Instance == null) return;

            // En entrenamiento la jugada ya la ha validado el puzzle: no hay veredicto que dar.
            // Si no, el motor juzgaba la propia solución del puzzle y le colgaba un "??" encima
            // (pasaba con el sacrificio de caballo en f7, que el motor no aprueba de entrada).
            if (_trainingMode) return;

            try
            {
                // 1. Analizar posición antes de la jugada (fuerza máxima depth 18)
                var beforeAnalysis = await WilderGambit.Engine.StockfishEngine.Instance.AnalyzePositionAsync(fenBefore, moveTimeMs: 300, maxDepth: 18);

                // 2. Analizar posición tras la jugada (fuerza máxima depth 18)
                var afterAnalysis = await WilderGambit.Engine.StockfishEngine.Instance.AnalyzePositionAsync(fenAfter, moveTimeMs: 300, maxDepth: 18);

                // 3. Clasificar la jugada
                var classification = WilderGambit.Engine.MoveEvaluator.ClassifyMove(
                    playedUci,
                    beforeAnalysis,
                    afterAnalysis,
                    isCurrentMoveFork: isCurrentMoveFork,
                    isPieceSacrifice: isPieceSacrifice
                );

                Debug.Log($"[Stockfish] Movimiento: {playedUci} | Clasificación: {classification} (Best: {beforeAnalysis.BestMove}, ScoreBefore: {beforeAnalysis.Centipawns:F2}, ScoreAfter: {-afterAnalysis.Centipawns:F2})");

                // 4. Actualizar GameAnalytics con evaluación real de Stockfish (Polish)
                if (Core.GameAnalytics.Instance != null && Core.GameAnalytics.Instance.TotalMoves > 0)
                {
                    float loss = beforeAnalysis.Centipawns - (-afterAnalysis.Centipawns);
                    var quality = Core.GameAnalytics.MapClassification(classification);
                    Core.GameAnalytics.Instance.UpdateLastMoveQuality(quality, loss);
                    Debug.Log($"[GameAnalytics] Actualizada calidad a {quality} con pérdida {loss:F1} cp");
                }

                // 5. Mostrar el Badge en el tablero
                if (WilderGambit.View.MoveBadgeView.Instance != null)
                {
                    WilderGambit.View.MoveBadgeView.Instance.DisplayBadge(targetSquare, classification);
                }

                // 5b. FX de jugada brillante (solo si el Destello Táctico está comprado y equipado)
                if (classification == WilderGambit.Engine.MoveClassification.Brilliant)
                {
                    try { WilderGambit.View.BrilliantFx.PlayAt(targetSquare); }
                    catch (System.Exception fxEx) { Debug.LogWarning("[GameManager] BrilliantFx skip: " + fxEx.Message); }
                }

                // 5c. FX de fork «Cometa Ígnea» (solo si está comprada y equipada)
                if (isCurrentMoveFork)
                {
                    try { WilderGambit.View.ForkCometFx.PlayAt(targetSquare); }
                    catch (System.Exception fxEx) { Debug.LogWarning("[GameManager] ForkCometFx skip: " + fxEx.Message); }
                }
            }
            catch (System.Exception ex)
            {
                Debug.LogWarning($"[GameManager] Error al evaluar jugada con Stockfish: {ex.Message}");
            }
        }

        // ─── Alfil Nigromante: Helpers ────────────────────────────────────────

        /// <summary>
        /// Recorre el tablero y notifica a todos los Alfil Nigromante del equipo aliado
        /// que una pieza aliada fue capturada (acumula 0.5 cargas por llamada).
        /// </summary>
        private void NotifyNecromancerAllyCaptured(TeamColor capturedTeam)
        {
            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (piece is WilderGambit.Pieces.NecromancerBishop necro && necro.Team == capturedTeam)
                    {
                        necro.OnAllyCaptured();
                        Debug.Log($"[GameManager] Nigromante en ({r},{c}) acumuló carga. Total: {necro.SoulCharges}");
                    }
                }
            }
        }

        /// <summary>
        /// Invoca un Peón Espectral en la casilla indicada, consume las cargas del Nigromante
        /// y NO consume el turno del jugador.
        /// </summary>
        private void TriggerResurrection(WilderGambit.Pieces.NecromancerBishop necromancer, Vector2IntCustom targetPos)
        {
            necromancer.ConsumeCharges();
            boardView.SpawnSpectralPawn(necromancer.Team, targetPos);
            _pendingResurrectionBishop = null;
            boardView.ClearOverlays();
            boardView.RefreshNecromancerIndicators(board);

            Debug.Log($"[GameManager] ¡Alzamiento Menor! Peón Espectral invocado en ({targetPos.Row},{targetPos.Col}). Cargas restantes: {necromancer.SoulCharges} consume turno)");

            Deselect();
            //  la resurrección ahora consume el turno
            EndTurn();
        }

        /// <summary>
        /// Permite al panel derecho activar la habilidad sin clickear la pieza en el tablero.
        /// </summary>
        public bool RequestResurrection(WilderGambit.Pieces.NecromancerBishop bishop)
        {
            if (bishop == null || !bishop.CanResurrect) return false;
            if (bishop.Team != CurrentTurn) return false;
            if (!IsGameActive || IsPaused) return false;
            if (_pendingResurrectionBishop != null) return false;
            if (_pendingMistKnight != null || _pendingPossessionKnight != null) return false;

            _pendingResurrectionBishop = bishop;
            var resSqs = bishop.GetResurrectionSquares(board);
            if (resSqs.Count == 0)
            {
                _pendingResurrectionBishop = null;
                return false;
            }
            var normalMoves = bishop.GetLegalMoves(board);
            boardView.ShowSelection(bishop.Position, normalMoves, board);
            foreach (var sq in resSqs) boardView.ShowResurrectionSquare(sq);
            boardView.ShowSoulReadyIndicator(bishop);
            SelectedPiece = bishop;
            ValidMovesForSelected = normalMoves;
            Debug.Log($"[GameManager] Modo resurrección activado desde panel para {bishop.Team} en {bishop.Position.Row},{bishop.Position.Col}");
            return true;
        }

        /// <summary>Expone el tablero para paneles UI.</summary>
        public Board GetBoard() => board;

        // ─── Torre Fragua: Sentencia de la Fragua ────────────────────────────

        /// <summary>Brasas disponibles del bando indicado (0..MaxSentencias, compartidas por bando).</summary>
        public int GetSentencias(TeamColor team) => team == TeamColor.White ? _sentenciasWhite : _sentenciasBlack;

        /// <summary>¿El bando tiene al menos una Sentencia para condenar?</summary>
        public bool HasSentencias(TeamColor team) => GetSentencias(team) > 0;

        /// <summary>+1 Sentencia (pasiva Brasas: al capturar Dama o Torre con la Torre Fragua, tope 3).</summary>
        private void AddSentencia(TeamColor team)
        {
            if (team == TeamColor.White)
            {
                if (_sentenciasWhite >= MaxSentencias) return;
                _sentenciasWhite++;
            }
            else
            {
                if (_sentenciasBlack >= MaxSentencias) return;
                _sentenciasBlack++;
            }
            Debug.Log($"[Fragua] Sentencia +1 → {team}: {GetSentencias(team)}/{MaxSentencias}");
            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
        }

        /// <summary>Vuelve al estado limpio de partida: brasas, sentencias, tributos e indultos.</summary>
        private void ResetFraguaState()
        {
            _pendingCondemnRook = null;
            _sentenciasWhite = 0;
            _sentenciasBlack = 0;
            _sentences.Clear();
            _loans.Clear();
            _indulted.Clear();
        }

        /// <summary>¿La pieza sigue en el tablero en su casilla? (detecta capturas, promociones y desvanecimientos).</summary>
        private bool IsPieceOnBoard(ChessPiece piece)
        {
            if (piece == null || board == null) return false;
            return board.GetPieceAt(piece.Position) == piece;
        }

        private static string PieceDisplayName(ChessPiece piece)
        {
            if (piece == null) return "pieza";
            switch (piece.Type)
            {
                case PieceType.Pawn:   return "Peón";
                case PieceType.Knight: return "Caballo";
                case PieceType.Bishop: return "Alfil";
                case PieceType.Rook:   return "Torre";
                case PieceType.Queen:  return "Dama";
                case PieceType.King:   return "Rey";
            }
            return "pieza";
        }

        /// <summary>
        /// Casillas válidas para condenar desde la torre dada: piezas enemigas (nunca el
        /// Rey) adyacentes (8 casillas) o en la misma fila/columna con camino libre a
        /// cualquier distancia. Excluye Indultadas y piezas bajo préstamo activo.
        /// </summary>
        public List<Vector2IntCustom> GetCondemnTargets(WilderGambit.Pieces.FraguaRook rook)
        {
            var targets = new List<Vector2IntCustom>();
            if (rook == null || board == null) return targets;

            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    var sq = new Vector2IntCustom(r, c);
                    ChessPiece p = board.GetPieceAt(sq);
                    if (p == null) continue;
                    if (p.Team == rook.Team) continue;   // no condena a su propio bando
                    if (p.Type == PieceType.King) continue; // el Rey nunca se condena
                    if (_indulted.Contains(p)) continue;
                    if (_loans.ContainsKey(p)) continue; // pieza prestando servicio en el bando condenador

                    int dr = Mathf.Abs(p.Position.Row - rook.Position.Row);
                    int dc = Mathf.Abs(p.Position.Col - rook.Position.Col);

                    if (dr <= 1 && dc <= 1)
                    {
                        targets.Add(sq); // adyacente
                        continue;
                    }
                    if (dr != 0 && dc != 0) continue; // solo misma fila o columna

                    // Línea recta con camino libre
                    int stepR = p.Position.Row > rook.Position.Row ? 1 : -1;
                    int stepC = p.Position.Col > rook.Position.Col ? 1 : -1;
                    int rr = rook.Position.Row + stepR;
                    int cc = rook.Position.Col + stepC;
                    bool clear = true;
                    while (rr != p.Position.Row || cc != p.Position.Col)
                    {
                        if (board.GetPieceAt(new Vector2IntCustom(rr, cc)) != null) { clear = false; break; }
                        rr += stepR;
                        cc += stepC;
                    }
                    if (clear) targets.Add(sq);
                }
            return targets;
        }

        /// <summary>Requisitos para entrar en modo sentencia: brasas, tu turno, sin jaque y con objetivos.</summary>
        private bool CanEnterCondemnMode(WilderGambit.Pieces.FraguaRook rook)
        {
            if (rook == null || board == null) return false;
            if (!HasSentencias(rook.Team)) return false;
            if (rook.Team != CurrentTurn) return false;
            if (board.IsInCheck(CurrentTurn)) return false; // no se puede condenar en jaque
            return GetCondemnTargets(rook).Count > 0;
        }

        /// <summary>Activa el modo sentencia sobre la torre: movimientos normales + objetivos de condena resaltados.</summary>
        private void EnterCondemnMode(WilderGambit.Pieces.FraguaRook rook)
        {
            _pendingCondemnRook = rook;
            var targets = GetCondemnTargets(rook);
            var normalMoves = rook.GetLegalMoves(board);
            boardView.ShowSelection(rook.Position, normalMoves, board);
            foreach (var sq in targets) boardView.ShowCondemnTarget(sq);
            boardView.ShowCondemnReadyIndicator(rook);
            SelectedPiece = rook;
            ValidMovesForSelected = normalMoves;
            Debug.Log($"[Fragua] Modo sentencia activado para {rook.Team} en ({rook.Position.Row},{rook.Position.Col}): {targets.Count} objetivo(s).");
        }

        /// <summary>Permite al panel derecho activar la condena sin clickear la pieza (espejo de RequestResurrection).</summary>
        public bool RequestCondemn(WilderGambit.Pieces.FraguaRook rook)
        {
            if (rook == null) return false;
            if (rook.Team != CurrentTurn) return false;
            if (!IsGameActive || IsPaused) return false;
            if (_pendingCondemnRook != null) return false;
            if (_pendingMistKnight != null || _pendingPossessionKnight != null) return false;
            if (!CanEnterCondemnMode(rook)) return false;

            EnterCondemnMode(rook);
            return true;
        }

        /// <summary>
        /// Ejecuta la condena sobre la pieza objetivo: gasta 1 Sentencia, cede el turno
        /// y decide el dueño (IA con heurística propia, humano con TributoModal) entre
        /// aceptar el Tributo o afrontar la mecha de SentenceFuse turnos.
        /// </summary>
        private void TriggerCondemn(WilderGambit.Pieces.FraguaRook rook, Vector2IntCustom targetPos)
        {
            ChessPiece target = board != null ? board.GetPieceAt(targetPos) : null;
            if (rook == null || target == null || !CanEnterCondemnMode(rook)
                || !GetCondemnTargets(rook).Contains(targetPos))
            {
                _pendingCondemnRook = null;
                if (boardView != null) boardView.ClearOverlays();
                Deselect();
                return;
            }

            // Estado pre-condena para deshacer (antes de gastar la Sentencia)
            SaveUndoState();

            if (rook.Team == TeamColor.White) _sentenciasWhite--; else _sentenciasBlack--;
            _pendingCondemnRook = null;
            boardView.ClearOverlays();
            Deselect();

            TeamColor condemnTeam = rook.Team;
            TeamColor ownerTeam = target.Team;
            string pieceName = PieceDisplayName(target);
            Debug.Log($"[Fragua] {condemnTeam} condena a {pieceName} en ({target.Position.Row},{target.Position.Col}).");

            bool aiOwns = vsAI && !_trainingMode && ownerTeam == TeamColor.Black && condemnTeam == TeamColor.White;
            if (aiOwns)
            {
                bool accept = AiAcceptsTribute(target, rook);
                Debug.Log($"[Fragua] IA {ownerTeam} responde al Tributo: {(accept ? "ACEPTA" : "DESAFÍA")}");
                ApplyCondemnation(target, rook, condemnTeam, accept);
                EndTurn();
            }
            else
            {
                // El dueño de la pieza condenada decide (partida 2 jugadores o rival humano)
                IsGameActive = false;
                if (WilderGambit.UI.TributoModal.Instance == null)
                {
                    GameObject modalObj = new GameObject("TributoModal");
                    modalObj.AddComponent<WilderGambit.UI.TributoModal>();
                }
                WilderGambit.UI.TributoModal.Instance.Show(ownerTeam, pieceName, accept =>
                {
                    IsGameActive = true;
                    ApplyCondemnation(target, rook, condemnTeam, accept);
                    EndTurn();
                });
            }
        }

        /// <summary>
        /// Heurística de la IA al ser condenada: afronta la mecha si puede cazar la
        /// torre condenadora el turno siguiente; si no, solo entrega piezas valiosas
        /// (Dama o Torre), que además ganan inmunidad al volver.
        /// </summary>
        private bool AiAcceptsTribute(ChessPiece target, WilderGambit.Pieces.FraguaRook rook)
        {
            bool canHuntRook = board.IsSquareAttacked(rook.Position, rook.Team);
            bool valuable = target.Type == PieceType.Queen || target.Type == PieceType.Rook;
            return valuable && !canHuntRook;
        }

        /// <summary>Aplica la decisión del dueño: Tributo (cambio de bando temporal) o Sentencia (mecha de 5).</summary>
        private void ApplyCondemnation(ChessPiece target, WilderGambit.Pieces.FraguaRook rook, TeamColor condemnTeam, bool acceptTribute)
        {
            if (target == null || rook == null) return;

            if (acceptTribute)
            {
                _loans[target] = new LoanInfo
                {
                    beneficiary = condemnTeam,
                    original = target.Team,
                    turnsLeft = LoanTurns,
                    skipFirstTick = true
                };
                target.SetTeam(condemnTeam);
                boardView?.RefreshPieceViewTeam(target);
                string loanMsg = $"TRIBUTO: {PieceDisplayName(target)} pelea por {condemnTeam} {LoanTurns} turnos y vuelve inmune";
                boardView?.ShowFraguaToast(target.Position, loanMsg);
                Debug.Log($"[Fragua] {loanMsg}.");
            }
            else
            {
                SentenceInfo s;
                if (_sentences.TryGetValue(target, out s))
                {
                    // Sentencia apilada: otra torre se suma a la mecha sin reiniciarla
                    if (!s.rooks.Contains(rook)) s.rooks.Add(rook);
                }
                else
                {
                    s = new SentenceInfo();
                    s.rooks.Add(rook);
                    _sentences[target] = s;
                }
                string sentenceMsg = $"SENTENCIADO: {PieceDisplayName(target)} arde en {s.fuse} turnos si no cazas la torre";
                boardView?.ShowFraguaToast(target.Position, sentenceMsg);
                Debug.Log($"[Fragua] {sentenceMsg} ({s.rooks.Count} torre(s) condenadora(s)).");
            }

            WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
        }

        /// <summary>
        /// Fin de turno: corre las mechas de las Sentencias del bando condenado
        /// (quema al llegar a 0 si queda ≥1 torre condenadora viva) y descuenta los
        /// turnos de los Tributos activos. Llamar con CurrentTurn = bando que acaba de jugar.
        /// </summary>
        private void TickFragua()
        {
            if (_sentences.Count == 0 && _loans.Count == 0) return;

            bool changed = false;

            // ── Sentencias: la mecha solo corre en el turno del bando condenado ──
            if (_sentences.Count > 0)
            {
                var toLift = new List<ChessPiece>();
                var toBurn = new List<ChessPiece>();

                foreach (var kv in _sentences)
                {
                    ChessPiece piece = kv.Key;
                    SentenceInfo s = kv.Value;

                    // Pieza fuera del tablero (capturada, promovida o desvanecida): purgar
                    if (!IsPieceOnBoard(piece)) { toLift.Add(piece); continue; }

                    // Torres condenadoras capturadas dejan de sostener la sentencia
                    s.rooks.RemoveAll(r => !IsPieceOnBoard(r));
                    if (s.rooks.Count == 0) { toLift.Add(piece); continue; }

                    if (piece.Team != CurrentTurn) continue; // turno de otro bando

                    s.fuse--;
                    if (s.fuse <= 0) toBurn.Add(piece);
                }

                foreach (var piece in toLift)
                {
                    bool alive = IsPieceOnBoard(piece);
                    _sentences.Remove(piece);
                    if (alive)
                    {
                        boardView?.ShowFraguaToast(piece.Position, "SENTENCIA LEVANTADA: cazaste todas sus torres");
                        Debug.Log($"[Fragua] Sentencia levantada sobre {PieceDisplayName(piece)} en ({piece.Position.Row},{piece.Position.Col}).");
                        changed = true;
                    }
                }

                foreach (var piece in toBurn)
                {
                    _sentences.Remove(piece);
                    BurnPiece(piece);
                    changed = true;
                }
            }

            // ── Tributos: 3 turnos completos del beneficiario (el de creación no cuenta) ──
            if (_loans.Count > 0)
            {
                var finished = new List<ChessPiece>();
                foreach (var kv in _loans)
                {
                    ChessPiece piece = kv.Key;
                    LoanInfo l = kv.Value;
                    if (!IsPieceOnBoard(piece)) { finished.Add(piece); continue; }
                    if (l.skipFirstTick) { l.skipFirstTick = false; continue; }
                    if (l.beneficiary != CurrentTurn) continue;
                    l.turnsLeft--;
                    if (l.turnsLeft <= 0) finished.Add(piece);
                }

                foreach (var piece in finished)
                {
                    LoanInfo l;
                    if (!_loans.TryGetValue(piece, out l)) continue;
                    _loans.Remove(piece);
                    if (!IsPieceOnBoard(piece)) continue; // capturado durante el servicio
                    piece.SetTeam(l.original);
                    _indulted.Add(piece);
                    boardView?.RefreshPieceViewTeam(piece);
                    boardView?.ShowFraguaToast(piece.Position, $"{PieceDisplayName(piece)} VUELVE A SU EJÉRCITO e INMUNE");
                    Debug.Log($"[Fragua] {PieceDisplayName(piece)} en ({piece.Position.Row},{piece.Position.Col}) vuelve a {l.original} e Indultado permanente.");
                    changed = true;
                }
            }

            if (changed) WilderGambit.UI.VariantAbilityPanel.Instance?.Refresh();
        }

        /// <summary>Quema una pieza sentenciada: la elimina del tablero lógico y visual e informa con toast.</summary>
        private void BurnPiece(ChessPiece piece)
        {
            if (piece == null) return;
            Vector2IntCustom sq = piece.Position;
            string name = PieceDisplayName(piece);
            if (board.GetPieceAt(sq) == piece) board.SetPieceAt(sq, null);
            boardView?.RemovePieceView(sq);
            boardView?.ShowFraguaToast(sq, $"{name} ARDE EN LA FRAGUA");
            Debug.Log($"[Fragua] {name} en ({sq.Row},{sq.Col}) consumida por la mecha.");
        }

        private static int SqIdx(Vector2IntCustom pos) => pos.Row * Board.BOARD_SIZE + pos.Col;

        /// <summary>
        /// Serializa el estado de la Fragua para Undo: brasas, torres Fragua, sentencias,
        /// tributos e indultos. Formato: secciones «X:...» separadas por '|', entradas por
        /// ';' y campos por ':' (listas de casillas separadas por ',').
        /// </summary>
        private string CaptureFragaData()
        {
            if (board == null) return "";
            var sb = new System.Text.StringBuilder();
            sb.Append("S:").Append(_sentenciasWhite).Append(',').Append(_sentenciasBlack);

            // R: torres Fragua (el FEN las reload como Torre base)
            sb.Append("|R:");
            bool first = true;
            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    if (board.GetPieceAt(new Vector2IntCustom(r, c)) is WilderGambit.Pieces.FraguaRook)
                    {
                        if (!first) sb.Append(';');
                        sb.Append(SqIdx(new Vector2IntCustom(r, c)));
                        first = false;
                    }
                }

            // C: sentencias vivas «casilla:fuse:torres»
            sb.Append("|C:");
            first = true;
            foreach (var kv in _sentences)
            {
                if (!IsPieceOnBoard(kv.Key)) continue;
                if (!first) sb.Append(';');
                sb.Append(SqIdx(kv.Key.Position)).Append(':').Append(kv.Value.fuse).Append(':');
                for (int i = 0; i < kv.Value.rooks.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    sb.Append(SqIdx(kv.Value.rooks[i].Position));
                }
                first = false;
            }

            // L: tributos «casilla:original:beneficiario:turnos:saltaprimero»
            sb.Append("|L:");
            first = true;
            foreach (var kv in _loans)
            {
                if (!IsPieceOnBoard(kv.Key)) continue;
                if (!first) sb.Append(';');
                sb.Append(SqIdx(kv.Key.Position))
                  .Append(':').Append((int)kv.Value.original)
                  .Append(':').Append((int)kv.Value.beneficiary)
                  .Append(':').Append(kv.Value.turnsLeft)
                  .Append(':').Append(kv.Value.skipFirstTick ? 1 : 0);
                first = false;
            }

            // I: indultadas
            sb.Append("|I:");
            first = true;
            foreach (var p in _indulted)
            {
                if (!IsPieceOnBoard(p)) continue;
                if (!first) sb.Append(';');
                sb.Append(SqIdx(p.Position));
                first = false;
            }

            return sb.ToString();
        }

        /// <summary>
        /// Reconstruye el estado de la Fragua tras cargar el FEN de Undo. Debe llamarse
        /// DESPUÉS de restaurar las demás variantes y ANTES de RebuildFromBoard.
        /// </summary>
        private void RestoreFragaData(string fragaData)
        {
            _sentenciasWhite = 0;
            _sentenciasBlack = 0;
            _sentences.Clear();
            _loans.Clear();
            _indulted.Clear();
            _pendingCondemnRook = null;
            if (board == null || string.IsNullOrEmpty(fragaData)) return;

            foreach (string section in fragaData.Split('|'))
            {
                int sep = section.IndexOf(':');
                if (sep <= 0) continue;
                string key = section.Substring(0, sep);
                string body = section.Substring(sep + 1);

                if (key == "S")
                {
                    string[] counters = body.Split(',');
                    if (counters.Length >= 1) int.TryParse(counters[0], out _sentenciasWhite);
                    if (counters.Length >= 2) int.TryParse(counters[1], out _sentenciasBlack);
                    continue;
                }
                if (string.IsNullOrEmpty(body)) continue;

                switch (key)
                {
                    case "R": // el FEN trae Torre base: reconvertir a Fragua
                        foreach (string entry in body.Split(';'))
                        {
                            if (!int.TryParse(entry, out int idx)) continue;
                            int r = idx / Board.BOARD_SIZE, c = idx % Board.BOARD_SIZE;
                            var pos = new Vector2IntCustom(r, c);
                            var baseRook = board.GetPieceAt(pos) as WilderGambit.Pieces.Rook;
                            if (baseRook == null) continue;
                            if (baseRook is WilderGambit.Pieces.FraguaRook) continue;
                            var go = new GameObject($"Restore_Fragua_{r}_{c}");
                            go.transform.SetParent(board.transform);
                            var fragua = go.AddComponent<WilderGambit.Pieces.FraguaRook>();
                            fragua.Init(baseRook.Team, pos);
                            fragua.HasMoved = baseRook.HasMoved;
                            board.SetPieceAt(pos, fragua);
                            Destroy(baseRook.gameObject);
                        }
                        break;

                    case "C":
                        foreach (string entry in body.Split(';'))
                        {
                            string[] parts = entry.Split(':');
                            if (parts.Length < 3) continue;
                            if (!int.TryParse(parts[0], out int idx)) continue;
                            if (!int.TryParse(parts[1], out int fuse)) continue;
                            int r = idx / Board.BOARD_SIZE, c = idx % Board.BOARD_SIZE;
                            var piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                            if (piece == null) continue;
                            var s = new SentenceInfo { fuse = fuse };
                            foreach (string rookIdx in parts[2].Split(','))
                            {
                                if (!int.TryParse(rookIdx, out int ri)) continue;
                                var rookPiece = board.GetPieceAt(
                                    new Vector2IntCustom(ri / Board.BOARD_SIZE, ri % Board.BOARD_SIZE))
                                    as WilderGambit.Pieces.FraguaRook;
                                if (rookPiece != null && !s.rooks.Contains(rookPiece)) s.rooks.Add(rookPiece);
                            }
                            if (s.rooks.Count == 0) continue; // sin torres vivas: sentencia levantada
                            _sentences[piece] = s;
                        }
                        break;

                    case "L":
                        foreach (string entry in body.Split(';'))
                        {
                            string[] parts = entry.Split(':');
                            if (parts.Length < 5) continue;
                            if (!int.TryParse(parts[0], out int idx)) continue;
                            int r = idx / Board.BOARD_SIZE, c = idx % Board.BOARD_SIZE;
                            var piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                            if (piece == null) continue;
                            if (!int.TryParse(parts[1], out int orig)) continue;
                            if (!int.TryParse(parts[2], out int bene)) continue;
                            if (!int.TryParse(parts[3], out int turns)) continue;
                            _loans[piece] = new LoanInfo
                            {
                                original = (TeamColor)orig,
                                beneficiary = (TeamColor)bene,
                                turnsLeft = turns,
                                skipFirstTick = parts[4] == "1"
                            };
                        }
                        break;

                    case "I":
                        foreach (string entry in body.Split(';'))
                        {
                            if (!int.TryParse(entry, out int idx)) continue;
                            var piece = board.GetPieceAt(
                                new Vector2IntCustom(idx / Board.BOARD_SIZE, idx % Board.BOARD_SIZE));
                            if (piece != null) _indulted.Add(piece);
                        }
                        break;
                }
            }
        }
    }
}
