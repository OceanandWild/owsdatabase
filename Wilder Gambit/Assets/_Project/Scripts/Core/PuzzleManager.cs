using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    [System.Serializable]
    public class Puzzle
    {
        public string id;
        public string fen;
        public string[] solutionMoves; // UCI format
        public int difficulty;          // 1-3 (easy/medium/hard)
        public string theme;            // "mate", "fork", "pin", "skewer", "sacrifice"
        public string description;
    }

    /// <summary>
    /// Manages chess puzzles: loading, solving, rating, and progression.
    /// </summary>
    public class PuzzleManager : MonoBehaviour
    {
        public static PuzzleManager Instance { get; private set; }

        /// <summary>Puzzles que dura una sesión de entrenamiento estándar.</summary>
        public const int TrainingSessionSize = 5;

        /// <summary>Gambits base por puzzle resuelto: el mínimo (dificultad 1) y el máximo (3).</summary>
        public const int MinPuzzlePayout = 20;
        public const int MaxPuzzlePayout = 60;

        /// <summary>Gambits base que paga un puzzle según su dificultad, antes del medio pago por fallo.</summary>
        public static int PayoutForDifficulty(int difficulty) => difficulty switch
        {
            1 => MinPuzzlePayout,
            2 => 35,
            _ => MaxPuzzlePayout,
        };

        /// <summary>
        /// Puzzles con premio al día: una sesión de entrenamiento. Repetir está permitido —hay
        /// pocos puzzles y algunos son duros—, pero a partir del cupo la sesión es práctica: sin
        /// Gambits, sin rating y sin tocar la racha. El cupo se gasta por puzzle resuelto, no por
        /// sesión: abandonar a medias no lo quema y repetir no lo amplía, así que repetir no
        /// puede convertirse en un farmeo de Gambits.
        /// </summary>
        public const int DailyPaidPuzzles = TrainingSessionSize;

        private const string PAID_DAY_KEY = "PuzzlePaidDay";
        private const string PAID_COUNT_KEY = "PuzzlePaidPuzzles";

        /// <summary>Puzzles con premio que quedan hoy.</summary>
        public static int PaidPuzzlesLeftToday
        {
            get
            {
                int used = PlayerPrefs.GetString(PAID_DAY_KEY, "") == DailyChallenge.TodayKey
                    ? PlayerPrefs.GetInt(PAID_COUNT_KEY, 0)
                    : 0;

                // Red de seguridad: el libro diario también apunta los pagos del entrenamiento.
                // Si el contador se queda corto (un PlayerPrefs viejo o un borrado a medias),
                // el cupo se recalcula con lo ya cobrado hoy en vez de regalarse entero.
                int pagos = GambitLedger.PaymentsToday(GambitSource.Puzzle);
                if (pagos > used) used = Mathf.Min(pagos, DailyPaidPuzzles);

                return Mathf.Max(0, DailyPaidPuzzles - used);
            }
        }

        /// <summary>El cupo de hoy está agotado: entrenar sigue disponible, pero como práctica.</summary>
        public static bool DailyPaidTrainingUsed => PaidPuzzlesLeftToday <= 0;

        /// <summary>Gasta un puzzle del cupo de hoy. False si ya no queda cupo.</summary>
        private static bool ConsumePaidPuzzle()
        {
            int left = PaidPuzzlesLeftToday;
            if (left <= 0) return false;

            // Se guarda el cupo ya gastado (no el contador crudo): así el valor efectivo y el
            // guardado nunca se separan, ni siquiera cuando entró en juego la red de seguridad.
            PlayerPrefs.SetString(PAID_DAY_KEY, DailyChallenge.TodayKey);
            PlayerPrefs.SetInt(PAID_COUNT_KEY, DailyPaidPuzzles - left + 1);
            PlayerPrefs.Save();
            return true;
        }

        private List<Puzzle> _puzzles = new List<Puzzle>();
        private int _currentPuzzleIndex = 0;
        private int _currentMoveIndex = 0;
        private int _faults = 0;
        private bool _isActive = false;

        /// <summary>Puzzle resuelto (limpio = sin fallar ninguna jugada).</summary>
        public event System.Action<Puzzle, bool> OnPuzzleResolved;
        /// <summary>Jugada equivocada dentro de un puzzle (para feedback inmediato).</summary>
        public event System.Action<Puzzle> OnPuzzleMistake;
        /// <summary>Puzzle perdido tras dos fallos.</summary>
        public event System.Action<Puzzle> OnPuzzleLost;
        /// <summary>Puzzle descartado por datos incoherentes (no es culpa del jugador).</summary>
        public event System.Action<Puzzle, string> OnPuzzleDiscarded;

        public Puzzle CurrentPuzzle => _isActive && _currentPuzzleIndex < _puzzles.Count
            ? _puzzles[_currentPuzzleIndex] : null;
        public bool IsActive => _isActive;
        public int SolvedCount { get; private set; }
        public int TotalPuzzles => _puzzles.Count;

        /// <summary>Fase actual: los índices pares los juega el jugador, los impares son la réplica guionada.</summary>
        public int CurrentMoveIndex => _currentMoveIndex;
        public bool AwaitingScriptedReply => _isActive && CurrentPuzzle != null && (_currentMoveIndex % 2) == 1;
        public int FaultsThisPuzzle => _faults;

        // ── Sesión de entrenamiento ────────────────────────────────────────────
        private int _sessionTarget = TrainingSessionSize;
        private int _sessionResolved = 0;
        private int _sessionSolved = 0;
        private int _sessionGambits = 0;
        private bool _isDailyChallenge = false;
        /// <summary>Puzzles de esta sesión que cayeron dentro del cupo y cobraron de verdad.</summary>
        private int _sessionPaidPuzzles;

        /// <summary>La sesión activa es el reto diario (un puzzle con racha de días).</summary>
        public bool IsDailyChallenge => _isDailyChallenge;

        /// <summary>Puzzles de la sesión que cobraron (la UI lo usa para titular el resumen).</summary>
        public int SessionPaidPuzzles => _sessionPaidPuzzles;

        /// <summary>Este puzzle concreto cobra: queda cupo hoy (el reto diario no gasta cupo).</summary>
        private bool PuzzleCanPay => _isDailyChallenge || PaidPuzzlesLeftToday > 0;

        public int SessionTarget => _sessionTarget;
        public int SessionResolved => _sessionResolved;
        public int SessionSolved => _sessionSolved;
        public int SessionGambits => _sessionGambits;
        public bool SessionFinished => !_isActive || _currentPuzzleIndex >= Mathf.Min(_sessionTarget, _puzzles.Count);

        // ── Rachas de puzzles ─────────────────────────────────────────────────
        private const string RATING_KEY = "PuzzleRating";
        private const string STREAK_KEY = "PuzzleSolveStreak";
        private const string BEST_STREAK_KEY = "PuzzleBestStreak";

        public int PlayerRating
        {
            get => PlayerPrefs.GetInt(RATING_KEY, 1000);
            private set { PlayerPrefs.SetInt(RATING_KEY, value); PlayerPrefs.Save(); }
        }

        public int SolveStreak
        {
            get => PlayerPrefs.GetInt(STREAK_KEY, 0);
            private set { PlayerPrefs.SetInt(STREAK_KEY, value); PlayerPrefs.Save(); }
        }

        public int BestSolveStreak => PlayerPrefs.GetInt(BEST_STREAK_KEY, 0);

        /// <summary>Crea el manager si la escena no lo tiene (la vista de Progreso lo necesita).</summary>
        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("PuzzleManager");
            go.AddComponent<PuzzleManager>();
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            LoadPuzzles();
        }

        /// <summary>Arranca una sesión de entrenamiento de N puzzles.</summary>
        public Puzzle StartSession(int count = TrainingSessionSize)
        {
            // Garantiza el catálogo completo (el reto diario lo sustituye temporalmente)
            LoadPuzzles();
            _sessionTarget = Mathf.Clamp(count, 1, _puzzles.Count);
            _sessionResolved = 0;
            _sessionSolved = 0;
            _sessionGambits = 0;
            _sessionPaidPuzzles = 0;
            return StartPuzzleMode();
        }

        /// <summary>Starts puzzle mode with the next available puzzle.</summary>
        public Puzzle StartPuzzleMode()
        {
            _isDailyChallenge = false;

            // Se puede entrenar siempre: solo cobran los puzzles que entren en el cupo de hoy.
            // El cupo se gasta al resolver cada puzzle, así que empezar y abandonar no lo quema.
            Debug.Log(PaidPuzzlesLeftToday > 0
                ? $"[PuzzleManager] Entrenamiento con premio: quedan {PaidPuzzlesLeftToday}/{DailyPaidPuzzles} puzzles pagados hoy."
                : $"[PuzzleManager] Entrenamiento en práctica: el cupo de {DailyPaidPuzzles} puzzles con premio de hoy ya está gastado.");

            _isActive = true;
            _currentPuzzleIndex = 0;
            _currentMoveIndex = 0;
            SolvedCount = 0;
            LoadPuzzles();
            return CurrentPuzzle;
        }

        /// <summary>
        /// Arranca una sesión con un puzzle externo (el desafío diario): una sola posición
        /// y sin pagar por puzzle, porque el reto paga la racha al resolverse. No toca el
        /// catálogo de entrenamiento, que se recarga en la siguiente sesión.
        /// </summary>
        public Puzzle StartDailyChallengePuzzle(Puzzle puzzle)
        {
            if (puzzle == null) return null;

            _puzzles = new List<Puzzle> { puzzle };
            _sessionTarget = 1;
            _sessionResolved = 0;
            _sessionSolved = 0;
            _sessionGambits = 0;
            _sessionPaidPuzzles = 0;
            _faults = 0;
            _isDailyChallenge = true;   // el reto diario lleva su propio tope (uno al día)

            _isActive = true;
            _currentPuzzleIndex = 0;
            _currentMoveIndex = 0;
            SolvedCount = 0;
            return CurrentPuzzle;
        }

        /// <summary>
        /// Jugada del jugador dentro del puzzle. Devuelve true si es la correcta
        /// (y avanza); false si falla (no se aplica en el tablero).
        /// </summary>
        /// <summary>¿La jugada es la que pide el paso actual del puzzle?</summary>
        public bool IsExpectedMove(string uciMove)
        {
            if (!_isActive || CurrentPuzzle == null) return false;
            if (AwaitingScriptedReply) return false;   // toca la réplica guionada del rival

            var puzzle = CurrentPuzzle;
            return _currentMoveIndex < puzzle.solutionMoves.Length &&
                   uciMove == puzzle.solutionMoves[_currentMoveIndex];
        }

        /// <summary>
        /// Acepta la jugada guionada y avanza el puzzle. Solo se llama tras
        /// <see cref="IsExpectedMove"/>.
        /// </summary>
        public bool SubmitPlayerMove(string uciMove)
        {
            if (!IsExpectedMove(uciMove)) return false;

            var puzzle = CurrentPuzzle;
            _currentMoveIndex++;
            if (_currentMoveIndex >= puzzle.solutionMoves.Length) CompletePuzzle(puzzle);
            return true;
        }

        /// <summary>
        /// Resuelve el puzzle con una jugada válida distinta de la guionada (otro mate).
        /// El objetivo es la posición, no repetir la línea: si el jugador encuentra un mate
        /// antes de tiempo, el puzzle cuenta como resuelto.
        /// </summary>
        public bool AcceptAlternateSolution(string uciMove)
        {
            if (!_isActive || CurrentPuzzle == null) return false;

            var puzzle = CurrentPuzzle;
            Debug.Log($"[PuzzleManager] {puzzle.id} resuelto con un mate alternativo ({uciMove}).");
            _currentMoveIndex = puzzle.solutionMoves.Length;
            CompletePuzzle(puzzle);
            return true;
        }

        /// <summary>Jugada equivocada: cuenta un fallo y, al segundo, se pierde el puzzle.</summary>
        public void RegisterWrongMove(string uciMove)
        {
            if (!_isActive || CurrentPuzzle == null) return;

            var puzzle = CurrentPuzzle;
            _faults++;
            if (PuzzleCanPay) PlayerRating = Mathf.Max(100, PlayerRating - 10);   // en práctica no se toca el rating
            OnPuzzleMistake?.Invoke(puzzle);
            Debug.Log($"[PuzzleManager] Jugada incorrecta en {puzzle.id} (fallo {_faults}).");

            if (_faults >= 2) LosePuzzle(puzzle);
        }

        /// <summary>Réplica guionada del rival (si toca). Devuelve la jugada UCI y avanza.</summary>
        public string ConsumeScriptedReply()
        {
            if (!_isActive || CurrentPuzzle == null) return null;
            if ((_currentMoveIndex % 2) != 1) return null;

            var puzzle = CurrentPuzzle;
            if (_currentMoveIndex >= puzzle.solutionMoves.Length) return null;

            string move = puzzle.solutionMoves[_currentMoveIndex];
            _currentMoveIndex++;
            if (_currentMoveIndex >= puzzle.solutionMoves.Length) CompletePuzzle(puzzle);
            return move;
        }

        private void CompletePuzzle(Puzzle puzzle)
        {
            bool clean = _faults == 0;

            // Solo pagan los puzzles que entren en el cupo de hoy. El resto es práctica: ni
            // Gambits, ni rating, ni racha (con 30 puzzles y pago por puzzle, repetir era farmeo).
            bool pays = _isDailyChallenge || ConsumePaidPuzzle();

            SolvedCount++;
            _sessionResolved++;
            _sessionSolved++;
            if (pays) _sessionPaidPuzzles++;
            _faults = 0;

            int streak = SolveStreak;
            if (pays)
            {
                PlayerRating += 10 + (puzzle.difficulty * 5);
                Achievements.NotePuzzleRating(PlayerRating);

                streak = SolveStreak + 1;
                SolveStreak = streak;
                if (streak > BestSolveStreak)
                {
                    PlayerPrefs.SetInt(BEST_STREAK_KEY, streak);
                    PlayerPrefs.Save();   // la mejor racha tiene que estar en disco ya: si el juego se cierra de golpe, no se pierde
                }
            }

            if (!pays)
            {
                Debug.Log($"[PuzzleManager] {puzzle.id} resuelto{(clean ? " limpio" : "")} en práctica: el cupo de hoy ya está gastado y practicar no paga.");
            }
            else if (_isDailyChallenge)
            {
                // El reto diario paga su propia racha (50 → 100 según los días seguidos)
                int claimed = DailyChallenge.Instance != null ? DailyChallenge.Instance.CompleteDailyChallenge() : 0;
                _sessionGambits += claimed;
                Debug.Log($"[PuzzleManager] Reto diario resuelto{(clean ? " limpio" : "")}: +{claimed}G (rating {PlayerRating}).");
            }
            else
            {
                // Pago: por dificultad, mitad si hubo un fallo
                int baseAmount = PayoutForDifficulty(puzzle.difficulty);
                if (!clean) baseAmount = Mathf.Max(1, baseAmount / 2);

                var payout = GambitEconomy.Earn(baseAmount, GambitSource.Puzzle, meta: puzzle.id, note: puzzle.theme);
                _sessionGambits += payout.granted;

                // Bonus por racha de 5 puzzles limpios
                if (streak > 0 && streak % 5 == 0)
                {
                    var bonus = GambitEconomy.Earn(80, GambitSource.Puzzle, meta: $"streak{streak}", note: $"racha de {streak}");
                    _sessionGambits += bonus.granted;
                }

                Debug.Log($"[PuzzleManager] {puzzle.id} resuelto{(clean ? " limpio" : " con un fallo")}: +{payout.granted}G (rating {PlayerRating}).");
            }

            OnPuzzleResolved?.Invoke(puzzle, clean);
            GameEvents.RaisePuzzleSolved(puzzle, clean);

            _currentPuzzleIndex++;
            _currentMoveIndex = 0;
        }

        /// <summary>
        /// Descarta el puzzle actual cuando su guion no se puede jugar en la posición
        /// alcanzada (por ejemplo, una réplica guionada ilegal). No penaliza al jugador:
        /// no cuenta como fallo, no baja el rating y no paga. Consume su hueco de la
        /// sesión y deja listo el siguiente puzzle.
        /// </summary>
        public void DiscardCurrentPuzzle(string reason)
        {
            if (!_isActive || CurrentPuzzle == null) return;

            var puzzle = CurrentPuzzle;
            Debug.LogWarning($"[PuzzleManager] {puzzle.id} descartado: {reason}");
            _faults = 0;
            _sessionResolved++;
            OnPuzzleDiscarded?.Invoke(puzzle, reason);

            _currentPuzzleIndex++;
            _currentMoveIndex = 0;
        }

        private void LosePuzzle(Puzzle puzzle)
        {
            if (PuzzleCanPay) SolveStreak = 0;   // practicar no rompe la racha
            _faults = 0;
            _sessionResolved++;

            Debug.Log($"[PuzzleManager] {puzzle.id} perdido.");
            OnPuzzleLost?.Invoke(puzzle);
            GameEvents.RaisePuzzleFailed(puzzle);

            _currentPuzzleIndex++;
            _currentMoveIndex = 0;
        }

        public void ResetStreak()
        {
            SolveStreak = 0;
            PlayerPrefs.Save();
        }

        /// <summary>Gets the next expected move in UCI format.</summary>
        public string GetNextSolutionMove()
        {
            if (CurrentPuzzle == null || _currentMoveIndex >= CurrentPuzzle.solutionMoves.Length)
                return null;
            return CurrentPuzzle.solutionMoves[_currentMoveIndex];
        }

        /// <summary>Skips to the next puzzle.</summary>
        public Puzzle SkipPuzzle()
        {
            _currentPuzzleIndex++;
            _currentMoveIndex = 0;
            return CurrentPuzzle;
        }

        public void StopPuzzleMode()
        {
            _isActive = false;
            _isDailyChallenge = false;
            _faults = 0;
            _currentMoveIndex = 0;
        }

        private void LoadPuzzles()
        {
            _puzzles.Clear();

            // 30 built-in puzzles
            _puzzles.Add(new Puzzle { id = "p01", fen = "6k1/5ppp/8/8/8/8/5PPP/4R1K1 w - - 0 1", solutionMoves = new[] { "e1e8" }, difficulty = 1, theme = "mate", description = "Mate en 1: Torre a e8." });
            _puzzles.Add(new Puzzle { id = "p02", fen = "r1bqkb1r/pppp1ppp/2n2n2/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR w KQkq - 4 4", solutionMoves = new[] { "h5f7" }, difficulty = 1, theme = "mate", description = "Mate en 1: Dama a f7 (Scholar's Mate)." });
            _puzzles.Add(new Puzzle { id = "p03", fen = "r1bqkb1r/ppp2ppp/2n5/3np1N1/2B5/8/PPPP1PPP/RNBQK2R w KQkq - 0 6", solutionMoves = new[] { "g5f7", "e8f7", "d1f3" }, difficulty = 2, theme = "fork", description = "Fork de caballo en f7: la dama entra con jaque en f3." });
            _puzzles.Add(new Puzzle { id = "p04", fen = "2kr3r/ppp2ppp/2n1b3/1B2q3/4n3/2N2N2/PPP2PPP/R1BQK2R w KQ - 0 1", solutionMoves = new[] { "b5c6" }, difficulty = 1, theme = "pin", description = "Clavar el caballo con el alfil." });
            _puzzles.Add(new Puzzle { id = "p05", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2B1P3/3P1N2/PPP2PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4f7", "e8f7", "f3g5" }, difficulty = 2, theme = "sacrifice", description = "Sacrificio de alfil para ganar material." });
            _puzzles.Add(new Puzzle { id = "p06", fen = "6k1/4Qppp/8/8/8/8/5PPP/6K1 w - - 0 1", solutionMoves = new[] { "e7e8" }, difficulty = 1, theme = "mate", description = "Mate en 1: Dama a e8." });
            _puzzles.Add(new Puzzle { id = "p07", fen = "6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1", solutionMoves = new[] { "a1a8" }, difficulty = 1, theme = "mate", description = "Mate en 1: Torre a a8." });
            _puzzles.Add(new Puzzle { id = "p08", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2BPP3/5N2/PPP2PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "d4e5", "c6e5", "f3e5" }, difficulty = 2, theme = "fork", description = "Ganar una pieza rompiendo el centro." });
            _puzzles.Add(new Puzzle { id = "p09", fen = "2k5/8/2K5/8/8/8/8/7R w - - 0 1", solutionMoves = new[] { "h1h8" }, difficulty = 1, theme = "mate", description = "Mate en 1 con la torre." });
            _puzzles.Add(new Puzzle { id = "p10", fen = "rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq e3 0 1", solutionMoves = new[] { "e7e5", "g1f3", "b8c6", "f1b5" }, difficulty = 3, theme = "book", description = "Ruy López: las mejores 4 jugadas." });

            // Mate in 2 puzzles
            _puzzles.Add(new Puzzle { id = "p11", fen = "r1bqkb1r/pppp1ppp/2n2n2/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR w KQkq - 0 1", solutionMoves = new[] { "h5f7" }, difficulty = 2, theme = "mate", description = "Mate en 1: Dama a f7 (mate del pastor)." });
            _puzzles.Add(new Puzzle { id = "p12", fen = "6k1/5ppp/8/8/8/8/4QPPP/6K1 w - - 0 1", solutionMoves = new[] { "e2e8" }, difficulty = 1, theme = "mate", description = "Mate en 1 simple." });
            _puzzles.Add(new Puzzle { id = "p13", fen = "r1b1k2r/ppppqppp/2n2n2/2b1p3/2B1P3/3P1N2/PPP2PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4f7", "e8d8", "f7b3" }, difficulty = 2, theme = "sacrifice", description = "Sacrificio en f7: el rey sale a d8 y las blancas se quedan el peón." });
            _puzzles.Add(new Puzzle { id = "p14", fen = "6k1/5ppp/8/8/8/8/5PPP/3Q2RK w - - 0 1", solutionMoves = new[] { "d1d8" }, difficulty = 1, theme = "mate", description = "Mate en 1 con la dama." });
            _puzzles.Add(new Puzzle { id = "p15", fen = "2k5/8/2K5/8/8/8/8/7R w - - 0 1", solutionMoves = new[] { "h1h8" }, difficulty = 1, theme = "mate", description = "Mate en 1: Torre corridor." });

            // Fork puzzles
            _puzzles.Add(new Puzzle { id = "p16", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2B1P3/5N2/PPP1QPPP/RNB1K2R w KQkq - 0 1", solutionMoves = new[] { "f3e5", "c6e5", "e2h5" }, difficulty = 2, theme = "fork", description = "Ganar pieza con dama." });
            _puzzles.Add(new Puzzle { id = "p17", fen = "r1bqk2r/ppppnppp/2n5/2b1p3/2B1P3/5N2/PPPP1PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4f7", "e8f7", "f3g5" }, difficulty = 2, theme = "fork", description = "Fork de caballo en g5." });
            _puzzles.Add(new Puzzle { id = "p18", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/4P3/3P1N2/PPP2PPP/RNBQKB1R w KQkq - 0 1", solutionMoves = new[] { "f3e5", "c6e5", "d3d4" }, difficulty = 2, theme = "fork", description = "Ganar pieza central." });
            _puzzles.Add(new Puzzle { id = "p19", fen = "r1bqk2r/pppp1ppp/2n5/2b1p3/2B1Pn2/5N2/PPPP1PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4f7", "e8f7", "f3e5" }, difficulty = 2, theme = "fork", description = "Fork doble de alfil y caballo." });
            _puzzles.Add(new Puzzle { id = "p20", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2B1P3/2N2N2/PPPP1PPP/R1BQK2R w KQkq - 0 1", solutionMoves = new[] { "f3e5", "c6e5", "d1h5" }, difficulty = 2, theme = "fork", description = "Doble amenaza con dama: e5 y f7." });

            // Pin puzzles
            _puzzles.Add(new Puzzle { id = "p21", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2B1P3/3P1N2/PPP2PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c1g5" }, difficulty = 1, theme = "pin", description = "Clavar el caballo de f6." });
            _puzzles.Add(new Puzzle { id = "p22", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/4P3/3P1N2/PPP1BPPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c1g5" }, difficulty = 1, theme = "pin", description = "Pin: clava el caballo de f6 con el alfil de c1." });
            _puzzles.Add(new Puzzle { id = "p23", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2B1P3/5N2/PPPP1PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4b5" }, difficulty = 1, theme = "pin", description = "Pin al caballo de c6." });

            // Sacrifice puzzles
            _puzzles.Add(new Puzzle { id = "p24", fen = "r2qkbnr/ppp2ppp/2np4/4p2b/2B1P3/2N2N1P/PPP2PP1/RNBQK2R w KQkq - 0 6", solutionMoves = new[] { "f3e5", "h5d1", "c4f7" }, difficulty = 2, theme = "sacrifice", description = "Sacrificio de dama (Légal): el alfil remata en f7 con jaque." });
            _puzzles.Add(new Puzzle { id = "p25", fen = "r1bqk2r/pppp1ppp/2n2n2/2b1p3/2B1P3/3P1N2/PPP2PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4f7", "e8f7", "f3g5" }, difficulty = 2, theme = "sacrifice", description = "Ataque contra el rey sin enrocar." });
            _puzzles.Add(new Puzzle { id = "p26", fen = "r1bqk2r/pppp1ppp/2n5/2b1p3/2B1Pn2/5N2/PPPP1PPP/RNBQK2R w KQkq - 0 1", solutionMoves = new[] { "c4f7", "e8f7", "f3e5" }, difficulty = 2, theme = "sacrifice", description = "Ataque contra rey expuesto." });

            // Skewer puzzles
            // Los cuatro skewer son posiciones limpias de rey y una pieza en la misma línea:
            // jaque primero, captura de lo que queda detrás después. Antes el guion ponía al
            // rey en jaque con el turno del otro bando y "resolvía" capturando al rey.
            _puzzles.Add(new Puzzle { id = "p27", fen = "4r3/8/8/4k3/8/8/8/R5K1 w - - 0 1", solutionMoves = new[] { "a1e1", "e5d5", "e1e8" }, difficulty = 1, theme = "skewer", description = "Skewer al rey con la torre: captura la torre de detrás." });
            _puzzles.Add(new Puzzle { id = "p28", fen = "7q/8/8/4k3/8/8/3B1PP1/4K3 w - - 0 1", solutionMoves = new[] { "d2c3", "e5d5", "c3h8" }, difficulty = 1, theme = "skewer", description = "Skewer diagonal: alfil a c3 y captura la dama de h8." });
            _puzzles.Add(new Puzzle { id = "p29", fen = "8/8/8/3k3q/8/8/8/R5K1 w - - 0 1", solutionMoves = new[] { "a1a5", "d5d4", "a5h5" }, difficulty = 1, theme = "skewer", description = "Torre skewer: jaque en quinta y captura la dama." });
            _puzzles.Add(new Puzzle { id = "p30", fen = "1q6/8/8/4k3/8/8/5PP1/4K1B1 w - - 0 1", solutionMoves = new[] { "g1h2", "e5d5", "h2b8" }, difficulty = 1, theme = "skewer", description = "Alfil skewer: jaque en h2 y captura la dama de b8." });
        }
    }
}
