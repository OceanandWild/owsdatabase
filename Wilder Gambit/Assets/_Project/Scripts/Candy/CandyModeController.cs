using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.Services;
using WilderGambit.UI;

namespace WilderGambit.Candy
{
    /// <summary>
    /// Cerebro de la Cacería de Dulces: ciclo de vida, turnos, bot, reloj real
    /// de 5 minutos, matchmaking online y cobro de Dulces al terminar.
    ///
    /// La partida online no aplica las jugadas locales de inmediato: las manda
    /// al servidor y espera a que vuelvan por el log de acciones. Así los dos
    /// clientes simulan exactamente la misma secuencia y los Dulces aleatorios
    /// coinciden.
    /// </summary>
    public class CandyModeController : MonoBehaviour
    {
        public static CandyModeController Instance { get; private set; }

        private CandyModeView _view;
        private CandyModeBoard _board = new CandyModeBoard();

        private CandyGameMode _mode = CandyGameMode.None;
        private CandyPhase _phase = CandyPhase.Closed;
        private TeamColor _localSide = TeamColor.White;
        private CandyLoadout _localLoadout;
        private CandyLoadout _whiteLoadout;
        private CandyLoadout _blackLoadout;
        private string _remoteName = "";
        private string _matchId = "";
        private int _seed;
        private int _lastSeq;
        private bool _needFullSync;
        private bool _rewardGranted;
        private bool _botRoutineActive;
        private bool _onlineLoopActive;
        private bool _searchLoopActive;
        private DateTime _deadlineUtc;
        private CandyAction _pendingAction;
        private float _pendingSince;
        private float _lastTimerRefresh;
        private float _exitConfirmUntil;
        private string _statusText = "";
        private int _syncFailures;

        private int _selectedPieceId;
        private PieceType? _selectedHandType;
        private readonly List<Vector2IntCustom> _legalMoves = new List<Vector2IntCustom>();

        public CandyModeBoard Board => _board;
        public CandyGameMode Mode => _mode;
        public CandyPhase Phase => _phase;
        public TeamColor LocalSide => _localSide;
        public TeamColor RivalSide => _localSide == TeamColor.White ? TeamColor.Black : TeamColor.White;
        public string LocalName => CandyApi.PlayerName;
        public string OpponentName => _remoteName;
        public string StatusText => _statusText;
        public bool IsOpen => _phase != CandyPhase.Closed;
        public bool IsMyTurn => _board != null && _board.CurrentSide == _localSide;
        public bool IsPendingOnline => _pendingAction != null;
        public int SelectedPieceId => _selectedPieceId;
        public PieceType? SelectedHandType => _selectedHandType;
        public List<Vector2IntCustom> LegalMoves => _legalMoves;

        public float SecondsLeft
        {
            get
            {
                double seconds = (_deadlineUtc - DateTime.UtcNow).TotalSeconds;
                return seconds <= 0 ? 0f : (float)seconds;
            }
        }

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(this);
                return;
            }
            Instance = this;
            _board = new CandyModeBoard();
        }

        private void OnDestroy()
        {
            if (Instance == this) Instance = null;
        }

        public void Open()
        {
            if (_phase != CandyPhase.Closed) return;
            if (!HalloweenEvent.IsActiveNow)
            {
                Debug.LogWarning("[CandyMode] La Cacería de Dulces sólo está disponible durante la Velada.");
                return;
            }
            if (!EnsureView()) return;

            _phase = CandyPhase.Intro;
            SetMenuVisible(false);
            _view.ShowIntro();
        }

        public void ShowIntro()
        {
            if (_phase == CandyPhase.Closed) return;
            _phase = CandyPhase.Intro;
            ClearSelection();
            _statusText = "";
            _view.ShowIntro();
        }

        public void ShowDraft(bool online)
        {
            if (_phase == CandyPhase.Closed) return;
            if (!EnsureView()) return;
            if (!EnsureEventActive()) return;
            _phase = CandyPhase.Draft;
            ClearSelection();
            _statusText = "";
            _view.ShowDraft(online);
        }

        public void StartBot(CandyLoadout loadout)
        {
            if (!EnsureView()) return;
            if (!EnsureEventActive()) return;

            StopAllCoroutines();
            _botRoutineActive = false;
            _onlineLoopActive = false;
            _searchLoopActive = false;
            _syncFailures = 0;
            _mode = CandyGameMode.Bot;
            _localSide = TeamColor.White;
            _localLoadout = (loadout ?? CandyLoadout.Default()).Clone();
            _localLoadout.Normalize();
            _whiteLoadout = _localLoadout.Clone();
            _blackLoadout = CandyLoadout.Default();
            _remoteName = "BOT";
            _matchId = "";
            _seed = UnityEngine.Random.Range(1, int.MaxValue - 1);
            _lastSeq = 0;
            _needFullSync = false;
            _rewardGranted = false;
            _pendingAction = null;
            _statusText = "";
            _deadlineUtc = DateTime.UtcNow.AddSeconds(CandyCatalog.MatchSeconds);
            _lastTimerRefresh = 0f;
            _exitConfirmUntil = 0f;

            _board.Reset(_seed, _whiteLoadout, _blackLoadout);
            _phase = CandyPhase.Playing;
            ClearSelection();
            _view.ClearLog();
            _view.ShowGame();
            _view.AddLog("La Cacería comenzó. Invocá una pieza: entra en juego en tu próximo turno.");
            RefreshAll();
        }

        public void StartOnlineSearch(CandyLoadout loadout)
        {
            if (!EnsureView()) return;
            if (!EnsureEventActive()) return;

            StopAllCoroutines();
            _botRoutineActive = false;
            _onlineLoopActive = false;
            _searchLoopActive = false;
            _syncFailures = 0;
            _mode = CandyGameMode.Online;
            _localLoadout = (loadout ?? CandyLoadout.Default()).Clone();
            _localLoadout.Normalize();
            _whiteLoadout = _localLoadout.Clone();
            _blackLoadout = CandyLoadout.Default();
            _remoteName = "";
            _matchId = "";
            _lastSeq = 0;
            _needFullSync = true;
            _rewardGranted = false;
            _pendingAction = null;
            _statusText = "";
            _phase = CandyPhase.Searching;
            _view.ShowSearching();
            StartCoroutine(SearchRoutine());
        }

        public void CancelSearch()
        {
            if (_phase != CandyPhase.Searching) return;
            _phase = CandyPhase.Intro;
            _statusText = "";
            CandyNetworkRunner.Run(CancelSearchRequestRoutine());
            _view.ShowIntro();
        }

        public void FallbackToBot()
        {
            if (_phase != CandyPhase.Searching && _phase != CandyPhase.Draft) return;
            StartBot(_localLoadout ?? CandyLoadout.LoadSaved());
            CandyNetworkRunner.Run(CancelSearchRequestRoutine());
        }

        public void OnCellClicked(int row, int col)
        {
            if (_phase != CandyPhase.Playing || _board == null) return;
            if (!_board.IsValidSquare(row, col)) return;
            if (!IsMyTurn) return;
            if (_pendingAction != null)
            {
                _view.ShowToast("Esperá a que el servidor confirme tu jugada.");
                return;
            }

            var pieceAt = _board.GetPieceAt(row, col);

            // 1) Si hay una pieza de reserva elegida y la casilla está vacía, invocar.
            if (_selectedHandType.HasValue)
            {
                PieceType type = _selectedHandType.Value;
                if (_board.CanDeploy(_localSide, type, row, col))
                {
                    string variant = GetLocalLoadout().Get(type);
                    var action = CandyAction.Deploy(_localSide, type, variant, row, col);
                    ClearSelection();
                    SubmitLocalAction(action);
                    return;
                }

                if (pieceAt == null)
                {
                    _view.ShowToast("Esa casilla no se puede usar para invocar.");
                    return;
                }
            }

            // 2) Si ya hay una pieza seleccionada y la casilla es un destino legal, mover.
            if (_selectedPieceId != 0 && IsLegalDestination(row, col))
            {
                int pieceId = _selectedPieceId;
                ClearSelection();
                SubmitLocalAction(CandyAction.Move(_localSide, pieceId, row, col));
                return;
            }

            // 3) Seleccionar una pieza propia.
            if (pieceAt != null && pieceAt.side == _localSide)
            {
                _selectedHandType = null;
                _selectedPieceId = pieceAt.id;
                _legalMoves.Clear();
                var moves = _board.GetLegalMoves(pieceAt);
                for (int i = 0; i < moves.Count; i++) _legalMoves.Add(moves[i]);
                if (_board.IsSummonedThisTurn(pieceAt))
                    _statusText = "La invocaste este turno: recién se mueve en tu próximo turno.";
                else
                    _statusText = moves.Count == 0 ? "Esa pieza no tiene movimientos legales." : "";
                RefreshAll();
                return;
            }

            if (pieceAt != null && pieceAt.side != _localSide)
            {
                _view.ShowToast("Esa pieza es del rival.");
                ClearSelection();
                RefreshAll();
                return;
            }

            ClearSelection();
            RefreshAll();
        }

        public void OnHandTypeSelected(PieceType type)
        {
            if (_phase != CandyPhase.Playing || _board == null) return;
            if (!IsMyTurn || _pendingAction != null) return;
            if (_board.DeployedThisTurn)
            {
                _view.ShowToast("Ya invocaste una pieza este turno. La nueva entra en el próximo.");
                return;
            }
            if (_board.GetReserve(_localSide, type) <= 0) return;

            _selectedPieceId = 0;
            _legalMoves.Clear();
            _selectedHandType = type;
            _statusText = "Elegí una casilla vacía para invocar " + CandyCatalog.PieceLabel(type) + ".";
            RefreshAll();
        }

        public void OnPassClicked()
        {
            if (_phase != CandyPhase.Playing || _board == null) return;
            if (!IsMyTurn || _pendingAction != null) return;

            ClearSelection();
            SubmitLocalAction(CandyAction.Pass(_localSide));
        }

        public void ConfirmExit()
        {
            if (_phase == CandyPhase.Playing)
            {
                if (Time.unscaledTime < _exitConfirmUntil)
                {
                    ReturnToMenu();
                    return;
                }

                _exitConfirmUntil = Time.unscaledTime + 3.5f;
                _view.ShowToast("Tocá SALIR otra vez para abandonar la Cacería.");
                return;
            }

            ReturnToMenu();
        }

        public void ReturnToMenu()
        {
            ForceClose();
            MainMenuController.Instance?.ShowMainMenu();
        }

        public void Rematch()
        {
            if (_mode == CandyGameMode.Bot)
            {
                StartBot((_localLoadout ?? CandyLoadout.Default()).Clone());
                return;
            }

            if (_mode == CandyGameMode.Online)
            {
                ShowDraft(true);
                return;
            }

            ShowIntro();
        }

        public void ForceClose()
        {
            // ShowMainMenu vuelve a llamar a ForceClose después de ReturnToMenu.
            // Si ya está cerrado, no hay que repetir StopAllCoroutines: eso
            // cancelaba el /leave o el /finish que acababa de arrancar.
            if (_phase == CandyPhase.Closed && (_view == null || !_view.IsVisible)) return;

            bool leaveOnline = _mode == CandyGameMode.Online &&
                               !string.IsNullOrEmpty(_matchId) &&
                               _phase == CandyPhase.Playing;
            bool cancelSearch = _mode == CandyGameMode.Online && _phase == CandyPhase.Searching;
            string matchId = _matchId;

            StopAllCoroutines();
            _botRoutineActive = false;
            _onlineLoopActive = false;
            _searchLoopActive = false;
            _phase = CandyPhase.Closed;
            _pendingAction = null;
            ClearSelection();
            _statusText = "";
            _view?.Hide();
            SetMenuVisible(true);

            if (leaveOnline && !string.IsNullOrEmpty(matchId))
                CandyNetworkRunner.Run(CloseNetworkRoutine(matchId, false));
            else if (cancelSearch)
                CandyNetworkRunner.Run(CloseNetworkRoutine("", true));

            _mode = CandyGameMode.None;
            _matchId = "";
        }

        public CandyLoadout GetLocalLoadout()
        {
            return _localLoadout ?? CandyLoadout.Default();
        }

        /// <summary>
        /// La Cacería es temporal: una partida puede terminar después del cierre
        /// de la Velada, pero no se puede empezar otra. En ese caso se vuelve al
        /// menú, donde la entrada ya queda oculta.
        /// </summary>
        private bool EnsureEventActive()
        {
            if (HalloweenEvent.IsActiveNow) return true;
            Debug.LogWarning("[CandyMode] La Velada terminó; la Cacería ya no está disponible.");
            ReturnToMenu();
            return false;
        }

        private bool EnsureView()
        {
            var menu = MainMenuController.Instance;
            // Instance puede quedar en null tras una recarga de scripts en el
            // editor; el menú sigue vivo en la escena. Buscarlo evita que la
            // Cacería no pueda montarse en ese caso.
            if (menu == null) menu = FindAnyObjectByType<MainMenuController>();
            if (menu == null || menu.UiRoot == null)
            {
                Debug.LogWarning("[CandyMode] No hay MainMenuController/UIDocument para montar la pantalla.");
                return false;
            }

            if (_view == null)
            {
                _view = gameObject.GetComponent<CandyModeView>();
                if (_view == null) _view = gameObject.AddComponent<CandyModeView>();
                _view.Bind(this);
                _view.Build(menu.UiRoot);
            }
            return true;
        }

        private void SetMenuVisible(bool visible)
        {
            var menu = MainMenuController.Instance;
            if (menu == null) menu = FindAnyObjectByType<MainMenuController>();
            var container = menu?.MenuContainer;
            if (container != null)
                container.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
        }

        private void Update()
        {
            if (_phase == CandyPhase.Playing && _board != null)
            {
                if (Time.unscaledTime - _lastTimerRefresh >= 0.1f)
                {
                    _lastTimerRefresh = Time.unscaledTime;
                    _view?.TickTimer(SecondsLeft);
                }

                if (_pendingAction != null && _pendingSince > 0f &&
                    Time.unscaledTime - _pendingSince > 6f)
                {
                    _pendingAction = null;
                    _pendingSince = 0f;
                    _needFullSync = true;
                    _statusText = "La confirmación tardó. Reintentando sincronización...";
                    _view?.ShowToast("La jugada no se confirmó. Reintentando...");
                    _view?.RefreshAll();
                }

                if (DateTime.UtcNow >= _deadlineUtc)
                {
                    FinishByTime();
                    return;
                }

                if (_mode == CandyGameMode.Bot &&
                    _board.CurrentSide == TeamColor.Black &&
                    !_botRoutineActive)
                {
                    StartCoroutine(BotTurnRoutine());
                }
            }
        }

        private void SubmitLocalAction(CandyAction action)
        {
            if (action == null || _phase != CandyPhase.Playing) return;

            if (_mode == CandyGameMode.Bot)
            {
                ApplyLocalAction(action);
                return;
            }

            if (_mode == CandyGameMode.Online)
            {
                if (_pendingAction != null) return;
                _pendingAction = action;
                _pendingSince = Time.unscaledTime;
                _statusText = "Sincronizando jugada...";
                RefreshAll();
                StartCoroutine(SubmitOnlineActionRoutine(action));
            }
        }

        private void ApplyLocalAction(CandyAction action)
        {
            var result = _board.ApplyAction(action);
            if (result == null || !result.ok)
            {
                _statusText = result != null ? result.error : "Jugada inválida.";
                _view?.ShowToast(_statusText);
                ClearSelection();
                RefreshAll();
                return;
            }

            _statusText = "";
            LogAction(action, result);
            ClearSelection();
            RefreshAll();
            CheckForElimination();
            if (_phase == CandyPhase.Playing &&
                _mode == CandyGameMode.Bot &&
                _board.CurrentSide == TeamColor.Black &&
                !_botRoutineActive)
            {
                StartCoroutine(BotTurnRoutine());
            }
        }

        private IEnumerator BotTurnRoutine()
        {
            if (_botRoutineActive) yield break;
            _botRoutineActive = true;
            yield return new WaitForSecondsRealtime(0.55f);

            while (_phase == CandyPhase.Playing &&
                   _mode == CandyGameMode.Bot &&
                   _board.CurrentSide == TeamColor.Black)
            {
                if (!_board.DeployedThisTurn && _board.GetReserveTotal(TeamColor.Black) > 0)
                {
                    var deploy = CandyBot.ChooseDeploy(_board, TeamColor.Black);
                    if (deploy != null)
                    {
                        var result = _board.ApplyAction(deploy);
                        if (result != null && result.ok)
                        {
                            LogAction(deploy, result);
                            _statusText = "El bot invocó una pieza.";
                            RefreshAll();
                        }
                        yield return new WaitForSecondsRealtime(0.4f);
                    }
                }

                if (_phase != CandyPhase.Playing || _board.CurrentSide != TeamColor.Black)
                    break;

                var move = CandyBot.ChooseMove(_board, TeamColor.Black);
                if (move != null)
                {
                    var result = _board.ApplyAction(move);
                    if (result != null && result.ok)
                    {
                        LogAction(move, result);
                        _statusText = "";
                    }
                    else if (result != null)
                    {
                        _statusText = result.error;
                        _board.Pass(TeamColor.Black);
                    }
                }

                RefreshAll();
                CheckForElimination();
                if (_phase != CandyPhase.Playing) break;
                yield return new WaitForSecondsRealtime(0.45f);
            }

            _botRoutineActive = false;
            if (_phase == CandyPhase.Playing) RefreshAll();
        }

        private IEnumerator SearchRoutine()
        {
            if (_searchLoopActive) yield break;
            _searchLoopActive = true;

            int attempts = 0;
            while (_phase == CandyPhase.Searching && _mode == CandyGameMode.Online)
            {
                var call = OwsApiFailover.Post(CandyApi.SearchPath, CandyApi.SearchBody(_localLoadout), null, 14);
                yield return call;

                if (_phase != CandyPhase.Searching || _mode != CandyGameMode.Online)
                    break;

                attempts++;
                if (call.Success)
                {
                    var response = CandyApi.ParseSearch(call.text);
                    if (response != null)
                    {
                        if (string.Equals(response.state, "found", StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrEmpty(response.match_id))
                        {
                            BeginOnlineMatch(response);
                            _searchLoopActive = false;
                            yield break;
                        }

                        if (!string.IsNullOrEmpty(response.error))
                            _view.SetSearchStatus("Error: " + response.error);
                        else if (attempts > 2)
                            _view.SetSearchStatus("Buscando rival en owsdatabase...");
                    }
                }
                else
                {
                    _view.SetSearchStatus("Servidor despertando. Reintentando por el espejo...");
                }

                yield return new WaitForSecondsRealtime(2f);
            }

            _searchLoopActive = false;
        }

        private void BeginOnlineMatch(CandySearchResponse response)
        {
            _matchId = response.match_id ?? "";
            _localSide = response.side == 0 ? TeamColor.White : TeamColor.Black;
            _remoteName = string.IsNullOrEmpty(response.opponent_name) ? "RIVAL" : response.opponent_name;
            _seed = response.seed;
            _lastSeq = 0;
            _needFullSync = false;
            _rewardGranted = false;
            _pendingAction = null;
            _pendingSince = 0f;
            _statusText = "";
            _syncFailures = 0;

            _whiteLoadout = CandyLoadout.FromJson(response.white_loadout);
            _blackLoadout = CandyLoadout.FromJson(response.black_loadout);
            _localLoadout = _localSide == TeamColor.White ? _whiteLoadout : _blackLoadout;
            _board.Reset(_seed, _whiteLoadout, _blackLoadout);
            _view.ClearLog();

            long remainingMs = response.started_at + (long)(CandyCatalog.MatchSeconds * 1000f) - response.server_time;
            if (remainingMs < 1000) remainingMs = 1000;
            _deadlineUtc = DateTime.UtcNow.AddMilliseconds(remainingMs);

            if (response.actions != null && response.actions.Length > 0)
                ApplyServerActions(response.actions);

            _phase = CandyPhase.Playing;
            ClearSelection();
            _view.ShowGame();
            _view.AddLog("Rival encontrado: " + _remoteName + ". ¡Que gane el que junte más Dulces!");
            RefreshAll();

            if (!_onlineLoopActive)
                StartCoroutine(OnlineLoopRoutine());
        }

        private IEnumerator OnlineLoopRoutine()
        {
            if (_onlineLoopActive) yield break;
            _onlineLoopActive = true;

            while (_phase == CandyPhase.Playing && _mode == CandyGameMode.Online && !string.IsNullOrEmpty(_matchId))
            {
                int since = _needFullSync ? 0 : _lastSeq;
                var call = OwsApiFailover.Get(CandyApi.StateUrl(_matchId, since), null, 10);
                yield return call;

                if (_phase != CandyPhase.Playing || _mode != CandyGameMode.Online)
                    break;

                if (call.ProtocolError && (call.responseCode == 404 || call.responseCode == 403))
                {
                    _statusText = "La partida ya no está disponible.";
                    FinishMatch("server", null);
                    yield break;
                }

                if (call.Success)
                {
                    var state = CandyApi.ParseState(call.text);
                    if (state != null)
                    {
                        UpdateDeadline(state);
                        ApplyServerState(state);
                    }
                }
                else if (_statusText != "Reconectando con el servidor...")
                {
                    _statusText = "Reconectando con el servidor...";
                    _view?.RefreshAll();
                }

                yield return new WaitForSecondsRealtime(0.55f);
            }

            _onlineLoopActive = false;
        }

        private void UpdateDeadline(CandyStateResponse state)
        {
            if (state.started_at <= 0 || state.server_time <= 0) return;
            long remainingMs = state.started_at + (long)(CandyCatalog.MatchSeconds * 1000f) - state.server_time;
            if (remainingMs <= 0)
            {
                _deadlineUtc = DateTime.UtcNow.AddSeconds(-1);
                return;
            }

            var target = DateTime.UtcNow.AddMilliseconds(remainingMs);
            if (Math.Abs((target - _deadlineUtc).TotalSeconds) > 1.5)
                _deadlineUtc = target;
        }

        private void ApplyServerState(CandyStateResponse state)
        {
            if (state == null) return;

            bool finished = string.Equals(state.status, "finished", StringComparison.OrdinalIgnoreCase);
            int beforeActions = _board.ActionCount;
            TeamColor beforeTurn = _board.CurrentSide;
            bool beforePending = _pendingAction != null;
            bool didFullSync = false;
            bool syncFailed = false;

            // Las acciones se aplican también cuando el estado ya viene como
            // "finished": el último paquete puede traer la jugada que definió
            // la partida. Sin esto el marcador y el botín quedaban atrasados.
            if (_needFullSync)
            {
                _board.Reset(_seed, _whiteLoadout, _blackLoadout);
                _lastSeq = 0;
                _view?.ClearLog();
                if (state.actions != null) ApplyServerActions(state.actions);
                didFullSync = true;
                if (_lastSeq < state.seq)
                {
                    _needFullSync = true;
                    syncFailed = true;
                }
            }
            else if (state.actions != null && state.actions.Length > 0)
            {
                int expected = _lastSeq + 1;
                for (int i = 0; i < state.actions.Length; i++)
                {
                    if (state.actions[i] == null || state.actions[i].seq != expected)
                    {
                        _needFullSync = true;
                        syncFailed = true;
                        break;
                    }
                    expected++;
                }

                if (!syncFailed)
                {
                    ApplyServerActions(state.actions);
                    if (_lastSeq < state.seq)
                    {
                        _needFullSync = true;
                        syncFailed = true;
                    }
                }
            }
            else if (state.seq > _lastSeq)
            {
                _needFullSync = true;
                syncFailed = true;
            }

            if (finished)
            {
                // El ganador que declara el servidor manda cuando existe. Sólo
                // se calcula localmente si el cierre por tiempo llegó sin
                // ganador (el servidor no simula el tablero).
                TeamColor? winner;
                bool hasWinner = CandyApi.TryParseWinner(state.winner, out winner);
                if (!hasWinner && string.Equals(state.result, "time", StringComparison.OrdinalIgnoreCase))
                    winner = EvaluateTimeWinner();
                FinishMatch(state.result ?? "abandon", winner);
                return;
            }

            if (syncFailed)
            {
                _syncFailures++;
                if (_syncFailures >= 4)
                {
                    _statusText = "No se pudo sincronizar la partida.";
                    _view?.ShowToast(_statusText);
                    FinishMatch("server", null);
                }
                return;
            }

            _syncFailures = 0;

            if (_board.IsEliminated(TeamColor.White) || _board.IsEliminated(TeamColor.Black))
                CheckForElimination();

            bool uiDirty = didFullSync ||
                           _board.ActionCount != beforeActions ||
                           _board.CurrentSide != beforeTurn ||
                           (_pendingAction != null) != beforePending;
            if (uiDirty && _phase == CandyPhase.Playing) RefreshAll();
        }

        private void ApplyServerActions(CandyAction[] actions)
        {
            if (actions == null) return;
            for (int i = 0; i < actions.Length; i++)
            {
                var action = actions[i];
                if (action == null) continue;
                if (action.seq <= _lastSeq) continue;

                var result = _board.ApplyAction(action);
                if (result == null || !result.ok)
                {
                    _needFullSync = true;
                    _lastSeq = 0;
                    return;
                }

                if (action.side == (_localSide == TeamColor.White ? 0 : 1))
                {
                    _pendingAction = null;
                    _pendingSince = 0f;
                    _statusText = "";
                }

                LogAction(action, result);
                _lastSeq = action.seq;
            }

            ClearSelection();
        }

        private IEnumerator SubmitOnlineActionRoutine(CandyAction action)
        {
            var call = OwsApiFailover.Post(CandyApi.ActionPath, CandyApi.ActionBody(_matchId, action), null, 12);
            yield return call;

            if (_phase != CandyPhase.Playing || _mode != CandyGameMode.Online) yield break;

            if (!call.Success)
            {
                if (call.ProtocolError && (call.responseCode == 404 || call.responseCode == 403))
                {
                    FinishMatch("server", null);
                    yield break;
                }

                _pendingAction = null;
                _pendingSince = 0f;
                _statusText = "No se pudo enviar la jugada. Reintentá.";
                _view?.ShowToast(_statusText);
                RefreshAll();
                yield break;
            }

            var response = CandyApi.ParseAction(call.text);
            if (response == null || !response.success)
            {
                _pendingAction = null;
                _pendingSince = 0f;
                _statusText = response != null && !string.IsNullOrEmpty(response.error)
                    ? response.error
                    : "El servidor rechazó la jugada.";
                _view?.ShowToast(_statusText);
                RefreshAll();
            }
        }

        private IEnumerator CancelSearchRequestRoutine()
        {
            var call = OwsApiFailover.Post(CandyApi.CancelPath, CandyApi.CancelBody(), null, 8);
            yield return call;
        }

        private IEnumerator CloseNetworkRoutine(string matchId, bool cancelSearch)
        {
            if (cancelSearch)
            {
                var cancel = OwsApiFailover.Post(CandyApi.CancelPath, CandyApi.CancelBody(), null, 8);
                yield return cancel;
                yield break;
            }

            if (string.IsNullOrEmpty(matchId)) yield break;
            var leave = OwsApiFailover.Post(CandyApi.LeavePath, CandyApi.LeaveBody(matchId), null, 8);
            yield return leave;
        }

        private IEnumerator ReportFinishRoutine(string matchId, string reason, string winner)
        {
            if (string.IsNullOrEmpty(matchId)) yield break;
            var call = OwsApiFailover.Post(
                CandyApi.FinishPath,
                CandyApi.FinishBody(matchId, reason, winner),
                null, 8);
            yield return call;
        }

        private void CheckForElimination()
        {
            if (_phase != CandyPhase.Playing || _board == null) return;

            bool whiteOut = _board.IsEliminated(TeamColor.White);
            bool blackOut = _board.IsEliminated(TeamColor.Black);
            if (!whiteOut && !blackOut) return;

            TeamColor? winner = null;
            if (whiteOut && !blackOut) winner = TeamColor.Black;
            else if (blackOut && !whiteOut) winner = TeamColor.White;
            FinishMatch("elimination", winner);
        }

        private void FinishByTime()
        {
            if (_phase != CandyPhase.Playing) return;
            FinishMatch("time", EvaluateTimeWinner());
        }

        private TeamColor? EvaluateTimeWinner()
        {
            int white = _board.WhiteScore;
            int black = _board.BlackScore;

            if (white > black) return TeamColor.White;
            if (black > white) return TeamColor.Black;

            int whitePieces = _board.GetPieceCount(TeamColor.White) + _board.GetReserveTotal(TeamColor.White);
            int blackPieces = _board.GetPieceCount(TeamColor.Black) + _board.GetReserveTotal(TeamColor.Black);
            if (whitePieces > blackPieces) return TeamColor.White;
            if (blackPieces > whitePieces) return TeamColor.Black;

            return null;
        }

        private void FinishMatch(string reason, TeamColor? winner)
        {
            if (_phase != CandyPhase.Playing) return;

            TeamColor? resolvedWinner = winner;
            if (!resolvedWinner.HasValue &&
                string.Equals(reason, "time", StringComparison.OrdinalIgnoreCase))
            {
                resolvedWinner = EvaluateTimeWinner();
            }

            int localScore = _board.GetScore(_localSide);
            int rivalScore = _board.GetScore(RivalSide);

            _phase = CandyPhase.Finished;
            _pendingAction = null;
            _pendingSince = 0f;
            ClearSelection();
            StopAllCoroutines();
            _botRoutineActive = false;
            _onlineLoopActive = false;
            _searchLoopActive = false;

            int reward = 0;
            if (!_rewardGranted)
            {
                _rewardGranted = true;
                reward = Mathf.Max(0, localScore);
                if (reward > 0)
                    HalloweenCurrency.Earn(reward, "Cacería de Dulces");

                bool victory = resolvedWinner.HasValue && resolvedWinner.Value == _localSide;
                HalloweenProgress.AddXp(HalloweenProgress.MatchXp +
                    (victory ? HalloweenProgress.VictoryXp : 0));
            }

            if (_mode == CandyGameMode.Online && !string.IsNullOrEmpty(_matchId))
            {
                string winnerText = resolvedWinner.HasValue
                    ? (resolvedWinner.Value == TeamColor.White ? "white" : "black")
                    : "draw";
                // Fuera del ciclo de vida del controlador: si el jugador vuelve
                // al menú enseguida, el reporte igual llega al servidor.
                CandyNetworkRunner.Run(ReportFinishRoutine(_matchId, reason, winnerText));
            }

            _statusText = "";
            _view?.ShowResult(resolvedWinner, localScore, rivalScore, reward, reason);
        }

        private bool IsLegalDestination(int row, int col)
        {
            for (int i = 0; i < _legalMoves.Count; i++)
            {
                if (_legalMoves[i].Row == row && _legalMoves[i].Col == col) return true;
            }
            return false;
        }

        private void ClearSelection()
        {
            _selectedPieceId = 0;
            _selectedHandType = null;
            _legalMoves.Clear();
        }

        private void RefreshAll()
        {
            _view?.RefreshAll();
            _view?.TickTimer(SecondsLeft);
        }

        private void LogAction(CandyAction action, CandyActionResult result)
        {
            if (action == null || result == null || !result.ok) return;

            int actionSide = action.side;
            int mine = _localSide == TeamColor.White ? 0 : 1;
            string who = actionSide == mine
                ? "Tú"
                : (_mode == CandyGameMode.Bot ? "Bot" : _remoteName);

            string kind = (action.kind ?? "").ToLowerInvariant();

            if (kind == "deploy")
            {
                string line = who + " invocó " + CandyCatalog.PieceLabel(ParseType(action.type)) + ".";
                line += " Entra en juego en el próximo turno.";
                if (result.promoted) line += " ¡Coronado!";
                if (result.candyCollected > 0)
                    line += " Recogió " + result.candyCollected + " Dulce" + (result.candyCollected == 1 ? "" : "s") + ".";
                _view?.AddLog(line);
                return;
            }

            if (kind == "pass")
            {
                _view?.AddLog(who + " pasó turno.");
                return;
            }

            if (result.capturedType.HasValue)
            {
                string line = who + " capturó " + CandyCatalog.PieceLabel(result.capturedType.Value) + ".";
                if (result.capturedKing) line += " ¡Rey cazado!";
                if (result.capturedQueen) line += " ¡Dama cazada!";
                if (result.scoreGained > 0) line += " +" + result.scoreGained + " Dulces.";
                _view?.AddLog(line);
                return;
            }

            if (result.candyCollected > 0)
                _view?.AddLog(who + " recogió " + result.candyCollected + " Dulce" +
                              (result.candyCollected == 1 ? "" : "s") + ".");
        }

        private static PieceType ParseType(string value)
        {
            return Enum.TryParse(value, out PieceType type) ? type : PieceType.Pawn;
        }
    }
}
