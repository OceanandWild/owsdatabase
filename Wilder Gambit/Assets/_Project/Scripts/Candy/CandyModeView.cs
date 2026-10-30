using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.Candy
{
    /// <summary>
    /// Pantalla completa de la Cacería de Dulces. Se construye con UI Toolkit
    /// para no tocar la escena 3D ni el tablero de ajedrez: la partida clásica
    /// queda intacta detrás de esta capa.
    /// </summary>
    public class CandyModeView : MonoBehaviour
    {
        private CandyModeController _controller;

        private VisualElement _root;
        private VisualElement _gameView;
        private VisualElement _introOverlay;
        private VisualElement _draftOverlay;
        private VisualElement _searchOverlay;
        private VisualElement _resultOverlay;

        private VisualElement _boardWrap;
        private VisualElement _boardElement;
        private VisualElement[,] _cells;
        private VisualElement _handRow;
        private VisualElement _rivalReserve;
        private ScrollView _logScroll;
        private Label _logEmpty;

        private Label _timer;
        private Label _scoreLocal;
        private Label _scoreRival;
        private Label _localScoreBig;
        private Label _turnLabel;
        private Label _stepLabel;
        private Label _status;
        private Label _localName;
        private Label _rivalName;
        private Label _modeLabel;
        private Label _toast;

        private Label _draftTitle;
        private Label _draftSub;
        private Button _draftConfirm;
        private Button _draftBack;
        private CandyLoadout _draftLoadout;
        private bool _draftOnline;
        private readonly Dictionary<string, Button> _variantCards = new Dictionary<string, Button>();

        private Label _searchStatus;
        private Label _searchDots;
        private Button _cancelSearch;
        private Button _searchBotFallback;
        private float _searchDotTime;
        private int _searchDotCount;

        private Label _resultTitle;
        private Label _resultSub;
        private Label _resultScore;
        private Label _resultReward;
        private Button _rematchButton;

        private Button _passButton;
        private float _toastHideAt;
        private bool _built;

        /// <summary>Sello «SE VA PRONTO!» del intro (solo en el último tramo).</summary>
        private VisualElement _introSeal;

        public bool IsVisible => _root != null && _root.style.display == DisplayStyle.Flex;

        public void Bind(CandyModeController controller) => _controller = controller;

        public void Build(VisualElement uiRoot)
        {
            if (_built || uiRoot == null) return;
            _built = true;

            _root = new VisualElement { name = "candy-mode-root" };
            _root.AddToClassList("candy-root");
            _root.style.position = Position.Absolute;
            _root.style.left = 0;
            _root.style.top = 0;
            _root.style.right = 0;
            _root.style.bottom = 0;
            _root.style.display = DisplayStyle.None;
            _root.RegisterCallback<GeometryChangedEvent>(_ => UpdateResponsiveClasses());
            uiRoot.Add(_root);

            BuildGameView();
            BuildIntro();
            BuildDraft();
            BuildSearching();
            BuildResult();

            _toast = new Label();
            _toast.AddToClassList("candy-toast");
            _toast.AddToClassList("hidden");
            _root.Add(_toast);

            HideAllOverlays();
        }

        public void Hide()
        {
            if (_root != null) _root.style.display = DisplayStyle.None;
        }

        private void UpdateResponsiveClasses()
        {
            if (_root == null) return;
            float width = _root.resolvedStyle.width;
            float height = _root.resolvedStyle.height;
            bool narrow = width > 0f && width < 1000f;
            bool wide = !narrow && width >= 1500f;
            // En 21:9 el panel virtual es mucho más ancho que alto. Las
            // columnas laterales aprovechan ese espacio en vez de dejar
            // dos desiertos entre el tablero y los bordes.
            bool ultraWide = wide && width > 0f && height > 0f && width / height > 2.05f;
            _root.EnableInClassList("candy-narrow", narrow);
            _root.EnableInClassList("candy-wide", wide);
            _root.EnableInClassList("candy-ultrawide", ultraWide);
        }

        public void ShowIntro()
        {
            if (!_built) return;
            _root.style.display = DisplayStyle.Flex;
            HideAllOverlays();
            _gameView.style.display = DisplayStyle.None;
            _introOverlay.style.display = DisplayStyle.Flex;

            // Se consulta al abrir y no al construir: si la velada entra en su
            // último tramo con el juego abierto, el sello aparece sin reiniciar.
            if (_introSeal != null)
                _introSeal.style.display = HalloweenEvent.IsFinalStretchNow
                    ? DisplayStyle.Flex
                    : DisplayStyle.None;
        }

        public void ShowDraft(bool online)
        {
            if (!_built) return;
            _root.style.display = DisplayStyle.Flex;
            HideAllOverlays();
            _gameView.style.display = DisplayStyle.None;
            _draftOverlay.style.display = DisplayStyle.Flex;

            _draftOnline = online;
            _draftLoadout = CandyLoadout.LoadSaved();
            _draftLoadout.Normalize();

            _draftTitle.text = online ? "BUSCAR RIVAL EN LÍNEA" : "JUGAR CONTRA EL BOT";
            _draftSub.text = "Elegí una variante por pieza. En este modo son gratis, aunque no las tengas compradas.";
            _draftConfirm.text = online ? "BUSCAR PARTIDA" : "EMPEZAR PARTIDA";
            RefreshDraftSelection();
        }

        public void ShowSearching()
        {
            if (!_built) return;
            _root.style.display = DisplayStyle.Flex;
            HideAllOverlays();
            _gameView.style.display = DisplayStyle.None;
            _searchOverlay.style.display = DisplayStyle.Flex;
            _searchStatus.text = "Buscando rival en owsdatabase...";
            _searchDots.text = "";
            _searchDotTime = 0f;
            _searchDotCount = 0;
        }

        public void SetSearchStatus(string text)
        {
            if (_searchStatus != null) _searchStatus.text = text ?? "";
        }

        public void ShowGame()
        {
            if (!_built) return;
            _root.style.display = DisplayStyle.Flex;
            UpdateResponsiveClasses();
            _root.schedule.Execute(UpdateResponsiveClasses).StartingIn(0);
            HideAllOverlays();
            _gameView.style.display = DisplayStyle.Flex;
            ScheduleResize();
            RefreshAll();
        }

        public void RefreshAll()
        {
            if (!_built || _controller == null || _controller.Board == null) return;
            if (_root.style.display == DisplayStyle.None) return;

            var board = _controller.Board;
            TeamColor me = _controller.LocalSide;

            _localName.text = "TÚ · " + _controller.LocalName.ToUpperInvariant();
            _rivalName.text = string.IsNullOrEmpty(_controller.OpponentName)
                ? "RIVAL"
                : _controller.OpponentName.ToUpperInvariant();
            _modeLabel.text = _controller.Mode == CandyGameMode.Online
                ? "ONLINE · OWSDATABASE"
                : "PRÁCTICA CONTRA EL BOT";

            int localScore = board.GetScore(me);
            int rivalScore = board.GetScore(_controller.RivalSide);
            _scoreLocal.text = localScore.ToString();
            _scoreRival.text = rivalScore.ToString();
            if (_localScoreBig != null) _localScoreBig.text = localScore.ToString();

            bool myTurn = _controller.IsMyTurn;
            _turnLabel.text = myTurn ? "TU TURNO" : "TURNO DEL RIVAL";
            _turnLabel.EnableInClassList("candy-turn-mine", myTurn);
            _turnLabel.EnableInClassList("candy-turn-rival", !myTurn);

            if (_controller.IsPendingOnline)
                _stepLabel.text = "SINCRONIZANDO JUGADA...";
            else if (!myTurn)
                _stepLabel.text = "El rival está jugando. El reloj sigue corriendo.";
            else if (board.DeployedThisTurn)
                _stepLabel.text = "Ya invocaste: la pieza nueva entra en tu próximo turno. Mové otra o pasá turno.";
            else if (board.GetReserveTotal(me) > 0)
                _stepLabel.text = "Invocá una pieza (opcional) y después mové una.";
            else
                _stepLabel.text = "Mové una pieza para atrapar Dulces o capturar.";

            string status = _controller.StatusText;
            _status.text = string.IsNullOrEmpty(status)
                ? "JUNTÁ MÁS DULCES QUE EL RIVAL ANTES DE QUE TERMINE EL TIEMPO."
                : status;
            _passButton.SetEnabled(myTurn && !_controller.IsPendingOnline);

            RebuildHand();
            RebuildRivalReserve();
            RenderBoard();
        }

        public void TickTimer(float seconds)
        {
            if (_timer == null) return;
            int total = Mathf.Max(0, Mathf.CeilToInt(seconds));
            int m = total / 60;
            int s = total % 60;
            _timer.text = $"{m:00}:{s:00}";
            _timer.EnableInClassList("candy-timer-low", total <= 60);
        }

        public void AddLog(string text)
        {
            if (_logScroll == null || string.IsNullOrEmpty(text)) return;
            if (_logEmpty != null) _logEmpty.style.display = DisplayStyle.None;
            var line = new Label(text);
            line.AddToClassList("candy-log-line");
            line.style.whiteSpace = WhiteSpace.Normal;
            _logScroll.Add(line);
            if (_logScroll.contentContainer.childCount > 24)
                _logScroll.contentContainer.RemoveAt(0);
        }

        public void ClearLog()
        {
            if (_logScroll == null) return;
            _logScroll.contentContainer.Clear();
            if (_logEmpty != null)
            {
                _logEmpty.style.display = DisplayStyle.Flex;
                _logScroll.Add(_logEmpty);
            }
        }

        public void ShowToast(string text)
        {
            if (_toast == null) return;
            _toast.text = text ?? "";
            _toast.RemoveFromClassList("hidden");
            _toastHideAt = Time.unscaledTime + 2.8f;
        }

        public void ShowResult(TeamColor? winner, int localScore, int rivalScore, int reward, string reason)
        {
            if (!_built) return;
            _root.style.display = DisplayStyle.Flex;
            HideAllOverlays();
            _gameView.style.display = DisplayStyle.Flex;
            _resultOverlay.style.display = DisplayStyle.Flex;
            string resultReason = (reason ?? "").ToLowerInvariant();
            if (resultReason == "time")
                TickTimer(0f);

            // Una partida interrumpida por el servidor no es un empate: los
            // marcadores pueden ser distintos simplemente porque la partida
            // quedó a medias. Se muestra como "sin resultado".
            bool interrupted = resultReason == "server";
            bool draw = !winner.HasValue && !interrupted;
            bool victory = winner.HasValue && winner.Value == _controller.LocalSide;
            bool loss = winner.HasValue && !victory;

            _resultTitle.text = interrupted
                ? "SIN RESULTADO"
                : (draw ? "EMPATE" : (victory ? "¡VICTORIA!" : "DERROTA"));
            _resultTitle.EnableInClassList("candy-result-win", victory);
            _resultTitle.EnableInClassList("candy-result-loss", loss);
            _resultTitle.EnableInClassList("candy-result-draw", draw || interrupted);

            switch (resultReason)
            {
                case "time":
                    _resultSub.text = "Se terminó el tiempo. Gana quien juntó más Dulces.";
                    break;
                case "abandon":
                    _resultSub.text = draw
                        ? "La partida terminó por desconexión."
                        : (victory ? "El rival abandonó la partida." : "Perdiste por desconexión.");
                    break;
                case "forfeit":
                    _resultSub.text = draw
                        ? "La partida terminó por abandono."
                        : (victory ? "El rival abandonó la partida." : "Abandonaste la partida.");
                    break;
                case "server":
                    _resultSub.text = "La partida se interrumpió porque el servidor se reinició. No cuenta como victoria ni derrota.";
                    break;
                default:
                    _resultSub.text = draw
                        ? "Los dos ejércitos se agotaron."
                        : (victory ? "El rival se quedó sin piezas." : "Tu ejército se quedó sin piezas.");
                    break;
            }

            _resultScore.text = $"TÚ {localScore}  ·  RIVAL {rivalScore}";

            if (reward > 0)
                _resultReward.text = $"+{reward} Dulces para tu saldo de la Velada";
            else
                _resultReward.text = "No juntaste Dulces esta vez";

            _rematchButton.text = _controller.Mode == CandyGameMode.Online ? "BUSCAR OTRA" : "REVANCHA";
            _rematchButton.SetEnabled(true);
        }

        private void Update()
        {
            if (_searchOverlay != null && _searchOverlay.style.display == DisplayStyle.Flex)
            {
                _searchDotTime += Time.unscaledDeltaTime;
                if (_searchDotTime >= 0.35f)
                {
                    _searchDotTime = 0f;
                    _searchDotCount = (_searchDotCount + 1) % 4;
                    _searchDots.text = new string('.', _searchDotCount);
                }
            }

            if (_toast != null && !_toast.ClassListContains("hidden") && Time.unscaledTime >= _toastHideAt)
                _toast.AddToClassList("hidden");
        }

        private void BuildGameView()
        {
            _gameView = new VisualElement();
            _gameView.AddToClassList("candy-game");
            _gameView.style.display = DisplayStyle.None;
            _root.Add(_gameView);

            var topbar = new VisualElement();
            topbar.AddToClassList("candy-topbar");
            _gameView.Add(topbar);

            var brand = new VisualElement();
            brand.AddToClassList("candy-brand");
            var title = new Label("CACERÍA DE DULCES");
            title.AddToClassList("candy-brand-title");
            brand.Add(title);
            _modeLabel = new Label("MODO TEMPORAL");
            _modeLabel.AddToClassList("candy-brand-sub");
            brand.Add(_modeLabel);
            topbar.Add(brand);

            var timerWrap = new VisualElement();
            timerWrap.AddToClassList("candy-timer-wrap");
            var timerCaption = new Label("TIEMPO");
            timerCaption.AddToClassList("candy-caption");
            timerWrap.Add(timerCaption);
            _timer = new Label("05:00");
            _timer.AddToClassList("candy-timer");
            timerWrap.Add(_timer);
            topbar.Add(timerWrap);

            var stats = new VisualElement();
            stats.AddToClassList("candy-topstats");
            stats.Add(CreateScoreChip("TÚ", out _scoreLocal, "candy-chip-local"));
            stats.Add(CreateScoreChip("RIVAL", out _scoreRival, "candy-chip-rival"));

            var exit = MakeButton("SALIR", "candy-btn candy-btn-ghost candy-btn-small");
            exit.clicked += () => _controller.ConfirmExit();
            stats.Add(exit);
            topbar.Add(stats);

            var main = new VisualElement();
            main.AddToClassList("candy-main");
            _gameView.Add(main);

            // Columna izquierda: reserva local.
            var left = new VisualElement();
            left.AddToClassList("candy-side");
            left.AddToClassList("candy-side-left");
            var leftTitle = new Label("TU RESERVA");
            leftTitle.AddToClassList("candy-section-title");
            left.Add(leftTitle);
            _localName = new Label("TÚ");
            _localName.AddToClassList("candy-player-name");
            left.Add(_localName);
            _handRow = new VisualElement();
            _handRow.AddToClassList("candy-hand");
            left.Add(_handRow);
            var leftHint = new Label("Invocá una pieza por turno y después mové una para juntar Dulces.");
            leftHint.AddToClassList("candy-hint");
            leftHint.style.whiteSpace = WhiteSpace.Normal;
            left.Add(leftHint);

            // Tablero de saldo: ocupa el alto que sobraba en la columna
            // izquierda y convierte el marcador en algo que se lee de lejos.
            var scoreCard = new VisualElement();
            scoreCard.AddToClassList("candy-score-card");
            var scoreTop = new VisualElement();
            scoreTop.AddToClassList("candy-score-top");
            var scoreArt = new Image
            {
                sprite = CandyCatalog.LoadCandySprite(1),
                scaleMode = ScaleMode.ScaleToFit,
                pickingMode = PickingMode.Ignore
            };
            scoreArt.AddToClassList("candy-score-art");
            scoreTop.Add(scoreArt);
            var scoreCaption = new Label("DULCES ATRAPADOS");
            scoreCaption.AddToClassList("candy-score-caption");
            scoreTop.Add(scoreCaption);
            _localScoreBig = new Label("0");
            _localScoreBig.AddToClassList("candy-score-big");
            scoreTop.Add(_localScoreBig);
            var scoreSub = new Label("EN ESTA PARTIDA");
            scoreSub.AddToClassList("candy-score-sub");
            scoreTop.Add(scoreSub);
            scoreCard.Add(scoreTop);

            var scoreSpacer = new VisualElement();
            scoreSpacer.AddToClassList("candy-score-spacer");
            scoreCard.Add(scoreSpacer);

            var legendTitle = new Label("VALOR DE CAPTURA");
            legendTitle.AddToClassList("candy-section-title candy-legend-title");
            scoreCard.Add(legendTitle);
            var legend = new VisualElement();
            legend.AddToClassList("candy-legend");
            AddLegendItem(legend, PieceType.Pawn);
            AddLegendItem(legend, PieceType.Knight);
            AddLegendItem(legend, PieceType.Bishop);
            AddLegendItem(legend, PieceType.Rook);
            AddLegendItem(legend, PieceType.Queen);
            AddLegendItem(legend, PieceType.King);
            scoreCard.Add(legend);
            left.Add(scoreCard);
            main.Add(left);

            // Centro: tablero 12×12.
            _boardWrap = new VisualElement();
            _boardWrap.AddToClassList("candy-board-wrap");
            _boardWrap.RegisterCallback<GeometryChangedEvent>(_ => ScheduleResize());
            main.Add(_boardWrap);

            _boardElement = new VisualElement();
            _boardElement.AddToClassList("candy-board");
            _boardWrap.Add(_boardElement);

            _cells = new VisualElement[CandyModeBoard.Size, CandyModeBoard.Size];
            for (int dr = 0; dr < CandyModeBoard.Size; dr++)
            {
                for (int dc = 0; dc < CandyModeBoard.Size; dc++)
                {
                    int capturedRow = dr;
                    int capturedCol = dc;
                    var cell = new VisualElement();
                    cell.AddToClassList("candy-cell");
                    cell.RegisterCallback<ClickEvent>(_ => OnCellClicked(capturedRow, capturedCol));
                    _boardElement.Add(cell);
                    _cells[dr, dc] = cell;
                }
            }

            // Columna derecha: rival y su ejército, registro y valores.
            var right = new VisualElement();
            right.AddToClassList("candy-side");
            right.AddToClassList("candy-side-right");
            var rivalCaption = new Label("RIVAL");
            rivalCaption.AddToClassList("candy-section-title");
            right.Add(rivalCaption);
            _rivalName = new Label("RIVAL");
            _rivalName.AddToClassList("candy-player-name candy-player-name-rival");
            right.Add(_rivalName);

            // Lo que le queda por invocar al rival: sin esto la columna era
            // un nombre y un registro vacío, y el ejército enemigo había que
            // contarlo a ojo en el tablero.
            var reserveCaption = new Label("EJÉRCITO EN RESERVA");
            reserveCaption.AddToClassList("candy-caption candy-reserve-caption");
            right.Add(reserveCaption);
            _rivalReserve = new VisualElement();
            _rivalReserve.AddToClassList("candy-rival-reserve");
            right.Add(_rivalReserve);

            var logTitle = new Label("REGISTRO");
            logTitle.AddToClassList("candy-section-title candy-log-title");
            right.Add(logTitle);
            _logScroll = new ScrollView(ScrollViewMode.Vertical);
            _logScroll.AddToClassList("candy-log");
            _logScroll.horizontalScrollerVisibility = ScrollerVisibility.Hidden;
            right.Add(_logScroll);
            _logEmpty = new Label("El registro de la partida aparece acá.");
            _logEmpty.AddToClassList("candy-log-empty");
            _logScroll.Add(_logEmpty);

            // Leyenda de Dulces: deja claro cuánto vale cada botín y rompe
            // el bloque vacío del registro cuando la partida recién empieza.
            var candyLegend = new VisualElement();
            candyLegend.AddToClassList("candy-candy-legend");
            var candyLegendTitle = new Label("VALOR DE LOS DULCES");
            candyLegendTitle.AddToClassList("candy-section-title");
            candyLegend.Add(candyLegendTitle);
            var candyLegendRow = new VisualElement();
            candyLegendRow.AddToClassList("candy-candy-legend-row");
            AddCandyValueItem(candyLegendRow, 1);
            AddCandyValueItem(candyLegendRow, 2);
            AddCandyValueItem(candyLegendRow, 3);
            candyLegend.Add(candyLegendRow);
            right.Add(candyLegend);
            main.Add(right);

            // Pie: estado del turno a la izquierda, instrucción al centro y
            // el botón de pasar turno a la derecha, todo en una sola barra.
            var footer = new VisualElement();
            footer.AddToClassList("candy-footer");
            _gameView.Add(footer);

            _turnLabel = new Label("TU TURNO");
            _turnLabel.AddToClassList("candy-turn-pill");
            footer.Add(_turnLabel);

            var footerText = new VisualElement();
            footerText.AddToClassList("candy-footer-text");
            _stepLabel = new Label("");
            _stepLabel.AddToClassList("candy-step");
            _stepLabel.style.whiteSpace = WhiteSpace.Normal;
            footerText.Add(_stepLabel);
            _status = new Label("");
            _status.AddToClassList("candy-status");
            _status.style.whiteSpace = WhiteSpace.Normal;
            footerText.Add(_status);
            footer.Add(footerText);

            _passButton = MakeButton("PASAR TURNO", "candy-btn candy-btn-secondary");
            _passButton.clicked += () => _controller.OnPassClicked();
            footer.Add(_passButton);
        }

        private void BuildIntro()
        {
            _introOverlay = CreateOverlay("candy-intro-overlay");
            var modal = new VisualElement();
            modal.AddToClassList("candy-modal");
            modal.AddToClassList("candy-intro-modal");
            _introOverlay.Add(modal);

            var eyebrow = new Label("MODO TEMPORAL DE LA VELADA · HASTA EL 4/11");
            eyebrow.AddToClassList("candy-eyebrow");

            var title = new Label("CACERÍA DE DULCES");
            title.AddToClassList("candy-title");

            // Cabecera: textos a la izquierda y el sello de despedida a la
            // derecha, apenas montado sobre el marco como una estampilla.
            var head = new VisualElement();
            head.AddToClassList("candy-intro-head");

            var headText = new VisualElement();
            headText.AddToClassList("candy-intro-head-text");
            headText.Add(eyebrow);
            headText.Add(title);
            head.Add(headText);

            _introSeal = new VisualElement();
            _introSeal.AddToClassList("candy-intro-seal");
            _introSeal.pickingMode = PickingMode.Ignore;
            Sprite sealArt = Resources.Load<Sprite>("UI/Wg/wg_seal_soon");
            if (sealArt != null)
            {
                // Con arte, el fondo y el borde de respaldo estorban en las
                // esquinas transparentes del placar.
                _introSeal.AddToClassList("candy-intro-seal-art");
                _introSeal.style.backgroundImage = new StyleBackground(sealArt);
            }
            var sealText = new Label("SE VA PRONTO!");
            sealText.AddToClassList("candy-intro-seal-text");
            sealText.pickingMode = PickingMode.Ignore;
            _introSeal.Add(sealText);
            _introSeal.style.display = DisplayStyle.None;
            head.Add(_introSeal);

            modal.Add(head);

            var sub = new Label("Un tablero más grande, piezas de Halloween gratis y una carrera de 6 minutos reales por los Dulces.");
            sub.AddToClassList("candy-subtitle");
            sub.style.whiteSpace = WhiteSpace.Normal;
            modal.Add(sub);

            var rules = new VisualElement();
            rules.AddToClassList("candy-rules");
            rules.Add(CreateRule("01", "INVOCÁ", "Cada turno podés colocar una pieza de tu reserva, incluido el rey, en cualquier casilla vacía."));
            rules.Add(CreateRule("02", "MOVÉ", "Después mové una pieza. La que acabás de invocar recién juega en tu próximo turno. Si cae en un Dulce, lo recogés. También podés capturar piezas rivales."));
            rules.Add(CreateRule("03", "SUMACIÓN", "Capturar una dama da +3 Dulces; capturar un rey, +5. Las variantes de Halloween suman bonus extra."));
            rules.Add(CreateRule("04", "GANÁ", "Gana quien deje al rival sin piezas o quien tenga más Dulces cuando se agoten los 6 minutos."));
            modal.Add(rules);

            var modeRow = new VisualElement();
            modeRow.AddToClassList("candy-mode-row");

            var bot = CreateModeCard("JUGAR CONTRA EL BOT", "Partida inmediata para probar variantes.", "hwp_knight_skeleton",
                () => _controller.ShowDraft(false));
            modeRow.Add(bot);

            var online = CreateModeCard("BUSCAR RIVAL EN LÍNEA", "Matchmaking en owsdatabase; si no responde, usa el espejo.", "hwp_queen_witch",
                () => _controller.ShowDraft(true));
            modeRow.Add(online);
            modal.Add(modeRow);

            var footer = new VisualElement();
            footer.AddToClassList("candy-modal-footer");
            var back = MakeButton("VOLVER AL MENÚ", "candy-btn candy-btn-ghost");
            back.clicked += () => _controller.ReturnToMenu();
            footer.Add(back);
            modal.Add(footer);
        }

        private void BuildDraft()
        {
            _draftOverlay = CreateOverlay("candy-draft-overlay");
            var modal = new VisualElement();
            modal.AddToClassList("candy-modal");
            modal.AddToClassList("candy-draft-modal");
            _draftOverlay.Add(modal);

            var eyebrow = new Label("VARIANTES DE LA VELADA · GRATIS EN ESTE MODO");
            eyebrow.AddToClassList("candy-eyebrow");
            modal.Add(eyebrow);

            _draftTitle = new Label("ELEGIR VARIANTES");
            _draftTitle.AddToClassList("candy-title candy-title-small");
            modal.Add(_draftTitle);

            _draftSub = new Label("");
            _draftSub.AddToClassList("candy-subtitle");
            _draftSub.style.whiteSpace = WhiteSpace.Normal;
            modal.Add(_draftSub);

            var scroll = new ScrollView(ScrollViewMode.Vertical);
            scroll.AddToClassList("candy-draft-scroll");
            scroll.horizontalScrollerVisibility = ScrollerVisibility.Hidden;
            modal.Add(scroll);

            for (int i = 0; i < CandyCatalog.DraftOrder.Length; i++)
            {
                PieceType type = CandyCatalog.DraftOrder[i];
                var typeLabel = new Label(CandyCatalog.PieceLabel(type));
                typeLabel.AddToClassList("candy-draft-type");
                scroll.Add(typeLabel);

                var row = new VisualElement();
                row.AddToClassList("candy-variant-row");
                var variants = CandyCatalog.ForType(type);
                for (int v = 0; v < variants.Count; v++)
                {
                    var variant = variants[v];
                    var card = new Button();
                    card.AddToClassList("candy-variant-card");

                    var icon = new UnityEngine.UIElements.Image
                    {
                        sprite = CandyCatalog.LoadVariantSprite(type, variant.id, TeamColor.White),
                        scaleMode = ScaleMode.ScaleToFit,
                        pickingMode = PickingMode.Ignore
                    };
                    icon.AddToClassList("candy-variant-icon");
                    card.Add(icon);

                    var name = new Label(variant.name);
                    name.AddToClassList("candy-variant-name");
                    card.Add(name);

                    var desc = new Label(variant.description);
                    desc.AddToClassList("candy-variant-desc");
                    desc.style.whiteSpace = WhiteSpace.Normal;
                    card.Add(desc);

                    PieceType capturedType = type;
                    string capturedId = variant.id;
                    card.clicked += () => SelectVariant(capturedType, capturedId);
                    HookButton(card);

                    _variantCards[type + ":" + variant.id] = card;
                    row.Add(card);
                }
                scroll.Add(row);
            }

            var footer = new VisualElement();
            footer.AddToClassList("candy-modal-footer");
            _draftBack = MakeButton("VOLVER", "candy-btn candy-btn-ghost");
            _draftBack.clicked += () => _controller.ShowIntro();
            footer.Add(_draftBack);

            _draftConfirm = MakeButton("EMPEZAR PARTIDA", "candy-btn candy-btn-primary");
            _draftConfirm.clicked += ConfirmDraft;
            footer.Add(_draftConfirm);
            modal.Add(footer);
        }

        private void BuildSearching()
        {
            _searchOverlay = CreateOverlay("candy-search-overlay");
            var modal = new VisualElement();
            modal.AddToClassList("candy-modal");
            modal.AddToClassList("candy-search-modal");
            _searchOverlay.Add(modal);

            var eyebrow = new Label("MATCHMAKING · OWSDATABASE");
            eyebrow.AddToClassList("candy-eyebrow");
            modal.Add(eyebrow);

            var title = new Label("BUSCANDO RIVAL");
            title.AddToClassList("candy-title candy-title-small");
            modal.Add(title);

            var row = new VisualElement();
            row.AddToClassList("candy-search-row");
            _searchStatus = new Label("Buscando rival en owsdatabase...");
            _searchStatus.AddToClassList("candy-search-status");
            row.Add(_searchStatus);
            _searchDots = new Label("");
            _searchDots.AddToClassList("candy-search-dots");
            row.Add(_searchDots);
            modal.Add(row);

            var note = new Label("Si el servidor principal está despertando, la búsqueda pasa sola al espejo owsdatabase2. Podés cancelar y jugar contra el bot.");
            note.AddToClassList("candy-subtitle");
            note.style.whiteSpace = WhiteSpace.Normal;
            modal.Add(note);

            var footer = new VisualElement();
            footer.AddToClassList("candy-modal-footer");

            _cancelSearch = MakeButton("CANCELAR", "candy-btn candy-btn-ghost");
            _cancelSearch.clicked += () => _controller.CancelSearch();
            footer.Add(_cancelSearch);

            _searchBotFallback = MakeButton("JUGAR CONTRA EL BOT", "candy-btn candy-btn-primary");
            _searchBotFallback.clicked += () => _controller.FallbackToBot();
            footer.Add(_searchBotFallback);

            modal.Add(footer);
        }

        private void BuildResult()
        {
            _resultOverlay = CreateOverlay("candy-result-overlay");
            var modal = new VisualElement();
            modal.AddToClassList("candy-modal");
            modal.AddToClassList("candy-result-modal");
            _resultOverlay.Add(modal);

            var eyebrow = new Label("FIN DE LA CACERÍA");
            eyebrow.AddToClassList("candy-eyebrow");
            modal.Add(eyebrow);

            _resultTitle = new Label("VICTORIA");
            _resultTitle.AddToClassList("candy-result-title");
            modal.Add(_resultTitle);

            _resultSub = new Label("");
            _resultSub.AddToClassList("candy-subtitle");
            _resultSub.style.whiteSpace = WhiteSpace.Normal;
            modal.Add(_resultSub);

            _resultScore = new Label("TÚ 0 · RIVAL 0");
            _resultScore.AddToClassList("candy-result-score");
            modal.Add(_resultScore);

            _resultReward = new Label("");
            _resultReward.AddToClassList("candy-result-reward");
            _resultReward.style.whiteSpace = WhiteSpace.Normal;
            modal.Add(_resultReward);

            var footer = new VisualElement();
            footer.AddToClassList("candy-modal-footer");

            var back = MakeButton("VOLVER AL MENÚ", "candy-btn candy-btn-ghost");
            back.clicked += () => _controller.ReturnToMenu();
            footer.Add(back);

            _rematchButton = MakeButton("REVANCHA", "candy-btn candy-btn-primary");
            _rematchButton.clicked += () => _controller.Rematch();
            footer.Add(_rematchButton);
            modal.Add(footer);
        }

        private VisualElement CreateOverlay(string className)
        {
            var overlay = new VisualElement();
            overlay.AddToClassList("candy-overlay");
            if (!string.IsNullOrEmpty(className)) overlay.AddToClassList(className);
            overlay.style.display = DisplayStyle.None;
            _root.Add(overlay);
            return overlay;
        }

        private static void AddCandyValueItem(VisualElement parent, int value)
        {
            var item = new VisualElement();
            item.AddToClassList("candy-candy-legend-item");
            var art = new Image
            {
                sprite = CandyCatalog.LoadCandySprite(value),
                scaleMode = ScaleMode.ScaleToFit,
                pickingMode = PickingMode.Ignore
            };
            art.AddToClassList("candy-candy-legend-icon");
            item.Add(art);
            var label = new Label("= " + value);
            label.AddToClassList("candy-candy-legend-value");
            item.Add(label);
            parent.Add(item);
        }

        private static void AddLegendItem(VisualElement parent, PieceType type)
        {
            var row = new VisualElement();
            row.AddToClassList("candy-legend-item");
            var icon = new Image
            {
                sprite = CandyCatalog.LoadVariantSprite(type, "", TeamColor.White),
                scaleMode = ScaleMode.ScaleToFit,
                pickingMode = PickingMode.Ignore
            };
            icon.AddToClassList("candy-legend-icon");
            row.Add(icon);
            var name = new Label(CandyCatalog.PieceLabel(type));
            name.AddToClassList("candy-legend-name");
            row.Add(name);
            var value = new Label(CandyCatalog.PieceValue(type).ToString());
            value.AddToClassList("candy-legend-value");
            row.Add(value);
            parent.Add(row);
        }

        private static VisualElement CreateScoreChip(string caption, out Label value, string extraClass)
        {
            var chip = new VisualElement();
            chip.AddToClassList("candy-chip");
            if (!string.IsNullOrEmpty(extraClass)) chip.AddToClassList(extraClass);
            Sprite candy = CandyCatalog.LoadCandySprite(1);
            if (candy != null)
            {
                var icon = new Image
                {
                    sprite = candy,
                    scaleMode = ScaleMode.ScaleToFit,
                    pickingMode = PickingMode.Ignore
                };
                icon.AddToClassList("candy-chip-icon");
                chip.Add(icon);
            }
            var cap = new Label(caption);
            cap.AddToClassList("candy-chip-caption");
            chip.Add(cap);
            value = new Label("0");
            value.AddToClassList("candy-chip-value");
            chip.Add(value);
            return chip;
        }

        private static VisualElement CreateRule(string number, string title, string text)
        {
            var row = new VisualElement();
            row.AddToClassList("candy-rule");
            var n = new Label(number);
            n.AddToClassList("candy-rule-number");
            row.Add(n);
            var body = new VisualElement();
            body.AddToClassList("candy-rule-body");
            var t = new Label(title);
            t.AddToClassList("candy-rule-title");
            body.Add(t);
            var d = new Label(text);
            d.AddToClassList("candy-rule-text");
            d.style.whiteSpace = WhiteSpace.Normal;
            body.Add(d);
            row.Add(body);
            return row;
        }

        private Button CreateModeCard(string title, string subtitle, string artName, Action onClick)
        {
            var card = new Button();
            card.AddToClassList("candy-mode-card");

            var icon = new UnityEngine.UIElements.Image
            {
                sprite = HalloweenArt.LoadSprite(artName),
                scaleMode = ScaleMode.ScaleToFit,
                pickingMode = PickingMode.Ignore
            };
            icon.AddToClassList("candy-mode-icon");
            card.Add(icon);

            var t = new Label(title);
            t.AddToClassList("candy-mode-title");
            card.Add(t);

            var s = new Label(subtitle);
            s.AddToClassList("candy-mode-sub");
            s.style.whiteSpace = WhiteSpace.Normal;
            card.Add(s);

            card.clicked += onClick;
            HookButton(card);
            return card;
        }

        private void RebuildHand()
        {
            if (_handRow == null || _controller == null || _controller.Board == null) return;
            _handRow.Clear();

            var board = _controller.Board;
            TeamColor me = _controller.LocalSide;
            var loadout = _controller.GetLocalLoadout();
            bool canDeploy = _controller.IsMyTurn && !_controller.IsPendingOnline && !board.DeployedThisTurn;

            bool any = false;
            for (int i = 0; i < CandyCatalog.DraftOrder.Length; i++)
            {
                PieceType type = CandyCatalog.DraftOrder[i];
                int count = board.GetReserve(me, type);
                if (count <= 0) continue;

                any = true;
                var card = new Button();
                card.AddToClassList("candy-hand-card");
                if (_controller.SelectedHandType.HasValue && _controller.SelectedHandType.Value == type)
                    card.AddToClassList("candy-hand-selected");
                card.SetEnabled(canDeploy);

                // El contador va como insignia sobre la carta: así el arte de
                // la pieza gana alto y deja de verse como un sello diminuto.
                var amount = new Label("x" + count);
                amount.AddToClassList("candy-hand-count");
                amount.pickingMode = PickingMode.Ignore;
                card.Add(amount);

                string variant = loadout.Get(type);
                var icon = new UnityEngine.UIElements.Image
                {
                    sprite = CandyCatalog.LoadVariantSprite(type, variant, me),
                    scaleMode = ScaleMode.ScaleToFit,
                    pickingMode = PickingMode.Ignore
                };
                if (CandyCatalog.UsesHalloweenTint(type, variant, me))
                    icon.tintColor = new Color(0.62f, 0.58f, 0.72f);
                icon.AddToClassList("candy-hand-icon");
                card.Add(icon);

                var name = new Label(CandyCatalog.PieceLabel(type));
                name.AddToClassList("candy-hand-name");
                card.Add(name);

                PieceType captured = type;
                card.clicked += () => _controller.OnHandTypeSelected(captured);
                HookButton(card);
                _handRow.Add(card);
            }

            if (!any)
            {
                var empty = new Label("Sin piezas en reserva.");
                empty.AddToClassList("candy-muted");
                _handRow.Add(empty);
            }
        }

        /// <summary>
        /// Ejército que al rival le queda por invocar. Se rehace en cada
        /// refresco (igual que la mano local) para que los contadores
        /// acompañen las capturas y las invocaciones.
        /// </summary>
        private void RebuildRivalReserve()
        {
            if (_rivalReserve == null || _controller == null || _controller.Board == null) return;
            _rivalReserve.Clear();

            var board = _controller.Board;
            TeamColor rival = _controller.RivalSide;
            var loadout = board.GetLoadout(rival);

            for (int i = 0; i < CandyCatalog.DraftOrder.Length; i++)
            {
                PieceType type = CandyCatalog.DraftOrder[i];
                int count = board.GetReserve(rival, type);

                var item = new VisualElement();
                item.AddToClassList("candy-rival-item");
                if (count <= 0) item.AddToClassList("candy-rival-empty");

                var amount = new Label("x" + count);
                amount.AddToClassList("candy-rival-count");
                item.Add(amount);

                string variant = loadout != null ? loadout.Get(type) : "";
                var icon = new UnityEngine.UIElements.Image
                {
                    sprite = CandyCatalog.LoadVariantSprite(type, variant, rival),
                    scaleMode = ScaleMode.ScaleToFit,
                    pickingMode = PickingMode.Ignore
                };
                if (CandyCatalog.UsesHalloweenTint(type, variant, rival))
                    icon.tintColor = new Color(0.62f, 0.58f, 0.72f);
                icon.AddToClassList("candy-rival-icon");
                item.Add(icon);

                var name = new Label(CandyCatalog.PieceLabel(type));
                name.AddToClassList("candy-rival-name");
                item.Add(name);

                _rivalReserve.Add(item);
            }
        }

        private void RenderBoard()
        {
            if (_cells == null || _controller == null || _controller.Board == null) return;
            var board = _controller.Board;
            bool flip = _controller.LocalSide == TeamColor.Black;
            TeamColor me = _controller.LocalSide;

            bool handSelected = _controller.SelectedHandType.HasValue;
            int selectedPiece = _controller.SelectedPieceId;
            var legal = _controller.LegalMoves;

            for (int dr = 0; dr < CandyModeBoard.Size; dr++)
            {
                for (int dc = 0; dc < CandyModeBoard.Size; dc++)
                {
                    int row = flip ? dr : (CandyModeBoard.Size - 1 - dr);
                    int col = flip ? (CandyModeBoard.Size - 1 - dc) : dc;
                    var cell = _cells[dr, dc];
                    cell.Clear();
                    cell.EnableInClassList("candy-cell-light", ((row + col) & 1) == 0);
                    cell.EnableInClassList("candy-cell-dark", ((row + col) & 1) != 0);
                    cell.EnableInClassList("candy-selected", false);
                    cell.EnableInClassList("candy-move-target", false);
                    cell.EnableInClassList("candy-capture-target", false);
                    cell.EnableInClassList("candy-deploy-target", false);
                    cell.EnableInClassList("candy-fresh", false);

                    int candy = board.GetCandyAt(row, col);
                    if (candy > 0)
                    {
                        var candyEl = new VisualElement();
                        candyEl.AddToClassList("candy-candy");
                        candyEl.pickingMode = PickingMode.Ignore;

                        Sprite candySprite = CandyCatalog.LoadCandySprite(candy);
                        if (candySprite != null)
                        {
                            var art = new Image
                            {
                                sprite = candySprite,
                                scaleMode = ScaleMode.ScaleToFit,
                                pickingMode = PickingMode.Ignore
                            };
                            art.AddToClassList("candy-candy-icon");
                            candyEl.Add(art);
                        }
                        else
                        {
                            candyEl.AddToClassList("candy-candy-fallback");
                            candyEl.AddToClassList("candy-candy-" + candy);
                        }

                        var value = new Label("+" + candy);
                        value.AddToClassList("candy-candy-value");
                        value.AddToClassList("candy-candy-value-" + candy);
                        value.pickingMode = PickingMode.Ignore;
                        candyEl.Add(value);
                        cell.Add(candyEl);
                    }

                    var piece = board.GetPieceAt(row, col);
                    if (piece != null)
                    {
                        string variant = piece.variantId;
                        Sprite pieceSprite = CandyCatalog.LoadVariantSprite(piece.type, variant, piece.side);

                        // Sombra de contacto: separa la escultura del damero,
                        // sobre todo las piezas blancas sobre casillas claras.
                        var pieceWrap = new VisualElement();
                        pieceWrap.AddToClassList("candy-piece-wrap");
                        pieceWrap.pickingMode = PickingMode.Ignore;

                        var shadow = new UnityEngine.UIElements.Image
                        {
                            sprite = pieceSprite,
                            scaleMode = ScaleMode.ScaleToFit,
                            pickingMode = PickingMode.Ignore
                        };
                        shadow.AddToClassList("candy-piece-shadow");
                        shadow.tintColor = new Color(0f, 0f, 0f, 0.5f);
                        pieceWrap.Add(shadow);

                        var icon = new UnityEngine.UIElements.Image
                        {
                            sprite = pieceSprite,
                            scaleMode = ScaleMode.ScaleToFit,
                            pickingMode = PickingMode.Ignore
                        };
                        if (CandyCatalog.UsesHalloweenTint(piece.type, variant, piece.side))
                            icon.tintColor = new Color(0.62f, 0.58f, 0.72f);
                        icon.AddToClassList("candy-piece");
                        pieceWrap.Add(icon);
                        cell.Add(pieceWrap);

                        // Pieza recién invocada: se marca para que se entienda
                        // que todavía no puede moverse en este turno.
                        if (board.IsSummonedThisTurn(piece))
                            cell.AddToClassList("candy-fresh");

                        if (piece.id == selectedPiece)
                            cell.AddToClassList("candy-selected");
                    }

                    bool isLegal = false;
                    for (int i = 0; i < legal.Count; i++)
                    {
                        if (legal[i].Row == row && legal[i].Col == col)
                        {
                            isLegal = true;
                            break;
                        }
                    }

                    if (isLegal)
                    {
                        if (piece != null && piece.side != me) cell.AddToClassList("candy-capture-target");
                        else cell.AddToClassList("candy-move-target");
                    }

                    if (handSelected && piece == null && _controller.IsMyTurn && !_controller.IsPendingOnline)
                    {
                        if (board.CanDeploy(me, _controller.SelectedHandType.Value, row, col))
                            cell.AddToClassList("candy-deploy-target");
                    }
                }
            }
        }

        private void OnCellClicked(int displayRow, int displayCol)
        {
            if (_controller == null) return;
            bool flip = _controller.LocalSide == TeamColor.Black;
            int row = flip ? displayRow : (CandyModeBoard.Size - 1 - displayRow);
            int col = flip ? (CandyModeBoard.Size - 1 - displayCol) : displayCol;
            _controller.OnCellClicked(row, col);
        }

        private void ScheduleResize()
        {
            if (_boardWrap == null) return;
            _boardWrap.schedule.Execute(ResizeBoard).StartingIn(0);
        }

        private void ResizeBoard()
        {
            if (_boardWrap == null || _boardElement == null || _cells == null) return;

            float w = _boardWrap.resolvedStyle.width;
            float h = _boardWrap.resolvedStyle.height;

            // El tablero no debe estirarse para llenar el ancho sobrante: eso
            // dejaba dos huecos muertos entre las columnas y el tablero. Se
            // calcula el ancho disponible de la fila (main - columnas) y se
            // fija el wrap a ese tamaño; el main centra el conjunto.
            var row = _boardWrap.parent;
            if (row != null && _root != null && !_root.ClassListContains("candy-narrow"))
            {
                float rowW = row.resolvedStyle.width;
                for (int i = 0; i < row.hierarchy.childCount; i++)
                {
                    var child = row.hierarchy.ElementAt(i);
                    if (child == _boardWrap) continue;
                    rowW -= child.resolvedStyle.width
                          + child.resolvedStyle.marginLeft
                          + child.resolvedStyle.marginRight;
                }
                if (rowW > 40f) w = rowW;
            }

            if (float.IsNaN(w) || w < 40f) w = Screen.width * 0.52f;
            if (float.IsNaN(h) || h < 40f) h = Screen.height * 0.65f;

            float size = Mathf.Min(w, h);
            size = Mathf.Clamp(size, 220f, 1100f);
            _boardElement.style.width = size;
            _boardElement.style.height = size;
            _boardWrap.style.width = size;
            _boardWrap.style.flexGrow = 0f;

            float cell = size / CandyModeBoard.Size;
            for (int dr = 0; dr < CandyModeBoard.Size; dr++)
            {
                for (int dc = 0; dc < CandyModeBoard.Size; dc++)
                {
                    var el = _cells[dr, dc];
                    el.style.position = Position.Absolute;
                    el.style.left = dc * cell;
                    el.style.top = dr * cell;
                    el.style.width = Mathf.Max(1f, cell - 1f);
                    el.style.height = Mathf.Max(1f, cell - 1f);
                }
            }
        }

        private void SelectVariant(PieceType type, string id)
        {
            if (_draftLoadout == null) _draftLoadout = CandyLoadout.Default();
            _draftLoadout.Set(type, id);
            RefreshDraftSelection();
        }

        private void RefreshDraftSelection()
        {
            if (_draftLoadout == null) return;
            foreach (var pair in _variantCards)
            {
                string[] parts = pair.Key.Split(':');
                if (parts.Length != 2) continue;
                if (!Enum.TryParse(parts[0], out PieceType type)) continue;
                bool selected = string.Equals(_draftLoadout.Get(type), parts[1], StringComparison.Ordinal);
                pair.Value.EnableInClassList("candy-variant-selected", selected);
            }
        }

        private void ConfirmDraft()
        {
            if (_draftLoadout == null) _draftLoadout = CandyLoadout.Default();
            _draftLoadout.Normalize();
            _draftLoadout.Save();
            if (_draftOnline) _controller.StartOnlineSearch(_draftLoadout.Clone());
            else _controller.StartBot(_draftLoadout.Clone());
        }

        private void HideAllOverlays()
        {
            SetHidden(_introOverlay);
            SetHidden(_draftOverlay);
            SetHidden(_searchOverlay);
            SetHidden(_resultOverlay);
            if (_toast != null) _toast.AddToClassList("hidden");
        }

        private static void SetHidden(VisualElement element)
        {
            if (element != null) element.style.display = DisplayStyle.None;
        }

        private static Button MakeButton(string text, string classes)
        {
            var button = new Button { text = text };
            button.AddToClassList("candy-btn");
            if (!string.IsNullOrEmpty(classes))
            {
                string[] parts = classes.Split(' ');
                for (int i = 0; i < parts.Length; i++)
                {
                    if (!string.IsNullOrEmpty(parts[i])) button.AddToClassList(parts[i]);
                }
            }
            HookButton(button);
            return button;
        }

        private static void HookButton(Button button)
        {
            if (button == null) return;
            button.RegisterCallback<PointerEnterEvent>(_ =>
                WilderGambit.Audio.MusicManager.Instance?.PlayHoverSound());
            button.RegisterCallback<PointerDownEvent>(_ =>
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound());
        }
    }
}
