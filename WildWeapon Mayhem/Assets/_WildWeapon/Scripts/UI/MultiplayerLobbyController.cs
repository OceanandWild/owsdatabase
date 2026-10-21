using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;
using UnityEngine.UI;
using WildWeapon.Pvp;

namespace WildWeapon.UI
{
    /// <summary>
    /// Lobby multijugador ONLINE: sala por codigo (4-6 digitos) sobre el servicio de
    /// duelos (server.js -> /wildweapon/pvp). El anfitrion crea la sala, suma o resta
    /// bots y arranca la partida; los demas entran escribiendo el codigo. Si la sala
    /// llego a los 15 combatientes, el que intenta entrar queda en espera (con boton
    /// para cancelar) hasta que el server le avise que se libero un asiento.
    ///
    /// Cada asiento se dibuja con la grilla de <see cref="LobbyLayout"/> (tarjeta del
    /// jugador + orbe de color + asiento + nombre + control + equipo); solo el asiento
    /// propio es editable y todo cambio viaja al server (lobby_set), que devuelve el
    /// roster completo. Los modales (entrar a la sala / sala llena) se arman por codigo
    /// con los sprites del lobby: panel, botones y campos.
    /// </summary>
    public class MultiplayerLobbyController : MonoBehaviour
    {
        public const int MaxPlayers = 15;

        /// <summary>Controles ofrecidos, en el orden que guarda <see cref="GameSession.PlayerSlot.controlIndex"/>.</summary>
        public static readonly string[] ControlNames = { "TECLADO", "PAD 1", "PAD 2", "PAD 3", "PAD 4" };
        /// <summary>Equipos ofrecidos, en el orden que guarda <see cref="GameSession.PlayerSlot.team"/>.</summary>
        public static readonly string[] TeamNames = { "EQUIPO A", "EQUIPO B", "EQUIPO C", "EQUIPO D" };

        private enum Step { Connect, Rooms, Waiting, Room }

        [Header("Lista")]
        public RectTransform listContent;
        public ScrollRect listScroll;
        [Tooltip("Placa 9-slice de las filas (Art/VFX/ui_panel).")]
        public Sprite rowPlate;
        [Tooltip("Circulo suave para el color del jugador (Art/VFX/soft_circle).")]
        public Sprite orbSprite;
        [Tooltip("Tarjeta del jugador (Art/Sprites/ww_lobby_player_card): medallon + asiento.")]
        public Sprite playerCard;
        [Tooltip("Placa grande de los modales (Art/Sprites/ww_lobby_panel).")]
        public Sprite modalPlate;
        [Tooltip("Placa de boton de los modales (Art/Sprites/ww_lobby_button_add).")]
        public Sprite modalButton;

        [Header("Textos")]
        public Text subLabel;
        public Text footHint;
        public Text countLabel;

        [Header("Botones")]
        public Button addButton;
        public Button removeButton;
        public Button continueButton;
        public Button backButton;

        [Header("Equipos")]
        [Tooltip("Boton para activar/desactivar equipos. Si queda vacio se crea por codigo.")]
        public Button teamsButton;

        [Header("Fundido")]
        public CanvasGroup fader;
        public float fadeTime = 0.45f;

        [Header("Paleta")]
        // Se completa en Start: GameSession tiene un constructor estatico que toca
        // PlayerPrefs y no se puede ejecutar desde el constructor del MonoBehaviour.
        public Color[] palette;

        // Tints de las piezas internas (mismo lenguaje que el menu: acero frio + acento).
        private static readonly Color RowTint = new Color(0.07f, 0.09f, 0.13f, 0.92f);
        private static readonly Color FieldTint = new Color(0.02f, 0.03f, 0.05f, 0.90f);
        private static readonly Color StepTint = new Color(0.10f, 0.13f, 0.19f, 0.96f);
        private static readonly Color LabelDim = new Color(1f, 1f, 1f, 0.58f);
        private static readonly Color ReadyText = new Color(0.62f, 0.85f, 1f, 0.85f);
        private static readonly Color WarnText = new Color(1f, 0.72f, 0.30f, 0.90f);
        private static readonly Color GoldText = new Color(1f, 0.84f, 0.42f, 0.95f);
        private static readonly Color Accent = new Color(0.36f, 0.86f, 1f);

        private Font _font;
        private bool _loading;

        // ---- Red ----
        private PvpClient _client;
        private Step _step = Step.Connect;
        private readonly List<PvpLobbyPlayer> _roster = new List<PvpLobbyPlayer>();
        private string _code = "";
        private int _seat = -1;
        private bool _host;
        private bool _inRoom;
        private bool _starting;
        private int _waiters;
        private PvpMsg _pendingState;
        private bool _stateDirty;
        /// <summary>Equipos activos en la sala (lo decide el anfitrion).</summary>
        private bool _teams = true;

        // ---- Modales ----
        private CanvasGroup _modal;
        private RectTransform _roomStep;
        private RectTransform _waitStep;
        private RectTransform _connectStep;
        private Text _roomStatus;
        private Text _waitTitle;
        private Text _waitSub;
        private Text _connectStatus;
        private RectTransform _waitOrb;
        private RectTransform _connectOrb;
        private InputField _codeInput;
        private Button _createButton;
        private Button _joinButton;
        private Button _connectRetry;
        private Button _connectBack;
        private Text _teamsLabel;

        // ---- Conexion en curso / accion pendiente ----
        private bool _watchingConnection;
        private bool _pendingCreate;
        private string _pendingJoin = "";

        private float _statusFlash;

        void Start()
        {
            Time.timeScale = 1f;
            if (_font == null) _font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (palette == null || palette.Length == 0) palette = GameSession.Palette;

            // Los botones del tablero ya vienen cableados desde la escena
            // (AddPlayer / RemoveLast / Continue / Back): no se agregan aca para
            // no disparar dos veces cada accion.

            BuildModals();
            BuildTeamsToggle();
            Refresh();

            _client = PvpClient.Ensure();
            _client.Message += OnMessage;
            if (_client.IsOnline) OnConnected();
            else BeginConnect();

            if (fader != null) StartCoroutine(Fade(1f, 0f, null));
        }

        void OnDestroy()
        {
            if (_client != null) _client.Message -= OnMessage;
        }

        void Update()
        {
            if (_loading) return;

            if (_watchingConnection) TickConnection();
            if (_connectOrb != null && _connectStep != null && _connectStep.gameObject.activeSelf)
                AnimateConnectOrb();

            // Estado del lobby pendiente (ver ApplyState): un refresco por frame.
            if (_stateDirty)
            {
                _stateDirty = false;
                var pending = _pendingState;
                _pendingState = null;
                if (pending != null) ApplyStateNow(pending);
            }

            // El orbe del modal "sala llena" late mientras se espera un lugar.
            if (_waitOrb != null && _waitStep != null && _waitStep.gameObject.activeSelf)
            {
                float k = 1f + 0.06f * Mathf.Sin(Time.unscaledTime * 3.4f);
                _waitOrb.localScale = new Vector3(k, k, 1f);
                var img = _waitOrb.GetComponent<Image>();
                if (img != null)
                {
                    var c = img.color;
                    c.a = 0.55f + 0.35f * Mathf.Sin(Time.unscaledTime * 3.4f);
                    img.color = c;
                }
            }

            if (_statusFlash > 0f)
            {
                _statusFlash -= Time.unscaledDeltaTime;
                if (_statusFlash <= 0f && _roomStatus != null && _step == Step.Rooms)
                    _roomStatus.text = DefaultRoomStatus();
            }

            var kb = Keyboard.current;
            var pad = Gamepad.current;
            bool editingText = IsEditingTextField();
            if (kb != null && kb.escapeKey.wasPressedThisFrame)
            {
                // Escape mientras se edita el nombre/codigo: solo suelta el foco.
                // Backspace NO es atajo de "volver": lo usa el campo para borrar letras.
                if (editingText) DeselectTextField();
                else Back();
            }
            else if (pad != null && pad.selectButton.wasPressedThisFrame)
            {
                if (editingText) DeselectTextField();
                else Back();
            }
        }

        /// <summary>Hay un InputField enfocado (nombre del asiento, codigo de sala, etc.).</summary>
        private static bool IsEditingTextField()
        {
            var es = UnityEngine.EventSystems.EventSystem.current;
            var selected = es != null ? es.currentSelectedGameObject : null;
            return selected != null && selected.GetComponentInParent<InputField>() != null;
        }

        private static void DeselectTextField()
        {
            var es = UnityEngine.EventSystems.EventSystem.current;
            if (es != null) es.SetSelectedGameObject(null);
        }

        // =================================================================
        // Estado observable (pruebas y depuracion)
        // =================================================================

        public bool IsConnected => _client != null && _client.IsConnected;
        public string StepName => _step.ToString();
        public string RoomCode => _code;
        public int Seat => _seat;
        public bool IsHost => _host;
        public bool WaitingSlot => _step == Step.Waiting;
        public int RosterCount => _roster != null ? _roster.Count : 0;
        public int BotsInRoster => BotCount();
        public int WaitersInRoom => _waiters;
        /// <summary>La sala juega con equipos (si no, es todos contra todos).</summary>
        public bool TeamsEnabled => _teams;

        /// <summary>Escribe el codigo en el campo (pegar/pegar rapido o pruebas).</summary>
        public void SetCode(string code)
        {
            if (_codeInput != null) _codeInput.text = OnlyDigits(code ?? "");
        }

        // =================================================================
        // Conexion y sala
        // =================================================================

        /// <summary>
        /// Muestra el paso "CONECTANDO" y arranca (o retoma) la ventana del PvpClient.
        /// Si Render esta dormido puede tardar 1-2 minutos; el texto muestra el progreso
        /// y la accion pedida (crear/entrar) se envia sola apenas haya conexion.
        /// </summary>
        private void BeginConnect()
        {
            if (_client == null) _client = PvpClient.Ensure();
            _watchingConnection = true;
            ShowConnectStep();
            _client.Connect();
        }

        private void ShowConnectStep()
        {
            _step = Step.Connect;
            if (_modal != null) { _modal.alpha = 1f; _modal.blocksRaycasts = true; }
            if (_roomStep != null) _roomStep.gameObject.SetActive(false);
            if (_waitStep != null) _waitStep.gameObject.SetActive(false);
            if (_connectStep != null) _connectStep.gameObject.SetActive(true);
            if (_connectStatus != null) _connectStatus.text = "Despertando el servidor de duelos...";
            SetConnectRetryVisible(false);
        }

        /// <summary>
        /// Muestra u oculta REINTENTAR del paso "CONECTANDO" y acomoda el
        /// "VOLVER AL MENU": centrado cuando va solo, a la derecha cuando
        /// comparten fila con el reintento.
        /// </summary>
        private void SetConnectRetryVisible(bool visible)
        {
            if (_connectRetry != null) _connectRetry.gameObject.SetActive(visible);
            if (_connectBack != null)
            {
                var rt = _connectBack.GetComponent<RectTransform>();
                if (rt != null) rt.anchoredPosition = new Vector2(visible ? 170f : 0f, -272f);
            }
        }

        /// <summary>Cada frame mientras se espera la conexion: progreso, tiempo y reintento.</summary>
        private void TickConnection()
        {
            if (_client == null) return;

            if (_client.IsOnline)
            {
                _watchingConnection = false;
                OnConnected();
                return;
            }

            if (_client.IsConnecting)
            {
                if (_connectStatus != null)
                {
                    string dots = new string('.', 1 + (int)(Time.unscaledTime * 2f) % 3);
                    int secs = Mathf.FloorToInt(_client.ConnectSeconds);
                    _connectStatus.text = _client.PhaseDetail.TrimEnd('.') + dots + "\n" +
                        secs + " s - la primera vez puede tardar 1 o 2 minutos.\n" +
                        "No cierres la ventana.";
                }
                SetConnectRetryVisible(false);
                return;
            }

            _watchingConnection = false;
            if (_connectStatus != null)
            {
                string detail = string.IsNullOrEmpty(_client.LastError) ? "" : "\nDetalle: " + _client.LastError;
                _connectStatus.text = "No se pudo despertar el servidor.\n" +
                    "Revisa tu conexion a internet y toca REINTENTAR." + detail;
            }
            SetConnectRetryVisible(true);
        }

        private void RetryConnection()
        {
            if (_loading) return;
            BeginConnect();
        }

        private void AnimateConnectOrb()
        {
            float k = 1f + 0.06f * Mathf.Sin(Time.unscaledTime * 3.2f);
            _connectOrb.localScale = new Vector3(k, k, 1f);
            var img = _connectOrb.GetComponentInChildren<Image>();
            if (img != null)
            {
                var c = img.color;
                c.a = 0.45f + 0.35f * Mathf.Sin(Time.unscaledTime * 3.2f);
                img.color = c;
            }
        }

        private void OnConnected()
        {
            if (_inRoom) return;

            GoRooms();

            // Lo que el jugador pidio mientras el servidor despertaba se manda ahora.
            if (_pendingCreate)
            {
                _pendingCreate = false;
                SendCreate();
            }
            else if (!string.IsNullOrEmpty(_pendingJoin))
            {
                string code = _pendingJoin;
                _pendingJoin = "";
                SendJoin(code);
            }
        }

        public void CreateRoom()
        {
            if (_loading || _client == null) return;

            if (!_client.IsConnected)
            {
                _pendingCreate = true;
                _pendingJoin = "";
                BeginConnect();
                return;
            }
            SendCreate();
        }

        private void SendCreate()
        {
            SetRoomStatus("CREANDO SALA...", ReadyText);
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.LobbyNew,
                name = PlayerName(),
                color = GameSession.GetColorIndex(0),
            });
        }

        public void JoinRoom()
        {
            if (_loading || _client == null) return;

            string code = _codeInput != null ? (_codeInput.text ?? "") : "";
            code = OnlyDigits(code);
            if (code.Length < 4)
            {
                SetRoomStatus("El codigo tiene entre 4 y 6 digitos.", WarnText);
                return;
            }
            if (_codeInput != null) _codeInput.text = code;

            if (!_client.IsConnected)
            {
                _pendingJoin = code;
                _pendingCreate = false;
                BeginConnect();
                return;
            }
            SendJoin(code);
        }

        private void SendJoin(string code)
        {
            SetRoomStatus("ENTRANDO A LA SALA " + code + "...", ReadyText);
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.LobbyJoin,
                room = code,
                name = PlayerName(),
                color = GameSession.GetColorIndex(0),
            });
        }

        /// <summary>Boton VOLVER del tablero: sale de la sala o, si ya estas afuera, vuelve al menu.</summary>
        public void Back()
        {
            if (_loading) return;

            // Escape con el campo de codigo enfocado: solo suelta el foco.
            var es = UnityEngine.EventSystems.EventSystem.current;
            if (es != null && _codeInput != null && es.currentSelectedGameObject == _codeInput.gameObject)
            {
                es.SetSelectedGameObject(null);
                return;
            }

            if (_inRoom || _step == Step.Waiting)
            {
                LeaveRoom();
                GoRooms();
                return;
            }

            _loading = true;
            if (_client != null && _client.IsConnected) _client.Send(new PvpMsg { t = PvpMsgType.Leave });
            if (_client != null) _client.LeaveAndDisconnect();
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MenuScene)));
        }

        /// <summary>Sale de la sala (o de la lista de espera) sin cortar la conexion.</summary>
        public void LeaveRoom()
        {
            _inRoom = false;
            _starting = false;
            _waiters = 0;
            _roster.Clear();
            _seat = -1;
            _host = false;
            _code = "";
            if (_client != null && _client.IsConnected) _client.Send(new PvpMsg { t = PvpMsgType.Leave });
            Refresh();
        }

        /// <summary>Cancelar del modal "sala llena": suelta la espera y vuelve al paso 1.</summary>
        public void CancelWait()
        {
            LeaveRoom();
            GoRooms();
            SetRoomStatus("Cancelaste la espera. Podes probar otro codigo.", ReadyText);
        }

        // ---- Bots (solo anfitrion) ----

        /// <summary>Boton + BOT (nombre que ya invoca la escena).</summary>
        public void AddPlayer() => AddBot(1);

        /// <summary>Boton - BOT (nombre que ya invoca la escena).</summary>
        public void RemoveLast() => AddBot(-1);

        /// <summary>Boton ARRANCAR (nombre que ya invoca la escena).</summary>
        public void Continue() => StartMatch();

        private void AddBot(int delta)
        {
            if (!Ready() || !_host || !_inRoom) return;
            int bots = BotCount();
            int target = Mathf.Clamp(bots + delta, 0, MaxPlayers - Humans());
            _client.Send(new PvpMsg { t = PvpMsgType.LobbyBots, n = target });
        }

        // ---- Equipos (solo anfitrion) ----

        /// <summary>
        /// Boton de equipos de la sala. Con equipos activos los companeros no se
        /// danan; apagados, la partida es todos contra todos.
        /// </summary>
        public void ToggleTeams()
        {
            if (!Ready() || !_host || !_inRoom || _starting) return;
            _teams = !_teams;
            UpdateTeamsToggle();
            if (_client != null && _client.IsConnected)
                _client.Send(new PvpMsg { t = PvpMsgType.LobbyTeams, teams = _teams ? 1 : 0 });
        }

        // ---- Arranque (solo anfitrion) ----

        private void StartMatch()
        {
            if (!Ready() || !_host || !_inRoom || _roster.Count < 2 || _starting) return;
            _starting = true;
            _client.Send(new PvpMsg { t = PvpMsgType.LobbyStart });
            if (footHint != null)
            {
                footHint.text = "ARRANCANDO LA PARTIDA...";
                footHint.color = ReadyText;
            }
        }

        // =================================================================
        // Mensajes del server
        // =================================================================

        private void OnMessage(PvpMsg m)
        {
            if (_loading) return;
            switch (m.t)
            {
                case PvpMsgType.LobbyState:
                    ApplyState(m);
                    break;

                case PvpMsgType.LobbyFull:
                    _inRoom = false;
                    _code = m.code ?? m.room ?? _code;
                    GoWaiting(m);
                    break;

                case PvpMsgType.LobbyClosed:
                    LeaveRoom();
                    GoRooms();
                    SetRoomStatus(string.IsNullOrEmpty(m.msg) ? "La sala se cerro." : m.msg + ".", WarnText);
                    break;

                case PvpMsgType.LobbyError:
                    SetRoomStatus(string.IsNullOrEmpty(m.msg) ? "No se pudo entrar a la sala." : m.msg, WarnText);
                    if (_step == Step.Waiting) { LeaveRoom(); GoRooms(); }
                    break;

                case PvpMsgType.Matched:
                    OnMatched(m);
                    break;

                case PvpMsgType.Error:
                    SetRoomStatus(string.IsNullOrEmpty(m.msg) ? "El server rechazo la operacion." : m.msg, WarnText);
                    break;

                case PvpMsgType.OppLeft:
                case PvpMsgType.Queued:
                case PvpMsgType.RematchWait:
                    break;
            }
        }

        private void ApplyState(PvpMsg m)
        {
            // El server puede mandar varios estados seguidos: se aplica uno por frame
            // (el ultimo gana) para no reconstruir la lista N veces en el mismo tick.
            _pendingState = m;
            _stateDirty = true;
        }

        private void ApplyStateNow(PvpMsg m)
        {
            _inRoom = true;
            _host = m.host;
            _seat = m.seat;
            _waiters = Mathf.Max(0, m.waiters);
            _teams = m.teams != 0;
            _code = string.IsNullOrEmpty(m.code) ? m.room : m.code;
            _roster.Clear();
            if (m.players != null) _roster.AddRange(m.players);
            _roster.Sort((a, b) => a.seat.CompareTo(b.seat));

            GoRoom();
            Refresh();
        }

        private void OnMatched(PvpMsg m)
        {
            if (!_inRoom && !_starting) return;             // nadie pidio arrancar desde esta sala
            GameSession.Mode = GameMode.Pvp;
            GameSession.PvpSeat = m.seat;
            GameSession.PvpHost = m.host;
            GameSession.PvpSeed = Mathf.Max(1, m.seed);
            // Equipos: el anfitrion decide si la sala pelea por equipos o todos
            // contra todos. El equipo propio viaja en el matched.
            GameSession.PvpTeams = m.teams != 0;
            GameSession.PvpTeam = m.team >= 0 ? m.team : Mathf.Abs(m.seat) % 4;
            GameSession.PvpLocalName = PlayerName();
            GameSession.PvpOpps.Clear();
            if (m.opps != null) GameSession.PvpOpps.AddRange(m.opps);
            GameSession.PvpOpponentName = "LA SALA";
            if (m.opps != null && m.opps.Length > 0 && !string.IsNullOrEmpty(m.opps[0].name))
                GameSession.PvpOpponentName = m.opps[0].name;

            _loading = true;
            if (fader != null) StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.ArenaScene)));
            else SceneManager.LoadScene(GameSession.ArenaScene);
        }

        // =================================================================
        // Lista
        // =================================================================

        private void Refresh()
        {
            if (listContent != null)
            {
                for (int i = listContent.childCount - 1; i >= 0; i--)
                {
                    var child = listContent.GetChild(i).gameObject;
                    child.SetActive(false);       // fuera del layout antes de destruirse
                    Destroy(child);
                }

                for (int i = 0; i < _roster.Count; i++) BuildRow(i);
                LayoutRebuilder.ForceRebuildLayoutImmediate(listContent);
            }

            RefreshStatus();
            ScrollToNewestIfNeeded();
        }

        private void BuildRow(int index)
        {
            var slot = _roster[index];
            var color = ColorOf(slot.color);
            bool mine = slot.seat == _seat;

            var row = NewRect(listContent, "Row" + (slot.seat + 1).ToString("00"), 0f, 0f, 0f, LobbyLayout.RowH);
            var rowRt = (RectTransform)row.transform;
            rowRt.sizeDelta = new Vector2(0f, LobbyLayout.RowH);   // el ancho lo define el layout
            var layout = row.gameObject.AddComponent<LayoutElement>();
            layout.minHeight = layout.preferredHeight = LobbyLayout.RowH;
            layout.flexibleHeight = 0f;

            // Placa de la fila
            var plate = NewImage(row.transform, "Bg", rowPlate, RowTint);
            Stretch(plate.rectTransform);
            if (rowPlate != null) { plate.type = Image.Type.Sliced; plate.pixelsPerUnitMultiplier = 3f; }
            if (slot.host)
            {
                var hostOutline = plate.gameObject.AddComponent<Outline>();
                hostOutline.effectColor = new Color(1f, 0.82f, 0.35f, 0.55f);
                hostOutline.effectDistance = new Vector2(2f, -2f);
            }

            // Tarjeta del jugador (ww_lobby_player_card): el medallon pintado lleva el
            // orbe del color y el panel de la derecha el numero de asiento.
            if (playerCard != null)
            {
                var card = NewImage(row.transform, "Card", playerCard, Color.white);
                Rect(card.rectTransform, LobbyLayout.CardX, 0f, LobbyLayout.CardW, LobbyLayout.CardH);
            }
            else
            {
                // Sin el arte de la tarjeta queda la barra de acento, en la misma columna.
                var accent = NewImage(row.transform, "Accent", rowPlate, color);
                Rect(accent.rectTransform, LobbyLayout.BarX, 0f, LobbyLayout.BarW, LobbyLayout.BarH);
                if (rowPlate != null) { accent.type = Image.Type.Sliced; accent.pixelsPerUnitMultiplier = 8f; }
            }

            // Numero de asiento, tenido con el color del jugador (se aclara porque el
            // panel de la tarjeta es oscuro).
            var seatColor = Color.Lerp(color, Color.white, 0.30f);
            var seat = NewText(row.transform, "Seat", "J" + (slot.seat + 1), 22, seatColor);
            Rect(seat.rectTransform, LobbyLayout.CardSeatX, 0f, LobbyLayout.CardSeatW, 30f);
            seat.alignment = TextAnchor.MiddleCenter;
            var seatSh = seat.gameObject.AddComponent<Shadow>();
            seatSh.effectColor = new Color(0f, 0f, 0f, 0.75f);
            seatSh.effectDistance = new Vector2(1.5f, -1.5f);

            // Orbe de color: en el asiento propio, click para pasar al siguiente color.
            var colorRt = NewRect(row.transform, "Color", LobbyLayout.CardColorX - LobbyLayout.ColorButtonSize * 0.5f,
                0f, LobbyLayout.ColorButtonSize, LobbyLayout.ColorButtonSize);
            Image orb = null;
            if (mine)
            {
                var colorBtn = colorRt.gameObject.AddComponent<Button>();
                colorBtn.transition = Selectable.Transition.ColorTint;
                colorBtn.colors = Highlighted();

                var glow = NewImage(colorRt, "Glow", orbSprite, new Color(color.r, color.g, color.b, 0.30f));
                Centered(glow.rectTransform, LobbyLayout.ColorGlowSize, LobbyLayout.ColorGlowSize);
                orb = NewImage(colorRt, "Orb", orbSprite, color);
                Centered(orb.rectTransform, LobbyLayout.ColorSize, LobbyLayout.ColorSize);
                orb.raycastTarget = true;      // es el blanco del click
                colorBtn.targetGraphic = orb;

                int slotIndex = index;
                colorBtn.onClick.AddListener(() => CycleColor(slotIndex, orb));
            }
            else
            {
                var glow = NewImage(colorRt, "Glow", orbSprite, new Color(color.r, color.g, color.b, 0.18f));
                Centered(glow.rectTransform, LobbyLayout.ColorGlowSize, LobbyLayout.ColorGlowSize);
                orb = NewImage(colorRt, "Orb", orbSprite, color);
                Centered(orb.rectTransform, LobbyLayout.ColorSize, LobbyLayout.ColorSize);
            }

            // Nombre: en el asiento propio es un campo editable.
            var nameRt = NewRect(row.transform, "Name", LobbyLayout.NameX, 0f, LobbyLayout.NameW, LobbyLayout.FieldH);
            var nameBg = NewImage(nameRt, "Bg", rowPlate, mine ? FieldTint : StepTint);
            Stretch(nameBg.rectTransform);
            nameBg.raycastTarget = true;
            if (rowPlate != null) { nameBg.type = Image.Type.Sliced; nameBg.pixelsPerUnitMultiplier = 8f; }

            Color nameColor = slot.bot ? new Color(0.98f, 0.80f, 0.45f) : new Color(0.92f, 0.95f, 1f);
            Text nameTxt = null;

            if (mine)
            {
                var nameOutline = nameBg.gameObject.AddComponent<Outline>();
                nameOutline.effectColor = new Color(0.35f, 0.80f, 1f, 0.20f);
                nameOutline.effectDistance = new Vector2(2f, -2f);

                var field = nameRt.gameObject.AddComponent<InputField>();
                field.targetGraphic = nameBg;
                field.lineType = InputField.LineType.SingleLine;
                field.characterLimit = 14;
                field.customCaretColor = true;
                field.caretColor = new Color(0.5f, 0.9f, 1f);
                field.selectionColor = new Color(0.30f, 0.85f, 1f, 0.35f);
                field.colors = Highlighted();

                nameTxt = NewText(nameRt, "Text", slot.name, 19, nameColor);
                Rect(nameTxt.rectTransform, 14f, 0f, LobbyLayout.NameW - 28f, 30f);
                nameTxt.alignment = TextAnchor.MiddleLeft;
                nameTxt.supportRichText = false;
                field.textComponent = nameTxt;
                field.text = slot.name;

                int slotIndex = index;
                field.onEndEdit.AddListener(v =>
                {
                    string clean = string.IsNullOrWhiteSpace(v) ? null : v.Trim();
                    if (clean == null) { field.text = _roster.Count > slotIndex ? _roster[slotIndex].name : slot.name; return; }
                    SendSet(name: clean);
                });
            }
            else
            {
                nameTxt = NewText(nameRt, "Text", slot.name, 19, nameColor);
                Rect(nameTxt.rectTransform, 14f, 0f, LobbyLayout.NameW - 28f, 30f);
                nameTxt.alignment = TextAnchor.MiddleLeft;
            }

            // Control y equipo: en el asiento propio ciclan con el click; en el resto
            // y en los bots se leen nomas (el server manda la verdad).
            var controlRt = NewRect(row.transform, "Control", LobbyLayout.ControlX, 0f, LobbyLayout.ControlW, LobbyLayout.FieldH);
            string controlText = slot.bot ? "IA" : ControlText(slot.control);
            var controlValue = NewText(controlRt, "Value", controlText, 18, slot.bot ? GoldText : Color.white);
            Stretch(controlValue.rectTransform);
            controlValue.rectTransform.offsetMin = new Vector2(34f, 0f);
            controlValue.rectTransform.offsetMax = new Vector2(-34f, 0f);
            if (mine) Stepper(controlRt, controlValue, () =>
            {
                int next = (slot.control + 1) % ControlNames.Length;
                controlValue.text = ControlText(next);
                SendSet(control: next);
            });

            var teamRt = NewRect(row.transform, "Team", LobbyLayout.TeamX, 0f, LobbyLayout.TeamW, LobbyLayout.FieldH);
            string teamLabel = _teams ? TeamText(slot.team) : "SIN EQUIPOS";
            var teamValue = NewText(teamRt, "Value", teamLabel, _teams ? 18 : 17,
                _teams ? Color.white : new Color(1f, 0.80f, 0.45f));
            Stretch(teamValue.rectTransform);
            teamValue.rectTransform.offsetMin = new Vector2(34f, 0f);
            teamValue.rectTransform.offsetMax = new Vector2(-34f, 0f);
            if (mine && _teams) Stepper(teamRt, teamValue, () =>
            {
                int next = (slot.team + 1) % TeamNames.Length;
                teamValue.text = TeamText(next);
                SendSet(team: next);
            });
        }

        /// <summary>Campo con flechas: cada click pasa al valor siguiente.</summary>
        private Button Stepper(RectTransform fieldRt, Text value, UnityEngine.Events.UnityAction cycle)
        {
            var bg = NewImage(fieldRt, "Bg", rowPlate, StepTint);
            bg.transform.SetAsFirstSibling();   // detras del valor y las flechas
            Stretch(bg.rectTransform);
            bg.raycastTarget = true;
            if (rowPlate != null) { bg.type = Image.Type.Sliced; bg.pixelsPerUnitMultiplier = 8f; }
            var outline = bg.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(1f, 1f, 1f, 0.10f);
            outline.effectDistance = new Vector2(2f, -2f);

            var btn = fieldRt.gameObject.AddComponent<Button>();
            btn.targetGraphic = bg;
            btn.colors = Highlighted();
            btn.onClick.AddListener(cycle);

            var left = NewText(fieldRt, "Left", "<", 20, LabelDim);
            Rect(left.rectTransform, 6f, 0f, 26f, 30f);
            left.alignment = TextAnchor.MiddleCenter;

            var right = NewText(fieldRt, "Right", ">", 20, LabelDim);
            Rect(right.rectTransform, fieldRt.sizeDelta.x - 32f, 0f, 26f, 30f);
            right.alignment = TextAnchor.MiddleCenter;

            value.raycastTarget = false;
            return btn;
        }

        private void CycleColor(int slotIndex, Image orb)
        {
            if (slotIndex < 0 || slotIndex >= _roster.Count) return;
            var slot = _roster[slotIndex];
            int next = (slot.color + 1) % palette.Length;
            orb.color = ColorOf(next);
            SendSet(color: next);
        }

        private void SendSet(string name = null, int? color = null, int? team = null, int? control = null)
        {
            if (_client == null || !_client.IsConnected || !_inRoom) return;
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.LobbySet,
                name = name,
                color = color ?? -1,
                team = team ?? -1,
                control = control ?? -1,
            });
        }

        // =================================================================
        // Estado de los textos y de los botones
        // =================================================================

        private void RefreshStatus()
        {
            int humans = Humans();
            int bots = BotCount();
            int total = _roster.Count;

            if (_inRoom)
            {
                if (subLabel != null)
                    subLabel.text = "SALA " + _code + " · " + total + " / " + MaxPlayers + " COMBATIENTES";
                if (countLabel != null)
                {
                    string modeText = _teams
                        ? TeamCount() + (TeamCount() == 1 ? " EQUIPO" : " EQUIPOS")
                        : "SIN EQUIPOS";
                    countLabel.text = humans + (humans == 1 ? " HUMANO" : " HUMANOS") +
                        (bots > 0 ? " · " + bots + (bots == 1 ? " BOT" : " BOTS") : "") +
                        " · " + modeText +
                        (_waiters > 0 ? " · " + _waiters + " EN ESPERA" : "");
                }
                if (footHint != null)
                {
                    if (_starting) { footHint.text = "ARRANCANDO LA PARTIDA..."; footHint.color = ReadyText; }
                    else if (_waiters > 0 && _host) { footHint.text = _waiters + (_waiters == 1 ? " ESPERA UN LUGAR · BAJA UN BOT" : " ESPERAN UN LUGAR · BAJA UN BOT"); footHint.color = GoldText; }
                    else if (_host) { footHint.text = total >= 2 ? "SOS EL ANFITRION · ARRANCA CUANDO QUIERAS" : "SUMA UN BOT O ESPERA A QUE ENTRE ALGUIEN"; footHint.color = _host ? GoldText : WarnText; }
                    else { footHint.text = "ESPERANDO AL ANFITRION..."; footHint.color = ReadyText; }
                }

                SetButton(addButton, _host && bots < MaxPlayers - humans && !_starting);
                SetButton(removeButton, _host && bots > 0 && !_starting);
                SetButton(continueButton, _host && total >= 2 && !_starting);
                SetButton(backButton, !_starting);
                SetLabel(continueButton, _host ? "ARRANCAR" : "ESPERANDO");
                SetLabel(addButton, "+ BOT");
                SetLabel(removeButton, "- BOT");
            }
            else
            {
                if (subLabel != null) subLabel.text = "SALA ONLINE · CODIGO DE 4 A 6 DIGITOS";
                if (countLabel != null) countLabel.text = "SIN SALA · " + MaxPlayers + " ASIENTOS DISPONIBLES";
                if (footHint != null) { footHint.text = "CREA UNA SALA O ENTRA CON UN CODIGO"; footHint.color = ReadyText; }
                SetButton(addButton, false);
                SetButton(removeButton, false);
                SetButton(continueButton, false);
                SetButton(backButton, true);
                SetLabel(continueButton, "CONTINUAR");
            }

            UpdateTeamsToggle();
        }

        // =================================================================
        // Boton de equipos (sala)
        // =================================================================

        /// <summary>
        /// Crea el boton de equipos si la escena no lo trae cableado. Va debajo de
        /// la botonera, centrado, y solo se ve cuando estas adentro de una sala.
        /// </summary>
        private void BuildTeamsToggle()
        {
            if (teamsButton == null)
            {
                var plate = modalButton != null ? modalButton : rowPlate;
                var img = NewImage(transform, "BtnEquipos", plate, new Color(0.12f, 0.16f, 0.24f, 0.96f));
                CenteredAt(img.rectTransform, new Vector2(0f, -492f), new Vector2(560f, 58f));
                img.raycastTarget = true;
                if (rowPlate != null && plate == rowPlate)
                {
                    img.type = Image.Type.Sliced;
                    img.pixelsPerUnitMultiplier = 6f;
                }

                var outline = img.gameObject.AddComponent<Outline>();
                outline.effectColor = new Color(0.36f, 0.86f, 1f, 0.22f);
                outline.effectDistance = new Vector2(2f, -2f);

                teamsButton = img.gameObject.AddComponent<Button>();
                teamsButton.targetGraphic = img;
                teamsButton.colors = Highlighted();
                teamsButton.onClick.AddListener(ToggleTeams);

                var fx = img.gameObject.AddComponent<MenuButtonFx>();
                fx.hoverScale = 1.04f;
                fx.normalColor = Color.white;
                fx.hoverColor = new Color(0.55f, 0.90f, 1f);
            }

            if (_teamsLabel == null)
            {
                _teamsLabel = NewText(teamsButton.transform, "Label", "", 24, Color.white);
                Stretch(_teamsLabel.rectTransform);
                _teamsLabel.rectTransform.offsetMin = new Vector2(18f, 0f);
                _teamsLabel.rectTransform.offsetMax = new Vector2(-18f, 0f);
                var sh = _teamsLabel.gameObject.AddComponent<Shadow>();
                sh.effectColor = new Color(0f, 0f, 0f, 0.75f);
                sh.effectDistance = new Vector2(1.5f, -2f);
            }

            UpdateTeamsToggle();
        }

        /// <summary>Pinta el estado del boton: solo el anfitrion puede cambiarlo.</summary>
        private void UpdateTeamsToggle()
        {
            if (teamsButton == null) return;

            bool visible = _inRoom && _step == Step.Room;
            teamsButton.gameObject.SetActive(visible);
            if (!visible) return;

            bool canToggle = _host && !_starting;
            teamsButton.interactable = canToggle;

            var group = teamsButton.GetComponent<CanvasGroup>();
            if (group == null) group = teamsButton.gameObject.AddComponent<CanvasGroup>();
            group.alpha = _host ? (canToggle ? 1f : 0.55f) : 0.80f;

            var img = teamsButton.targetGraphic as Image;
            if (img != null)
                img.color = _teams
                    ? new Color(0.12f, 0.26f, 0.20f, 0.96f)
                    : new Color(0.30f, 0.20f, 0.10f, 0.96f);

            if (_teamsLabel != null)
            {
                _teamsLabel.text = _teams ? "EQUIPOS: ACTIVADOS" : "EQUIPOS: DESACTIVADOS";
                _teamsLabel.color = _teams
                    ? new Color(0.62f, 1f, 0.72f)
                    : new Color(1f, 0.82f, 0.48f);
            }
        }

        private int TeamCount()
        {
            bool[] used = new bool[TeamNames.Length];
            int n = 0;
            foreach (var p in _roster)
            {
                int t = Mathf.Clamp(p.team, 0, TeamNames.Length - 1);
                if (!used[t]) { used[t] = true; n++; }
            }
            return n;
        }

        private int Humans()
        {
            int n = 0;
            foreach (var p in _roster) if (!p.bot) n++;
            return n;
        }

        private int BotCount()
        {
            int n = 0;
            foreach (var p in _roster) if (p.bot) n++;
            return n;
        }

        /// <summary>Apaga el boton entero (placa + label) con un CanvasGroup, sin pelear con MenuButtonFx.</summary>
        private static void SetButton(Button b, bool on)
        {
            if (b == null) return;
            b.interactable = on;
            var group = b.GetComponent<CanvasGroup>();
            if (group == null) group = b.gameObject.AddComponent<CanvasGroup>();
            group.alpha = on ? 1f : 0.42f;
        }

        private static void SetLabel(Button b, string text)
        {
            if (b == null) return;
            var label = b.GetComponentInChildren<Text>();
            if (label != null && label.text != text) label.text = text;
        }

        private static string ControlText(int index)
        {
            return ControlNames[Mathf.Clamp(index, 0, ControlNames.Length - 1)];
        }

        private static string TeamText(int index)
        {
            return TeamNames[Mathf.Clamp(index, 0, TeamNames.Length - 1)];
        }

        private Color ColorOf(int colorIndex)
        {
            if (palette == null || palette.Length == 0) return Color.white;
            return palette[Mathf.Clamp(colorIndex, 0, palette.Length - 1)];
        }

        private static string OnlyDigits(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            var sb = new System.Text.StringBuilder(6);
            foreach (char c in value)
                if (c >= '0' && c <= '9' && sb.Length < 6) sb.Append(c);
            return sb.ToString();
        }

        private static string PlayerName()
        {
            const string key = "ww_pvp_name";
            string name = PlayerPrefs.GetString(key, "");
            if (string.IsNullOrEmpty(name))
            {
                name = "PORTADOR-" + Random.Range(100, 999);
                PlayerPrefs.SetString(key, name);
                PlayerPrefs.Save();
            }
            return name;
        }

        private bool Ready()
        {
            if (_loading || _client == null) return false;
            if (!_client.IsConnected)
            {
                SetRoomStatus("SIN CONEXION. Revisa la red e intenta de nuevo.", WarnText);
                return false;
            }
            return true;
        }

        private void ScrollToNewestIfNeeded()
        {
            if (listScroll == null || listContent == null) return;
            Canvas.ForceUpdateCanvases();
            var viewport = listScroll.viewport;
            if (viewport != null && listContent.rect.height > viewport.rect.height)
                listScroll.verticalNormalizedPosition = 0f;
        }

        private IEnumerator Fade(float from, float to, System.Action done)
        {
            if (fader != null)
            {
                fader.blocksRaycasts = true;
                float t = 0f;
                while (t < fadeTime)
                {
                    t += Time.unscaledDeltaTime;
                    fader.alpha = Mathf.Lerp(from, to, t / fadeTime);
                    yield return null;
                }
                fader.alpha = to;
                fader.blocksRaycasts = to > 0.5f;
            }
            done?.Invoke();
        }

        // =================================================================
        // Modales (entrar a la sala / sala llena)
        // =================================================================

        private void GoRooms()
        {
            _step = Step.Rooms;
            _inRoom = false;
            if (_modal != null) { _modal.alpha = 1f; _modal.blocksRaycasts = true; }
            if (_roomStep != null) _roomStep.gameObject.SetActive(true);
            if (_waitStep != null) _waitStep.gameObject.SetActive(false);
            if (_connectStep != null) _connectStep.gameObject.SetActive(false);
            SetRoomStatus(DefaultRoomStatus(), LabelDim);
            Refresh();
        }

        private void GoRoom()
        {
            _step = Step.Room;
            if (_modal != null) { _modal.alpha = 0f; _modal.blocksRaycasts = false; }
            if (_roomStep != null) _roomStep.gameObject.SetActive(false);
            if (_waitStep != null) _waitStep.gameObject.SetActive(false);
            if (_connectStep != null) _connectStep.gameObject.SetActive(false);
        }

        private void GoWaiting(PvpMsg m)
        {
            _step = Step.Waiting;
            if (_modal != null) { _modal.alpha = 1f; _modal.blocksRaycasts = true; }
            if (_roomStep != null) _roomStep.gameObject.SetActive(false);
            if (_waitStep != null) _waitStep.gameObject.SetActive(true);
            if (_connectStep != null) _connectStep.gameObject.SetActive(false);
            if (_waitTitle != null) _waitTitle.text = "SALA LLENA";
            if (_waitSub != null)
            {
                int cap = m.cap > 0 ? m.cap : MaxPlayers;
                int n = m.n > 0 ? m.n : cap;
                _waitSub.text = "Los " + cap + " lugares estan ocupados (" + n + "/" + cap + ").\n" +
                    "Te metemos apenas se libere uno" +
                    (m.pos > 1 ? " (puesto " + m.pos + " de la fila)." : ".");
            }
            RefreshStatus();
        }

        private void SetRoomStatus(string text, Color color)
        {
            if (_roomStatus == null) return;
            _roomStatus.text = text;
            _roomStatus.color = color;
            _statusFlash = 2.4f;
        }

        private string DefaultRoomStatus()
        {
            if (!_client.IsConnected) return "CONECTANDO CON EL SERVIDOR...";
            return "CREA UNA SALA Y PASA EL CODIGO, O ENTRA CON EL DE UN AMIGO.";
        }

        /// <summary>Arma los dos modales por codigo con los sprites del lobby.</summary>
        private void BuildModals()
        {
            var canvas = GetComponentInParent<Canvas>();
            Transform parent = canvas != null ? canvas.transform : transform;

            var modalGo = new GameObject("RoomModal", typeof(RectTransform));
            modalGo.transform.SetParent(parent, false);
            Stretch((RectTransform)modalGo.transform);
            _modal = modalGo.AddComponent<CanvasGroup>();
            _modal.alpha = 1f;

            var dim = NewImage(modalGo.transform, "Dim", null, new Color(0f, 0.02f, 0.05f, 0.78f));
            Stretch(dim.rectTransform);

            // ---- Paso 1: crear o entrar con codigo ----
            _roomStep = BuildStep(modalGo.transform, "StepRooms", "ENTRAR A LA SALA",
                "SALA ONLINE · EL ANFITRION ARMA EL PLANTEL (HASTA " + MaxPlayers + ")", out _roomStatus);

            var roomStep = _roomStep;
            _createButton = ModalButton(roomStep, "Create", "CREAR SALA", Accent, new Vector2(0f, 118f), new Vector2(420f, 92f),
                out _);
            _createButton.onClick.AddListener(CreateRoom);

            var or = NewText(roomStep, "Or", "O ENTRA CON EL CODIGO", 17, LabelDim);
            CenteredAt(or.rectTransform, new Vector2(0f, 44f), new Vector2(420f, 26f));

            // Campo del codigo + boton unir
            var inputRt = NewRectAt(roomStep, "CodeInput", new Vector2(-120f, -38f), new Vector2(300f, 76f));
            var inputBg = NewImage(inputRt, "Bg", rowPlate != null ? rowPlate : null, FieldTint);
            Stretch(inputBg.rectTransform);
            if (rowPlate != null) { inputBg.type = Image.Type.Sliced; inputBg.pixelsPerUnitMultiplier = 6f; }
            inputBg.raycastTarget = true;
            var inputOutline = inputBg.gameObject.AddComponent<Outline>();
            inputOutline.effectColor = new Color(0.35f, 0.80f, 1f, 0.25f);
            inputOutline.effectDistance = new Vector2(2f, -2f);

            _codeInput = inputRt.gameObject.AddComponent<InputField>();
            _codeInput.targetGraphic = inputBg;
            _codeInput.lineType = InputField.LineType.SingleLine;
            _codeInput.characterLimit = 6;
            _codeInput.characterValidation = InputField.CharacterValidation.Integer;
            _codeInput.customCaretColor = true;
            _codeInput.caretColor = new Color(0.5f, 0.9f, 1f);
            _codeInput.selectionColor = new Color(0.30f, 0.85f, 1f, 0.35f);
            _codeInput.colors = Highlighted();

            var inputText = NewText(inputRt, "Text", "", 34, Color.white);
            Stretch(inputText.rectTransform);
            inputText.rectTransform.offsetMin = new Vector2(18f, 0f);
            inputText.rectTransform.offsetMax = new Vector2(-18f, 0f);
            inputText.alignment = TextAnchor.MiddleCenter;
            inputText.supportRichText = false;
            _codeInput.textComponent = inputText;

            var placeholder = NewText(inputRt, "Placeholder", "CODIGO", 30, new Color(1f, 1f, 1f, 0.28f));
            Stretch(placeholder.rectTransform);
            placeholder.alignment = TextAnchor.MiddleCenter;
            _codeInput.placeholder = placeholder;

            _joinButton = ModalButton(roomStep, "Join", "UNIRSE", new Color(0.52f, 0.92f, 0.55f), new Vector2(230f, -38f), new Vector2(280f, 92f),
                out _);
            _joinButton.onClick.AddListener(JoinRoom);

            var backMenu = ModalButton(roomStep, "Menu", "VOLVER AL MENU", new Color(0.72f, 0.80f, 0.95f), new Vector2(0f, -256f), new Vector2(340f, 78f),
                out _);
            backMenu.onClick.AddListener(Back);

            // ---- Paso 2: sala llena ----
            _waitStep = BuildStep(modalGo.transform, "StepWait", "SALA LLENA",
                "ESPERANDO UN LUGAR", out _waitSub);
            _waitSub.fontSize = 22;
            _waitSub.alignment = TextAnchor.UpperCenter;
            CenteredAt(_waitSub.rectTransform, new Vector2(0f, -150f), new Vector2(780f, 110f));

            var orbGo = NewRectAt(_waitStep, "WaitOrb", new Vector2(0f, 40f), new Vector2(150f, 150f));
            var waitOrb = NewImage(orbGo, "Orb", orbSprite, new Color(1f, 0.75f, 0.35f, 0.7f));
            Stretch(waitOrb.rectTransform);
            _waitOrb = orbGo;

            var cancel = ModalButton(_waitStep, "Cancel", "CANCELAR ESPERA", new Color(1f, 0.45f, 0.40f), new Vector2(0f, -262f), new Vector2(420f, 86f),
                out _);
            cancel.onClick.AddListener(CancelWait);

            // ---- Paso 0: despertando / conectando ----
            _connectStep = BuildStep(modalGo.transform, "StepConnect", "CONECTANDO", "SERVIDOR PVP ONLINE", out _connectStatus);
            _connectStatus.fontSize = 22;
            _connectStatus.alignment = TextAnchor.UpperCenter;
            CenteredAt(_connectStatus.rectTransform, new Vector2(0f, -150f), new Vector2(820f, 140f));

            var connectOrbGo = NewRectAt(_connectStep, "ConnectOrb", new Vector2(0f, 40f), new Vector2(130f, 130f));
            var connectOrb = NewImage(connectOrbGo, "Orb", orbSprite, new Color(Accent.r, Accent.g, Accent.b, 0.70f));
            Stretch(connectOrb.rectTransform);
            _connectOrb = connectOrbGo;

            _connectRetry = ModalButton(_connectStep, "Retry", "REINTENTAR", new Color(0.52f, 0.92f, 0.55f),
                new Vector2(-160f, -272f), new Vector2(300f, 84f), out _);
            _connectRetry.onClick.AddListener(RetryConnection);

            _connectBack = ModalButton(_connectStep, "ConnectBack", "VOLVER AL MENU", new Color(0.72f, 0.80f, 0.95f),
                new Vector2(0f, -272f), new Vector2(300f, 84f), out _);
            _connectBack.onClick.AddListener(Back);

            // Mientras no haya REINTENTAR al lado, VOLVER AL MENU va centrado.
            SetConnectRetryVisible(false);

            _waitStep.gameObject.SetActive(false);
            _connectStep.gameObject.SetActive(true);
            _roomStep.gameObject.SetActive(false);
        }

        /// <summary>Placa base de un paso del modal (titulo + bajada + riel bereber de estado).</summary>
        private RectTransform BuildStep(Transform parent, string name, string title, string sub, out Text body)
        {
            var step = new GameObject(name, typeof(RectTransform));
            step.transform.SetParent(parent, false);
            var rt = (RectTransform)step.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = new Vector2(0f, 6f);
            rt.sizeDelta = new Vector2(1000f, 700f);

            var plate = NewImage(step.transform, "Plate", modalPlate, Color.white);
            Stretch(plate.rectTransform);
            if (modalPlate != null) { plate.type = Image.Type.Sliced; plate.pixelsPerUnitMultiplier = 2.4f; }
            var sh = plate.gameObject.AddComponent<Shadow>();
            sh.effectColor = new Color(0f, 0f, 0f, 0.55f);
            sh.effectDistance = new Vector2(0f, -8f);

            var titleText = NewText(step.transform, "Title", title, 44, Color.white);
            CenteredAt(titleText.rectTransform, new Vector2(0f, 288f), new Vector2(780f, 60f));
            var tsh = titleText.gameObject.AddComponent<Shadow>();
            tsh.effectColor = new Color(0f, 0f, 0f, 0.85f);
            tsh.effectDistance = new Vector2(2f, -2f);

            var subText = NewText(step.transform, "Sub", sub, 19, new Color(1f, 1f, 1f, 0.62f));
            CenteredAt(subText.rectTransform, new Vector2(0f, 232f), new Vector2(860f, 34f));
            subText.fontStyle = FontStyle.Normal;

            UiLine(step.transform, new Vector2(0f, 206f), new Vector2(720f, 2f), new Color(1f, 1f, 1f, 0.12f));

            body = NewText(step.transform, "Body", "", 20, LabelDim);
            CenteredAt(body.rectTransform, new Vector2(0f, -160f), new Vector2(860f, 60f));
            body.fontStyle = FontStyle.Normal;
            body.horizontalOverflow = HorizontalWrapMode.Wrap;
            return rt;
        }

        private Button ModalButton(Transform parent, string name, string label, Color accent, Vector2 pos, Vector2 size, out Button button)
        {
            var plate = modalButton;
            Image img;
            if (plate != null) img = NewImage(parent, name, plate, Color.Lerp(Color.white, accent, 0.20f));
            else
            {
                img = NewImage(parent, name, rowPlate, Color.Lerp(new Color(0.05f, 0.07f, 0.11f, 0.96f), accent, 0.28f));
                if (rowPlate != null) { img.type = Image.Type.Sliced; img.pixelsPerUnitMultiplier = 6f; }
            }

            var rt = img.rectTransform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = pos;
            rt.sizeDelta = size;
            img.raycastTarget = true;

            var outline = img.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(accent.r, accent.g, accent.b, 0.30f);
            outline.effectDistance = new Vector2(2f, -2f);

            button = img.gameObject.AddComponent<Button>();
            button.targetGraphic = img;
            var colors = button.colors;
            colors.normalColor = Color.white;
            colors.highlightedColor = new Color(1.16f, 1.20f, 1.28f);
            colors.selectedColor = new Color(1.16f, 1.20f, 1.28f);
            colors.pressedColor = new Color(0.80f, 0.84f, 0.90f);
            colors.disabledColor = new Color(0.55f, 0.58f, 0.64f, 0.85f);
            colors.fadeDuration = 0.1f;
            button.colors = colors;

            var fx = img.gameObject.AddComponent<MenuButtonFx>();
            fx.hoverScale = 1.05f;
            fx.normalColor = new Color(1f, 1f, 1f, 0.96f);
            fx.hoverColor = accent;

            var text = NewText(img.transform, "Label", label, 28, Color.white);
            Stretch(text.rectTransform);
            text.rectTransform.offsetMin = new Vector2(18f, 0f);
            text.rectTransform.offsetMax = new Vector2(-18f, 0f);
            var sh = text.gameObject.AddComponent<Shadow>();
            sh.effectColor = new Color(0f, 0f, 0f, 0.7f);
            sh.effectDistance = new Vector2(1.5f, -2f);
            fx.label = text;
            return button;
        }

        private Image UiLine(Transform parent, Vector2 pos, Vector2 size, Color color)
        {
            var line = NewImage(parent, "Line", modalPlate, color);
            if (modalPlate != null) { line.type = Image.Type.Sliced; line.pixelsPerUnitMultiplier = 12f; }
            CenteredAt(line.rectTransform, pos, size);
            return line;
        }

        // =================================================================
        // Utilidades de UI por codigo
        // =================================================================

        private static readonly ColorBlock HighlightBlock = new ColorBlock
        {
            normalColor = Color.white,
            highlightedColor = new Color(1.22f, 1.26f, 1.34f, 1f),
            pressedColor = new Color(0.82f, 0.84f, 0.90f, 1f),
            selectedColor = new Color(1.22f, 1.26f, 1.34f, 1f),
            disabledColor = new Color(0.50f, 0.50f, 0.55f, 0.70f),
            colorMultiplier = 1f,
            fadeDuration = 0.1f,
        };

        private static ColorBlock Highlighted()
        {
            var b = HighlightBlock;
            b.colorMultiplier = 1f;
            return b;
        }

        /// <summary>hijo con rect anclado al borde izquierdo del padre (para columnas).</summary>
        private static RectTransform NewRect(Transform parent, string name, float x, float y, float w, float h)
        {
            var go = new GameObject(name, typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0f, 0.5f);
            rt.pivot = new Vector2(0f, 0.5f);
            rt.anchoredPosition = new Vector2(x, y);
            rt.sizeDelta = new Vector2(w, h);
            return rt;
        }

        private static RectTransform NewRectAt(Transform parent, string name, Vector2 pos, Vector2 size)
        {
            var go = new GameObject(name, typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = pos;
            rt.sizeDelta = size;
            return rt;
        }

        private static void Rect(RectTransform rt, float x, float y, float w, float h)
        {
            rt.anchorMin = rt.anchorMax = new Vector2(0f, 0.5f);
            rt.pivot = new Vector2(0f, 0.5f);
            rt.anchoredPosition = new Vector2(x, y);
            rt.sizeDelta = new Vector2(w, h);
        }

        private static void Centered(RectTransform rt, float w, float h)
        {
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = Vector2.zero;
            rt.sizeDelta = new Vector2(w, h);
        }

        private static void CenteredAt(RectTransform rt, Vector2 pos, Vector2 size)
        {
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = pos;
            rt.sizeDelta = size;
        }

        private static void Stretch(RectTransform rt)
        {
            rt.anchorMin = Vector2.zero;
            rt.anchorMax = Vector2.one;
            rt.offsetMin = Vector2.zero;
            rt.offsetMax = Vector2.zero;
        }

        private Image NewImage(Transform parent, string name, Sprite sprite, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Image));
            go.transform.SetParent(parent, false);
            var img = go.GetComponent<Image>();
            img.sprite = sprite;
            img.color = color;
            img.raycastTarget = false;
            return img;
        }

        private Text NewText(Transform parent, string name, string value, int size, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Text));
            go.transform.SetParent(parent, false);
            var t = go.GetComponent<Text>();
            if (_font == null) _font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            t.font = _font;
            t.text = value;
            t.fontSize = size;
            t.fontStyle = FontStyle.Bold;
            t.alignment = TextAnchor.MiddleCenter;
            t.color = color;
            t.raycastTarget = false;
            t.horizontalOverflow = HorizontalWrapMode.Overflow;
            t.verticalOverflow = VerticalWrapMode.Overflow;
            return t;
        }
    }
}
