using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Candy;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Panel de pausa / menú en partida implementado con UI Toolkit (UXML/USS).
    /// Permite reanudar, reiniciar la partida, volver al menú principal o salir del juego
    /// sin tener que detener el Play Mode.
    /// Usa el menú Editor: Wilder Gambit > Setup Pause Menu para configurarlo en la escena.
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class PauseMenuController : MonoBehaviour
    {
        public static PauseMenuController Instance { get; private set; }

        [Header("UI Toolkit Assets (asignar en Inspector o usar Wilder Gambit > Setup Pause Menu)")]
        [SerializeField] public VisualTreeAsset pauseMenuViewAsset;
        [SerializeField] public PanelSettings panelSettings;

        private UIDocument _uiDocument;
        private VisualElement _root;
        private VisualElement _pauseMenuView;
        private VisualElement _pauseOverlay;

        private Button _btnResume;
        private Button _btnRestart;
        private Button _btnMainMenu;
        private Button _btnQuitGame;
        private VisualElement _pauseHud;
        private Button _btnPauseHud;
        private VisualElement _moveHistoryPanel;
        private Button _btnUndo;
        private MoveHistoryPanel _historyPanelComponent;

        // Reloj de partida (solo con control de tiempo)
        private VisualElement _clockHud;
        private VisualElement _clockWhiteRow;
        private VisualElement _clockBlackRow;
        private Label _clockWhiteTime;
        private Label _clockBlackTime;

        private VisualElement _abilityPanelRoot;
        private VariantAbilityPanel _abilityPanelComponent;

        private bool _uiInitialized = false;

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }
            Instance = this;

            _uiDocument = GetComponent<UIDocument>();
            if (_uiDocument == null)
                _uiDocument = gameObject.AddComponent<UIDocument>();

            // Reutilizar PanelSettings del Menú Principal si no está asignado
            if (_uiDocument.panelSettings == null)
            {
                if (panelSettings != null)
                    _uiDocument.panelSettings = panelSettings;
                else
                {
                    var mainMenu = FindAnyObjectByType<MainMenuController>();
                    if (mainMenu != null && mainMenu.panelSettings != null)
                        _uiDocument.panelSettings = mainMenu.panelSettings;
                }
            }

            // Asignar el UXML si no está asignado
            if (pauseMenuViewAsset != null && _uiDocument.visualTreeAsset == null)
                _uiDocument.visualTreeAsset = pauseMenuViewAsset;
        }

        private void Start()
        {
            InitializeUI();
        }

        private void Update()
        {
            if (CandyModeController.Instance != null && CandyModeController.Instance.IsOpen)
            {
                if (_pauseHud != null) _pauseHud.AddToClassList("hidden");
                return;
            }

            if (WasEscapePressed())
            {
                if (IsOpen) Close();
                else if (GameManager.Instance != null && GameManager.Instance.IsGameActive) Open();
            }

            UpdateHudVisibility();
            UpdateClock();

            // Refrescar habilidades cada frame si hay cambios (ligero)
            if (_abilityPanelComponent != null && GameManager.Instance != null && GameManager.Instance.IsGameActive && !IsOpen)
            {
                // Throttle cada 0.5s para no spamear
                if (Time.frameCount % 30 == 0)
                    _abilityPanelComponent.Refresh();
            }
        }

        /// <summary>
        /// Muestra el indicador de pausa (botón táctil) solo durante la partida
        /// y cuando el menú de pausa no está abierto.
        /// </summary>
        private void UpdateHudVisibility()
        {
            if (_pauseHud == null) return;

            if (CandyModeController.Instance != null && CandyModeController.Instance.IsOpen)
            {
                _pauseHud.AddToClassList("hidden");
                return;
            }

            bool gameActive = GameManager.Instance != null && GameManager.Instance.IsGameActive;
            bool shouldShow = gameActive && !IsOpen;

            if (shouldShow) _pauseHud.RemoveFromClassList("hidden");
            else            _pauseHud.AddToClassList("hidden");
        }

        /// <summary>
        /// Refresca el reloj de partida. Se oculta solo (sin reloj: "Sin Límite",
        /// puzzles o menús) y se ve en cuanto la partida corre contra reloj.
        /// </summary>
        private void UpdateClock()
        {
            if (_clockHud == null) return;

            var clock = GameClock.Instance;
            var gm = GameManager.Instance;

            // En pausa IsGameActive vale false, pero el reloj debe SEGUIR viéndose
            // (congelado): es justo cuando el jugador quiere leerlo.
            bool paused = gm != null && gm.IsPaused;
            bool gameActive = (gm != null && gm.IsGameActive) || paused;
            bool timed = clock != null && gameActive && clock.Control != TimeControl.None;

            if (!timed)
            {
                if (!_clockHud.ClassListContains("hidden")) _clockHud.AddToClassList("hidden");
                return;
            }

            _clockHud.RemoveFromClassList("hidden");

            bool whiteTurn = clock.ActiveTeam == TeamColor.White;
            _clockWhiteRow?.EnableInClassList("clock-row-active", whiteTurn);
            _clockBlackRow?.EnableInClassList("clock-row-active", !whiteTurn);

            SetClockLabel(_clockWhiteTime, clock.WhiteTime, paused);
            SetClockLabel(_clockBlackTime, clock.BlackTime, paused);
        }

        /// <summary>Escribe el tiempo formateado y marca el aviso de último minuto.</summary>
        private static void SetClockLabel(Label label, float seconds, bool paused)
        {
            if (label == null) return;
            label.text = GameClock.FormatTime(seconds);
            label.EnableInClassList("clock-time-paused", paused);
            // Último minuto (o menos) en rojo: es cuando el modo aprieta de verdad
            label.EnableInClassList("clock-time-low", !paused && seconds <= 60f);
        }

        private static bool WasEscapePressed()
        {
#if ENABLE_INPUT_SYSTEM
            var keyboard = UnityEngine.InputSystem.Keyboard.current;
            return keyboard != null && keyboard.escapeKey.wasPressedThisFrame;
#elif ENABLE_LEGACY_INPUT_MANAGER
            return Input.GetKeyDown(KeyCode.Escape);
#else
            return false;
#endif
        }

        public void InitializeUI()
        {
            if (_uiInitialized) return;
            if (_uiDocument == null) return;

            _root = _uiDocument.rootVisualElement;
            if (_root == null)
            {
                Debug.LogWarning("[PauseMenuController] rootVisualElement es null. Verifica que VisualTreeAsset y PanelSettings estén asignados.");
                return;
            }

            _pauseMenuView = _root.Q<VisualElement>("pause-menu-root");
            _pauseOverlay  = _root.Q<VisualElement>("pause-overlay");

            // Breakpoints móviles: clases is-wide/is-narrow/is-short + safe area del HUD
            UiResponsive.Attach(_uiDocument, _root);

            _btnResume   = _root.Q<Button>("btn-resume");
            _btnRestart  = _root.Q<Button>("btn-restart");
            _btnMainMenu = _root.Q<Button>("btn-main-menu");
            _btnQuitGame = _root.Q<Button>("btn-quit-game");

            _pauseHud   = _root.Q<VisualElement>("pause-hud");
            _btnPauseHud = _root.Q<Button>("btn-pause-hud");

            // Reloj de partida
            _clockHud       = _root.Q<VisualElement>("clock-hud");
            _clockWhiteRow  = _root.Q<VisualElement>("clock-row-white");
            _clockBlackRow  = _root.Q<VisualElement>("clock-row-black");
            _clockWhiteTime = _root.Q<Label>("clock-white-time");
            _clockBlackTime = _root.Q<Label>("clock-black-time");

            // Remaches de las tapas de cuero (reloj y panel de pausa)
            foreach (var rivets in _root.Query<VisualElement>(className: "rivets").ToList())
            {
                for (int i = 0; i < 6; i++)
                {
                    var rivet = new VisualElement();
                    rivet.AddToClassList("rivet");
                    rivet.pickingMode = PickingMode.Ignore;
                    rivets.Add(rivet);
                }
            }

            _btnResume?.RegisterCallback<ClickEvent>(_ => Close());
            _btnRestart?.RegisterCallback<ClickEvent>(_ => OnRestartClicked());
            _btnMainMenu?.RegisterCallback<ClickEvent>(_ => OnMainMenuClicked());
            _btnQuitGame?.RegisterCallback<ClickEvent>(_ => OnQuitClicked());

            // Botón de pausa del HUD (funciona con táctil / ratón)
            _btnPauseHud?.RegisterCallback<ClickEvent>(_ =>
            {
                if (!IsOpen && GameManager.Instance != null && GameManager.Instance.IsGameActive)
                    Open();
            });

            // Click en el fondo oscuro también reanuda
            _pauseOverlay?.RegisterCallback<ClickEvent>(_ => Close());

            // Move History Panel
            _moveHistoryPanel = _root.Q<VisualElement>("move-history-panel");
            _btnUndo = _root.Q<Button>("btn-undo");

            // Initialize MoveHistoryPanel component
            _historyPanelComponent = gameObject.GetComponent<MoveHistoryPanel>();
            if (_historyPanelComponent == null)
                _historyPanelComponent = gameObject.AddComponent<MoveHistoryPanel>();
            if (_moveHistoryPanel != null)
                _historyPanelComponent.Initialize(_moveHistoryPanel);

            _btnUndo?.RegisterCallback<ClickEvent>(_ => OnUndoClicked());

            // Variant Ability Panel (derecho)
            _abilityPanelRoot = _root.Q<VisualElement>("variant-ability-panel");
            _abilityPanelComponent = gameObject.GetComponent<VariantAbilityPanel>();
            if (_abilityPanelComponent == null)
                _abilityPanelComponent = gameObject.AddComponent<VariantAbilityPanel>();
            if (_abilityPanelRoot != null)
                _abilityPanelComponent.Initialize(_abilityPanelRoot);

            _root.Q<Button>("btn-ability-help")?.RegisterCallback<ClickEvent>(_ =>
            {
                // Abre la enciclopedia en Mis Piezas para más detalle
                var mainMenu = FindAnyObjectByType<MainMenuController>();
                if (mainMenu != null)
                {
                    Close();
                    // Pequeño delay para que cierre el menú de pausa antes de abrir Mis Piezas
                    mainMenu.OpenYourPiecesModal();
                }
            });

            RegisterSoundEffects();

            _uiInitialized = true;

            // Empezar oculto
            _pauseMenuView?.AddToClassList("hidden");
            Debug.Log("[PauseMenuController] UI de pausa inicializada correctamente.");
        }

        public bool IsOpen => _pauseMenuView != null && !_pauseMenuView.ClassListContains("hidden");

        // ── SFX de hover y click ──────────────────────────────────────────────
        // El menu de pausa era el unico sin sonido: MainMenuController tiene su
        // RegisterSoundEffects y este no lo tenia. Se replica la misma regla, con
        // reanudar y volver al menu en sonido de "volver" por ser salidas hacia
        // atras. Se llama al final de InitializeUI para que entre tambien en el
        // conteo el boton que arma MoveHistoryPanel / VariantAbilityPanel.
        //
        // El click va en PointerDownEvent y NO en ClickEvent, y el registro va
        // antes que las acciones de cada boton. Con ClickEvent el sonido se
        // perdia justo en los botones que hacen algo: el clic dispara la
        // accion en el mismo frame (cerrar el panel, reiniciar, volver al
        // menu) y el sonido se cortaba a los milisegundos. Solo se oia en los
        // que no navegan (deshacer, historial). Anticipandolo se escucha entero.
        private void RegisterSoundEffects()
        {
            if (_root == null) return;

            // Click en el fondo oscuro: tambien reanuda, asi que suena como "volver".
            _pauseOverlay?.RegisterCallback<PointerDownEvent>(_ =>
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound());

            foreach (var btn in _root.Query<Button>().ToList())
            {
                if (btn == null) continue;

                btn.RegisterCallback<PointerEnterEvent>(_ =>
                    WilderGambit.Audio.MusicManager.Instance?.PlayHoverSound());

                bool isBackBtn = btn == _btnResume || btn == _btnMainMenu;
                btn.RegisterCallback<PointerDownEvent>(_ =>
                {
                    if (isBackBtn)
                        WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                    else
                        WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                });
            }
        }

        public void Open()
        {
            if (_pauseMenuView == null) return;
            if (CandyModeController.Instance != null && CandyModeController.Instance.IsOpen) return;
            _pauseMenuView.RemoveFromClassList("hidden");
            GameManager.Instance?.PauseGame();
            Debug.Log("[PauseMenuController] Partida en pausa.");
        }

        public void Close()
        {
            if (_pauseMenuView == null) return;
            _pauseMenuView.AddToClassList("hidden");
            GameManager.Instance?.ResumeGame();
            Debug.Log("[PauseMenuController] Partida reanudada.");
        }

        private void OnRestartClicked()
        {
            Close();
            GameManager.Instance?.RestartGame();
        }

        private void OnMainMenuClicked()
        {
            Close();
            GameManager.Instance?.ReturnToMainMenu();
        }

        private void OnUndoClicked()
        {
            if (GameManager.Instance != null)
            {
                GameManager.Instance.UndoLastMove();
            }
        }

        /// <summary>Shows the move history panel, ability panel and undo button during gameplay.</summary>
        public void ShowGameHUD()
        {
            _moveHistoryPanel?.RemoveFromClassList("hidden");
            _btnUndo?.RemoveFromClassList("hidden");
            _abilityPanelRoot?.RemoveFromClassList("hidden");
            _abilityPanelComponent?.Refresh();
        }

        /// <summary>Hides the move history panel, ability panel and undo button.</summary>
        public void HideGameHUD()
        {
            _moveHistoryPanel?.AddToClassList("hidden");
            _btnUndo?.AddToClassList("hidden");
            _abilityPanelRoot?.AddToClassList("hidden");
        }

        private void OnQuitClicked()
        {
            Debug.Log("[PauseMenuController] Saliendo del juego...");
#if UNITY_EDITOR
            UnityEditor.EditorApplication.isPlaying = false;
#else
            Application.Quit();
#endif
        }
    }
}
