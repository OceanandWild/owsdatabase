using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.AI;
using WilderGambit.Candy;
using WilderGambit.Core;
using WilderGambit.Services;

namespace WilderGambit.UI
{
    /// <summary>
    /// Controlador principal de la UI del Menú y Selector de Dificultad implementado con UI Toolkit (UXML/USS).
    /// Requiere: UIDocument con PanelSettings y VisualTreeAsset asignados.
    /// Usa el menú Editor: Wilder Gambit > Setup Main Menu para configurar automáticamente.
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class MainMenuController : MonoBehaviour
    {
        public static MainMenuController Instance { get; private set; }

        [Header("UI Toolkit Assets (asignar en Inspector o usar Wilder Gambit > Setup Main Menu)")]
        [SerializeField] public VisualTreeAsset mainMenuViewAsset;
        [SerializeField] public PanelSettings panelSettings;

        private UIDocument _uiDocument;
        private VisualElement _root;

        private VisualElement _mainMenuView;
        private VisualElement _difficultyView;
        private VisualElement _settingsModalView;
        private VisualElement _shopModalView;
        private VisualElement _yourPiecesModalView;
        private VisualElement _progressModalView;
        private VisualElement _inventoryModalView;

        private Button _btnPlay;
        private Button _btnYourPieces;
        private Button _btnInventory;
        private Label  _btnInventoryCount;
        private VisualElement _inventoryRail;
        private Button _btnSettings;
        private Button _btnShop;
        private Button _btnProgress;
        private Button _btnQuit;
        private Button _btnCandyMode;
        private Button _btnBackToMain;
        private Button _btnToggleCinematics;
        private Button _btnToggleMusic;
        private Button _btnToggleFullscreen;
        private Button _btnCloseSettings;
        private Button _btnCloseShop;

        // ── Progreso y economía de Gambits ──
        private ProgressModal _progressModal;
        private GambitToast   _gambitToast;
        private Label         _menuGambitsValue;
        private Label         _btnProgressBadge;
        private bool          _progressEventsHooked;

        private Button _btnMenuMusicPrev;
        private Button _btnMenuMusicNext;
        private Button _btnMenuMusicOpen;
        private Button _btnBattleMusicPrev;
        private Button _btnBattleMusicNext;
        private Button _btnBattleMusicOpen;

        // Popup de Búsqueda de Música
        private VisualElement _musicSearchPopup;
        private Label         _lblMusicSearchTitle;
        private Label         _lblMusicSearchSubtitle;
        private TextField     _inputMusicSearch;
        private ScrollView    _scrollMusicTracks;
        private Button        _btnCloseMusicSearch;
        private bool          _isSearchingMenuMusic = true;

        private bool _isCinematicsEnabled = true;
        private bool _uiInitialized = false;

        private ShopModal _shopModal;
        private YourPiecesModal _yourPiecesModal;
        private InventoryModal _inventoryModal;
        private SeasonPassModal _seasonPassModal;
        private VisualElement _seasonPassModalView;

        /// <summary>
        /// Pase de Halloween: mini-pase de la velada (20/10 → 4/11) con XP,
        /// misiones, Dulces y dos vías de cobro, cada uno con claves propias.
        /// El modal tiene su propio script; aquí se guardan ambos para
        /// abrir/cerrar y refrescar el cintillo de la tarjeta del menú.
        /// </summary>
        private VisualElement _halloweenPassModalView;
        private HalloweenPassModal _halloweenPassModal;

        /// <summary>
        /// Tablero de misiones de la velada: modal que se abre por encima del
        /// pase (botón MISIONES y fichas de resumen). Vive como hermano del
        /// pase para poder mostrarse sin cerrarlo.
        /// </summary>
        private VisualElement _halloweenMissionsModalView;
        private HalloweenMissionsModal _halloweenMissionsModal;
        private VisualElement _halloweenShopModalView;
        private HalloweenShopModal _halloweenShopModal;

        // Phase 8.2 — Dynamic Difficulty Suggestion
        private VisualElement _suggestionBanner;
        private Label _suggestionTitle;
        private Label _suggestionSubtitle;
        private Label _suggestionStreak;
        private Label _suggestionIcon;
        private Button _btnSuggestionAccept;
        private Button _btnSuggestionDismiss;
        private DifficultyLevel _pendingSuggestedLevel;

        // Premium vault — single CTA selection
        private DifficultyLevel? _selectedDifficulty;
        private Button _btnStartGame;

        // Animaciones del menú: entrada escalonada, transiciones de vista y ambiente
        private readonly List<VisualElement> _mainStaggerItems = new List<VisualElement>();
        private readonly List<VisualElement> _diffStaggerItems = new List<VisualElement>();
        private int _staggerGeneration;
        private Coroutine _viewTransition;
        private Coroutine _headerIdle;
        private Coroutine _shineLoop;
        private Coroutine _ctaShake;
        private float _headerIdleTime;
        private VisualElement _titleCrown;
        private VisualElement _separatorDiamond;
        private VisualElement _titleGlow;
        private Vector2 _parallaxMouseTarget;
        private Vector2 _parallaxMouseCurrent;
        private readonly Dictionary<VisualElement, IVisualElementScheduledItem> _modalHideSchedules =
            new Dictionary<VisualElement, IVisualElementScheduledItem>();

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

            // Asignar PanelSettings si no está asignado
            if (panelSettings != null && _uiDocument.panelSettings == null)
                _uiDocument.panelSettings = panelSettings;

            // Asignar el UXML si no está asignado
            if (mainMenuViewAsset != null && _uiDocument.visualTreeAsset == null)
                _uiDocument.visualTreeAsset = mainMenuViewAsset;

            EnsureEventSystem();

            _isCinematicsEnabled = PlayerPrefs.GetInt("EnableCinematics", 1) == 1;
        }

        private void EnsureEventSystem()
        {
            var es = FindAnyObjectByType<UnityEngine.EventSystems.EventSystem>();
            if (es == null)
            {
                var esObj = new GameObject("EventSystem");
                es = esObj.AddComponent<UnityEngine.EventSystems.EventSystem>();
                DontDestroyOnLoad(esObj);
            }

            var standalone = es.GetComponent<UnityEngine.EventSystems.StandaloneInputModule>();
            if (standalone != null)
            {
                Destroy(standalone);
            }

            var inputModule = es.GetComponent<UnityEngine.InputSystem.UI.InputSystemUIInputModule>();
            if (inputModule == null)
            {
                inputModule = es.gameObject.AddComponent<UnityEngine.InputSystem.UI.InputSystemUIInputModule>();
            }
            inputModule.AssignDefaultActions();
        }

        private void Start()
        {
            // En Start() la UIDocument ya habrá construido el visual tree
            if (GameManager.Instance != null)
                GameManager.Instance.EnableCinematics = _isCinematicsEnabled;

            InitializeUI();
            ApplyMainMenuBackground();
            BackdropManager.Changed += ApplyMainMenuBackground;

            // Economía: misiones, barra semanal y logros escuchando los eventos de juego
            // (idempotente: si GameManager ya lo hizo, no vuelve a suscribirse)
            GambitProgress.Init();
            RefreshProgressionUI();
        }

        private void OnDestroy()
        {
            DisplaySettings.Changed -= UpdateFullscreenUI;
            BackdropManager.Changed -= ApplyMainMenuBackground;

            if (!_progressEventsHooked) return;
            GambitProgress.OnChanged -= RefreshProgressionUI;
            _progressEventsHooked = false;

            if (GameManager.Instance != null)
                GameManager.Instance.OnTrainingSessionFinished -= OnTrainingSessionFinished;
        }

        /// <summary>
        /// Loads the main menu background texture and applies it to the
        /// root-container element, replacing its solid background color.
        /// </summary>
        private void ApplyMainMenuBackground()
        {
            if (_root == null) return;

            // Fondos del Atelier: si el jugador equipó un fondo, ese manda;
            // si no, se conserva el fondo clásico del menú.
            Texture2D bgTex = null;
            if (BackdropManager.HasCustomSelection)
                bgTex = BackdropManager.LoadSelectedTexture();
            if (bgTex == null)
                bgTex = BoardBackgroundManager.LoadMainMenuTexture();
            if (bgTex == null)
            {
                Debug.LogWarning("[MainMenuController] No se pudo cargar el fondo del menú principal.");
                return;
            }

            // Find the root-container that holds all menu UI
            var container = _root.Q<VisualElement>("root-container");
            if (container == null)
            {
                Debug.LogWarning("[MainMenuController] root-container no encontrado.");
                return;
            }

            // Apply the texture as background image on the container itself
            var bgSprite = Sprite.Create(
                bgTex,
                new Rect(0, 0, bgTex.width, bgTex.height),
                new Vector2(0.5f, 0.5f),
                100f
            );
            container.style.backgroundImage = new StyleBackground(bgSprite);
            container.style.backgroundSize = new BackgroundSize(BackgroundSizeType.Cover);
            container.style.backgroundPositionX = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Left, new Length(50f, LengthUnit.Percent)));
            container.style.backgroundPositionY = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Top, new Length(50f, LengthUnit.Percent)));

            Debug.Log($"[MainMenuController] Fondo aplicado: {bgTex.width}x{bgTex.height}");

            // Start parallax drift coroutine
            StartCoroutine(ParallaxDrift(container));
            SpawnMainMenuParticles(_root);
            // El overlay de frames FireEmbers (ImageMagick) quedó reemplazado por
            // el sistema de brasas reworkeado de SpawnMainMenuParticles.
            // SpawnFireEmbersOverlay(_root);
        }

        /// <summary>
        /// Subtle parallax drift that slowly pans the background.
        /// </summary>
        private IEnumerator ParallaxDrift(VisualElement container)
        {
            float elapsed = 0f;
            float driftDuration = 30f; // full cycle
            float driftRange = 5f; // percent offset

            while (container != null && container.panel != null)
            {
                elapsed += Time.unscaledDeltaTime;
                float t = (Mathf.Sin(elapsed * Mathf.PI * 2f / driftDuration) + 1f) * 0.5f;
                // Parallax del ratón (suavizado) sumado al drift lento
                _parallaxMouseCurrent = Vector2.Lerp(_parallaxMouseCurrent, _parallaxMouseTarget,
                    1f - Mathf.Exp(-4f * Time.unscaledDeltaTime));
                float xPos = 50f + (t - 0.5f) * driftRange + _parallaxMouseCurrent.x * 3f;
                float yPos = 50f + Mathf.Sin(elapsed * 0.3f) * 2f + _parallaxMouseCurrent.y * 2.4f;

                container.style.backgroundPositionX = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Left, new Length(xPos, LengthUnit.Percent)));
                container.style.backgroundPositionY = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Top, new Length(yPos, LengthUnit.Percent)));

                yield return null;
            }
        }

        // -- Floating Particles (Polish) -----------------------------------
        // Rework de brasas: partículas de fuego que ASCIENDEN desde el borde
        // inferior, con núcleo caliente que se enfría al subir (blanco-ámbar ->
        // naranja -> rojo profundo), parpadeo individual y chispas volátiles
        // rápidas, más el polvo dorado en suspensión de siempre.
        private VisualElement _particlesLayer;
        private enum ParticleKind : byte { Dust = 0, Ember = 1, Spark = 2 }
        private struct ParticleData
        {
            public VisualElement element;
            public float x, y, speed, drift, phase;
            public float baseOpacity, flickerSpeed;
            public float life, lifeSpeed; // solo brasas/chispas: 1 = nacida abajo, 0 = muerta arriba
            public ParticleKind kind;
        }
        private System.Collections.Generic.List<ParticleData> _particles = new System.Collections.Generic.List<ParticleData>();

        // Paleta de brasa: el enfriamiento por altitud (life) se interpola en AnimateParticles
        private static readonly Color EmberHot  = new Color(1.00f, 0.86f, 0.55f); // núcleo casi blanco
        private static readonly Color EmberWarm = new Color(1.00f, 0.52f, 0.15f); // naranja incandescente
        private static readonly Color EmberCool = new Color(0.70f, 0.18f, 0.07f); // rojo profundo / ceniza
        private static readonly Color SparkCore = new Color(1.00f, 0.95f, 0.75f); // chispa blanca

        private void SpawnMainMenuParticles(VisualElement root)
        {
            if (root == null) return;
            _particlesLayer = root.Q<VisualElement>("main-menu-particles");
            if (_particlesLayer == null)
            {
                _particlesLayer = new VisualElement();
                _particlesLayer.name = "main-menu-particles";
                _particlesLayer.AddToClassList("main-menu-particles");
                _particlesLayer.pickingMode = PickingMode.Ignore;
                root.Insert(0, _particlesLayer);
            }
            _particlesLayer.Clear();
            _particles.Clear();

            // 1) Polvo dorado en suspensión: tres planos de profundidad (bokeh)
            SpawnDustLayer(10, "particle-far",  1.4f, 2.6f, 0.10f, 0.18f, 0.35f, 0.60f, 0.6f, 1.1f, 1.4f, 2.6f);
            SpawnDustLayer(8,  "particle-mid",  2.4f, 4.4f, 0.16f, 0.26f, 0.55f, 0.95f, 0.9f, 1.6f, 1.8f, 3.2f);
            SpawnDustLayer(6,  "particle-near", 5.0f, 9.0f, 0.10f, 0.16f, 0.90f, 1.50f, 1.4f, 2.2f, 2.2f, 3.8f);

            // 2) Brasas de fuego: nacen en la mitad inferior, ascienden y se enfrían al subir
            SpawnEmberLayer(14, "particle-ember-far",  2.0f, 3.4f, 0.30f, 0.50f, 2.0f, 3.2f, 0.7f, 1.3f);
            SpawnEmberLayer(10, "particle-ember-mid",  3.4f, 5.6f, 0.42f, 0.62f, 3.0f, 4.6f, 1.0f, 1.8f);
            SpawnEmberLayer(6,  "particle-ember-near", 6.5f, 11.0f, 0.30f, 0.45f, 4.0f, 6.0f, 1.3f, 2.2f);

            // 3) Chispas volátiles: rápidas, brillantes y de vida corta
            SpawnSparkLayer(7, "particle-spark", 1.4f, 2.6f, 0.55f, 0.85f, 20f, 34f, 2.5f, 5.0f);
            StopCoroutine(nameof(AnimateParticles));
            StartCoroutine(AnimateParticles());
        }

        private ParticleData CreateParticle(string layerClass, float size, float x, float y,
            float baseOpacity, ParticleKind kind)
        {
            var p = new VisualElement();
            p.AddToClassList("particle");
            p.AddToClassList(layerClass);
            p.pickingMode = PickingMode.Ignore;
            p.style.position = Position.Absolute;
            p.style.left = new Length(x, LengthUnit.Percent);
            p.style.top = new Length(y, LengthUnit.Percent);
            p.style.width = size;
            p.style.height = size;
            p.style.opacity = baseOpacity;
            return new ParticleData
            {
                element = p, x = x, y = y, kind = kind, baseOpacity = baseOpacity,
                phase = UnityEngine.Random.Range(0f, Mathf.PI * 2f),
                speed = 0f, drift = 0f, flickerSpeed = 1f, life = 1f, lifeSpeed = 0f
            };
        }

        private void SpawnDustLayer(int count, string layerClass, float minSize, float maxSize,
            float minOpacity, float maxOpacity, float minSpeed, float maxSpeed,
            float minDrift, float maxDrift, float minFlicker, float maxFlicker)
        {
            for (int i = 0; i < count; i++)
            {
                var p = CreateParticle(layerClass,
                    UnityEngine.Random.Range(minSize, maxSize),
                    UnityEngine.Random.Range(2f, 98f),
                    UnityEngine.Random.Range(5f, 95f),
                    UnityEngine.Random.Range(minOpacity, maxOpacity), ParticleKind.Dust);
                p.speed = UnityEngine.Random.Range(minSpeed, maxSpeed);
                p.drift = UnityEngine.Random.Range(minDrift, maxDrift);
                p.flickerSpeed = UnityEngine.Random.Range(minFlicker, maxFlicker);
                _particlesLayer.Add(p.element);
                _particles.Add(p);
            }
        }

        private void SpawnEmberLayer(int count, string layerClass, float minSize, float maxSize,
            float minOpacity, float maxOpacity, float minSpeed, float maxSpeed, float minDrift, float maxDrift)
        {
            for (int i = 0; i < count; i++)
            {
                // Sesgo vertical: la mayoría de brasas nacen en la mitad inferior
                float y = UnityEngine.Random.Range(35f, 106f);
                var p = CreateParticle(layerClass,
                    UnityEngine.Random.Range(minSize, maxSize),
                    UnityEngine.Random.Range(0f, 100f), y,
                    UnityEngine.Random.Range(minOpacity, maxOpacity), ParticleKind.Ember);
                p.speed = UnityEngine.Random.Range(minSpeed, maxSpeed);
                p.drift = UnityEngine.Random.Range(minDrift, maxDrift);
                p.flickerSpeed = UnityEngine.Random.Range(5f, 11f);
                p.lifeSpeed = p.speed / 110f; // sincronizado con el recorrido vertical (110%)
                p.life = Mathf.Clamp01((p.y + 6f) / 112f);
                _particlesLayer.Add(p.element);
                _particles.Add(p);
            }
        }

        private void SpawnSparkLayer(int count, string layerClass, float minSize, float maxSize,
            float minOpacity, float maxOpacity, float minSpeed, float maxSpeed, float minDrift, float maxDrift)
        {
            for (int i = 0; i < count; i++)
            {
                float y = UnityEngine.Random.Range(40f, 106f);
                var p = CreateParticle(layerClass,
                    UnityEngine.Random.Range(minSize, maxSize),
                    UnityEngine.Random.Range(0f, 100f), y,
                    UnityEngine.Random.Range(minOpacity, maxOpacity), ParticleKind.Spark);
                p.speed = UnityEngine.Random.Range(minSpeed, maxSpeed);
                p.drift = UnityEngine.Random.Range(minDrift, maxDrift);
                p.flickerSpeed = UnityEngine.Random.Range(14f, 24f);
                p.lifeSpeed = p.speed / 110f;
                p.life = Mathf.Clamp01((p.y + 6f) / 112f);
                _particlesLayer.Add(p.element);
                _particles.Add(p);
            }
        }

        private System.Collections.IEnumerator AnimateParticles()
        {
            float elapsed = 0f;
            while (_particlesLayer != null && _particlesLayer.panel != null)
            {
                float dt = Time.unscaledDeltaTime;
                elapsed += dt;
                for (int i = 0; i < _particles.Count; i++)
                {
                    var d = _particles[i];
                    var el = d.element;
                    if (el == null || el.panel == null) continue;

                    if (d.kind == ParticleKind.Dust)
                    {
                        // Polvo: deriva lenta hacia arriba + balanceo + brillo suave
                        d.y -= d.speed * dt;
                        if (d.y < -4f) d.y = 104f;
                        float sway = Mathf.Sin(elapsed * d.drift + d.phase) * (0.8f + d.drift * 0.6f);
                        el.style.top = new Length(d.y, LengthUnit.Percent);
                        el.style.left = new Length(WrapX(d.x + sway), LengthUnit.Percent);
                        el.style.opacity = d.baseOpacity * (0.78f + 0.22f * Mathf.Sin(elapsed * d.flickerSpeed + d.phase));
                    }
                    else
                    {
                        // Brasas y chispas: ascenso continuo; al morir reaparecen bajo el borde
                        d.y -= d.speed * dt;
                        d.life -= d.lifeSpeed * dt;
                        if (d.life <= 0f || d.y < -6f)
                        {
                            d.y = UnityEngine.Random.Range(100f, 108f);
                            d.x = UnityEngine.Random.Range(0f, 100f);
                            d.life = 1f;
                        }
                        float sway = Mathf.Sin(elapsed * d.drift + d.phase) * (d.kind == ParticleKind.Spark ? 0.6f : 1.4f);
                        el.style.top = new Length(d.y, LengthUnit.Percent);
                        el.style.left = new Length(WrapX(d.x + sway), LengthUnit.Percent);

                        float p = 1f - Mathf.Clamp01(d.life); // 0 = recién nacida (abajo) -> 1 = arriba
                        float fadeIn = Mathf.Clamp01(p / 0.10f);
                        float fadeOut = Mathf.Clamp01((1f - p) / 0.30f);
                        float flicker = 0.72f + 0.28f * Mathf.Sin(elapsed * d.flickerSpeed + d.phase);
                        el.style.opacity = d.baseOpacity * fadeIn * fadeOut * flicker;

                        if (d.kind == ParticleKind.Ember)
                        {
                            Color c = p < 0.5f
                                ? Color.Lerp(EmberHot, EmberWarm, p * 2f)
                                : Color.Lerp(EmberWarm, EmberCool, (p - 0.5f) * 2f);
                            el.style.backgroundColor = new StyleColor(c);
                        }
                        else
                        {
                            el.style.backgroundColor = new StyleColor(Color.Lerp(SparkCore, EmberWarm, p));
                        }
                    }
                    _particles[i] = d;
                }
                yield return null;
            }
        }

        private static float WrapX(float x)
        {
            if (x < 0f) x += 100f;
            else if (x > 100f) x -= 100f;
            return x;
        }

        // -- Fire Embers ImageMagick Overlay ---------------------------------
        private VisualElement _fireOverlay;
        private Sprite[] _fireSprites;
        private int _fireFrameCount = 48;

        private void SpawnFireEmbersOverlay(VisualElement root)
        {
            if (root == null) return;
            _fireOverlay = root.Q<VisualElement>("fire-embers-overlay");
            if (_fireOverlay == null)
            {
                _fireOverlay = new VisualElement();
                _fireOverlay.name = "fire-embers-overlay";
                _fireOverlay.AddToClassList("fire-embers-overlay");
                _fireOverlay.pickingMode = PickingMode.Ignore;
                if (_particlesLayer != null && _particlesLayer.parent == root)
                {
                    int idx = root.IndexOf(_particlesLayer);
                    root.Insert(idx + 1, _fireOverlay);
                }
                else
                {
                    root.Insert(0, _fireOverlay);
                }
            }
            _fireOverlay.style.position = Position.Absolute;
            _fireOverlay.style.left = 0; _fireOverlay.style.right = 0; _fireOverlay.style.bottom = 0;
            _fireOverlay.style.top = new StyleLength(StyleKeyword.Null);
            _fireOverlay.style.height = new Length(42, LengthUnit.Percent);
            _fireOverlay.style.width = new Length(100, LengthUnit.Percent);
            _fireOverlay.style.opacity = 0.52f;
            if (_fireSprites == null || _fireSprites.Length == 0)
                StartCoroutine(LoadFireEmbersFrames());
            else
                StartCoroutine(AnimateFireEmbers());
        }

        private System.Collections.IEnumerator LoadFireEmbersFrames()
        {
            var list = new System.Collections.Generic.List<Sprite>();
            for (int i = 0; i < _fireFrameCount; i++)
            {
                string path = $"FireEmbers/frame_{i:0000}";
                Sprite s = Resources.Load<Sprite>(path);
                if (s == null)
                {
                    Texture2D tex = Resources.Load<Texture2D>(path);
                    if (tex != null)
                    {
                        tex.filterMode = FilterMode.Bilinear;
                        tex.wrapMode = TextureWrapMode.Clamp;
                        tex.mipMapBias = 0f;
                        s = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                        s.name = $"frame_{i:0000}";
                        s.texture.filterMode = FilterMode.Bilinear;
                        s.texture.wrapMode = TextureWrapMode.Clamp;
                    }
                }
                else
                {
                    if (s.texture != null)
                    {
                        s.texture.filterMode = FilterMode.Bilinear;
                        s.texture.wrapMode = TextureWrapMode.Clamp;
                    }
                }
                if (s != null) list.Add(s);
                if (i % 8 == 7) yield return null;
            }
            _fireSprites = list.ToArray();
            UnityEngine.Debug.Log($"[FireEmbers] Cargados {_fireSprites.Length}/{_fireFrameCount} frames con transparencia ImageMagick");
            if (_fireSprites.Length > 0) StartCoroutine(AnimateFireEmbers());
            else UnityEngine.Debug.LogWarning("[FireEmbers] No se encontraron frames en Resources/FireEmbers");
        }

        private System.Collections.IEnumerator AnimateFireEmbers()
        {
            if (_fireOverlay == null || _fireSprites == null || _fireSprites.Length == 0) yield break;
            float fps = 8f; // more subtle, slower
            float frameTime = 1f / fps;
            int idx = 0;
            while (_fireOverlay != null && _fireOverlay.panel != null)
            {
                Sprite s = _fireSprites[idx % _fireSprites.Length];
                if (s != null)
                {
                    _fireOverlay.style.backgroundImage = new StyleBackground(s);
                    _fireOverlay.style.backgroundPositionX = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Center, new Length(0)));
                    _fireOverlay.style.backgroundPositionY = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Bottom, new Length(0)));
                }
                idx = (idx + 1) % _fireSprites.Length;
                yield return new WaitForSeconds(frameTime);
            }
        }




        public void InitializeUI()
        {
            if (_uiInitialized) return;
            if (_uiDocument == null) return;

            _root = _uiDocument.rootVisualElement;
            if (_root == null)
            {
                Debug.LogWarning("[MainMenuController] rootVisualElement es null. Verifica que VisualTreeAsset y PanelSettings estén asignados en el Inspector.");
                return;
            }

            // Breakpoints móviles: clases is-wide/is-narrow/is-short + safe area
            UiResponsive.Attach(_uiDocument, _root.Q<VisualElement>("root-container"));
            // Vistas principales
            _mainMenuView      = _root.Q<VisualElement>("main-menu-view");
            _difficultyView    = _root.Q<VisualElement>("difficulty-view");
            _settingsModalView = _root.Q<VisualElement>("settings-modal-view");
            _shopModalView     = _root.Q<VisualElement>("shop-modal-view");
            _yourPiecesModalView = _root.Q<VisualElement>("your-pieces-modal-view");
            _progressModalView   = _root.Q<VisualElement>("progress-modal-view");
            _inventoryModalView  = _root.Q<VisualElement>("inventory-modal-view");

            // Botones del Menú Principal
            _btnPlay       = _root.Q<Button>("btn-play");
            _btnYourPieces = _root.Q<Button>("btn-your-pieces");
            _btnInventory  = _root.Q<Button>("btn-inventory");
            _btnInventoryCount = _root.Q<Label>("btn-inventory-count");
            _inventoryRail = _root.Q<VisualElement>("menu-inventory-rail");
            _btnSettings   = _root.Q<Button>("btn-settings");
            _btnShop       = _root.Q<Button>("btn-shop");
            _btnProgress   = _root.Q<Button>("btn-progress");
            _btnQuit       = _root.Q<Button>("btn-quit");
            _btnCandyMode  = _root.Q<Button>("btn-candy-mode");

            // Chip de saldo + aviso de misiones pendientes en el menú
            _menuGambitsValue  = _root.Q<Label>("menu-gambits-value");
            _btnProgressBadge  = _root.Q<Label>("btn-progress-badge");

            // Botón volver al menú
            _btnBackToMain = _root.Q<Button>("btn-back-to-main");

            // Botones de ajustes
            _btnToggleCinematics = _root.Q<Button>("btn-toggle-cinematics");
            _btnToggleMusic      = _root.Q<Button>("btn-toggle-music");
            _btnToggleFullscreen = _root.Q<Button>("btn-toggle-fullscreen");
            _btnCloseSettings    = _root.Q<Button>("btn-close-settings");

            // Selectores de Música
            _btnMenuMusicPrev   = _root.Q<Button>("btn-menu-music-prev");
            _btnMenuMusicNext   = _root.Q<Button>("btn-menu-music-next");
            _btnMenuMusicOpen   = _root.Q<Button>("btn-menu-music-open");

            _btnBattleMusicPrev  = _root.Q<Button>("btn-battle-music-prev");
            _btnBattleMusicNext  = _root.Q<Button>("btn-battle-music-next");
            _btnBattleMusicOpen  = _root.Q<Button>("btn-battle-music-open");

            // Popup de Búsqueda
            _musicSearchPopup       = _root.Q<VisualElement>("music-search-popup");
            _lblMusicSearchTitle    = _root.Q<Label>("lbl-music-search-title");
            _lblMusicSearchSubtitle = _root.Q<Label>("lbl-music-search-subtitle");
            _inputMusicSearch       = _root.Q<TextField>("input-music-search");
            _scrollMusicTracks      = _root.Q<ScrollView>("scroll-music-tracks");
            _btnCloseMusicSearch    = _root.Q<Button>("btn-close-music-search");

            // Botones de tienda
            _btnCloseShop = _root.Q<Button>("btn-close-shop");

            // Registrar eventos
            _btnPlay?.RegisterCallback<ClickEvent>(_ => ShowDifficultyView());
            _btnYourPieces?.RegisterCallback<ClickEvent>(_ => OpenYourPiecesModal());
            _btnInventory?.RegisterCallback<ClickEvent>(_ => OpenInventoryModal());
            _btnSettings?.RegisterCallback<ClickEvent>(_ => OpenSettingsModal());
            _btnShop?.RegisterCallback<ClickEvent>(_ => OpenShopModal());
            _btnProgress?.RegisterCallback<ClickEvent>(_ => OpenProgressModal());
            _btnCandyMode?.RegisterCallback<ClickEvent>(_ => OpenCandyMode());
            _btnQuit?.RegisterCallback<ClickEvent>(_ => OnQuitClicked());
            _root.Q<VisualElement>("seasonpass-entry")?.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                OpenSeasonPassModal();
            });
            _root.Q<VisualElement>("halloweenpass-entry")?.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                OpenHalloweenPassModal();
            });
            _btnBackToMain?.RegisterCallback<ClickEvent>(_ => ShowMainMenu());
            _btnToggleCinematics?.RegisterCallback<ClickEvent>(_ => ToggleCinematics());
            _btnToggleMusic?.RegisterCallback<ClickEvent>(_ => ToggleMusicEnabled());
            _btnToggleFullscreen?.RegisterCallback<ClickEvent>(_ => ToggleFullscreen());
            _btnCloseSettings?.RegisterCallback<ClickEvent>(_ => CloseSettingsModal());
            _btnCloseShop?.RegisterCallback<ClickEvent>(_ => CloseShopModal());

            _btnMenuMusicPrev?.RegisterCallback<ClickEvent>(_ => CycleMenuMusic(-1));
            _btnMenuMusicNext?.RegisterCallback<ClickEvent>(_ => CycleMenuMusic(1));
            _btnMenuMusicOpen?.RegisterCallback<ClickEvent>(_ => OpenMusicSearchPopup(true));

            _btnBattleMusicPrev?.RegisterCallback<ClickEvent>(_ => CycleBattleMusic(-1));
            _btnBattleMusicNext?.RegisterCallback<ClickEvent>(_ => CycleBattleMusic(1));
            _btnBattleMusicOpen?.RegisterCallback<ClickEvent>(_ => OpenMusicSearchPopup(false));

            _btnCloseMusicSearch?.RegisterCallback<ClickEvent>(_ => CloseMusicSearchPopup());
            _inputMusicSearch?.RegisterValueChangedCallback(evt => FilterMusicTracks(evt.newValue));

            // Enlazar sonidos SFX a todos los botones del menú
            RegisterSoundEffects();

            // Enlazar tarjetas de dificultad
            BindDifficultyCard("card-novice",      "btn-diff-1", DifficultyLevel.Novice);
            BindDifficultyCard("card-apprentice",  "btn-diff-2", DifficultyLevel.Apprentice);
            BindDifficultyCard("card-knight",      "btn-diff-3", DifficultyLevel.Knight);
            BindDifficultyCard("card-master",      "btn-diff-4", DifficultyLevel.Master);
            BindDifficultyCard("card-grandmaster", "btn-diff-5", DifficultyLevel.GrandMaster);

            // Phase 8.2 — Suggestion banner
            _suggestionBanner      = _root.Q<VisualElement>("difficulty-suggestion");
            _suggestionTitle       = _root.Q<Label>("suggestion-title");
            _suggestionSubtitle    = _root.Q<Label>("suggestion-subtitle");
            _suggestionStreak      = _root.Q<Label>("suggestion-streak");
            _suggestionIcon        = _root.Q<Label>("suggestion-icon");
            _btnSuggestionAccept   = _root.Q<Button>("btn-suggestion-accept");
            _btnSuggestionDismiss  = _root.Q<Button>("btn-suggestion-dismiss");
            _btnSuggestionAccept?.RegisterCallback<ClickEvent>(_ => AcceptDifficultySuggestion());
            _btnSuggestionDismiss?.RegisterCallback<ClickEvent>(_ => DismissDifficultySuggestion());

            // CTA único
            _btnStartGame = _root.Q<Button>("btn-start-game");
            _btnStartGame?.RegisterCallback<ClickEvent>(_ => OnStartGameClicked());
            _ctaHint = _root.Q<Label>("cta-hint");

            // Time control selector
            BindTimeControlButtons();

            // Inicializar ShopModal
            _shopModal = gameObject.GetComponent<ShopModal>() ?? gameObject.AddComponent<ShopModal>();
            _shopModal.Initialize(_root.Q<VisualElement>("shop-modal-view"));

            // Inicializar YourPiecesModal (catálogo: se consulta y se compra)
            _yourPiecesModal = gameObject.GetComponent<YourPiecesModal>() ?? gameObject.AddComponent<YourPiecesModal>();
            _yourPiecesModal.Initialize(_yourPiecesModalView, () => CloseYourPiecesModal());

            // Inicializar el INVENTARIO: el único sitio donde se equipa
            _inventoryModal = gameObject.GetComponent<InventoryModal>() ?? gameObject.AddComponent<InventoryModal>();
            _inventoryModal.Initialize(
                _inventoryModalView,
                onClose: () => CloseInventoryModal(),
                onToast: (message, subtitle) => _gambitToast?.Show(message, subtitle),
                onBoardEquipped: ApplyMainMenuBackground);
            ApplyInventoryButtonArt();
            SetupInventoryRail();

            if (_inventoryModalView == null)
                Debug.LogError("[MainMenuController] No existe «inventory-modal-view» en el UXML: el INVENTARIO no podrá abrirse.");

            // Inicializar la vista de Progreso (misiones, barra semanal, logros y fuentes)
            _progressModal = gameObject.GetComponent<ProgressModal>() ?? gameObject.AddComponent<ProgressModal>();
            _progressModal.Initialize(
                _progressModalView,
                onClose: () => CloseProgressModal(),
                onTraining: () => StartTrainingSession(),
                onDailyChallenge: () => StartDailyChallenge(),
                onToast: (message) => _gambitToast?.Show(message));

            // Toast de Gambits (escucha todas las recompensas de la economía)
            _gambitToast = gameObject.GetComponent<GambitToast>() ?? gameObject.AddComponent<GambitToast>();
            _gambitToast.Initialize(_root);

            // Pase de temporada a pantalla completa (hero banner + barra + medallones)
            _seasonPassModalView = _root.Q<VisualElement>("seasonpass-modal-view");
            _seasonPassModal = gameObject.GetComponent<SeasonPassModal>() ?? gameObject.AddComponent<SeasonPassModal>();
            _seasonPassModal.Initialize(
                _seasonPassModalView,
                onClose: () => CloseSeasonPassModal(),
                onToast: (message, subtitle) => _gambitToast?.Show(message, subtitle));
            if (_seasonPassModalView == null)
                Debug.LogError("[MainMenuController] No existe «seasonpass-modal-view» en el UXML: el pase no podrá abrirse.");

            // Pase de Halloween: mini-pase de la velada (XP, misiones y Dulces propios).
            _halloweenPassModalView = _root.Q<VisualElement>("halloweenpass-modal-view");
            // Respaldo por código: si el USS por URL no resolvió, se aplica el sprite.
            SeasonPassSprites.Apply(_halloweenPassModalView?.Q("halloween-banner-art"), SeasonPassSprites.HalloweenBanner);
            SeasonPassSprites.Apply(_halloweenPassModalView?.Q("halloween-title-art"), SeasonPassSprites.HalloweenLabel);
            // Los tres paneles del topbar llevan placa con 9-slice (arte 2× → escala 0.5).
            HalloweenSprites.Apply(_halloweenPassModalView?.Q("hw-chip-nivel"), HalloweenSprites.ChipNivel);
            HalloweenSprites.Apply(_halloweenPassModalView?.Q("hw-chip-xp"), HalloweenSprites.ChipXp);
            HalloweenSprites.Apply(_halloweenPassModalView?.Q("hw-chip-dulces"), HalloweenSprites.ChipDulces);
            if (_halloweenPassModalView != null)
            {
                _halloweenPassModal = gameObject.GetComponent<HalloweenPassModal>()
                    ?? gameObject.AddComponent<HalloweenPassModal>();
                // Cerrar vive dentro del modal (se registra en Initialize).
                _halloweenPassModal.Initialize(
                    _halloweenPassModalView,
                    onClose: () => CloseHalloweenPassModal(),
                    onToast: (message, subtitle) => _gambitToast?.Show(message, subtitle),
                    onMissions: sangre => OpenHalloweenMissionsModal(sangre),
                    onShop: () => OpenHalloweenShopModal());
            }
            else
            {
                Debug.LogError("[MainMenuController] No existe «halloweenpass-modal-view» en el UXML: el pase de Halloween no podrá abrirse.");
            }

            // Tablero de misiones de la velada: modal por encima del pase (VIEW 10).
            _halloweenMissionsModalView = _root.Q<VisualElement>("halloween-missions-modal-view");
            if (_halloweenMissionsModalView != null)
            {
                _halloweenMissionsModal = gameObject.GetComponent<HalloweenMissionsModal>()
                    ?? gameObject.AddComponent<HalloweenMissionsModal>();
                _halloweenMissionsModal.Initialize(
                    _halloweenMissionsModalView,
                    onClose: () => CloseHalloweenMissionsModal(),
                    onToast: (message, subtitle) => _gambitToast?.Show(message, subtitle));
            }
            else
            {
                Debug.LogError("[MainMenuController] No existe «halloween-missions-modal-view» en el UXML: las misiones de la velada no podrán abrirse.");
            }

            // Tienda de la velada: modal por encima del pase (VIEW 11). Vende
            // niveles del mini-pase, skins esculpidas y variantes; todo con
            // Dulces. El inventario sigue siendo el único que equipa.
            _halloweenShopModalView = _root.Q<VisualElement>("halloween-shop-modal-view");
            if (_halloweenShopModalView != null)
            {
                _halloweenShopModal = gameObject.GetComponent<HalloweenShopModal>()
                    ?? gameObject.AddComponent<HalloweenShopModal>();
                _halloweenShopModal.Initialize(
                    _halloweenShopModalView,
                    onClose: () => CloseHalloweenShopModal(),
                    onToast: (message, subtitle) => _gambitToast?.Show(message, subtitle),
                    onOpenInventory: tab =>
                    {
                        CloseHalloweenShopModal();
                        OpenInventoryModal(tab);
                    });
            }
            else
            {
                Debug.LogError("[MainMenuController] No existe «halloween-shop-modal-view» en el UXML: la tienda de la velada no podrá abrirse.");
            }

            // El botón PROGRESO del menú es ahora una ficha más de la botonera
            // (antes llevaba el marco ornamental de 9-slice, que solo encajaba
            // con un botón de ancho completo y lo convertía en un cartel en vez
            // de un botón). El marco sigue usándose dentro del modal.

            // La UI de progreso se repinta cuando cambia cualquier contador
            if (!_progressEventsHooked)
            {
                GambitProgress.OnChanged += RefreshProgressionUI;
                _progressEventsHooked = true;
            }

            // Asegurar OceanPayService en escena
            if (OceanPayService.Instance == null)
                new GameObject("OceanPayService").AddComponent<OceanPayService>();

            // Animaciones: vignette, stagger, ambiente del header y parallax con ratón
            ApplyMenuVignette();
            BuildStaggerLists();

            // Chapa del rail INVENTARIO: cuántas cosas tuyas hay
            UpdateInventoryBadge();
            _root.RegisterCallback<PointerMoveEvent>(OnRootPointerMove);
            if (_headerIdle == null) _headerIdle = StartCoroutine(AnimateHeaderIdle());
            if (_shineLoop == null) _shineLoop = StartCoroutine(AnimateButtonShine());

            DisplaySettings.Changed -= UpdateFullscreenUI;
            DisplaySettings.Changed += UpdateFullscreenUI;
            UpdateCinematicsUI();
            UpdateMusicToggleUI();
            UpdateMusicPreferencesUI();
            UpdateFullscreenUI();
            ShowMainMenu();

            _uiInitialized = true;
            Debug.Log("[MainMenuController] UI inicializada correctamente.");
        }

        // ── Difficulty Card Binding ────────────────────────────────────────────

        private void BindDifficultyCard(string cardName, string btnName, DifficultyLevel level)
        {
            var card = _root.Q<VisualElement>(cardName);
            if (card == null) return;
            // Legacy button ya no existe (COMBATIR removido) pero mantener compat
            var btn = _root.Q<Button>(btnName);
            if (btn != null) btn.style.display = DisplayStyle.None;
            // Toda la tarjeta es clicable y navegable con gamepad/teclado
            card.focusable = true;
            card.RegisterCallback<ClickEvent>(_ => SelectDifficulty(level));
            card.RegisterCallback<NavigationSubmitEvent>(_ => SelectDifficulty(level));

            // Recompensa del modo: se anuncia en cada card (más difícil el rival, más paga)
            var reward = GambitIcon.Row(MatchRewards.CardLabel(level), 14f, "diff-reward");
            reward.name = $"lbl-reward-{(int)level}";
            reward.pickingMode = PickingMode.Ignore;
            card.Add(reward);
        }

        private void SelectDifficulty(DifficultyLevel level, bool playSound = true)
        {
            _selectedDifficulty = level;
            // Marcar visualmente la seleccionada
            string[] allCards = { "card-novice", "card-apprentice", "card-knight", "card-master", "card-grandmaster" };
            string selectedName = GetCardNameForLevel(level);
            VisualElement selectedCard = null;
            foreach (var cname in allCards)
            {
                var c = _root.Q<VisualElement>(cname);
                if (c == null) continue;
                if (cname == selectedName)
                {
                    c.AddToClassList("diff-card-selected");
                    selectedCard = c;
                }
                else
                {
                    c.RemoveFromClassList("diff-card-selected");
                }
            }

            // Pop de feedback solo en interacción del usuario (no en preselección)
            if (playSound)
            {
                if (selectedCard != null)
                {
                    var popCard = selectedCard;
                    popCard.AddToClassList("diff-pop");
                    popCard.schedule.Execute(() => popCard.RemoveFromClassList("diff-pop")).StartingIn(270);
                }
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            }

            UpdateCTA();
        }

        private string GetCardNameForLevel(DifficultyLevel level)
        {
            return level switch
            {
                DifficultyLevel.Novice => "card-novice",
                DifficultyLevel.Apprentice => "card-apprentice",
                DifficultyLevel.Knight => "card-knight",
                DifficultyLevel.Master => "card-master",
                DifficultyLevel.GrandMaster => "card-grandmaster",
                _ => "card-knight"
            };
        }

        private void UpdateCTA()
        {
            if (_btnStartGame == null) return;
            if (_selectedDifficulty.HasValue)
            {
                var cfg = AIDifficultyPresets.GetConfig(_selectedDifficulty.Value);
                _btnStartGame.RemoveFromClassList("cta-disabled");
                _btnStartGame.SetEnabled(true);
                _btnStartGame.text = $"⚔️  INICIAR PARTIDA — {cfg.name.ToUpper()}";
            }
            else
            {
                _btnStartGame.AddToClassList("cta-disabled");
                _btnStartGame.SetEnabled(false);
                _btnStartGame.text = "SELECCIONA UN RIVAL";
            }

            // El hint del CTA anuncia lo que se gana en el modo elegido
            UpdateCTAHint();
        }

        private void OnStartGameClicked()
        {
            if (!_selectedDifficulty.HasValue)
            {
                // Feedback sutil si no hay selección
                PlayCtaShake();
                return;
            }
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            OnDifficultySelected(_selectedDifficulty.Value);
        }

        // ── Vista transitions ─────────────────────────────────────────────────

        public VisualElement UiRoot => _root;
        public VisualElement MenuContainer => _root?.Q<VisualElement>("root-container");

        /// <summary>
        /// Abre la Cacería de Dulces (modo temporal de la Velada) sobre el menú.
        /// La pantalla se monta en el mismo UIDocument y deja intacto el tablero 3D.
        /// </summary>
        private void OpenCandyMode()
        {
            if (HalloweenEvent.CurrentPhase != HalloweenEvent.Phase.Active) return;

            var candy = GetComponent<CandyModeController>();
            if (candy == null) candy = gameObject.AddComponent<CandyModeController>();
            candy.Open();
        }

        public void ShowMainMenu()
        {
            if (_root == null) return;
            CandyModeController.Instance?.ForceClose();
            _root.style.display = DisplayStyle.Flex;

            bool mainVisible = _mainMenuView != null && !_mainMenuView.ClassListContains("hidden");
            bool diffVisible = _difficultyView != null && !_difficultyView.ClassListContains("hidden");

            // Paridad con el comportamiento anterior: cerrar modales de inmediato
            CloseModalImmediate(_settingsModalView);
            CloseModalImmediate(_shopModalView);
            CloseModalImmediate(_yourPiecesModalView);
            CloseModalImmediate(_inventoryModalView);
            if (_progressModalView != null && !_progressModalView.ClassListContains("hidden"))
            {
                CloseModalImmediate(_progressModalView);
                _progressModal?.OnClosed();
            }
            if (_seasonPassModalView != null && !_seasonPassModalView.ClassListContains("hidden"))
            {
                CloseModalImmediate(_seasonPassModalView);
                _seasonPassModal?.OnClosed();
            }
            if (_halloweenPassModalView != null && !_halloweenPassModalView.ClassListContains("hidden"))
            {
                CloseModalImmediate(_halloweenPassModalView);
                _halloweenPassModal?.OnClosed();
            }
            if (_halloweenMissionsModalView != null && !_halloweenMissionsModalView.ClassListContains("hidden"))
            {
                CloseModalImmediate(_halloweenMissionsModalView);
                _halloweenMissionsModal?.OnClosed();
            }
            if (_halloweenShopModalView != null && !_halloweenShopModalView.ClassListContains("hidden"))
            {
                CloseModalImmediate(_halloweenShopModalView);
                _halloweenShopModal?.OnClosed();
            }

            // Cintillo de la tarjeta de Halloween: PRÓXIMAMENTE / ACTIVO / TERMINADO.
            UpdateHalloweenEntryUI();

            if (WilderGambit.Audio.MusicManager.Instance != null)
            {
                WilderGambit.Audio.MusicManager.Instance.PlayMenuMusic();
            }

            if (mainVisible)
            {
                _difficultyView?.AddToClassList("hidden");
                // Primera entrada (init): reproducir el stagger del menú
                if (!_uiInitialized)
                    PlayStagger(_mainStaggerItems);
                return;
            }

            // Transición con fundido: dificultad -> menú
            TransitionToViews(diffVisible ? _difficultyView : null, _mainMenuView,
                () => _difficultyView?.AddToClassList("hidden"), _mainStaggerItems);
        }

        public void ShowDifficultyView()
        {
            if (_root == null) return;

            bool diffVisible = _difficultyView != null && !_difficultyView.ClassListContains("hidden");
            bool mainVisible = _mainMenuView != null && !_mainMenuView.ClassListContains("hidden");

            UpdateDifficultySuggestionUI();
            UpdateCTA();

            if (diffVisible) return;

            // Paridad con el comportamiento anterior: cerrar Ajustes, Tus Piezas e Inventario al entrar
            CloseModalImmediate(_settingsModalView);
            CloseModalImmediate(_yourPiecesModalView);
            CloseModalImmediate(_inventoryModalView);

            // Preselección del último rival + récords + badge de recomendación + hint
            SelectDifficulty(DynamicDifficultyManager.LastDifficulty, playSound: false);
            UpdateRecommendedBadge();
            UpdateRecordChips();
            UpdateCTAHint();

            // Drawers del control de tiempo: re-aparcados en cada entrada a la vista
            _hoveredTimeCard = null;
            _focusedTimeCard = null;
            ApplyTimeDrawerState();

            // Transición con fundido: menú -> dificultad
            TransitionToViews(mainVisible ? _mainMenuView : null, _difficultyView,
                () => _mainMenuView?.AddToClassList("hidden"), _diffStaggerItems);

            // Re-aplicar el parked al terminar el fundido (el scale del view-panel desplaza el bound)
            _root?.schedule.Execute(ApplyTimeDrawerState).StartingIn(450);
        }

        // -- Transiciones de vista con fundido cruzado ---------------------------

        private void TransitionToViews(VisualElement outgoing, VisualElement incoming, System.Action hideOutgoing, List<VisualElement> staggerItems)
        {
            if (_viewTransition != null)
            {
                StopCoroutine(_viewTransition);
                _viewTransition = null;
            }

            // Limpiar opacidades residuales de una transición anterior
            if (_mainMenuView != null) _mainMenuView.style.opacity = new StyleFloat(StyleKeyword.Null);
            if (_difficultyView != null) _difficultyView.style.opacity = new StyleFloat(StyleKeyword.Null);

            if (incoming == null) return;
            _viewTransition = StartCoroutine(ViewTransitionRoutine(outgoing, incoming, hideOutgoing, staggerItems));
        }

        private IEnumerator ViewTransitionRoutine(VisualElement outgoing, VisualElement incoming, System.Action hideOutgoing, List<VisualElement> staggerItems)
        {
            // 1) Fundido de salida (la transición de .view-panel dura 0.3s)
            if (outgoing != null && outgoing != incoming)
            {
                outgoing.style.opacity = 0f;
                yield return new WaitForSecondsRealtime(0.3f);
                hideOutgoing?.Invoke();
                outgoing.style.opacity = new StyleFloat(StyleKeyword.Null);
            }

            // 2) Preparar la entrada escalonada mientras la vista sigue oculta
            PlayStagger(staggerItems);

            // 3) Entrada con fundido
            incoming.RemoveFromClassList("hidden");
            incoming.style.opacity = 0f;
            yield return null;
            incoming.style.opacity = new StyleFloat(StyleKeyword.Null);

            _viewTransition = null;
        }

        // -- Entrada escalonada (stagger) ----------------------------------------

        private void PlayStagger(List<VisualElement> items, int startDelayMs = 80, int stepMs = 60)
        {
            if (items == null || items.Count == 0) return;
            int gen = ++_staggerGeneration;

            foreach (var el in items)
            {
                if (el == null) continue;
                el.RemoveFromClassList("stagger-in");
                el.AddToClassList("stagger-item");
            }

            int i = 0;
            foreach (var el in items)
            {
                if (el == null) continue;
                var target = el;
                int delay = startDelayMs + i * stepMs;
                target.schedule.Execute(() =>
                {
                    if (gen != _staggerGeneration) return;
                    target.AddToClassList("stagger-in");
                }).StartingIn(delay);
                i++;
            }

            // Retirar las clases al terminar para no pisar los estilos de hover/active
            int cleanupDelay = startDelayMs + items.Count * stepMs + 700;
            var root = _root;
            if (root == null) return;
            root.schedule.Execute(() =>
            {
                if (gen != _staggerGeneration) return;
                foreach (var el in items)
                {
                    if (el == null) continue;
                    el.RemoveFromClassList("stagger-in");
                    el.RemoveFromClassList("stagger-item");
                }
            }).StartingIn(cleanupDelay);
        }

        private void BuildStaggerLists()
        {
            _titleCrown = _root.Q<VisualElement>(className: "title-crown");
            _separatorDiamond = _root.Q<VisualElement>(className: "separator-diamond");
            _titleGlow = _root.Q<VisualElement>(className: "title-glow");

            _mainStaggerItems.Clear();
            _mainStaggerItems.Add(_titleCrown);
            _mainStaggerItems.Add(_root.Q<VisualElement>(className: "title-wrap"));
            _mainStaggerItems.Add(_root.Q<VisualElement>(className: "title-separator"));
            _mainStaggerItems.Add(_root.Q<VisualElement>(className: "main-subtitle"));
            _mainStaggerItems.Add(_btnPlay);
            _mainStaggerItems.Add(_btnYourPieces);
            // Las dos filas de fichas (Tienda/Ajustes y Progreso/Salir) entran
            // escalonadas: se recogen todas, no solo la primera.
            _mainStaggerItems.AddRange(_root.Query<VisualElement>(className: "menu-action-row").ToList());
            _mainStaggerItems.Add(_root.Q<VisualElement>("menu-inventory-rail"));
            _mainStaggerItems.Add(_root.Q<VisualElement>(className: "menu-wallet"));
            _mainStaggerItems.Add(_root.Q<VisualElement>(className: "menu-rail-left"));
            _mainStaggerItems.Add(_root.Q<VisualElement>(className: "footer-badge"));
            _mainStaggerItems.RemoveAll(v => v == null);

            _diffStaggerItems.Clear();
            _diffStaggerItems.Add(_root.Q<VisualElement>(className: "difficulty-header"));
            _diffStaggerItems.Add(_root.Q<VisualElement>("difficulty-suggestion"));
            foreach (string cardName in new[] { "card-novice", "card-apprentice", "card-knight", "card-master", "card-grandmaster" })
                _diffStaggerItems.Add(_root.Q<VisualElement>(cardName));
            _diffStaggerItems.Add(_root.Q<VisualElement>(className: "section-divider"));
            _diffStaggerItems.Add(_root.Q<VisualElement>(className: "time-control-section"));
            _diffStaggerItems.Add(_root.Q<VisualElement>("btn-start-game"));
            _diffStaggerItems.Add(_root.Q<Label>("cta-hint"));
            _diffStaggerItems.Add(_root.Q<VisualElement>(className: "bottom-bar"));
            _diffStaggerItems.RemoveAll(v => v == null);
        }

        // -- Modales con fundido --------------------------------------------------

        private void ShowModalWithFade(VisualElement modal)
        {
            if (modal == null) return;
            if (_modalHideSchedules.TryGetValue(modal, out var pendingHide))
            {
                pendingHide?.Pause();
                _modalHideSchedules.Remove(modal);
            }
            modal.style.opacity = 0f;
            modal.RemoveFromClassList("hidden");
            modal.schedule.Execute(() => modal.style.opacity = new StyleFloat(StyleKeyword.Null)).StartingIn(30);
        }

        private void HideModalWithFade(VisualElement modal)
        {
            if (modal == null || modal.ClassListContains("hidden")) return;
            modal.style.opacity = 0f;
            if (_modalHideSchedules.TryGetValue(modal, out var pendingHide))
                pendingHide.Pause();
            _modalHideSchedules[modal] = modal.schedule.Execute(() =>
            {
                modal.AddToClassList("hidden");
                modal.style.opacity = new StyleFloat(StyleKeyword.Null);
                _modalHideSchedules.Remove(modal);
            }).StartingIn(250);
        }

        private void CloseModalImmediate(VisualElement modal)
        {
            if (modal == null) return;
            if (_modalHideSchedules.TryGetValue(modal, out var pendingHide))
            {
                pendingHide?.Pause();
                _modalHideSchedules.Remove(modal);
            }
            modal.style.opacity = new StyleFloat(StyleKeyword.Null);
            modal.AddToClassList("hidden");
        }

        // -- Vignette radial generado por código ----------------------------------

        private void ApplyMenuVignette()
        {
            var vignette = _root.Q<VisualElement>("menu-vignette");
            if (vignette == null) return;

            const int size = 256;
            var tex = new Texture2D(size, size, TextureFormat.RGBA32, false)
            {
                name = "menu-vignette-tex",
                filterMode = FilterMode.Bilinear,
                wrapMode = TextureWrapMode.Clamp
            };

            var pixels = new Color32[size * size];
            for (int y = 0; y < size; y++)
            {
                float ny = (y / (float)(size - 1)) * 2f - 1f;
                for (int x = 0; x < size; x++)
                {
                    float nx = (x / (float)(size - 1)) * 2f - 1f;
                    float d = Mathf.Sqrt(nx * nx + ny * ny) * 0.70710678f; // 0 centro -> 1 esquina
                    float a = Mathf.SmoothStep(0.42f, 1f, d) * 0.8f;
                    pixels[y * size + x] = new Color32(5, 8, 15, (byte)Mathf.Clamp(Mathf.RoundToInt(a * 255f), 0, 255));
                }
            }

            tex.SetPixels32(pixels);
            tex.Apply(false);
            vignette.style.backgroundImage = new StyleBackground(Background.FromTexture2D(tex));
        }

        // -- Parallax del ratón ---------------------------------------------------

        private void OnRootPointerMove(PointerMoveEvent evt)
        {
            var panel = _root?.panel;
            if (panel == null) return;
            float w = panel.visualTree.resolvedStyle.width;
            float h = panel.visualTree.resolvedStyle.height;
            if (w <= 1f || h <= 1f) return;
            _parallaxMouseTarget.x = Mathf.Clamp(evt.position.x / w - 0.5f, -0.5f, 0.5f);
            _parallaxMouseTarget.y = Mathf.Clamp(evt.position.y / h - 0.5f, -0.5f, 0.5f);
        }

        // -- Ambiente del header: corona, diamante y halo -------------------------

        private IEnumerator AnimateHeaderIdle()
        {
            while (_root != null && _root.panel != null)
            {
                _headerIdleTime += Time.unscaledDeltaTime;
                float e = _headerIdleTime;

                // Corona: flotación vertical suave
                if (_titleCrown != null)
                    _titleCrown.style.translate = new Translate(new Length(0f, LengthUnit.Pixel), new Length(Mathf.Sin(e * 1.1f) * 4f, LengthUnit.Pixel));

                // Diamante del separador: pulso dorado
                if (_separatorDiamond != null)
                    _separatorDiamond.style.opacity = 0.5f + 0.5f * (Mathf.Sin(e * 2.1f) * 0.5f + 0.5f);

                // Halo del título: respiración lenta
                if (_titleGlow != null)
                    _titleGlow.style.opacity = 0.35f + 0.4f * (Mathf.Sin(e * 0.9f) * 0.5f + 0.5f);

                // Pista de control de tiempo: balanceo suave de las flechas hacia las esquinas
                if (_timeHintRow != null)
                    _timeHintRow.style.translate = new Translate(new Length(0f, LengthUnit.Pixel), new Length(Mathf.Sin(e * 2.6f) * 3.5f, LengthUnit.Pixel));

                yield return null;
            }
            _headerIdle = null;
        }

        // -- Shine del botón JUGAR ------------------------------------------------

        private IEnumerator AnimateButtonShine()
        {
            while (_root != null && _root.panel != null && (_btnPlay == null || _btnPlay.panel == null))
                yield return null;
            if (_root == null || _btnPlay == null) yield break;

            var shine = _btnPlay.Q<VisualElement>(className: "btn-shine");
            if (shine == null) yield break;

            shine.style.opacity = 0f;

            while (_root != null && _root.panel != null && _btnPlay.panel != null)
            {
                // Pausa entre barridos (solo con el menú visible)
                float rest = 0f;
                while (rest < 4f)
                {
                    bool menuHidden = _mainMenuView != null && _mainMenuView.ClassListContains("hidden");
                    if (menuHidden) rest = 0f;
                    else rest += Time.unscaledDeltaTime;
                    yield return null;
                }

                float width = _btnPlay.resolvedStyle.width;
                if (width <= 1f) { yield return null; continue; }

                shine.style.opacity = 0.45f;
                float dur = 1.15f;
                float u = 0f;
                while (u < dur)
                {
                    u += Time.unscaledDeltaTime;
                    float p = Mathf.Clamp01(u / dur);
                    p = p * p * (3f - 2f * p); // smoothstep
                    shine.style.translate = new Translate(new Length(p * (width + 80f), LengthUnit.Pixel), new Length(0f, LengthUnit.Pixel));
                    yield return null;
                }

                shine.style.opacity = 0f;
                shine.style.translate = new Translate(new Length(0f, LengthUnit.Pixel), new Length(0f, LengthUnit.Pixel));
            }
            _shineLoop = null;
        }

        // -- Feedback de shake en el CTA sin selección ----------------------------

        private void PlayCtaShake()
        {
            if (_btnStartGame == null) return;
            if (_ctaShake != null) StopCoroutine(_ctaShake);
            _ctaShake = StartCoroutine(CtaShakeRoutine());
        }

        private IEnumerator CtaShakeRoutine()
        {
            var btn = _btnStartGame;
            if (btn == null) { _ctaShake = null; yield break; }

            float dur = 0.35f;
            float u = 0f;
            while (u < dur && btn.panel != null)
            {
                u += Time.unscaledDeltaTime;
                float p = Mathf.Clamp01(u / dur);
                float x = Mathf.Sin(p * Mathf.PI * 6f) * (1f - p) * 9f;
                btn.style.translate = new Translate(new Length(x, LengthUnit.Pixel), new Length(0f, LengthUnit.Pixel));
                yield return null;
            }

            if (btn.panel != null)
                btn.style.translate = new Translate(new Length(0f, LengthUnit.Pixel), new Length(0f, LengthUnit.Pixel));
            _ctaShake = null;
        }

        private void UpdateDifficultySuggestionUI()
        {
            if (_suggestionBanner == null) return;
            if (DynamicDifficultyManager.TryGetSuggestedLevel(out var suggested))
            {
                _pendingSuggestedLevel = suggested;
                bool isHarder = (int)suggested > (int)DynamicDifficultyManager.LastDifficulty;
                _suggestionBanner.RemoveFromClassList("hidden");
                _suggestionBanner.RemoveFromClassList("suggestion-harder");
                _suggestionBanner.RemoveFromClassList("suggestion-easier");
                _suggestionBanner.AddToClassList(isHarder ? "suggestion-harder" : "suggestion-easier");

                if (_suggestionIcon != null) _suggestionIcon.text = isHarder ? "🔥" : "🧘";
                if (_suggestionTitle != null)
                    _suggestionTitle.text = isHarder
                        ? $"¡Racha de {DynamicDifficultyManager.WinStreak} victorias!"
                        : $"Racha de {DynamicDifficultyManager.LossStreak} derrotas";
                if (_suggestionSubtitle != null)
                {
                    var cfg = AIDifficultyPresets.GetConfig(suggested);
                    _suggestionSubtitle.text = isHarder
                        ? $"Dominas este nivel. ¿Probar {cfg.name}?"
                        : $"¿Bajar a {cfg.name} para recuperar confianza?";
                }
                if (_suggestionStreak != null)
                    _suggestionStreak.text = $"{DynamicDifficultyManager.GetStreakText()} • Sugerido: {suggested}";
                if (_btnSuggestionAccept != null) _btnSuggestionAccept.text = $"PROBAR {suggested.ToString().ToUpper()} →";
            }
            else
            {
                _suggestionBanner.AddToClassList("hidden");
            }
        }

        private void AcceptDifficultySuggestion()
        {
            DynamicDifficultyManager.AcceptSuggestion();
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            SelectDifficulty(_pendingSuggestedLevel);
        }

        private void DismissDifficultySuggestion()
        {
            DynamicDifficultyManager.DismissSuggestion();
            _suggestionBanner?.AddToClassList("hidden");
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
        }

        public void OpenSettingsModal()
        {
            UpdateCinematicsUI();
            UpdateMusicToggleUI();
            UpdateMusicPreferencesUI();
            UpdateFullscreenUI();
            ShowModalWithFade(_settingsModalView);
            CloseMusicSearchPopup();
        }

        public void CloseSettingsModal()
        {
            HideModalWithFade(_settingsModalView);
            CloseMusicSearchPopup();
        }

        public void OpenShopModal()
        {
            ShowModalWithFade(_shopModalView);
            _shopModal?.OnShopOpened();
        }

        public void CloseShopModal()
        {
            HideModalWithFade(_shopModalView);
            _shopModal?.OnShopClosed();
        }

        // ── Pase de temporada (pantalla completa) ────────────────────────

        /// <summary>
        /// Abre el pase a pantalla completa: hero con el banner del rey, título
        /// diseñado, barra ornamental y medallones con doble vía de recompensas.
        /// </summary>
        public void OpenSeasonPassModal()
        {
            if (_seasonPassModalView == null)
                _seasonPassModalView = _root?.Q<VisualElement>("seasonpass-modal-view");
            if (_seasonPassModalView == null)
            {
                _gambitToast?.Show("🎟️ PASE DE TEMPORADA", "No se pudo abrir el pase · reintenta");
                return;
            }
            ShowModalWithFade(_seasonPassModalView);
            _seasonPassModal?.OnOpened();
            Debug.Log("[MainMenuController] Pase de temporada abierto.");
        }

        public void CloseSeasonPassModal()
        {
            HideModalWithFade(_seasonPassModalView);
            _seasonPassModal?.OnClosed();
        }

        // ── Pase de Halloween (la velada: 20/10 → 4/11) ─────────────────

        /// <summary>
        /// Abre el pase de la velada: XP del evento, misiones diarias, Dulces
        /// y la pista de 30 niveles con dos vías (Luna y Sangre).
        /// </summary>
        public void OpenHalloweenPassModal()
        {
            if (_halloweenPassModalView == null)
                _halloweenPassModalView = _root?.Q<VisualElement>("halloweenpass-modal-view");
            if (_halloweenPassModalView == null)
            {
                _gambitToast?.Show("🎃 PASE DE HALLOWEEN", "No se pudo abrir el pase · reintenta");
                return;
            }
            ShowModalWithFade(_halloweenPassModalView);
            _halloweenPassModal?.OnOpened();
            Debug.Log("[MainMenuController] Pase de Halloween abierto.");
        }

        public void CloseHalloweenPassModal()
        {
            HideModalWithFade(_halloweenPassModalView);
            _halloweenPassModal?.OnClosed();
        }

        // ── Misiones de la velada (modal del tablero) ────────────────────

        /// <summary>
        /// Abre el tablero de misiones por encima de la velada: la pestaña Luna
        /// con las 3 misiones del día o la de Sangre con las 10 exclusivas.
        /// </summary>
        /// <param name="sangre">true abre directamente la pestaña Vía Sangre.</param>
        public void OpenHalloweenMissionsModal(bool sangre = false)
        {
            if (_halloweenMissionsModalView == null)
                _halloweenMissionsModalView = _root?.Q<VisualElement>("halloween-missions-modal-view");
            if (_halloweenMissionsModalView == null)
            {
                _gambitToast?.Show("🕯️ MISIONES DE LA VELADA", "No se pudo abrir el tablero · reintenta");
                return;
            }
            _halloweenMissionsModal?.PrepareTab(sangre);
            ShowModalWithFade(_halloweenMissionsModalView);
            _halloweenMissionsModal?.OnOpened();
            Debug.Log($"[MainMenuController] Tablero de misiones de la velada abierto ({(sangre ? "Sangre" : "Luna")}).");
        }

        public void CloseHalloweenMissionsModal()
        {
            HideModalWithFade(_halloweenMissionsModalView);
            _halloweenMissionsModal?.OnClosed();
        }

        // ── Tienda de la velada (modal de Dulces) ────────────────────────

        /// <summary>
        /// Abre la tienda de la velada por encima del pase: niveles del mini-pase
        /// (y completar todo el pase), skins esculpidas y variantes. Todo se paga
        /// con Dulces y nada se equipa desde aquí.
        /// </summary>
        public void OpenHalloweenShopModal()
        {
            if (_halloweenShopModalView == null)
                _halloweenShopModalView = _root?.Q<VisualElement>("halloween-shop-modal-view");
            if (_halloweenShopModalView == null)
            {
                _gambitToast?.Show("🍬 TIENDA DE LA VELADA", "No se pudo abrir la tienda · reintenta");
                return;
            }
            ShowModalWithFade(_halloweenShopModalView);
            _halloweenShopModal?.OnOpened();
            Debug.Log("[MainMenuController] Tienda de la velada abierta.");
        }

        public void CloseHalloweenShopModal()
        {
            HideModalWithFade(_halloweenShopModalView);
            _halloweenShopModal?.OnClosed();
        }

        /// <summary>
        /// Cintillo de la tarjeta de Halloween en el menú: PRÓXIMAMENTE →
        /// ¡ACTIVO! → TERMINADO, con su clase de color y el detalle en tooltip.
        /// </summary>
        private void UpdateHalloweenEntryUI()
        {
            UpdateCandyModeEntryUI();

            var ribbon = _root?.Q<Label>("halloweenpass-soon");
            if (ribbon == null) return;

            ribbon.RemoveFromClassList("soon-active");
            ribbon.RemoveFromClassList("soon-ended");

            switch (HalloweenEvent.CurrentPhase)
            {
                case HalloweenEvent.Phase.NotStarted:
                    ribbon.text = "PRÓXIMAMENTE";
                    ribbon.tooltip = HalloweenEvent.TimeTextNow;
                    break;
                case HalloweenEvent.Phase.Active:
                    ribbon.text = "¡ACTIVO!";
                    ribbon.AddToClassList("soon-active");
                    ribbon.tooltip = HalloweenEvent.TimeTextNow;
                    break;
                default:
                    ribbon.text = "TERMINADO";
                    ribbon.AddToClassList("soon-ended");
                    ribbon.tooltip = HalloweenEvent.TimeTextNow;
                    break;
            }
        }

        // ── Progreso (Gambits, misiones y barra semanal) ──────────────────────

        /// <summary>
        /// La Cacería de Dulces es temporal: sólo se puede abrir mientras la
        /// Velada está activa. Antes del 20/10 se muestra apagada; después del
        /// 4/11 desaparece del menú.
        /// </summary>
        private void UpdateCandyModeEntryUI()
        {
            if (_btnCandyMode == null) return;

            var sub = _btnCandyMode.Q<Label>("btn-candy-sub");
            _btnCandyMode.tooltip = HalloweenEvent.TimeTextNow;

            switch (HalloweenEvent.CurrentPhase)
            {
                case HalloweenEvent.Phase.Active:
                    _btnCandyMode.style.display = DisplayStyle.Flex;
                    _btnCandyMode.SetEnabled(true);
                    if (sub != null) sub.text = "DE DULCES";
                    break;
                case HalloweenEvent.Phase.NotStarted:
                    _btnCandyMode.style.display = DisplayStyle.Flex;
                    _btnCandyMode.SetEnabled(false);
                    if (sub != null) sub.text = "PRONTO";
                    break;
                default:
                    _btnCandyMode.style.display = DisplayStyle.None;
                    _btnCandyMode.SetEnabled(false);
                    break;
            }
        }

        public void OpenProgressModal()
        {
            if (_progressModalView == null) return;
            ShowModalWithFade(_progressModalView);
            _progressModal?.OnOpened();
        }

        public void CloseProgressModal()
        {
            HideModalWithFade(_progressModalView);
            _progressModal?.OnClosed();
            RefreshProgressionUI();
        }

        /// <summary>Saldo en el botón PROGRESO + aviso de misiones pendientes de cobro.</summary>
        public void RefreshProgressionUI()
        {
            if (_menuGambitsValue != null)
                _menuGambitsValue.text = $"{GambitEconomy.Balance:N0} Gambits";

            // La colección también cambia cuando se compra o se equipa algo
            UpdateInventoryBadge();

            if (_btnProgressBadge != null)
            {
                int pending = GambitProgress.PendingClaimsCount;
                if (pending > 0)
                {
                    _btnProgressBadge.text = pending.ToString();
                    ProgressSprites.Apply(_btnProgressBadge, "badge_pending");
                    _btnProgressBadge.RemoveFromClassList("hidden");
                }
                else
                {
                    _btnProgressBadge.AddToClassList("hidden");
                }
            }
        }

        /// <summary>Abre el entrenamiento táctico sobre el tablero (5 puzzles).</summary>
        private void StartTrainingSession()
        {
            var gm = GameManager.Instance;
            if (gm == null)
            {
                _gambitToast?.Show("No hay partida en curso", "Vuelve a intentarlo");
                return;
            }

            CloseProgressModal();

            if (!gm.StartTrainingSession(PuzzleManager.TrainingSessionSize))
            {
                _gambitToast?.Show("No se pudo abrir el entrenamiento");
                return;
            }

            gm.OnTrainingSessionFinished -= OnTrainingSessionFinished;
            gm.OnTrainingSessionFinished += OnTrainingSessionFinished;

            // El tablero toma el protagonismo: se oculta el menú (igual que al empezar partida)
            if (_root != null) _root.style.display = DisplayStyle.None;
        }

        /// <summary>Abre el desafío diario (un puzzle, paga la racha de días).</summary>
        private void StartDailyChallenge()
        {
            var gm = GameManager.Instance;
            if (gm == null)
            {
                _gambitToast?.Show("No hay partida en curso", "Vuelve a intentarlo");
                return;
            }

            CloseProgressModal();

            if (!gm.StartDailyChallenge())
            {
                _gambitToast?.Show("El desafío de hoy ya está hecho");
                ShowMainMenu();
                return;
            }

            gm.OnTrainingSessionFinished -= OnTrainingSessionFinished;
            gm.OnTrainingSessionFinished += OnTrainingSessionFinished;

            if (_root != null) _root.style.display = DisplayStyle.None;
        }

        /// <summary>Fin de entrenamiento/reto: vuelve al menú y cuenta lo que se ganó.</summary>
        private void OnTrainingSessionFinished(TrainingSummary summary)
        {
            if (GameManager.Instance != null)
                GameManager.Instance.OnTrainingSessionFinished -= OnTrainingSessionFinished;

            ShowMainMenu();
            RefreshProgressionUI();

            if (summary.dailyChallenge)
            {
                if (summary.solved > 0)
                {
                    string reward = summary.gambits > 0
                        ? $"+{summary.gambits:N0} Gambits por la racha de días"
                        : "Racha de días registrada";
                    _gambitToast?.Show("🎯 ¡Desafío diario completado!", reward);
                }
                else
                {
                    // Perderlo no cierra el día: la racha y el premio siguen ahí
                    _gambitToast?.Show("🎯 Desafío diario no resuelto", "Puedes reintentarlo hoy");
                }
            }
            else if (summary.practice)
            {
                // Repetir sesión no paga: se dice claro, y por qué, para que no parezca un fallo
                _gambitToast?.Show($"🧩 Práctica: {summary.solved}/{summary.resolved} puzzles",
                                  "La sesión de hoy ya está cobrada · practicar no da Gambits");
            }
            else
            {
                string reward = summary.gambits > 0 ? $"+{summary.gambits:N0} Gambits · rating {summary.rating}" : $"Rating {summary.rating}";
                _gambitToast?.Show($"🧩 Entrenamiento: {summary.solved}/{summary.resolved} puzzles", reward);
            }

            OpenProgressModal();
        }

        public void OpenYourPiecesModal()
        {
            ShowModalWithFade(_yourPiecesModalView);
            _yourPiecesModal?.OnModalOpened();
        }

        public void CloseYourPiecesModal()
        {
            HideModalWithFade(_yourPiecesModalView);
        }

        // ── INVENTARIO (único sitio donde se equipa) ──────────────────────────

        /// <summary>Abre el inventario. <paramref name="tab"/> es opcional: "skins", "boards"…</summary>
        public void OpenInventoryModal(string tab = null)
        {
            if (_inventoryModalView == null)
            {
                Debug.LogError("[MainMenuController] El INVENTARIO no puede abrirse: falta «inventory-modal-view» en el UXML.");
                return;
            }
            if (!string.IsNullOrEmpty(tab)) _inventoryModal?.OpenTab(tab);
            ShowModalWithFade(_inventoryModalView);
            _inventoryModal?.OnOpened();
            UpdateInventoryBadge();
        }

        public void CloseInventoryModal()
        {
            HideModalWithFade(_inventoryModalView);
            UpdateInventoryBadge();
        }

        /// <summary>Chapa del rail: cuántas piezas, skins y tableros hay en la colección.</summary>
        private void UpdateInventoryBadge()
        {
            if (_btnInventoryCount == null) return;

            int size = InventoryModal.CollectionSize();
            _btnInventoryCount.text = size.ToString();
            _btnInventoryCount.EnableInClassList("hidden", size <= 0);
        }

        /// <summary>
        /// Red de seguridad del rail del INVENTARIO: el botón ya lo abre, pero si un
        /// overlay se comiera el <i>pick</i> del rail, este enganche de la raíz detecta
        /// el clic por rectángulo, lo abre igual y deja constancia del intruso.
        /// </summary>
        private void SetupInventoryRail()
        {
            if (_root == null || _inventoryRail == null) return;

            _root.RegisterCallback<ClickEvent>(evt =>
            {
                if (_btnInventory == null) return;

                var target = evt.target as VisualElement;
                bool wentToButton = target != null && (target == _btnInventory || _btnInventory.Contains(target));
                if (wentToButton) return;                                  // camino normal

                // Solo con el menú principal delante y el inventario cerrado: si no,
                // un clic sobre el modal abierto reabriría el inventario sin querer.
                if (_mainMenuView == null || _mainMenuView.ClassListContains("hidden")) return;
                if (_inventoryModalView != null && !_inventoryModalView.ClassListContains("hidden")) return;
                // Con la tienda abierta, sus clics (cards, CTA, vista previa de
                // animaciones…) los atiende la tienda: nunca son del rail.
                if (_shopModalView != null && !_shopModalView.ClassListContains("hidden")) return;
                // Cualquier otro modal (ajustes, progreso, pase, tus piezas…) cuelga de la
                // raíz, no del menú principal: sus clics nunca son del rail.
                if (target == null || !(target == _mainMenuView || _mainMenuView.Contains(target))) return;
                if (!_inventoryRail.worldBound.Contains(evt.position)) return;

                Debug.LogWarning($"[MainMenuController] El clic del rail lo atrapó «{target?.name}» ({target?.GetType().Name}): se abre el INVENTARIO igualmente.");
                OpenInventoryModal();
            });
        }

        /// <summary>Arte del macuto en el rail girado. Si el PNG no está, queda el emoji.</summary>
        private void ApplyInventoryButtonArt()
        {
            if (_root == null) return;

            Sprite backpack = InventorySprites.BackpackSprite;
            var art = _root.Q<Image>("btn-inventory-art");
            if (art != null && backpack != null)
            {
                art.sprite = backpack;
                art.scaleMode = ScaleMode.ScaleToFit;
            }
            art?.EnableInClassList("hidden", backpack == null);
            _root.Q<Label>("btn-inventory-art-fallback")?.EnableInClassList("hidden", backpack != null);
        }

        // ── Settings ──────────────────────────────────────────────────────────

        private void ToggleFullscreen()
        {
            DisplaySettings.Toggle();
            UpdateFullscreenUI();
        }

        private void UpdateFullscreenUI()
        {
            if (_btnToggleFullscreen == null) return;

            bool fullscreen = DisplaySettings.IsFullscreen;
            _btnToggleFullscreen.text = fullscreen ? "ACTIVADO" : "DESACTIVADO";
            _btnToggleFullscreen.EnableInClassList("active", fullscreen);
            _btnToggleFullscreen.EnableInClassList("inactive", !fullscreen);
        }

        private void ToggleCinematics()
        {
            _isCinematicsEnabled = !_isCinematicsEnabled;
            PlayerPrefs.SetInt("EnableCinematics", _isCinematicsEnabled ? 1 : 0);
            PlayerPrefs.Save();
            if (GameManager.Instance != null)
                GameManager.Instance.EnableCinematics = _isCinematicsEnabled;
            UpdateCinematicsUI();
        }

        private void ToggleMusicEnabled()
        {
            if (WilderGambit.Audio.MusicManager.Instance == null) return;
            bool newState = !WilderGambit.Audio.MusicManager.Instance.IsMusicEnabled;
            WilderGambit.Audio.MusicManager.Instance.SetMusicEnabled(newState);
            UpdateMusicToggleUI();
            UpdateMusicPreferencesUI();
        }

        private void UpdateCinematicsUI()
        {
            if (_btnToggleCinematics == null) return;

            if (_isCinematicsEnabled)
            {
                _btnToggleCinematics.text = "✅  ACTIVADO";
                _btnToggleCinematics.RemoveFromClassList("inactive");
                _btnToggleCinematics.AddToClassList("active");
            }
            else
            {
                _btnToggleCinematics.text = "❌  DESACTIVADO";
                _btnToggleCinematics.RemoveFromClassList("active");
                _btnToggleCinematics.AddToClassList("inactive");
            }
        }

        private void UpdateMusicToggleUI()
        {
            if (_btnToggleMusic == null) return;

            bool isEnabled = WilderGambit.Audio.MusicManager.Instance == null || WilderGambit.Audio.MusicManager.Instance.IsMusicEnabled;

            if (isEnabled)
            {
                _btnToggleMusic.text = "✅  ACTIVADO";
                _btnToggleMusic.RemoveFromClassList("inactive");
                _btnToggleMusic.AddToClassList("active");
            }
            else
            {
                _btnToggleMusic.text = "❌  DESACTIVADO";
                _btnToggleMusic.RemoveFromClassList("active");
                _btnToggleMusic.AddToClassList("inactive");
            }
        }

        private void CycleMenuMusic(int delta)
        {
            if (WilderGambit.Audio.MusicManager.Instance == null) return;
            var names = WilderGambit.Audio.MusicManager.Instance.GetMenuTrackNames();
            if (names.Count == 0) return;

            // Mapeo: 0..Count-2 = pistas, Count-1 = Desactivada (-1)
            int current = WilderGambit.Audio.MusicManager.Instance.SelectedMenuTrackIndex;
            int total = names.Count;
            int currentIndex = current == -1 ? (total - 1) : current;

            int nextIndex = (currentIndex + delta + total) % total;
            int targetPref = nextIndex == (total - 1) ? -1 : nextIndex;

            WilderGambit.Audio.MusicManager.Instance.SetMenuTrackPreference(targetPref);
            UpdateMusicPreferencesUI();
        }

        private void CycleBattleMusic(int delta)
        {
            if (WilderGambit.Audio.MusicManager.Instance == null) return;
            var options = WilderGambit.Audio.MusicManager.Instance.GetBattleTrackOptions();
            if (options.Count == 0) return;

            int current = WilderGambit.Audio.MusicManager.Instance.SelectedBattleTrackIndex;
            int total = options.Count;
            // Mapeo: 0 = Alternar (-1), 1..total-2 = pistas (0..N-1), total-1 = Desactivada (-2)
            int currentOpt;
            if (current == -1) currentOpt = 0;
            else if (current == -2) currentOpt = total - 1;
            else currentOpt = current + 1;

            int nextOpt = (currentOpt + delta + total) % total;
            WilderGambit.Audio.MusicManager.Instance.SetBattleTrackPreference(nextOpt);
            UpdateMusicPreferencesUI();
        }

        private void UpdateMusicPreferencesUI()
        {
            if (WilderGambit.Audio.MusicManager.Instance == null) return;

            if (_btnMenuMusicOpen != null)
            {
                var menuNames = WilderGambit.Audio.MusicManager.Instance.GetMenuTrackNames();
                int current = WilderGambit.Audio.MusicManager.Instance.SelectedMenuTrackIndex;
                string name;
                if (current == -1) name = "🔇 Desactivada";
                else if (current >= 0 && current < menuNames.Count) name = menuNames[current];
                else name = "Sovereign Gambit";

                _btnMenuMusicOpen.text = $"🔍 {name} ▾";
            }

            if (_btnBattleMusicOpen != null)
            {
                var battleOptions = WilderGambit.Audio.MusicManager.Instance.GetBattleTrackOptions();
                int current = WilderGambit.Audio.MusicManager.Instance.SelectedBattleTrackIndex;
                string name;
                if (current == -1) name = "🎲 Alternar pistas";
                else if (current == -2) name = "🔇 Desactivada";
                else if (current >= 0 && current + 1 < battleOptions.Count) name = battleOptions[current + 1];
                else name = "🎲 Alternar pistas";

                _btnBattleMusicOpen.text = $"🔍 {name} ▾";
            }
        }

        // ── Popup de Búsqueda de Música ───────────────────────────────────────

        private void OpenMusicSearchPopup(bool forMenuMusic)
        {
            _isSearchingMenuMusic = forMenuMusic;
            if (_musicSearchPopup == null) return;

            if (_lblMusicSearchTitle != null)
                _lblMusicSearchTitle.text = forMenuMusic ? "🎵  MÚSICA DEL MENÚ" : "⚔️  MÚSICA DE PARTIDA";

            if (_lblMusicSearchSubtitle != null)
                _lblMusicSearchSubtitle.text = forMenuMusic
                    ? "Selecciona la pista que sonará en el menú principal y la tienda."
                    : "Selecciona el tema que sonará durante los combates de ajedrez.";

            if (_inputMusicSearch != null)
            {
                _inputMusicSearch.value = "";
                _inputMusicSearch.Focus();
            }

            PopulateMusicTracksList("");
            _musicSearchPopup.RemoveFromClassList("hidden");
        }

        private void CloseMusicSearchPopup()
        {
            _musicSearchPopup?.AddToClassList("hidden");
        }

        private void FilterMusicTracks(string filter)
        {
            PopulateMusicTracksList(filter ?? "");
        }

        private void PopulateMusicTracksList(string filter)
        {
            if (_scrollMusicTracks == null || WilderGambit.Audio.MusicManager.Instance == null) return;
            _scrollMusicTracks.Clear();

            string searchLower = (filter ?? "").Trim().ToLowerInvariant();

            if (_isSearchingMenuMusic)
            {
                var names = WilderGambit.Audio.MusicManager.Instance.GetMenuTrackNames();
                int selected = WilderGambit.Audio.MusicManager.Instance.SelectedMenuTrackIndex;

                for (int i = 0; i < names.Count; i++)
                {
                    string trackName = names[i];
                    int prefValue = (i == names.Count - 1) ? -1 : i; // última opción es Desactivada (-1)

                    if (!string.IsNullOrEmpty(searchLower) && !trackName.ToLowerInvariant().Contains(searchLower))
                        continue;

                    bool isSelected = (selected == prefValue);
                    var card = CreateTrackCard(trackName, isSelected, () =>
                    {
                        WilderGambit.Audio.MusicManager.Instance.SetMenuTrackPreference(prefValue);
                        UpdateMusicPreferencesUI();
                        CloseMusicSearchPopup();
                    });

                    _scrollMusicTracks.Add(card);
                }
            }
            else
            {
                var options = WilderGambit.Audio.MusicManager.Instance.GetBattleTrackOptions();
                int selected = WilderGambit.Audio.MusicManager.Instance.SelectedBattleTrackIndex;

                for (int i = 0; i < options.Count; i++)
                {
                    string optName = options[i];
                    int optIndex = i;

                    if (!string.IsNullOrEmpty(searchLower) && !optName.ToLowerInvariant().Contains(searchLower))
                        continue;

                    bool isSelected;
                    if (optIndex == 0) isSelected = (selected == -1); // Alternar
                    else if (optIndex == options.Count - 1) isSelected = (selected == -2); // Desactivada
                    else isSelected = (selected == optIndex - 1);

                    var card = CreateTrackCard(optName, isSelected, () =>
                    {
                        WilderGambit.Audio.MusicManager.Instance.SetBattleTrackPreference(optIndex);
                        UpdateMusicPreferencesUI();
                        CloseMusicSearchPopup();
                    });

                    _scrollMusicTracks.Add(card);
                }
            }
        }

        private VisualElement CreateTrackCard(string title, bool isSelected, System.Action onClick)
        {
            var card = new Button();
            card.AddToClassList("track-item-card");
            if (isSelected) card.AddToClassList("track-selected");

            var label = new Label(title);
            label.AddToClassList("track-item-name");
            card.Add(label);

            if (isSelected)
            {
                var check = new Label("✓ Activa");
                check.AddToClassList("track-item-badge");
                card.Add(check);
            }

            card.RegisterCallback<ClickEvent>(_ => onClick?.Invoke());
            return card;
        }

        // ── Difficulty Selection ──────────────────────────────────────────────

        // ── Time Control ──────────────────────────────────────────────────────
        private Core.TimeControl _selectedTimeControl = Core.TimeControl.None;
        private Button _btnTimeNone, _btnTimeBullet, _btnTimeBlitz, _btnTimeRapid;
        private List<Button> _timeButtons;

        // Hint bajo el CTA
        private Label _ctaHint;

        // Drawers del control de tiempo (aparcan debajo del borde inferior; estado por tarjeta)
        private VisualElement _timeCardsRow;
        private Button _hoveredTimeCard;
        private Button _focusedTimeCard;
        private VisualElement _timeHintRow;

        private void BindTimeControlButtons()
        {
            _btnTimeNone   = _root?.Q<Button>("btn-time-none");
            _btnTimeBullet = _root?.Q<Button>("btn-time-bullet");
            _btnTimeBlitz  = _root?.Q<Button>("btn-time-blitz");
            _btnTimeRapid  = _root?.Q<Button>("btn-time-rapid");
            _timeButtons = new List<Button> { _btnTimeNone, _btnTimeBullet, _btnTimeBlitz, _btnTimeRapid };

            _btnTimeNone?.RegisterCallback<ClickEvent>(_ => SelectTimeControl(Core.TimeControl.None));
            _btnTimeBullet?.RegisterCallback<ClickEvent>(_ => SelectTimeControl(Core.TimeControl.Bullet));
            _btnTimeBlitz?.RegisterCallback<ClickEvent>(_ => SelectTimeControl(Core.TimeControl.Blitz));
            _btnTimeRapid?.RegisterCallback<ClickEvent>(_ => SelectTimeControl(Core.TimeControl.Rapid));

            // Drawers: hover/foco por tarjeta (la selección solo mantiene arriba a la elegida)
            _timeCardsRow = _root?.Q<VisualElement>(className: "time-cards-row");
            _timeHintRow = _root?.Q<VisualElement>(className: "time-hint-row");

            // Re-aplicar al resolverse el layout (peek exacto) o al cambiar el tamaño del panel
            _timeCardsRow?.RegisterCallback<GeometryChangedEvent>(_ => ApplyTimeDrawerState());
            _difficultyView?.RegisterCallback<GeometryChangedEvent>(_ => ApplyTimeDrawerState());

            foreach (var btn in _timeButtons)
            {
                if (btn == null) continue;
                btn.RegisterCallback<PointerEnterEvent>(_ => { _hoveredTimeCard = btn; ApplyTimeDrawerState(); });
                btn.RegisterCallback<PointerLeaveEvent>(_ =>
                {
                    // Pequeño margen al salir: al cruzar el hueco entre cards no se hunde la anterior
                    btn.schedule.Execute(() =>
                    {
                        if (_hoveredTimeCard == btn) { _hoveredTimeCard = null; ApplyTimeDrawerState(); }
                    }).StartingIn(120);
                });
                btn.RegisterCallback<FocusEvent>(_ => { _focusedTimeCard = btn; ApplyTimeDrawerState(); });
                btn.RegisterCallback<FocusOutEvent>(_ =>
                {
                    if (_focusedTimeCard == btn) { _focusedTimeCard = null; ApplyTimeDrawerState(); }
                });
            }

            ApplyTimeDrawerState();
        }

        private void SelectTimeControl(Core.TimeControl control)
        {
            _selectedTimeControl = control;
            foreach (var btn in _timeButtons)
            {
                if (btn == null) continue;
                btn.RemoveFromClassList("time-btn-active");
                btn.AddToClassList("time-card-dimmed");
            }

            Button activeBtn = control switch
            {
                Core.TimeControl.None   => _btnTimeNone,
                Core.TimeControl.Bullet => _btnTimeBullet,
                Core.TimeControl.Blitz  => _btnTimeBlitz,
                Core.TimeControl.Rapid  => _btnTimeRapid,
                _ => _btnTimeNone
            };

            // Efecto de selección: la elegida se enciende, las demás quedan en gris
            if (activeBtn != null)
            {
                activeBtn.RemoveFromClassList("time-card-dimmed");
                activeBtn.AddToClassList("time-btn-active");
                var popBtn = activeBtn;
                popBtn.AddToClassList("time-card-pop");
                popBtn.schedule.Execute(() => popBtn.RemoveFromClassList("time-card-pop")).StartingIn(270);
            }

            // La selección solo sube la tarjeta elegida (la del lado no se descubre)
            ApplyTimeDrawerState();
        }

        // -- Badge RECOMENDADO en la tarjeta sugerida -----------------------------

        private void UpdateRecommendedBadge()
        {
            string[] allCards = { "card-novice", "card-apprentice", "card-knight", "card-master", "card-grandmaster" };
            foreach (var cname in allCards)
                _root.Q<VisualElement>(cname)?.RemoveFromClassList("diff-recommended");

            if (DynamicDifficultyManager.TryGetSuggestedLevel(out var suggested))
                _root.Q<VisualElement>(GetCardNameForLevel(suggested))?.AddToClassList("diff-recommended");
        }

        // -- Récord V-E-D por tarjeta ---------------------------------------------

        private void UpdateRecordChips()
        {
            for (int lvl = 1; lvl <= 5; lvl++)
            {
                var chip = _root.Q<Label>($"lbl-record-{lvl}");
                if (chip == null) continue;
                var record = DynamicDifficultyManager.GetRecord((DifficultyLevel)lvl);
                int total = record.wins + record.losses + record.draws;
                if (total == 0)
                {
                    chip.AddToClassList("hidden");
                    continue;
                }
                chip.RemoveFromClassList("hidden");
                chip.text = record.draws > 0
                    ? $"{record.wins}V · {record.draws}E · {record.losses}D"
                    : $"{record.wins}V · {record.losses}D";
            }
        }

        // -- Hint bajo el CTA ------------------------------------------------------

        private void UpdateCTAHint()
        {
            if (_ctaHint == null) return;

            // Con rival elegido, lo importante es saber cuántos Gambits deja la partida
            if (_selectedDifficulty.HasValue)
            {
                _ctaHint.text = MatchRewards.Hint(_selectedDifficulty.Value);
                return;
            }

            int games = DynamicDifficultyManager.GamesPlayed;
            _ctaHint.text = games == 0
                ? "Primera partida — elige el ritmo y el tamaño del desafío"
                : $"Último rival: {GetCardDisplayName(DynamicDifficultyManager.LastDifficulty).ToUpper()}  •  Partidas jugadas: {games}";
        }

        private static string GetCardDisplayName(DifficultyLevel level)
        {
            return level switch
            {
                DifficultyLevel.Novice => "Principiante",
                DifficultyLevel.Apprentice => "Aprendiz",
                DifficultyLevel.Knight => "Caballero",
                DifficultyLevel.Master => "Maestro",
                DifficultyLevel.GrandMaster => "Gran Maestro",
                _ => "Caballero"
            };
        }

        // -- Drawers del control de tiempo ----------------------------------------

        private void ApplyTimeDrawerState()
        {
            // Estado POR TARJETA (suben desde debajo del borde inferior):
            // seleccionada = arriba; hover/foco de esa tarjeta = parcial (~60%); resto = aparcada (tira de ~56px)
            var panel = _root?.panel;
            float panelWidth = panel != null ? panel.visualTree.resolvedStyle.width : 0f;
            float panelHeight = panel != null ? panel.visualTree.resolvedStyle.height : 0f;

            bool narrow = panelWidth > 0f && panelWidth <= UiResponsive.NarrowThreshold;
            bool geometryOk = !narrow && panelHeight > 1f && _difficultyView != null
                              && _difficultyView.worldBound.width > 1f;

            if (_timeButtons == null) return;

            foreach (var btn in _timeButtons)
            {
                if (btn == null) continue;

                // Fallbacks pre-layout: top natural 261 (= bottom 16 + margin 5 + alto 240)
                float parked = 261f - 56f;
                float partial = 261f - 240f * 0.6f;

                if (geometryOk)
                {
                    float cardH = btn.resolvedStyle.height;
                    if (cardH > 1f)
                    {
                        // top natural = borde inferior de la vista - bottom:16 del grupo - margin:5 de la card
                        float naturalTop = _difficultyView.worldBound.yMax - 21f - cardH;
                        parked = panelHeight - 56f - naturalTop;
                        partial = panelHeight - cardH * 0.6f - naturalTop;
                    }
                }

                float target;
                if (narrow)
                    target = 0f; // panel estrecho: sin drawer (grupos estáticos por @media)
                else if (IsSelectedTimeCard(btn))
                    target = (btn == _hoveredTimeCard || btn == _focusedTimeCard) ? -3f : -2f; // selección arriba
                else if (btn == _hoveredTimeCard || btn == _focusedTimeCard)
                    target = partial - 3f; // hover/foco de ESTA tarjeta: sube ~60% con leve lift
                else
                    target = parked; // la hermana y el resto: aparcadas (no se descubren)

                btn.style.translate = new Translate(new Length(0f, LengthUnit.Pixel), new Length(target, LengthUnit.Pixel));
            }
        }

        private bool IsSelectedTimeCard(Button btn)
        {
            return (_selectedTimeControl == Core.TimeControl.None   && btn == _btnTimeNone)
                || (_selectedTimeControl == Core.TimeControl.Bullet && btn == _btnTimeBullet)
                || (_selectedTimeControl == Core.TimeControl.Blitz  && btn == _btnTimeBlitz)
                || (_selectedTimeControl == Core.TimeControl.Rapid  && btn == _btnTimeRapid);
        }

        private void OnDifficultySelected(DifficultyLevel selectedLevel)
        {
            Debug.Log($"[MainMenuController] Dificultad: {selectedLevel}, Tiempo: {_selectedTimeControl}");

            // Ocultar completamente la UI para dar paso al tablero
            if (_root != null)
                _root.style.display = DisplayStyle.None;

            if (GameManager.Instance != null)
            {
                // El modo de tiempo se guarda en el GameManager: es él quien arranca el
                // reloj al empezar, para que "Reiniciar partida" mantenga el modo elegido.
                GameManager.Instance.SetTimeControl(_selectedTimeControl);
                GameManager.Instance.StartGameWithDifficulty(selectedLevel);
            }
        }

        // ── SFX Sound Effects Registration ───────────────────────────────────

        private void RegisterSoundEffects()
        {
            if (_root == null) return;

            var allButtons = _root.Query<Button>().ToList();
            foreach (var btn in allButtons)
            {
                if (btn == null) continue;

                // Sonido de Hover (pasar cursor)
                btn.RegisterCallback<PointerEnterEvent>(_ =>
                {
                    WilderGambit.Audio.MusicManager.Instance?.PlayHoverSound();
                });

                // Sonido de Click o Volver
                bool isBackBtn = btn == _btnBackToMain || btn == _btnCloseSettings || btn == _btnCloseShop || btn == _btnCloseMusicSearch;
                btn.RegisterCallback<ClickEvent>(_ =>
                {
                    if (isBackBtn)
                        WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                    else
                        WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                });
            }
        }

        // ── Quit ─────────────────────────────────────────────────────────────

        private void OnQuitClicked()
        {
            Debug.Log("[MainMenuController] Saliendo del juego...");
#if UNITY_EDITOR
            UnityEditor.EditorApplication.isPlaying = false;
#else
            Application.Quit();
#endif
        }
    }
}
