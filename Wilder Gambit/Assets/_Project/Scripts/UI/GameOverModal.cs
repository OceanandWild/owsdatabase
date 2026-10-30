using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.InputSystem.UI;
using UnityEngine.EventSystems;
using UnityEngine.UI;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Modal flotante de Fin de Partida (Victoria, Derrota o Empate/Tablas).
    /// Rework: sin tarjeta central; overlay fuerte a pantalla completa,
    /// Victoria arriba y detalles en 2 tablas laterales
    /// (izquierda = principales/recompensa, derecha = secundarios/rendimiento).
    /// Cada sección está blindada: si una falla, pone placeholder en vez de
    /// tumbar todo el modal al fallback mínimo.
    /// </summary>
    public class GameOverModal : MonoBehaviour
    {
        public static GameOverModal Instance { get; private set; }

        private GameObject _modalContainer;
        private Canvas _canvas;
        private CanvasGroup _overlayGroup;
        private Image _overlayImage;
        private Action _onPlayAgainCallback;
        private Action _onMainMenuCallback;
        private bool _isShowing = false;

        private RectTransform _btnPlayAgainRect;
        private RectTransform _btnMainMenuRect;

        private const float OverlayAlpha = 1f;

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }
            Instance = this;
            DontDestroyOnLoad(gameObject);

            EnsureEventSystem();
            CreateModalUI();
        }

        private void EnsureEventSystem()
        {
            EventSystem es = FindAnyObjectByType<EventSystem>();
            if (es == null)
            {
                GameObject esObj = new GameObject("EventSystem");
                es = esObj.AddComponent<EventSystem>();
                DontDestroyOnLoad(esObj);
            }

            var standalone = es.GetComponent<StandaloneInputModule>();
            if (standalone != null)
            {
                Destroy(standalone);
            }

            var inputModule = es.GetComponent<InputSystemUIInputModule>();
            if (inputModule == null)
            {
                inputModule = es.gameObject.AddComponent<InputSystemUIInputModule>();
            }
            inputModule.AssignDefaultActions();
        }

        private void CreateModalUI()
        {
            GameObject canvasObj = new GameObject("GameOver_Canvas");
            canvasObj.transform.SetParent(transform);
            _canvas = canvasObj.AddComponent<Canvas>();
            _canvas.renderMode = RenderMode.ScreenSpaceOverlay;
            _canvas.sortingOrder = 1000;

            CanvasScaler scaler = canvasObj.AddComponent<CanvasScaler>();
            scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920, 1080);
            UiResponsive.ApplyCanvasScaler(scaler);

            canvasObj.AddComponent<GraphicRaycaster>();

            _modalContainer = new GameObject("GameOverContainer");
            _modalContainer.transform.SetParent(canvasObj.transform, false);

            RectTransform containerRect = _modalContainer.AddComponent<RectTransform>();
            containerRect.anchorMin = Vector2.zero;
            containerRect.anchorMax = Vector2.one;
            containerRect.sizeDelta = Vector2.zero;

            Image bgOverlay = _modalContainer.AddComponent<Image>();
            bgOverlay.color = new Color(0f, 0f, 0f, OverlayAlpha);
            try
            {
                Sprite overlaySprite = VictoryAssets.StrongOverlay;
                if (overlaySprite != null)
                {
                    bgOverlay.sprite = overlaySprite;
                    bgOverlay.type = Image.Type.Simple;
                    bgOverlay.preserveAspect = false;
                    bgOverlay.color = Color.white;
                }
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Overlay asset falló, se usa negro pleno: {ex}");
            }
            _overlayImage = bgOverlay;

            _overlayGroup = _modalContainer.AddComponent<CanvasGroup>();

            _modalContainer.SetActive(false);
        }

        public void Show(string title, string subtitle, Color titleColor, Action onPlayAgain, Action onMainMenu)
        {
            Show(title, subtitle, titleColor, onPlayAgain, onMainMenu, null);
        }

        public void Show(string title, string subtitle, Color titleColor, Action onPlayAgain, Action onMainMenu, GameAnalytics analytics)
        {
            Show(title, subtitle, titleColor, onPlayAgain, onMainMenu, analytics, 0, 0);
        }

        public void Show(string title, string subtitle, Color titleColor, Action onPlayAgain, Action onMainMenu, GameAnalytics analytics, int rewardGambits, int balanceGambits)
        {
            Show(title, subtitle, titleColor, onPlayAgain, onMainMenu, analytics, rewardGambits, balanceGambits, null);
        }

        public void Show(string title, string subtitle, Color titleColor, Action onPlayAgain, Action onMainMenu, GameAnalytics analytics, int rewardGambits, int balanceGambits, WilderGambit.Core.MatchBreakdown breakdown)
        {
            if (_isShowing)
            {
                if (_modalContainer == null || !_modalContainer.activeSelf)
                {
                    Debug.LogWarning("[GameOverModal] Estado atascado detectado: se reintenta mostrar.");
                    _isShowing = false;
                }
                else return;
            }
            _isShowing = true;
            Debug.Log($"[GameOverModal] Show: {title} | {subtitle} | reward={rewardGambits} balance={balanceGambits} analytics={analytics != null} breakdownLines={(breakdown != null ? breakdown.lines.Count : 0)}");
            try
            {
                ShowInner(title, subtitle, titleColor, onPlayAgain, onMainMenu, analytics, rewardGambits, balanceGambits, breakdown);
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Falló el layout reworkeado, se usa fallback mínimo: {ex}");
                try { BuildFallbackModal(title, subtitle, titleColor, onPlayAgain, onMainMenu); }
                catch (Exception ex2)
                {
                    Debug.LogError($"[GameOverModal] Falló incluso el fallback: {ex2}");
                    _isShowing = false;
                }
            }
        }

        private void ShowInner(string title, string subtitle, Color titleColor, Action onPlayAgain, Action onMainMenu, GameAnalytics analytics, int rewardGambits, int balanceGambits, WilderGambit.Core.MatchBreakdown breakdown)
        {
            _onPlayAgainCallback = onPlayAgain;
            _onMainMenuCallback = onMainMenu;

            EnsureEventSystem();
            if (_modalContainer == null) CreateModalUI();

            Transform existing = _modalContainer.transform.Find("CardBox");
            if (existing != null) Destroy(existing.gameObject);

            bool hasAnalytics = analytics != null;
            float accuracy = 0f;
            int brilliant = 0, great = 0, good = 0, inaccuracies = 0, mistakes = 0, blunders = 0;
            float avgLoss = 0f;
            if (hasAnalytics)
            {
                try
                {
                    analytics.ComputeStats();
                    accuracy = analytics.Accuracy;
                    brilliant = analytics.BrilliantCount;
                    great = analytics.GreatCount;
                    good = analytics.GoodCount;
                    inaccuracies = analytics.InaccuracyCount;
                    mistakes = analytics.MistakeCount;
                    blunders = analytics.BlunderCount;
                    avgLoss = analytics.AvgCentipawnLoss;
                }
                catch (Exception ex)
                {
                    Debug.LogError($"[GameOverModal] Analytics falló, se oculta esa tabla: {ex}");
                    hasAnalytics = false;
                }
            }

            bool hasReward = rewardGambits > 0;
            int breakdownLines = breakdown != null ? breakdown.lines.Count : 0;
            bool showBreakdown = hasReward && breakdownLines > 0;
            bool tooShort = breakdown != null && breakdown.TooShort;

            string outcomeBadge = OutcomeBadgeText(title);
            string cleanTitle = CleanTitle(title);

            // Raíz a pantalla completa (se sigue llamando CardBox por compatibilidad
            // con la limpieza de la tarjeta previa). Sin fondo propio: el fondo es
            // el overlay fuerte del contenedor.
            GameObject root = new GameObject("CardBox");
            root.transform.SetParent(_modalContainer.transform, false);
            RectTransform rootRect = root.AddComponent<RectTransform>();
            rootRect.anchorMin = Vector2.zero;
            rootRect.anchorMax = Vector2.one;
            rootRect.offsetMin = Vector2.zero;
            rootRect.offsetMax = Vector2.zero;

            VerticalLayoutGroup rootVlg = root.AddComponent<VerticalLayoutGroup>();
            rootVlg.spacing = 20;
            // Un poco más de ancho útil para que ambos títulos respiren y el
            // RENDIMIENTO (PNG muy apaisado, limitado por ancho) gane tamaño.
            rootVlg.padding = new RectOffset(90, 90, 46, 40);
            rootVlg.childAlignment = TextAnchor.UpperCenter;
            rootVlg.childControlWidth = true;
            rootVlg.childControlHeight = true;
            rootVlg.childForceExpandWidth = true;
            rootVlg.childForceExpandHeight = false;

            // ── VICTORIA ARRIBA (banner diseñado si hay asset, texto si no) ──
            bool isVictoryBanner = (title ?? "").ToUpperInvariant().Contains("VICTORIA");
            Sprite victoryBanner = null;
            try { victoryBanner = VictoryAssets.VictoryText; } catch { }
            // Con desglose de recompensa hay que mostrar filas etiqueta/monto en el
            // panel izq: si el header es muy alto, esas filas desbordan el panel.
            // Banner compacto cuando hay muchas filas que mostrar.
            bool compactHeader = showBreakdown && breakdownLines >= 3;
            float headerH = (isVictoryBanner && victoryBanner != null)
                ? (compactHeader ? 140f : 190f)
                : 148f;
            try
            {
                GameObject header = new GameObject("ResultHeader");
                header.transform.SetParent(root.transform, false);
                LayoutElement headerLE = header.AddComponent<LayoutElement>();
                headerLE.preferredHeight = headerH;
                headerLE.flexibleWidth = 1;
                VerticalLayoutGroup headerVlg = header.AddComponent<VerticalLayoutGroup>();
                headerVlg.spacing = 6;
                headerVlg.childAlignment = TextAnchor.MiddleCenter;
                headerVlg.childControlWidth = true;
                headerVlg.childControlHeight = true;
                headerVlg.childForceExpandWidth = true;
                headerVlg.childForceExpandHeight = false;

                if (isVictoryBanner && victoryBanner != null)
                {
                    GameObject bannerObj = new GameObject("VictoryBanner");
                    bannerObj.transform.SetParent(header.transform, false);
                    LayoutElement bannerLE = bannerObj.AddComponent<LayoutElement>();
                    // El banner es un PNG apaisado: se dimensiona por ALTURA y el
                    // ancho sale de su proporción real (no del hueco disponible),
                    // así no crece con pantallas anchas ni invade el subtítulo.
                    float bannerH = compactHeader ? 100f : 150f;
                    bannerLE.preferredHeight = bannerH;
                    bannerLE.preferredWidth = SpriteWidthForHeight(victoryBanner, bannerH, 3.06f);
                    bannerLE.flexibleWidth = 0;
                    Image bannerImg = bannerObj.AddComponent<Image>();
                    bannerImg.sprite = victoryBanner;
                    bannerImg.preserveAspect = true;
                    bannerImg.color = Color.white;
                }
                else
                {
                    GameObject badgeObj = new GameObject("OutcomeBadge");
                    badgeObj.transform.SetParent(header.transform, false);
                    LayoutElement badgeLE = badgeObj.AddComponent<LayoutElement>();
                    badgeLE.preferredHeight = 26;
                    badgeLE.preferredWidth = 300;
                    Image badgeBg = badgeObj.AddComponent<Image>();
                    badgeBg.color = new Color(titleColor.r, titleColor.g, titleColor.b, 0.18f);
                    Text badgeText = badgeObj.AddComponent<Text>();
                    badgeText.text = outcomeBadge;
                    badgeText.fontSize = 13;
                    badgeText.fontStyle = FontStyle.Bold;
                    badgeText.alignment = TextAnchor.MiddleCenter;
                    badgeText.color = titleColor;
                    badgeText.horizontalOverflow = HorizontalWrapMode.Overflow;
                    badgeText.verticalOverflow = VerticalWrapMode.Overflow;
                    badgeText.font = ResolveFont(13);

                    GameObject titleObj = new GameObject("Title");
                    titleObj.transform.SetParent(header.transform, false);
                    LayoutElement titleLE = titleObj.AddComponent<LayoutElement>();
                    titleLE.preferredHeight = 72;
                    titleLE.flexibleWidth = 1;
                    Text titleText = titleObj.AddComponent<Text>();
                    titleText.text = cleanTitle;
                    titleText.fontSize = 60;
                    titleText.fontStyle = FontStyle.Bold;
                    titleText.alignment = TextAnchor.MiddleCenter;
                    titleText.color = titleColor;
                    titleText.horizontalOverflow = HorizontalWrapMode.Overflow;
                    titleText.verticalOverflow = VerticalWrapMode.Overflow;
                    titleText.font = ResolveFont(60);
                }

                GameObject subtitleObj = new GameObject("Subtitle");
                subtitleObj.transform.SetParent(header.transform, false);
                LayoutElement subtitleLE = subtitleObj.AddComponent<LayoutElement>();
                subtitleLE.preferredHeight = 28;
                subtitleLE.flexibleWidth = 1;
                Text subtitleText = subtitleObj.AddComponent<Text>();
                subtitleText.text = subtitle;
                subtitleText.fontSize = 17;
                subtitleText.alignment = TextAnchor.MiddleCenter;
                subtitleText.color = new Color(0.86f, 0.89f, 0.93f);
                subtitleText.horizontalOverflow = HorizontalWrapMode.Wrap;
                subtitleText.verticalOverflow = VerticalWrapMode.Overflow;
                subtitleText.font = ResolveFont(17);
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Header falló: {ex}");
            }

            // ── Divider dorado diseñado ──
            try
            {
                Sprite dividerSprite = VictoryAssets.GoldenDivider;
                if (dividerSprite != null)
                {
                    GameObject divObj = new GameObject("GoldenDivider");
                    divObj.transform.SetParent(root.transform, false);
                    LayoutElement divLE = divObj.AddComponent<LayoutElement>();
                    divLE.preferredHeight = 64;
                    divLE.flexibleWidth = 1;
                    Image divImg = divObj.AddComponent<Image>();
                    divImg.sprite = dividerSprite;
                    divImg.preserveAspect = true;
                    divImg.color = Color.white;
                }
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Divider asset falló: {ex}");
            }

            // ── TABLAS A LOS 2 LADOS ──
            GameObject columns = new GameObject("DetailColumns");
            columns.transform.SetParent(root.transform, false);
            LayoutElement columnsLE = columns.AddComponent<LayoutElement>();
            columnsLE.flexibleWidth = 1;
            columnsLE.flexibleHeight = 1;
            // Altura mínima para que el 9-slice de los marcos (bandas 210+210)
            // nunca se solape: por debajo de ~430 las esquinas colapsarían.
            columnsLE.minHeight = 430;
            HorizontalLayoutGroup columnsLayout = columns.AddComponent<HorizontalLayoutGroup>();
            columnsLayout.spacing = 24;
            columnsLayout.padding = new RectOffset(0, 0, 0, 0);
            columnsLayout.childAlignment = TextAnchor.UpperCenter;
            columnsLayout.childControlWidth = true;
            columnsLayout.childControlHeight = true;
            columnsLayout.childForceExpandWidth = true;
            columnsLayout.childForceExpandHeight = true;

            // IZQUIERDA = principales (recompensa + desglose)
            try
            {
                // Contenedor diseñado calado (solo marco dorado, resto transparente):
                // el texto RECOMPENSA flota sin ningún fondo detrás, sobre el humo.
                Sprite leftBg = null, leftHeader = null;
                try { leftBg = VictoryAssets.LeftContainer; leftHeader = VictoryAssets.RewardText; } catch { }
                GameObject left = MakeTablePanel(columns.transform, "MainTable", "RECOMPENSA", leftBg, leftHeader,
                    new Color(0.96f, 0.79f, 0.36f, 0.45f));
                if (hasReward)
                {
                    GameObject hero = new GameObject("RewardHero");
                    hero.transform.SetParent(left.transform, false);
                    LayoutElement heroLE = hero.AddComponent<LayoutElement>();
                    heroLE.preferredHeight = 112;
                    heroLE.flexibleWidth = 1;
                    // Franja cálida sutil detrás del botín: da jerarquía al panel
                    // izquierdo sin competir con el número dorado. Apenas un velo
                    // (0.10), sin bordes ni píldora: el título sigue flotando libre.
                    Image heroBg = hero.AddComponent<Image>();
                    heroBg.color = new Color(1f, 0.84f, 0.34f, 0.10f);
                    HorizontalLayoutGroup heroLayout = hero.AddComponent<HorizontalLayoutGroup>();
                    heroLayout.spacing = 18;
                    heroLayout.padding = new RectOffset(18, 18, 12, 12);
                    heroLayout.childAlignment = TextAnchor.MiddleLeft;
                    heroLayout.childControlWidth = true;
                    heroLayout.childControlHeight = true;
                    heroLayout.childForceExpandWidth = false;
                    heroLayout.childForceExpandHeight = true;

                    try
                    {
                        Sprite coin = GambitIcon.Sprite;
                        if (coin != null)
                        {
                            GameObject iconObj = new GameObject("GambitIcon");
                            iconObj.transform.SetParent(hero.transform, false);
                            Image iconImg = iconObj.AddComponent<Image>();
                            iconImg.sprite = coin;
                            iconImg.preserveAspect = true;
                            LayoutElement iconLE = iconObj.AddComponent<LayoutElement>();
                            iconLE.preferredWidth = 72;
                            iconLE.preferredHeight = 72;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.LogError($"[GameOverModal] Icono gambits falló: {ex}");
                    }

                    GameObject texts = new GameObject("RewardTexts");
                    texts.transform.SetParent(hero.transform, false);
                    LayoutElement textsLE = texts.AddComponent<LayoutElement>();
                    textsLE.flexibleWidth = 1;
                    textsLE.preferredHeight = 92;
                    VerticalLayoutGroup textsVlg = texts.AddComponent<VerticalLayoutGroup>();
                    textsVlg.spacing = 3;
                    textsVlg.childAlignment = TextAnchor.MiddleLeft;
                    textsVlg.childControlWidth = true;
                    textsVlg.childControlHeight = true;
                    textsVlg.childForceExpandWidth = true;
                    textsVlg.childForceExpandHeight = false;

                    GameObject rewardObj = new GameObject("GambitReward");
                    rewardObj.transform.SetParent(texts.transform, false);
                    LayoutElement rewardLE = rewardObj.AddComponent<LayoutElement>();
                    rewardLE.preferredHeight = 58;
                    rewardLE.flexibleWidth = 1;
                    Text rewardText = rewardObj.AddComponent<Text>();
                    rewardText.text = $"+{rewardGambits:N0} GAMBITS";
                    rewardText.fontSize = 46;
                    rewardText.fontStyle = FontStyle.Bold;
                    rewardText.alignment = TextAnchor.MiddleLeft;
                    rewardText.color = new Color(1f, 0.84f, 0.34f);
                    rewardText.horizontalOverflow = HorizontalWrapMode.Overflow;
                    rewardText.verticalOverflow = VerticalWrapMode.Overflow;
                    rewardText.font = ResolveFont(46);

                    GameObject balanceObj = new GameObject("GambitBalance");
                    balanceObj.transform.SetParent(texts.transform, false);
                    LayoutElement balanceLE = balanceObj.AddComponent<LayoutElement>();
                    balanceLE.preferredHeight = 24;
                    balanceLE.flexibleWidth = 1;
                    Text balanceText = balanceObj.AddComponent<Text>();
                    balanceText.text = $"Saldo: {balanceGambits:N0} Gambits";
                    balanceText.fontSize = 17;
                    balanceText.alignment = TextAnchor.MiddleLeft;
                    balanceText.color = new Color(0.70f, 0.75f, 0.83f);
                    balanceText.horizontalOverflow = HorizontalWrapMode.Overflow;
                    balanceText.verticalOverflow = VerticalWrapMode.Overflow;
                    balanceText.font = ResolveFont(17);

                    if (showBreakdown)
                    {
                        AddThinDivider(left.transform);
                        foreach (var line in breakdown.lines)
                        {
                            try { AddBreakdownRow(left.transform, line.label, Mathf.RoundToInt(line.amount)); }
                            catch (Exception ex) { Debug.LogError($"[GameOverModal] Fila desglose falló: {ex}"); }
                        }
                        if (breakdown.Limited)
                        {
                            string reason = string.IsNullOrEmpty(breakdown.LimitReason) ? "ritmo diario" : breakdown.LimitReason;
                            AddNote(left.transform, $"Tope aplicado: {reason}. Vuelve mañana para cobrar al 100%.");
                        }
                    }
                }
                else if (tooShort)
                {
                    int minTurns = 8;
                    try { minTurns = WilderGambit.Core.GambitEconomyConfig.Instance.minTurnsToReward; } catch { }
                    AddNote(left.transform, $"Sin recompensa: la partida duró menos de {minTurns} jugadas.");
                }
                else if (breakdown != null && breakdown.Limited)
                {
                    // Ganaste pero un tope diario dejó el cobro en 0: decirlo claro
                    // en vez del genérico "Sin recompensa", que confunde al jugador.
                    string reason = string.IsNullOrEmpty(breakdown.LimitReason) ? "límite diario" : breakdown.LimitReason;
                    AddNote(left.transform, $"Cobro en 0: {reason}.");
                    AddNote(left.transform, "Volvé mañana para seguir cobrando al 100%.");
                }
                else
                {
                    AddNote(left.transform, "Sin recompensa en esta partida.");
                }
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Tabla principal falló: {ex}");
            }

            // DERECHA = secundarios (rendimiento/analytics)
            try
            {
                // RightContainer plateado calado: pareja del izquierdo, el título
                // RENDIMIENTO flota centrado y sin nada detrás.
                Sprite rightBg = null, rightHeader = null;
                try { rightBg = VictoryAssets.RightContainer; rightHeader = VictoryAssets.PerformanceText; } catch { }
                // 43 para igualar la ALTURA DE TINTA con RECOMPENSA (46): este PNG tiene 89%
                // de tinta contra 84% del otro, asi que necesita un poco menos de
                // alto de caja para que las letras queden exactamente iguales.
                // Inset 0: ahora ambos titulos miden ~360 de ancho y comparten
                // centrado. topPadding 100 compensa el marco derecho, cuyo arte
                // tiene la linea superior 32px mas abajo (y=74 vs y=42 del
                // izquierdo): sin esto el titulo se apoiaba sobre la filigrana.
                GameObject right = MakeTablePanel(columns.transform, "SideTable", "RENDIMIENTO", rightBg, rightHeader,
                    new Color(0.78f, 0.84f, 0.96f, 0.30f), 0f, 43f, 100f);
                if (hasAnalytics)
                {
                    GameObject accObj = new GameObject("AccuracyHeader");
                    accObj.transform.SetParent(right.transform, false);
                    LayoutElement accLE = accObj.AddComponent<LayoutElement>();
                    accLE.preferredHeight = 44;
                    accLE.flexibleWidth = 1;
                    Text accText = accObj.AddComponent<Text>();
                    Color accColor = accuracy >= 80f ? new Color(0.3f, 0.85f, 0.4f) :
                                     accuracy >= 60f ? new Color(1f, 0.85f, 0.2f) :
                                                     new Color(0.95f, 0.35f, 0.3f);
                    accText.text = $"Precisión: {accuracy:F1}%";
                    accText.fontSize = 28;
                    accText.fontStyle = FontStyle.Bold;
                    accText.alignment = TextAnchor.MiddleCenter;
                    accText.color = accColor;
                    accText.horizontalOverflow = HorizontalWrapMode.Overflow;
                    accText.verticalOverflow = VerticalWrapMode.Overflow;
                    accText.font = ResolveFont(28);

                    GameObject statsGrid = new GameObject("StatsGrid");
                    statsGrid.transform.SetParent(right.transform, false);
                    LayoutElement gridLE = statsGrid.AddComponent<LayoutElement>();
                    gridLE.preferredHeight = 190;
                    gridLE.flexibleWidth = 1;
                    GridLayoutGroup glg = statsGrid.AddComponent<GridLayoutGroup>();
                    glg.cellSize = new Vector2(200, 58);
                    glg.spacing = new Vector2(10, 10);
                    glg.constraint = GridLayoutGroup.Constraint.FixedColumnCount;
                    glg.constraintCount = 2;
                    glg.childAlignment = TextAnchor.MiddleCenter;

                    CreateStatChip(statsGrid.transform, "BRILLANTES", brilliant, new Color(0.35f, 0.85f, 1f));
                    CreateStatChip(statsGrid.transform, "GRANDES", great, new Color(0.3f, 0.85f, 0.4f));
                    CreateStatChip(statsGrid.transform, "BUENOS", good, new Color(0.75f, 0.78f, 0.82f));
                    CreateStatChip(statsGrid.transform, "INEXACTITUDES", inaccuracies, new Color(1f, 0.75f, 0.2f));
                    CreateStatChip(statsGrid.transform, "ERRORES", mistakes, new Color(0.95f, 0.55f, 0.2f));
                    CreateStatChip(statsGrid.transform, "GRAVES", blunders, new Color(0.95f, 0.35f, 0.35f));

                    GameObject lossObj = new GameObject("CentipawnLoss");
                    lossObj.transform.SetParent(right.transform, false);
                    LayoutElement lossLE = lossObj.AddComponent<LayoutElement>();
                    lossLE.preferredHeight = 26;
                    lossLE.flexibleWidth = 1;
                    Text lossText = lossObj.AddComponent<Text>();
                    lossText.text = $"Pérdida promedio: {avgLoss:F0} centipawns";
                    lossText.fontSize = 13;
                    lossText.alignment = TextAnchor.MiddleCenter;
                    lossText.color = new Color(0.65f, 0.68f, 0.73f);
                    lossText.horizontalOverflow = HorizontalWrapMode.Overflow;
                    lossText.verticalOverflow = VerticalWrapMode.Overflow;
                    lossText.font = ResolveFont(13);
                }
                else
                {
                    AddNote(right.transform, "Sin análisis de jugadas en esta partida.");
                    AddNote(right.transform, "Saldo y bonos a la izquierda; aquí verás precisión y errores cuando haya telemetría.");
                    // Resumen de la partida para no dejar el panel derecho vacío:
                    // muestra el desglose completo de la recompensa en vez de 2 notas.
                    if (hasReward && breakdown != null && breakdown.lines.Count > 0)
                    {
                        AddThinDivider(right.transform);
                        foreach (var line in breakdown.lines)
                        {
                            try { AddBreakdownRow(right.transform, line.label, Mathf.RoundToInt(line.amount)); }
                            catch (Exception ex) { Debug.LogError($"[GameOverModal] Fila resumen falló: {ex}"); }
                        }
                        if (breakdown.Limited)
                        {
                            string reason2 = string.IsNullOrEmpty(breakdown.LimitReason) ? "ritmo diario" : breakdown.LimitReason;
                            AddNote(right.transform, $"Tope aplicado: {reason2}. Vuelve mañana para cobrar al 100%.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Tabla secundaria falló: {ex}");
            }

            // ── CTAs ──
            try
            {
                GameObject buttonsRow = new GameObject("ButtonsRow");
                buttonsRow.transform.SetParent(root.transform, false);
                LayoutElement rowLE = buttonsRow.AddComponent<LayoutElement>();
                rowLE.preferredHeight = 62;
                rowLE.flexibleWidth = 1;
                HorizontalLayoutGroup hlg = buttonsRow.AddComponent<HorizontalLayoutGroup>();
                hlg.spacing = 18;
                hlg.childAlignment = TextAnchor.MiddleCenter;
                hlg.childControlWidth = false;
                hlg.childControlHeight = true;
                hlg.childForceExpandWidth = false;
                hlg.childForceExpandHeight = false;

                Sprite majorSprite = null, secondarySprite = null;
                try { majorSprite = VictoryAssets.MajorButton; secondarySprite = VictoryAssets.SecondaryButton; } catch { }
                _btnPlayAgainRect = CreateActionButton(buttonsRow.transform, "JUGAR DE NUEVO", new Color(0.16f, 0.55f, 0.30f), 300, OnPlayAgainClicked, majorSprite);
                // Contenedor plateado claro -> texto en azul casi negro para que lea.
                _btnMainMenuRect = CreateActionButton(buttonsRow.transform, "MENÚ PRINCIPAL", new Color(0.22f, 0.30f, 0.44f), 300, OnMainMenuClicked, secondarySprite, new Color(0.09f, 0.12f, 0.17f), isBack: true);
            }
            catch (Exception ex)
            {
                Debug.LogError($"[GameOverModal] Botones fallaron: {ex}");
                throw;
            }

            _modalContainer.SetActive(true);
            StartCoroutine(AnimateShow(root.transform));
        }

        private GameObject MakeTablePanel(Transform parent, string name, string headerTitle, Sprite bgSprite = null, Sprite headerSprite = null, Color? dividerColor = null, float headerSideInset = 0f, float headerHeight = 46f, float topPadding = 68f)
        {
            GameObject panel = new GameObject(name);
            panel.transform.SetParent(parent, false);
            LayoutElement panelLE = panel.AddComponent<LayoutElement>();
            panelLE.flexibleWidth = 1;
            panelLE.flexibleHeight = 1;
            Image panelBg = panel.AddComponent<Image>();
            if (bgSprite != null)
            {
                panelBg.sprite = bgSprite;
                panelBg.type = Image.Type.Sliced;
                panelBg.fillCenter = true;
                panelBg.color = Color.white;
            }
            else
            {
                // Fondo procedural uniforme y casi invisible (solo si falta el sprite):
                // velo apenas perceptible para dar estructura, SIN banda ni píldora
                // detrás del título.
                panelBg.color = new Color(1f, 1f, 1f, 0.065f);
            }
            VerticalLayoutGroup panelVlg = panel.AddComponent<VerticalLayoutGroup>();
            panelVlg.spacing = 10;
            // Respiro amplio para que el contenido quede DENTRO del marco diseñado.
            // topPadding se ajusta por panel porque cada marco es un arte aparte con
            // su filigrana superior a una altura distinta (derecha 32px mas abajo).
            panelVlg.padding = new RectOffset(60, 60, Mathf.RoundToInt(topPadding), 60);
            panelVlg.childAlignment = TextAnchor.UpperCenter;
            panelVlg.childControlWidth = true;
            panelVlg.childControlHeight = true;
            panelVlg.childForceExpandWidth = true;
            panelVlg.childForceExpandHeight = false;

            if (headerSprite != null)
            {
                // Título del panel: sprite de texto (PNG calado, sin caja) escalado
                // a un alto contenido y centrado. Sin placa de fondo detrás: el texto
                // flota sobre el interior del marco (transparente, se ve el humo).
                // headerSideInset angosta solo la imagen (ej. RENDIMIENTO, muy
                // apaisado) sin tocar el resto del contenido.
                GameObject headerRowObj = new GameObject("TableHeaderRow");
                headerRowObj.transform.SetParent(panel.transform, false);
                LayoutElement headerRowLE = headerRowObj.AddComponent<LayoutElement>();
                // Alto FIJO y elegido a mano: define el tamaño real del título.
                // Antes crecía con el ancho del panel (preserveAspect rellenaba el
                // hueco) y los rótulos quedaban enormes, cruzando las filigranas.
                headerRowLE.preferredHeight = headerHeight;
                headerRowLE.flexibleWidth = 1;
                HorizontalLayoutGroup headerRowHlg = headerRowObj.AddComponent<HorizontalLayoutGroup>();
                int inset = Mathf.RoundToInt(headerSideInset);
                headerRowHlg.padding = new RectOffset(inset, inset, 0, 0);
                headerRowHlg.spacing = 0;
                headerRowHlg.childAlignment = TextAnchor.MiddleCenter;
                headerRowHlg.childControlWidth = true;
                headerRowHlg.childControlHeight = true;
                // Esta fila tiene UN solo hijo (la imagen): sin forzar expansión no
                // se estira y respeta su tamaño natural.
                headerRowHlg.childForceExpandWidth = false;
                headerRowHlg.childForceExpandHeight = false;

                GameObject headerImgObj = new GameObject("TableHeaderImage");
                headerImgObj.transform.SetParent(headerRowObj.transform, false);
                LayoutElement headerImgLE = headerImgObj.AddComponent<LayoutElement>();
                // Ancho derivado de la proporción real del PNG a esa altura, para
                // que RECOMPENSA (~7.7:1) y RENDIMIENTO (~12:1) conserven su
                // diseño sin deformarse ni desbordar el marco.
                headerImgLE.preferredHeight = headerHeight;
                headerImgLE.preferredWidth = SpriteWidthForHeight(headerSprite, headerHeight, 8f);
                headerImgLE.flexibleWidth = 0;
                headerImgLE.flexibleHeight = 0;
                Image headerImg = headerImgObj.AddComponent<Image>();
                headerImg.sprite = headerSprite;
                headerImg.preserveAspect = true;
                headerImg.color = Color.white;
            }
            else
            {
                GameObject titleObj = new GameObject("TableTitle");
                titleObj.transform.SetParent(panel.transform, false);
                LayoutElement titleLE = titleObj.AddComponent<LayoutElement>();
                titleLE.preferredHeight = headerHeight;
                titleLE.flexibleWidth = 1;
                Text titleText = titleObj.AddComponent<Text>();
                titleText.text = headerTitle;
                titleText.fontSize = 25;
                titleText.fontStyle = FontStyle.Bold;
                titleText.alignment = TextAnchor.MiddleCenter;
                titleText.color = new Color(0.80f, 0.84f, 0.91f);
                titleText.horizontalOverflow = HorizontalWrapMode.Overflow;
                titleText.verticalOverflow = VerticalWrapMode.Overflow;
                titleText.font = ResolveFont(25);
            }

            GameObject sep = new GameObject("TableDivider");
            sep.transform.SetParent(panel.transform, false);
            LayoutElement sepLE = sep.AddComponent<LayoutElement>();
            sepLE.preferredHeight = 2;
            sepLE.flexibleWidth = 1;
            Image sepImg = sep.AddComponent<Image>();
            sepImg.color = dividerColor ?? new Color(1f, 1f, 1f, 0.12f);

            return panel;
        }

        private void AddThinDivider(Transform parent)
        {
            GameObject sep = new GameObject("Separator");
            sep.transform.SetParent(parent, false);
            LayoutElement sepLE = sep.AddComponent<LayoutElement>();
            sepLE.preferredHeight = 2;
            sepLE.flexibleWidth = 1;
            Image sepImg = sep.AddComponent<Image>();
            sepImg.color = new Color(1f, 1f, 1f, 0.14f);
        }

        private void AddNote(Transform parent, string text)
        {
            GameObject noteObj = new GameObject("Note");
            noteObj.transform.SetParent(parent, false);
            LayoutElement noteLE = noteObj.AddComponent<LayoutElement>();
            noteLE.preferredHeight = 32;
            noteLE.flexibleWidth = 1;
            Text noteText = noteObj.AddComponent<Text>();
            noteText.text = text;
            noteText.fontSize = 14;
            noteText.alignment = TextAnchor.MiddleCenter;
            noteText.color = new Color(0.74f, 0.78f, 0.85f);
            noteText.horizontalOverflow = HorizontalWrapMode.Wrap;
            noteText.verticalOverflow = VerticalWrapMode.Overflow;
            noteText.font = ResolveFont(14);
        }

        private void AddBreakdownRow(Transform parent, string label, int amount)
        {
            GameObject row = new GameObject("BreakdownRow");
            row.transform.SetParent(parent, false);
            LayoutElement rowLE = row.AddComponent<LayoutElement>();
            rowLE.preferredHeight = 28;
            rowLE.flexibleWidth = 1;
            HorizontalLayoutGroup rowLayout = row.AddComponent<HorizontalLayoutGroup>();
            rowLayout.spacing = 12;
            rowLayout.padding = new RectOffset(16, 16, 2, 2);
            rowLayout.childAlignment = TextAnchor.MiddleCenter;
            rowLayout.childControlWidth = true;
            rowLayout.childControlHeight = true;
            rowLayout.childForceExpandWidth = false;
            rowLayout.childForceExpandHeight = false;

            GameObject labelObj = new GameObject("Label");
            labelObj.transform.SetParent(row.transform, false);
            LayoutElement labelLE = labelObj.AddComponent<LayoutElement>();
            labelLE.flexibleWidth = 1;
            labelLE.preferredHeight = 24;
            Text labelText = labelObj.AddComponent<Text>();
            labelText.text = string.IsNullOrEmpty(label) ? "—" : label;
            labelText.fontSize = 15;
            labelText.alignment = TextAnchor.MiddleLeft;
            labelText.color = new Color(0.87f, 0.90f, 0.95f);
            labelText.horizontalOverflow = HorizontalWrapMode.Overflow;
            labelText.verticalOverflow = VerticalWrapMode.Overflow;
            labelText.font = ResolveFont(15);

            GameObject amountObj = new GameObject("Amount");
            amountObj.transform.SetParent(row.transform, false);
            LayoutElement amountLE = amountObj.AddComponent<LayoutElement>();
            amountLE.preferredWidth = 104;
            amountLE.preferredHeight = 24;
            amountLE.flexibleWidth = 0;
            Text amountText = amountObj.AddComponent<Text>();
            amountText.text = (amount >= 0 ? "+" : "") + amount.ToString("N0");
            amountText.fontSize = 14;
            amountText.fontStyle = FontStyle.Bold;
            amountText.alignment = TextAnchor.MiddleRight;
            amountText.color = amount >= 0 ? new Color(0.38f, 0.87f, 0.48f) : new Color(0.95f, 0.45f, 0.45f);
            amountText.horizontalOverflow = HorizontalWrapMode.Overflow;
            amountText.verticalOverflow = VerticalWrapMode.Overflow;
            amountText.font = ResolveFont(14);
        }

        private void CreateStatChip(Transform parent, string label, int value, Color valueColor)
        {
            GameObject chip = new GameObject("StatChip");
            chip.transform.SetParent(parent, false);
            Image chipBg = chip.AddComponent<Image>();
            chipBg.color = new Color(1f, 1f, 1f, 0.05f);
            VerticalLayoutGroup chipVlg = chip.AddComponent<VerticalLayoutGroup>();
            chipVlg.spacing = 0;
            chipVlg.padding = new RectOffset(4, 4, 6, 6);
            chipVlg.childAlignment = TextAnchor.MiddleCenter;
            chipVlg.childControlWidth = true;
            chipVlg.childControlHeight = true;
            chipVlg.childForceExpandWidth = true;
            chipVlg.childForceExpandHeight = false;

            GameObject labelObj = new GameObject("ChipLabel");
            labelObj.transform.SetParent(chip.transform, false);
            Text labelTxt = labelObj.AddComponent<Text>();
            labelTxt.text = label;
            labelTxt.fontSize = 10;
            labelTxt.fontStyle = FontStyle.Bold;
            labelTxt.alignment = TextAnchor.MiddleCenter;
            labelTxt.color = new Color(0.58f, 0.62f, 0.70f);
            labelTxt.horizontalOverflow = HorizontalWrapMode.Overflow;
            labelTxt.verticalOverflow = VerticalWrapMode.Overflow;
            labelTxt.font = ResolveFont(10);

            GameObject valueObj = new GameObject("ChipValue");
            valueObj.transform.SetParent(chip.transform, false);
            Text valueTxt = valueObj.AddComponent<Text>();
            valueTxt.text = value.ToString("N0");
            valueTxt.fontSize = 18;
            valueTxt.fontStyle = FontStyle.Bold;
            valueTxt.alignment = TextAnchor.MiddleCenter;
            valueTxt.color = valueColor;
            valueTxt.horizontalOverflow = HorizontalWrapMode.Overflow;
            valueTxt.verticalOverflow = VerticalWrapMode.Overflow;
            valueTxt.font = ResolveFont(18);
        }

        private RectTransform CreateActionButton(Transform parent, string label, Color bgColor, Action onClick, bool isBack = false)
        {
            return CreateActionButton(parent, label, bgColor, 240, onClick, null, null, isBack);
        }

        private RectTransform CreateActionButton(Transform parent, string label, Color bgColor, float width, Action onClick, Sprite bgSprite = null, Color? textColor = null, bool isBack = false)
        {
            GameObject btnObj = new GameObject("BtnAction");
            btnObj.transform.SetParent(parent, false);

            RectTransform btnRect = btnObj.AddComponent<RectTransform>();
            btnRect.sizeDelta = new Vector2(width, 58);

            LayoutElement btnLE = btnObj.AddComponent<LayoutElement>();
            btnLE.preferredWidth = width;
            btnLE.preferredHeight = 58;
            btnLE.flexibleWidth = 0;

            Image btnImg = btnObj.AddComponent<Image>();
            // El sprite ya trae su propio color (verde / plateado): teñirlo con
            // bgColor lo apagaba. Con arte va en blanco y el color solo se usa
            // de respaldo cuando NO hay PNG.
            Color tint = bgSprite != null ? Color.white : bgColor;
            if (bgSprite != null)
            {
                btnImg.sprite = bgSprite;
                btnImg.type = Image.Type.Sliced;
                btnImg.fillCenter = true;
                btnImg.preserveAspect = false;
            }

            Button btn = btnObj.AddComponent<Button>();
            // El Image.color y el ColorBlock se multiplican entre si, asi que el
            // Image queda SIEMPRE en blanco y el color final viaja por el ColorBlock.
            // Dejar el Image en `tint` y teñir tambien aqui cebaba el color al
            // cuadrado en el camino sin sprite.
            btnImg.color = Color.white;

            if (bgSprite != null)
            {
                // CON SPRITE el juego del color es al reves. No se puede subir el
                // brillo desde blanco: Gain(blanco, 1.15) se recorta a blanco, asi
                // que hover y normal quedaban identicos y el boton no tenia NINGUN
                // feedback (solo el click, que si bajaba a 0.85). Por eso el sprite
                // se pinta apenas atenuado en reposo y el hover lo sube a blanco
                // puro: ese salto es lo que se ve. El click va en dorado, que es el
                // mismo destello que usa el resto de la UI.
                const float rest = 0.86f;
                UiFeedback.Apply(btn,
                    new Color(rest, rest, rest, 1f),
                    Color.white,
                    Color.Lerp(Color.white, new Color(1f, 0.85f, 0.35f), 0.45f),
                    fade: 0.12f);
            }
            else
            {
                // SIN SPRITE el color es plano y Gain si sirve: se sube al pasar el
                // cursor y se baja al presionar.
                UiFeedback.Apply(btn, tint,
                    UiFeedback.Gain(tint, 1.15f),
                    UiFeedback.Gain(tint, 0.85f));
            }

            // Sonido de hover y click. Este modal es uGUI y se arma con
            // new GameObject, asi que no lo cubre el RegisterSoundEffects de
            // UI Toolkit: sin esto el boton se ve pero suena a mudo.
            UiFeedback.AttachSounds(btn, isBack);

            btn.onClick.AddListener(() => onClick?.Invoke());

            GameObject txtObj = new GameObject("Text");
            txtObj.transform.SetParent(btnObj.transform, false);
            RectTransform txtRect = txtObj.AddComponent<RectTransform>();
            txtRect.anchorMin = Vector2.zero;
            txtRect.anchorMax = Vector2.one;
            txtRect.sizeDelta = Vector2.zero;
            txtRect.offsetMin = new Vector2(12, 0);
            txtRect.offsetMax = new Vector2(-12, 0);

            Text txt = txtObj.AddComponent<Text>();
            txt.text = label;
            txt.fontSize = 16;
            txt.fontStyle = FontStyle.Bold;
            txt.alignment = TextAnchor.MiddleCenter;
            // El botón plateado es claro: el blanco no lee, va tinta oscura.
            txt.color = textColor ?? Color.white;
            txt.horizontalOverflow = HorizontalWrapMode.Overflow;
            txt.verticalOverflow = VerticalWrapMode.Overflow;
            txt.font = ResolveFont(16);

            return btnRect;
        }

        private void BuildFallbackModal(string title, string subtitle, Color titleColor, Action onPlayAgain, Action onMainMenu)
        {
            _onPlayAgainCallback = onPlayAgain;
            _onMainMenuCallback = onMainMenu;
            EnsureEventSystem();
            if (_modalContainer == null) CreateModalUI();
            Transform existingCard = _modalContainer.transform.Find("CardBox");
            if (existingCard != null) Destroy(existingCard.gameObject);

            GameObject cardObj = new GameObject("CardBox");
            cardObj.transform.SetParent(_modalContainer.transform, false);
            RectTransform cardRect = cardObj.AddComponent<RectTransform>();
            cardRect.sizeDelta = new Vector2(560, 280);
            cardRect.anchorMin = new Vector2(0.5f, 0.5f);
            cardRect.anchorMax = new Vector2(0.5f, 0.5f);
            cardRect.pivot = new Vector2(0.5f, 0.5f);
            Image cardBg = cardObj.AddComponent<Image>();
            cardBg.color = new Color(0.086f, 0.102f, 0.133f, 0.98f);
            Outline outline = cardObj.AddComponent<Outline>();
            outline.effectColor = titleColor;
            outline.effectDistance = new Vector2(2, -2);
            VerticalLayoutGroup vlg = cardObj.AddComponent<VerticalLayoutGroup>();
            vlg.spacing = 10;
            vlg.padding = new RectOffset(24, 24, 18, 18);
            vlg.childAlignment = TextAnchor.UpperCenter;
            vlg.childControlWidth = true;
            vlg.childControlHeight = true;
            vlg.childForceExpandWidth = true;
            vlg.childForceExpandHeight = false;

            GameObject titleObj = new GameObject("Title");
            titleObj.transform.SetParent(cardObj.transform, false);
            titleObj.AddComponent<LayoutElement>().preferredHeight = 46;
            Text titleText = titleObj.AddComponent<Text>();
            titleText.text = CleanTitle(title);
            titleText.fontSize = 30;
            titleText.fontStyle = FontStyle.Bold;
            titleText.alignment = TextAnchor.MiddleCenter;
            titleText.color = titleColor;
            titleText.horizontalOverflow = HorizontalWrapMode.Overflow;
            titleText.verticalOverflow = VerticalWrapMode.Overflow;
            titleText.font = ResolveFont(30);

            GameObject subtitleObj = new GameObject("Subtitle");
            subtitleObj.transform.SetParent(cardObj.transform, false);
            subtitleObj.AddComponent<LayoutElement>().preferredHeight = 30;
            Text subtitleText = subtitleObj.AddComponent<Text>();
            subtitleText.text = subtitle;
            subtitleText.fontSize = 15;
            subtitleText.alignment = TextAnchor.MiddleCenter;
            subtitleText.color = new Color(0.85f, 0.88f, 0.92f);
            subtitleText.horizontalOverflow = HorizontalWrapMode.Wrap;
            subtitleText.verticalOverflow = VerticalWrapMode.Overflow;
            subtitleText.font = ResolveFont(15);

            GameObject buttonsRow = new GameObject("ButtonsRow");
            buttonsRow.transform.SetParent(cardObj.transform, false);
            LayoutElement rowLE = buttonsRow.AddComponent<LayoutElement>();
            rowLE.preferredHeight = 60;
            rowLE.flexibleWidth = 1;
            HorizontalLayoutGroup hlg = buttonsRow.AddComponent<HorizontalLayoutGroup>();
            hlg.spacing = 16;
            hlg.childAlignment = TextAnchor.MiddleCenter;
            hlg.childControlWidth = true;
            hlg.childControlHeight = true;
            hlg.childForceExpandWidth = true;
            hlg.childForceExpandHeight = false;
            _btnPlayAgainRect = CreateActionButton(buttonsRow.transform, "JUGAR DE NUEVO", new Color(0.16f, 0.55f, 0.30f), OnPlayAgainClicked);
            _btnMainMenuRect = CreateActionButton(buttonsRow.transform, "MENÚ PRINCIPAL", new Color(0.22f, 0.30f, 0.44f), OnMainMenuClicked, isBack: true);

            _modalContainer.SetActive(true);
            StartCoroutine(AnimateShow(cardObj.transform));
        }

        /// <summary>
        /// Ancho natural de un sprite de TEXTO a una altura dada.
        /// Los títulos (VICTORIA / RECOMPENSA / RENDIMIENTO) son PNG, no Text: sin
        /// fijar el ancho, preserveAspect los estiraba hasta llenar el hueco y
        /// quedaban gigantes (y cruzando el marco). Con el ancho derivado de la
        /// proporción real del PNG el tamaño queda fijo en cualquier resolución.
        /// </summary>
        private static float SpriteWidthForHeight(Sprite sprite, float height, float fallbackRatio)
        {
            if (sprite == null || sprite.rect.height <= 0f) return height * fallbackRatio;
            return height * (sprite.rect.width / sprite.rect.height);
        }

        private static Font ResolveFont(int size)
        {
            Font f = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (f == null) f = Font.CreateDynamicFontFromOSFont("Arial", size);
            return f;
        }

        private static string OutcomeBadgeText(string title)
        {
            string t = (title ?? "").ToUpperInvariant();
            if (t.Contains("VICTORIA")) return "★  VICTORIA  ★";
            if (t.Contains("DERROTA")) return "DERROTA";
            if (t.Contains("TABLAS") || t.Contains("EMPATE")) return "TABLAS";
            return "FIN DE PARTIDA";
        }

        private static string CleanTitle(string title)
        {
            string t = (title ?? "").Trim();
            int i = 0;
            while (i < t.Length && !char.IsLetterOrDigit(t[i]) && t[i] != '¡' && t[i] != '!' && t[i] != '¿' && t[i] != '?')
            {
                i++;
            }
            string cleaned = i < t.Length ? t.Substring(i).TrimStart() : t;
            return string.IsNullOrEmpty(cleaned) ? t : cleaned;
        }

        private void Update()
        {
            if (!_isShowing) return;

            var pointer = Pointer.current;
            if (pointer != null && pointer.press.wasPressedThisFrame)
            {
                Vector2 screenPos = pointer.position.ReadValue();

                if (_btnPlayAgainRect != null && RectTransformUtility.RectangleContainsScreenPoint(_btnPlayAgainRect, screenPos))
                {
                    OnPlayAgainClicked();
                }
                else if (_btnMainMenuRect != null && RectTransformUtility.RectangleContainsScreenPoint(_btnMainMenuRect, screenPos))
                {
                    OnMainMenuClicked();
                }
            }
        }

        private void OnPlayAgainClicked()
        {
            if (!_isShowing) return;
            Hide();
            var cb = _onPlayAgainCallback;
            _onPlayAgainCallback = null;
            cb?.Invoke();
        }

        private void OnMainMenuClicked()
        {
            if (!_isShowing) return;
            Hide();
            var cb = _onMainMenuCallback;
            _onMainMenuCallback = null;
            cb?.Invoke();
        }

        private IEnumerator AnimateShow(Transform card)
        {
            if (_overlayGroup != null) _overlayGroup.alpha = 0f;
            if (_overlayImage != null)
            {
                Color c = _overlayImage.color;
                c.a = 0f;
                _overlayImage.color = c;
            }
            if (card != null) card.localScale = Vector3.one;

            float elapsed = 0f;
            float duration = 0.22f;
            while (elapsed < duration)
            {
                elapsed += Time.unscaledDeltaTime;
                float p = Mathf.Clamp01(elapsed / duration);
                float eased = 1f - Mathf.Pow(1f - p, 3f);
                if (_overlayGroup != null) _overlayGroup.alpha = eased;
                if (_overlayImage != null)
                {
                    Color c2 = _overlayImage.color;
                    c2.a = OverlayAlpha * eased;
                    _overlayImage.color = c2;
                }
                yield return null;
            }

            if (_overlayGroup != null) _overlayGroup.alpha = 1f;
            if (_overlayImage != null)
            {
                Color c3 = _overlayImage.color;
                c3.a = OverlayAlpha;
                _overlayImage.color = c3;
            }
            if (card != null) card.localScale = Vector3.one;
            yield break;
        }

        public void Hide()
        {
            _isShowing = false;
            if (_modalContainer != null)
            {
                _modalContainer.SetActive(false);
            }
        }
    }
}
