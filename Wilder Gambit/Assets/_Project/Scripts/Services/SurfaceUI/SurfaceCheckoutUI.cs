using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;
using UnityEngine.UIElements;

namespace OWS.Surface
{
    /// <summary>
    /// Checkout global de Surface para Unity (UI Toolkit).
    ///
    /// USO RAPIDO
    /// 1. Copiá esta carpeta a Assets/Resources/SurfaceUI/ o asigná el UXML y el
    ///    USS en el Inspector. El módulo también intenta cargarlos de Resources
    ///    como "SurfaceUI/SurfaceCheckout".
    /// 2. En la escena, agregá un GameObject con UIDocument + PanelSettings y
    ///    sumale el componente SurfaceCheckoutUI.
    /// 3. Antes de abrir una compra, entregá la sesión y llamá al checkout:
    ///
    ///      SurfaceCheckoutUI.Instance.SessionToken = miTokenDeSurface;
    ///      SurfaceCheckoutUI.Instance.OpenCheckout(
    ///          new SurfacePurchaseRequest {
    ///              productName = "Pase de temporada",
    ///              description = "Acceso a la temporada actual",
    ///              price = 750,
    ///              currency = "tides",          // "gambits" o "tides"
    ///              origin = "Mi Juego"          // etiqueta visible en Surface
    ///          },
    ///          result => {
    ///              if (result.success) { /* entregar el producto */ }
    ///          });
    ///
    /// El módulo pide el saldo y los topes a Surface, muestra el ticket de
    /// revisión, valida saldo + tope del período + máximo por operación y, al
    /// confirmar, registra el movimiento en Surface › Transacciones. El servidor
    /// vuelve a validar todo antes de debitar, así que no se puede saltear el
    /// tope manipulando el cliente.
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class SurfaceCheckoutUI : MonoBehaviour
    {
        public static SurfaceCheckoutUI Instance { get; private set; }

        [Header("Surface")]
        [SerializeField] private string baseUrl = "https://owsdatabase.onrender.com";
        [SerializeField] private string fallbackBaseUrl = "https://owsdatabase2.onrender.com";
        [SerializeField] private int requestTimeoutSeconds = 25;

        [Header("Sesión")]
        [Tooltip("Token JWT de Surface. Si se deja vacío, se lee de PlayerPrefs con la clave indicada abajo.")]
        [SerializeField] private string tokenPlayerPrefsKey = "SurfaceToken";
        [Tooltip("Etiqueta que verá Surface en Transacciones si el juego no envía un origen.")]
        [SerializeField] private string defaultOrigin = "Surface";

        [Header("UI")]
        [SerializeField] private VisualTreeAsset checkoutUxml;
        [SerializeField] private StyleSheet checkoutUss;
        [SerializeField] private PanelSettings panelSettings = null;

        // ── API pública ──────────────────────────────────────────────────────

        /// <summary>Token de la sesión Surface. Si está vacío se usa PlayerPrefs.</summary>
        public string SessionToken { get; set; }

        /// <summary>
        /// Cobro alternativo para juegos que ya tienen su propio endpoint de compra
        /// (por ejemplo, un pase que además entrega una ventaja en el servidor).
        /// Si está asignado, el checkout muestra la revisión y los topes igual que
        /// siempre, pero al confirmar ejecuta esta rutina en vez de
        /// POST /surface/checkout/purchase. La rutina debe devolver el resultado
        /// real del cobro; el módulo no vuelve a debitar.
        /// </summary>
        public Func<SurfacePurchaseRequest, Action<SurfacePurchaseResult>, IEnumerator> SubmitHandler { get; set; }

        public string BaseUrl
        {
            get { return baseUrl; }
            set { baseUrl = value; }
        }

        public bool IsOpen
        {
            get { return _root != null && _root.style.display == DisplayStyle.Flex; }
        }

        // ── Etapas ───────────────────────────────────────────────────────────

        private enum Stage
        {
            Loading,
            Review,
            Processing,
            Ticket
        }

        private enum CheckState
        {
            Ok,
            Warn,
            Bad,
            Neutral
        }

        private enum NoticeKind
        {
            Info,
            Warn,
            Bad,
            Ok
        }

        // ── Estado interno ───────────────────────────────────────────────────

        private UIDocument _uiDocument;
        private VisualElement _root;
        private bool _uiReady;
        private int _setupAttempts;

        private VisualElement _stageLoading;
        private VisualElement _stageReview;
        private VisualElement _stageProcessing;
        private VisualElement _stageTicket;
        private ScrollView _stageScroll;

        private VisualElement _step1;
        private VisualElement _step2;
        private VisualElement _step3;

        private Label _lblSessionUser;
        private Label _lblProductName;
        private Label _lblProductDesc;
        private Label _lblPrice;
        private Label _lblCurrency;
        private Label _lblTotal;
        private Label _lblBalance;
        private Label _lblBalanceCurrency;
        private Label _lblHolder;
        private Label _lblBalanceAfter;
        private Label _lblLimitCaption;
        private Label _lblLimitPercent;
        private Label _lblNotice;
        private Label _lblProcessingTitle;
        private Label _lblProcessingSub;
        private Label _lblResultIcon;
        private Label _lblResultTitle;
        private Label _lblResultSub;
        private Label _lblResultStatus;
        private Label _lblTicketProduct;
        private Label _lblTicketId;
        private Label _lblTicketDate;
        private Label _lblTicketCurrency;
        private Label _lblTicketTotal;
        private Label _lblTicketBalance;
        private Label _lblTicketNote;
        private Label _lblStatusAlert;
        private Label _lblFooterRef;

        private Label _chkBalanceIcon;
        private Label _chkBalanceHint;
        private Label _chkBalanceValue;
        private Label _chkLimitIcon;
        private Label _chkLimitHint;
        private Label _chkLimitValue;
        private Label _chkPerOpIcon;
        private Label _chkPerOpHint;
        private Label _chkPerOpValue;

        private VisualElement _rowBalance;
        private VisualElement _rowLimit;
        private VisualElement _rowPerOp;
        private VisualElement _meterLimit;
        private VisualElement _barLimitFill;
        private VisualElement _boxNotice;
        private VisualElement _resultBadge;
        private VisualElement _resultStatusChip;
        private VisualElement _spinnerElement;
        private VisualElement _spinnerProcessing;

        private Button _btnClose;
        private Button _btnCancel;
        private Button _btnConfirm;
        private Button _btnTicketClose;

        private Stage _stage = Stage.Loading;
        private SurfacePurchaseRequest _request;
        private SurfaceCheckoutSessionDto _session;
        private SurfaceCheckoutEvaluationDto _evaluation;
        private SurfacePurchaseResult _pendingResult;
        private Action<SurfacePurchaseResult> _onComplete;
        private Coroutine _prepareRoutine;
        private Coroutine _purchaseRoutine;
        private bool _busy;
        private float _spinnerAngle;
        private string _activeBaseUrl;

        // ── Ciclo de vida ────────────────────────────────────────────────────

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }

            Instance = this;
            DontDestroyOnLoad(gameObject);
            _uiDocument = GetComponent<UIDocument>();
        }

        private void Start()
        {
            EnsureSetup();
        }

        private void OnDestroy()
        {
            if (Instance == this) Instance = null;
        }

        private void Update()
        {
            // El UIDocument instancia su árbol después de Awake. Si el checkout
            // se creó en el mismo frame, reintentamos hasta encontrarlo.
            if (!_uiReady) EnsureSetup();

            bool loading = _stage == Stage.Loading && _spinnerElement != null;
            bool processing = _stage == Stage.Processing && _spinnerProcessing != null;
            if (!loading && !processing) return;

            _spinnerAngle = Mathf.Repeat(_spinnerAngle - Time.unscaledDeltaTime * 210f, 360f);
            Rotate rotation = new Rotate(new Angle(_spinnerAngle, AngleUnit.Degree));
            if (loading) _spinnerElement.style.rotate = rotation;
            if (processing) _spinnerProcessing.style.rotate = rotation;
        }

        // ── Montaje de UI ────────────────────────────────────────────────────

        private void EnsureSetup()
        {
            if (_uiReady) return;
            SetupUI();
            _uiReady = _root != null && _stageReview != null;
            if (_uiReady) HideRoot();
        }

        private void SetupUI()
        {
            if (_uiDocument == null) _uiDocument = GetComponent<UIDocument>();
            if (_uiDocument == null)
            {
                Debug.LogError("[SurfaceCheckout] Falta el componente UIDocument.");
                return;
            }

            if (panelSettings != null && _uiDocument.panelSettings == null)
            {
                _uiDocument.panelSettings = panelSettings;
            }

            if (checkoutUxml == null)
            {
                checkoutUxml = Resources.Load<VisualTreeAsset>("SurfaceUI/SurfaceCheckout");
            }
            if (checkoutUss == null)
            {
                checkoutUss = Resources.Load<StyleSheet>("SurfaceUI/SurfaceCheckout");
            }

            if (checkoutUxml != null && _uiDocument.visualTreeAsset == null)
            {
                _uiDocument.visualTreeAsset = checkoutUxml;
            }

            _root = _uiDocument.rootVisualElement;
            if (_root == null)
            {
                Debug.LogWarning("[SurfaceCheckout] UIDocument todavía no tiene un árbol visual. Se reintentará.");
                return;
            }

            // El árbol del UXML puede tardar un frame en instanciarse.
            if (_root.Q<VisualElement>("surface-checkout-root") == null)
            {
                _root = null;
                _setupAttempts++;
                if (_setupAttempts == 180)
                {
                    Debug.LogWarning("[SurfaceCheckout] UIDocument no tiene el árbol de SurfaceCheckout. " +
                        "Asigná el UXML en el Inspector o copiá los archivos a Resources/SurfaceUI.");
                }
                return;
            }

            if (checkoutUss != null && !_root.styleSheets.Contains(checkoutUss))
            {
                _root.styleSheets.Add(checkoutUss);
            }

            _stageLoading = _root.Q<VisualElement>("stage-loading");
            _stageReview = _root.Q<VisualElement>("stage-review");
            _stageProcessing = _root.Q<VisualElement>("stage-processing");
            _stageTicket = _root.Q<VisualElement>("stage-ticket");
            _stageScroll = _root.Q<ScrollView>("stage-scroll");

            _step1 = _root.Q<VisualElement>("step-1");
            _step2 = _root.Q<VisualElement>("step-2");
            _step3 = _root.Q<VisualElement>("step-3");

            _lblSessionUser = _root.Q<Label>("lbl-session-user");
            _lblProductName = _root.Q<Label>("lbl-product-name");
            _lblProductDesc = _root.Q<Label>("lbl-product-desc");
            _lblPrice = _root.Q<Label>("lbl-price");
            _lblCurrency = _root.Q<Label>("lbl-currency");
            _lblTotal = _root.Q<Label>("lbl-total");
            _lblBalance = _root.Q<Label>("lbl-balance");
            _lblBalanceCurrency = _root.Q<Label>("lbl-balance-currency");
            _lblHolder = _root.Q<Label>("lbl-holder");
            _lblBalanceAfter = _root.Q<Label>("lbl-balance-after");
            _lblLimitCaption = _root.Q<Label>("lbl-limit-caption");
            _lblLimitPercent = _root.Q<Label>("lbl-limit-percent");
            _lblNotice = _root.Q<Label>("lbl-notice");
            _lblProcessingTitle = _root.Q<Label>("lbl-processing-title");
            _lblProcessingSub = _root.Q<Label>("lbl-processing-sub");
            _lblResultIcon = _root.Q<Label>("lbl-result-icon");
            _lblResultTitle = _root.Q<Label>("lbl-result-title");
            _lblResultSub = _root.Q<Label>("lbl-result-sub");
            _lblResultStatus = _root.Q<Label>("lbl-result-status");
            _lblTicketProduct = _root.Q<Label>("lbl-ticket-product");
            _lblTicketId = _root.Q<Label>("lbl-ticket-id");
            _lblTicketDate = _root.Q<Label>("lbl-ticket-date");
            _lblTicketCurrency = _root.Q<Label>("lbl-ticket-currency");
            _lblTicketTotal = _root.Q<Label>("lbl-ticket-total");
            _lblTicketBalance = _root.Q<Label>("lbl-ticket-balance");
            _lblTicketNote = _root.Q<Label>("lbl-ticket-note");
            _lblStatusAlert = _root.Q<Label>("lbl-status-alert");
            _lblFooterRef = _root.Q<Label>("lbl-footer-ref");

            _chkBalanceIcon = _root.Q<Label>("chk-balance-icon");
            _chkBalanceHint = _root.Q<Label>("chk-balance-hint");
            _chkBalanceValue = _root.Q<Label>("chk-balance-value");
            _chkLimitIcon = _root.Q<Label>("chk-limit-icon");
            _chkLimitHint = _root.Q<Label>("chk-limit-hint");
            _chkLimitValue = _root.Q<Label>("chk-limit-value");
            _chkPerOpIcon = _root.Q<Label>("chk-perop-icon");
            _chkPerOpHint = _root.Q<Label>("chk-perop-hint");
            _chkPerOpValue = _root.Q<Label>("chk-perop-value");

            _rowBalance = _root.Q<VisualElement>("row-balance");
            _rowLimit = _root.Q<VisualElement>("row-limit");
            _rowPerOp = _root.Q<VisualElement>("row-perop");
            _meterLimit = _root.Q<VisualElement>("meter-limit");
            _barLimitFill = _root.Q<VisualElement>("bar-limit-fill");
            _boxNotice = _root.Q<VisualElement>("box-notice");
            _resultBadge = _root.Q<VisualElement>("result-badge");
            _resultStatusChip = _root.Q<VisualElement>("result-status-chip");
            _spinnerElement = _root.Q<VisualElement>("spinner-element");
            _spinnerProcessing = _root.Q<VisualElement>("spinner-processing");

            _btnClose = _root.Q<Button>("btn-close");
            _btnCancel = _root.Q<Button>("btn-cancel");
            _btnConfirm = _root.Q<Button>("btn-confirm");
            _btnTicketClose = _root.Q<Button>("btn-ticket-close");

            if (_btnClose != null) _btnClose.clicked += OnCloseClicked;
            if (_btnCancel != null) _btnCancel.clicked += OnCancelClicked;
            if (_btnConfirm != null) _btnConfirm.clicked += OnConfirmClicked;
            if (_btnTicketClose != null) _btnTicketClose.clicked += CloseTicket;

            ResetUI();
            HideRoot();
        }

        // ── API de compra ────────────────────────────────────────────────────

        /// <summary>
        /// Abre el checkout y devuelve el resultado por callback. Si el jugador
        /// cancela, <see cref="SurfacePurchaseResult.cancelled"/> es true.
        /// </summary>
        public void OpenCheckout(SurfacePurchaseRequest request, Action<SurfacePurchaseResult> onComplete)
        {
            EnsureSetup();

            if (_root == null)
            {
                onComplete?.Invoke(Failure("El checkout de Surface no está listo en esta escena.", "UI_NOT_READY"));
                return;
            }

            if (_stage == Stage.Processing)
            {
                onComplete?.Invoke(Failure("Ya hay una compra en proceso. Esperá a que termine.", "BUSY"));
                return;
            }

            if (IsOpen)
            {
                CancelCheckout("Reemplazado por una nueva compra.");
            }

            string normalized = request != null ? NormalizeCurrency(request.currency) : null;
            if (request == null || string.IsNullOrEmpty(request.productName))
            {
                onComplete?.Invoke(Failure("La compra no tiene un producto válido.", "INVALID_PRODUCT"));
                return;
            }
            if (request.price <= 0)
            {
                onComplete?.Invoke(Failure("El precio de la compra debe ser mayor a cero.", "INVALID_AMOUNT"));
                return;
            }
            if (normalized == null)
            {
                onComplete?.Invoke(Failure("La divisa debe ser 'gambits' o 'tides'.", "INVALID_CURRENCY"));
                return;
            }

            request.currency = normalized;
            request.origin = string.IsNullOrWhiteSpace(request.origin)
                ? (string.IsNullOrWhiteSpace(defaultOrigin) ? "Surface" : defaultOrigin.Trim())
                : request.origin.Trim();

            _request = request;
            _onComplete = onComplete;
            _pendingResult = null;
            _session = null;
            _evaluation = null;
            _busy = false;

            ResetUI();
            ShowRoot();
            SetStage(Stage.Loading);
            HideAlert();
            _prepareRoutine = StartCoroutine(PrepareSessionRoutine());
        }

        /// <summary>Atajo para compras simples.</summary>
        public void OpenCheckout(string productName, string description, int price, string currency,
            Action<bool, string> onComplete)
        {
            OpenCheckout(
                new SurfacePurchaseRequest
                {
                    productName = productName,
                    description = description,
                    price = price,
                    currency = currency
                },
                result => onComplete?.Invoke(result.success, result.message));
        }

        /// <summary>Cierra el checkout si está abierto. Una compra en proceso no se cancela.</summary>
        public void Close()
        {
            CancelCheckout("Checkout cerrado.");
        }

        // ── Sesión / elegibilidad ────────────────────────────────────────────

        private IEnumerator PrepareSessionRoutine()
        {
            float started = Time.realtimeSinceStartup;

            string token = ResolveToken();
            if (string.IsNullOrEmpty(token))
            {
                ShowSessionError("Iniciá sesión en Surface para poder comprar.");
                _prepareRoutine = null;
                yield break;
            }

            string path = "/surface/checkout/session?currency=" +
                          UnityWebRequest.EscapeURL(CurrencyKey) +
                          "&amount=" + _request.price +
                          "&origin=" + UnityWebRequest.EscapeURL(_request.origin);

            SurfaceCheckoutHttpResult http = null;
            yield return SendRequest("GET", path, null, token, result => http = result);

            float elapsed = Time.realtimeSinceStartup - started;
            if (elapsed < 0.35f)
            {
                yield return new WaitForSecondsRealtime(0.35f - elapsed);
            }

            if (http == null || !http.ok)
            {
                ShowSessionError(DescribeHttpError(http, "No pudimos leer tu cuenta de Surface."));
                _prepareRoutine = null;
                yield break;
            }

            SurfaceCheckoutSessionDto session = null;
            try
            {
                session = JsonUtility.FromJson<SurfaceCheckoutSessionDto>(http.text);
            }
            catch (Exception e)
            {
                Debug.LogWarning("[SurfaceCheckout] Respuesta de sesión ilegible: " + e.Message);
            }

            if (session == null || !session.success)
            {
                ShowSessionError(session != null && !string.IsNullOrEmpty(session.error)
                    ? session.error
                    : "Surface no devolvió tu saldo. Probá de nuevo.");
                _prepareRoutine = null;
                yield break;
            }

            _session = session;
            _evaluation = session.evaluation != null ? session.evaluation : BuildLocalEvaluation();
            RenderReview();
            SetStage(Stage.Review);
            _prepareRoutine = null;
        }

        private void ShowSessionError(string message)
        {
            _session = null;
            _evaluation = null;
            _busy = false;

            string currency = CurrencyLabel;
            string product = _request != null ? _request.productName : "Producto";
            string description = _request != null && !string.IsNullOrEmpty(_request.description)
                ? _request.description
                : "Artículo digital de Surface";
            long price = _request != null ? _request.price : 0;

            SetText(_lblSessionUser, "Sin conexión");
            SetText(_lblProductName, product);
            SetText(_lblProductDesc, description);
            SetText(_lblPrice, FormatAmount(price) + " " + currency);
            SetText(_lblCurrency, currency);
            SetText(_lblTotal, FormatAmount(price) + " " + currency);
            SetText(_lblBalance, "—");
            SetText(_lblBalanceCurrency, currency);
            SetText(_lblHolder, "TITULAR: —");
            SetText(_lblBalanceAfter, "Quedarán —");
            SetText(_lblFooterRef, "Checkout · " + (_request != null ? _request.origin : "Surface"));

            SetCheck(_rowBalance, _chkBalanceIcon, _chkBalanceValue, _chkBalanceHint,
                CheckState.Neutral, "—", "Sin datos de Surface.");
            SetCheck(_rowLimit, _chkLimitIcon, _chkLimitValue, _chkLimitHint,
                CheckState.Neutral, "—", "Sin datos de Surface.");
            SetCheck(_rowPerOp, _chkPerOpIcon, _chkPerOpValue, _chkPerOpHint,
                CheckState.Neutral, "—", "Sin datos de Surface.");

            SetVisible(_meterLimit, false);
            SetNotice("", NoticeKind.Info);

            if (_btnConfirm != null)
            {
                _btnConfirm.SetEnabled(false);
                _btnConfirm.text = "No disponible";
            }

            SetStage(Stage.Review);
            ShowAlert(message, true);
        }

        private void RenderReview()
        {
            if (_request == null) return;
            if (_session == null) return;

            string currency = CurrencyKey;
            string label = CurrencyLabel;
            long price = _request.price;
            long balance = ToLong(AmountOf(_session.balances, currency));
            long spent = ToLong(AmountOf(_session.spent, currency));

            SurfaceCheckoutLimitsDto limits = _session.management != null ? _session.management.limits : null;
            bool limitEnabled = limits != null && limits.enabled;
            long limitAmount = limitEnabled ? ToLong(LimitOf(limits, currency)) : 0;
            long perOpLimit = limitEnabled ? ToLong(PerOpOf(limits, currency)) : 0;
            bool blockOnExceed = limits == null || limits.block;
            int threshold = limits != null && limits.threshold > 0 ? limits.threshold : 80;

            long projected = spent + price;
            bool balanceOk = balance >= price;
            bool perOpOk = perOpLimit <= 0 || price <= perOpLimit;
            bool limitExceeded = limitEnabled && limitAmount > 0 && projected > limitAmount;
            bool limitBlocked = limitExceeded && blockOnExceed;
            double percent = limitAmount > 0 ? (projected * 100.0 / limitAmount) : 0;

            if (_evaluation == null) _evaluation = BuildLocalEvaluation();

            string periodTitle = _evaluation != null && !string.IsNullOrEmpty(_evaluation.periodLabel)
                ? _evaluation.periodLabel
                : PeriodTitle(limits != null ? limits.period : "monthly");

            string username = _session.user != null && !string.IsNullOrEmpty(_session.user.username)
                ? _session.user.username
                : "Jugador";

            SetText(_lblSessionUser, username);
            SetText(_lblProductName, _request.productName);
            SetText(_lblProductDesc, string.IsNullOrEmpty(_request.description)
                ? "Artículo digital de " + _request.origin
                : _request.description);
            SetText(_lblPrice, FormatAmount(price) + " " + label);
            SetText(_lblCurrency, label);
            SetText(_lblTotal, FormatAmount(price) + " " + label);
            SetText(_lblBalance, FormatAmount(balance));
            SetText(_lblBalanceCurrency, label);
            SetText(_lblHolder, "TITULAR: " + username.ToUpperInvariant());
            SetText(_lblBalanceAfter, balanceOk
                ? "Quedarán " + FormatAmount(balance - price) + " " + label
                : "Faltan " + FormatAmount(price - balance) + " " + label);
            SetText(_lblFooterRef, "Checkout · " + _request.origin +
                (limitEnabled ? " · Tope " + periodTitle : " · Sin tope"));

            SetCheck(_rowBalance, _chkBalanceIcon, _chkBalanceValue, _chkBalanceHint,
                balanceOk ? CheckState.Ok : CheckState.Bad,
                FormatAmount(balance) + " / " + FormatAmount(price),
                balanceOk ? "Cubre el total de la compra." : "Te faltan " + FormatAmount(price - balance) + " " + label + ".");

            if (!limitEnabled || limitAmount <= 0)
            {
                SetCheck(_rowLimit, _chkLimitIcon, _chkLimitValue, _chkLimitHint,
                    CheckState.Neutral, "—",
                    "Podés activar un tope en Surface › Gestión.");
            }
            else
            {
                CheckState limitState = limitExceeded
                    ? (blockOnExceed ? CheckState.Bad : CheckState.Warn)
                    : CheckState.Ok;
                string limitHint = limitExceeded
                    ? (blockOnExceed
                        ? "Supera el tope de " + periodTitle + "."
                        : "Supera el tope, pero solo avisa: no bloquea.")
                    : "Gastado " + FormatAmount(spent) + " · Disponible " +
                      FormatAmount(Math.Max(0, limitAmount - spent)) + ".";
                SetCheck(_rowLimit, _chkLimitIcon, _chkLimitValue, _chkLimitHint,
                    limitState,
                    FormatAmount(projected) + " / " + FormatAmount(limitAmount),
                    limitHint);
            }

            if (perOpLimit <= 0)
            {
                SetCheck(_rowPerOp, _chkPerOpIcon, _chkPerOpValue, _chkPerOpHint,
                    CheckState.Neutral, "—", "Sin máximo por operación.");
            }
            else
            {
                SetCheck(_rowPerOp, _chkPerOpIcon, _chkPerOpValue, _chkPerOpHint,
                    perOpOk ? CheckState.Ok : CheckState.Bad,
                    FormatAmount(price) + " / " + FormatAmount(perOpLimit),
                    "Máximo permitido en una sola compra.");
            }

            SetLimitMeter(limitEnabled, limitAmount, percent, threshold, periodTitle);

            // Aviso contextual: primero el bloqueo del servidor, luego el aviso
            // de umbral, y por último una explicación local si no vino nada.
            string notice = _evaluation != null ? _evaluation.reason : "";
            NoticeKind noticeKind = NoticeKind.Bad;
            if (string.IsNullOrEmpty(notice) && _evaluation != null && !string.IsNullOrEmpty(_evaluation.hint))
            {
                notice = _evaluation.hint;
                noticeKind = _evaluation.warn ? NoticeKind.Warn : NoticeKind.Info;
            }
            if (string.IsNullOrEmpty(notice) && !balanceOk)
            {
                notice = "Saldo insuficiente: te faltan " + FormatAmount(price - balance) + " " + label + ".";
                noticeKind = NoticeKind.Bad;
            }
            if (string.IsNullOrEmpty(notice) && !perOpOk)
            {
                notice = "Esta compra supera el máximo por operación de " + FormatAmount(perOpLimit) + " " + label + ".";
                noticeKind = NoticeKind.Bad;
            }
            if (string.IsNullOrEmpty(notice) && limitBlocked)
            {
                notice = "Esta compra supera tu tope de " + label + " para " + periodTitle.ToLowerInvariant() + ".";
                noticeKind = NoticeKind.Bad;
            }
            if (string.IsNullOrEmpty(notice) && limitEnabled && limitAmount > 0 && threshold > 0 && percent >= threshold)
            {
                notice = "Con esta compra vas a usar el " + Math.Round(percent) + "% de tu tope de " + label + ".";
                noticeKind = NoticeKind.Warn;
            }
            SetNotice(notice, noticeKind);

            bool canPurchase = _evaluation != null
                ? _evaluation.canPurchase
                : (balanceOk && perOpOk && !limitBlocked);

            if (_btnConfirm != null)
            {
                _btnConfirm.SetEnabled(canPurchase);
                if (canPurchase)
                {
                    _btnConfirm.text = "Confirmar compra · " + FormatAmount(price) + " " + label;
                }
                else if (!balanceOk)
                {
                    _btnConfirm.text = "Saldo insuficiente";
                }
                else if (!perOpOk)
                {
                    _btnConfirm.text = "Supera el máximo por operación";
                }
                else if (limitBlocked)
                {
                    _btnConfirm.text = "Tope alcanzado";
                }
                else
                {
                    _btnConfirm.text = "No disponible";
                }
            }
        }

        private SurfaceCheckoutEvaluationDto BuildLocalEvaluation()
        {
            string currency = CurrencyKey;
            string label = CurrencyLabel;
            long price = _request != null ? _request.price : 0;
            long balance = ToLong(AmountOf(_session.balances, currency));
            long spent = ToLong(AmountOf(_session.spent, currency));

            SurfaceCheckoutLimitsDto limits = _session.management != null ? _session.management.limits : null;
            bool enabled = limits != null && limits.enabled;
            long limit = enabled ? ToLong(LimitOf(limits, currency)) : 0;
            long perOp = enabled ? ToLong(PerOpOf(limits, currency)) : 0;
            bool block = limits == null || limits.block;
            int threshold = limits != null && limits.threshold > 0 ? limits.threshold : 80;
            string period = limits != null ? limits.period : "monthly";

            long projected = spent + price;
            bool sufficient = price > 0 && balance >= price;
            bool perOpExceeded = perOp > 0 && price > perOp;
            bool limitExceeded = enabled && limit > 0 && projected > limit;
            bool blocked = price <= 0 || perOpExceeded || (limitExceeded && block) || !sufficient;
            double percent = limit > 0 ? (projected * 100.0 / limit) : 0;

            string reason = "";
            string hint = "";
            string code = "";
            bool warn = false;

            if (price <= 0)
            {
                code = "INVALID_AMOUNT";
                reason = "El importe de la compra no es válido.";
            }
            else if (perOpExceeded)
            {
                code = "PER_OP_LIMIT";
                reason = "El máximo por operación en " + label + " es " + FormatAmount(perOp) + ".";
            }
            else if (limitExceeded && block)
            {
                code = "PERIOD_LIMIT";
                reason = "Este gasto supera tu tope de " + label + " para " + PeriodPhrase(period) +
                         ". Ya usaste " + FormatAmount(spent) + " y esta compra necesita " + FormatAmount(price) + ".";
            }
            else if (!sufficient)
            {
                code = "INSUFFICIENT_BALANCE";
                reason = "Saldo insuficiente: tenés " + FormatAmount(balance) + " " + label +
                         " y necesitás " + FormatAmount(price) + ".";
            }
            else if (limitExceeded)
            {
                warn = true;
                hint = "Con esta compra superás tu tope de " + label + " para " + PeriodPhrase(period) +
                       "; el tope solo avisa, no bloquea.";
            }
            else if (enabled && limit > 0 && threshold > 0 && percent >= threshold)
            {
                warn = true;
                hint = "Con esta compra vas a usar el " + Math.Round(percent) + "% de tu tope de " + label +
                       " (" + FormatAmount(limit) + " para " + PeriodPhrase(period) + ").";
            }

            return new SurfaceCheckoutEvaluationDto
            {
                currency = currency,
                amount = price,
                balance = balance,
                sufficientBalance = sufficient,
                limitEnabled = enabled,
                period = period,
                periodLabel = PeriodTitle(period),
                limitAmount = limit,
                perOpLimit = perOp,
                spent = spent,
                remaining = limit > 0 ? Math.Max(0, limit - spent) : 0,
                projected = projected,
                percentUsed = percent,
                threshold = threshold,
                blockOnExceed = block,
                limitExceeded = limitExceeded,
                perOpExceeded = perOpExceeded,
                canPurchase = !blocked,
                blocked = blocked,
                warn = warn,
                code = code,
                reason = reason,
                hint = hint
            };
        }

        // ── Pago ─────────────────────────────────────────────────────────────

        private void OnConfirmClicked()
        {
            if (_busy) return;
            if (_request == null || _session == null)
            {
                ShowAlert("No pudimos validar tu cuenta. Cerrá y volvé a intentar.", true);
                return;
            }
            if (_evaluation != null && !_evaluation.canPurchase)
            {
                ShowAlert(string.IsNullOrEmpty(_evaluation.reason)
                    ? "No podés completar esta compra."
                    : _evaluation.reason, true);
                return;
            }

            _busy = true;
            _purchaseRoutine = StartCoroutine(PurchaseRoutine());
        }

        private IEnumerator PurchaseRoutine()
        {
            string token = ResolveToken();
            if (string.IsNullOrEmpty(token))
            {
                _busy = false;
                _purchaseRoutine = null;
                ReturnToReview("Tu sesión de Surface venció. Iniciá sesión de nuevo.", true);
                yield break;
            }

            SetStage(Stage.Processing);
            SetText(_lblProcessingTitle, "Procesando tu compra");
            SetText(_lblProcessingSub, "Surface está verificando tu saldo y registrando el movimiento.");

            // El juego puede resolver el cobro con su propio backend (p. ej. el
            // pase de temporada, que además de debitar entrega la ventaja).
            if (SubmitHandler != null)
            {
                SurfacePurchaseResult external = null;
                yield return SubmitHandler(_request, result => external = result);
                _busy = false;
                _purchaseRoutine = null;

                if (external != null && external.success)
                {
                    ShowTicket(external);
                }
                else
                {
                    string externalMessage = external != null && !string.IsNullOrEmpty(external.message)
                        ? external.message
                        : "No pudimos completar la compra.";
                    ReturnToReview(externalMessage, true);
                }
                yield break;
            }

            SurfaceCheckoutPayload payload = new SurfaceCheckoutPayload
            {
                productId = _request.productId,
                productName = _request.productName,
                description = _request.description,
                amount = _request.price,
                currency = CurrencyKey,
                origin = _request.origin
            };

            string body = JsonUtility.ToJson(payload);
            SurfaceCheckoutHttpResult http = null;
            yield return SendRequest("POST", "/surface/checkout/purchase", body, token, result => http = result);

            SurfaceCheckoutPurchaseDto purchase = null;
            try
            {
                if (http != null && !string.IsNullOrEmpty(http.text))
                {
                    purchase = JsonUtility.FromJson<SurfaceCheckoutPurchaseDto>(http.text);
                }
            }
            catch (Exception e)
            {
                Debug.LogWarning("[SurfaceCheckout] Respuesta de compra ilegible: " + e.Message);
            }

            if (http != null && http.ok && purchase != null && purchase.success)
            {
                _busy = false;
                _purchaseRoutine = null;
                FinishTicket(purchase);
                yield break;
            }

            // Si el servidor mandó datos actualizados, corregimos la revisión.
            if (purchase != null)
            {
                if (purchase.balances != null && _session != null) _session.balances = purchase.balances;
                if (purchase.spent != null && _session != null) _session.spent = purchase.spent;
                if (purchase.management != null && _session != null) _session.management = purchase.management;
                if (purchase.evaluation != null) _evaluation = purchase.evaluation;
            }

            _busy = false;
            _purchaseRoutine = null;

            bool uncertain = http == null || http.status == 0 || http.status >= 500;
            string message;
            if (uncertain)
            {
                message = "No sabemos si Surface alcanzó a registrar la compra. Revisá Transacciones antes de reintentar.";
            }
            else if (purchase != null && !string.IsNullOrEmpty(purchase.error))
            {
                message = purchase.error;
            }
            else
            {
                message = "Surface no pudo completar la compra.";
            }

            ReturnToReview(message, true);
        }

        private void ReturnToReview(string message, bool error)
        {
            _busy = false;
            if (_session != null)
            {
                if (_evaluation == null) _evaluation = BuildLocalEvaluation();
                RenderReview();
            }
            SetStage(Stage.Review);
            ShowAlert(message, error);
        }

        private void FinishTicket(SurfaceCheckoutPurchaseDto purchase)
        {
            long previousBalance = ToLong(purchase.previousBalance);
            long newBalance = ToLong(purchase.newBalance);
            string label = CurrencyLabel;

            if (_session != null && _session.balances != null)
            {
                if (CurrencyKey == "tides") _session.balances.tides = purchase.newBalance;
                else _session.balances.gambits = purchase.newBalance;
            }

            ShowTicket(new SurfacePurchaseResult
            {
                success = true,
                cancelled = false,
                message = "Compra completada",
                code = "OK",
                transactionId = purchase.transactionId,
                productName = _request.productName,
                price = _request.price,
                currency = label,
                previousBalance = previousBalance,
                newBalance = newBalance,
                purchasedAt = purchase.purchasedAt,
                origin = _request.origin
            });
        }

        /// <summary>Pinta el comprobante final a partir de un resultado ya cobrado.</summary>
        private void ShowTicket(SurfacePurchaseResult result)
        {
            if (result == null) return;
            _pendingResult = result;

            string label = string.IsNullOrEmpty(result.currency) ? CurrencyLabel : result.currency;
            string product = string.IsNullOrEmpty(result.productName)
                ? (_request != null ? _request.productName : "Producto")
                : result.productName;
            int price = result.price > 0 ? result.price : (_request != null ? _request.price : 0);

            SetText(_lblResultIcon, "✓");
            SetText(_lblResultTitle, "Compra aprobada");
            SetText(_lblResultSub, "Listo. Tu compra ya está registrada en Surface.");
            SetText(_lblResultStatus, "APROBADA");
            SetText(_lblTicketProduct, product);
            SetText(_lblTicketId, result.transactionId > 0
                ? "#" + result.transactionId.ToString("D6", CultureInfo.InvariantCulture)
                : "SIN CARGO");
            SetText(_lblTicketDate, FormatDate(result.purchasedAt));
            SetText(_lblTicketCurrency, label);
            SetText(_lblTicketTotal, FormatAmount(price) + " " + label);
            SetText(_lblTicketBalance, FormatAmount(result.newBalance) + " " + label);
            SetText(_lblTicketNote, "Este movimiento ya figura en Surface › Transacciones.");

            if (_resultBadge != null)
            {
                _resultBadge.RemoveFromClassList("surface-result-bad");
                _resultBadge.AddToClassList("surface-result-ok");
            }
            if (_resultStatusChip != null)
            {
                _resultStatusChip.RemoveFromClassList("surface-status-bad");
                _resultStatusChip.AddToClassList("surface-status-ok");
            }

            SetStage(Stage.Ticket);
        }

        // ── Cierre / cancelación ─────────────────────────────────────────────

        private void OnCloseClicked()
        {
            if (_stage == Stage.Ticket)
            {
                CloseTicket();
                return;
            }
            CancelCheckout("Compra cancelada.");
        }

        private void OnCancelClicked()
        {
            CancelCheckout("Compra cancelada por el jugador.");
        }

        private void CancelCheckout(string reason)
        {
            if (_stage == Stage.Processing) return;
            if (_stage == Stage.Ticket && _pendingResult != null)
            {
                CloseTicket();
                return;
            }

            if (_prepareRoutine != null)
            {
                StopCoroutine(_prepareRoutine);
                _prepareRoutine = null;
            }
            if (_purchaseRoutine != null)
            {
                StopCoroutine(_purchaseRoutine);
                _purchaseRoutine = null;
            }

            Action<SurfacePurchaseResult> callback = _onComplete;
            _onComplete = null;
            _pendingResult = null;
            _busy = false;
            HideRoot();

            callback?.Invoke(new SurfacePurchaseResult
            {
                success = false,
                cancelled = true,
                message = reason,
                code = "CANCELLED",
                productName = _request != null ? _request.productName : "",
                price = _request != null ? _request.price : 0,
                currency = CurrencyLabel,
                origin = _request != null ? _request.origin : ""
            });
        }

        private void CloseTicket()
        {
            SurfacePurchaseResult result = _pendingResult;
            _pendingResult = null;

            Action<SurfacePurchaseResult> callback = _onComplete;
            _onComplete = null;
            _busy = false;
            HideRoot();

            if (result != null && callback != null)
            {
                callback(result);
            }
        }

        // ── Red ──────────────────────────────────────────────────────────────

        private IEnumerator SendRequest(string method, string path, string body, string token,
            Action<SurfaceCheckoutHttpResult> done)
        {
            string[] bases = BuildBases();
            SurfaceCheckoutHttpResult last = null;

            for (int i = 0; i < bases.Length; i++)
            {
                string url = bases[i].TrimEnd('/') + path;
                SurfaceCheckoutHttpResult current = null;
                yield return SendSingle(method, url, body, token, result => current = result);
                last = current;

                if (current == null) break;
                if (current.ok)
                {
                    // Se recuerda el host que respondió para que la compra vaya
                    // al mismo backend (el POST no se reintenta).
                    _activeBaseUrl = bases[i];
                    break;
                }

                // El POST no se reintenta: si la respuesta se perdió, la compra
                // pudo haberse registrado y reintentar cobraría dos veces.
                bool retryable = method == "GET" &&
                                 (current.status == 0 || current.status == 502 ||
                                  current.status == 503 || current.status == 504);
                if (!retryable || i == bases.Length - 1) break;
            }

            done?.Invoke(last ?? new SurfaceCheckoutHttpResult
            {
                ok = false,
                status = 0,
                text = "",
                error = "Sin respuesta de Surface"
            });
        }

        private IEnumerator SendSingle(string method, string url, string body, string token,
            Action<SurfaceCheckoutHttpResult> done)
        {
            using (UnityWebRequest request = new UnityWebRequest(url, method))
            {
                request.downloadHandler = new DownloadHandlerBuffer();
                if (!string.IsNullOrEmpty(body))
                {
                    request.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(body));
                    request.SetRequestHeader("Content-Type", "application/json");
                }
                if (!string.IsNullOrEmpty(token))
                {
                    request.SetRequestHeader("Authorization", "Bearer " + token);
                }
                request.SetRequestHeader("Accept", "application/json");
                request.timeout = Mathf.Max(8, requestTimeoutSeconds);

                yield return request.SendWebRequest();

                done?.Invoke(new SurfaceCheckoutHttpResult
                {
                    ok = request.result == UnityWebRequest.Result.Success,
                    status = request.responseCode,
                    text = request.downloadHandler != null ? request.downloadHandler.text : "",
                    error = request.error
                });
            }
        }

        private string[] BuildBases()
        {
            List<string> bases = new List<string>(3);
            AddBase(bases, _activeBaseUrl);
            AddBase(bases, baseUrl);
            AddBase(bases, fallbackBaseUrl);
            return bases.ToArray();
        }

        private static void AddBase(List<string> bases, string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            string clean = value.Trim();
            for (int i = 0; i < bases.Count; i++)
            {
                if (string.Equals(bases[i], clean, StringComparison.OrdinalIgnoreCase)) return;
            }
            bases.Add(clean);
        }

        private string ResolveToken()
        {
            if (!string.IsNullOrEmpty(SessionToken)) return SessionToken;
            if (string.IsNullOrEmpty(tokenPlayerPrefsKey)) return "";
            return PlayerPrefs.GetString(tokenPlayerPrefsKey, "");
        }

        private static string DescribeHttpError(SurfaceCheckoutHttpResult http, string fallback)
        {
            if (http == null || http.status == 0)
            {
                return "No pudimos conectar con Surface. Revisá tu conexión e intentá de nuevo.";
            }
            if (http.status == 401)
            {
                return "Tu sesión de Surface venció. Iniciá sesión de nuevo.";
            }
            if (http.status == 403)
            {
                return "Surface no autorizó esta operación.";
            }
            return !string.IsNullOrEmpty(fallback) ? fallback : "Surface no está disponible ahora.";
        }

        // ── Pintura ──────────────────────────────────────────────────────────

        private void ResetUI()
        {
            SetText(_lblSessionUser, "Sesión Surface");
            SetText(_lblProductName, "Producto");
            SetText(_lblProductDesc, "Descripción del artículo");
            SetText(_lblPrice, "0 GAMBITS");
            SetText(_lblCurrency, "GAMBITS");
            SetText(_lblTotal, "0 GAMBITS");
            SetText(_lblBalance, "0");
            SetText(_lblBalanceCurrency, "GAMBITS");
            SetText(_lblHolder, "TITULAR: —");
            SetText(_lblBalanceAfter, "Quedarán 0");
            SetText(_lblLimitCaption, "Uso del tope");
            SetText(_lblLimitPercent, "0%");
            SetText(_lblProcessingTitle, "Procesando tu compra");
            SetText(_lblProcessingSub, "Surface está verificando tu saldo y registrando el movimiento.");
            SetText(_lblTicketProduct, "—");
            SetText(_lblTicketId, "#000000");
            SetText(_lblTicketDate, "—");
            SetText(_lblTicketCurrency, "GAMBITS");
            SetText(_lblTicketTotal, "0 GAMBITS");
            SetText(_lblTicketBalance, "—");
            SetText(_lblTicketNote, "Este movimiento ya figura en Surface › Transacciones.");
            SetText(_lblFooterRef, "Checkout global");
            HideAlert();
            SetNotice("", NoticeKind.Info);

            SetCheck(_rowBalance, _chkBalanceIcon, _chkBalanceValue, _chkBalanceHint,
                CheckState.Neutral, "—", "Contra tu saldo Surface.");
            SetCheck(_rowLimit, _chkLimitIcon, _chkLimitValue, _chkLimitHint,
                CheckState.Neutral, "—", "Configurado en Surface › Gestión.");
            SetCheck(_rowPerOp, _chkPerOpIcon, _chkPerOpValue, _chkPerOpHint,
                CheckState.Neutral, "—", "Límite de una sola compra.");

            SetVisible(_meterLimit, false);
            if (_barLimitFill != null)
            {
                _barLimitFill.style.width = Length.Percent(0);
                _barLimitFill.RemoveFromClassList("surface-meter-warn");
                _barLimitFill.RemoveFromClassList("surface-meter-bad");
            }
            if (_btnConfirm != null)
            {
                _btnConfirm.SetEnabled(false);
                _btnConfirm.text = "Confirmar compra";
            }
            if (_btnClose != null) _btnClose.SetEnabled(true);
        }

        private void SetStage(Stage stage)
        {
            _stage = stage;
            SetVisible(_stageLoading, stage == Stage.Loading);
            SetVisible(_stageReview, stage == Stage.Review);
            SetVisible(_stageProcessing, stage == Stage.Processing);
            SetVisible(_stageTicket, stage == Stage.Ticket);

            SetStep(_step1, stage == Stage.Loading, stage != Stage.Loading);
            SetStep(_step2, stage == Stage.Review,
                stage == Stage.Processing || stage == Stage.Ticket);
            SetStep(_step3, stage == Stage.Processing, stage == Stage.Ticket);

            if (_btnClose != null) _btnClose.SetEnabled(stage != Stage.Processing);
            if (stage == Stage.Processing) HideAlert();

            // Al cambiar de etapa el contenido anterior puede ser más alto: sin este
            // reset el ScrollView conserva el offset y el encabezado aparece recortado.
            if (_stageScroll != null)
            {
                _stageScroll.scrollOffset = Vector2.zero;
                _stageScroll.verticalScrollerVisibility = ScrollerVisibility.Auto;
            }
        }

        private static void SetStep(VisualElement step, bool active, bool done)
        {
            if (step == null) return;
            step.RemoveFromClassList("is-active");
            step.RemoveFromClassList("is-done");
            if (done) step.AddToClassList("is-done");
            if (active) step.AddToClassList("is-active");
        }

        private void SetCheck(VisualElement row, Label icon, Label value, Label hint,
            CheckState state, string valueText, string hintText)
        {
            if (row != null)
            {
                row.RemoveFromClassList("surface-check-ok");
                row.RemoveFromClassList("surface-check-warn");
                row.RemoveFromClassList("surface-check-bad");
                row.RemoveFromClassList("surface-check-neutral");
                row.AddToClassList(StateClass(state));
            }
            SetText(icon, StateIcon(state));
            SetText(value, valueText);
            SetText(hint, hintText);
        }

        private void SetLimitMeter(bool enabled, long limit, double percent, int threshold, string periodTitle)
        {
            bool show = enabled && limit > 0;
            SetVisible(_meterLimit, show);
            if (!show) return;

            SetText(_lblLimitCaption, "Uso del tope · " + periodTitle);
            int whole = (int)Math.Round(percent);
            if (whole < 0) whole = 0;
            SetText(_lblLimitPercent, whole + "%");

            if (_barLimitFill != null)
            {
                _barLimitFill.style.width = Length.Percent(Mathf.Clamp((float)percent, 0f, 100f));
                _barLimitFill.RemoveFromClassList("surface-meter-warn");
                _barLimitFill.RemoveFromClassList("surface-meter-bad");
                if (percent > 100) _barLimitFill.AddToClassList("surface-meter-bad");
                else if (percent >= threshold) _barLimitFill.AddToClassList("surface-meter-warn");
            }
        }

        private void SetNotice(string text, NoticeKind kind)
        {
            bool show = !string.IsNullOrEmpty(text);
            SetVisible(_boxNotice, show);
            if (!show) return;

            SetText(_lblNotice, text);
            if (_boxNotice != null)
            {
                _boxNotice.RemoveFromClassList("surface-notice-warn");
                _boxNotice.RemoveFromClassList("surface-notice-bad");
                _boxNotice.RemoveFromClassList("surface-notice-ok");
                if (kind == NoticeKind.Warn) _boxNotice.AddToClassList("surface-notice-warn");
                else if (kind == NoticeKind.Bad) _boxNotice.AddToClassList("surface-notice-bad");
                else if (kind == NoticeKind.Ok) _boxNotice.AddToClassList("surface-notice-ok");
            }
        }

        private void ShowAlert(string message, bool error)
        {
            if (_lblStatusAlert == null) return;
            _lblStatusAlert.text = message ?? "";
            _lblStatusAlert.RemoveFromClassList("surface-alert-ok");
            if (!error) _lblStatusAlert.AddToClassList("surface-alert-ok");
            SetVisible(_lblStatusAlert, !string.IsNullOrEmpty(message));
        }

        private void HideAlert()
        {
            SetVisible(_lblStatusAlert, false);
        }

        private void ShowRoot()
        {
            if (_root == null) return;
            _root.style.display = DisplayStyle.Flex;
            _root.BringToFront();
        }

        private void HideRoot()
        {
            if (_root != null) _root.style.display = DisplayStyle.None;
        }

        // ── Utilidades ───────────────────────────────────────────────────────

        private string CurrencyKey
        {
            get
            {
                string normalized = _request != null ? NormalizeCurrency(_request.currency) : null;
                return normalized ?? "gambits";
            }
        }

        private string CurrencyLabel
        {
            get { return CurrencyKey == "tides" ? "TIDES" : "GAMBITS"; }
        }

        private static string NormalizeCurrency(string raw)
        {
            string value = (raw ?? "").Trim().ToLowerInvariant();
            if (value == "gambits" || value == "gambit") return "gambits";
            if (value == "tides" || value == "tide") return "tides";
            return null;
        }

        private static double AmountOf(SurfaceCheckoutAmountsDto amounts, string currency)
        {
            if (amounts == null) return 0;
            return currency == "tides" ? amounts.tides : amounts.gambits;
        }

        private static double LimitOf(SurfaceCheckoutLimitsDto limits, string currency)
        {
            if (limits == null) return 0;
            return currency == "tides" ? limits.tides : limits.gambits;
        }

        private static double PerOpOf(SurfaceCheckoutLimitsDto limits, string currency)
        {
            if (limits == null || limits.perOp == null) return 0;
            return currency == "tides" ? limits.perOp.tides : limits.perOp.gambits;
        }

        private static long ToLong(double value)
        {
            if (double.IsNaN(value) || double.IsInfinity(value)) return 0;
            return (long)Math.Round(value);
        }

        private static string FormatAmount(long value)
        {
            return value.ToString("N0", CultureInfo.InvariantCulture).Replace(',', '.');
        }

        private static string PeriodTitle(string period)
        {
            if (period == "daily") return "Hoy";
            if (period == "weekly") return "Últimos 7 días";
            return "Este mes";
        }

        private static string PeriodPhrase(string period)
        {
            if (period == "daily") return "hoy";
            if (period == "weekly") return "los últimos 7 días";
            return "este mes";
        }

        private static string FormatDate(string iso)
        {
            if (string.IsNullOrEmpty(iso)) return DateTime.Now.ToString("dd/MM/yyyy · HH:mm", CultureInfo.InvariantCulture);
            DateTime parsed;
            if (DateTime.TryParse(iso, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out parsed))
            {
                return parsed.ToLocalTime().ToString("dd/MM/yyyy · HH:mm", CultureInfo.InvariantCulture);
            }
            return iso;
        }

        private static string StateClass(CheckState state)
        {
            if (state == CheckState.Ok) return "surface-check-ok";
            if (state == CheckState.Warn) return "surface-check-warn";
            if (state == CheckState.Bad) return "surface-check-bad";
            return "surface-check-neutral";
        }

        private static string StateIcon(CheckState state)
        {
            if (state == CheckState.Ok) return "✓";
            if (state == CheckState.Warn) return "!";
            if (state == CheckState.Bad) return "×";
            return "–";
        }

        private static void SetText(Label label, string text)
        {
            if (label != null) label.text = text ?? "";
        }

        private static void SetVisible(VisualElement element, bool visible)
        {
            if (element != null)
            {
                element.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
            }
        }

        private static SurfacePurchaseResult Failure(string message, string code)
        {
            return new SurfacePurchaseResult
            {
                success = false,
                cancelled = false,
                message = message,
                code = code
            };
        }
    }

    // ── Contrato público ─────────────────────────────────────────────────────

    [Serializable]
    public class SurfacePurchaseRequest
    {
        public string productId;
        public string productName;
        public string description;
        public int price;
        public string currency = "gambits";
        public string origin = "Surface";
    }

    [Serializable]
    public class SurfacePurchaseResult
    {
        public bool success;
        public bool cancelled;
        public string message;
        public string code;
        public long transactionId;
        public string productName;
        public int price;
        public string currency;
        public long previousBalance;
        public long newBalance;
        public string purchasedAt;
        public string origin;
    }

    // ── DTOs internos (JsonUtility) ──────────────────────────────────────────

    [Serializable]
    public class SurfaceCheckoutSessionDto
    {
        public bool success;
        public string error;
        public SurfaceCheckoutUserDto user;
        public SurfaceCheckoutAmountsDto balances;
        public SurfaceCheckoutAmountsDto spent;
        public SurfaceCheckoutManagementDto management;
        public SurfaceCheckoutEvaluationDto evaluation;
    }

    [Serializable]
    public class SurfaceCheckoutUserDto
    {
        public long id;
        public string username;
    }

    [Serializable]
    public class SurfaceCheckoutAmountsDto
    {
        public double gambits;
        public double tides;
    }

    [Serializable]
    public class SurfaceCheckoutManagementDto
    {
        public SurfaceCheckoutLimitsDto limits;
    }

    [Serializable]
    public class SurfaceCheckoutLimitsDto
    {
        public bool enabled;
        public string period;
        public double gambits;
        public double tides;
        public SurfaceCheckoutAmountsDto perOp;
        public int threshold;
        public bool block;
    }

    [Serializable]
    public class SurfaceCheckoutEvaluationDto
    {
        public string currency;
        public double amount;
        public double balance;
        public bool sufficientBalance;
        public bool limitEnabled;
        public string period;
        public string periodLabel;
        public double limitAmount;
        public double perOpLimit;
        public double spent;
        public double remaining;
        public double projected;
        public double percentUsed;
        public int threshold;
        public bool blockOnExceed;
        public bool limitExceeded;
        public bool perOpExceeded;
        public bool canPurchase;
        public bool blocked;
        public bool warn;
        public string code;
        public string reason;
        public string hint;
    }

    [Serializable]
    public class SurfaceCheckoutPurchaseDto
    {
        public bool success;
        public string error;
        public string code;
        public long transactionId;
        public string concept;
        public double amount;
        public string currency;
        public double previousBalance;
        public double newBalance;
        public string purchasedAt;
        public SurfaceCheckoutAmountsDto balances;
        public SurfaceCheckoutAmountsDto spent;
        public SurfaceCheckoutManagementDto management;
        public SurfaceCheckoutEvaluationDto evaluation;
    }

    [Serializable]
    internal class SurfaceCheckoutPayload
    {
        public string productId;
        public string productName;
        public string description;
        public long amount;
        public string currency;
        public string origin;
    }

    internal class SurfaceCheckoutHttpResult
    {
        public bool ok;
        public long status;
        public string text;
        public string error;
    }
}
