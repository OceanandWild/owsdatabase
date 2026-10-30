using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.Services;

namespace WilderGambit.UI
{
    /// <summary>
    /// Controlador del modal de la Tienda.
    /// Gestiona las sub-vistas: Login, Conectado y Loading.
    /// Depende de OceanPayService (singleton en escena).
    /// </summary>
    public class ShopModal : MonoBehaviour
    {
        // ── Referencias UI ────────────────────────────────────────────────────
        private VisualElement _loginView;
        private VisualElement _connectedView;
        private VisualElement _loadingView;
        private VisualElement _heroPanel;
        private VisualElement _heroBadge;

        private TextField _inputUsername;
        private TextField _inputPassword;
        private Label     _errorLabel;

        private Label _usernameLabel;
        private Label _tidesLabel;
        private Label _gambitsLabel;

        // Bóveda unificada: slots + caché de saldos para el feedback de cambio
        private VisualElement _tidesSlot;
        private VisualElement _gambitsSlot;
        private float _cachedTides   = float.NaN;
        private float _cachedGambits = float.NaN;
        private IVisualElementScheduledItem _balanceAnim;
        private VisualElement _balanceSlot;
        private Label         _balanceLabel;
        private Color         _balanceBaseColor = Color.white;
        private bool   _balanceUp;
        private float  _balanceT;
        private const float BALANCE_FEEDBACK_DUR = 0.9f;

        // Header User Area
        private VisualElement _headerUserArea;
        private Label         _headerUsername;
        private Label         _avatarInitial;

        private Button _btnLogin;
        private Button _btnRegister;
        private Button _btnLogout;

        private bool _isBusy = false;
        private Coroutine _cursorBlinkCoroutine;
        private TextField _focusedField;
        private int _retryCount = 0;
        private const int MAX_RETRIES = 2;
        private const float REQUEST_TIMEOUT = 15f;

        // ── Animación del estado de carga (skeletons + barra + contador) ────
        private IVisualElementScheduledItem _loadingAnim;
        private List<VisualElement> _skeletonCards;
        private VisualElement _loadingBarFill;
        private Label  _loadingPercent;
        private Label  _loadingTextLabel;
        private string _loadingBaseText;
        private bool   _animateLoadingDots;
        private string _loadingPercentCache;
        private const float PCT_RATE = 42f; // puntos de progreso por segundo (0 → 100 en ~2.4s)
        private float  _loadingT;

        // Root element reference for background selector
        private VisualElement _shopModalRoot;

        // Carrito del Atelier: selección en memoria + checkout único de Surface
        private ShopCart _cart;
        private ShopCartUI _cartUI;
        private Button _btnDetailCart;
        private IShopCartSource _activeCartSource;

        // ── Inicialización ────────────────────────────────────────────────────

        public void Initialize(VisualElement shopModalRoot)
        {
            _shopModalRoot = shopModalRoot;

            _loginView     = shopModalRoot.Q<VisualElement>("shop-login-view");
            _connectedView = shopModalRoot.Q<VisualElement>("shop-connected-view");
            _loadingView   = shopModalRoot.Q<VisualElement>("shop-loading-view");

            // Cache de elementos del estado de carga (para la animación concurrente)
            if (_loadingView != null)
            {
                _skeletonCards   = _loadingView.Query(className: "shop2-skeleton-card").ToList();
                _loadingBarFill  = _loadingView.Q(className: "shop2-loading-bar-fill");
                _loadingPercent  = _loadingView.Q<Label>(className: "shop2-loading-percent");
                _loadingTextLabel = _loadingView.Q<Label>(className: "shop2-loading-text");
            }
            _heroPanel     = shopModalRoot.Q<VisualElement>("bg-preview-panel");
            _heroBadge     = _heroPanel?.Q<VisualElement>(className: "shop2-hero-badge");

            // Header User Profile
            _headerUserArea = shopModalRoot.Q<VisualElement>("shop-header-user-area");
            _headerUsername = shopModalRoot.Q<Label>("shop-header-username");
            _avatarInitial  = shopModalRoot.Q<Label>("shop-avatar-initial");

            _inputUsername = shopModalRoot.Q<TextField>("shop-input-username");
            _inputPassword = shopModalRoot.Q<TextField>("shop-input-password");
            _errorLabel    = shopModalRoot.Q<Label>("shop-error-label");

            if (_inputPassword != null)
            {
                _inputPassword.isPasswordField = true;
                _inputPassword.maskChar = '•';
            }

            SetupFieldEvents(_inputUsername);
            SetupFieldEvents(_inputPassword);

            // Atajos de teclado para UI Toolkit (Enter para enviar, Tab para alternar)
            _inputUsername?.RegisterCallback<KeyDownEvent>(evt =>
            {
                if (evt.keyCode == KeyCode.Return || evt.keyCode == KeyCode.KeypadEnter)
                {
                    OnLoginClicked();
                    evt.StopPropagation();
                }
                else if (evt.keyCode == KeyCode.Tab)
                {
                    _inputPassword?.Focus();
                    evt.StopPropagation();
                }
            });

            _inputPassword?.RegisterCallback<KeyDownEvent>(evt =>
            {
                if (evt.keyCode == KeyCode.Return || evt.keyCode == KeyCode.KeypadEnter)
                {
                    OnLoginClicked();
                    evt.StopPropagation();
                }
                else if (evt.keyCode == KeyCode.Tab)
                {
                    _inputUsername?.Focus();
                    evt.StopPropagation();
                }
            });

            _usernameLabel = shopModalRoot.Q<Label>("shop-username-label");
            _tidesLabel    = shopModalRoot.Q<Label>("shop-tides-label");
            _gambitsLabel  = shopModalRoot.Q<Label>("shop-gambits-label");
            _tidesSlot     = shopModalRoot.Q<VisualElement>("shop-slot-tides");
            _gambitsSlot   = shopModalRoot.Q<VisualElement>("shop-slot-gambits");

            _btnLogin    = shopModalRoot.Q<Button>("btn-shop-login");
            _btnRegister = shopModalRoot.Q<Button>("btn-shop-register");
            _btnLogout   = shopModalRoot.Q<Button>("btn-shop-logout");

            _btnLogin?.RegisterCallback<ClickEvent>(_ => OnLoginClicked());
            _btnRegister?.RegisterCallback<ClickEvent>(_ => OnRegisterClicked());
            _btnLogout?.RegisterCallback<ClickEvent>(_ => OnLogoutClicked());

            // Carrito: el modelo vive con el modal; el overlay se engancha al UXML.
            _cart = new ShopCart();
            _btnDetailCart = shopModalRoot.Q<Button>("btn-detail-cart");
            _btnDetailCart?.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                _activeCartSource?.TryAddSelectedToCart();
            });

            _cartUI = new ShopCartUI(shopModalRoot, _cart, OnCartPaid, OnCartChanged);
            _cart.ItemAdded += item =>
                _cartUI?.ShowToast("«" + item.displayName + "» se añadió al carrito.");
            _cart.AddRejected += message => _cartUI?.ShowToast(message, true);

            _tabBoards     = shopModalRoot.Q<Button>("tab-boards");
            _tabPieces     = shopModalRoot.Q<Button>("tab-pieces");
            _tabAnimations = shopModalRoot.Q<Button>("tab-animations");
            _tabFonds      = shopModalRoot.Q<Button>("tab-fonds");

            // Pestaña de variantes: "tab-variants" (copia _Project); en la copia
            // Resources esa misma categoría es "tab-pieces" (02 VARIANTES del rail).
            _tabVariants = shopModalRoot.Q<Button>("tab-variants") ?? _tabPieces;

            // Pestaña de skins: "tab-skins" (nueva sección SKINS, solo visuales).
            // Fallback a "tab-pieces" por si el UXML aún no se ha actualizado.
            _tabSkins = shopModalRoot.Q<Button>("tab-skins") ?? _tabPieces;

            _categoryTabs = new List<Button>();
            foreach (var tab in new[] { _tabBoards, _tabFonds, _tabVariants, _tabSkins, _tabPieces, _tabAnimations })
            {
                if (tab == null || _categoryTabs.Contains(tab)) continue; // sin duplicados
                _categoryTabs.Add(tab);
            }
            foreach (var tab in _categoryTabs)
            {
                var target = tab;
                target.RegisterCallback<ClickEvent>(_ => SelectTab(target));
            }

            _countBoards     = shopModalRoot.Q<Label>("shop-count-boards");
            _countFonds      = shopModalRoot.Q<Label>("shop-count-fonds");
            _countVariants   = shopModalRoot.Q<Label>("shop-count-variants");
            _countSkins      = shopModalRoot.Q<Label>("shop-count-skins");
            _countAnimations = shopModalRoot.Q<Label>("shop-count-animations");

            SetupPagination(shopModalRoot);
        }

        private Button _tabBoards;
        private Button _tabPieces;
        private Button _tabAnimations;
        private Button _tabFonds;
        private Button _tabVariants;
        private Button _tabSkins;
        private List<Button> _categoryTabs;

        // Contadores reales de cada pestaña (se refrescan contra la fuente del catálogo)
        private Label _countBoards;
        private Label _countFonds;
        private Label _countVariants;
        private Label _countSkins;
        private Label _countAnimations;

        // Background selector
        private ShopBackgroundSelector _bgSelector;
        private ShopBackdropSelector _backdropSelector;
        private ShopGridPager _gridPager;

        // Variant selector (pestaña de variantes de piezas)
        private ShopVariantSelector _variantSelector;

        // Skin selector (pestaña de aspectos visuales: solo visuales, sin pasiva)
        private ShopSkinSelector _skinSelector;

        // Animation selector (pestaña de animaciones: FX de evento por gatillo)
        private ShopAnimationSelector _animationSelector;

        /// <summary>Paginación global del catálogo: capacidad por espacio real, compartida por todas las pestañas.</summary>
        public ShopGridPager GridPager => _gridPager;

        private void SelectTab(Button targetTab)
        {
            if (targetTab == null) return;
            foreach (var tab in _categoryTabs)
            {
                if (tab == null) continue;
                if (tab == targetTab)
                {
                    tab.AddToClassList("shop-tab-active");
                    tab.AddToClassList("shop2-nav-active");
                }
                else
                {
                    tab.RemoveFromClassList("shop-tab-active");
                    tab.RemoveFromClassList("shop2-nav-active");
                }
            }

            // TABLEROS → catálogo de tableros; FONDOS → catálogo de fondos ambiente;
            // VARIANTES → catálogo de variantes de piezas
            if (targetTab == _tabBoards)
            {
                ClearSharedDetailMarkers();
                _backdropSelector?.CloseDetail();
                _bgSelector?.CloseDetailIfVariant(); // el detalle de variantes no cruza de pestaña
                _bgSelector?.Refresh();
            }
            else if (targetTab == _tabFonds)
            {
                ClearSharedDetailMarkers();
                _bgSelector?.CloseDetail(); // el panel de detalle pertenece a los tableros
                _backdropSelector?.Refresh();
            }
            else if (targetTab == _tabVariants)
            {
                ClearSharedDetailMarkers();
                _bgSelector?.CloseDetail(); // el panel de detalle pertenece a los tableros
                _backdropSelector?.CloseDetail();
                _variantSelector?.Refresh();
            }
            else if (targetTab == _tabSkins)
            {
                ClearSharedDetailMarkers();
                _bgSelector?.CloseDetail(); // el panel de detalle pertenece a los tableros
                _backdropSelector?.CloseDetail();
                _skinSelector?.Refresh();
            }
            else if (targetTab == _tabAnimations)
            {
                ClearSharedDetailMarkers();
                _bgSelector?.CloseDetail(); // el panel de detalle pertenece a los tableros
                _backdropSelector?.CloseDetail();
                _animationSelector?.Refresh();
            }

            RefreshActiveCartSource();
            RefreshCategoryChrome();
        }

        /// <summary>
        /// Sincroniza los contadores de las pestañas con el catálogo real: las
        /// listas cambian (skins nuevas, exclusivos de evento fuera de la tienda)
        /// y el UXML no debe quedarse con números escritos a mano.
        /// </summary>
        private void RefreshCategoryChrome()
        {
            if (_bgSelector != null)        SetTabCount(_countBoards, _bgSelector.ShopCount);
            if (_backdropSelector != null)  SetTabCount(_countFonds, _backdropSelector.ShopCount);
            if (_variantSelector != null)   SetTabCount(_countVariants, ShopVariantSelector.Count);
            if (_skinSelector != null)      SetTabCount(_countSkins, ShopSkinSelector.Count);
            if (_animationSelector != null) SetTabCount(_countAnimations, ShopAnimationSelector.Count);
        }

        private static void SetTabCount(Label label, int count)
        {
            if (label != null) label.text = Mathf.Max(0, count).ToString();
        }

        /// <summary>
        /// El panel de detalle es compartido por todas las pestañas y cada una lo
        /// marca con su clase (variantes / paquetes). Al cambiar de pestaña se
        /// retiran las marcas para que el CTA de la pestaña anterior no atienda
        /// compras que ya no están en pantalla (el panel se oculta pero conserva clases).
        /// </summary>
        private void ClearSharedDetailMarkers()
        {
            if (_shopModalRoot == null) return;
            var detail = _shopModalRoot.Q<VisualElement>("shop2-detail");
            if (detail == null) return;
            ShopVariantSelector.ClearVariantDetail(detail);
            ShopAnimationSelector.ClearAnimDetail(detail);
            ShopBackdropSelector.ClearBackdropDetail(detail);
            ShopSkinSelector.ClearSkinDetail(detail);
            _animationSelector?.HidePreviewEntry();
        }

        private static bool IsTabActive(Button tab)
        {
            return tab != null && (tab.ClassListContains("shop-tab-active") || tab.ClassListContains("shop2-nav-active"));
        }

        /// <summary>Repinta el catálogo de la pestaña activa (tableros, fondos, variantes, skins o animaciones).</summary>
        private void RefreshActiveCatalog()
        {
            if (_tabVariants != null && IsTabActive(_tabVariants)) _variantSelector?.Refresh();
            else if (_tabSkins != null && IsTabActive(_tabSkins)) _skinSelector?.Refresh();
            else if (_tabAnimations != null && IsTabActive(_tabAnimations)) _animationSelector?.Refresh();
            else if (_tabFonds != null && IsTabActive(_tabFonds)) _backdropSelector?.Refresh();
            else _bgSelector?.Refresh();

            RefreshActiveCartSource();
        }

        /// <summary>
        /// La pestaña activa es la dueña del CTA del panel de detalle. El botón
        /// de carrito se rutea a esa fuente y se repinta con su selección actual.
        /// </summary>
        private void RefreshActiveCartSource()
        {
            if (_tabVariants != null && IsTabActive(_tabVariants)) _activeCartSource = _variantSelector;
            else if (_tabSkins != null && IsTabActive(_tabSkins)) _activeCartSource = _skinSelector;
            else if (_tabAnimations != null && IsTabActive(_tabAnimations)) _activeCartSource = _animationSelector;
            else if (_tabFonds != null && IsTabActive(_tabFonds)) _activeCartSource = _backdropSelector;
            else _activeCartSource = _bgSelector;

            _activeCartSource?.RefreshCartButton();
        }

        // ── Carrito ─────────────────────────────────────────────────────────

        private void OnCartChanged()
        {
            _activeCartSource?.RefreshCartButton();
        }

        private void OnCartPaid()
        {
            // El detalle abierto puede mostrar algo que acaba de comprarse:
            // se colapsa antes de repintar el catálogo activo.
            _bgSelector?.CloseDetail();
            RefreshVaultChips();
            RefreshActiveCatalog();
        }

        /// <summary>
        /// Cada compra directa avisa por acá: refresca la bóveda y saca del
        /// carrito lo que acaba de entrar al inventario para no cobrarlo dos veces.
        /// </summary>
        private void OnStoreBalanceChanged()
        {
            RefreshVaultChips();
            if (_cart == null || _cart.IsEmpty) return;

            int pruned = _cart.PruneOwned();
            if (pruned <= 0) return;

            _cartUI?.ShowToast(pruned == 1
                ? "Quitamos del carrito un artículo que ya compraste."
                : "Quitamos del carrito " + pruned + " artículos que ya compraste.");
        }

        /// <summary>Sincroniza el chip de Gambits del header tras una compra en la tienda.</summary>
        private void RefreshGambitsChip()
        {
            SetBalance(_gambitsLabel, _gambitsSlot, PieceSkinManager.GetLocalGambits(), ref _cachedGambits);
        }

        /// <summary>
        /// Sincroniza ambos chips de la bóveda (Tides + Gambits) tras comprar un
        /// paquete. Lee la sesión de Surface si existe, si no el fallback local.
        /// Si el valor no cambió, SetBalance no anima (es solo un repintado).
        /// </summary>
        private void RefreshVaultChips()
        {
            var svc = OceanPayService.Instance;
            if (svc != null && svc.CurrentUser != null)
            {
                SetBalance(_tidesLabel,   _tidesSlot,   svc.CurrentUser.tides,   ref _cachedTides);
                SetBalance(_gambitsLabel, _gambitsSlot, svc.CurrentUser.gambits, ref _cachedGambits);
            }
            else
            {
                SetBalance(_tidesLabel, _tidesSlot, PlayerPrefs.GetInt("PlayerTides", 0), ref _cachedTides);
                RefreshGambitsChip();
            }
        }

        private void SetupPagination(VisualElement root)
        {
            var p1 = root.Q<Button>("btn-page-1");
            var p2 = root.Q<Button>("btn-page-2");
            var p3 = root.Q<Button>("btn-page-3");
            var pages = new List<Button> { p1, p2, p3 };

            System.Action<Button> selectPage = selected =>
            {
                foreach (var p in pages)
                {
                    if (p == null) continue;
                    if (p == selected)
                        p.AddToClassList("page-active");
                    else
                        p.RemoveFromClassList("page-active");
                }
                // Also notify selector to change page if needed (kept for compatibility,
                // real pagination is handled by ShopGridPager)
            };

            p1?.RegisterCallback<ClickEvent>(_ => selectPage(p1));
            p2?.RegisterCallback<ClickEvent>(_ => selectPage(p2));
            p3?.RegisterCallback<ClickEvent>(_ => selectPage(p3));
        }

        private void SetupFieldEvents(TextField field)
        {
            if (field == null) return;

            field.RegisterCallback<FocusInEvent>(_ =>
            {
                _focusedField = field;
                field.RemoveFromClassList("cursor-hidden");
                StartCursorBlink();
            });

            field.RegisterCallback<FocusOutEvent>(_ =>
            {
                field.RemoveFromClassList("cursor-hidden");
                if (_focusedField == field)
                {
                    _focusedField = null;
                    StopCursorBlink();
                }
            });
        }

        private void StartCursorBlink()
        {
            StopCursorBlink();
            if (gameObject.activeInHierarchy)
            {
                _cursorBlinkCoroutine = StartCoroutine(CursorBlinkLoop());
            }
        }

        private void StopCursorBlink()
        {
            if (_cursorBlinkCoroutine != null)
            {
                StopCoroutine(_cursorBlinkCoroutine);
                _cursorBlinkCoroutine = null;
            }
            _inputUsername?.RemoveFromClassList("cursor-hidden");
            _inputPassword?.RemoveFromClassList("cursor-hidden");
        }

        private IEnumerator CursorBlinkLoop()
        {
            bool visible = true;
            while (_focusedField != null)
            {
                if (visible)
                    _focusedField.RemoveFromClassList("cursor-hidden");
                else
                    _focusedField.AddToClassList("cursor-hidden");

                visible = !visible;
                yield return new WaitForSecondsRealtime(0.53f);
            }
            _inputUsername?.RemoveFromClassList("cursor-hidden");
            _inputPassword?.RemoveFromClassList("cursor-hidden");
        }

        private void OnDisable()
        {
            StopCursorBlink();
            StopBalanceFeedback();
        }

        private Coroutine _currentRequestCoroutine;

        // ── Llamado al abrir/cerrar el modal ──────────────────────────────────

        public void OnShopOpened()
        {
            StopRunningRequests();
            HideError();
            EnsureService();
            _retryCount = 0;

            // Visual: brasas sutiles de fondo en la tienda
            ShopEmberField.Start(_shopModalRoot);

            // El carrito sobrevive al cierre: al reabrir se oculta el overlay y
            // se depura lo que ya entró al inventario por otra vía.
            _cartUI?.Close();
            _cartUI?.HideToast();
            int pruned = _cart != null ? _cart.PruneOwned() : 0;
            if (pruned > 0)
            {
                _cartUI?.ShowToast(pruned == 1
                    ? "Quitamos del carrito un artículo que ya estaba en tu inventario."
                    : "Quitamos del carrito " + pruned + " artículos que ya estaban en tu inventario.");
            }

            // Initialize background selector if not done yet
            if (_bgSelector == null && _shopModalRoot != null)
            {
                _gridPager = new ShopGridPager(_shopModalRoot);
                _bgSelector = new ShopBackgroundSelector(_shopModalRoot, _gridPager, _cart);
                _bgSelector.BalanceChanged += OnStoreBalanceChanged;
                _backdropSelector = new ShopBackdropSelector(_shopModalRoot, _gridPager, _cart);
                _backdropSelector.BalanceChanged += OnStoreBalanceChanged;
                _variantSelector = new ShopVariantSelector(_shopModalRoot, _gridPager, _bgSelector, _cart);
                _variantSelector.BalanceChanged += OnStoreBalanceChanged;
                _skinSelector = new ShopSkinSelector(_shopModalRoot, _gridPager, _bgSelector, _cart);
                _skinSelector.BalanceChanged += OnStoreBalanceChanged;
                _animationSelector = new ShopAnimationSelector(_shopModalRoot, _gridPager, _bgSelector, _cart);
                _animationSelector.BalanceChanged += OnStoreBalanceChanged;
            }

            // También al reabrir: el pase pudo desbloquear un tablero o un fondo
            // mientras la tienda estaba cerrada, y la pestaña activa debe verlo.
            RefreshActiveCatalog();
            RefreshCategoryChrome();
            _cartUI?.Refresh();

            if (OceanPayService.Instance != null && OceanPayService.Instance.IsLoggedIn)
                _currentRequestCoroutine = StartCoroutine(TryAutoLogin());
            else
                ShowLoginView();
        }

        public void OnShopClosed()
        {
            StopRunningRequests();
            StopCursorBlink();
            StopBalanceFeedback();
            _cartUI?.Close();
            ShopEmberField.Stop();
        }

        private void StopRunningRequests()
        {
            _isBusy = false;
            if (_currentRequestCoroutine != null)
            {
                StopCoroutine(_currentRequestCoroutine);
                _currentRequestCoroutine = null;
            }
        }

        // ── Auto-login con token guardado ─────────────────────────────────────

        private IEnumerator TryAutoLogin()
        {
            ShowLoadingView("Verificando sesión guardada...");
            bool done = false;

            yield return OceanPayService.Instance.TryAutoLoginAsync(
                onSuccess: user =>
                {
                    done = true;
                    _currentRequestCoroutine = null;
                    ShowConnectedView(user);
                },
                onFail: () =>
                {
                    done = true;
                    _currentRequestCoroutine = null;
                    ShowLoginView();
                }
            );

            if (!done)
            {
                _currentRequestCoroutine = null;
                ShowLoginView();
                ShowError("La sesión guardada expiró o el servidor no responde. Inicia sesión manualmente.");
            }
        }

        // ── Botón: Iniciar sesión ─────────────────────────────────────────────

        private void OnLoginClicked()
        {
            if (_isBusy) return;
            var username = _inputUsername?.value?.Trim() ?? "";
            var password = _inputPassword?.value?.Trim() ?? "";

            if (string.IsNullOrEmpty(username)) { ShowError("Ingresa tu usuario."); return; }
            if (string.IsNullOrEmpty(password)) { ShowError("Ingresa tu contraseña."); return; }

            _retryCount = 0;
            StopRunningRequests();
            _currentRequestCoroutine = StartCoroutine(DoLogin(username, password));
        }

        private IEnumerator DoLogin(string username, string password)
        {
            _isBusy = true;
            ShowLoadingView("Conectando con Surface...");
            EnsureService();

            bool done = false;
            string errorMsg = null;

            yield return OceanPayService.Instance.LoginAsync(
                username, password,
                onSuccess: user =>
                {
                    done = true;
                    _retryCount = 0;
                    _isBusy = false;
                    _currentRequestCoroutine = null;
                    ShowConnectedView(user);
                },
                onError: err =>
                {
                    done = true;
                    errorMsg = err;
                }
            );

            if (done && errorMsg == null) yield break; // success

            _isBusy = false;
            _currentRequestCoroutine = null;

            if (!done)
            {
                // Coroutine was stopped externally or timed out
                ShowLoginView();
                ShowError("La conexión tardó demasiado. Verifica tu internet e intenta de nuevo.");
                yield break;
            }

            // Classify the error and decide retry
            string userMsg = ClassifyLoginError(errorMsg);

            if (_retryCount < MAX_RETRIES && IsRetryableError(errorMsg))
            {
                _retryCount++;
                ShowLoadingView($"Reintentando... ({_retryCount}/{MAX_RETRIES})");
                yield return new WaitForSecondsRealtime(1.5f);
                _currentRequestCoroutine = StartCoroutine(DoLogin(username, password));
                yield break;
            }

            _retryCount = 0;
            ShowLoginView();
            ShowError(userMsg);
        }

        // ── Botón: Registrarse ────────────────────────────────────────────────

        private void OnRegisterClicked()
        {
            if (_isBusy) return;
            var username = _inputUsername?.value?.Trim() ?? "";
            var password = _inputPassword?.value?.Trim() ?? "";

            if (string.IsNullOrEmpty(username)) { ShowError("Ingresa un nombre de usuario."); return; }
            if (password.Length < 4)            { ShowError("La contraseña debe tener al menos 4 caracteres."); return; }

            StopRunningRequests();
            _currentRequestCoroutine = StartCoroutine(DoRegister(username, password));
        }

        private IEnumerator DoRegister(string username, string password)
        {
            _isBusy = true;
            ShowLoadingView("Creando tu cuenta...");
            EnsureService();

            bool done = false;
            string errorMsg = null;

            yield return OceanPayService.Instance.RegisterAsync(
                username, password,
                onSuccess: user =>
                {
                    done = true;
                    _retryCount = 0;
                    _isBusy = false;
                    _currentRequestCoroutine = null;
                    ShowConnectedView(user);
                },
                onError: err =>
                {
                    done = true;
                    errorMsg = err;
                }
            );

            if (done && errorMsg == null) yield break;

            _isBusy = false;
            _currentRequestCoroutine = null;

            if (!done)
            {
                ShowLoginView();
                ShowError("La conexión tardó demasiado. Verifica tu internet e intenta de nuevo.");
                yield break;
            }

            string userMsg = ClassifyRegisterError(errorMsg);

            if (_retryCount < MAX_RETRIES && IsRetryableError(errorMsg))
            {
                _retryCount++;
                ShowLoadingView($"Reintentando... ({_retryCount}/{MAX_RETRIES})");
                yield return new WaitForSecondsRealtime(1.5f);
                _currentRequestCoroutine = StartCoroutine(DoRegister(username, password));
                yield break;
            }

            _retryCount = 0;
            ShowLoginView();
            ShowError(userMsg);
        }

        // ── Botón: Cerrar sesión ──────────────────────────────────────────────

        private void OnLogoutClicked()
        {
            _retryCount = 0;
            if (OceanPayService.Instance != null)
                OceanPayService.Instance.ClearSession();
            ShowLoginView();
        }

        // ── Error Classification ────────────────────────────────────────────

        /// <summary>Returns true if the error is transient and worth retrying.</summary>
        private static bool IsRetryableError(string error)
        {
            if (string.IsNullOrEmpty(error)) return false;
            string lower = error.ToLowerInvariant();
            return lower.Contains("timeout") || lower.Contains("conexión") ||
                   lower.Contains("connection") || lower.Contains("network") ||
                   lower.Contains("unreachable") || lower.Contains("dns") ||
                   lower.Contains("ssl") || lower.Contains("tls");
        }

        private static string ClassifyLoginError(string error)
        {
            if (string.IsNullOrEmpty(error))
                return "Error desconocido. Intenta de nuevo.";

            string lower = error.ToLowerInvariant();

            if (lower.Contains("timeout") || lower.Contains("timed out"))
                return "⏳ El servidor tardó demasiado en responder. Tu conexión puede ser lenta.";

            if (lower.Contains("connection refused") || lower.Contains("unreachable") || lower.Contains("dns"))
                return "🔌 No se pudo alcanzar el servidor. Verifica tu conexión a internet.";

            if (lower.Contains("ssl") || lower.Contains("tls") || lower.Contains("certificate"))
                return "🔒 Error de seguridad (SSL). Actualiza tu sistema y vuelve a intentar.";

            if (lower.Contains("invalid") || lower.Contains("incorrect") || lower.Contains("credenciales"))
                return "❌ Usuario o contraseña incorrectos.";

            if (lower.Contains("network") || lower.Contains("connect"))
                return "📡 Error de red. Verifica tu conexión a internet.";

            if (lower.Contains("500") || lower.Contains("502") || lower.Contains("503"))
                return "🛠️ El servidor está temporalmente fuera de servicio. Intenta en unos minutos.";

            return "⚠️ " + error;
        }

        private static string ClassifyRegisterError(string error)
        {
            if (string.IsNullOrEmpty(error))
                return "Error desconocido. Intenta de nuevo.";

            string lower = error.ToLowerInvariant();

            if (lower.Contains("timeout") || lower.Contains("timed out"))
                return "⏳ El servidor tardó demasiado. Tu conexión puede ser lenta.";

            if (lower.Contains("connection refused") || lower.Contains("unreachable") || lower.Contains("dns"))
                return "🔌 No se pudo alcanzar el servidor. Verifica tu conexión a internet.";

            if (lower.Contains("already exists") || lower.Contains("ya existe") || lower.Contains("taken"))
                return "👤 Ese nombre de usuario ya está registrado. Prueba con otro.";

            if (lower.Contains("network") || lower.Contains("connect"))
                return "📡 Error de red. Verifica tu conexión a internet.";

            if (lower.Contains("500") || lower.Contains("502") || lower.Contains("503"))
                return "🛠️ El servidor está temporalmente fuera de servicio. Intenta en unos minutos.";

            return "⚠️ " + error;
        }

        // ── Switch de vistas — ATELIER NOIR ───────────────────────────────────

        private void ShowLoginView()
        {
            StopLoadingAnimation();
            _loginView?.RemoveFromClassList("hidden");
            _connectedView?.AddToClassList("hidden");
            _loadingView?.AddToClassList("hidden");
            _heroPanel?.AddToClassList("hidden");

            _headerUserArea?.AddToClassList("hidden");
            _btnLogout?.AddToClassList("hidden");

            if (_inputPassword != null) _inputPassword.value = "";

            _cartUI?.Refresh();
            _inputUsername?.Focus();
        }

        private void ShowConnectedView(OceanPayUser user)
        {
            StopLoadingAnimation();
            _loginView?.AddToClassList("hidden");
            _connectedView?.RemoveFromClassList("hidden");
            _loadingView?.AddToClassList("hidden");
            _heroPanel?.RemoveFromClassList("hidden");

            _headerUserArea?.RemoveFromClassList("hidden");
            _btnLogout?.RemoveFromClassList("hidden");

            if (user == null) return;

            if (_headerUsername != null) _headerUsername.text = user.username;
            if (_avatarInitial  != null) _avatarInitial.text  = !string.IsNullOrEmpty(user.username) ? user.username.Substring(0, 1).ToUpper() : "W";

            if (_usernameLabel != null) _usernameLabel.text = $"{user.username}";
            SetBalance(_tidesLabel,   _tidesSlot,   user.tides,   ref _cachedTides);
            SetBalance(_gambitsLabel, _gambitsSlot, user.gambits, ref _cachedGambits);

            // Refresh hero badge state (catálogo de la pestaña activa)
            RefreshActiveCatalog();
            _cartUI?.Refresh();
        }

        private void ShowLoadingView(string message = null)
        {
            _loginView?.AddToClassList("hidden");
            _connectedView?.AddToClassList("hidden");
            _loadingView?.RemoveFromClassList("hidden");
            _heroPanel?.AddToClassList("hidden");

            // Update loading text if a custom message is provided
            if (!string.IsNullOrEmpty(message) && _loadingView != null)
            {
                var loadingLabel = _loadingView.Q<Label>(className: "shop2-loading-text");
                if (loadingLabel != null)
                    loadingLabel.text = message;
                else
                {
                    var fallback = _loadingView.Q<Label>();
                    if (fallback != null) fallback.text = message;
                }
                SetLoadingBaseText(message);
            }

            StartLoadingAnimation();
        }

        // ── Animación del estado de carga ───────────────────────────────────

        /// <summary>
        /// Arranca la animación concurrente del estado de carga: shimmer escalonado
        /// en los skeletons (arriba), barrido de la barra de progreso, contador de
        /// porcentaje y puntos "..." animados en el mensaje (abajo).
        /// </summary>
        private void StartLoadingAnimation()
        {
            if (_loadingView == null) return;

            if (_loadingTextLabel == null)
                _loadingTextLabel = _loadingView.Q<Label>(className: "shop2-loading-text");
            if (_loadingBaseText == null && _loadingTextLabel != null)
                SetLoadingBaseText(_loadingTextLabel.text);

            _loadingT = 0f;
            _loadingPercentCache = null;

            if (_loadingAnim == null)
                _loadingAnim = _loadingView.schedule.Execute(TickLoadingAnimation).Every(16);
            else
                _loadingAnim.Resume();
        }

        private void StopLoadingAnimation()
        {
            _loadingAnim?.Pause();
        }

        /// <summary>Guarda el mensaje base; si termina en puntos, se animan aparte.</summary>
        private void SetLoadingBaseText(string message)
        {
            if (string.IsNullOrEmpty(message)) return;
            _animateLoadingDots = message.EndsWith(".") || message.EndsWith("…");
            _loadingBaseText = _animateLoadingDots
                ? message.TrimEnd('.', '…').TrimEnd()
                : message;
        }

        private void TickLoadingAnimation()
        {
            if (_loadingView == null || _loadingView.ClassListContains("hidden")) return;

            _loadingT += Time.unscaledDeltaTime;

            // 1) Skeletons (arriba): pulso de opacidad + flotación escalonada
            if (_skeletonCards != null)
            {
                for (int i = 0; i < _skeletonCards.Count; i++)
                {
                    var card = _skeletonCards[i];
                    if (card == null) continue;
                    float wave = 0.5f + 0.5f * Mathf.Sin(
                        Mathf.Repeat(_loadingT * 0.85f - i * 0.14f, 1f) * Mathf.PI * 2f);
                    card.style.opacity = Mathf.Lerp(0.35f, 0.95f, wave);
                    card.style.translate = new Translate(
                        new Length(0f, LengthUnit.Pixel),
                        new Length(Mathf.Lerp(0f, -4f, wave), LengthUnit.Pixel));
                }
            }

            // 2) Contador de datos:0 → 100; al llegar, indica los segundos adicionales
            int pct = Mathf.Min(100, Mathf.RoundToInt(_loadingT * PCT_RATE));
            if (_loadingPercent != null)
            {
                string pctText;
                if (pct < 100)
                {
                    pctText = pct + "%";
                }
                else
                {
                    // Llegó al 100%: informa cuántos segundos adicionales lleva cargando
                    float extra = _loadingT - 100f / PCT_RATE;
                    int secs = Mathf.Max(1, Mathf.CeilToInt(extra));
                    pctText = $"100% (+{secs}s)";
                }

                if (pctText != _loadingPercentCache)
                {
                    _loadingPercentCache = pctText;
                    _loadingPercent.text = pctText;
                }
            }

            // 3) Barra (abajo): crece sincronizada con el contador hasta el 100%
            if (_loadingBarFill != null)
            {
                float p = pct / 100f;
                _loadingBarFill.style.translate = new Translate(
                    new Length(Mathf.Lerp(-100f, 0f, p), LengthUnit.Percent),
                    new Length(0f, LengthUnit.Pixel));
                // Al 100% late suave mientras la carga se alarga; antes, pulso de carga
                _loadingBarFill.style.opacity = pct >= 100
                    ? 0.85f + 0.15f * Mathf.Sin(_loadingT * 4f)
                    : 0.7f + 0.3f * Mathf.Sin(_loadingT * 3.14f);
            }

            // 4) Mensaje con puntos animados
            if (_loadingTextLabel != null && _animateLoadingDots && _loadingBaseText != null)
            {
                int dots = Mathf.FloorToInt(_loadingT * 2.6f) % 4;
                _loadingTextLabel.text = _loadingBaseText + new string('.', dots);
            }
        }

        // ── Error label ───────────────────────────────────────────────────────

        private void ShowError(string message)
        {
            if (_errorLabel == null) return;
            _errorLabel.text = message;
            _errorLabel.RemoveFromClassList("hidden");
        }

        private void HideError()
        {
            _errorLabel?.AddToClassList("hidden");
            if (_errorLabel != null) _errorLabel.text = "";
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /// <summary>
        /// Escribe el saldo en el slot de la bóveda y, si el valor cambió, dispara
        /// el feedback visual (flash de color + pulso). La primera escritura
        /// (cache sin primed) no anima: es la carga inicial, no un cambio de saldo.
        /// </summary>
        private void SetBalance(Label label, VisualElement slot, float value, ref float cache)
        {
            if (label == null) return;

            bool primed    = !float.IsNaN(cache);
            float previous = cache;
            cache = value;

            label.text = FormatBalance(value);

            if (primed && !Mathf.Approximately(previous, value))
                PlayBalanceFeedback(slot, label, value > previous);
        }

        private void PlayBalanceFeedback(VisualElement slot, Label label, bool increased)
        {
            if (slot == null) return;

            StopBalanceFeedback();

            _balanceSlot      = slot;
            _balanceLabel     = label;
            _balanceBaseColor = label != null ? label.resolvedStyle.color : Color.white;
            _balanceUp        = increased;
            _balanceT         = 0f;

            if (_balanceAnim == null)
                _balanceAnim = slot.schedule.Execute(TickBalanceFeedback).Every(16);
            else
            {
                _balanceAnim.Pause();
                _balanceAnim.Resume();
            }
        }

        private void TickBalanceFeedback()
        {
            if (_balanceSlot == null) { StopBalanceFeedback(); return; }

            _balanceT += Time.unscaledDeltaTime;
            float p = Mathf.Clamp01(_balanceT / BALANCE_FEEDBACK_DUR);

            // Flash: entra fuerte y decae (cuadrático para que la cola sea suave)
            float fade = (1f - p) * (1f - p);

            // Verde si el saldo sube, rojo si baja; se mezcla sobre fondo transparente
            Color flashColor = _balanceUp
                ? new Color(0.37f, 0.88f, 0.63f, 0.30f)
                : new Color(0.91f, 0.38f, 0.38f, 0.30f);
            _balanceSlot.style.backgroundColor = new Color(flashColor.r, flashColor.g, flashColor.b, flashColor.a * fade);

            if (_balanceLabel != null)
                _balanceLabel.style.color = Color.Lerp(_balanceBaseColor, flashColor, fade * 1.6f);

            // Pulso: sube rápido y se apaga (senoidal amortiguada)
            if (p < 1f)
            {
                float pulse = Mathf.Sin(p * Mathf.PI) * Mathf.Exp(-p * 1.4f);
                float s = 1f + 0.075f * pulse;
                _balanceSlot.style.scale = new Scale(new Vector2(s, s));
            }

            if (p >= 1f) StopBalanceFeedback();
        }

        private void StopBalanceFeedback()
        {
            _balanceAnim?.Pause();
            if (_balanceSlot != null)
            {
                _balanceSlot.style.backgroundColor = StyleKeyword.Null;
                _balanceSlot.style.scale = StyleKeyword.Null;
            }
            if (_balanceLabel != null)
                _balanceLabel.style.color = StyleKeyword.Null;

            _balanceSlot  = null;
            _balanceLabel = null;
        }

        private static string FormatBalance(float value)
        {
            // Formato español explícito: "61,18K" (coma decimal), independiente de la cultura
            if (value >= 1_000_000f) return $"{value / 1_000_000f:0.##}".Replace('.', ',') + "M";
            if (value >= 1_000f)     return $"{value / 1_000f:0.##}".Replace('.', ',') + "K";
            return Mathf.RoundToInt(value).ToString();
        }

        private void EnsureService()
        {
            if (OceanPayService.Instance == null)
                new GameObject("OceanPayService").AddComponent<OceanPayService>();
        }
    }
}
