using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Generates and manages board background selection cards inside the shop's items grid.
    /// Shows the purchasable backgrounds in a paginated grid with thumbnail previews; los
    /// exclusivos de evento (Pase de Halloween) no se listan. La tienda solo compra:
    /// equipar un tablero vive en InventoryModal.
    /// </summary>
    public class ShopBackgroundSelector : IShopCartSource
    {
        /// <summary>Se dispara tras comprar para que ShopModal refresque el chip de Gambits.</summary>
        public event Action BalanceChanged;

        private readonly VisualElement _shopRoot;
        private readonly ShopCart _cart;
        private VisualElement _itemsGrid;
        private VisualElement _previewPanel;
        private Image _previewImage;
        private Label _previewName;
        private Label _previewDesc;

        private VisualElement _heroBadge;

        // Paginación global de la tienda (compartida por todas las pestañas)
        private readonly ShopGridPager _pager;

        private int _selectedIndex;

        // Panel de detalle (derecha) — solo visible tras seleccionar una card
        private VisualElement _detail;
        private Button _detailAction;
        private Button _detailCart;
        private Label _detailKicker;
        private Label _detailPrice;
        private Label _detailStock;
        private Label _detailLore;
        private int _detailActionIndex = -1;
        private int _selectedCardIndex = -1;
        private IVisualElementScheduledItem _detailOpenSchedule;
        private IVisualElementScheduledItem _detailCloseSchedule;

        // Texture cache to avoid reloading on every page switch
        private readonly Dictionary<int, Texture2D> _textureCache = new Dictionary<int, Texture2D>();

        // Icon mapping for each theme
        private static readonly string[] ThemeIcons = {
            "🏛️", "🌋", "❄️", "🌿", "🌊",
            "✨", "🏺", "⛪", "🐉", "👑"
        };

        // Precios de los tableros (en Gambits): el único listado vive en el manager,
        // porque el inventario los enseña aunque la tienda no esté abierta.
        private static int[] ThemePrices => BoardBackgroundManager.ThemePrices;

        private static readonly string[] ThemeDescriptions = {
            "Clásico mármol de palacio",
            "Fuego volcánico y obsidiana",
            "Hielo ancestral cristalino",
            "Bosque encantado y antiguo",
            "Abismo oceánico profundo",
            "Nebulosa cósmica estelar",
            "Tumba egipcia milenaria",
            "Catedral gótica sombría",
            "Gruta del dragón ardiente",
            "Trono del palacio real"
        };

        private int TotalThemes => BoardBackgroundManager.ThemeCount;

        /// <summary>Tableros visibles en la tienda (sin los exclusivos de evento).</summary>
        public int ShopCount => BuildShopIndexes().Count;

        /// <summary>
        /// Índices de los tableros a la venta, en orden. Los exclusivos de evento
        /// (Luna Llena / Luna de Sangre, del Pase de Halloween) no se listan: solo
        /// llegan al inventario reclamando su recompensa.
        /// </summary>
        private static List<int> BuildShopIndexes()
        {
            var list = new List<int>();
            for (int i = 0; i < BoardBackgroundManager.ThemeCount; i++)
                if (!BoardBackgroundManager.IsPassExclusive(i)) list.Add(i);
            return list;
        }

        public ShopBackgroundSelector(VisualElement shopRoot, ShopGridPager pager, ShopCart cart = null)
        {
            _shopRoot = shopRoot;
            _pager = pager;
            _cart = cart;
            _selectedIndex = BoardBackgroundManager.SelectedIndex;

            // Find the scroll view and the grid inside it
            var scrollView = shopRoot.Q<ScrollView>("shop-items-scroll");
            _itemsGrid = shopRoot.Q<VisualElement>("shop-items-grid");
            // Fallback: if grid not found, use the scroll view's content container
            if (_itemsGrid == null && scrollView != null)
                _itemsGrid = scrollView.Q<VisualElement>("shop-items-grid");

            // Find/create preview panel (ATELIER hero)
            _previewPanel = shopRoot.Q<VisualElement>("bg-preview-panel");
            _previewImage = shopRoot.Q<Image>("bg-preview-image");
            _previewName = shopRoot.Q<Label>("bg-preview-name");
            _previewDesc = shopRoot.Q<Label>("bg-preview-desc");
            _heroBadge = _previewPanel?.Q<VisualElement>(className: "shop2-hero-badge");
            if (_heroBadge == null)
                _heroBadge = shopRoot.Q<VisualElement>(className: "shop2-hero-badge");

            // If preview panel doesn't exist in UXML, create it dynamically
            if (_previewPanel == null)
            {
                CreatePreviewPanel();
                _heroBadge = _previewPanel?.Q<VisualElement>(className: "shop2-hero-badge");
            }

            // Panel de detalle (derecha): no ocupa espacio hasta que se selecciona una card
            _detail       = shopRoot.Q<VisualElement>("shop2-detail");
            _detailAction = shopRoot.Q<Button>("btn-detail-action");
            _detailCart   = shopRoot.Q<Button>("btn-detail-cart");
            _detailKicker = shopRoot.Q<Label>(className: "shop2-detail-kicker");
            _detailPrice  = shopRoot.Q<Label>("shop-detail-price");
            _detailStock  = shopRoot.Q<Label>("shop-detail-stock");
            _detailLore   = shopRoot.Q<Label>("shop-detail-lore");
            _detailAction?.RegisterCallback<ClickEvent>(_ => OnDetailAction());

            // CERRAR del panel: colapsa el detalle con su animación de salida
            var btnCloseDetail = shopRoot.Q<Button>("btn-detail-close");
            if (btnCloseDetail != null)
            {
                btnCloseDetail.RegisterCallback<ClickEvent>(_ => CloseDetail());
                ApplyCloseButtonGradient(btnCloseDetail);
            }

            // Conecta la paginación global: primera carga de la fuente de fondos
            _pager.PageIndexChanged += CloseDetail;
            _pager.SetSource(BuildShopIndexes().Count, PopulatePage, resetPage: true);

            UpdatePreview(_selectedIndex);
        }

        /// <summary>Refreshes everything (call when tab becomes visible).</summary>
        public void Refresh()
        {
            _selectedIndex = BoardBackgroundManager.SelectedIndex;
            _pager.SetSource(BuildShopIndexes().Count, PopulatePage); // recalcula espacio + repuebla
            UpdatePreview(_selectedIndex);
            CloseDetail();
        }

        // ── Preview Panel ────────────────────────────────────────────────────

        private void CreatePreviewPanel()
        {
            _previewPanel = new VisualElement();
            _previewPanel.name = "bg-preview-panel";
            _previewPanel.AddToClassList("bg-preview-panel");

            _previewImage = new Image();
            _previewImage.name = "bg-preview-image";
            _previewImage.AddToClassList("bg-preview-image");
            _previewPanel.Add(_previewImage);

            var infoContainer = new VisualElement();
            infoContainer.AddToClassList("bg-preview-info");

            _previewName = new Label("Selecciona un fondo");
            _previewName.name = "bg-preview-name";
            _previewName.AddToClassList("bg-preview-name");
            infoContainer.Add(_previewName);

            _previewDesc = new Label("Haz clic en una tarjeta para ver la vista previa del fondo que se mostrará detrás del tablero de ajedrez.");
            _previewDesc.name = "bg-preview-desc";
            _previewDesc.AddToClassList("bg-preview-desc");
            infoContainer.Add(_previewDesc);

            _previewPanel.Add(infoContainer);

            // Insert preview panel before the scroll view in the connected view
            var connectedView = _shopRoot.Q<VisualElement>("shop-connected-view");
            var scrollView = _shopRoot.Q<ScrollView>("shop-items-scroll");
            if (connectedView != null && scrollView != null)
            {
                int scrollIndex = connectedView.IndexOf(scrollView);
                if (scrollIndex >= 0)
                    connectedView.Insert(scrollIndex, _previewPanel);
                else
                    connectedView.Add(_previewPanel);
            }
        }

        private void UpdatePreview(int themeIndex)
        {
            if (themeIndex < 0 || themeIndex >= TotalThemes) return;

            // La pestaña de Variantes deja aquí el sprite de su pieza: limpiarlo siempre
            // (aunque la textura del tablero aún no esté cacheada) para no mezclarlos.
            if (_previewImage != null)
            {
                _previewImage.sprite = null;
                _previewImage.scaleMode = ScaleMode.ScaleToFit; // coincide con .shop2-hero-image
            }

            Texture2D tex = GetCachedTexture(themeIndex);
            if (tex != null && _previewImage != null)
            {
                _previewImage.image = tex;
                _previewImage.style.display = DisplayStyle.Flex;
            }

            // La pestaña de Variantes deja su propio rótulo en el hero: devolverlo a Tableros
            var heroKicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (heroKicker != null) heroKicker.text = "VISTA PREVIA  •  EDICIÓN ARTESANAL";

            if (_previewName != null)
                _previewName.text = GetName(themeIndex);

            if (_previewDesc != null)
            {
                bool isActive = (themeIndex == _selectedIndex);
                _previewDesc.text = isActive
                    ? "Este fondo viste tu tablero ahora mismo. Cambia a otro desde el INVENTARIO."
                    : "Compra este fondo y equipa la atmósfera desde el INVENTARIO.";
            }

            if (_heroBadge != null)
            {
                bool isActive = (themeIndex == _selectedIndex);
                if (isActive)
                    _heroBadge.RemoveFromClassList("hidden");
                else
                    _heroBadge.AddToClassList("hidden");
            }
        }

        // ── Card Generation ──────────────────────────────────────────────────

        /// <summary>Puebla la página indicada por el paginador global de la tienda.</summary>
        private void PopulatePage(int start, int count)
        {
            if (_itemsGrid == null) return;

            _itemsGrid.Clear();
            // Los tableros llenan la fila: sin centrado de showcase
            _itemsGrid.RemoveFromClassList(ShopVariantSelector.GRID_VARIANT_CLASS);

            // El paginador cuenta posiciones de venta: se mapean a índices de tema
            // (los exclusivos de evento quedan fuera de la lista).
            List<int> shopIndexes = BuildShopIndexes();
            int end = Mathf.Min(start + count, shopIndexes.Count);

            for (int pos = start; pos < end; pos++)
            {
                _itemsGrid.Add(CreateCard(shopIndexes[pos]));
            }

            // Entrada escalonada sutil (0.18 s, 28 ms entre cards)
            for (int i = 0; i < _itemsGrid.childCount; i++)
            {
                var target = _itemsGrid[i];
                target.AddToClassList("shop-card-enter");
                var delayed = target;
                delayed.schedule.Execute(() => delayed.RemoveFromClassList("shop-card-enter"))
                    .StartingIn(30 + i * 28);
            }
        }

        private VisualElement CreateCard(int themeIndex)
        {
            Texture2D thumbnail = GetCachedTexture(themeIndex);
            string name = GetName(themeIndex);
            string icon = GetIcon(themeIndex);
            bool isActive = (themeIndex == _selectedIndex);
            int price = ThemePrices[themeIndex];
            bool isFree = price == 0;
            bool isUnlocked = IsThemeUnlocked(themeIndex);
            int balance = PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            // ── Card Container ──
            var card = new VisualElement();
            card.AddToClassList("bg-card");
            if (isActive) card.AddToClassList("bg-card-active");
            if (!isUnlocked && !isActive) card.AddToClassList("bg-card-locked");
            card.name = $"bg-card-{themeIndex}";

            // Clic en la card -> selecciona y abre/actualiza el panel de detalle
            card.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                SelectCard(themeIndex);
            });
            if (themeIndex == _selectedCardIndex) card.AddToClassList("bg-card-selected");

            // ── Thumbnail ──
            var thumbWrap = new VisualElement();
            thumbWrap.AddToClassList("bg-card-thumb");

            if (thumbnail != null)
            {
                var img = new Image();
                img.image = thumbnail;
                // El tablero decorado (Luna Llena / Luna de Sangre) es un objeto con
                // marco: mostrarlo completo en vez de recortarlo como las fotos.
                if (BoardBackgroundManager.HasDecoratedBoardArt(themeIndex))
                    img.scaleMode = ScaleMode.ScaleToFit;
                img.AddToClassList("bg-card-thumb-img");
                thumbWrap.Add(img);
            }
            else
            {
                var ph = new Label(icon);
                ph.AddToClassList("bg-card-thumb-placeholder");
                thumbWrap.Add(ph);
            }

            // Overlay gradient at bottom of thumbnail
            var thumbOverlay = new VisualElement();
            thumbOverlay.AddToClassList("bg-card-thumb-overlay");
            thumbWrap.Add(thumbOverlay);

            // Lock overlay
            if (!isUnlocked && !isActive)
            {
                var lockOverlay = new VisualElement();
                lockOverlay.AddToClassList("bg-card-lock-overlay");
                var lockIcon = new Label("🔒");
                lockIcon.AddToClassList("bg-card-lock-icon");
                lockOverlay.Add(lockIcon);
                thumbWrap.Add(lockOverlay);
            }

            card.Add(thumbWrap);

            // ── Active Badge ──
            if (isActive)
            {
                var badge = new Label("ACTIVO");
                badge.AddToClassList("bg-card-badge");
                card.Add(badge);
            }

            // ── Nombre (fila propia) ──
            var nameRow = new VisualElement();
            nameRow.AddToClassList("bg-card-name-row");
            nameRow.AddToClassList("bg-card-name-row-single");

            var nameLabel = new Label(name);
            nameLabel.AddToClassList("bg-card-name");
            nameRow.Add(nameLabel);

            card.Add(nameRow);

            // ── Pie: altura fija y anclado al borde inferior para que todas las
            // cards alineen su precio/estado, tengan o no importe ──
            var footer = new VisualElement();
            footer.AddToClassList("bg-card-footer");
            if (!isActive)
            {
                if (isFree)
                {
                    var gratis = new Label("GRATIS");
                    gratis.AddToClassList("bg-card-price");
                    footer.Add(gratis);
                }
                else
                {
                    var priceRow = GambitIcon.Price(price, 16f, "bg-card-price");
                    if (!canAfford)
                    {
                        var inner = priceRow.Q<Label>(className: "gambits-inline-text") ?? priceRow.Q<Label>();
                        inner?.AddToClassList("bg-card-price-expensive");
                    }
                    footer.Add(priceRow);
                }
            }
            card.Add(footer);

            // El CTA (comprar/equipar) vive ahora en el panel de detalle (btn-detail-action)

            return card;
        }

        // ── Panel de detalle ──────────────────────────────────────────────────

        private static Texture2D _closeGradTex;

        /// <summary>Gradiente horizontal rojo -> negro para el botón CERRAR (USS no admite gradients).</summary>
        private static void ApplyCloseButtonGradient(Button btn)
        {
            if (_closeGradTex == null)
            {
                const int w = 64;
                _closeGradTex = new Texture2D(w, 1, TextureFormat.RGBA32, false)
                {
                    name = "shop-close-gradient",
                    filterMode = FilterMode.Bilinear,
                    wrapMode = TextureWrapMode.Clamp
                };
                var px = new Color32[w];
                Color32 red = new Color32(166, 29, 29, 255);  // rojo encendido
                Color32 black = new Color32(12, 7, 9, 255);   // negro casi puro
                for (int x = 0; x < w; x++)
                    px[x] = Color32.Lerp(red, black, x / (float)(w - 1));
                _closeGradTex.SetPixels32(px);
                _closeGradTex.Apply(false);
            }
            btn.style.backgroundImage = Background.FromTexture2D(_closeGradTex);
        }

        private void SelectCard(int index)
        {
            // El panel vuelve a ser de Tableros (las otras pestañas marcan su propio uso)
            ShopVariantSelector.ClearVariantDetail(_detail);
            ShopSkinSelector.ClearSkinDetail(_detail);
            ShopAnimationSelector.ClearAnimDetail(_detail);
            ShopBackdropSelector.ClearBackdropDetail(_detail);

            // Segunda pulsación sobre la misma card -> colapsa el panel
            if (_selectedCardIndex == index && IsDetailOpen())
            {
                CloseDetail();
                return;
            }

            _selectedCardIndex = index;
            UpdateCardSelectionVisual();
            UpdatePreview(index);
            UpdateDetail(index);
            OpenDetail();
            RefreshCartButton();
        }

        private bool IsDetailOpen()
        {
            return _detail != null && _detail.ClassListContains("shop2-detail-open");
        }

        /// <summary>Abre el panel con la animación sutil (fade + slide, 0.25 s).</summary>
        public void OpenDetail()
        {
            if (_detail == null) return;
            _detailCloseSchedule?.Pause();

            if (!_detail.ClassListContains("hidden"))
            {
                _detail.AddToClassList("shop2-detail-open");
                return;
            }

            _detail.RemoveFromClassList("hidden");
            _detail.RemoveFromClassList("shop2-detail-open");
            if (_detail.panel == null)
            {
                _detail.AddToClassList("shop2-detail-open");
                return;
            }
            // 1 frame en estado inicial (opacity 0 / translate 18px) para que la transición arranque
            _detailOpenSchedule = _detail.schedule.Execute(() =>
            {
                if (_detail != null && !_detail.ClassListContains("hidden"))
                    _detail.AddToClassList("shop2-detail-open");
            }).StartingIn(30);
        }

        /// <summary>Colapsa el panel (0.18 s) y solo entonces lo retira del layout. Público: lo cierra ShopModal al cambiar de pestaña.</summary>
        public void CloseDetail()
        {
            _selectedCardIndex = -1;
            UpdateCardSelectionVisual();
            if (_detail == null || _detail.ClassListContains("hidden")) return;

            _detailOpenSchedule?.Pause();
            _detail.RemoveFromClassList("shop2-detail-open");
            if (_detail.panel == null)
            {
                _detail.AddToClassList("hidden");
                return;
            }
            _detailCloseSchedule = _detail.schedule.Execute(() =>
                _detail?.AddToClassList("hidden")).StartingIn(200);
        }

        /// <summary>Colapsa el panel solo si lo está mostrando la pestaña de Variantes.</summary>
        public void CloseDetailIfVariant()
        {
            if (_detail != null && _detail.ClassListContains(ShopVariantSelector.DETAIL_VARIANT_CLASS))
                CloseDetail();
        }

        private void UpdateCardSelectionVisual()
        {
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name == null || !child.name.StartsWith("bg-card-")) continue;
                if (int.TryParse(child.name.Substring("bg-card-".Length), out int idx))
                {
                    if (idx == _selectedCardIndex) child.AddToClassList("bg-card-selected");
                    else child.RemoveFromClassList("bg-card-selected");
                }
            }
        }

        private void UpdateDetail(int index)
        {
            if (index < 0 || index >= TotalThemes) return;

            if (_detailKicker != null)
            {
                _detailKicker.text = "TABLERO • EDICIÓN ATELIER";
                _detailKicker.style.color = StyleKeyword.Null;
            }

            int price = ThemePrices[index];
            bool isFree = price == 0;
            bool isActive = index == _selectedIndex;
            bool isUnlocked = IsThemeUnlocked(index);
            bool canAfford = PieceSkinManager.GetLocalGambits() >= price;

            if (_detailPrice != null)
                _detailPrice.text = isFree ? "GRATIS" : $"{price:N0} Gambits";
            if (_detailStock != null)
                _detailStock.text = isActive ? "● ACTIVO" : isUnlocked ? "EN POSESIÓN" : "BLOQUEADO";
            if (_detailLore != null)
            {
                string desc = (index >= 0 && index < ThemeDescriptions.Length)
                    ? ThemeDescriptions[index]
                    : "Edición artesanal del Atelier.";
                _detailLore.text = isUnlocked
                    ? $"{desc}. Aquí solo se vende: se equipa desde el INVENTARIO."
                    : $"{desc}. Al comprarlo entra en tu INVENTARIO, donde se equipa.";
            }

            _detailActionIndex = index;
            if (_detailAction == null)
            {
                RefreshCartButton();
                return;
            }

            _detailAction.SetEnabled(true);
            if (isActive)
            {
                _detailAction.text = "✓  EN USO";
                _detailAction.SetEnabled(false);
            }
            else if (isUnlocked)
            {
                // Ya es tuyo: la tienda no equipa (ver InventoryModal)
                _detailAction.text = "✓  EN TU INVENTARIO";
                _detailAction.SetEnabled(false);
            }
            else if (canAfford)
            {
                _detailAction.text = $"🔓  COMPRAR — {price:N0} GAMBITS";
            }
            else
            {
                _detailAction.text = $"NECESITAS {price:N0} GAMBITS";
                _detailAction.SetEnabled(false);
            }

            RefreshCartButton();
        }

        // ── Carrito ─────────────────────────────────────────────────────────

        /// <summary>Añade el tablero seleccionado al carrito (solo si falta comprarlo).</summary>
        public bool TryAddSelectedToCart()
        {
            if (_cart == null || _detail == null) return false;
            if (_detail.ClassListContains("hidden")) return false;
            if (_detail.ClassListContains(ShopVariantSelector.DETAIL_VARIANT_CLASS)) return false;
            if (_detail.ClassListContains(ShopBackdropSelector.DETAIL_BACKDROP_CLASS)) return false;
            if (_detail.ClassListContains(ShopAnimationSelector.DETAIL_ANIM_CLASS)) return false;
            if (_detail.ClassListContains(ShopSkinSelector.DETAIL_SKIN_CLASS)) return false;

            int index = _detailActionIndex;
            if (index < 0 || index >= TotalThemes) return false;
            if (BoardBackgroundManager.IsPassExclusive(index) || IsThemeUnlocked(index)) return false;

            int price = ThemePrices[index];
            if (price <= 0) return false;

            var item = new ShopCartItem
            {
                productId = "wilder-gambit-board-" + index,
                displayName = GetName(index),
                description = "Tablero artesanal · Atelier",
                kindLabel = "TABLERO",
                price = price,
                currency = ShopCurrency.Gambits,
                thumbnail = GetCachedTexture(index),
                fallbackIcon = GetIcon(index),
                isOwned = () => IsThemeUnlocked(index),
                grant = () => GrantBoardFromCart(index),
            };
            return _cart.Add(item);
        }

        /// <summary>Pinta el botón secundario del detalle según la selección actual.</summary>
        public void RefreshCartButton()
        {
            if (_detail == null) return;

            // El panel aplica «shop2-detail-open» un frame después de mostrarse; el
            // CTA del carrito usa el estado estable (visible + marca de la pestaña).
            bool showing = !_detail.ClassListContains("hidden")
                && !_detail.ClassListContains(ShopVariantSelector.DETAIL_VARIANT_CLASS)
                && !_detail.ClassListContains(ShopBackdropSelector.DETAIL_BACKDROP_CLASS)
                && !_detail.ClassListContains(ShopAnimationSelector.DETAIL_ANIM_CLASS)
                && !_detail.ClassListContains(ShopSkinSelector.DETAIL_SKIN_CLASS);

            int index = _detailActionIndex;
            bool purchasable = showing
                && index >= 0 && index < TotalThemes
                && !BoardBackgroundManager.IsPassExclusive(index)
                && !IsThemeUnlocked(index)
                && ThemePrices[index] > 0;

            ShopCart.RefreshDetailButton(
                _detailCart, _cart,
                purchasable ? "wilder-gambit-board-" + index : null,
                purchasable);
        }

        private void GrantBoardFromCart(int index)
        {
            BoardBackgroundManager.Unlock(index);
            Debug.Log($"[Shop] Tablero entregado desde el carrito: {GetName(index)}. " +
                      "Se equipa desde el INVENTARIO.");
            BalanceChanged?.Invoke();
        }

        private void OnDetailAction()
        {
            // El panel está mostrando otra pestaña: lo maneja su selector
            if (_detail != null && _detail.ClassListContains(ShopVariantSelector.DETAIL_VARIANT_CLASS)) return;
            if (_detail != null && _detail.ClassListContains(ShopBackdropSelector.DETAIL_BACKDROP_CLASS)) return;
            if (_detail != null && _detail.ClassListContains(ShopAnimationSelector.DETAIL_ANIM_CLASS)) return;
            if (_detail != null && _detail.ClassListContains(ShopSkinSelector.DETAIL_SKIN_CLASS)) return;

            int index = _detailActionIndex;
            if (index < 0 || index >= TotalThemes) return;

            // Solo compra: si ya es tuyo o ya está puesto, el CTA está desactivado y
            // aquí no hay nada que hacer (equipar vive en el inventario).
            if (IsThemeUnlocked(index)) return;

            OnBuyAndEquip(index, ThemePrices[index]);
        }

        private bool IsThemeUnlocked(int index)
        {
            // Gratis de entrada o comprado — la regla vive en el manager
            return BoardBackgroundManager.IsUnlocked(index);
        }

        private void OnBuyAndEquip(int index, int price)
        {
            // Blindaje: los exclusivos de evento no se compran ni por un clic escondido.
            if (BoardBackgroundManager.IsPassExclusive(index)) return;

            int balance = PieceSkinManager.GetLocalGambits();
            if (balance < price)
            {
                Debug.Log($"[Shop] No tienes suficientes Gambits. Necesitas {price}, tienes {balance}.");
                return;
            }

            // El checkout de Surface cobra en el servidor y devuelve el saldo
            // real. La compra solo deja el tablero en el inventario.
            Action grant = () =>
            {
                BoardBackgroundManager.Unlock(index);

                Debug.Log($"[Shop] ¡Tablero desbloqueado! {GetName(index)} por {price} Gambits. " +
                          "Se equipa desde el INVENTARIO.");
                BalanceChanged?.Invoke();
                _pager.Refresh();
                UpdatePreview(_selectedIndex);
                UpdateDetail(index);
            };

            if (price <= 0)
            {
                grant();
                return;
            }

            WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                "wilder-gambit-board-" + index,
                GetName(index),
                "Tablero artesanal · Atelier",
                price,
                result =>
                {
                    if (!result.success) return;
                    grant();
                });
        }

        // ── Actions ──────────────────────────────────────────────────────────

        // Aquí vivía OnEquip: la tienda ya no equipa. Poner un tablero vive en
        // InventoryModal (pestaña TABLEROS) y refresca el fondo del menú por callback.

        // La paginación (capacidad por espacio, flechas y dots) vive en ShopGridPager,
        // el paginador global compartido por todas las pestañas de la tienda.

        // ───────────────────────────────────────────────────────

        // ── Helpers ──────────────────────────────────────────────────────────

        private Texture2D GetCachedTexture(int index)
        {
            if (_textureCache.TryGetValue(index, out Texture2D cached))
                return cached;

            Texture2D tex = BoardBackgroundManager.LoadThumbnailForIndex(index);
            if (tex != null)
                _textureCache[index] = tex;
            return tex;
        }

        private string GetName(int index)
        {
            if (BoardBackgroundManager.Library != null)
            {
                var theme = BoardBackgroundManager.Library.GetTheme(index);
                if (theme != null) return theme.displayName;
            }
            if (index >= 0 && index < BoardBackgroundManager.FallbackThemes.Length)
                return BoardBackgroundManager.FallbackThemes[index].displayName;
            return "Fondo";
        }

        private string GetIcon(int index)
        {
            if (index >= 0 && index < ThemeIcons.Length)
                return ThemeIcons[index];
            return "🎨";
        }
    }
}
