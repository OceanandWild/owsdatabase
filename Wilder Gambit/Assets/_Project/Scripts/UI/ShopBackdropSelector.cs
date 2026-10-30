using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Catálogo de FONDOS ambientales de la tienda (pestaña tab-fonds).
    /// Cosmético puro: se paga en Gambits (divisa farmeable), con precios bajos
    /// y sin rareza. La tienda vende y equipa al momento (no hay pestaña de
    /// fondos en el inventario todavía). Reutiliza las cards .bg-card y el
    /// panel de detalle compartido shop2-detail.
    /// </summary>
    public class ShopBackdropSelector : IShopCartSource
    {
        /// <summary>Marcador en shop2-detail: el panel lo está usando esta pestaña.</summary>
        internal const string DETAIL_BACKDROP_CLASS = "detail-showing-backdrop";

        internal static void MarkBackdropDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.AddToClassList(DETAIL_BACKDROP_CLASS);
        }

        internal static void ClearBackdropDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.RemoveFromClassList(DETAIL_BACKDROP_CLASS);
        }

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

        private readonly ShopGridPager _pager;

        private int _selectedIndex;

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

        private readonly Dictionary<int, Texture2D> _textureCache = new Dictionary<int, Texture2D>();

        private static readonly string[] ThemeIcons = {
            "🍺", "⚓", "⛈️", "🔥", "🌕",
            "🌊", "🔭", "🏜️", "🕯️", "🐉",
            "🎃", "🌾", "🍷"
        };

        private static readonly string[] ThemeDescriptions = {
            "Taberna apagada del Atelier, velas al fondo",
            "Muelles en niebla, faroles ámbar lejanos",
            "Acantilados de tormenta en el horizonte",
            "Forja antigua, brasas flotando en los bordes",
            "Jardín nocturno bajo luna llena",
            "Fosa abisal vista desde arriba",
            "Ruinas de observatorio bajo vacío violeta",
            "Caravana nocturna en el horizonte",
            "Cripta inundada a la luz de las velas",
            "Mirador del dragón, huesos colosales",
            "Cabaña de bruja entre calabazas, luna llena y niebla",
            "Cosecha tardía bajo la luna de octubre",
            "Gran salón del banquete, velas y terciopelo rojo",
        };

        private static int[] ThemePrices => BackdropManager.ThemePrices;
        private int TotalThemes => BackdropManager.ThemeCount;

        /// <summary>
        /// Fondos visibles en la tienda: todo el catálogo menos los exclusivos
        /// de evento que aún no se poseen. Los del pase se listan en cuanto se
        /// cobran, porque esta pestaña es también la única forma de equiparlos.
        /// </summary>
        public int ShopCount => BuildShopIndexes().Count;

        /// <summary>
        /// Índices de los fondos a la venta, en orden. Los fondos de evento
        /// (Noche de Brujas y los del Pase de la Velada) no se venden: solo
        /// aparecen cuando la recompensa ya los desbloqueó, para poder equiparlos.
        /// </summary>
        private static List<int> BuildShopIndexes()
        {
            var list = new List<int>(BackdropManager.ThemeCount);
            for (int i = 0; i < BackdropManager.ThemeCount; i++)
            {
                if (!BackdropManager.IsEventExclusive(i) || BackdropManager.IsUnlocked(i))
                    list.Add(i);
            }
            return list;
        }

        public ShopBackdropSelector(VisualElement shopRoot, ShopGridPager pager, ShopCart cart = null)
        {
            _shopRoot = shopRoot;
            _pager = pager;
            _cart = cart;
            _selectedIndex = BackdropManager.SelectedIndex;

            var scrollView = shopRoot.Q<ScrollView>("shop-items-scroll");
            _itemsGrid = shopRoot.Q<VisualElement>("shop-items-grid");
            if (_itemsGrid == null && scrollView != null)
                _itemsGrid = scrollView.Q<VisualElement>("shop-items-grid");

            _previewPanel = shopRoot.Q<VisualElement>("bg-preview-panel");
            _previewImage = shopRoot.Q<Image>("bg-preview-image");
            _previewName = shopRoot.Q<Label>("bg-preview-name");
            _previewDesc = shopRoot.Q<Label>("bg-preview-desc");
            _heroBadge = _previewPanel?.Q<VisualElement>(className: "shop2-hero-badge");
            if (_heroBadge == null)
                _heroBadge = shopRoot.Q<VisualElement>(className: "shop2-hero-badge");

            _detail       = shopRoot.Q<VisualElement>("shop2-detail");
            _detailAction = shopRoot.Q<Button>("btn-detail-action");
            _detailCart   = shopRoot.Q<Button>("btn-detail-cart");
            _detailKicker = shopRoot.Q<Label>(className: "shop2-detail-kicker");
            _detailPrice  = shopRoot.Q<Label>("shop-detail-price");
            _detailStock  = shopRoot.Q<Label>("shop-detail-stock");
            _detailLore   = shopRoot.Q<Label>("shop-detail-lore");
            _detailAction?.RegisterCallback<ClickEvent>(_ => OnDetailAction());

            _pager.PageIndexChanged += CloseDetail;
            _pager.SetSource(ShopCount, PopulatePage, resetPage: true);

            UpdatePreview(_selectedIndex);
        }

        /// <summary>Refreshes everything (call when tab becomes visible).</summary>
        public void Refresh()
        {
            _selectedIndex = BackdropManager.SelectedIndex;
            _pager.SetSource(ShopCount, PopulatePage);
            UpdatePreview(_selectedIndex);
            CloseDetail();
        }

        private void UpdatePreview(int index)
        {
            if (index < 0 || index >= TotalThemes) return;

            if (_previewImage != null)
            {
                _previewImage.sprite = null;
                _previewImage.scaleMode = ScaleMode.ScaleToFit;
            }

            Texture2D tex = GetCachedTexture(index);
            if (tex != null && _previewImage != null)
            {
                _previewImage.image = tex;
                _previewImage.style.display = DisplayStyle.Flex;
            }

            var heroKicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (heroKicker != null) heroKicker.text = "VISTA PREVIA  •  FONDO AMBIENTE";

            if (_previewName != null)
                _previewName.text = GetName(index);

            if (_previewDesc != null)
            {
                bool isActive = (index == _selectedIndex);
                _previewDesc.text = isActive
                    ? "Este fondo ambienta tu menú ahora mismo."
                    : BackdropManager.IsUnlocked(index)
                        ? "Ya es tuyo: equípalo para ambientar tu menú."
                        : "Compra este fondo y se aplica al momento a tu menú.";
            }

            if (_heroBadge != null)
            {
                bool isActive = (index == _selectedIndex);
                if (isActive)
                    _heroBadge.RemoveFromClassList("hidden");
                else
                    _heroBadge.AddToClassList("hidden");
            }
        }

        private void PopulatePage(int start, int count)
        {
            if (_itemsGrid == null) return;

            _itemsGrid.Clear();
            _itemsGrid.RemoveFromClassList(ShopVariantSelector.GRID_VARIANT_CLASS);

            var shopIndexes = BuildShopIndexes();
            int end = Mathf.Min(start + count, shopIndexes.Count);
            for (int i = start; i < end; i++)
                _itemsGrid.Add(CreateCard(shopIndexes[i]));

            for (int i = 0; i < _itemsGrid.childCount; i++)
            {
                var target = _itemsGrid[i];
                target.AddToClassList("shop-card-enter");
                var delayed = target;
                delayed.schedule.Execute(() => delayed.RemoveFromClassList("shop-card-enter"))
                    .StartingIn(30 + i * 28);
            }
        }

        private VisualElement CreateCard(int index)
        {
            Texture2D thumbnail = GetCachedTexture(index);
            string name = GetName(index);
            string icon = GetIcon(index);
            bool isActive = (index == _selectedIndex);
            int price = ThemePrices[index];
            bool isFree = price == 0;
            bool isEvent = BackdropManager.IsEventExclusive(index);
            bool isUnlocked = BackdropManager.IsUnlocked(index);
            int balance = PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            var card = new VisualElement();
            card.AddToClassList("bg-card");
            if (isActive) card.AddToClassList("bg-card-active");
            if (!isUnlocked && !isActive) card.AddToClassList("bg-card-locked");
            card.name = $"backdrop-card-{index}";

            card.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                SelectCard(index);
            });
            if (index == _selectedCardIndex) card.AddToClassList("bg-card-selected");

            var thumbWrap = new VisualElement();
            thumbWrap.AddToClassList("bg-card-thumb");

            if (thumbnail != null)
            {
                var img = new Image();
                img.image = thumbnail;
                img.AddToClassList("bg-card-thumb-img");
                thumbWrap.Add(img);
            }
            else
            {
                var ph = new Label(icon);
                ph.AddToClassList("bg-card-thumb-placeholder");
                thumbWrap.Add(ph);
            }

            var thumbOverlay = new VisualElement();
            thumbOverlay.AddToClassList("bg-card-thumb-overlay");
            thumbWrap.Add(thumbOverlay);

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

            if (isActive)
            {
                var badge = new Label("ACTIVO");
                badge.AddToClassList("bg-card-badge");
                card.Add(badge);
            }

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
                if (isEvent)
                {
                    var pass = new Label("PASE");
                    pass.AddToClassList("bg-card-price");
                    footer.Add(pass);
                }
                else if (isFree)
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

            return card;
        }

        private void SelectCard(int index)
        {
            ShopVariantSelector.ClearVariantDetail(_detail);
            MarkBackdropDetail(_detail);

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
            _detailOpenSchedule = _detail.schedule.Execute(() =>
            {
                if (_detail != null && !_detail.ClassListContains("hidden"))
                    _detail.AddToClassList("shop2-detail-open");
            }).StartingIn(30);
        }

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

        private void UpdateCardSelectionVisual()
        {
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name == null || !child.name.StartsWith("backdrop-card-")) continue;
                if (int.TryParse(child.name.Substring("backdrop-card-".Length), out int idx))
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
                _detailKicker.text = BackdropManager.IsEventExclusive(index)
                    ? "FONDO • VELADA DE HALLOWEEN"
                    : "FONDO • AMBIENTE ATELIER";
                _detailKicker.style.color = StyleKeyword.Null;
            }

            int price = ThemePrices[index];
            bool isFree = price == 0;
            bool isActive = index == _selectedIndex;
            bool isUnlocked = BackdropManager.IsUnlocked(index);
            bool canAfford = PieceSkinManager.GetLocalGambits() >= price;

            if (_detailPrice != null)
                _detailPrice.text = BackdropManager.IsEventExclusive(index)
                    ? "RECOMPENSA DEL PASE"
                    : isFree ? "GRATIS" : $"{price:N0} Gambits";
            if (_detailStock != null)
                _detailStock.text = isActive ? "● ACTIVO" : isUnlocked ? "EN POSESIÓN" : "BLOQUEADO";
            if (_detailLore != null)
            {
                string desc = (index >= 0 && index < ThemeDescriptions.Length)
                    ? ThemeDescriptions[index]
                    : "Ambiente artesanal del Atelier.";
                _detailLore.text = isActive
                    ? $"{desc}. Este fondo ambienta tu menú ahora mismo."
                    : isUnlocked
                        ? $"{desc}. Ya es tuyo: equípalo para ambientar tu menú."
                        : $"{desc}. Al comprarlo se aplica al momento a tu menú.";
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
                _detailAction.text = "✨  EQUIPAR FONDO";
            }
            else if (canAfford)
            {
                _detailAction.text = isFree ? "🔓  CONSEGUIR GRATIS" : $"🔓  COMPRAR — {price:N0} GAMBITS";
            }
            else
            {
                _detailAction.text = $"NECESITAS {price:N0} GAMBITS";
                _detailAction.SetEnabled(false);
            }

            RefreshCartButton();
        }

        // ── Carrito ─────────────────────────────────────────────────────────

        /// <summary>Añade el fondo seleccionado al carrito (solo si falta comprarlo).</summary>
        public bool TryAddSelectedToCart()
        {
            if (_cart == null || _detail == null) return false;
            if (_detail.ClassListContains("hidden")) return false;
            if (!_detail.ClassListContains(DETAIL_BACKDROP_CLASS)) return false;

            int index = _detailActionIndex;
            if (index < 0 || index >= TotalThemes) return false;
            if (BackdropManager.IsUnlocked(index)) return false;

            int price = ThemePrices[index];
            if (price <= 0) return false;

            var item = new ShopCartItem
            {
                productId = ProductId(index),
                displayName = GetName(index),
                description = "Fondo de tablero · Atelier",
                kindLabel = "FONDO",
                price = price,
                currency = ShopCurrency.Gambits,
                thumbnail = GetCachedTexture(index),
                fallbackIcon = GetIcon(index),
                isOwned = () => BackdropManager.IsUnlocked(index),
                grant = () => GrantBackdropFromCart(index),
            };
            return _cart.Add(item);
        }

        /// <summary>Pinta el botón secundario del detalle según la selección actual.</summary>
        public void RefreshCartButton()
        {
            if (_detail == null) return;

            // El panel aplica «shop2-detail-open» un frame después de mostrarse.
            bool showing = !_detail.ClassListContains("hidden")
                && _detail.ClassListContains(DETAIL_BACKDROP_CLASS);

            int index = _detailActionIndex;
            bool purchasable = showing
                && index >= 0 && index < TotalThemes
                && !BackdropManager.IsUnlocked(index)
                && ThemePrices[index] > 0;

            ShopCart.RefreshDetailButton(
                _detailCart, _cart,
                purchasable ? ProductId(index) : null,
                purchasable);
        }

        private static string ProductId(int index)
        {
            string themeId = index >= 0 && index < BackdropManager.Themes.Length
                ? BackdropManager.Themes[index].id
                : index.ToString();
            return "wilder-gambit-backdrop-" + themeId;
        }

        private void GrantBackdropFromCart(int index)
        {
            BackdropManager.Unlock(index);
            BackdropManager.Select(index);
            _selectedIndex = index;
            Debug.Log($"[Shop] Fondo entregado desde el carrito: {GetName(index)}.");
            BalanceChanged?.Invoke();
        }

        private void OnDetailAction()
        {
            // El panel está mostrando otra pestaña: lo maneja su selector
            if (_detail != null && _detail.ClassListContains(ShopVariantSelector.DETAIL_VARIANT_CLASS)) return;
            if (_detail != null && _detail.ClassListContains(ShopAnimationSelector.DETAIL_ANIM_CLASS)) return;
            if (_detail != null && _detail.ClassListContains(ShopSkinSelector.DETAIL_SKIN_CLASS)) return;

            int index = _detailActionIndex;
            if (index < 0 || index >= TotalThemes) return;

            // Ya es tuyo pero no está puesto -> equipar sin cobrar
            if (BackdropManager.IsUnlocked(index))
            {
                BackdropManager.Select(index);
                _selectedIndex = index;
                _pager.Refresh();
                UpdatePreview(_selectedIndex);
                UpdateDetail(index);
                Debug.Log($"[Shop] ¡Fondo equipado! {GetName(index)}.");
                return;
            }

            OnBuyAndEquip(index, ThemePrices[index]);
        }

        private void OnBuyAndEquip(int index, int price)
        {
            int balance = PieceSkinManager.GetLocalGambits();
            if (balance < price)
            {
                Debug.Log($"[Shop] No tienes suficientes Gambits. Necesitas {price}, tienes {balance}.");
                return;
            }

            // El checkout de Surface cobra en el servidor; recién después se
            // desbloquea y se equipa el fondo localmente.
            Action grant = () =>
            {
                BackdropManager.Unlock(index);
                BackdropManager.Select(index);
                _selectedIndex = index;

                Debug.Log($"[Shop] ¡Fondo desbloqueado! {GetName(index)} por {price} Gambits.");
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

            string themeId = index >= 0 && index < BackdropManager.Themes.Length
                ? BackdropManager.Themes[index].id
                : index.ToString();
            WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                "wilder-gambit-backdrop-" + themeId,
                GetName(index),
                "Fondo de tablero · Atelier",
                price,
                result =>
                {
                    if (!result.success) return;
                    grant();
                });
        }

        private Texture2D GetCachedTexture(int index)
        {
            if (_textureCache.TryGetValue(index, out Texture2D cached))
                return cached;

            Texture2D tex = BackdropManager.LoadThumbnailForIndex(index);
            if (tex != null)
                _textureCache[index] = tex;
            return tex;
        }

        private string GetName(int index)
        {
            if (index >= 0 && index < BackdropManager.Themes.Length)
                return BackdropManager.Themes[index].displayName;
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
