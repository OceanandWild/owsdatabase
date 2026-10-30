using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Catálogo de SKINS visuales de la tienda (pestaña tab-skins).
    /// Espejo liviano de ShopVariantSelector: se engancha al paginador global
    /// (ShopGridPager), reutiliza las cards .bg-card y comparte el panel de detalle
    /// shop2-detail (marcado con DETAIL_SKIN_CLASS para que cada pestaña atienda
    /// su propio CTA). Moneda: Gambits. Regla: la tienda vende, el inventario equipa.
    ///
    /// Las skins son SOLO visuales (tinte + aura idle): no dan pasivas ni ventajas.
    /// Fuente: PieceSkinManager (ScriptableObject + fallback hardcodeado).
    /// </summary>
    public class ShopSkinSelector : IShopCartSource
    {
        /// <summary>Marcador en shop2-detail: el panel lo está usando esta pestaña.</summary>
        internal const string DETAIL_SKIN_CLASS = "detail-showing-skin";

        /// <summary>Marca el panel de detalle compartido como ficha de skin.</summary>
        internal static void MarkSkinDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.AddToClassList(DETAIL_SKIN_CLASS);
            detail.AddToClassList(ShopVariantSelector.DETAIL_VARIANT_THEME_CLASS);
        }

        /// <summary>Devuelve el panel al estilo de Tableros (lo llama ShopModal al cambiar de pestaña).</summary>
        internal static void ClearSkinDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.RemoveFromClassList(DETAIL_SKIN_CLASS);
            detail.RemoveFromClassList(ShopVariantSelector.DETAIL_VARIANT_THEME_CLASS);
        }

        /// <summary>Se dispara tras una compra para que ShopModal refresque el chip de Gambits.</summary>
        public event Action BalanceChanged;

        public static int Count => BuildShopIndices().Count;

        /// <summary>
        /// Orden curado del catálogo: pieza → precio → nombre. Así cada familia
        /// (peones, caballos, alfiles…) queda junta y de la más barata a la más
        /// cara, en vez de mezclar rarezas y precios al azar.
        /// </summary>
        private static readonly PieceType[] PieceOrder =
        {
            PieceType.Pawn,
            PieceType.Knight,
            PieceType.Bishop,
            PieceType.NecromancerBishop,
            PieceType.Rook,
            PieceType.Queen,
            PieceType.King,
            PieceType.Custom,
        };

        private static int PieceRank(PieceType type)
        {
            for (int i = 0; i < PieceOrder.Length; i++)
                if (PieceOrder[i] == type) return i;
            return PieceOrder.Length;
        }

        /// <summary>
        /// Índices de las skins a la venta en el Atelier. Se excluyen las que
        /// pertenecen a la tienda de la velada (se compran con Dulces en su
        /// propio escaparate) y las exclusivas del Pase de la Velada (se cobran
        /// subiendo de nivel), y se ordenan por pieza y precio.
        /// </summary>
        private static List<int> BuildShopIndices()
        {
            var list = new List<int>(PieceSkinManager.Count);
            for (int i = 0; i < PieceSkinManager.Count; i++)
                if (!PieceSkinManager.IsHalloweenShopExclusive(i) && !PieceSkinManager.IsPassExclusiveSkin(i))
                    list.Add(i);

            list.Sort((a, b) =>
            {
                int rankA = PieceRank(PieceSkinManager.GetSkinPieceType(a));
                int rankB = PieceRank(PieceSkinManager.GetSkinPieceType(b));
                if (rankA != rankB) return rankA.CompareTo(rankB);

                int priceA = PieceSkinManager.GetSkinPrice(a);
                int priceB = PieceSkinManager.GetSkinPrice(b);
                if (priceA != priceB) return priceA.CompareTo(priceB);

                return string.Compare(
                    PieceSkinManager.GetSkinName(a),
                    PieceSkinManager.GetSkinName(b),
                    StringComparison.OrdinalIgnoreCase);
            });

            return list;
        }

        private readonly VisualElement _shopRoot;
        private readonly VisualElement _itemsGrid;
        private readonly ShopGridPager _pager;
        private readonly ShopBackgroundSelector _detailHost;
        private readonly ShopCart _cart;

        // Índices reales de las skins visibles en esta página, ya filtradas y ordenadas.
        private List<int> _shopIndices = new List<int>();

        // Panel de detalle compartido (lo abre/colapsa el host de Tableros)
        private VisualElement _detail;
        private Button _detailAction;
        private Button _detailCart;
        private Label _detailKicker;
        private Label _detailPrice;
        private Label _detailStock;
        private Label _detailLore;
        private int _detailIndex = -1;

        public ShopSkinSelector(VisualElement shopRoot, ShopGridPager pager, ShopBackgroundSelector detailHost = null, ShopCart cart = null)
        {
            _shopRoot = shopRoot;
            _pager = pager;
            _detailHost = detailHost;
            _cart = cart;

            var scrollView = shopRoot.Q<ScrollView>("shop-items-scroll");
            _itemsGrid = shopRoot.Q<VisualElement>("shop-items-grid");
            if (_itemsGrid == null && scrollView != null)
                _itemsGrid = scrollView.Q<VisualElement>("shop-items-grid");

            // Panel de detalle (derecha) — el mismo que usan las demás pestañas
            _detail       = shopRoot.Q<VisualElement>("shop2-detail");
            _detailAction = shopRoot.Q<Button>("btn-detail-action");
            _detailCart   = shopRoot.Q<Button>("btn-detail-cart");
            _detailKicker = shopRoot.Q<Label>(className: "shop2-detail-kicker");
            _detailPrice  = shopRoot.Q<Label>("shop-detail-price");
            _detailStock  = shopRoot.Q<Label>("shop-detail-stock");
            _detailLore   = shopRoot.Q<Label>("shop-detail-lore");
            _detailAction?.RegisterCallback<ClickEvent>(_ => OnDetailAction());

            // CERRAR: además de colapsar el panel, suelta la selección de la card
            shopRoot.Q<Button>("btn-detail-close")?.RegisterCallback<ClickEvent>(_ => ClearSelection());
        }

        /// <summary>Conecta la fuente de skins al paginador global y repinta la página.</summary>
        public void Refresh()
        {
            if (_pager == null || _itemsGrid == null) return;
            _shopIndices = BuildShopIndices();
            _pager.SetSource(_shopIndices.Count, PopulatePage, resetPage: true);
            UpdateHero();
        }

        // ── Grid ────────────────────────────────────────────────────────────

        /// <summary>Puebla la página indicada por el paginador global de la tienda.</summary>
        private void PopulatePage(int start, int count)
        {
            if (_itemsGrid == null) return;

            _itemsGrid.Clear();
            // Skins en formato compacto (.bg-card): el arte es apaisado y así
            // caben dos filas por página. El orden (pieza → precio) lo fija
            // BuildShopIndices, no el orden interno del manager.
            _itemsGrid.RemoveFromClassList(ShopVariantSelector.GRID_VARIANT_CLASS);

            int end = Mathf.Min(start + count, _shopIndices.Count);
            for (int i = start; i < end; i++)
                _itemsGrid.Add(CreateCard(_shopIndices[i]));

            // Entrada escalonada sutil (igual que los tableros)
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
            string name = PieceSkinManager.GetSkinName(index);
            SkinRarity rarity = PieceSkinManager.GetSkinRarity(index);
            string rarityLabel = PieceSkinManager.RarityLabel(rarity);
            bool owned = PieceSkinManager.IsOwned(index);
            bool equipped = PieceSkinManager.IsEquipped(index);
            int price = PieceSkinManager.GetSkinPrice(index);
            int balance = PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;
            Color tint = PieceSkinManager.GetSkinTint(index);

            var card = new VisualElement();
            card.AddToClassList("bg-card");
            card.name = $"skin-card-{index}";
            if (equipped) card.AddToClassList("bg-card-active");

            // Clic en la card -> abre el panel de detalle con la info de la skin,
            // aunque el saldo no alcance para comprarla todavía
            card.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                ToggleSkin(index);
            });

            // Miniatura: thumbnail propio si existe; si no, sprite de la pieza;
            // si no hay BoardView en menú, icono de fallback con el tinte.
            // (Sin halos: la elipse de fondo tapaba el arte de la skin.)
            var thumbWrap = new VisualElement();
            thumbWrap.AddToClassList("bg-card-thumb");

            Texture2D thumbTex = PieceSkinManager.GetSkinThumbnail(index);
            if (thumbTex != null)
            {
                var thumbImg = new Image { image = thumbTex, scaleMode = ScaleMode.ScaleToFit };
                thumbImg.AddToClassList("bg-card-thumb-img");
                thumbWrap.Add(thumbImg);
            }
            else
            {
                Sprite art = GetSkinArt(index);
                if (art != null)
                {
                    var artImg = new Image { sprite = art, scaleMode = ScaleMode.ScaleToFit };
                    artImg.AddToClassList("bg-card-thumb-img");
                    artImg.style.unityBackgroundImageTintColor = new StyleColor(tint);
                    thumbWrap.Add(artImg);
                }
                else
                {
                    var iconLabel = new Label(PieceSkinManager.GetSkinIcon(index));
                    iconLabel.AddToClassList("bg-card-thumb-placeholder");
                    iconLabel.style.color = new StyleColor(tint);
                    thumbWrap.Add(iconLabel);
                }
            }
            card.Add(thumbWrap);

            // Rareza (fila propia) + nombre (fila propia): no compiten por ancho
            var rarityRow = new VisualElement();
            rarityRow.AddToClassList("bg-card-rarity-row");
            var rarityPill = new Label(rarityLabel);
            ShopRarity.StyleCardLabel(rarityPill, rarity);
            rarityRow.Add(rarityPill);
            card.Add(rarityRow);

            var nameRow = new VisualElement();
            nameRow.AddToClassList("bg-card-name-row");
            nameRow.AddToClassList("bg-card-name-row-single");
            var nameLabel = new Label(name);
            nameLabel.AddToClassList("bg-card-name");
            nameRow.Add(nameLabel);
            card.Add(nameRow);

            // Pie de la card: un único rótulo de estado (la compra vive en el panel
            // de detalle, igual que en la pestaña de Tableros: nada duplicado).
            // Va en un contenedor fijo anclado abajo para que todas las cards
            // alineen su precio/estado aunque el texto superior ocupe distinto.
            var footer = new VisualElement();
            footer.AddToClassList("bg-card-footer");
            if (equipped)
            {
                var state = new Label("✓  EN USO");
                state.AddToClassList("bg-card-state");
                state.AddToClassList("bg-card-state-active");
                footer.Add(state);
            }
            else if (owned)
            {
                // Ya es tuya: la tienda no equipa (ver InventoryModal)
                var inventory = new Label("✓  EN EL INVENTARIO");
                inventory.AddToClassList("bg-card-state");
                footer.Add(inventory);
            }
            else if (price <= 0 || canAfford)
            {
                if (price <= 0)
                {
                    var gratis = new Label("GRATIS");
                    gratis.AddToClassList("bg-card-state");
                    footer.Add(gratis);
                }
                else footer.Add(GambitIcon.Price(price, 16f, "bg-card-state"));
            }
            else
            {
                var priceLabel = new Label($"🔒 Faltan {price - balance:N0} G");
                priceLabel.AddToClassList("bg-card-state");
                priceLabel.AddToClassList("bg-card-state-locked");
                footer.Add(priceLabel);
            }
            card.Add(footer);

            ShopRarity.TintCardBorder(card, rarityLabel, equipped);
            return card;
        }

        // ── Panel de detalle (compartido con la pestaña de Tableros) ───────────

        /// <summary>
        /// Abre el panel derecho con la info de la skin. Siempre se abre, aunque
        /// el jugador no tenga Gambits suficientes (el CTA explica lo que falta).
        /// </summary>
        private void SelectSkin(int index)
        {
            if (index < 0 || index >= PieceSkinManager.Count || _detail == null) return;

            _detailIndex = index;
            MarkSelectedCard(index);

            // El panel pasa a ser "de skins": ShopBackgroundSelector no debe comprar fondos
            // y la USS le da el layout de vista previa de pieza.
            MarkSkinDetail(_detail);
            FillDetail(index);

            if (_detailHost != null) _detailHost.OpenDetail();
            else
            {
                _detail.RemoveFromClassList("hidden");
                _detail.AddToClassList("shop2-detail-open");
            }
            RefreshCartButton();
        }

        /// <summary>Clic en la card: alterna el detalle de esta skin (como en Tableros).</summary>
        private void ToggleSkin(int index)
        {
            if (_detail != null
                && _detailIndex == index
                && _detail.ClassListContains(DETAIL_SKIN_CLASS)
                && _detail.ClassListContains("shop2-detail-open"))
            {
                if (_detailHost != null) _detailHost.CloseDetail();
                else
                {
                    _detail.RemoveFromClassList("shop2-detail-open");
                    _detail.AddToClassList("hidden");
                }
                ClearSelection();
                return;
            }

            SelectSkin(index);
        }

        /// <summary>Rellena kicker, precio, estado, lore, hero y CTA con la skin indicada.</summary>
        private void FillDetail(int index)
        {
            string name = PieceSkinManager.GetSkinName(index);
            string desc = PieceSkinManager.GetSkinDescription(index);
            PieceType type = PieceSkinManager.GetSkinPieceType(index);
            SkinRarity rarity = PieceSkinManager.GetSkinRarity(index);
            string rarityLabel = PieceSkinManager.RarityLabel(rarity);
            SkinAnimation anim = PieceSkinManager.GetSkinAnimation(index);
            bool owned = PieceSkinManager.IsOwned(index);
            bool equipped = PieceSkinManager.IsEquipped(index);
            int price = PieceSkinManager.GetSkinPrice(index);
            int balance = PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            if (_detailKicker != null)
            {
                _detailKicker.text = $"SKIN VISUAL  •  {rarityLabel}";
                ShopRarity.StyleDetailKicker(_detailKicker, rarityLabel);
            }
            if (_detailPrice != null)  _detailPrice.text = price <= 0 ? "GRATIS" : $"{price:N0} Gambits";
            if (_detailStock != null)
            {
                _detailStock.text = equipped ? "● EN USO"
                                  : owned ? "EN POSESIÓN · SE EQUIPA EN EL INVENTARIO"
                                  : "BLOQUEADO · SOLO VISUAL";
            }
            // Esta pestaña no tiene ofertas: apaga el distintivo de Halloween.
            ShopVariantSelector.ClearOfferBadge(_detail);

            // Ficha de aspecto: pieza + animación idle (las skins no tienen pasiva)
            var abilityTitle = _shopRoot.Q<Label>("shop-detail-ability");
            if (abilityTitle != null)
                abilityTitle.text = $"PIEZA  •  {PieceLabel(type)}  •  {AnimLabel(anim)}";
            if (_detailLore != null)
            {
                _detailLore.text = desc +
                    "  Solo visual: no cambia reglas ni pasivas." +
                    (owned ? "  Aquí solo se vende: se equipa desde el INVENTARIO."
                           : "  Al comprarla entra en tu INVENTARIO.");
            }

            // Hero (dentro del panel en la copia _Project; siempre visible en la Resources)
            var heroKicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (heroKicker != null) heroKicker.text = "ASPECTO DEL ATELIER";
            var heroName = _shopRoot.Q<Label>("bg-preview-name");
            if (heroName != null) heroName.text = name;
            var heroDesc = _shopRoot.Q<Label>("bg-preview-desc");
            if (heroDesc != null)
            {
                heroDesc.text = $"{rarityLabel}  ·  Aspecto visual para {PieceLabel(type).ToLowerInvariant()} ({AnimLabel(anim).ToLowerInvariant()}).";
                ShopRarity.StyleDetailKicker(heroDesc, rarityLabel);
            }

            // Insignia del hero: solo si la skin está equipada
            var heroBadge = _shopRoot.Q<VisualElement>(className: "shop2-hero-badge");
            if (heroBadge != null)
            {
                if (equipped) heroBadge.RemoveFromClassList("hidden");
                else heroBadge.AddToClassList("hidden");
            }

            var heroImg = _shopRoot.Q<Image>("bg-preview-image");
            if (heroImg != null)
            {
                Texture2D thumbTex = PieceSkinManager.GetSkinThumbnail(index);
                heroImg.image = null;
                heroImg.sprite = null;
                if (thumbTex != null)
                {
                    heroImg.image = thumbTex;
                }
                else
                {
                    heroImg.sprite = GetSkinArt(index);
                }
                heroImg.scaleMode = ScaleMode.ScaleToFit;
            }

            if (_detailAction == null)
            {
                RefreshCartButton();
                return;
            }
            _detailAction.SetEnabled(true);
            if (equipped)
            {
                _detailAction.text = "✓  EN USO";
                _detailAction.SetEnabled(false);
            }
            else if (owned)
            {
                // Ya es tuya: equipar vive en el inventario
                _detailAction.text = "✓  EN TU INVENTARIO";
                _detailAction.SetEnabled(false);
            }
            else if (price <= 0 || canAfford)
            {
                _detailAction.text = price <= 0 ? "🔓  ADQUIRIR" : $"🔓  COMPRAR — {price:N0} GAMBITS";
            }
            else
            {
                _detailAction.text = $"NECESITAS {price:N0} GAMBITS";
                _detailAction.SetEnabled(false);
            }

            RefreshCartButton();
        }

        // ── Carrito ─────────────────────────────────────────────────────────

        /// <summary>Añade la skin seleccionada al carrito (solo si falta comprarla).</summary>
        public bool TryAddSelectedToCart()
        {
            if (_cart == null || _detail == null) return false;
            if (_detail.ClassListContains("hidden")) return false;
            if (!_detail.ClassListContains(DETAIL_SKIN_CLASS)) return false;

            int index = _detailIndex;
            if (index < 0 || index >= PieceSkinManager.Count) return false;
            if (PieceSkinManager.IsOwned(index)) return false;

            int price = PieceSkinManager.GetSkinPrice(index);
            if (price <= 0) return false;

            var item = new ShopCartItem
            {
                productId = ProductId(index),
                displayName = PieceSkinManager.GetSkinName(index),
                description = "Aspecto de pieza · Tienda del Atelier",
                kindLabel = "SKIN",
                price = price,
                currency = ShopCurrency.Gambits,
                thumbnail = PieceSkinManager.GetSkinThumbnail(index),
                sprite = GetSkinArt(index),
                fallbackIcon = PieceSkinManager.GetSkinIcon(index),
                isOwned = () => PieceSkinManager.IsOwned(index),
                grant = () => GrantSkinFromCart(index),
            };
            return _cart.Add(item);
        }

        /// <summary>Pinta el botón secundario del detalle según la selección actual.</summary>
        public void RefreshCartButton()
        {
            if (_detail == null) return;

            // El panel aplica «shop2-detail-open» un frame después de mostrarse.
            bool showing = !_detail.ClassListContains("hidden")
                && _detail.ClassListContains(DETAIL_SKIN_CLASS);

            int index = _detailIndex;
            bool purchasable = showing
                && index >= 0 && index < PieceSkinManager.Count
                && !PieceSkinManager.IsOwned(index)
                && PieceSkinManager.GetSkinPrice(index) > 0;

            ShopCart.RefreshDetailButton(
                _detailCart, _cart,
                purchasable ? ProductId(index) : null,
                purchasable);
        }

        private static string ProductId(int index)
        {
            return "wilder-gambit-skin-" + PieceSkinManager.GetSkinId(index);
        }

        private void GrantSkinFromCart(int index)
        {
            string skinName = PieceSkinManager.GetSkinName(index);
            PieceSkinManager.OwnSkin(index);
            BalanceChanged?.Invoke();
            WilderGambit.Core.GambitProgress.NotifyChanged();
            Debug.Log($"[Shop] {skinName} entregada desde el carrito.");
        }

        /// <summary>CTA del panel: solo actúa si el panel está mostrando una skin.</summary>
        private void OnDetailAction()
        {
            if (_detail == null || !_detail.ClassListContains(DETAIL_SKIN_CLASS)) return;
            if (_detailIndex < 0 || _detailIndex >= PieceSkinManager.Count) return;
            if (PieceSkinManager.IsOwned(_detailIndex)) return;   // ya es tuya: el CTA está apagado

            OnAction(_detailIndex);
            SelectSkin(_detailIndex); // refresca el detalle y repinta la selección de la card
        }

        private void MarkSelectedCard(int index)
        {
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name == null || !child.name.StartsWith("skin-card-")) continue;
                bool isSelected = int.TryParse(child.name.Substring("skin-card-".Length), out int idx)
                                  && idx == index;
                if (isSelected) child.AddToClassList("bg-card-selected");
                else child.RemoveFromClassList("bg-card-selected");
            }
        }

        private void ClearSelection()
        {
            _detailIndex = -1;
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name != null && child.name.StartsWith("skin-card-"))
                    child.RemoveFromClassList("bg-card-selected");
            }
        }

        // ── Acciones ────────────────────────────────────────────────────────

        /// <summary>Solo compra: vestir la pieza vive en InventoryModal (pestaña SKINS).</summary>
        private void OnAction(int index)
        {
            if (index < 0 || index >= PieceSkinManager.Count) return;
            if (PieceSkinManager.IsOwned(index)) return;

            int price = PieceSkinManager.GetSkinPrice(index);
            int balance = PieceSkinManager.GetLocalGambits();
            if (balance < price)
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                Debug.Log($"[Shop] No tienes suficientes Gambits para {PieceSkinManager.GetSkinName(index)}. " +
                          $"Necesitas {price}, tienes {balance}.");
                Refresh();
                return;
            }

            // La tienda ya no cobra por su cuenta: el checkout global de
            // Surface muestra el ticket, valida saldo/topes y debita en el
            // servidor. La skin se entrega recién cuando el cobro vuelve OK.
            string skinName = PieceSkinManager.GetSkinName(index);
            string skinId = PieceSkinManager.GetSkinId(index);
            WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                "wilder-gambit-skin-" + skinId,
                skinName,
                "Aspecto de pieza · Tienda del Atelier",
                price,
                result =>
                {
                    if (!result.success)
                    {
                        WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                        Refresh();
                        return;
                    }

                    PieceSkinManager.OwnSkin(index);
                    BalanceChanged?.Invoke();
                    WilderGambit.Core.GambitProgress.NotifyChanged();

                    // Ya NO se equipa al comprar: la skin espera en el inventario.
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    Debug.Log($"[Shop] ¡{skinName} desbloqueado por {price} Gambits!");
                    Refresh();
                });
        }

        // ── Hero / preview ──────────────────────────────────────────────────

        /// <summary>
        /// Actualiza el hero de fondo para que no muestre un tablero al
        /// navegar el catálogo de skins.
        /// </summary>
        private void UpdateHero()
        {
            if (_shopRoot == null || PieceSkinManager.Count == 0) return;

            var kicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (kicker != null) kicker.text = "ASPECTO DEL ATELIER";

            var name = _shopRoot.Q<Label>("bg-preview-name");
            if (name != null) name.text = PieceSkinManager.GetSkinName(0);

            var desc = _shopRoot.Q<Label>("bg-preview-desc");
            if (desc != null)
                desc.text = "Elige un aspecto para ver la pieza y su acabado visual.";

            // Hero con el arte de la skin (borra el tablero que deje la pestaña Tableros;
            // ShopBackgroundSelector limpia este sprite al volver a su pestaña)
            var hero = _shopRoot.Q<Image>("bg-preview-image");
            if (hero != null)
            {
                Texture2D thumbTex = PieceSkinManager.GetSkinThumbnail(0);
                hero.image = null;
                hero.sprite = null;
                if (thumbTex != null) hero.image = thumbTex;
                else hero.sprite = GetSkinArt(0);
                hero.scaleMode = ScaleMode.ScaleToFit;
            }

            var badge = _shopRoot.Q<VisualElement>(className: "shop2-hero-badge");
            badge?.AddToClassList("hidden");
        }

        // ── Helpers ─────────────────────────────────────────────────────────

        /// <summary>Sprite base de la pieza (blancas) para cards y hero sin thumbnail.</summary>
        private static Sprite GetSkinArt(int index)
        {
            if (BoardView.Instance == null) return null;
            try
            {
                PieceType type = PieceSkinManager.GetSkinPieceType(index);
                return BoardView.Instance.GetPieceSprite(type, TeamColor.White);
            }
            catch
            {
                return null;
            }
        }

        internal static string PieceLabel(PieceType type)
        {
            switch (type)
            {
                case PieceType.Pawn: return "PEÓN";
                case PieceType.Knight: return "CABALLO";
                case PieceType.Bishop: return "ALFIL";
                case PieceType.NecromancerBishop: return "NIGROMANTE";
                case PieceType.Rook: return "TORRE";
                case PieceType.Queen: return "DAMA";
                case PieceType.King: return "REY";
                default: return type.ToString().ToUpperInvariant();
            }
        }

        internal static string AnimLabel(SkinAnimation anim)
        {
            switch (anim)
            {
                case SkinAnimation.None: return "SIN ANIMACIÓN";
                case SkinAnimation.Breathing: return "RESPIRACIÓN";
                case SkinAnimation.Fire: return "FUEGO";
                case SkinAnimation.Ice: return "HIELO";
                case SkinAnimation.Spectral: return "ESPECTRAL";
                case SkinAnimation.Embers: return "BRASAS";
                case SkinAnimation.Necrotic: return "NECRÓTICO";
                case SkinAnimation.Solar: return "SOLAR";
                case SkinAnimation.Abyssal: return "ABISAL";
                default: return anim.ToString().ToUpperInvariant();
            }
        }
    }
}
