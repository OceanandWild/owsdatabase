using System;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Catálogo de VARIANTES DE PIEZAS de la tienda (pestaña tab-variants / 02 VARIANTES).
    /// Espejo liviano de ShopBackgroundSelector: se engancha al paginador global
    /// (ShopGridPager), reutiliza las cards .bg-card y comparte el panel de detalle
    /// shop2-detail con la pestaña de Tableros (marcado con DETAIL_VARIANT_CLASS para
    /// que cada pestaña atienda su propio CTA). Moneda: Gambits (no premium).
    /// </summary>
    public class ShopVariantSelector : IShopCartSource
    {
        /// <summary>Marcador en shop2-detail: el panel lo está usando esta pestaña.</summary>
        internal const string DETAIL_VARIANT_CLASS = "detail-showing-variant";

        /// <summary>Clase de presentación: la USS monta el panel como vista previa de pieza
        /// (arte enmarcado arriba y textos debajo, sin solapes).</summary>
        internal const string DETAIL_VARIANT_THEME_CLASS = "variant-detail";

        /// <summary>Clase del grid de la tienda: centra las cards cuando hay pocas variantes.</summary>
        internal const string GRID_VARIANT_CLASS = "grid-variants";

        /// <summary>Marca el panel de detalle compartido como ficha de variante.</summary>
        internal static void MarkVariantDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.AddToClassList(DETAIL_VARIANT_CLASS);
            detail.AddToClassList(DETAIL_VARIANT_THEME_CLASS);
        }

        /// <summary>Devuelve el panel al estilo de Tableros (lo llama ShopBackgroundSelector).</summary>
        internal static void ClearVariantDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.RemoveFromClassList(DETAIL_VARIANT_CLASS);
            detail.RemoveFromClassList(DETAIL_VARIANT_THEME_CLASS);
            ClearOfferBadge(detail);
        }

        /// <summary>
        /// Apaga el distintivo de oferta (Halloween) del panel de detalle: lo
        /// heredan todas las pestañas que comparten ese panel.
        /// </summary>
        internal static void ClearOfferBadge(VisualElement detail)
        {
            var badge = detail?.Q<Label>("shop-detail-offer");
            badge?.AddToClassList("hidden");
            if (badge != null) badge.text = "";
        }

        private readonly VisualElement _shopRoot;
        private readonly VisualElement _itemsGrid;
        private readonly ShopGridPager _pager;
        private readonly ShopBackgroundSelector _detailHost;
        private readonly ShopCart _cart;

        // Panel de detalle compartido (lo abre/colapsa el host de Tableros)
        private VisualElement _detail;
        private Button _detailAction;
        private Button _detailCart;
        private Label _detailKicker;
        private Label _detailPrice;
        private Label _detailStock;
        private Label _detailLore;
        private int _detailIndex = -1;

        /// <summary>Se dispara tras una compra para que ShopModal refresque el chip de Gambits.</summary>
        public event Action BalanceChanged;

        // ── Idle animado Dama Jinete (48 frames 2D en Resources/RiderQueenIdle) ──
        private static Sprite[] _riderIdleFrames;
        private readonly System.Collections.Generic.List<Image> _riderImages = new System.Collections.Generic.List<Image>();
        private IVisualElementScheduledItem _riderTicker;
        private int _riderFrameIdx;

        internal static Sprite[] RiderIdleFrames
        {
            get
            {
                if (_riderIdleFrames != null && _riderIdleFrames.Length > 0) return _riderIdleFrames;
                _riderIdleFrames = LoadRiderIdleFrames();
                return _riderIdleFrames;
            }
        }

        internal static Sprite RiderIdleFirstFrame()
        {
            var frames = RiderIdleFrames;
            if (frames != null && frames.Length > 0) return frames[0];
            return BoardView.Instance != null ? BoardView.Instance.GetRiderQueenSprite(TeamColor.White) : null;
        }

        private static Sprite[] LoadRiderIdleFrames()
        {
            try
            {
                var loaded = Resources.LoadAll<Sprite>("RiderQueenIdle");
                var list = new System.Collections.Generic.List<Sprite>();
                if (loaded != null)
                {
                    foreach (var s in loaded)
                        if (s != null && s.name.StartsWith("frame_")) list.Add(s);
                }
                if (list.Count == 0)
                {
                    string folder = System.IO.Path.Combine(UnityEngine.Application.dataPath, "Resources", "RiderQueenIdle");
                    if (System.IO.Directory.Exists(folder))
                    {
                        foreach (string file in System.IO.Directory.GetFiles(folder, "frame_*.png"))
                        {
                            try
                            {
                                byte[] bytes = System.IO.File.ReadAllBytes(file);
                                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                                if (tex.LoadImage(bytes))
                                {
                                    tex.filterMode = FilterMode.Bilinear;
                                    var spr = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                                    spr.name = System.IO.Path.GetFileNameWithoutExtension(file);
                                    list.Add(spr);
                                }
                            }
                            catch { /* un frame roto no tumba el idle */ }
                        }
                    }
                }
                list.Sort((a, b) => string.Compare(a.name, b.name, System.StringComparison.Ordinal));
                if (list.Count > 0) Debug.Log($"[Shop] RiderQueen idle: {list.Count} frames.");
                return list.ToArray();
            }
            catch { return new Sprite[0]; }
        }

        private void TrackRiderImage(Image img)
        {
            if (img == null) return;
            if (!_riderImages.Contains(img)) _riderImages.Add(img);
            EnsureRiderTicker();
        }

        private void EnsureRiderTicker()
        {
            if (_riderTicker != null || _shopRoot == null) return;
            _riderTicker = _shopRoot.schedule.Execute(TickRiderIdle).Every(83);
        }

        private void TickRiderIdle()
        {
            var frames = RiderIdleFrames;
            if (frames == null || frames.Length < 2) return;
            _riderFrameIdx = (_riderFrameIdx + 1) % frames.Length;
            Sprite f = frames[_riderFrameIdx];
            for (int i = _riderImages.Count - 1; i >= 0; i--)
            {
                var img = _riderImages[i];
                if (img == null || img.panel == null) { _riderImages.RemoveAt(i); continue; }
                img.sprite = f;
            }
        }

        private class VariantItem
        {
            public string id;
            public string displayName;
            public string icon;
            public string rarity;
            /// <summary>Pieza base de la variante (Peón, Alfil…), para los textos del hero.</summary>
            public string pieceLabel;
            /// <summary>Nombre de la pasiva sin prefijo («Lanza»).</summary>
            public string abilityName;
            /// <summary>Mecánica de la pasiva, texto plano para la ficha del detalle.</summary>
            public string abilityDesc;
            public int priceGambits;
            /// <summary>
            /// Precio en Tides (divisa premium). 0 = se paga en Gambits.
            /// Hoy solo la Dama Jinete es premium; el resto va en Gambits.
            /// </summary>
            public int priceTides;
            /// <summary>La variante tiene oferta de Halloween (precio rebajado en la velada).</summary>
            public bool halloweenOffer;
            public Func<bool> isOwned;
            public Action own;
            /// <summary>Solo para informar del estado: la tienda ya no equipa.</summary>
            public Func<bool> isEquipped;
            /// <summary>Arte propio de la variante (null → icono de fallback).</summary>
            public Func<Sprite> art;
        }

        private static readonly VariantItem[] Items =
        {
            new VariantItem
            {
                id = "necromancer",
                displayName = "Alfil Nigromante",
                icon = "💀",
                rarity = "ÉPICA",
                pieceLabel = "Alfil",
                abilityName = "Cosecha de Almas",
                abilityDesc =
                    "Pasiva: acumula almas con piezas aliadas capturadas (máx 4). " +
                    "Activa Alzamiento Menor: invoca un Peón Espectral en tu territorio. " +
                    "Al comprarla entra en tu INVENTARIO.",
                priceGambits = PieceLoadoutManager.NECROMANCER_PRICE_GAMBITS,
                halloweenOffer = true,   // -20% por Halloween (hasta el 31/10 23:59 UYT)
                isOwned = PieceLoadoutManager.IsNecroOwned,
                own = PieceLoadoutManager.OwnNecro,
                isEquipped = () => PieceLoadoutManager.UsesNecromancerBishop(TeamColor.White),
                art = () =>
                {
                    var view = BoardView.Instance;
                    if (view == null) return null;
                    Sprite necro = view.GetPieceSprite(PieceType.NecromancerBishop, TeamColor.White);
                    return necro != null ? necro : view.GetPieceSprite(PieceType.Bishop, TeamColor.White);
                },
            },
            new VariantItem
            {
                id = "lancer",
                displayName = "Peón Lancero",
                icon = "⚑",
                rarity = "RARA",
                pieceLabel = "Peón",
                abilityName = "Lanza",
                abilityDesc =
                    "Captura hacia adelante además de en diagonal y conserva el avance simple y " +
                    "doble: presiona el frente y complica las clavadas.",
                priceGambits = 0,
                priceTides = PieceLoadoutManager.LANCER_PRICE_TIDES,
                isOwned = PieceLoadoutManager.IsLancerOwned,
                own = PieceLoadoutManager.OwnLancer,
                isEquipped = () => PieceLoadoutManager.UsesLancerPawn(TeamColor.White),
                art = () => BoardView.Instance != null
                    ? BoardView.Instance.GetLancerPawnSprite(TeamColor.White)
                    : null,
            },
            new VariantItem
            {
                id = "rider",
                displayName = "Dama Jinete",
                icon = "♞",
                rarity = "LEGENDARIA",
                pieceLabel = "Dama",
                abilityName = "Cabalgada",
                abilityDesc =
                    "Una vez por partida, salta como un Caballo a una de sus 8 " +
                    "casillas, con captura. Por lo demás mueve como la Dama clásica.",
                priceGambits = 0,
                priceTides = PieceLoadoutManager.RIDER_PRICE_TIDES,
                isOwned = PieceLoadoutManager.IsRiderOwned,
                own = PieceLoadoutManager.OwnRider,
                isEquipped = () => PieceLoadoutManager.UsesRiderQueen(TeamColor.White),
                art = () => RiderIdleFirstFrame(),
            },
        };

        public ShopVariantSelector(VisualElement shopRoot, ShopGridPager pager, ShopBackgroundSelector detailHost = null, ShopCart cart = null)
        {
            _shopRoot = shopRoot;
            _pager = pager;
            _detailHost = detailHost;
            _cart = cart;

            var scrollView = shopRoot.Q<ScrollView>("shop-items-scroll");
            _itemsGrid = shopRoot.Q<VisualElement>("shop-items-grid");
            if (_itemsGrid == null && scrollView != null)
                _itemsGrid = scrollView.Q<VisualElement>("shop-items-grid");

            // Panel de detalle (derecha) — el mismo que usa la pestaña de Tableros
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

        /// <summary>Variantes disponibles en la tienda.</summary>
        public static int Count => Items.Length;

        /// <summary>Conecta la fuente de variantes al paginador global y repinta la página.</summary>
        public void Refresh()
        {
            if (_pager == null || _itemsGrid == null) return;
            _pager.SetSource(Items.Length, PopulatePage, resetPage: true);
            UpdateHero();
        }

        // ── Grid ────────────────────────────────────────────────────────────

        /// <summary>
        /// Precio final de la variante: el de lista, o el de la oferta de
        /// Halloween si la velada lo tiene activo.
        /// </summary>
        private static int PriceOf(VariantItem item, out bool discounted)
        {
            int listPrice = item.priceTides > 0 ? item.priceTides : item.priceGambits;
            discounted = item.halloweenOffer && HalloweenDiscount.IsActive;
            return discounted
                ? HalloweenDiscount.ApplyPercent(listPrice, HalloweenDiscount.NecromancerPercentOff)
                : listPrice;
        }

        /// <summary>
        /// Pie de la card: el precio final en Gambits y, si hay oferta, el
        /// distintivo de Halloween al lado.
        /// </summary>
        private static VisualElement PriceRow(int price, bool discounted)
        {
            var row = new VisualElement();
            row.AddToClassList("shop2-price-row");
            row.Add(GambitIcon.Price(price, 16f, "bg-card-state"));

            if (discounted)
            {
                var badge = new Label(HalloweenDiscount.Badge);
                badge.AddToClassList("shop2-discount-badge");
                row.Add(badge);
            }

            return row;
        }

        /// <summary>Puebla la página indicada por el paginador global de la tienda.</summary>
        private void PopulatePage(int start, int count)
        {
            if (_itemsGrid == null) return;

            _itemsGrid.Clear();
            // Vista de variantes: cards centradas (son pocas y el arte manda)
            _itemsGrid.AddToClassList(GRID_VARIANT_CLASS);

            int end = Mathf.Min(start + count, Items.Length);
            for (int i = start; i < end; i++)
                _itemsGrid.Add(CreateCard(i));

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
            VariantItem item = Items[index];
            bool owned = item.isOwned();
            bool equipped = item.isEquipped();
            bool usesTides = item.priceTides > 0;
            bool discounted;
            int price = PriceOf(item, out discounted);
            int balance = usesTides ? GetPlayerTides() : PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            var card = new VisualElement();
            card.AddToClassList("bg-card");
            card.AddToClassList("bg-card-variant"); // showcase: card y thumb más grandes (USS)
            card.name = $"variant-card-{index}";
            if (equipped) card.AddToClassList("bg-card-active");

            // Clic en la card -> abre el panel de detalle con la info de la variante,
            // aunque el saldo no alcance para comprarla todavía
            card.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                ToggleVariant(index);
            });

            // Miniatura: arte propio de la variante si existe; si no, icono de fallback.
            // Sin altura inline (la USS .bg-card-variant .bg-card-thumb la gobierna)
            // y sin el degradado inferior de las cards de tablero: tapa la base de la pieza.
            // (Sin halos: la elipse de fondo tapaba el arte.)
            var thumbWrap = new VisualElement();
            thumbWrap.AddToClassList("bg-card-thumb");

            Sprite art = item.art != null ? item.art() : null;
            if (art != null)
            {
                var artImg = new Image { sprite = art, scaleMode = ScaleMode.ScaleToFit };
                artImg.AddToClassList("bg-card-thumb-img");
                thumbWrap.Add(artImg);
                if (item.id == "rider") TrackRiderImage(artImg);
            }
            else
            {
                var iconLabel = new Label(item.icon);
                iconLabel.AddToClassList("bg-card-thumb-placeholder");
                thumbWrap.Add(iconLabel);
            }
            card.Add(thumbWrap);

            // Rareza (fila propia) + nombre (fila propia): no compiten por ancho
            var rarityRow = new VisualElement();
            rarityRow.AddToClassList("bg-card-rarity-row");
            var rarityLabel = new Label(item.rarity);
            ShopRarity.StyleCardLabel(rarityLabel, item.rarity);
            rarityRow.Add(rarityLabel);
            card.Add(rarityRow);

            var nameRow = new VisualElement();
            nameRow.AddToClassList("bg-card-name-row");
            nameRow.AddToClassList("bg-card-name-row-single");
            var nameLabel = new Label(item.displayName);
            nameLabel.AddToClassList("bg-card-name");
            nameRow.Add(nameLabel);
            card.Add(nameRow);

            // Pie de la card: un único rótulo de estado (la compra vive en el panel
            // de detalle, igual que en la pestaña de Tableros: nada duplicado).
            // Contenedor fijo anclado abajo: alinea precios, estados y descuentos.
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
            else if (canAfford)
            {
                if (usesTides)
                {
                    var tidesLabel = new Label($"💧 {price:N0} Tides");
                    tidesLabel.AddToClassList("bg-card-state");
                    footer.Add(tidesLabel);
                }
                else footer.Add(PriceRow(price, discounted));
            }
            else
            {
                var row = new VisualElement();
                row.AddToClassList("shop2-price-row");

                var priceLabel = new Label($"🔒 Faltan {price - balance:N0} {(usesTides ? "T" : "G")}");
                priceLabel.AddToClassList("bg-card-state");
                priceLabel.AddToClassList("bg-card-state-locked");
                row.Add(priceLabel);

                if (discounted)
                {
                    var badge = new Label(HalloweenDiscount.Badge);
                    badge.AddToClassList("shop2-discount-badge");
                    row.Add(badge);
                }

                footer.Add(row);
            }
            card.Add(footer);

            ShopRarity.TintCardBorder(card, item.rarity, equipped);
            return card;
        }

        // ── Panel de detalle (compartido con la pestaña de Tableros) ───────────

        /// <summary>
        /// Abre el panel derecho con la info de la variante. Siempre se abre, aunque
        /// el jugador no tenga Gambits suficientes (el CTA explica lo que falta).
        /// </summary>
        private void SelectVariant(int index)
        {
            if (index < 0 || index >= Items.Length || _detail == null) return;

            _detailIndex = index;
            MarkSelectedCard(index);

            // El panel pasa a ser "de variantes": ShopBackgroundSelector no debe comprar fondos
            // y la USS le da el layout de vista previa de pieza.
            MarkVariantDetail(_detail);
            FillDetail(index);

            if (_detailHost != null) _detailHost.OpenDetail();
            else
            {
                _detail.RemoveFromClassList("hidden");
                _detail.AddToClassList("shop2-detail-open");
            }
            RefreshCartButton();
        }

        /// <summary>Clic en la card: alterna el detalle de esta variante (como en Tableros).</summary>
        private void ToggleVariant(int index)
        {
            if (_detail != null
                && _detailIndex == index
                && _detail.ClassListContains(DETAIL_VARIANT_CLASS)
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

            SelectVariant(index);
        }

        /// <summary>Rellena kicker, precio, estado, lore, hero y CTA con la variante indicada.</summary>
        private void FillDetail(int index)
        {
            VariantItem item = Items[index];
            bool owned = item.isOwned();
            bool equipped = item.isEquipped();
            bool usesTides = item.priceTides > 0;
            bool discounted;
            int price = PriceOf(item, out discounted);
            string coin = usesTides ? "TIDES" : "GAMBITS";
            int balance = usesTides ? GetPlayerTides() : PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            if (_detailKicker != null)
            {
                _detailKicker.text = $"VARIANTE DE PIEZA  •  {ShopRarity.CanonicalLabel(item.rarity)}";
                ShopRarity.StyleDetailKicker(_detailKicker, item.rarity);
            }
            if (_detailPrice != null)  _detailPrice.text = usesTides ? $"💧 {price:N0} Tides" : $"{price:N0} Gambits";
            if (_detailStock != null)
            {
                _detailStock.text = equipped ? "● EN USO"
                                  : owned ? "EN POSESIÓN · SE EQUIPA EN EL INVENTARIO"
                                  : "BLOQUEADO";
            }

            // Distintivo de la oferta de Halloween (solo el Nigromante la tiene).
            var offerLabel = _shopRoot.Q<Label>("shop-detail-offer");
            if (offerLabel != null)
            {
                if (discounted)
                {
                    offerLabel.text = HalloweenDiscount.Badge;
                    offerLabel.RemoveFromClassList("hidden");
                }
                else offerLabel.AddToClassList("hidden");
            }

            // Ficha de pasiva: título + mecánica (antes era un solo párrafo largo)
            var abilityTitle = _shopRoot.Q<Label>("shop-detail-ability");
            if (abilityTitle != null) abilityTitle.text = $"PASIVA  •  {item.abilityName.ToUpperInvariant()}";
            if (_detailLore != null)
            {
                _detailLore.text = item.abilityDesc +
                    (owned ? "  Aquí solo se vende: se equipa desde el INVENTARIO."
                           : "  Al comprarla entra en tu INVENTARIO.") +
                    (discounted ? "  " + HalloweenDiscount.Note : "");
            }

            // Hero (dentro del panel en la copia _Project; siempre visible en la Resources)
            var heroKicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (heroKicker != null) heroKicker.text = "PIEZA DE ATELIER";
            var heroName = _shopRoot.Q<Label>("bg-preview-name");
            if (heroName != null) heroName.text = item.displayName;
            var heroDesc = _shopRoot.Q<Label>("bg-preview-desc");
            if (heroDesc != null)
            {
                heroDesc.text = $"{ShopRarity.CanonicalLabel(item.rarity)}  ·  Variante de {item.pieceLabel} con la pasiva «{item.abilityName}».";
                ShopRarity.StyleDetailKicker(heroDesc, item.rarity);
            }

            // Insignia del hero: solo si la variante está equipada
            var heroBadge = _shopRoot.Q<VisualElement>(className: "shop2-hero-badge");
            if (heroBadge != null)
            {
                if (equipped) heroBadge.RemoveFromClassList("hidden");
                else heroBadge.AddToClassList("hidden");
            }

            var heroImg = _shopRoot.Q<Image>("bg-preview-image");
            if (heroImg != null)
            {
                Sprite art = item.art != null ? item.art() : null;
                heroImg.image = null;
                heroImg.sprite = art;
                heroImg.scaleMode = ScaleMode.ScaleToFit;
                if (item.id == "rider") TrackRiderImage(heroImg);
                else _riderImages.Remove(heroImg);
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
            else if (canAfford)
            {
                _detailAction.text = $"🔓  COMPRAR — {price:N0} {coin}";
            }
            else
            {
                _detailAction.text = $"NECESITAS {price:N0} {coin}";
                _detailAction.SetEnabled(false);
            }

            RefreshCartButton();
        }

        // ── Carrito ─────────────────────────────────────────────────────────

        /// <summary>Añade la variante seleccionada al carrito (solo si falta comprarla).</summary>
        public bool TryAddSelectedToCart()
        {
            if (_cart == null || _detail == null) return false;
            if (_detail.ClassListContains("hidden")) return false;
            if (!_detail.ClassListContains(DETAIL_VARIANT_CLASS)) return false;

            int index = _detailIndex;
            if (index < 0 || index >= Items.Length) return false;

            VariantItem item = Items[index];
            if (item.isOwned()) return false;

            bool discounted;
            int price = PriceOf(item, out discounted);
            if (price <= 0) return false;

            var cartItem = new ShopCartItem
            {
                productId = ProductId(item),
                displayName = item.displayName,
                description = "Variante de " + item.pieceLabel + " · " + item.abilityName +
                              (discounted ? " · oferta de Halloween" : ""),
                kindLabel = "VARIANTE",
                price = price,
                currency = item.priceTides > 0 ? ShopCurrency.Tides : ShopCurrency.Gambits,
                sprite = item.art != null ? item.art() : null,
                fallbackIcon = item.icon,
                isOwned = item.isOwned,
                grant = () => GrantVariantFromCart(item, price, discounted),
            };
            return _cart.Add(cartItem);
        }

        /// <summary>Pinta el botón secundario del detalle según la selección actual.</summary>
        public void RefreshCartButton()
        {
            if (_detail == null) return;

            // El panel aplica «shop2-detail-open» un frame después de mostrarse.
            bool showing = !_detail.ClassListContains("hidden")
                && _detail.ClassListContains(DETAIL_VARIANT_CLASS);

            int index = _detailIndex;
            bool purchasable = false;
            if (showing && index >= 0 && index < Items.Length && !Items[index].isOwned())
            {
                bool discounted;
                purchasable = PriceOf(Items[index], out discounted) > 0;
            }

            ShopCart.RefreshDetailButton(
                _detailCart, _cart,
                purchasable ? ProductId(Items[index]) : null,
                purchasable);
        }

        private static string ProductId(VariantItem item)
        {
            return "wilder-gambit-variant-" + item.id;
        }

        private void GrantVariantFromCart(VariantItem item, int price, bool discounted)
        {
            item.own();
            BalanceChanged?.Invoke();
            Debug.Log($"[Shop] {item.displayName} entregado desde el carrito por {price} " +
                      $"{(item.priceTides > 0 ? "Tides" : "Gambits")}." +
                      (discounted ? $" (oferta de Halloween -{HalloweenDiscount.NecromancerPercentOff}%)" : ""));

            WilderGambit.Core.GambitProgress.SyncVariantsOwned();
            WilderGambit.Core.GambitProgress.NotifyChanged();
        }

        /// <summary>CTA del panel: solo actúa si el panel está mostrando una variante.</summary>
        private void OnDetailAction()
        {
            if (_detail == null || !_detail.ClassListContains(DETAIL_VARIANT_CLASS)) return;
            if (_detailIndex < 0 || _detailIndex >= Items.Length) return;
            if (Items[_detailIndex].isOwned()) return;   // ya es tuya: el CTA está apagado

            OnAction(_detailIndex);
            SelectVariant(_detailIndex); // refresca el detalle y repinta la selección de la card
        }

        private void MarkSelectedCard(int index)
        {
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name == null || !child.name.StartsWith("variant-card-")) continue;
                bool isSelected = int.TryParse(child.name.Substring("variant-card-".Length), out int idx)
                                  && idx == index;
                if (isSelected) child.AddToClassList("bg-card-selected");
                else child.RemoveFromClassList("bg-card-selected");
            }
        }

        private void ClearSelection()
        {
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name != null && child.name.StartsWith("variant-card-"))
                    child.RemoveFromClassList("bg-card-selected");
            }
        }

        // ── Acciones ────────────────────────────────────────────────────────

        /// <summary>Solo compra: poner la pieza vive en InventoryModal.</summary>
        private void OnAction(int index)
        {
            if (index < 0 || index >= Items.Length) return;
            VariantItem item = Items[index];
            if (item.isOwned()) return;

            bool usesTides = item.priceTides > 0;
            string coin = usesTides ? "Tides" : "Gambits";
            bool discounted;
            int price = PriceOf(item, out discounted);
            int balance = usesTides ? GetPlayerTides() : PieceSkinManager.GetLocalGambits();
            if (balance < price)
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                Debug.Log($"[Shop] No tienes suficientes {coin} para {item.displayName}. " +
                          $"Necesitas {price}, tienes {balance}.");
                Refresh();
                return;
            }

            // Entrega local recién después de que Surface confirma el cobro.
            // El precio con descuento de Halloween es el que se cobra.
            Action grant = () =>
            {
                item.own();
                BalanceChanged?.Invoke();
                Debug.Log($"[Shop] ¡{item.displayName} desbloqueado por {price} {coin}!" +
                          (discounted ? $" (oferta de Halloween -{HalloweenDiscount.NecromancerPercentOff}%)" : ""));

                // Logros de coleccionista y repintado del progreso (nueva variante en propiedad)
                WilderGambit.Core.GambitProgress.SyncVariantsOwned();
                WilderGambit.Core.GambitProgress.NotifyChanged();

                // Ya NO se equipa al comprar: la variante espera en el inventario.
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                Refresh();
            };

            string description = "Variante de " + item.pieceLabel + " · " + item.abilityName +
                                 (discounted ? " · oferta de Halloween" : "");
            Action<OWS.Surface.SurfacePurchaseResult> afterPurchase = result =>
            {
                if (!result.success)
                {
                    WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                    Refresh();
                    return;
                }
                grant();
            };

            if (usesTides)
            {
                WilderGambit.Services.SurfaceCheckoutBridge.BuyTides(
                    "wilder-gambit-variant-" + item.id, item.displayName, description, price, afterPurchase);
            }
            else
            {
                WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                    "wilder-gambit-variant-" + item.id, item.displayName, description, price, afterPurchase);
            }
        }

        // ── Hero / preview ──────────────────────────────────────────────────

        /// <summary>
        /// Actualiza el hero de fondo (siempre visible en la copia Resources; dentro del
        /// panel de detalle en la copia _Project) para que no muestre un tablero al
        /// navegar el catálogo de variantes.
        /// </summary>
        private void UpdateHero()
        {
            if (_shopRoot == null) return;

            var kicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (kicker != null) kicker.text = "PIEZA DE ATELIER";

            var name = _shopRoot.Q<Label>("bg-preview-name");
            if (name != null) name.text = Items[0].displayName;

            var desc = _shopRoot.Q<Label>("bg-preview-desc");
            if (desc != null)
                desc.text = "Elige una variante para ver el arte de la pieza y su pasiva.";

            // Hero con el arte de la variante (borra el tablero que deje la pestaña Tableros;
            // ShopBackgroundSelector limpia este sprite al volver a su pestaña)
            var hero = _shopRoot.Q<Image>("bg-preview-image");
            if (hero != null)
            {
                Sprite art = Items[0].art != null ? Items[0].art() : null;
                hero.image = null;
                hero.sprite = art;
                hero.scaleMode = ScaleMode.ScaleToFit;
            }

            var badge = _shopRoot.Q<VisualElement>(className: "shop2-hero-badge");
            badge?.AddToClassList("hidden");
        }

        // ── Moneda premium (Tides) ──────────────────────────────────────────

        private static int GetPlayerTides()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc != null && svc.IsLoggedIn && svc.CurrentUser != null)
                return Mathf.RoundToInt(svc.CurrentUser.tides);
            return PlayerPrefs.GetInt("PlayerTides", 0);
        }
    }
}
