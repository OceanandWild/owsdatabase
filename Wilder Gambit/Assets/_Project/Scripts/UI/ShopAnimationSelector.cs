using System;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Catálogo de ANIMACIONES de la tienda (pestaña tab-animations).
    /// Espejo liviano de ShopVariantSelector: se engancha al paginador global
    /// (ShopGridPager), reutiliza las cards .bg-card y comparte el panel de detalle
    /// shop2-detail (marcado con DETAIL_ANIM_CLASS para que cada pestaña atienda
    /// su propio CTA). Moneda: Gambits (priceTides &gt; 0 = se paga en Tides premium).
    /// Regla: la tienda vende, el inventario equipa
    /// (aquí la compra equipa directo: 1 animación activa por gatillo).
    /// </summary>
    public class ShopAnimationSelector : IShopCartSource
    {
        /// <summary>Marcador en shop2-detail: el panel lo está usando esta pestaña.</summary>
        internal const string DETAIL_ANIM_CLASS = "detail-showing-anim";

        /// <summary>Marca el panel de detalle compartido como ficha de animación.</summary>
        internal static void MarkAnimDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.AddToClassList(DETAIL_ANIM_CLASS);
            detail.AddToClassList(ShopVariantSelector.DETAIL_VARIANT_THEME_CLASS);
        }

        /// <summary>Devuelve el panel al estilo de Tableros (lo llama ShopModal al cambiar de pestaña).</summary>
        internal static void ClearAnimDetail(VisualElement detail)
        {
            if (detail == null) return;
            detail.RemoveFromClassList(DETAIL_ANIM_CLASS);
            detail.RemoveFromClassList(ShopVariantSelector.DETAIL_VARIANT_THEME_CLASS);
        }

        /// <summary>Se dispara tras una compra para que ShopModal refresque el chip de Gambits.</summary>
        public event Action BalanceChanged;

        private class AnimItem
        {
            public string id;
            public string displayName;
            public string icon;
            public string rarity;
            public string triggerLabel;
            public string durationLabel;
            public string abilityDesc;
            public int priceGambits;
            /// <summary>Precio en Tides (divisa premium). 0 = se paga en Gambits.</summary>
            public int priceTides;
            public Func<bool> isOwned;
            public Action own;
            public Func<bool> isEquipped;
            public Func<Sprite> art;
        }

        private static readonly AnimItem[] Items =
        {
            new AnimItem
            {
                id = DefeatFx.AnimId,
                displayName = "Ceniza al Viento",
                icon = "🌪️",
                rarity = "RARA",
                triggerLabel = "DERROTA",
                durationLabel = "2,0 s",
                abilityDesc =
                    "Al perder por mate, tus piezas se apagan en gris y suben como brasas " +
                    "que el viento se lleva a la izquierda sobre niebla del Atelier. " +
                    "Pura cosmética: no toca reglas ni recompensas.",
                priceGambits = DefeatFx.PriceGambits,
                isOwned = DefeatFx.IsOwned,
                own = DefeatFx.OwnAndEquip,
                isEquipped = DefeatFx.IsEquipped,
                art = () => DefeatFx.GetArtSprite(),
            },
            new AnimItem
            {
                id = DoubleCheckFx.AnimId,
                displayName = "Doble Filo",
                icon = "⚔️",
                rarity = "RARA",
                triggerLabel = "DOBLE JAQUE",
                durationLabel = "1,4 s",
                abilityDesc =
                    "Cuando dos piezas dan jaque a la vez, dos anillos rojos se entrelazan " +
                    "sobre el Rey con cruz destellante y sello. Combina con Sello de Sangre. " +
                    "Pura cosmética: no toca reglas ni recompensas.",
                priceGambits = DoubleCheckFx.PriceGambits,
                isOwned = DoubleCheckFx.IsOwned,
                own = DoubleCheckFx.OwnAndEquip,
                isEquipped = DoubleCheckFx.IsEquipped,
                art = () => DoubleCheckFx.GetArtSprite(),
            },
            new AnimItem
            {
                id = BrilliantFx.AnimId,
                displayName = "Destello Táctico",
                icon = "🌟",
                rarity = "ÉPICA",
                triggerLabel = "JUGADA BRILLANTE",
                durationLabel = "1,4 s",
                abilityDesc =
                    "Cuando el motor clasifica tu jugada como Brillante (!!), un destello " +
                    "dorado estalla sobre la casilla con el sello !! y anillos expansivos. " +
                    "Pura cosmética: no toca reglas ni recompensas.",
                priceGambits = BrilliantFx.PriceGambits,
                isOwned = BrilliantFx.IsOwned,
                own = BrilliantFx.OwnAndEquip,
                isEquipped = BrilliantFx.IsEquipped,
                art = () => BrilliantFx.GetArtSprite(),
            },
            new AnimItem
            {
                id = ForkCometFx.AnimId,
                displayName = "Cometa Ígnea",
                icon = "☄️",
                rarity = "ÉPICA",
                triggerLabel = "FORK",
                durationLabel = "1,2 s",
                abilityDesc =
                    "Cuando tu caballo clava una horquilla (2+ piezas atacadas), un cometa " +
                    "de fuego cruza y estalla sobre la casilla con onda de choque y brasas. " +
                    "Pura cosmética: no toca reglas ni recompensas.",
                priceTides = ForkCometFx.PriceTides,
                isOwned = ForkCometFx.IsOwned,
                own = ForkCometFx.OwnAndEquip,
                isEquipped = ForkCometFx.IsEquipped,
                art = () => ForkCometFx.GetArtSprite(),
            },
        };

        public static int Count => Items.Length;

        private readonly VisualElement _shopRoot;
        private readonly VisualElement _itemsGrid;
        private readonly ShopGridPager _pager;
        private readonly ShopBackgroundSelector _detailHost;
        private readonly ShopCart _cart;

        // Panel de detalle compartido (lo abre/colapsa el host de Tableros)
        private VisualElement _detail;
        private Button _detailAction;
        private Button _detailCart;
        private Button _previewButton;
        private Label _detailKicker;
        private Label _detailPrice;
        private Label _detailStock;
        private Label _detailLore;
        private int _detailIndex = -1;

        /// <summary>Oculta la entrada a la vista previa (cambio de pestaña / cierre).</summary>
        public void HidePreviewEntry()
        {
            ShopAnimationPreview.Hide();
            if (_previewButton != null) _previewButton.style.display = DisplayStyle.None;
        }

        public ShopAnimationSelector(VisualElement shopRoot, ShopGridPager pager, ShopBackgroundSelector detailHost = null, ShopCart cart = null)
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

            // VISTA PREVIA: botón propio de animaciones dentro del contenedor de
            // acciones del panel compartido. Solo visible con ficha de animación.
            _previewButton = new Button() { text = "▶  VISTA PREVIA", name = "btn-anim-preview" };
            // Este clic ya tiene dueño (el modal de preview): no debe burbujear
            // hasta la red de seguridad del rail del inventario.
            _previewButton.RegisterCallback<ClickEvent>(evt => { evt.StopPropagation(); OnPreviewClicked(); });
            // Los estilos (incluido :hover y :active) van en el USS, no por C#:
            // el estilo en linea gana contra el USS y el boton se veria plano.
            _previewButton.AddToClassList("btn-inline-gold");
            _previewButton.style.marginTop = 8f;
            _previewButton.style.display = DisplayStyle.None;
            var actionsWrap = shopRoot.Q<VisualElement>(className: "shop2-detail-actions");
            if (actionsWrap != null) actionsWrap.Add(_previewButton);
            else _detail?.Add(_previewButton);

            // CERRAR: además de colapsar el panel, suelta la selección de la card
            shopRoot.Q<Button>("btn-detail-close")?.RegisterCallback<ClickEvent>(_ => ClearSelection());
        }

        /// <summary>Conecta la fuente de animaciones al paginador global y repinta la página.</summary>
        public void Refresh()
        {
            if (_pager == null || _itemsGrid == null) return;
            _pager.SetSource(Items.Length, PopulatePage, resetPage: true);
            UpdateHero();
        }

        // ── Grid ────────────────────────────────────────────────────────────

        /// <summary>Puebla la página indicada por el paginador global de la tienda.</summary>
        private void PopulatePage(int start, int count)
        {
            if (_itemsGrid == null) return;

            _itemsGrid.Clear();
            // Vista de animaciones: cards centradas (son pocas y el arte manda)
            _itemsGrid.AddToClassList(ShopVariantSelector.GRID_VARIANT_CLASS);

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
            AnimItem item = Items[index];
            bool owned = item.isOwned();
            bool equipped = item.isEquipped();
            bool usesTides = item.priceTides > 0;
            int price = usesTides ? item.priceTides : item.priceGambits;
            int balance = usesTides ? GetPlayerTides() : PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            var card = new VisualElement();
            card.AddToClassList("bg-card");
            card.AddToClassList("bg-card-variant"); // showcase: card y thumb más grandes (USS)
            card.name = $"anim-card-{index}";
            if (equipped) card.AddToClassList("bg-card-active");

            // Clic en la card -> abre el panel de detalle con la info de la animación,
            // aunque el saldo no alcance para comprarla todavía
            card.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                ToggleAnim(index);
            });

            // Miniatura: arte propio si existe; si no, icono de fallback.
            // (Sin halos: la elipse de fondo tapaba el arte.)
            var thumbWrap = new VisualElement();
            thumbWrap.AddToClassList("bg-card-thumb");

            Sprite art = item.art != null ? item.art() : null;
            if (art != null)
            {
                var artImg = new Image { sprite = art, scaleMode = ScaleMode.ScaleToFit };
                artImg.AddToClassList("bg-card-thumb-img");
                thumbWrap.Add(artImg);
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
            // Contenedor fijo anclado abajo: alinea precios y estados.
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
                else footer.Add(GambitIcon.Price(price, 16f, "bg-card-state"));
            }
            else
            {
                var priceLabel = new Label(usesTides
                    ? $"🔒 Faltan {price - balance:N0} T"
                    : $"🔒 Faltan {price - balance:N0} G");
                priceLabel.AddToClassList("bg-card-state");
                priceLabel.AddToClassList("bg-card-state-locked");
                footer.Add(priceLabel);
            }
            card.Add(footer);

            ShopRarity.TintCardBorder(card, item.rarity, equipped);
            return card;
        }

        // ── Panel de detalle (compartido con la pestaña de Tableros) ───────────

        /// <summary>
        /// Abre el panel derecho con la info de la animación. Siempre se abre, aunque
        /// el jugador no tenga Gambits suficientes (el CTA explica lo que falta).
        /// </summary>
        private void SelectAnim(int index)
        {
            if (index < 0 || index >= Items.Length || _detail == null) return;

            _detailIndex = index;
            MarkSelectedCard(index);

            // El panel pasa a ser "de animaciones": ShopBackgroundSelector no debe comprar fondos
            // y la USS le da el layout de vista previa de pieza.
            MarkAnimDetail(_detail);
            FillDetail(index);

            if (_previewButton != null) _previewButton.style.display = DisplayStyle.Flex;

            if (_detailHost != null) _detailHost.OpenDetail();
            else
            {
                _detail.RemoveFromClassList("hidden");
                _detail.AddToClassList("shop2-detail-open");
            }
            RefreshCartButton();
        }

        /// <summary>Clic en la card: alterna el detalle de esta animación (como en Tableros).</summary>
        private void ToggleAnim(int index)
        {
            if (_detail != null
                && _detailIndex == index
                && _detail.ClassListContains(DETAIL_ANIM_CLASS)
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

            SelectAnim(index);
        }

        /// <summary>Rellena kicker, precio, estado, lore, hero y CTA con la animación indicada.</summary>
        private void FillDetail(int index)
        {
            AnimItem item = Items[index];
            bool owned = item.isOwned();
            bool equipped = item.isEquipped();
            bool usesTides = item.priceTides > 0;
            int price = usesTides ? item.priceTides : item.priceGambits;
            int balance = usesTides ? GetPlayerTides() : PieceSkinManager.GetLocalGambits();
            bool canAfford = balance >= price;

            if (_detailKicker != null)
            {
                _detailKicker.text = $"ANIMACIÓN  •  {ShopRarity.CanonicalLabel(item.rarity)}";
                ShopRarity.StyleDetailKicker(_detailKicker, item.rarity);
            }
            if (_detailPrice != null)  _detailPrice.text = usesTides ? $"💧 {price:N0} Tides" : $"{price:N0} Gambits";
            if (_detailStock != null)
            {
                _detailStock.text = equipped ? "● EN USO"
                                  : owned ? "EN POSESIÓN · SE EQUIPA EN EL INVENTARIO"
                                  : "BLOQUEADO";
            }
            // Esta pestaña no tiene ofertas: apaga el distintivo de Halloween.
            ShopVariantSelector.ClearOfferBadge(_detail);

            // Ficha de gatillo: título + mecánica
            var abilityTitle = _shopRoot.Q<Label>("shop-detail-ability");
            if (abilityTitle != null) abilityTitle.text = $"GATILLO  •  {item.triggerLabel}  •  {item.durationLabel}";
            if (_detailLore != null)
            {
                _detailLore.text = item.abilityDesc +
                    (owned ? "  Aquí solo se vende: se equipa desde el INVENTARIO."
                           : "  Al comprarla entra en tu INVENTARIO.");
            }

            // Hero (dentro del panel en la copia _Project; siempre visible en la Resources)
            var heroKicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (heroKicker != null) heroKicker.text = "ANIMACIÓN DEL ATELIER";
            var heroName = _shopRoot.Q<Label>("bg-preview-name");
            if (heroName != null) heroName.text = item.displayName;
            var heroDesc = _shopRoot.Q<Label>("bg-preview-desc");
            if (heroDesc != null)
            {
                heroDesc.text = $"{ShopRarity.CanonicalLabel(item.rarity)}  ·  Gatillo {item.triggerLabel} ({item.durationLabel}).";
                ShopRarity.StyleDetailKicker(heroDesc, item.rarity);
            }

            // Insignia del hero: solo si la animación está equipada
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
                _detailAction.text = usesTides ? $"🔓  COMPRAR — {price:N0} TIDES" : $"🔓  COMPRAR — {price:N0} GAMBITS";
            }
            else
            {
                _detailAction.text = usesTides ? $"NECESITAS {price:N0} TIDES" : $"NECESITAS {price:N0} GAMBITS";
                _detailAction.SetEnabled(false);
            }

            RefreshCartButton();
        }

        // ── Carrito ─────────────────────────────────────────────────────────

        /// <summary>Añade la animación seleccionada al carrito (solo si falta comprarla).</summary>
        public bool TryAddSelectedToCart()
        {
            if (_cart == null || _detail == null) return false;
            if (_detail.ClassListContains("hidden")) return false;
            if (!_detail.ClassListContains(DETAIL_ANIM_CLASS)) return false;

            int index = _detailIndex;
            if (index < 0 || index >= Items.Length) return false;

            AnimItem item = Items[index];
            if (item.isOwned()) return false;

            bool usesTides = item.priceTides > 0;
            int price = usesTides ? item.priceTides : item.priceGambits;
            if (price <= 0) return false;

            var cartItem = new ShopCartItem
            {
                productId = ProductId(item),
                displayName = item.displayName,
                description = "Animación de tablero · Atelier",
                kindLabel = "ANIMACIÓN",
                price = price,
                currency = usesTides ? ShopCurrency.Tides : ShopCurrency.Gambits,
                sprite = item.art != null ? item.art() : null,
                fallbackIcon = item.icon,
                isOwned = item.isOwned,
                grant = () => GrantAnimationFromCart(item),
            };
            return _cart.Add(cartItem);
        }

        /// <summary>Pinta el botón secundario del detalle según la selección actual.</summary>
        public void RefreshCartButton()
        {
            if (_detail == null) return;

            // El panel aplica «shop2-detail-open» un frame después de mostrarse.
            bool showing = !_detail.ClassListContains("hidden")
                && _detail.ClassListContains(DETAIL_ANIM_CLASS);

            int index = _detailIndex;
            bool purchasable = false;
            if (showing && index >= 0 && index < Items.Length && !Items[index].isOwned())
            {
                AnimItem item = Items[index];
                purchasable = (item.priceTides > 0 ? item.priceTides : item.priceGambits) > 0;
            }

            ShopCart.RefreshDetailButton(
                _detailCart, _cart,
                purchasable ? ProductId(Items[index]) : null,
                purchasable);
        }

        private static string ProductId(AnimItem item)
        {
            return "wilder-gambit-animation-" + item.id;
        }

        private void GrantAnimationFromCart(AnimItem item)
        {
            item.own();
            BalanceChanged?.Invoke();
            WilderGambit.Core.GambitProgress.NotifyChanged();
            Debug.Log($"[Shop] {item.displayName} entregada desde el carrito.");
        }

        /// <summary>CTA del panel: solo actúa si el panel está mostrando una animación.</summary>
        private void OnDetailAction()
        {
            if (_detail == null || !_detail.ClassListContains(DETAIL_ANIM_CLASS)) return;
            if (_detailIndex < 0 || _detailIndex >= Items.Length) return;
            if (Items[_detailIndex].isOwned()) return;   // ya es tuya: el CTA está apagado

            OnAction(_detailIndex);
            SelectAnim(_detailIndex); // refresca el detalle y repinta la selección de la card
        }

        private void MarkSelectedCard(int index)
        {
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name == null || !child.name.StartsWith("anim-card-")) continue;
                bool isSelected = int.TryParse(child.name.Substring("anim-card-".Length), out int idx)
                                  && idx == index;
                if (isSelected) child.AddToClassList("bg-card-selected");
                else child.RemoveFromClassList("bg-card-selected");
            }
        }

        private void ClearSelection()
        {
            _detailIndex = -1;
            HidePreviewEntry();
            if (_itemsGrid == null) return;
            foreach (var child in _itemsGrid.Children())
            {
                if (child.name != null && child.name.StartsWith("anim-card-"))
                    child.RemoveFromClassList("bg-card-selected");
            }
        }

        /// <summary>Botón VISTA PREVIA: abre el modal con el loop de la animación.</summary>
        private void OnPreviewClicked()
        {
            if (_detail == null || !_detail.ClassListContains(DETAIL_ANIM_CLASS)) return;
            if (_detailIndex < 0 || _detailIndex >= Items.Length) return;
            ShopAnimationPreview.Show(_shopRoot, Items[_detailIndex].id);
        }

        // ── Acciones ────────────────────────────────────────────────────────

        /// <summary>Solo compra: equipar vive en el inventario (aquí equipa directo:
        /// 1 animación activa por gatillo, sin ranuras que gestionar).</summary>
        private void OnAction(int index)
        {
            if (index < 0 || index >= Items.Length) return;
            AnimItem item = Items[index];
            if (item.isOwned()) return;

            bool usesTides = item.priceTides > 0;
            string coin = usesTides ? "Tides" : "Gambits";
            int price = usesTides ? item.priceTides : item.priceGambits;
            int balance = usesTides ? GetPlayerTides() : PieceSkinManager.GetLocalGambits();
            if (balance < price)
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                Debug.Log($"[Shop] No tienes suficientes {coin} para {item.displayName}. " +
                          $"Necesitas {price}, tienes {balance}.");
                Refresh();
                return;
            }

            // Entrega local sólo cuando Surface confirma el cobro.
            Action grant = () =>
            {
                item.own();
                BalanceChanged?.Invoke();
                Debug.Log($"[Shop] ¡{item.displayName} desbloqueado por {price} {coin}!");

                // Repintado del progreso (nueva pieza en propiedad)
                WilderGambit.Core.GambitProgress.NotifyChanged();

                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                Refresh();
            };

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

            if (price <= 0)
            {
                grant();
                return;
            }

            if (usesTides)
            {
                WilderGambit.Services.SurfaceCheckoutBridge.BuyTides(
                    "wilder-gambit-animation-" + item.id,
                    item.displayName,
                    "Animación de tablero · Atelier",
                    price,
                    afterPurchase);
            }
            else
            {
                WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                    "wilder-gambit-animation-" + item.id,
                    item.displayName,
                    "Animación de tablero · Atelier",
                    price,
                    afterPurchase);
            }
        }

        // ── Hero / preview ──────────────────────────────────────────────────

        /// <summary>
        /// Actualiza el hero de fondo para que no muestre un tablero al
        /// navegar el catálogo de animaciones.
        /// </summary>
        private void UpdateHero()
        {
            if (_shopRoot == null) return;

            var kicker = _shopRoot.Q<Label>("shop-hero-kicker");
            if (kicker != null) kicker.text = "ANIMACIÓN DEL ATELIER";

            var name = _shopRoot.Q<Label>("bg-preview-name");
            if (name != null) name.text = Items[0].displayName;

            var desc = _shopRoot.Q<Label>("bg-preview-desc");
            if (desc != null)
                desc.text = "Elige una animación para ver su gatillo y su efecto.";

            // Hero con el arte de la animación (borra el tablero que deje la pestaña Tableros;
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

        // ── Moneda ──────────────────────────────────────────────────────────

        private static int GetPlayerTides()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc != null && svc.IsLoggedIn && svc.CurrentUser != null)
                return Mathf.RoundToInt(svc.CurrentUser.tides);
            return PlayerPrefs.GetInt("PlayerTides", 0);
        }

        // ── Arte ────────────────────────────────────────────────────────────

        /// <summary>
        /// Carga perezosa del sprite ilustrativo. No cachea el fallo:
        /// si el PNG aún no está importado como Sprite, devuelve null y la UI
        /// usa el icono de fallback. Cuando el sprite se importe, aparece solo.
        /// </summary>
        internal static Sprite TryLoadAnimArt(string resourcePath)
        {
            if (string.IsNullOrEmpty(resourcePath)) return null;
            try
            {
                return Resources.Load<Sprite>(resourcePath);
            }
            catch
            {
                return null;
            }
        }
    }
}
