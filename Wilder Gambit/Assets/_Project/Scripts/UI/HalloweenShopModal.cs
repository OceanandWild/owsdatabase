using System;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// TIENDA DE LA VELADA — el destino de los Dulces de Halloween, abierta
    /// desde el botón TIENDA del pase (modal por encima de la velada).
    ///
    /// Tres pestañas:
    ///  · NIVELES   — niveles del mini-pase, incluido «completar todo el pase»
    ///                (carísimo a propósito). Solo con la velada activa.
    ///  · SKINS     — las seis esculpidas del lote hwp_*, con visor de las dos caras.
    ///  · VARIANTES — Peón Calabaza y Caballo Fantasma.
    ///
    /// Regla de la casa: **la tienda vende, el inventario equipa**. Las fichas
    /// ya compradas muestran «EN TU INVENTARIO» y llevan al macuto; ninguna
    /// compra pone nada en uso. El catálogo y los precios viven en
    /// <see cref="HalloweenShop"/>: aquí solo se pinta y se pide.
    /// </summary>
    public class HalloweenShopModal : MonoBehaviour
    {
        private const int TabLevels   = 0;
        private const int TabSkins    = 1;
        private const int TabVariants = 2;

        private VisualElement _root;
        private ScrollView _bodyScroll;

        private Button _tabLevels;
        private Button _tabSkins;
        private Button _tabVariants;

        private VisualElement _paneLevels;
        private VisualElement _paneSkins;
        private VisualElement _paneVariants;

        private VisualElement _listLevels;
        private VisualElement _listSkins;
        private VisualElement _listVariants;

        private Label _noteLevels;
        private Label _noteSkins;
        private Label _noteVariants;

        private Label _dulcesLabel;
        private Label _gambitsLabel;
        private Label _stateChip;
        private Label _footerNote;

        // ── Visor de vista previa (pestaña SKINS) ─────────────────────────
        // La tienda solo añade esto: una ficha grande con las dos caras de la
        // escultura seleccionada, su tipo, rareza y precio. No compra ni equipa.
        private VisualElement _preview;
        private Label _previewName;
        private Label _previewMeta;
        private VisualElement _previewWhiteSide;
        private VisualElement _previewBlackSide;
        private Image _previewWhite;
        private Image _previewBlack;
        private Label _previewWhiteEmpty;
        private Label _previewBlackEmpty;
        private VisualElement _previewChips;

        /// <summary>Oferta que enseña el visor (-1 = elegir la primera con lado negro).</summary>
        private int _previewIndex = -1;

        private int _tab = TabLevels;

        /// <summary>Firma del último repintado: evita rehacer las fichas por nada.</summary>
        private string _stamp;

        private Action _onClose;
        private Action<string> _onOpenInventory;
        private Action<string, string> _onToast;
        private bool _subscribed;

        // ── Ciclo de vida ─────────────────────────────────────────────────

        /// <summary>
        /// Se llama una vez desde MainMenuController tras cargar el UXML.
        /// </summary>
        /// <param name="onOpenInventory">
        /// Lleva al macuto en la pestaña pedida («skins» / «variants») cuando la
        /// ficha comprada invita a equiparla: la tienda nunca equipa sola.
        /// </param>
        public void Initialize(VisualElement root, Action onClose,
            Action<string, string> onToast = null, Action<string> onOpenInventory = null)
        {
            _root = root;
            _onClose = onClose;
            _onToast = onToast;
            _onOpenInventory = onOpenInventory;
            if (_root == null) return;

            _bodyScroll = _root.Q<ScrollView>("hwshop-body-scroll");

            _tabLevels = _root.Q<Button>("hwshop-tab-levels");
            _tabSkins = _root.Q<Button>("hwshop-tab-skins");
            _tabVariants = _root.Q<Button>("hwshop-tab-variants");

            _paneLevels = _root.Q<VisualElement>("hwshop-pane-levels");
            _paneSkins = _root.Q<VisualElement>("hwshop-pane-skins");
            _paneVariants = _root.Q<VisualElement>("hwshop-pane-variants");

            _listLevels = _root.Q<VisualElement>("hwshop-list-levels");
            _listSkins = _root.Q<VisualElement>("hwshop-list-skins");
            _listVariants = _root.Q<VisualElement>("hwshop-list-variants");

            _noteLevels = _root.Q<Label>("hwshop-note-levels");
            _noteSkins = _root.Q<Label>("hwshop-note-skins");
            _noteVariants = _root.Q<Label>("hwshop-note-variants");

            _dulcesLabel = _root.Q<Label>("hwshop-dulces-label");
            _gambitsLabel = _root.Q<Label>("hwshop-gambits-label");
            _stateChip = _root.Q<Label>("hwshop-state-chip");
            _footerNote = _root.Q<Label>("hwshop-footer-note");

            _root.Q<Button>("btn-close-hw-shop")?.RegisterCallback<ClickEvent>(_ => Close());
            _root.Q<Button>("btn-close-hw-shop-foot")?.RegisterCallback<ClickEvent>(_ => Close());

            _tabLevels?.RegisterCallback<ClickEvent>(_ => ShowTab(TabLevels));
            _tabSkins?.RegisterCallback<ClickEvent>(_ => ShowTab(TabSkins));
            _tabVariants?.RegisterCallback<ClickEvent>(_ => ShowTab(TabVariants));

            if (_listLevels == null || _listSkins == null || _listVariants == null)
                Debug.LogWarning("[HalloweenShopModal] Faltan listas «hwshop-list-*» en el UXML: la tienda no se pintará.");

            BuildPreview();
        }

        public void OnOpened()
        {
            if (!_subscribed)
            {
                GambitProgress.OnChanged += Refresh;
                _subscribed = true;
            }
            _stamp = null;
            ShowTab(_tab);
            Refresh();
        }

        public void OnClosed()
        {
            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        private void OnDestroy()
        {
            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        private void Close()
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            _onClose?.Invoke();
        }

        // ── Pestañas ──────────────────────────────────────────────────────

        private void ShowTab(int tab)
        {
            _tab = tab;

            _paneLevels?.EnableInClassList("hidden", tab != TabLevels);
            _paneSkins?.EnableInClassList("hidden", tab != TabSkins);
            _paneVariants?.EnableInClassList("hidden", tab != TabVariants);

            _tabLevels?.EnableInClassList("hwshop-tab-active", tab == TabLevels);
            _tabSkins?.EnableInClassList("hwshop-tab-active", tab == TabSkins);
            _tabVariants?.EnableInClassList("hwshop-tab-active", tab == TabVariants);

            if (_bodyScroll != null) _bodyScroll.scrollOffset = Vector2.zero;
        }

        // ── Pintado ───────────────────────────────────────────────────────

        public void Refresh()
        {
            if (_root == null) return;

            var phase = HalloweenEvent.CurrentPhase;
            string stamp = Stamp(phase);
            if (stamp == _stamp) return;
            _stamp = stamp;

            if (_dulcesLabel != null) _dulcesLabel.text = $"{HalloweenCurrency.Balance:N0}";
            if (_gambitsLabel != null) _gambitsLabel.text = $"{GambitEconomy.Balance:N0}";
            if (_stateChip != null)
                _stateChip.text = phase == HalloweenEvent.Phase.Active ? "¡VELADA ACTIVA!"
                    : phase == HalloweenEvent.Phase.NotStarted ? "PRÓXIMAMENTE" : "TERMINADA";

            RefreshTabLabels(phase);
            BuildLevels(phase);
            BuildSkins();
            BuildVariants();

            if (_footerNote != null)
                _footerNote.text = phase == HalloweenEvent.Phase.Active
                    ? "Los Dulces se ganan en las misiones de la velada · la tienda vende, el inventario equipa"
                    : phase == HalloweenEvent.Phase.NotStarted
                        ? $"La velada arranca el {HalloweenEvent.Start:dd/MM} · los niveles del pase se compran con la velada abierta"
                        : "La velada terminó: quedan las skins y las variantes";
        }

        private void RefreshTabLabels(HalloweenEvent.Phase phase)
        {
            int levels = HalloweenProgress.CurrentLevel;
            int tiers = HalloweenProgress.TierCount;

            if (_tabLevels != null) _tabLevels.text = $"✦ NIVELES · {levels}/{tiers}";
            if (_tabSkins != null) _tabSkins.text = $"🕷️ SKINS · {ShopSkinsOwned()}/{HalloweenShop.SkinOffers.Length}";
            if (_tabVariants != null) _tabVariants.text = $"🎃 VARIANTES · {ShopVariantsOwned()}/{HalloweenShop.VariantOffers.Length}";
        }

        private static int ShopSkinsOwned()
        {
            int n = 0;
            for (int i = 0; i < HalloweenShop.SkinOffers.Length; i++)
            {
                int idx = PieceSkinManager.GetIndexById(HalloweenShop.SkinOffers[i].skinId);
                if (idx >= 0 && PieceSkinManager.IsOwned(idx)) n++;
            }
            return n;
        }

        private static int ShopVariantsOwned()
        {
            int n = 0;
            for (int i = 0; i < HalloweenShop.VariantOffers.Length; i++)
                if (HalloweenShop.IsVariantOwned(HalloweenShop.VariantOffers[i].id)) n++;
            return n;
        }

        // ── Pestaña NIVELES ───────────────────────────────────────────────

        private void BuildLevels(HalloweenEvent.Phase phase)
        {
            if (_listLevels == null) return;
            _listLevels.Clear();

            _listLevels.Add(BuildLevelCard(HalloweenShop.LevelMidCount, HalloweenShop.LevelMidPrice,
                $"{HalloweenShop.LevelMidCount} NIVELES", "El tramo medio: baja unos Dulces por nivel."));
            _listLevels.Add(BuildLevelCard(HalloweenShop.LevelTenCount, HalloweenShop.LevelTenPrice,
                $"{HalloweenShop.LevelTenCount} NIVELES", "La decena: el mejor precio por nivel."));
            _listLevels.Add(BuildLevelCard(1, HalloweenShop.LevelPrice,
                "1 NIVEL", "Suelto: el precio más caro por nivel."));
            _listLevels.Add(BuildCompletePassCard());

            if (_noteLevels != null)
                _noteLevels.text = phase == HalloweenEvent.Phase.Active
                    ? $"{HalloweenProgress.Xp:N0}/{HalloweenProgress.MaxXp:N0} XP · nivel {HalloweenProgress.CurrentLevel} de {HalloweenProgress.TierCount}"
                      + (HalloweenShop.PassComplete ? " · pase completo" : $" · faltan {HalloweenShop.MissingLevels} niveles")
                    : phase == HalloweenEvent.Phase.NotStarted
                        ? $"Los niveles solo se compran con la velada abierta · arranca el {HalloweenEvent.Start:dd/MM}"
                        : "La velada terminó: el pase ya no vende niveles";
        }

        private VisualElement BuildLevelCard(int levels, int fullPrice, string title, string flavor)
        {
            int deliver = HalloweenShop.BulkLevels(levels);
            int price = HalloweenShop.BulkPrice(levels, fullPrice);
            bool onSale = HalloweenShop.LevelsOnSale;
            bool complete = HalloweenShop.PassComplete;
            bool afford = HalloweenCurrency.Balance >= price;

            var card = NewCard($"hwshop-levels-{levels}");

            card.Add(NewThumb("✦", null));

            var body = new VisualElement();
            body.AddToClassList("hwshop-card-body");

            var titleLabel = new Label(title);
            titleLabel.AddToClassList("hwshop-card-title");
            body.Add(titleLabel);

            var note = new Label(flavor);
            note.AddToClassList("hwshop-card-note");
            body.Add(note);

            string gainText = deliver > 0 && deliver != levels
                ? $"+{deliver} × {HalloweenProgress.XpPerTier} XP (solo faltan {deliver})"
                : $"+{levels} × {HalloweenProgress.XpPerTier} XP";
            var gain = new Label(gainText);
            gain.AddToClassList("hwshop-card-price");
            body.Add(gain);
            card.Add(body);

            if (!onSale)
            {
                card.Add(StatePill(
                    HalloweenEvent.IsNotStartedNow ? $"SE ABRE EL {HalloweenEvent.Start:dd/MM}" : "CERRADA",
                    "hwshop-state-locked"));
            }
            else if (complete)
            {
                card.Add(StatePill("PASE COMPLETO", "hwshop-state-on"));
            }
            else if (deliver <= 0 || price <= 0)
            {
                card.Add(StatePill("NADA POR COMPRAR", "hwshop-state-locked"));
            }
            else if (afford)
            {
                card.Add(BuyButton($"🔓 COMPRAR — {price:N0} {HalloweenCurrency.Icon}", () =>
                {
                    if (!HalloweenShop.BuyLevels(levels, fullPrice, out string detail))
                    {
                        Reject(detail);
                        return;
                    }
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    AfterPurchase("NIVELES ADQUIRIDOS", detail);
                }));
            }
            else
            {
                card.Add(StatePill($"NECESITAS {price:N0} {HalloweenCurrency.Icon}", "hwshop-state-off"));
            }

            return card;
        }

        private VisualElement BuildCompletePassCard()
        {
            int missing = HalloweenShop.MissingLevels;
            int price = HalloweenShop.CompletePassPrice;
            bool onSale = HalloweenShop.LevelsOnSale;
            bool complete = HalloweenShop.PassComplete;
            bool afford = HalloweenCurrency.Balance >= price;

            var card = NewCard("hwshop-levels-complete", "hwshop-card-complete");

            card.Add(NewThumb("🔓", null));

            var body = new VisualElement();
            body.AddToClassList("hwshop-card-body");

            var title = new Label("COMPLETAR TODO EL PASE");
            title.AddToClassList("hwshop-card-title");
            body.Add(title);

            var note = new Label(complete
                ? "El pase ya está completo: no queda nada que comprar."
                : $"Los {missing} niveles que faltan de golpe · {HalloweenShop.CompletePassPerLevel} "
                  + $"{HalloweenCurrency.Icon} por nivel: el atajo de lujo.");
            note.AddToClassList("hwshop-card-note");
            body.Add(note);

            var gain = new Label(complete ? "—" : $"{price:N0} {HalloweenCurrency.Icon}");
            gain.AddToClassList("hwshop-card-price");
            gain.AddToClassList("hwshop-card-price-lux");
            body.Add(gain);
            card.Add(body);

            if (!onSale)
            {
                card.Add(StatePill(
                    HalloweenEvent.IsNotStartedNow ? $"SE ABRE EL {HalloweenEvent.Start:dd/MM}" : "CERRADA",
                    "hwshop-state-locked"));
            }
            else if (complete)
            {
                card.Add(StatePill("PASE COMPLETO", "hwshop-state-on"));
            }
            else if (afford)
            {
                card.Add(BuyButton($"🔓 COMPLETAR — {price:N0} {HalloweenCurrency.Icon}", () =>
                {
                    if (!HalloweenShop.BuyCompletePass(out string detail))
                    {
                        Reject(detail);
                        return;
                    }
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    AfterPurchase("PASE COMPLETADO", detail);
                }));
            }
            else
            {
                card.Add(StatePill($"NECESITAS {price:N0} {HalloweenCurrency.Icon}", "hwshop-state-off"));
            }

            return card;
        }

        // ── Pestaña SKINS ─────────────────────────────────────────────────

        private void BuildSkins()
        {
            if (_listSkins == null) return;
            _listSkins.Clear();

            for (int i = 0; i < HalloweenShop.SkinOffers.Length; i++)
                _listSkins.Add(BuildSkinCard(i));

            if (_noteSkins != null)
                _noteSkins.text = "Arte propio para tus piezas · se equipan en el inventario, nunca aquí";

            RefreshPreview();
        }

        private VisualElement BuildSkinCard(int offerIndex)
        {
            HalloweenShop.SkinOffer offer = HalloweenShop.SkinOffers[offerIndex];
            int idx = PieceSkinManager.GetIndexById(offer.skinId);
            bool owned = idx >= 0 && PieceSkinManager.IsOwned(idx);
            bool equipped = idx >= 0 && PieceSkinManager.IsEquipped(idx);
            bool afford = HalloweenCurrency.Balance >= offer.price;

            string name = idx >= 0 ? PieceSkinManager.GetSkinName(idx) : offer.skinId;
            PieceType type = idx >= 0 ? PieceSkinManager.GetSkinPieceType(idx) : PieceType.Pawn;

            var card = NewCard($"hwshop-skin-{offerIndex}");
            if (equipped) card.AddToClassList("hwshop-card-equipped");

            card.Add(NewThumb(PieceSkinManager.GetSkinIcon(idx), null,
                idx >= 0 ? PieceSkinManager.GetSkinThumbnail(idx) : null));

            var body = new VisualElement();
            body.AddToClassList("hwshop-card-body");

            var title = new Label(name);
            title.AddToClassList("hwshop-card-title");
            body.Add(title);

            var note = new Label($"{type.ToString().ToUpperInvariant()} · {offer.flavor}");
            note.AddToClassList("hwshop-card-note");
            body.Add(note);

            var price = new Label($"{offer.price:N0} {HalloweenCurrency.Icon}");
            price.AddToClassList("hwshop-card-price");
            body.Add(price);
            card.Add(body);

            if (equipped)
            {
                card.Add(StatePill("✓ EN USO", "hwshop-state-on"));
            }
            else if (owned)
            {
                card.Add(StatePill("✔ EN TU INVENTARIO", "hwshop-state-owned"));
                HookInventory(card, InventoryModal.TAB_SKINS);
            }
            else if (!afford)
            {
                card.Add(StatePill($"NECESITAS {offer.price:N0} {HalloweenCurrency.Icon}", "hwshop-state-off"));
            }
            else
            {
                card.Add(BuyButton($"🔓 COMPRAR — {offer.price:N0} {HalloweenCurrency.Icon}", () =>
                {
                    if (!HalloweenShop.BuySkin(offer.skinId, out string detail))
                    {
                        Reject(detail);
                        return;
                    }
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    AfterPurchase("ESCULTURA ADQUIRIDA", detail);
                }));
            }

            return card;
        }

        // ── Visor de vista previa ─────────────────────────────────────────

        /// <summary>
        /// Monta la ficha del visor al principio de la pestaña SKINS. Se construye
        /// una sola vez; <see cref="RefreshPreview"/> solo cambia su contenido.
        /// </summary>
        private void BuildPreview()
        {
            if (_paneSkins == null || _preview != null) return;

            _preview = new VisualElement { name = "hwshop-preview" };
            _preview.AddToClassList("hwshop-preview");

            var head = new VisualElement();
            head.AddToClassList("hwshop-preview-head");

            var kicker = new Label("VISTA PREVIA");
            kicker.AddToClassList("hwshop-preview-kicker");
            head.Add(kicker);

            _previewName = new Label();
            _previewName.AddToClassList("hwshop-preview-name");
            head.Add(_previewName);

            _previewMeta = new Label();
            _previewMeta.AddToClassList("hwshop-preview-meta");
            head.Add(_previewMeta);

            _preview.Add(head);

            var stage = new VisualElement();
            stage.AddToClassList("hwshop-preview-stage");

            _previewWhiteSide = AddPreviewSide(stage, "BLANCAS", out _previewWhite, out _previewWhiteEmpty);
            _previewBlackSide = AddPreviewSide(stage, "NEGRAS",  out _previewBlack, out _previewBlackEmpty);
            _preview.Add(stage);

            _previewChips = new VisualElement();
            _previewChips.AddToClassList("hwshop-preview-chips");
            _preview.Add(_previewChips);

            // El visor va arriba del todo: es el escaparate de la pestaña.
            _paneSkins.Insert(0, _preview);
        }

        private static VisualElement AddPreviewSide(VisualElement stage, string caption,
            out Image image, out Label empty)
        {
            var side = new VisualElement();
            side.AddToClassList("hwshop-preview-side");

            var tag = new Label(caption);
            tag.AddToClassList("hwshop-preview-caption");
            side.Add(tag);

            image = new Image { scaleMode = ScaleMode.ScaleToFit };
            image.AddToClassList("hwshop-preview-art");
            side.Add(image);

            empty = new Label("✦");
            empty.AddToClassList("hwshop-preview-empty");
            empty.AddToClassList("hidden");
            side.Add(empty);

            stage.Add(side);
            return side;
        }

        /// <summary>
        /// Pinta la escultura elegida: las dos caras, el tipo, la rareza y el
        /// precio. Solo las skins con `_black` propio enseñan la cara negra; el
        /// resto cae al horneado en partida y aquí se queda en la blanca.
        /// </summary>
        private void RefreshPreview()
        {
            if (_preview == null) return;

            int count = HalloweenShop.SkinOffers.Length;
            if (count == 0)
            {
                _preview.AddToClassList("hidden");
                return;
            }
            _preview.RemoveFromClassList("hidden");

            if (_previewIndex < 0)
                _previewIndex = FirstOfferWithBlackArt();
            _previewIndex = Mathf.Clamp(_previewIndex, 0, count - 1);

            HalloweenShop.SkinOffer offer = HalloweenShop.SkinOffers[_previewIndex];
            int idx = PieceSkinManager.GetIndexById(offer.skinId);
            string name = idx >= 0 ? PieceSkinManager.GetSkinName(idx) : offer.skinId;
            PieceType type = idx >= 0 ? PieceSkinManager.GetSkinPieceType(idx) : PieceType.Pawn;
            SkinRarity rarity = idx >= 0 ? PieceSkinManager.GetSkinRarity(idx) : SkinRarity.Common;
            bool owned = idx >= 0 && PieceSkinManager.IsOwned(idx);
            bool equipped = idx >= 0 && PieceSkinManager.IsEquipped(idx);

            string artName = PieceSkinManager.GetSkinArtName(offer.skinId);
            bool hasBlack = HalloweenArt.ArtExists(HalloweenArt.PiecePath(artName, true));

            _previewName.text = name;

            string state = equipped ? " · EN USO"
                : owned ? " · EN TU INVENTARIO"
                : hasBlack ? " · LADO NEGRO PROPIO"
                : "";
            _previewMeta.text = $"{type.ToString().ToUpperInvariant()} · {PieceSkinManager.RarityLabel(rarity)}"
                + $" · {offer.price:N0} {HalloweenCurrency.Icon}{state}";

            ApplyPreviewArt(_previewWhite, _previewWhiteEmpty, artName, false, idx);
            _previewBlackSide.EnableInClassList("hidden", !hasBlack);
            if (hasBlack) ApplyPreviewArt(_previewBlack, _previewBlackEmpty, artName, true, idx);

            BuildPreviewChips(count);
        }

        private static void ApplyPreviewArt(Image image, Label empty, string artName, bool blackSide, int skinIndex)
        {
            if (image == null) return;

            // LoadSprite recibe el nombre del lote (sin «Halloween/», que ya
            // antepone HalloweenArt), igual que el resto de llamadas.
            string spriteName = string.IsNullOrEmpty(artName)
                ? null
                : artName + (blackSide ? HalloweenArt.BlackSuffix : "");
            Sprite art = string.IsNullOrEmpty(spriteName)
                ? null
                : HalloweenArt.LoadSprite(spriteName);

            image.sprite = art;
            image.EnableInClassList("hidden", art == null);

            if (empty == null) return;
            empty.EnableInClassList("hidden", art != null);
            if (art == null)
                empty.text = blackSide ? "SIN ARTE NEGRO"
                    : skinIndex >= 0 ? PieceSkinManager.GetSkinIcon(skinIndex) : "✦";
        }

        /// <summary>Primera oferta con `_black` propio; si no hay ninguna, la primera.</summary>
        private static int FirstOfferWithBlackArt()
        {
            for (int i = 0; i < HalloweenShop.SkinOffers.Length; i++)
            {
                string art = PieceSkinManager.GetSkinArtName(HalloweenShop.SkinOffers[i].skinId);
                if (!string.IsNullOrEmpty(art) && HalloweenArt.ArtExists(HalloweenArt.PiecePath(art, true)))
                    return i;
            }
            return 0;
        }

        private void BuildPreviewChips(int count)
        {
            if (_previewChips == null) return;
            _previewChips.Clear();

            for (int i = 0; i < count; i++)
            {
                int offerIndex = i;
                string id = HalloweenShop.SkinOffers[i].skinId;
                int idx = PieceSkinManager.GetIndexById(id);

                var chip = new Button(() =>
                {
                    if (_previewIndex == offerIndex) return;
                    _previewIndex = offerIndex;
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    RefreshPreview();
                })
                {
                    text = idx >= 0 ? PieceSkinManager.GetSkinName(idx) : id,
                };
                chip.AddToClassList("hwshop-preview-chip");
                chip.EnableInClassList("hwshop-preview-chip-active", i == _previewIndex);
                chip.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
                _previewChips.Add(chip);
            }
        }

        // ── Pestaña VARIANTES ─────────────────────────────────────────────

        private void BuildVariants()
        {
            if (_listVariants == null) return;
            _listVariants.Clear();

            for (int i = 0; i < HalloweenShop.VariantOffers.Length; i++)
                _listVariants.Add(BuildVariantCard(i));

            if (_noteVariants != null)
                _noteVariants.text = "Esculturas de la velada · entra al tablero con su arte y se equipan en el inventario";
        }

        private VisualElement BuildVariantCard(int offerIndex)
        {
            HalloweenShop.VariantOffer offer = HalloweenShop.VariantOffers[offerIndex];
            bool owned = HalloweenShop.IsVariantOwned(offer.id);
            bool equipped = HalloweenShop.IsVariantEquipped(offer.id);
            bool afford = HalloweenCurrency.Balance >= offer.price;

            var card = NewCard($"hwshop-variant-{offerIndex}");
            if (equipped) card.AddToClassList("hwshop-card-equipped");

            card.Add(NewThumb(offer.icon, VariantArt(offer.id)));

            var body = new VisualElement();
            body.AddToClassList("hwshop-card-body");

            var title = new Label(offer.name);
            title.AddToClassList("hwshop-card-title");
            body.Add(title);

            var note = new Label($"{offer.tag} · {offer.flavor}");
            note.AddToClassList("hwshop-card-note");
            body.Add(note);

            var price = new Label($"{offer.price:N0} {HalloweenCurrency.Icon}");
            price.AddToClassList("hwshop-card-price");
            body.Add(price);
            card.Add(body);

            if (equipped)
            {
                card.Add(StatePill("✓ EN USO", "hwshop-state-on"));
            }
            else if (owned)
            {
                card.Add(StatePill("✔ EN TU INVENTARIO", "hwshop-state-owned"));
                HookInventory(card, InventoryModal.TAB_VARIANTS);
            }
            else if (!afford)
            {
                card.Add(StatePill($"NECESITAS {offer.price:N0} {HalloweenCurrency.Icon}", "hwshop-state-off"));
            }
            else
            {
                card.Add(BuyButton($"🔓 COMPRAR — {offer.price:N0} {HalloweenCurrency.Icon}", () =>
                {
                    if (!HalloweenShop.BuyVariant(offer.id, out string detail))
                    {
                        Reject(detail);
                        return;
                    }
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    AfterPurchase("VARIANTE ADQUIRIDA", detail);
                }));
            }

            return card;
        }

        /// <summary>Arte de la variante para la ficha; si el PNG todavía no está, el sprite de su pieza.</summary>
        private static Sprite VariantArt(string variantId)
        {
            Sprite art = HalloweenArt.LoadSprite(HalloweenArt.ArtForVariant(variantId));
            if (art != null) return art;

            var view = BoardView.Instance;
            if (view == null) return null;
            switch (variantId)
            {
                case HalloweenArt.PumpkinPawnId: return view.GetPumpkinPawnSprite(TeamColor.White);
                case HalloweenArt.GhostKnightId: return view.GetGhostKnightSprite(TeamColor.White);
                default: return null;
            }
        }

        // ── Piezas de carta compartidas ───────────────────────────────────

        private static VisualElement NewCard(string name, string extraClass = null)
        {
            var card = new VisualElement { name = name };
            card.AddToClassList("hwshop-card");
            if (!string.IsNullOrEmpty(extraClass)) card.AddToClassList(extraClass);
            return card;
        }

        private static VisualElement NewThumb(string icon, Sprite art, Texture2D tex = null)
        {
            var thumb = new VisualElement();
            thumb.AddToClassList("hwshop-thumb");
            thumb.pickingMode = PickingMode.Ignore;

            if (tex != null)
            {
                var texImg = new Image { image = tex, scaleMode = ScaleMode.ScaleToFit };
                texImg.AddToClassList("hwshop-thumb-img");
                thumb.Add(texImg);
                return thumb;
            }

            if (art != null)
            {
                var img = new Image { sprite = art, scaleMode = ScaleMode.ScaleToFit };
                img.AddToClassList("hwshop-thumb-img");
                thumb.Add(img);
                return thumb;
            }

            var iconLabel = new Label(string.IsNullOrEmpty(icon) ? "✦" : icon);
            iconLabel.AddToClassList("hwshop-thumb-icon");
            thumb.Add(iconLabel);
            return thumb;
        }

        private static Button BuyButton(string text, Action onClick)
        {
            var btn = new Button(onClick) { text = text };
            btn.AddToClassList("hwshop-cta");
            btn.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
            return btn;
        }

        private static Label StatePill(string text, string stateClass)
        {
            var pill = new Label(text);
            pill.AddToClassList("hwshop-state");
            if (!string.IsNullOrEmpty(stateClass)) pill.AddToClassList(stateClass);
            pill.pickingMode = PickingMode.Ignore;
            return pill;
        }

        /// <summary>La ficha comprada invita al macuto: la tienda nunca equipa.</summary>
        private void HookInventory(VisualElement card, string tab)
        {
            card.RegisterCallback<ClickEvent>(_ =>
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                _onOpenInventory?.Invoke(tab);
            });
        }

        private void AfterPurchase(string title, string detail)
        {
            _stamp = null;
            GambitProgress.NotifyChanged();   // repinta la tienda, el pase y los contadores
            _onToast?.Invoke(title, detail);
        }

        private void Reject(string detail)
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            if (!string.IsNullOrEmpty(detail))
                _onToast?.Invoke("Tienda de la velada", detail);
        }

        // ── Firma del repintado ───────────────────────────────────────────

        private static string Stamp(HalloweenEvent.Phase phase)
        {
            var sb = new System.Text.StringBuilder(phase.ToString());
            sb.Append('|').Append(HalloweenCurrency.Balance)
              .Append('|').Append(GambitEconomy.Balance)
              .Append('|').Append(HalloweenProgress.Xp);

            for (int i = 0; i < HalloweenShop.SkinOffers.Length; i++)
            {
                int idx = PieceSkinManager.GetIndexById(HalloweenShop.SkinOffers[i].skinId);
                sb.Append('|').Append(idx >= 0 && PieceSkinManager.IsOwned(idx) ? 1 : 0)
                  .Append(idx >= 0 && PieceSkinManager.IsEquipped(idx) ? 1 : 0);
            }

            for (int i = 0; i < HalloweenShop.VariantOffers.Length; i++)
            {
                string id = HalloweenShop.VariantOffers[i].id;
                sb.Append('|').Append(HalloweenShop.IsVariantOwned(id) ? 1 : 0)
                  .Append(HalloweenShop.IsVariantEquipped(id) ? 1 : 0);
            }

            return sb.ToString();
        }
    }
}
