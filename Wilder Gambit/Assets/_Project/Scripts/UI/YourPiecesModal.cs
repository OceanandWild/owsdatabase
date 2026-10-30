using System;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Controlador del modal "Tus Piezas": el <b>catálogo</b> de la colección. Aquí se
    /// consulta y se compra (skins con Gambits), pero desde el INVENTARIO se equipa:
    /// este modal solo dice qué tienes y qué está puesto (ver InventoryModal).
    /// </summary>
    public class YourPiecesModal : MonoBehaviour
    {
        private VisualElement _modalRoot;
        private VisualElement _cardClassic;
        private VisualElement _cardNecro;
        private Button _btnEquipClassic;
        private Button _btnEquipNecro;
        private Label _lblStatusClassic;
        private Label _lblStatusNecro;

        // Variante Peón Lancero (V4)
        private VisualElement _cardPawnClassic;
        private VisualElement _cardPawnLancer;
        private Button _btnEquipPawnClassic;
        private Button _btnEquipPawnLancer;
        private Label _lblStatusPawnClassic;
        private Label _lblStatusPawnLancer;

        // Variantes de Dama (Jinete + Vampira)
        private VisualElement _cardQueenClassic;
        private VisualElement _cardQueenRider;
        private VisualElement _cardQueenVampire;
        private Button _btnEquipQueenClassic;
        private Button _btnEquipQueenRider;
        private Button _btnEquipQueenVampire;
        private Label _lblStatusQueenClassic;
        private Label _lblStatusQueenRider;
        private Label _lblStatusQueenVampire;
        private Button _btnClose;

        // Skins grid
        private VisualElement _skinsGrid;
        private ScrollView _skinsScroll;
        private Label _skinsGambitsLabel;
        private Button _filterAll, _filterKnight, _filterBishop, _filterQueen, _filterPawn;
        private string _currentFilter = "all";

        // Enciclopedia
        private VisualElement _encyGrid;
        private Button _encyFilterAll, _encyFilterBishop, _encyFilterPawn, _encyFilterOthers;
        private string _encyFilter = "all";

        public void Initialize(VisualElement modalRoot, System.Action onCloseCallback)
        {
            _modalRoot = modalRoot;
            if (_modalRoot == null) return;

            _cardClassic = _modalRoot.Q<VisualElement>("card-bishop-classic");
            _cardNecro   = _modalRoot.Q<VisualElement>("card-bishop-necro");

            _cardPawnClassic = _modalRoot.Q<VisualElement>("card-pawn-classic");
            _cardPawnLancer  = _modalRoot.Q<VisualElement>("card-pawn-lancer");

            _cardQueenClassic = _modalRoot.Q<VisualElement>("card-queen-classic");
            _cardQueenRider   = _modalRoot.Q<VisualElement>("card-queen-rider");
            _cardQueenVampire = _modalRoot.Q<VisualElement>("card-queen-vampire");

            _btnEquipClassic = _modalRoot.Q<Button>("btn-equip-classic");
            _btnEquipNecro   = _modalRoot.Q<Button>("btn-equip-necro");

            _lblStatusClassic = _modalRoot.Q<Label>("lbl-status-classic");
            _lblStatusNecro   = _modalRoot.Q<Label>("lbl-status-necro");

            _btnEquipPawnClassic = _modalRoot.Q<Button>("btn-equip-pawn-classic");
            _btnEquipPawnLancer  = _modalRoot.Q<Button>("btn-equip-pawn-lancer");
            _lblStatusPawnClassic = _modalRoot.Q<Label>("lbl-status-pawn-classic");
            _lblStatusPawnLancer  = _modalRoot.Q<Label>("lbl-status-pawn-lancer");

            _btnEquipQueenClassic = _modalRoot.Q<Button>("btn-equip-queen-classic");
            _btnEquipQueenRider   = _modalRoot.Q<Button>("btn-equip-queen-rider");
            _btnEquipQueenVampire = _modalRoot.Q<Button>("btn-equip-queen-vampire");
            _lblStatusQueenClassic = _modalRoot.Q<Label>("lbl-status-queen-classic");
            _lblStatusQueenRider   = _modalRoot.Q<Label>("lbl-status-queen-rider");
            _lblStatusQueenVampire = _modalRoot.Q<Label>("lbl-status-queen-vampire");

            _btnClose = _modalRoot.Q<Button>("btn-close-your-pieces");

            // Sprites de retrato: usar el Nigromante si existe textura propia; si no, fallback al clásico
            var boardView = BoardView.Instance;
            var classicSprite = boardView != null
                ? boardView.GetPieceSprite(PieceType.Bishop, TeamColor.White)
                : null;
            var necroSprite = boardView != null
                ? boardView.GetPieceSprite(PieceType.NecromancerBishop, TeamColor.White)
                : classicSprite;

            var imgClassic = _modalRoot.Q<Image>("img-bishop-classic");
            var imgNecro   = _modalRoot.Q<Image>("img-bishop-necro");
            if (imgClassic != null) imgClassic.sprite = classicSprite;
            if (imgNecro != null)
            {
                imgNecro.sprite = necroSprite;
                imgNecro.EnableInClassList("variant-portrait-untinted", necroSprite != classicSprite);
            }

            // Retratos de peón: el Clásico con su sprite base y el Lancero con su arte propio
            var pawnSprite = boardView != null
                ? boardView.GetPieceSprite(PieceType.Pawn, TeamColor.White)
                : null;
            var lancerSprite = boardView != null
                ? boardView.GetLancerPawnSprite(TeamColor.White)
                : null;
            var imgPawnClassic = _modalRoot.Q<Image>("img-pawn-classic");
            var imgPawnLancer  = _modalRoot.Q<Image>("img-pawn-lancer");
            if (imgPawnClassic != null) imgPawnClassic.sprite = pawnSprite;
            if (imgPawnLancer != null)
            {
                imgPawnLancer.sprite = lancerSprite != null ? lancerSprite : pawnSprite;

                // El arte del Lancero es más alto (lanza + pendón): el cuerpo del peón ocupa
                // 744/900 del sprite, así que su caja se agranda para que el cuerpo mida lo
                // mismo que el retrato del Peón Clásico. Se recalcula cuando cambia el Clásico
                // (las media queries de la USS redimensionan los dos retratos).
                if (lancerSprite != null && lancerSprite != pawnSprite)
                {
                    System.Action fit = () =>
                    {
                        float baseW = imgPawnClassic != null ? imgPawnClassic.resolvedStyle.width : 0f;
                        if (float.IsNaN(baseW) || baseW <= 1f) baseW = 100f;
                        float box = baseW * (900f / 744f);
                        imgPawnLancer.style.width = box;
                        imgPawnLancer.style.height = box;
                    };
                    imgPawnLancer.schedule.Execute(fit);
                    imgPawnClassic?.RegisterCallback<GeometryChangedEvent>(_ => fit());
                }
            }

            // Retratos de dama: la Clásica con su sprite base y la Jinete con su arte propio
            // (más ancha por espada + puño: el Image la ajusta con ScaleToFit, sin hack de caja)
            var queenSprite = boardView != null
                ? boardView.GetPieceSprite(PieceType.Queen, TeamColor.White)
                : null;
            var riderSprite = boardView != null
                ? boardView.GetRiderQueenSprite(TeamColor.White)
                : null;
            var imgQueenClassic = _modalRoot.Q<Image>("img-queen-classic");
            var imgQueenRider   = _modalRoot.Q<Image>("img-queen-rider");
            if (imgQueenClassic != null) imgQueenClassic.sprite = queenSprite;
            if (imgQueenRider != null)
            {
                imgQueenRider.sprite = riderSprite != null ? riderSprite : queenSprite;
                imgQueenRider.EnableInClassList("variant-portrait-untinted", riderSprite != null && riderSprite != queenSprite);
            }

            // Retrato de la Vampira: arte propio de la velada, con la Dama clásica como red de seguridad
            var vampireSprite = boardView != null
                ? boardView.GetVampireQueenSprite(TeamColor.White)
                : null;
            var imgQueenVampire = _modalRoot.Q<Image>("img-queen-vampire");
            if (imgQueenVampire != null)
            {
                imgQueenVampire.sprite = vampireSprite != null ? vampireSprite : queenSprite;
                imgQueenVampire.EnableInClassList("variant-portrait-untinted", vampireSprite != null && vampireSprite != queenSprite);
            }
            // Los botones de variante ya no equipan: son el rótulo de estado de cada carta
            // (equipar vive en el INVENTARIO). Quedan desactivados y sin eventos de clic.
            _btnEquipClassic?.SetEnabled(false);
            _btnEquipNecro?.SetEnabled(false);
            _btnEquipPawnClassic?.SetEnabled(false);
            _btnEquipPawnLancer?.SetEnabled(false);
            _btnEquipQueenClassic?.SetEnabled(false);
            _btnEquipQueenRider?.SetEnabled(false);
            _btnEquipQueenVampire?.SetEnabled(false);

            _btnClose?.RegisterCallback<ClickEvent>(_ => onCloseCallback?.Invoke());

            // Skins grid
            _skinsGrid = _modalRoot.Q<VisualElement>("skins-grid");
            _skinsScroll = _modalRoot.Q<ScrollView>("skins-scroll");
            _skinsGambitsLabel = _modalRoot.Q<Label>("skins-gambits-label");

            _filterAll    = _modalRoot.Q<Button>("skin-filter-all");
            _filterKnight = _modalRoot.Q<Button>("skin-filter-knight");
            _filterBishop = _modalRoot.Q<Button>("skin-filter-bishop");
            _filterQueen  = _modalRoot.Q<Button>("skin-filter-queen");
            _filterPawn   = _modalRoot.Q<Button>("skin-filter-pawn");

            _filterAll?.RegisterCallback<ClickEvent>(_ => SetFilter("all"));
            _filterKnight?.RegisterCallback<ClickEvent>(_ => SetFilter("knight"));
            _filterBishop?.RegisterCallback<ClickEvent>(_ => SetFilter("bishop"));
            _filterQueen?.RegisterCallback<ClickEvent>(_ => SetFilter("queen"));
            _filterPawn?.RegisterCallback<ClickEvent>(_ => SetFilter("pawn"));

            // Enciclopedia
            _encyGrid = _modalRoot.Q<VisualElement>("encyclopedia-grid");
            _encyFilterAll = _modalRoot.Q<Button>("ency-filter-all");
            _encyFilterBishop = _modalRoot.Q<Button>("ency-filter-bishop");
            _encyFilterPawn = _modalRoot.Q<Button>("ency-filter-pawn");
            _encyFilterOthers = _modalRoot.Q<Button>("ency-filter-others");
            _encyFilterAll?.RegisterCallback<ClickEvent>(_ => SetEncyFilter("all"));
            _encyFilterBishop?.RegisterCallback<ClickEvent>(_ => SetEncyFilter("bishop"));
            _encyFilterPawn?.RegisterCallback<ClickEvent>(_ => SetEncyFilter("pawn"));
            _encyFilterOthers?.RegisterCallback<ClickEvent>(_ => SetEncyFilter("others"));

            _dual = _modalRoot.Q<VisualElement>("your-pieces-dual");
            _tabPieces = _modalRoot.Q<Button>("ypm-tab-pieces");
            _tabEncy = _modalRoot.Q<Button>("ypm-tab-ency");
            _tabPieces?.RegisterCallback<ClickEvent>(_ => ShowEncyTab(false));
            _tabEncy?.RegisterCallback<ClickEvent>(_ => ShowEncyTab(true));
            ShowEncyTab(false);

            UpdateUI();
            RefreshSkins();
            RefreshEncyclopedia();
        }

        private VisualElement _dual;
        private Button _tabPieces, _tabEncy;

        /// <summary>Móvil en vertical: una sola columna, así que Tus Piezas y la Enciclopedia se alternan con pestañas.</summary>
        private void ShowEncyTab(bool ency)
        {
            _dual?.EnableInClassList("show-ency", ency);
            _tabPieces?.EnableInClassList("ypm-tab-active", !ency);
            _tabEncy?.EnableInClassList("ypm-tab-active", ency);
        }

        public void OnModalOpened()
        {
            ShowEncyTab(false);
            PieceSkinManager.SyncFromOceanPay();
            UpdateUI();
            RefreshSkins();
            RefreshEncyclopedia();
        }

        // ── Skins ──────────────────────────────────────────────────────────

        private void SetFilter(string filter)
        {
            _currentFilter = filter;
            var all = new[] { _filterAll, _filterKnight, _filterBishop, _filterQueen, _filterPawn };
            foreach (var btn in all)
            {
                if (btn == null) continue;
                btn.RemoveFromClassList("skin-filter-active");
            }
            Button active = filter switch
            {
                "knight" => _filterKnight,
                "bishop" => _filterBishop,
                "queen"  => _filterQueen,
                "pawn"   => _filterPawn,
                _        => _filterAll
            };
            active?.AddToClassList("skin-filter-active");
            RefreshSkins();
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
        }

        private bool PassesFilter(int index)
        {
            if (_currentFilter == "all") return true;
            var type = PieceSkinManager.GetSkinPieceType(index);
            return _currentFilter switch
            {
                "knight" => type == PieceType.Knight,
                "bishop" => type == PieceType.Bishop || type == PieceType.NecromancerBishop,
                "queen"  => type == PieceType.Queen || type == PieceType.King || type == PieceType.Rook,
                "pawn"   => type == PieceType.Pawn,
                _ => true
            };
        }

        private void RefreshSkins()
        {
            if (_skinsGrid == null) return;
            PieceSkinManager.SyncFromOceanPay();
            _skinsGrid.Clear();

            int count = PieceSkinManager.Count;
            int shown = 0;
            for (int i = 0; i < count; i++)
            {
                if (!PassesFilter(i)) continue;
                // Las esculturas de la velada no se venden por Gambits: las del
                // pase se cobran subiendo de nivel y las de la tienda, con Dulces.
                // El inventario las muestra en sus secciones propias.
                if (PieceSkinManager.IsPassExclusiveSkin(i)
                    || PieceSkinManager.IsHalloweenShopExclusive(i)) continue;
                _skinsGrid.Add(CreateSkinCard(i));
                shown++;
            }

            if (shown == 0)
            {
                var empty = new Label("No hay skins en este filtro.");
                empty.AddToClassList("skins-balance-hint");
                _skinsGrid.Add(empty);
            }

            UpdateBalanceLabel();
        }

        private void UpdateBalanceLabel()
        {
            if (_skinsGambitsLabel == null) return;
            int bal = PieceSkinManager.GetLocalGambits();
            _skinsGambitsLabel.text = $"💰 Gambits: {bal}";
        }

        private VisualElement CreateSkinCard(int index)
        {
            string id = PieceSkinManager.GetSkinId(index);
            string name = PieceSkinManager.GetSkinName(index);
            string desc = PieceSkinManager.GetSkinDescription(index);
            PieceType pieceType = PieceSkinManager.GetSkinPieceType(index);
            int price = PieceSkinManager.GetSkinPrice(index);
            bool owned = PieceSkinManager.IsOwned(index);
            bool equipped = PieceSkinManager.IsEquipped(index);
            Color tint = PieceSkinManager.GetSkinTint(index);
            SkinAnimation anim = PieceSkinManager.GetSkinAnimation(index);
            SkinRarity rarity = PieceSkinManager.GetSkinRarity(index);
            string icon = PieceSkinManager.GetSkinIcon(index);
            Texture2D thumb = PieceSkinManager.GetSkinThumbnail(index);

            var card = new VisualElement();
            card.AddToClassList("skin-card");
            if (equipped) card.AddToClassList("skin-card-equipped");
            else if (owned) card.AddToClassList("skin-card-owned");
            else card.AddToClassList("skin-card-locked");

            // Portrait
            var portrait = new VisualElement();
            portrait.AddToClassList("skin-portrait");
            // tint glow if animated
            var glow = new VisualElement();
            glow.AddToClassList("skin-portrait-glow");
            glow.style.backgroundColor = new StyleColor(new Color(tint.r, tint.g, tint.b, 0.35f));
            portrait.Add(glow);

            // Animated pulse border for non-None
            if (anim != SkinAnimation.None)
            {
                var pulse = new VisualElement();
                pulse.AddToClassList("skin-portrait-anim-pulse");
                var pulseBorder = new StyleColor(tint);
                pulse.style.borderLeftColor = pulseBorder;
                pulse.style.borderRightColor = pulseBorder;
                pulse.style.borderTopColor = pulseBorder;
                pulse.style.borderBottomColor = pulseBorder;
                pulse.style.backgroundColor = new StyleColor(new Color(tint.r, tint.g, tint.b, 0.09f));
                portrait.Add(pulse);
            }

            // Sprite or icon fallback
            string pieceSpritePath = GetSpritePathForPiece(pieceType);
            Sprite pieceSprite = null;
            if (BoardView.Instance != null)
            {
                // Try to get real sprite to tint preview
                pieceSprite = BoardView.Instance.GetPieceSprite(pieceType, TeamColor.White);
            }

            if (thumb != null)
            {
                var img = new Image { image = thumb };
                img.AddToClassList("skin-portrait-img");
                portrait.Add(img);
            }
            else if (pieceSprite != null)
            {
                var img = new Image { sprite = pieceSprite };
                img.AddToClassList("skin-portrait-img");
                img.style.unityBackgroundImageTintColor = new StyleColor(tint);
                portrait.Add(img);
            }
            else
            {
                var lbl = new Label(icon);
                lbl.style.fontSize = 28;
                lbl.style.color = new StyleColor(tint);
                portrait.Add(lbl);
            }

            // Rarity badge (píldora con color por tier)
            var rarityLbl = new Label(PieceSkinManager.RarityLabel(rarity));
            ShopRarity.StyleBadge(rarityLbl, rarity, 7f);
            rarityLbl.AddToClassList("skin-rarity-badge");
            portrait.Add(rarityLbl);

            card.Add(portrait);

            // Title
            var titleLbl = new Label(name);
            titleLbl.AddToClassList("skin-card-title");
            card.Add(titleLbl);

            // Piece type
            var pieceLbl = new Label(pieceType.ToString().ToUpper());
            pieceLbl.AddToClassList("skin-card-piece");
            card.Add(pieceLbl);

            // Desc (trim to 46 chars)
            string shortDesc = desc.Length > 56 ? desc.Substring(0, 56) + "…" : desc;
            var descLbl = new Label(shortDesc);
            descLbl.AddToClassList("skin-card-desc");
            card.Add(descLbl);

            // Price or status
            if (!owned)
            {
                var priceLbl = new Label($"{price} Gambits");
                priceLbl.AddToClassList("skin-card-price");
                priceLbl.AddToClassList(PieceSkinManager.CanAfford(index) ? "skin-card-price-affordable" : "skin-card-price-expensive");
                card.Add(priceLbl);
            }

            // Button
            var btn = new Button(() => OnSkinAction(index));
            btn.AddToClassList("skin-card-btn");
            if (equipped)
            {
                btn.text = "✓ EN USO";
                btn.AddToClassList("skin-btn-equipped");
                btn.SetEnabled(false);
            }
            else if (owned)
            {
                // Ya es tuya: se pone desde el INVENTARIO (aquí solo se dice el estado)
                btn.text = "✓ EN EL INVENTARIO";
                btn.AddToClassList("skin-btn-elsewhere");
                btn.SetEnabled(false);
            }
            else
            {
                if (PieceSkinManager.CanAfford(index))
                {
                    btn.text = $"COMPRAR {price}G";
                    btn.AddToClassList("skin-btn-buy");
                }
                else
                {
                    btn.text = $"FALTAN {price - PieceSkinManager.GetLocalGambits()}G";
                    btn.AddToClassList("skin-btn-locked");
                }
            }
            card.Add(btn);

            // Hover preview: could trigger glow intensify
            card.RegisterCallback<MouseEnterEvent>(_ => {
                glow.style.backgroundColor = new StyleColor(new Color(tint.r, tint.g, tint.b, 0.55f));
            });
            card.RegisterCallback<MouseLeaveEvent>(_ => {
                glow.style.backgroundColor = new StyleColor(new Color(tint.r, tint.g, tint.b, 0.35f));
            });

            return card;
        }

        private string GetSpritePathForPiece(PieceType t) => t.ToString();

        /// <summary>
        /// Catálogo: compra con Gambits y nada más. Lo comprado espera en el INVENTARIO,
        /// que es el único sitio donde se equipa (antes se ponía sola al comprarla).
        /// </summary>
        private void OnSkinAction(int index)
        {
            if (PieceSkinManager.IsOwned(index))
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                return;
            }

            int price = PieceSkinManager.GetSkinPrice(index);
            Action grant = () =>
            {
                PieceSkinManager.OwnSkin(index);
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                WilderGambit.Core.GambitProgress.NotifyChanged();
                Debug.Log($"[YourPieces] {PieceSkinManager.GetSkinName(index)} comprada: " +
                          "se equipa desde el INVENTARIO.");
                RefreshSkins();
                UpdateUI();
            };

            if (price <= 0)
            {
                grant();
                return;
            }

            // Cobro centralizado en el checkout de Surface.
            WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                "wilder-gambit-skin-" + PieceSkinManager.GetSkinId(index),
                PieceSkinManager.GetSkinName(index),
                "Aspecto de pieza · Tus piezas",
                price,
                result =>
                {
                    if (!result.success)
                    {
                        WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                        RefreshSkins();
                        UpdateUI();
                        return;
                    }
                    grant();
                });
        }

        // ── Enciclopedia ─────────────────────────────────────────────────

        private void SetEncyFilter(string f)
        {
            _encyFilter = f;
            var all = new[] { _encyFilterAll, _encyFilterBishop, _encyFilterPawn, _encyFilterOthers };
            foreach (var b in all) if (b != null) b.RemoveFromClassList("ency-filter-active");
            Button act = f switch { "bishop" => _encyFilterBishop, "pawn" => _encyFilterPawn, "others" => _encyFilterOthers, _ => _encyFilterAll };
            act?.AddToClassList("ency-filter-active");
            RefreshEncyclopedia();
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
        }

        private bool PassesEncyFilter(string category)
        {
            if (_encyFilter == "all") return true;
            return _encyFilter == category;
        }

        private void RefreshEncyclopedia()
        {
            if (_encyGrid == null) return;
            _encyGrid.Clear();
            // Datos detallados — mucho más que en partida
            var entries = new[]
            {
                new { cat="bishop", icon="♝", name="Alfil Clásico", type="BISHOP • Pieza base", rarity="COMÚN", color=new Color(0.62f,0.65f,0.70f), passive="Sin pasiva", pDesc="Alfil clásico sin habilidades. Movimiento diagonal ilimitado, valor 3. Ideal para control de diagonales largas.", active="Sin activa", aDesc="No tiene habilidad activa. Juego posicional puro.", stats="Mov: diagonal ∞ • Valor: 3 • Alcance: largo", lore="El alfil de mármol blanco, tallado en la cantera del primer tablero. Silencioso y letal en diagonales abiertas.", tip="Úsalo en diagonales largas y no lo encierres tras peones." },
                new { cat="bishop", icon="🧙", name="Alfil Nigromante", type="VARIANTE • Alfil", rarity="ÉPICA", color=new Color(0.75f,0.35f,0.95f), passive="Cosecha de Almas", pDesc="Pasiva: 0.35 almas por pieza aliada capturada. Las piezas espectrales no cuentan. Cada 3 capturas ≈ 1 alma. Máx 4 almas. A 3/4 el aura es amarilla, a 4/4 verde pulsante con contador y aviso.", active="Alzamiento Menor — 4 almas", aDesc="Activa: invoca un Peón Espectral a 1-2 casillas en tu diagonal, solo en tu territorio y si la casilla no está atacada por el rival. Cuesta 4 almas y consume tu turno. Se bloquea si hay pieza en medio. El peón invocado es frágil: sin doble avance, no promociona y se desvanece en 4 medios-turnos; si lo capturan no genera almas.", stats="Mov: diagonal ∞ • Valor: 3+ • Alcance resurrección: ≤2", lore="Un alfil que comercia con el velo. Cada caída alimenta su foso. Cuando el foso rebosa, devuelve un peón del otro lado — pero frágil y efímero.", tip="No lo expongas: necesita que caigan aliados para cargarse. Resérvalo para emergencias cerca de tu rey." },
                new { cat="pawn", icon="♟", name="Peón Clásico", type="PAWN • Base", rarity="COMÚN", color=new Color(0.62f,0.65f,0.70f), passive="Avance y captura", pDesc="Avanza 1, desde inicio 2. Captura en diagonal.", active="Coronación", aDesc="Al llegar a fila 8 (o 1 negras) promociona a Dama/Torre/Alfil/Caballo. Decide la partida.", stats="Mov: 1 adelante / x diagonal • Valor: 1", lore="La infantería. Débil sola, decisiva en masa y al coronar.", tip="No bloquees tus alfiles con tu cadena de peones." },
                new { cat="pawn", icon="⚑", name="Peón Lancero", type="PAWN • Variante", rarity="RARA", color=new Color(0.35f,0.65f,1.00f), passive="Lanza", pDesc="Puede capturar hacia adelante además de en diagonal. Conserva avance simple y doble desde la fila inicial. La casilla frontal vacía sigue siendo un avance normal, no una captura.", active="Sin activa", aDesc="No tiene habilidad activa: la Lanza es una pasiva permanente. Su amenaza frontal cambia el cálculo de clavadas y jaques a la descubierta.", stats="Mov: 1 adelante / x y frontal • Valor: 1+", lore="La infantería que dejó de temer el frente. Cuando la formación enemiga avanza, la lanza encuentra rendija donde el acero se estrella.", tip="Colócalo frente a piezas centrales: su clavada ahora presiona de frente. Cuidado con los jaques a la descubierta de torres y damas." },
                new { cat="others", icon="♞", name="Caballo", type="KNIGHT • Base", rarity="COMÚN", color=new Color(0.62f,0.65f,0.70f), passive="Salto en L", pDesc="Salta por encima de piezas. Ideal para horquillas.", active="Fork Ígneo (si está transformado)", aDesc="Si el Caballo blanco clava horquilla (≥2 piezas atacadas), se prende en fuego: animación idle llameante y ataque cometa.", stats="Mov: L 2+1 • Valor: 3", lore="El jinete que ignora barreras. Su fork puede incendiar el tablero.", tip="Busca horquillas al centro, no en la banda." },
                new { cat="others", icon="♜", name="Torre", type="ROOK • Base", rarity="COMÚN", color=new Color(0.62f,0.65f,0.70f), passive="Línea recta", pDesc="Domina filas y columnas. Clave en finales.", active="Enroque", aDesc="Con el Rey sin mover y sin jaque, enroca corto/largo. La torre salta.", stats="Mov: ortogonal ∞ • Valor: 5", lore="La fortaleza móvil.", tip="Abre columnas y dobla torres." },
                new { cat="others", icon="♛", name="Dama", type="QUEEN • Base", rarity="COMÚN", color=new Color(0.62f,0.65f,0.70f), passive="Omnidireccional", pDesc="Alfil+Torre. La más valiosa.", active="Sin activa especial", aDesc="La Dama clásica no tiene activa; sus variantes Jinete y Vampira sí: ver fichas siguientes.", stats="Mov: 8 dirs ∞ • Valor: 9", lore="La soberana.", tip="No la expongas temprano." },
                new { cat="others", icon="♞", name="Dama Jinete", type="QUEEN • Variante", rarity="LEGENDARIA", color=new Color(1.00f,0.78f,0.20f), passive="Cabalgada 1×/partida", pDesc="Mueve como Dama clásica y, una vez por partida, salta como un Caballo a una de sus 8 casillas, con captura. El salto gasta su único uso: la tarjeta del panel de habilidades pasa a USADA.", active="Cabalgada — salto de caballo", aDesc="Se juega moviendo la Dama a una casilla de caballo: no hay botón, el destino solo existe mientras la Cabalgada está disponible. Respeta la regla del jaque propio como cualquier jugada.", stats="Mov: 8 dirs ∞ + salto L • Valor: 9+", lore="La soberana aprendió a cabalgar: una vez por batalla abandona la marcha real y cae como un rayo donde ningún cañón alcanza.", tip="Guárdala para el momento ganador: un salto a tiempo vale más que diez amenazas. El rival la ve disponible: finta antes de gastarla." },
                new { cat="others", icon="🧛", name="Reina Vampira", type="QUEEN • Variante de la velada", rarity="LEGENDARIA", color=new Color(0.94f,0.27f,0.27f), passive="No Muerta 1×/partida", pDesc="Mueve como Dama clásica. Si la capturan, renace una vez por partida en la primera casilla libre de su primera fila, en orden fijo: d, c, e, b, f, a, g, h. Si la fila está completa, no regresa.", active="Sin activa", aDesc="La No Muerta es pasiva: no hay botón. Se consume sola la primera vez que cae y la tarjeta del panel de habilidades pasa a USADA. El rival puede negarte el regreso ocupando toda la fila.", stats="Mov: 8 dirs ∞ • Valor: 9+ • Renacer: 1", lore="La soberana que no acepta el jaque mate. Una vez por batalla, la tumba la devuelve al tablero con la misma corona y una sed nueva.", tip="Cámbiala sin miedo si el intercambio te conviene: su primer regreso es una pieza extra. Pero no cuentes con ella dos veces." },
                new { cat="others", icon="♚", name="Rey", type="KING • Base", rarity="COMÚN", color=new Color(0.62f,0.65f,0.70f), passive="Último bastión", pDesc="Una casilla en cualquier dirección. No puede entrar en jaque.", active="Enroque", aDesc="Ver Torre. Si está en jaque y sin movimientos, es mate.", stats="Mov: 1 casilla • Valor: ∞", lore="Si cae, todo cae.", tip="Mantenlo seguro, enrócate pronto." },
            };
            int shown = 0;
            foreach (var e in entries)
            {
                if (!PassesEncyFilter(e.cat)) continue;
                var card = new VisualElement(); card.AddToClassList("ency-card");
                // Header sin emoji: placa ornamental centrada (chip de rareza → título → tipo → filo con rombo)
                var header = new VisualElement(); header.AddToClassList("ency-card-header");
                var rar = new Label(e.rarity); rar.AddToClassList("ency-rarity");
                ShopRarity.StyleBadge(rar, e.rarity, 10f);
                header.Add(rar);
                var n1 = new Label(e.name); n1.AddToClassList("ency-name"); header.Add(n1);
                var n2 = new Label(e.type.ToUpperInvariant()); n2.AddToClassList("ency-type"); header.Add(n2);
                var divider = new VisualElement(); divider.AddToClassList("ency-header-divider");
                var lineL = new VisualElement(); lineL.AddToClassList("ency-header-line");
                var gem = new Label("◆"); gem.AddToClassList("ency-header-gem");
                var lineR = new VisualElement(); lineR.AddToClassList("ency-header-line");
                divider.Add(lineL); divider.Add(gem); divider.Add(lineR);
                header.Add(divider);
                card.Add(header);
                // Stats como píldoras (MOV · VALOR · ALCANCE): una por segmento "etiqueta: valor"
                var stats = new VisualElement(); stats.AddToClassList("ency-stats");
                foreach (var raw in e.stats.Split('•'))
                {
                    var seg = raw.Trim();
                    if (seg.Length == 0) continue;
                    var pill = new VisualElement(); pill.AddToClassList("ency-stat");
                    int colon = seg.IndexOf(':');
                    if (colon > 0)
                    {
                        var k = new Label(seg.Substring(0, colon).Trim()); k.AddToClassList("ency-stat-label"); pill.Add(k);
                        var v = new Label(seg.Substring(colon + 1).Trim()); v.AddToClassList("ency-stat-value"); pill.Add(v);
                    }
                    else
                    {
                        var v = new Label(seg); v.AddToClassList("ency-stat-value"); pill.Add(v);
                    }
                    stats.Add(pill);
                }
                card.Add(stats);
                var ab1 = new VisualElement(); ab1.AddToClassList("ency-ability");
                var t1 = new Label("Pasiva — " + e.passive); t1.AddToClassList("ency-ability-title"); ab1.Add(t1);
                var d1 = new Label(e.pDesc); d1.AddToClassList("ency-ability-desc"); ab1.Add(d1);
                card.Add(ab1);
                var ab2 = new VisualElement(); ab2.AddToClassList("ency-ability"); ab2.AddToClassList("ency-ability-active");
                var t2 = new Label("Activa — " + e.active); t2.AddToClassList("ency-ability-title"); ab2.Add(t2);
                var d2 = new Label(e.aDesc); d2.AddToClassList("ency-ability-desc"); ab2.Add(d2);
                card.Add(ab2);
                var lore = new Label("Lore: " + e.lore); lore.AddToClassList("ency-lore"); card.Add(lore);
                var tip = new Label("Consejo: " + e.tip); tip.AddToClassList("ency-tip-box"); card.Add(tip);
                _encyGrid.Add(card);
                shown++;
            }
            if (shown == 0)
            {
                var empty = new Label("No hay entradas en este filtro."); empty.AddToClassList("ency-tip"); empty.AddToClassList("ency-tip-box"); _encyGrid.Add(empty);
            }
        }

        private void UpdateUI()
        {
            bool isNecro = PieceLoadoutManager.UsesNecromancerBishop(TeamColor.White);

            // Tarjeta Clásico
            if (_cardClassic != null)
            {
                if (!isNecro)
                {
                    _cardClassic.AddToClassList("piece-variant-card-equipped");
                    _cardClassic.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardClassic.RemoveFromClassList("piece-variant-card-equipped");
                    _cardClassic.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipClassic != null)
            {
                _btnEquipClassic.text = !isNecro ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                if (!isNecro)
                {
                    _btnEquipClassic.AddToClassList("btn-variant-equipped");
                    _btnEquipClassic.RemoveFromClassList("btn-variant-elsewhere");
                }
                else
                {
                    _btnEquipClassic.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipClassic.AddToClassList("btn-variant-elsewhere");
                }
            }

            if (_lblStatusClassic != null)
            {
                _lblStatusClassic.text = !isNecro ? "ACTIVO EN PARTIDA" : "EN EL INVENTARIO";
            }

            // Tarjeta Nigromante
            bool necroOwned = PieceLoadoutManager.IsNecroOwned();
            if (_cardNecro != null)
            {
                if (isNecro)
                {
                    _cardNecro.AddToClassList("piece-variant-card-equipped");
                    _cardNecro.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardNecro.RemoveFromClassList("piece-variant-card-equipped");
                    _cardNecro.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipNecro != null)
            {
                if (!necroOwned)
                {
                    _btnEquipNecro.text = $"🔒  {HalloweenDiscount.NecromancerPrice:N0} G EN TIENDA";
                    _btnEquipNecro.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipNecro.RemoveFromClassList("btn-variant-elsewhere");
                    _btnEquipNecro.AddToClassList("skin-btn-locked");
                }
                else
                {
                    _btnEquipNecro.RemoveFromClassList("skin-btn-locked");
                    _btnEquipNecro.text = isNecro ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                    if (isNecro)
                    {
                        _btnEquipNecro.AddToClassList("btn-variant-equipped");
                        _btnEquipNecro.RemoveFromClassList("btn-variant-elsewhere");
                    }
                    else
                    {
                        _btnEquipNecro.RemoveFromClassList("btn-variant-equipped");
                        _btnEquipNecro.AddToClassList("btn-variant-elsewhere");
                    }
                }
            }

            if (_lblStatusNecro != null)
            {
                if (!necroOwned)
                    _lblStatusNecro.text = $"BLOQUEADO · {HalloweenDiscount.NecromancerPrice:N0} G";
                else
                    _lblStatusNecro.text = isNecro ? "ACTIVO EN PARTIDA" : "DISPONIBLE";
            }

            // ── Peón: Clásico vs Lancero (espejo del bloque del obispo) ──
            bool lancerOwned = PieceLoadoutManager.IsLancerOwned();
            bool isLancer = PieceLoadoutManager.UsesLancerPawn(TeamColor.White);

            if (_cardPawnClassic != null)
            {
                if (!isLancer)
                {
                    _cardPawnClassic.AddToClassList("piece-variant-card-equipped");
                    _cardPawnClassic.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardPawnClassic.RemoveFromClassList("piece-variant-card-equipped");
                    _cardPawnClassic.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipPawnClassic != null)
            {
                _btnEquipPawnClassic.text = !isLancer ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                if (!isLancer)
                {
                    _btnEquipPawnClassic.AddToClassList("btn-variant-equipped");
                    _btnEquipPawnClassic.RemoveFromClassList("btn-variant-elsewhere");
                }
                else
                {
                    _btnEquipPawnClassic.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipPawnClassic.AddToClassList("btn-variant-elsewhere");
                }
            }

            if (_lblStatusPawnClassic != null)
            {
                _lblStatusPawnClassic.text = !isLancer ? "ACTIVO EN PARTIDA" : "EN EL INVENTARIO";
            }

            if (_cardPawnLancer != null)
            {
                if (isLancer)
                {
                    _cardPawnLancer.AddToClassList("piece-variant-card-equipped");
                    _cardPawnLancer.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardPawnLancer.RemoveFromClassList("piece-variant-card-equipped");
                    _cardPawnLancer.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipPawnLancer != null)
            {
                if (!lancerOwned)
                {
                    // Bloqueado hasta comprarlo en la Tienda (premium: Tides)
                    _btnEquipPawnLancer.text = $"🔒  {PieceLoadoutManager.LANCER_PRICE_TIDES:N0} T EN TIENDA";
                    _btnEquipPawnLancer.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipPawnLancer.RemoveFromClassList("btn-variant-elsewhere");
                    _btnEquipPawnLancer.AddToClassList("skin-btn-locked");
                }
                else
                {
                    _btnEquipPawnLancer.RemoveFromClassList("skin-btn-locked");
                    _btnEquipPawnLancer.text = isLancer ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                    if (isLancer)
                    {
                        _btnEquipPawnLancer.AddToClassList("btn-variant-equipped");
                        _btnEquipPawnLancer.RemoveFromClassList("btn-variant-elsewhere");
                    }
                    else
                    {
                        _btnEquipPawnLancer.RemoveFromClassList("btn-variant-equipped");
                        _btnEquipPawnLancer.AddToClassList("btn-variant-elsewhere");
                    }
                }
            }

            if (_lblStatusPawnLancer != null)
            {
                if (!lancerOwned)
                    _lblStatusPawnLancer.text = $"BLOQUEADO · {PieceLoadoutManager.LANCER_PRICE_TIDES:N0} T";
                else
                    _lblStatusPawnLancer.text = isLancer ? "ACTIVO EN PARTIDA" : "DISPONIBLE";
            }

            // ── Dama: Clásica vs Jinete vs Vampira (espejo del bloque del peón) ──
            // La Vampira comparte el ciclo de la Dama: la Clásica solo está activa
            // cuando el loadout es 0 (con Jinete o Vampira equipadas pasa al inventario).
            bool riderOwned = PieceLoadoutManager.IsRiderOwned();
            bool isRider = PieceLoadoutManager.UsesRiderQueen(TeamColor.White);
            bool isClassicQueen = PieceLoadoutManager.GetQueenLoadout(TeamColor.White)
                                  == PieceLoadoutManager.LOADOUT_QUEEN_CLASSIC;

            if (_cardQueenClassic != null)
            {
                if (isClassicQueen)
                {
                    _cardQueenClassic.AddToClassList("piece-variant-card-equipped");
                    _cardQueenClassic.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardQueenClassic.RemoveFromClassList("piece-variant-card-equipped");
                    _cardQueenClassic.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipQueenClassic != null)
            {
                _btnEquipQueenClassic.text = isClassicQueen ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                if (isClassicQueen)
                {
                    _btnEquipQueenClassic.AddToClassList("btn-variant-equipped");
                    _btnEquipQueenClassic.RemoveFromClassList("btn-variant-elsewhere");
                }
                else
                {
                    _btnEquipQueenClassic.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipQueenClassic.AddToClassList("btn-variant-elsewhere");
                }
            }

            if (_lblStatusQueenClassic != null)
            {
                _lblStatusQueenClassic.text = isClassicQueen ? "ACTIVO EN PARTIDA" : "EN EL INVENTARIO";
            }

            if (_cardQueenRider != null)
            {
                if (isRider)
                {
                    _cardQueenRider.AddToClassList("piece-variant-card-equipped");
                    _cardQueenRider.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardQueenRider.RemoveFromClassList("piece-variant-card-equipped");
                    _cardQueenRider.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipQueenRider != null)
            {
                if (!riderOwned)
                {
                    // Bloqueado hasta comprarlo en la Tienda (primera variante premium: Tides)
                    _btnEquipQueenRider.text = $"🔒  {PieceLoadoutManager.RIDER_PRICE_TIDES:N0} T EN TIENDA";
                    _btnEquipQueenRider.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipQueenRider.RemoveFromClassList("btn-variant-elsewhere");
                    _btnEquipQueenRider.AddToClassList("skin-btn-locked");
                }
                else
                {
                    _btnEquipQueenRider.RemoveFromClassList("skin-btn-locked");
                    _btnEquipQueenRider.text = isRider ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                    if (isRider)
                    {
                        _btnEquipQueenRider.AddToClassList("btn-variant-equipped");
                        _btnEquipQueenRider.RemoveFromClassList("btn-variant-elsewhere");
                    }
                    else
                    {
                        _btnEquipQueenRider.RemoveFromClassList("btn-variant-equipped");
                        _btnEquipQueenRider.AddToClassList("btn-variant-elsewhere");
                    }
                }
            }

            if (_lblStatusQueenRider != null)
            {
                if (!riderOwned)
                    _lblStatusQueenRider.text = $"BLOQUEADO · {PieceLoadoutManager.RIDER_PRICE_TIDES:N0} T";
                else
                    _lblStatusQueenRider.text = isRider ? "ACTIVO EN PARTIDA" : "DISPONIBLE";
            }

            bool vampireOwned = PieceLoadoutManager.IsVampireOwned();
            bool isVampire = PieceLoadoutManager.UsesVampireQueen(TeamColor.White);

            if (_cardQueenVampire != null)
            {
                if (isVampire)
                {
                    _cardQueenVampire.AddToClassList("piece-variant-card-equipped");
                    _cardQueenVampire.RemoveFromClassList("piece-variant-card-idle");
                }
                else
                {
                    _cardQueenVampire.RemoveFromClassList("piece-variant-card-equipped");
                    _cardQueenVampire.AddToClassList("piece-variant-card-idle");
                }
            }

            if (_btnEquipQueenVampire != null)
            {
                if (!vampireOwned)
                {
                    // Se desbloquea en la Vía Sangre de la velada, no con Gambits.
                    _btnEquipQueenVampire.text = "🔒  VÍA SANGRE";
                    _btnEquipQueenVampire.RemoveFromClassList("btn-variant-equipped");
                    _btnEquipQueenVampire.RemoveFromClassList("btn-variant-elsewhere");
                    _btnEquipQueenVampire.AddToClassList("skin-btn-locked");
                }
                else
                {
                    _btnEquipQueenVampire.RemoveFromClassList("skin-btn-locked");
                    _btnEquipQueenVampire.text = isVampire ? "✓ EN USO" : "✓ EN EL INVENTARIO";
                    if (isVampire)
                    {
                        _btnEquipQueenVampire.AddToClassList("btn-variant-equipped");
                        _btnEquipQueenVampire.RemoveFromClassList("btn-variant-elsewhere");
                    }
                    else
                    {
                        _btnEquipQueenVampire.RemoveFromClassList("btn-variant-equipped");
                        _btnEquipQueenVampire.AddToClassList("btn-variant-elsewhere");
                    }
                }
            }

            if (_lblStatusQueenVampire != null)
            {
                if (!vampireOwned)
                    _lblStatusQueenVampire.text = "BLOQUEADO · VÍA SANGRE";
                else
                    _lblStatusQueenVampire.text = isVampire ? "ACTIVO EN PARTIDA" : "DISPONIBLE";
            }
        }
    }
}
