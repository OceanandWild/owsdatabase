using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// INVENTARIO — la <b>única</b> sección donde se equipa algo, con tres pestañas:
    /// VARIANTES (clásico/Nigromante y clásico/Lancero), SKINS (las de PieceSkinManager)
    /// y TABLEROS (los de BoardBackgroundManager). La tienda solo vende: aquí se pone
    /// lo que ya es tuyo, y lo que no lo es aparece con su precio y su candado.
    ///
    /// Todas las cartas se construyen en C# con las clases de la tienda (.bg-card y
    /// familia) para que el inventario y el catálogo se vean como la misma casa. El
    /// estado de cada carta vive en la píldora .inv-state.
    ///
    /// Se abre desde el botón girado del menú (menu-inventory-rail) y se puede abrir
    /// ya en una pestaña concreta: <see cref="OpenTab"/>.
    /// </summary>
    public class InventoryModal : MonoBehaviour
    {
        public const string TAB_VARIANTS = "variants";
        public const string TAB_SKINS    = "skins";
        public const string TAB_BOARDS   = "boards";

        private VisualElement _root;
        private VisualElement _grid;
        private VisualElement _filterRow;

        private Image _crestArt;
        private Image _watermark;
        private Label _crestFallback;
        private Label _chipGambits;
        private Label _chipOwned;
        private Label _chipOwnedLabel;
        private Label _tabHint;
        private Label _countVariants;
        private Label _countSkins;
        private Label _countBoards;

        private Button _tabVariants;
        private Button _tabSkins;
        private Button _tabBoards;
        private Button _filterAll;
        private Button _filterKnight;
        private Button _filterBishop;
        private Button _filterQueen;
        private Button _filterPawn;

        private Action _onClose;
        private Action<string, string> _onToast;
        private Action _onBoardEquipped;

        private string _tab = TAB_VARIANTS;
        private string _skinFilter = "all";

        private readonly Dictionary<int, Texture2D> _boardThumbs = new Dictionary<int, Texture2D>();

        /// <summary>Iconos de reserva de los tableros (mismo orden que la biblioteca).</summary>
        private static readonly string[] BoardIcons =
        {
            "🏛️", "🌋", "❄️", "🌿", "🌊", "✨", "🏺", "⛪", "🐉", "👑",
            "🌙", "🩸", "🪦", "⚰️"
        };

        // ── Variantes de pieza ────────────────────────────────────────────────

        /// <summary>Una variante equipable: quién la posee, cuál está puesta y cómo se pinta.</summary>
        private sealed class VariantRow
        {
            public string name;
            public string tag;
            public string passive;
            public Func<bool> owned;
            public Func<bool> equipped;
            public Action equip;
            public Func<Sprite> art;
            /// <summary>Etiqueta de la píldora cuando la variante aún no es del jugador.</summary>
            public Func<string> lockedLabel;
        }

        private VariantRow[] _variants;

        private VariantRow[] Variants
        {
            get
            {
                if (_variants == null) _variants = BuildVariants();
                return _variants;
            }
        }

        private static VariantRow[] BuildVariants()
        {
            return new[]
            {
                new VariantRow
                {
                    name    = "Alfil Clásico",
                    tag     = "ALFIL",
                    passive = "Sin pasiva · juego posicional puro",
                    owned     = () => true,
                    equipped  = () => PieceLoadoutManager.GetBishopLoadout(TeamColor.White)
                                     == PieceLoadoutManager.LOADOUT_CLASSIC,
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetBishopLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_CLASSIC);
                        RefreshBoardLoadout();
                    },
                    art = () => BoardView.Instance != null
                        ? BoardView.Instance.GetPieceSprite(PieceType.Bishop, TeamColor.White)
                        : null,
                },
                new VariantRow
                {
                    name    = "Alfil Nigromante",
                    tag     = "ALFIL",
                    passive = "Pasiva · Cosecha de Almas",
                    lockedLabel = () => $"🔒 {HalloweenDiscount.NecromancerPrice:N0} G",
                    owned     = PieceLoadoutManager.IsNecroOwned,
                    equipped  = () => PieceLoadoutManager.UsesNecromancerBishop(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetBishopLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_NECROMANCER);
                        RefreshBoardLoadout();
                    },
                    art = () =>
                    {
                        var view = BoardView.Instance;
                        if (view == null) return null;
                        Sprite necro = view.GetPieceSprite(PieceType.NecromancerBishop, TeamColor.White);
                        return necro != null ? necro : view.GetPieceSprite(PieceType.Bishop, TeamColor.White);
                    },
                },
                new VariantRow
                {
                    name    = "Caballo Clásico",
                    tag     = "CABALLO",
                    passive = "Sin pasiva · salto en L",
                    owned     = () => true,
                    equipped  = () => PieceLoadoutManager.GetKnightLoadout(TeamColor.White)
                                     == PieceLoadoutManager.LOADOUT_KNIGHT_CLASSIC,
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetKnightLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_KNIGHT_CLASSIC);
                        RefreshBoardLoadout();
                    },
                    art = () => BoardView.Instance != null
                        ? BoardView.Instance.GetPieceSprite(PieceType.Knight, TeamColor.White)
                        : null,
                },
                new VariantRow
                {
                    name    = "Caballo Fantasma",
                    tag     = "CABALLO",
                    passive = "Pasiva · Salto de Niebla + activa · Posesión",
                    lockedLabel = () => $"🔒 {HalloweenShop.VariantPrice(HalloweenArt.GhostKnightId)} 🍬",
                    owned     = PieceLoadoutManager.IsGhostKnightOwned,
                    equipped  = () => PieceLoadoutManager.UsesGhostKnight(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetKnightLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_KNIGHT_GHOST);
                        RefreshBoardLoadout();
                    },
                    art = () =>
                    {
                        var view = BoardView.Instance;
                        if (view == null) return null;
                        Sprite ghost = view.GetGhostKnightSprite(TeamColor.White);
                        return ghost != null ? ghost : view.GetPieceSprite(PieceType.Knight, TeamColor.White);
                    },
                },
                new VariantRow
                {
                    name    = "Peón Clásico",
                    tag     = "PEÓN",
                    passive = "Sin pasiva · avance y captura diagonal",
                    owned     = () => true,
                    equipped  = () => PieceLoadoutManager.GetPawnLoadout(TeamColor.White)
                                     == PieceLoadoutManager.LOADOUT_PAWN_CLASSIC,
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetPawnLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_PAWN_CLASSIC);
                        RefreshBoardLoadout();
                    },
                    art = () => BoardView.Instance != null
                        ? BoardView.Instance.GetPieceSprite(PieceType.Pawn, TeamColor.White)
                        : null,
                },
                new VariantRow
                {
                    name    = "Peón Lancero",
                    tag     = "PEÓN",
                    passive = "Pasiva · Lanza (captura al frente)",
                    lockedLabel = () => $"🔒 {PieceLoadoutManager.LANCER_PRICE_TIDES:N0} TIDES",
                    owned     = PieceLoadoutManager.IsLancerOwned,
                    equipped  = () => PieceLoadoutManager.UsesLancerPawn(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetPawnLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_PAWN_LANCER);
                        RefreshBoardLoadout();
                    },
                    art = () =>
                    {
                        var view = BoardView.Instance;
                        if (view == null) return null;
                        Sprite lancer = view.GetLancerPawnSprite(TeamColor.White);
                        return lancer != null ? lancer : view.GetPieceSprite(PieceType.Pawn, TeamColor.White);
                    },
                },
                new VariantRow
                {
                    name    = "Peón Calabaza",
                    tag     = "PEÓN",
                    passive = "Pasiva · Explosión de Calabaza (aturde 2 turnos)",
                    lockedLabel = () => $"🔒 {HalloweenShop.VariantPrice(HalloweenArt.PumpkinPawnId)} 🍬",
                    owned     = PieceLoadoutManager.IsPumpkinPawnOwned,
                    equipped  = () => PieceLoadoutManager.UsesPumpkinPawn(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetPawnLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_PAWN_PUMPKIN);
                        RefreshBoardLoadout();
                    },
                    art = () =>
                    {
                        var view = BoardView.Instance;
                        if (view == null) return null;
                        Sprite pumpkin = view.GetPumpkinPawnSprite(TeamColor.White);
                        return pumpkin != null ? pumpkin : view.GetPieceSprite(PieceType.Pawn, TeamColor.White);
                    },
                },
                new VariantRow
                {
                    name    = "Dama Clásica",
                    tag     = "DAMA",
                    passive = "Sin pasiva · rectas y diagonales",
                    owned     = () => true,
                    equipped  = () => PieceLoadoutManager.GetQueenLoadout(TeamColor.White)
                                     == PieceLoadoutManager.LOADOUT_QUEEN_CLASSIC,
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetQueenLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_QUEEN_CLASSIC);
                        RefreshBoardLoadout();
                    },
                    art = () => BoardView.Instance != null
                        ? BoardView.Instance.GetPieceSprite(PieceType.Queen, TeamColor.White)
                        : null,
                },
                new VariantRow
                {
                    name    = "Dama Jinete",
                    tag     = "DAMA",
                    passive = "Pasiva · Cabalgada (salto de caballo 1×/partida)",
                    lockedLabel = () => $"🔒 {PieceLoadoutManager.RIDER_PRICE_TIDES:N0} TIDES",
                    owned     = PieceLoadoutManager.IsRiderOwned,
                    equipped  = () => PieceLoadoutManager.UsesRiderQueen(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetQueenLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_QUEEN_RIDER);
                        RefreshBoardLoadout();
                    },
                    art = () =>
                    {
                        var view = BoardView.Instance;
                        if (view == null) return null;
                        Sprite rider = view.GetRiderQueenSprite(TeamColor.White);
                        return rider != null ? rider : view.GetPieceSprite(PieceType.Queen, TeamColor.White);
                    },
                },
                new VariantRow
                {
                    name    = "Reina Vampira",
                    tag     = "DAMA",
                    passive = "Pasiva · No Muerta (renace 1×/partida)",
                    lockedLabel = () => "🔒 PASE · VÍA SANGRE",
                    owned     = PieceLoadoutManager.IsVampireOwned,
                    equipped  = () => PieceLoadoutManager.UsesVampireQueen(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetQueenLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_QUEEN_VAMPIRE);
                        RefreshBoardLoadout();
                    },
                    art = () =>
                    {
                        var view = BoardView.Instance;
                        if (view == null) return null;
                        Sprite vampire = view.GetVampireQueenSprite(TeamColor.White);
                        return vampire != null ? vampire : view.GetPieceSprite(PieceType.Queen, TeamColor.White);
                    },
                },
                new VariantRow
                {
                    name    = "Torre Clásica",
                    tag     = "TORRE",
                    passive = "Sin pasiva · rectas a cualquier distancia",
                    owned     = () => true,
                    equipped  = () => !PieceLoadoutManager.UsesFraguaRook(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetRookLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_ROOK_CLASSIC);
                        RefreshBoardLoadout();
                    },
                    art = () => BoardView.Instance != null
                        ? BoardView.Instance.GetPieceSprite(PieceType.Rook, TeamColor.White)
                        : null,
                },
                new VariantRow
                {
                    name    = "Torre Fragua",
                    tag     = "TORRE",
                    passive = "Exclusiva del pase · Sentencia (próximamente)",
                    lockedLabel = () => "🔒 PASE REAL · NIVEL 75",
                    owned     = PieceLoadoutManager.IsFraguaOwned,
                    equipped  = () => PieceLoadoutManager.UsesFraguaRook(TeamColor.White),
                    equip     = () =>
                    {
                        PieceLoadoutManager.SetRookLoadout(
                            TeamColor.White, PieceLoadoutManager.LOADOUT_ROOK_FRAGUA);
                        RefreshBoardLoadout();
                    },
                    art = () => BoardView.Instance != null
                        ? BoardView.Instance.GetPieceSprite(PieceType.Rook, TeamColor.White)
                        : null,
                },
            };
        }

        /// <summary>
        /// Recoloca las piezas del tablero con el loadout recién equipado. Sin esto la
        /// variante sí se guardaba en PlayerPrefs, pero el tablero seguía con la anterior
        /// hasta que se volvía al menú (que llama a ResetBoard) o se reiniciaba la app.
        /// </summary>
        private static void RefreshBoardLoadout()
        {
            if (BoardView.Instance != null)
                BoardView.Instance.ResetBoard();
        }

        // ── Ciclo de vida ─────────────────────────────────────────────────────

        public void Initialize(VisualElement modalRoot, Action onClose,
                               Action<string, string> onToast = null, Action onBoardEquipped = null)
        {
            _root = modalRoot;
            if (_root == null) return;

            _onClose = onClose;
            _onToast = onToast;
            _onBoardEquipped = onBoardEquipped;

            _grid        = _root.Q<VisualElement>("inv-grid");
            _filterRow   = _root.Q<VisualElement>("inv-filter-row");
            _crestArt    = _root.Q<Image>("inv-crest-art");
            _watermark   = _root.Q<Image>("inv-watermark");
            _crestFallback = _root.Q<Label>("inv-crest-fallback");
            _chipGambits = _root.Q<Label>("inv-chip-gambits");
            _chipOwned   = _root.Q<Label>("inv-chip-owned");
            _chipOwnedLabel = _root.Q<Label>("inv-chip-owned-label");
            _tabHint     = _root.Q<Label>("inv-tab-hint");
            _countVariants = _root.Q<Label>("inv-count-variants");
            _countSkins    = _root.Q<Label>("inv-count-skins");
            _countBoards   = _root.Q<Label>("inv-count-boards");

            _tabVariants = _root.Q<Button>("inv-tab-variants");
            _tabSkins    = _root.Q<Button>("inv-tab-skins");
            _tabBoards   = _root.Q<Button>("inv-tab-boards");

            _filterAll    = _root.Q<Button>("inv-filter-all");
            _filterKnight = _root.Q<Button>("inv-filter-knight");
            _filterBishop = _root.Q<Button>("inv-filter-bishop");
            _filterQueen  = _root.Q<Button>("inv-filter-queen");
            _filterPawn   = _root.Q<Button>("inv-filter-pawn");

            _tabVariants?.RegisterCallback<ClickEvent>(_ => SelectTab(TAB_VARIANTS));
            _tabSkins?.RegisterCallback<ClickEvent>(_ => SelectTab(TAB_SKINS));
            _tabBoards?.RegisterCallback<ClickEvent>(_ => SelectTab(TAB_BOARDS));

            _filterAll?.RegisterCallback<ClickEvent>(_ => SetSkinFilter("all"));
            _filterKnight?.RegisterCallback<ClickEvent>(_ => SetSkinFilter("knight"));
            _filterBishop?.RegisterCallback<ClickEvent>(_ => SetSkinFilter("bishop"));
            _filterQueen?.RegisterCallback<ClickEvent>(_ => SetSkinFilter("queen"));
            _filterPawn?.RegisterCallback<ClickEvent>(_ => SetSkinFilter("pawn"));

            _root.Q<Button>("btn-close-inventory")?.RegisterCallback<ClickEvent>(_ => Close());
            _root.Q<Button>("btn-close-inventory-foot")?.RegisterCallback<ClickEvent>(_ => Close());

            // Arte del macuto: si el PNG todavía no está importado, el emoji hace de marcador
            Sprite backpack = InventorySprites.BackpackSprite;
            if (_crestArt != null && backpack != null)
            {
                _crestArt.sprite = backpack;
                _crestArt.scaleMode = ScaleMode.ScaleToFit;
            }
            _crestArt?.EnableInClassList("hidden", backpack == null);
            _crestFallback?.EnableInClassList("hidden", backpack != null);

            Sprite archive = InventorySprites.ArchiveSprite;
            if (_watermark != null && archive != null)
            {
                _watermark.sprite = archive;
                _watermark.scaleMode = ScaleMode.ScaleToFit;
            }
        }

        /// <summary>Se llama al abrir el modal: refresca propiedad, contadores y rejilla.</summary>
        public void OnOpened()
        {
            PieceSkinManager.SyncFromOceanPay();
            Refresh();
        }

        /// <summary>Abre el inventario en una pestaña concreta (atajo desde la tienda).</summary>
        public void OpenTab(string tab)
        {
            _tab = Normalize(tab);
            Refresh();
        }

        private static string Normalize(string tab)
        {
            switch (tab)
            {
                case TAB_SKINS:  return TAB_SKINS;
                case TAB_BOARDS: return TAB_BOARDS;
                default:         return TAB_VARIANTS;
            }
        }

        public void SelectTab(string tab)
        {
            _tab = Normalize(tab);
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            Refresh();
        }

        private void Close()
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            _onClose?.Invoke();
        }

        // ── Pintado ───────────────────────────────────────────────────────────

        private void Refresh()
        {
            if (_grid == null) return;

            MarkTabs();
            RefreshCounters();

            _grid.Clear();
            switch (_tab)
            {
                case TAB_SKINS:  BuildSkins();  break;
                case TAB_BOARDS: BuildBoards(); break;
                default:         BuildVariantsTab(); break;
            }
        }

        private void MarkTabs()
        {
            // Misma clase de pestaña activa que la tienda (USS: .shop2-tab.shop2-nav-active)
            _tabVariants?.EnableInClassList("shop2-nav-active", _tab == TAB_VARIANTS);
            _tabSkins?.EnableInClassList("shop2-nav-active", _tab == TAB_SKINS);
            _tabBoards?.EnableInClassList("shop2-nav-active", _tab == TAB_BOARDS);

            _filterRow?.EnableInClassList("hidden", _tab != TAB_SKINS);

            if (_tabHint != null)
            {
                switch (_tab)
                {
                    case TAB_SKINS:
                        _tabHint.text = "Filtra por pieza y pulsa una carta para vestirla.";
                        break;
                    case TAB_BOARDS:
                        _tabHint.text = "Pulsa un tablero para cambiar la atmósfera.";
                        break;
                    default:
                        _tabHint.text = "Pulsa una carta para equiparla en el tablero.";
                        break;
                }
            }
        }

        private void RefreshCounters()
        {
            PieceSkinManager.SyncFromOceanPay();

            int skinsOwned = CountOwnedSkins();
            int variantsOwned = CountOwnedVariants();
            int boardsOwned = BoardBackgroundManager.UnlockedCount;

            if (_chipGambits != null)
                _chipGambits.text = $"{GambitEconomy.Balance:N0}";

            // El chip de posesión habla de la pestaña abierta
            if (_chipOwned != null)
            {
                switch (_tab)
                {
                    case TAB_SKINS:  _chipOwned.text = $"{skinsOwned} / {PieceSkinManager.Count}"; break;
                    case TAB_BOARDS: _chipOwned.text = $"{boardsOwned} / {BoardBackgroundManager.ThemeCount}"; break;
                    default:         _chipOwned.text = $"{variantsOwned} / {Variants.Length}"; break;
                }
            }
            if (_chipOwnedLabel != null)
                _chipOwnedLabel.text = _tab == TAB_BOARDS ? "DESBLOQUEADOS" : "EN POSESIÓN";

            if (_countVariants != null) _countVariants.text = variantsOwned.ToString();
            if (_countSkins != null)    _countSkins.text = skinsOwned.ToString();
            if (_countBoards != null)   _countBoards.text = boardsOwned.ToString();
        }

        /// <summary>Tamaño de la colección: lo enseña la chapa del botón girado del menú.</summary>
        public static int CollectionSize()
        {
            return CountOwnedSkins() + CountOwnedVariants() + BoardBackgroundManager.UnlockedCount;
        }

        private static int CountOwnedSkins()
        {
            int n = 0;
            for (int i = 0; i < PieceSkinManager.Count; i++)
                if (PieceSkinManager.IsOwned(i)) n++;
            return n;
        }

        /// <summary>5 clásicos + variantes (Nigromante, Lancero, Jinete, Vampira, Fragua y las de la velada).</summary>
        private static int CountOwnedVariants()
        {
            int n = 5;
            if (PieceLoadoutManager.IsNecroOwned()) n++;
            if (PieceLoadoutManager.IsLancerOwned()) n++;
            if (PieceLoadoutManager.IsRiderOwned()) n++;
            if (PieceLoadoutManager.IsVampireOwned()) n++;
            if (PieceLoadoutManager.IsFraguaOwned()) n++;
            if (PieceLoadoutManager.IsPumpkinPawnOwned()) n++;
            if (PieceLoadoutManager.IsGhostKnightOwned()) n++;
            return n;
        }

        // ── Pestaña VARIANTES ─────────────────────────────────────────────────

        private void BuildVariantsTab()
        {
            var rows = Variants;
            int equippedCount = 0;
            var cards = new List<VisualElement>(rows.Length);

            for (int i = 0; i < rows.Length; i++)
            {
                if (rows[i].equipped()) equippedCount++;
                cards.Add(BuildVariantCard(i, rows[i]));
            }

            // La formación actual va primero: se lee de un vistazo qué piezas
            // entran al tablero y deja la rejilla de colección limpia y pareja.
            AddLoadoutStrip(rows);
            AddSection("TODAS LAS VARIANTES",
                $"{rows.Length} en el catálogo · {CountOwnedVariants()} en tu colección · " +
                $"{equippedCount} en el tablero",
                cards);

            if (cards.Count == 0)
                AddEmpty("SIN VARIANTES", "Compra variantes en la tienda y aparecerán aquí.");
        }

        private VisualElement BuildVariantCard(int index, VariantRow row)
        {
            bool equipped = row.equipped();
            bool owned = row.owned();

            var card = NewCard($"inv-variant-{index}", wide: true, equipped: equipped, locked: !owned);

            var thumb = NewThumb(248);
            thumb.Add(NewGlow(265, 205, new Color(0.83f, 0.70f, 0.42f, 0.30f)));
            thumb.Add(NewGlow(165, 130, new Color(0.94f, 0.82f, 0.48f, 0.34f)));
            thumb.Add(NewFloorShadow());
            Sprite art = row.art != null ? row.art() : null;
            if (art != null)
            {
                var img = new Image { sprite = art, scaleMode = ScaleMode.ScaleToFit };
                img.AddToClassList("bg-card-thumb-img");
                img.style.width = Length.Percent(80);
                img.style.height = Length.Percent(94);
                thumb.Add(img);
            }
            else
            {
                var icon = new Label("♟");
                icon.AddToClassList("bg-card-thumb-placeholder");
                thumb.Add(icon);
            }

            var typeChip = new Label(row.tag);
            typeChip.AddToClassList("inv-type-chip");
            typeChip.pickingMode = PickingMode.Ignore;
            thumb.Add(typeChip);

            card.Add(thumb);
            card.Add(NewCardRule());

            card.Add(NewNameRow("◆", row.name));

            // El tipo ya vive en la chapa del arte: la nota queda para la pasiva.
            var note = new Label(row.passive);
            note.AddToClassList("inv-card-note");
            card.Add(note);
            AddStatePill(card, owned, equipped, row.equip, row.name,
                row.lockedLabel != null ? row.lockedLabel() : "🔒 EN LA TIENDA");
            AddCornerMark(card, equipped, !owned);
            HookCardClick(card, owned, equipped, row.equip, row.name);

            return card;
        }

        // ── Pestaña SKINS ─────────────────────────────────────────────────────

        private void SetSkinFilter(string filter)
        {
            _skinFilter = filter;

            var buttons = new[] { _filterAll, _filterKnight, _filterBishop, _filterQueen, _filterPawn };
            foreach (Button btn in buttons)
                btn?.RemoveFromClassList("skin-filter-active");

            Button active = filter switch
            {
                "knight" => _filterKnight,
                "bishop" => _filterBishop,
                "queen"  => _filterQueen,
                "pawn"   => _filterPawn,
                _        => _filterAll,
            };
            active?.AddToClassList("skin-filter-active");

            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            Refresh();
        }

        private bool SkinPassesFilter(int index)
        {
            if (_skinFilter == "all") return true;
            PieceType type = PieceSkinManager.GetSkinPieceType(index);
            switch (_skinFilter)
            {
                case "knight": return type == PieceType.Knight;
                case "bishop": return type == PieceType.Bishop || type == PieceType.NecromancerBishop;
                case "queen":  return type == PieceType.Queen || type == PieceType.King || type == PieceType.Rook;
                case "pawn":   return type == PieceType.Pawn;
                default:       return true;
            }
        }

        private void BuildSkins()
        {
            var equipped = new List<VisualElement>();
            var owned = new List<VisualElement>();
            var locked = new List<VisualElement>();
            int shown = 0;
            int ownedShown = 0;

            for (int i = 0; i < PieceSkinManager.Count; i++)
            {
                if (!SkinPassesFilter(i)) continue;
                shown++;
                if (PieceSkinManager.IsOwned(i)) ownedShown++;

                VisualElement card = BuildSkinCard(i);
                if (PieceSkinManager.IsEquipped(i)) equipped.Add(card);
                else if (PieceSkinManager.IsOwned(i)) owned.Add(card);
                else locked.Add(card);
            }

            var cards = new List<VisualElement>(shown);
            cards.AddRange(equipped);
            cards.AddRange(owned);
            cards.AddRange(locked);

            string note = $"{shown} aspectos · {ownedShown} en tu colección";
            string filter = SkinFilterLabel();
            if (!string.IsNullOrEmpty(filter)) note += $" · filtro {filter}";

            AddSection("ASPECTOS", note, cards);

            if (shown == 0)
                AddEmpty("SIN ASPECTOS EN ESTE FILTRO", "Prueba con otro tipo de pieza.");
        }

        private string SkinFilterLabel()
        {
            switch (_skinFilter)
            {
                case "knight": return "CABALLO";
                case "bishop": return "ALFIL";
                case "queen":  return "DAMA · REY · TORRE";
                case "pawn":   return "PEÓN";
                default:       return null;
            }
        }

        private static string PieceLabel(PieceType type)
        {
            switch (type)
            {
                case PieceType.Pawn:               return "PEÓN";
                case PieceType.Knight:             return "CABALLO";
                case PieceType.Bishop:             return "ALFIL";
                case PieceType.NecromancerBishop:  return "NIGROMANTE";
                case PieceType.Rook:               return "TORRE";
                case PieceType.Queen:              return "DAMA";
                case PieceType.King:               return "REY";
                default:                           return type.ToString().ToUpperInvariant();
            }
        }

        private VisualElement BuildSkinCard(int index)
        {
            string name = PieceSkinManager.GetSkinName(index);
            PieceType type = PieceSkinManager.GetSkinPieceType(index);
            bool owned = PieceSkinManager.IsOwned(index);
            bool equipped = PieceSkinManager.IsEquipped(index);
            int price = PieceSkinManager.GetSkinPrice(index);
            Color tint = PieceSkinManager.GetSkinTint(index);
            SkinRarity rarity = PieceSkinManager.GetSkinRarity(index);
            bool eventSkin = PieceSkinManager.IsHalloweenShopExclusive(index);
            bool passSkin = PieceSkinManager.IsPassExclusiveSkin(index);

            var card = NewCard($"inv-skin-{index}", wide: false, equipped: equipped, locked: !owned);

            var thumb = NewThumb(248);
            thumb.Add(NewGlow(265, 205, new Color(tint.r, tint.g, tint.b, 0.38f)));
            thumb.Add(NewFloorShadow());

            Texture2D thumbTex = PieceSkinManager.GetSkinThumbnail(index);
            Sprite pieceSprite = BoardView.Instance != null
                ? BoardView.Instance.GetPieceSprite(type, TeamColor.White)
                : null;

            if (thumbTex != null)
            {
                var img = new Image { image = thumbTex, scaleMode = ScaleMode.ScaleToFit };
                img.AddToClassList("bg-card-thumb-img");
                thumb.Add(img);
            }
            else if (pieceSprite != null)
            {
                var img = new Image { sprite = pieceSprite, scaleMode = ScaleMode.ScaleToFit };
                img.AddToClassList("bg-card-thumb-img");
                img.style.width = Length.Percent(80);
                img.style.height = Length.Percent(94);
                img.style.unityBackgroundImageTintColor = new StyleColor(tint);
                thumb.Add(img);
            }
            else
            {
                var icon = new Label(PieceSkinManager.GetSkinIcon(index));
                icon.AddToClassList("bg-card-thumb-placeholder");
                icon.style.color = new StyleColor(tint);
                thumb.Add(icon);
            }
            card.Add(thumb);
            card.Add(NewCardRule());
            card.Add(NewNameRow("◆", name));

            var note = new Label($"{PieceLabel(type)} · {PieceSkinManager.RarityLabel(rarity)}");
            note.AddToClassList("inv-card-note");
            ShopRarity.StyleDetailKicker(note, PieceSkinManager.RarityLabel(rarity));
            card.Add(note);
            ShopRarity.TintCardBorder(card, PieceSkinManager.RarityLabel(rarity), equipped);
            AddCornerMark(card, equipped, !owned);

            if (!owned)
            {
                // Las de la velada no se compran con Gambits: solo se muestran y
                // mandan a la tienda del evento (donde se pagan con Dulces).
                if (eventSkin)
                    AddStatePill(card, false, false, null, name,
                        $"🍬 {price} · TIENDA DE LA VELADA");
                else if (passSkin)
                    AddStatePill(card, false, false, null, name, "🎃 PASE DE LA VELADA");
                else
                    AddSkinBuyPill(card, index, name);
                return card;
            }

            Action equip = () =>
            {
                if (PieceSkinManager.IsEquipped(index)) PieceSkinManager.UnequipSkin(type);
                else PieceSkinManager.EquipSkin(index);
                RefreshBoardLoadout(); // si hay tablero cargado, aplica tinte/aura al instante
            };
            AddStatePill(card, true, equipped, equip, name);
            HookCardClick(card, true, equipped, equip, name);

            return card;
        }

        /// <summary>
        /// Las skins no tenían dónde comprarse: «TUS PIEZAS» nunca llegó a montar la
        /// rejilla, así que las vende la pestaña SKINS. Comprar no es equipar: la carta
        /// pasa a «EQUIPAR» y decide el jugador.
        /// </summary>
        private void AddSkinBuyPill(VisualElement card, int index, string displayName)
        {
            int price = PieceSkinManager.GetSkinPrice(index);

            if (price > 0 && !PieceSkinManager.CanAfford(index))
            {
                var off = new Label($"FALTAN {price - PieceSkinManager.GetLocalGambits():N0} G");
                off.AddToClassList("inv-state");
                off.AddToClassList("inv-state-off");
                off.pickingMode = PickingMode.Ignore;
                card.Add(off);
                return;
            }

            var btn = new Button(() =>
            {
                Action grant = () =>
                {
                    PieceSkinManager.OwnSkin(index);
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    WilderGambit.Core.GambitProgress.NotifyChanged();
                    Refresh();
                    _onToast?.Invoke("Comprada", $"{displayName} · ya puedes equiparla");
                };

                if (price <= 0)
                {
                    grant();
                    return;
                }

                // Cobro centralizado en el checkout de Surface.
                WilderGambit.Services.SurfaceCheckoutBridge.BuyGambits(
                    "wilder-gambit-skin-" + PieceSkinManager.GetSkinId(index),
                    displayName,
                    "Aspecto de pieza · Inventario",
                    price,
                    result =>
                    {
                        if (!result.success)
                        {
                            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                            return;
                        }
                        grant();
                    });
            });
            btn.text = price > 0 ? $"🔓 COMPRAR {price:N0} G" : "🔓 ADQUIRIR";
            btn.AddToClassList("inv-state");
            btn.AddToClassList("inv-state-act");
            btn.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
            card.Add(btn);
        }

        // ── Pestaña TABLEROS ──────────────────────────────────────────────────

        private void BuildBoards()
        {
            var active = new List<VisualElement>();
            var owned = new List<VisualElement>();
            var locked = new List<VisualElement>();

            int selected = BoardBackgroundManager.SelectedIndex;
            for (int i = 0; i < BoardBackgroundManager.ThemeCount; i++)
            {
                bool isEquipped = i == selected;
                bool unlocked = BoardBackgroundManager.IsUnlocked(i);
                VisualElement card = BuildBoardCard(i, isEquipped, unlocked);
                if (isEquipped) active.Add(card);
                else if (unlocked) owned.Add(card);
                else locked.Add(card);
            }

            var cards = new List<VisualElement>(BoardBackgroundManager.ThemeCount);
            cards.AddRange(active);
            cards.AddRange(owned);
            cards.AddRange(locked);

            AddSection("TABLEROS",
                $"{BoardBackgroundManager.ThemeCount} atmósferas · " +
                $"{BoardBackgroundManager.UnlockedCount} desbloqueadas",
                cards);

            if (cards.Count == 0)
                AddEmpty("SIN TABLEROS", "Los tableros artesanales aparecerán aquí.");
        }

        private VisualElement BuildBoardCard(int index, bool equipped, bool unlocked)
        {
            string name = BoardBackgroundManager.GetDisplayName(index);
            int price = BoardPrice(index);
            bool passExclusive = BoardBackgroundManager.IsPassExclusive(index);

            var card = NewCard($"inv-board-{index}", wide: false, equipped: equipped, locked: !unlocked);

            var thumb = NewThumb(138);
            Texture2D tex = BoardThumb(index);
            if (tex != null)
            {
                var img = new Image { image = tex, scaleMode = ScaleMode.ScaleToFit };
                img.AddToClassList("bg-card-thumb-img");
                thumb.Add(img);
            }
            else
            {
                var icon = new Label(BoardIcon(index));
                icon.AddToClassList("bg-card-thumb-placeholder");
                thumb.Add(icon);
            }
            card.Add(thumb);
            card.Add(NewCardRule());
            card.Add(NewNameRow(BoardIcon(index), name));

            var note = new Label(
                equipped ? "Tu tablero activo"
                : passExclusive ? "Pase de Halloween"
                : // desbloqueado: ya es del jugador; bloqueado: precio de tienda
                unlocked ? "En tu colección"
                : price > 0 ? $"{price:N0} Gambits"
                : "Gratis");
            note.AddToClassList("inv-card-note");
            card.Add(note);
            AddCornerMark(card, equipped, !unlocked);

            Action equip = () =>
            {
                BoardBackgroundManager.Select(index);
                _onBoardEquipped?.Invoke();
            };
            AddStatePill(card, unlocked, equipped, equip, name,
                passExclusive ? "🔒 EXCLUSIVO DEL PASE" : "🔒 EN LA TIENDA");
            HookCardClick(card, unlocked, equipped, equip, name);

            return card;
        }

        private Texture2D BoardThumb(int index)
        {
            if (_boardThumbs.TryGetValue(index, out Texture2D cached)) return cached;
            Texture2D tex = BoardBackgroundManager.LoadThumbnailForIndex(index);
            if (tex != null) _boardThumbs[index] = tex;
            return tex;
        }

        private static int BoardPrice(int index)
        {
            int[] prices = BoardBackgroundManager.ThemePrices;
            if (prices != null && index >= 0 && index < prices.Length) return prices[index];
            return 0;
        }

        private static string BoardIcon(int index)
        {
            if (index >= 0 && index < BoardIcons.Length) return BoardIcons[index];
            return "🎨";
        }

        // ── Formación actual (cabecera de VARIANTES) ──────────────────────────

        /// <summary>
        /// Las cinco piezas que hoy entran al tablero. Va arriba de la colección
        /// para leer el loadout de un vistazo y dejar la rejilla pareja: las
        /// cartas ya no cambian de tamaño según estén o no equipadas.
        /// </summary>
        private void AddLoadoutStrip(VariantRow[] rows)
        {
            string[] order = { "ALFIL", "CABALLO", "PEÓN", "DAMA", "TORRE" };

            var strip = new VisualElement();
            strip.AddToClassList("inv-loadout");
            strip.pickingMode = PickingMode.Ignore;

            var head = new VisualElement();
            head.AddToClassList("inv-loadout-head");
            head.pickingMode = PickingMode.Ignore;

            var title = new Label("TU FORMACIÓN");
            title.AddToClassList("inv-loadout-title");
            head.Add(title);

            var note = new Label("Las cinco piezas que entran al tablero.");
            note.AddToClassList("inv-loadout-note");
            head.Add(note);

            strip.Add(head);

            var slots = new VisualElement();
            slots.AddToClassList("inv-loadout-slots");
            slots.pickingMode = PickingMode.Ignore;

            for (int i = 0; i < order.Length; i++)
            {
                VariantRow row = FindEquipped(rows, order[i]);
                if (row != null)
                    slots.Add(BuildLoadoutSlot(row, i == order.Length - 1));
            }

            strip.Add(slots);
            _grid.Add(strip);
        }

        private static VariantRow FindEquipped(VariantRow[] rows, string tag)
        {
            for (int i = 0; i < rows.Length; i++)
                if (rows[i].tag == tag && rows[i].equipped()) return rows[i];

            // Respaldo: si el loadout guardado no coincide con ninguna fila,
            // se muestra la primera de esa familia antes que dejar un hueco.
            for (int i = 0; i < rows.Length; i++)
                if (rows[i].tag == tag) return rows[i];

            return null;
        }

        private static VisualElement BuildLoadoutSlot(VariantRow row, bool last)
        {
            var slot = new VisualElement();
            slot.AddToClassList("inv-loadout-slot");
            if (last) slot.AddToClassList("inv-loadout-slot-last");
            slot.pickingMode = PickingMode.Ignore;

            var art = new VisualElement();
            art.AddToClassList("inv-loadout-art");
            art.pickingMode = PickingMode.Ignore;

            Sprite sprite = row.art != null ? row.art() : null;
            if (sprite != null)
            {
                var img = new Image { sprite = sprite, scaleMode = ScaleMode.ScaleToFit };
                img.AddToClassList("inv-loadout-art-img");
                art.Add(img);
            }
            else
            {
                var icon = new Label("♟");
                icon.AddToClassList("inv-loadout-art-icon");
                art.Add(icon);
            }
            slot.Add(art);

            var texts = new VisualElement();
            texts.AddToClassList("inv-loadout-texts");
            texts.pickingMode = PickingMode.Ignore;

            var tag = new Label(row.tag);
            tag.AddToClassList("inv-loadout-tag");
            texts.Add(tag);

            var name = new Label(ShortVariantName(row.name));
            name.AddToClassList("inv-loadout-name");
            texts.Add(name);
            slot.Add(texts);

            var check = new Label("✓");
            check.AddToClassList("inv-loadout-check");
            check.pickingMode = PickingMode.Ignore;
            slot.Add(check);

            return slot;
        }

        /// <summary>«Alfil Nigromante» → «Nigromante»: en la tira cabe el distintivo.</summary>
        private static string ShortVariantName(string name)
        {
            if (string.IsNullOrEmpty(name)) return string.Empty;
            int space = name.IndexOf(' ');
            return space >= 0 && space < name.Length - 1 ? name.Substring(space + 1) : name;
        }

        // ── Piezas de carta compartidas ───────────────────────────────────────

        private VisualElement NewCard(string name, bool wide, bool equipped, bool locked)
        {
            var card = new VisualElement { name = name };
            card.AddToClassList("bg-card");
            card.AddToClassList("inv-card");
            if (wide) card.AddToClassList("bg-card-variant");
            if (wide) card.AddToClassList("inv-card-wide");
            if (equipped) card.AddToClassList("bg-card-active");
            if (locked) card.AddToClassList("bg-card-locked");

            return card;
        }

        private static VisualElement NewThumb(float height)
        {
            var thumb = new VisualElement();
            thumb.AddToClassList("bg-card-thumb");
            thumb.pickingMode = PickingMode.Ignore;
            return thumb;
        }

        private static VisualElement NewGlow(float w, float h, Color color)
        {
            var glow = new VisualElement();
            glow.AddToClassList("bg-card-thumb-glow");
            glow.style.width = w;
            glow.style.height = h;
            glow.style.unityBackgroundImageTintColor = new StyleColor(color);
            glow.pickingMode = PickingMode.Ignore;
            return glow;
        }

        /// <summary>Sombra de contacto: asienta la pieza dentro de la vitrina.</summary>
        private static VisualElement NewFloorShadow()
        {
            var floor = new VisualElement();
            floor.AddToClassList("inv-thumb-floor");
            floor.pickingMode = PickingMode.Ignore;
            return floor;
        }

        /// <summary>Filete ornamental entre el arte y el nombre.</summary>
        private static VisualElement NewCardRule()
        {
            var rule = new VisualElement();
            rule.AddToClassList("inv-card-rule");
            rule.pickingMode = PickingMode.Ignore;
            return rule;
        }

        private static VisualElement NewNameRow(string mark, string name)
        {
            var row = new VisualElement();
            row.AddToClassList("bg-card-name-row");
            row.pickingMode = PickingMode.Ignore;

            var icon = new Label(mark);
            icon.AddToClassList("bg-card-icon");
            row.Add(icon);

            var label = new Label(name);
            label.AddToClassList("bg-card-name");
            row.Add(label);

            return row;
        }

        /// <summary>
        /// Píldora de estado. Compra = botón dorado (equipa). Ya es tuyo y está puesto =
        /// «EN USO» en verde. Si no es tuyo, candado: a la tienda o su etiqueta de evento.
        /// </summary>
        private void AddStatePill(VisualElement card, bool owned, bool equipped,
                                  Action equip, string displayName,
                                  string lockedLabel = null)
        {
            if (equipped)
            {
                var on = new Label("✓ EN USO");
                on.AddToClassList("inv-state");
                on.AddToClassList("inv-state-on");
                on.pickingMode = PickingMode.Ignore;
                card.Add(on);
                return;
            }

            if (!owned)
            {
                var off = new Label(string.IsNullOrEmpty(lockedLabel)
                    ? "🔒 EN LA TIENDA"
                    : lockedLabel);
                off.AddToClassList("inv-state");
                off.AddToClassList("inv-state-off");
                off.pickingMode = PickingMode.Ignore;
                card.Add(off);
                return;
            }

            var btn = new Button(() =>
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                equip?.Invoke();
                Refresh();
                _onToast?.Invoke("Equipado", displayName);
            });
            btn.text = "EQUIPAR";
            btn.AddToClassList("inv-state");
            btn.AddToClassList("inv-state-act");
            btn.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
            card.Add(btn);
        }

        /// <summary>Toda la carta equipa (más cómodo que buscar la píldora).</summary>
        private void HookCardClick(VisualElement card, bool owned, bool equipped,
                                   Action equip, string displayName)
        {
            if (!owned || equipped) return;

            card.RegisterCallback<ClickEvent>(_ =>
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                equip?.Invoke();
                Refresh();
                _onToast?.Invoke("Equipado", displayName);
            });
        }

        /// <summary>Medallón de esquina: ✓ si está en uso, candado si aún no es del jugador.</summary>
        private static void AddCornerMark(VisualElement card, bool equipped, bool locked)
        {
            if (!equipped && !locked) return;

            var mark = new Label(equipped ? "✓" : "🔒");
            mark.AddToClassList("inv-mark");
            mark.AddToClassList(equipped ? "inv-mark-on" : "inv-mark-lock");
            mark.pickingMode = PickingMode.Ignore;
            card.Add(mark);
        }

        private static VisualElement NewSectionHead(string title, string note)
        {
            var head = new VisualElement();
            head.AddToClassList("inv-section");
            head.pickingMode = PickingMode.Ignore;

            var label = new Label(title);
            label.AddToClassList("inv-section-title");
            head.Add(label);

            var rule = new VisualElement();
            rule.AddToClassList("inv-section-rule");
            head.Add(rule);

            if (!string.IsNullOrEmpty(note))
            {
                var sub = new Label(note);
                sub.AddToClassList("inv-section-note");
                head.Add(sub);
            }

            return head;
        }

        private void AddSection(string title, string note, List<VisualElement> cards)
        {
            if (cards == null || cards.Count == 0) return;

            _grid.Add(NewSectionHead(title, note));
            foreach (VisualElement card in cards) _grid.Add(card);
        }

        private void AddEmpty(string title, string desc)
        {
            var empty = new VisualElement();
            empty.AddToClassList("inv-empty");

            var t = new Label(title);
            t.AddToClassList("inv-empty-title");
            empty.Add(t);

            var d = new Label(desc);
            d.AddToClassList("inv-empty-desc");
            empty.Add(d);

            _grid.Add(empty);
        }
    }
}
