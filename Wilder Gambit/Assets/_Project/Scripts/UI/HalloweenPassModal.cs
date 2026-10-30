using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// PASE DE HALLOWEEN — la velada en vivo (20/10 → 4/11).
    ///
    /// Mini-pase paralelo a la temporada: 30 niveles de 60 XP, dos vías
    /// (Luna gratis / Sangre premium) y cobro instantáneo. Las claves son
    /// propias y por año (HalloweenProgress / HalloweenCurrency): la temporada
    /// T1 no se toca.
    ///
    /// La Vía Sangre se abre con Dulces (la moneda temporal de la velada), no
    /// con Tides: el servidor sigue siendo el único camino del Gambito Real de
    /// la temporada.
    ///
    /// El camino de niveles tiene las dos formas del pase de temporada:
    /// en escritorio es un carril HORIZONTAL (columnas con carta Luna arriba,
    /// medallón sobre la línea al medio y carta Sangre abajo, con flechas y
    /// scroll lateral) que se escala para caber sin scroll vertical
    /// (<see cref="FitTrack"/>); en móvil vertical (.is-portrait, lo pone
    /// UiResponsive) es una lista VERTICAL con scroll (fila = medallón +
    /// carta Luna + carta Sangre). El UXML trae las dos y el USS muestra la
    /// que toca, así que ambas se pintan siempre.
    ///
    /// Estados: PRÓXIMAMENTE (con cuenta atrás) → ACTIVO (timer) → TERMINADO
    /// (resumen de lo cobrado). Los cobros y las misiones solo viven mientras
    /// la velada está abierta.
    /// </summary>
    public class HalloweenPassModal : MonoBehaviour
    {
        /// <summary>Coste de abrir la Vía Sangre en Dulces (la moneda de la velada).</summary>
        public const int SangreUnlockCost = HalloweenLanes.SangreUnlockCost;

        private const string KeyClaimPrefix = "WG_Halloween_Claim_";

        // ── Recompensas ──────────────────────────────────────────────────

        private enum Kind { Gambits, Dulces, Reroll, Skin, Variant, Animation, Board, Backdrop }

        private struct Reward
        {
            public Kind kind;
            public string icon;
            public string name;
            public int amount;
            public string refId;
            public int index;
        }

        private static Reward Gambits(int amount) => new Reward
        {
            kind = Kind.Gambits, icon = "♔", name = "Gambits", amount = amount, index = -1,
        };

        private static Reward Dulces(int amount) => new Reward
        {
            kind = Kind.Dulces, icon = HalloweenCurrency.Icon, name = HalloweenCurrency.Label,
            amount = amount, index = -1,
        };

        private static Reward Reroll() => new Reward
        {
            kind = Kind.Reroll, icon = "🎲", name = "Cambio de misión", index = -1,
        };

        /// <summary>Skin por id del catálogo: nombre, icono e índice los pone el catálogo.</summary>
        private static Reward Skin(string skinId)
        {
            int index = PieceSkinManager.GetIndexById(skinId);
            string icon = index >= 0 ? PieceSkinManager.GetSkinIcon(index) : "✨";
            string name = index >= 0 ? PieceSkinManager.GetSkinName(index) : skinId;
            return new Reward
            {
                kind = Kind.Skin, icon = icon, name = name, refId = skinId, index = index,
            };
        }

        /// <summary>Variante de pieza por id: el arte y el cobro van por <c>refId</c>.</summary>
        private static Reward Variant(string variantId, string icon, string name) => new Reward
        {
            kind = Kind.Variant, icon = icon, name = name, refId = variantId, index = -1,
        };

        /// <summary>Animación de efecto por id (se desbloquea sin equipar).</summary>
        private static Reward Animation(string refId, string icon, string name) => new Reward
        {
            kind = Kind.Animation, icon = icon, name = name, refId = refId, index = -1,
        };

        private static Reward Board(int index) => new Reward
        {
            kind = Kind.Board, icon = "♟️",
            name = index >= 0 ? BoardBackgroundManager.GetDisplayName(index) : "Tablero", index = index,
        };

        private static Reward Backdrop(int index) => new Reward
        {
            kind = Kind.Backdrop, icon = "🖼️",
            name = index >= 0 ? BackdropManager.GetDisplayName(index) : "Fondo", index = index,
        };

        // Índices del catálogo de la velada. Los tableros y fondos de la Parte 2
        // se resuelven por id: si todavía no están cableados, la tarjeta cae al
        // emoji y el cobro no se consume (no rompe la pista).
        private static readonly int MoonBoardIndex = SafeBoardIndex("halloween_moon");
        private static readonly int BloodBoardIndex = SafeBoardIndex("halloween_blood");
        private static readonly int GraveyardBoardIndex = SafeBoardIndex("halloween_graveyard");
        private static readonly int CryptBoardIndex = SafeBoardIndex("halloween_crypt");
        private static readonly int WitchBackdropIndex = SafeBackdropIndex("halloween_night");
        private static readonly int HarvestBackdropIndex = SafeBackdropIndex("halloween_harvest");
        private static readonly int BanquetBackdropIndex = SafeBackdropIndex("halloween_banquet");

        private static int SafeBoardIndex(string id)
        {
            try { return BoardBackgroundManager.GetIndexById(id); }
            catch { return -1; }
        }

        private static int SafeBackdropIndex(string id)
        {
            try { return BackdropManager.GetIndexById(id); }
            catch { return -1; }
        }

        // ── Vía Luna (gratis): la moneda, los esculpidos y el Peón Calabaza ─────

        private static readonly Reward[] LunaRewards =
        {
            // Niveles 1-20: la edición original.
            Dulces(5), Gambits(60), Reroll(), Dulces(6), Gambits(80),
            Gambits(100), Dulces(8), Reroll(), Gambits(120), Dulces(8),
            Gambits(150), Skin("skin_pawn_halloween"),
            Variant(HalloweenArt.PumpkinPawnId, "🎃", "Peón Calabaza"), Gambits(180),
            Gambits(210), Dulces(12), Skin("skin_king_halloween"), Dulces(15),
            Gambits(300), Backdrop(WitchBackdropIndex),

            // Niveles 21-30 · «La Cosecha» (Parte 2). Cierran el set con el Alfil
            // y el Caballo, dan el fondo y el tablero de la vía y mantienen la
            // economía documentada: 72 Dulces y 800 Gambits. El hueco que dejó el
            // Peón Golosina (reservado para los Gummy Bears) se cubre con Dulces.
            Dulces(20), Skin("skin_bishop_lantern"), Gambits(350), Backdrop(HarvestBackdropIndex), Dulces(24),
            Dulces(10), Gambits(450), Dulces(18), Board(GraveyardBoardIndex),
            Skin("skin_knight_scarecrow"),
        };

        // ── Vía Sangre (se abre con Dulces): los esculpidos del banner, el
        //    Caballo Fantasma y la Dama Vampira ───────────────────────────────

        private static readonly Reward[] SangreRewards =
        {
            // Niveles 1-20: la edición original.
            Dulces(10), Gambits(120), Gambits(150), Dulces(12),
            Skin("skin_rook_halloween"), Gambits(200), Dulces(15), Gambits(250),
            Skin("skin_queen_halloween"), Dulces(18), Gambits(320), Dulces(20),
            Variant(HalloweenArt.GhostKnightId, "👻", "Caballo Fantasma"),
            Board(MoonBoardIndex), Dulces(25), Gambits(450),
            Board(BloodBoardIndex), Dulces(30), Variant("vampira", "🧛", "Reina Vampira"),
            Gambits(800),

            // Niveles 21-30 · «La Corte» (Parte 2). La Torre Relicario y la Reina
            // Maleficio se compran con Dulces en la tienda de la velada, así que
            // sus tramos pasan a pagar Dulces para financiarlas. La vía cierra
            // con el Rey Carmesí, la Cripta y el Banquete: 52 Dulces y 1.600 Gambits.
            Dulces(10), Dulces(8), Dulces(12), Gambits(700), Board(CryptBoardIndex),
            Dulces(10), Backdrop(BanquetBackdropIndex), Gambits(900), Dulces(12),
            Skin("skin_king_crimson"),
        };

        /// <summary>Recompensa de un nivel. Nunca falla: si la tabla es corta, cicla.</summary>
        private static Reward RewardAt(int tier, bool sangre)
        {
            Reward[] table = sangre ? SangreRewards : LunaRewards;
            if (table == null || table.Length == 0) return Gambits(0);
            return table[(tier - 1) % table.Length];
        }

        /// <summary>
        /// Resumen del carril Sangre para la confirmación de compra: Dulces y
        /// Gambits totales de los 30 niveles, más los nombres de las piezas,
        /// skins, animaciones y tableros que reparte. Lo pinta <see cref="HalloweenSangreConfirm"/>.
        /// </summary>
        public static void GetSangreLaneSummary(out int dulces, out int gambits, out List<string> highlights)
        {
            dulces = 0;
            gambits = 0;
            highlights = new List<string>();

            for (int i = 0; i < SangreRewards.Length; i++)
            {
                Reward r = SangreRewards[i];
                switch (r.kind)
                {
                    case Kind.Dulces: dulces += r.amount; break;
                    case Kind.Gambits: gambits += r.amount; break;
                    case Kind.Skin:
                    case Kind.Variant:
                    case Kind.Animation:
                    case Kind.Board:
                    case Kind.Backdrop:
                        if (!string.IsNullOrEmpty(r.name)) highlights.Add(r.name);
                        break;
                }
            }
        }

        /// <summary>Texto de la línea de valor: cifra o rareza/categoría del objeto.</summary>
        private static string TagFor(Reward r)
        {
            switch (r.kind)
            {
                case Kind.Gambits: return $"{r.amount:N0}";
                case Kind.Dulces: return $"{r.amount:N0} {HalloweenCurrency.Icon}";
                case Kind.Reroll: return "1 AL DÍA";
                case Kind.Skin:
                    return r.index >= 0 ? RarityLabel(PieceSkinManager.GetSkinRarity(r.index)) : "PIEZA";
                case Kind.Variant: return "VARIANTE";
                case Kind.Animation: return "ANIMACIÓN";
                case Kind.Board: return "TABLERO";
                case Kind.Backdrop: return "FONDO";
                default: return "";
            }
        }

        private static string RarityLabel(SkinRarity rarity)
        {
            switch (rarity)
            {
                case SkinRarity.Common: return "COMÚN";
                case SkinRarity.Uncommon: return "POCO COMÚN";
                case SkinRarity.Rare: return "RARA";
                case SkinRarity.Epic: return "ÉPICA";
                case SkinRarity.Legendary: return "LEGENDARIA";
                case SkinRarity.Mythic: return "MÍTICA";
                default: return "PIEZA";
            }
        }

        // ── Arte de la tarjeta ────────────────────────────────────────────

        private static readonly Dictionary<string, Sprite> ArtCache = new Dictionary<string, Sprite>();

        // Con "Fast Play Mode" los estáticos sobreviven entre Plays: se vacía la caché.
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void ResetArtCache() => ArtCache.Clear();

        /// <summary>
        /// Rutas de arte (StreamingAssets/Pieces) de las variantes de la velada.
        /// Clave = refId de la recompensa; valor = rutas en orden de preferencia.
        /// Política del pase: versión blanca primero (solo visual; el desbloqueo
        /// sirve para blancas y negras).
        /// </summary>
        private static readonly Dictionary<string, string[]> VariantArtPaths =
            new Dictionary<string, string[]>
            {
                { "vampira", new[] { "White/VampireQueen", "Black/VampireQueen" } },
            };

        private static Sprite Wrap(Texture2D tex)
        {
            if (tex == null) return null;
            var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                new Vector2(0.5f, 0.5f), 100f);
            sprite.name = "hw-reward-art";
            return sprite;
        }

        /// <summary>Miniatura del regalo, o null si su categoría no trae arte (cae al emoji).</summary>
        private static Sprite ArtFor(Reward r)
        {
            string key = $"{r.kind}|{r.refId}|{r.index}";
            if (ArtCache.TryGetValue(key, out Sprite cached)) return cached;

            Sprite art = null;
            try
            {
                switch (r.kind)
                {
                    case Kind.Gambits:
                        art = GambitIcon.Sprite;
                        break;
                    case Kind.Reroll:
                        art = RerollIcon.Sprite;
                        break;
                    case Kind.Skin:
                        if (r.index >= 0) art = Wrap(PieceSkinManager.GetSkinThumbnail(r.index));
                        break;
                    case Kind.Variant:
                        art = LoadVariantArt(r.refId);
                        break;
                    case Kind.Animation:
                        art = AnimationArt(r.refId);
                        break;
                    case Kind.Backdrop:
                        if (r.index >= 0) art = Wrap(BackdropManager.LoadThumbnailForIndex(r.index));
                        break;
                    case Kind.Board:
                        if (r.index >= 0) art = Wrap(BoardBackgroundManager.LoadThumbnailForIndex(r.index));
                        break;
                }
            }
            catch (Exception e)
            {
                Debug.LogWarning($"[HalloweenPassModal] Sin arte para «{r.name}»: {e.Message}");
            }

            ArtCache[key] = art;
            return art;
        }

        /// <summary>
        /// Arte de una variante en tiempo de ejecución. Las variantes de la tienda
        /// (Peón Calabaza y Caballo Fantasma) viven en Resources/Pieces/Halloween;
        /// la Reina Vampira y las futuras usan StreamingAssets/Pieces.
        /// </summary>
        private static Sprite LoadVariantArt(string variantId)
        {
            if (string.IsNullOrEmpty(variantId)) return null;

            // Lote de la velada (hwp_*): misma carga que la tienda y el inventario.
            Sprite halloweenArt = HalloweenArt.LoadSprite(HalloweenArt.ArtForVariant(variantId));
            if (halloweenArt != null) return halloweenArt;

            if (VariantArtPaths.TryGetValue(variantId, out string[] paths))
            {
                foreach (string variantPath in paths)
                {
                    Sprite art = LoadVariantArtFile(variantPath);
                    if (art != null) return art;
                }
            }
            // Variante futura sin entrada: intento genérico blanco→negro.
            return LoadVariantArtFile("White/" + variantId)
                ?? LoadVariantArtFile("Black/" + variantId);
        }

        private static Sprite LoadVariantArtFile(string relativePath)
        {
            string path = System.IO.Path.Combine(Application.streamingAssetsPath, "Pieces", relativePath + ".png");
            if (!System.IO.File.Exists(path))
                path = System.IO.Path.Combine(Application.dataPath, "_Project", "Textures", "Pieces", relativePath + ".png");
            if (!System.IO.File.Exists(path))
                path = System.IO.Path.Combine(Application.dataPath, "Resources", "Pieces", relativePath + ".png");
            if (!System.IO.File.Exists(path)) return null;

            byte[] bytes = System.IO.File.ReadAllBytes(path);
            var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
            if (!tex.LoadImage(bytes)) return null;
            return Wrap(tex);
        }

        /// <summary>
        /// Arte de una animación de efecto para su tarjeta del pase. Son las
        /// cuatro FX del juego (las mismas fichas del pase de temporada); si
        /// el id no existe, la tarjeta cae al emoji de respaldo.
        /// </summary>
        private static Sprite AnimationArt(string refId)
        {
            if (refId == DefeatFx.AnimId) return DefeatFx.GetArtSprite();
            if (refId == DoubleCheckFx.AnimId) return DoubleCheckFx.GetArtSprite();
            if (refId == BrilliantFx.AnimId) return BrilliantFx.GetArtSprite();
            if (refId == ForkCometFx.AnimId) return ForkCometFx.GetArtSprite();
            return null;
        }

        // ── Estado persistente (claves propias, por año) ─────────────────
        //
        // La apertura de la Vía Sangre vive en HalloweenLanes: la comparten el
        // camino de niveles, las misiones premium y el modal de misiones.

        private static string ClaimKey(int tier, bool sangre)
            => $"{KeyClaimPrefix}{HalloweenEvent.Year}_{(sangre ? 'S' : 'L')}{tier}";

        private static bool SangreUnlocked => HalloweenLanes.SangreUnlocked;

        private static bool IsClaimed(int tier, bool sangre)
            => PlayerPrefs.GetInt(ClaimKey(tier, sangre), 0) == 1;

        private static void MarkClaimed(int tier, bool sangre)
        {
            PlayerPrefs.SetInt(ClaimKey(tier, sangre), 1);
            PlayerPrefs.Save();
        }

        /// <summary>Niveles cobrados de una vía (para el resumen del cierre).</summary>
        public static int ClaimedCount(bool sangre)
        {
            int n = 0;
            for (int tier = 1; tier <= HalloweenProgress.TierCount; tier++)
                if (IsClaimed(tier, sangre)) n++;
            return n;
        }

        /// <summary>Solo para depuración: abre la Vía Sangre sin gastar Dulces.</summary>
        public static void DebugUnlockSangre() => HalloweenLanes.UnlockSangre();

        /// <summary>Solo para depuración: borra cobros y el estado de la Vía Sangre.</summary>
        public static void DebugReset()
        {
            HalloweenLanes.DebugLockSangre();
            for (int tier = 1; tier <= HalloweenProgress.TierCount; tier++)
            {
                PlayerPrefs.DeleteKey(ClaimKey(tier, false));
                PlayerPrefs.DeleteKey(ClaimKey(tier, true));
            }
            PlayerPrefs.Save();
        }

        // ── UI ────────────────────────────────────────────────────────────

        private VisualElement _root;
        private ScrollView _bodyScroll;      // lista vertical del móvil
        private ScrollView _trackHScroll;    // carril horizontal de escritorio
        private VisualElement _trackH;       // columnas del carril
        private VisualElement _trackV;       // filas de la lista móvil
        private VisualElement _missions;     // misiones, bloque de escritorio
        private VisualElement _missionsMob;  // misiones, bloque del móvil
        private Label _missionsNoteDesk;
        private Label _missionsNoteMob;
        private Label _levelLabel;
        private Label _countLabel;
        private Label _xpLabel;
        private Label _stateChip;
        private Label _dulcesLabel;
        private Label _timerLabel;
        private Label _heroState;
        private Label _laneHintSangre;
        private Button _btnSangre;
        private Button _btnMissions;
        private Label _footerNote;

        /// <summary>Firma del último repintado de la pista: evita rehacer 80 tarjetas por refresco.</summary>
        private int _trackStamp = int.MinValue;

        /// <summary>Firma de la última tanda de misiones pintada.</summary>
        private string _missionsStamp;

        private Action _onClose;
        private Action<bool> _onMissions;
        private Action _onShop;
        private Action<string, string> _onToast;
        private bool _subscribed;

        // Overlay de cobro (misma coreografía que el pase de temporada).
        private VisualElement _claimOverlay;
        private VisualElement _claimCard;
        private VisualElement _claimDetails;
        private Label _claimSparkles;
        private IVisualElementScheduledItem _claimTicker;
        private float _claimStart;
        private bool _claimAnimating;

        private const float ClaimInTime = 0.42f;
        private const float ClaimHoldTime = 1.05f;
        private const float ClaimOutTime = 0.36f;

        // ── Ciclo de vida ─────────────────────────────────────────────────

        /// <summary>Se llama una vez desde MainMenuController tras cargar el UXML.</summary>
        /// <param name="onMissions">
        /// Abre el tablero de misiones; el bool indica si se abre en la pestaña
        /// de la Vía Sangre (true) o en la de la Vía Luna (false).
        /// </param>
        /// <param name="onShop">Abre la tienda de la velada (Dulces) encima del pase.</param>
        public void Initialize(VisualElement root, Action onClose,
            Action<string, string> onToast = null, Action<bool> onMissions = null,
            Action onShop = null)
        {
            _root = root;
            _onClose = onClose;
            _onToast = onToast;
            _onMissions = onMissions;
            _onShop = onShop;
            if (_root == null) return;

            _bodyScroll = _root.Q<ScrollView>("hw-body-scroll");
            _trackHScroll = _root.Q<ScrollView>("hw-track-scroll");
            _trackH = _root.Q<VisualElement>("hw-track-h");
            _trackV = _root.Q<VisualElement>("hw-track-v");
            _missions = _root.Q<VisualElement>("hw-missions-desk");
            _missionsMob = _root.Q<VisualElement>("hw-missions-mob");
            _missionsNoteDesk = _root.Q<Label>("hw-missions-note-desk");
            _missionsNoteMob = _root.Q<Label>("hw-missions-note-mob");
            _levelLabel = _root.Q<Label>("hw-level-label");
            _countLabel = _root.Q<Label>("hw-count-label");
            _xpLabel = _root.Q<Label>("hw-xp-label");
            _stateChip = _root.Q<Label>("hw-state-chip");
            _dulcesLabel = _root.Q<Label>("hw-dulces-label");
            _timerLabel = _root.Q<Label>("hw-timer-label");
            _heroState = _root.Q<Label>("halloween-hero-state");
            _laneHintSangre = _root.Q<Label>("hw-lane-hint-sangre");
            _btnSangre = _root.Q<Button>("btn-halloween-sangre");
            _btnMissions = _root.Q<Button>("btn-halloween-missions");
            _footerNote = _root.Q<Label>("hw-footer-note");

            // Botón «TIENDA» del topbar: abre la tienda de la velada (Dulces)
            // por encima del pase, igual que MISIONES abre su tablero.
            _root.Q<Button>("btn-halloween-shop")?.RegisterCallback<ClickEvent>(_ => OpenShop());

            _root.Q<Button>("btn-close-halloween")?.RegisterCallback<ClickEvent>(_ => Close());
            _root.Q<Button>("btn-close-halloween-foot")?.RegisterCallback<ClickEvent>(_ => Close());
            _btnSangre?.RegisterCallback<ClickEvent>(_ => OnSangreClicked());
            // El botón MISIONES abre el modal de misiones por encima de la velada.
            _btnMissions?.RegisterCallback<ClickEvent>(_ => OpenMissions(false));

            // Flechas del carril: la velada no se recorre entera solo con la rueda.
            _root.Q<Button>("btn-hw-track-prev")?.RegisterCallback<ClickEvent>(_ => ScrollTrack(-1f));
            _root.Q<Button>("btn-hw-track-next")?.RegisterCallback<ClickEvent>(_ => ScrollTrack(1f));

            // Sin scroll vertical en escritorio: el carril se mide y se escala
            // al alto disponible. El centrado pendiente se aplica aquí, con el
            // layout ya resuelto (misma coreografía que el pase de temporada).
            if (_trackHScroll != null)
                _trackHScroll.RegisterCallback<GeometryChangedEvent>(_ =>
                {
                    FitTrack();
                    ApplyPendingTrackScroll();
                });

            if (_trackH == null || _trackV == null)
                Debug.LogWarning("[HalloweenPassModal] Faltan «hw-track-h» o «hw-track-v» en el UXML: el camino de niveles no se pintará.");
        }

        public void OnOpened()
        {
            if (!_subscribed)
            {
                GambitProgress.OnChanged += Refresh;
                _subscribed = true;
            }
            Refresh();
            ScrollToCurrentLevel();
        }

        public void OnClosed()
        {
            HalloweenSangreConfirm.Hide(_root);
            if (_claimAnimating) FinishClaimOverlay();
            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        private void OnDestroy()
        {
            if (_claimAnimating) FinishClaimOverlay();
            if (_subscribed)
            {
                GambitProgress.OnChanged -= Refresh;
                _subscribed = false;
            }
        }

        private void Close()
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            _onClose?.Invoke();
        }

        /// <summary>
        /// Abre el modal de misiones (lo muestra MainMenuController encima de la
        /// velada, así al cerrarlo se vuelve a este mismo pase). El bool elige
        /// la pestaña: false = Vía Luna, true = Vía Sangre.
        /// </summary>
        private void OpenMissions(bool sangre)
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            _onMissions?.Invoke(sangre);
        }

        /// <summary>
        /// Abre la tienda de la velada (la muestra MainMenuController encima de
        /// este pase, así al cerrarla se vuelve aquí mismo).
        /// </summary>
        private void OpenShop()
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            _onShop?.Invoke();
        }

        /// <summary>
        /// Deja el nivel actual a la vista al abrir el pase: centra la columna
        /// en el carril de escritorio o la fila en la lista del móvil.
        /// </summary>
        private void ScrollToCurrentLevel()
        {
            if (HalloweenEvent.CurrentPhase != HalloweenEvent.Phase.Active) return;
            int level = Mathf.Max(1, HalloweenProgress.CurrentLevel);

            if (IsPortraitLayout())
            {
                if (_bodyScroll == null || _trackV == null) return;
                var row = _trackV.Q<VisualElement>($"hw-tier-{level}");
                if (row == null) return;

                _bodyScroll.schedule.Execute(() =>
                {
                    if (_bodyScroll != null && row.parent != null) _bodyScroll.ScrollTo(row);
                }).StartingIn(140);
                return;
            }

            // No se usa ScrollView.ScrollTo: si el panel está sucio cuando se
            // llama, Unity deja un scroll diferido que se re-aplica cada frame
            // y la pista queda clavada en ese nivel. El centrado se fija a mano
            // sobre el Scroller, igual que el resto de la navegación.
            _trackScrollPending = _trackH != null && _trackHScroll != null;
            if (!_trackScrollPending) return;
            _trackH.schedule.Execute(ApplyPendingTrackScroll).StartingIn(60);
        }

        /// <summary>
        /// Aplica el centrado pendiente del carril horizontal. Solo cuando la
        /// pista está escalada y las columnas medidas; si no, vuelve a
        /// intentarlo en el siguiente <c>GeometryChangedEvent</c> del ScrollView.
        /// </summary>
        private void ApplyPendingTrackScroll()
        {
            if (!_trackScrollPending || _trackH == null || _trackHScroll == null) return;
            if (_trackScale <= 0f) return;

            var scroller = _trackHScroll.horizontalScroller;
            var viewport = _trackHScroll.contentViewport;
            if (scroller == null || viewport == null) return;

            int level = Mathf.Max(1, HalloweenProgress.CurrentLevel);
            var target = _trackH.Q<VisualElement>($"hw-col-{level}");
            if (target == null) return;

            Rect view = viewport.worldBound;
            Rect col = target.worldBound;
            if (view.width <= 1f || col.width <= 1f || float.IsNaN(view.x) || float.IsNaN(col.x))
                return;

            // Offset actual + desplazamiento en pantalla hasta centrar la
            // columna: worldBound ya lleva el translate aplicado, así que la
            // diferencia es lo que hay que mover el contenido.
            float want = scroller.value + (col.xMin + col.width * 0.5f) - (view.xMin + view.width * 0.5f);
            scroller.value = Mathf.Clamp(want, scroller.lowValue, scroller.highValue);
            _trackScrollPending = false;
        }

        /// <summary>Desplaza el carril una página (flechas ← →).</summary>
        private void ScrollTrack(float pages)
        {
            if (_trackHScroll == null) return;
            var scroller = _trackHScroll.horizontalScroller;
            if (scroller == null) return;

            float viewport = _trackHScroll.contentViewport != null
                ? _trackHScroll.contentViewport.layout.width
                : 0f;
            float page = Mathf.Max(240f, viewport * 0.8f);
            scroller.value = Mathf.Clamp(scroller.value + page * pages, scroller.lowValue, scroller.highValue);
        }

        /// <summary>Móvil en vertical: la clase la pone UiResponsive en la raíz del panel.</summary>
        private bool IsPortraitLayout()
        {
            for (VisualElement e = _root; e != null; e = e.parent)
                if (e.ClassListContains(UiResponsive.PortraitClass)) return true;
            return false;
        }

        // ── Pintado ───────────────────────────────────────────────────────

        public void Refresh()
        {
            if (_root == null) return;

            var phase = HalloweenEvent.CurrentPhase;
            int xp = HalloweenProgress.Xp;
            int level = HalloweenProgress.LevelFor(xp);

            if (_levelLabel != null) _levelLabel.text = $"NIVEL {level}";
            if (_countLabel != null) _countLabel.text = $"{level}/{HalloweenProgress.TierCount} niveles";
            if (_xpLabel != null) _xpLabel.text = $"{xp:N0} / {HalloweenProgress.MaxXp:N0} XP";
            if (_dulcesLabel != null) _dulcesLabel.text = $"{HalloweenCurrency.Balance:N0}";
            if (_stateChip != null) _stateChip.text = StateChipText(phase);
            if (_timerLabel != null) _timerLabel.text = TimerText(phase);
            if (_heroState != null) _heroState.text = HeroText(phase);
            if (_footerNote != null) _footerNote.text = FooterText(phase);

            RefreshSangreButton(phase);
            RefreshMissionsButton();
            BuildTrack(level, phase);
            BuildMissions(phase);
        }

        /// <summary>Botón MISIONES del topbar: contador de cobros pendientes.</summary>
        private void RefreshMissionsButton()
        {
            if (_btnMissions == null) return;
            int pending = HalloweenMissions.TotalPendingClaims;
            _btnMissions.text = pending > 0 ? $"MISIONES · {pending}" : "MISIONES";
            _btnMissions.EnableInClassList("hw-missions-btn-ready", pending > 0);
        }

        private static string StateChipText(HalloweenEvent.Phase phase)
        {
            switch (phase)
            {
                case HalloweenEvent.Phase.NotStarted: return "PRÓXIMAMENTE";
                case HalloweenEvent.Phase.Active: return "¡ACTIVO!";
                default: return "TERMINADO";
            }
        }

        private string TimerText(HalloweenEvent.Phase phase)
        {
            switch (phase)
            {
                case HalloweenEvent.Phase.NotStarted:
                    return $"{HalloweenEvent.TimeTextNow.ToUpperInvariant()} · LAS MISIONES SE ENCIENDEN ESE DÍA";
                case HalloweenEvent.Phase.Active:
                    return HalloweenEvent.TimeTextNow.ToUpperInvariant();
                default:
                    return $"Cobraste {ClaimedCount(false)}/{HalloweenProgress.TierCount} niveles de la Vía Luna"
                         + $" y {ClaimedCount(true)}/{HalloweenProgress.TierCount} de la Vía Sangre"
                         + $" · {HalloweenCurrency.Balance:N0} {HalloweenCurrency.Label} te esperan en la tienda de la velada";
            }
        }

        private static string HeroText(HalloweenEvent.Phase phase)
        {
            switch (phase)
            {
                case HalloweenEvent.Phase.NotStarted: return $"PRÓXIMAMENTE · ABRE EL {HalloweenEvent.Start:dd/MM}";
                case HalloweenEvent.Phase.Active: return "¡LA VELADA ESTÁ ABIERTA!";
                default: return "LAS PUERTAS SE CERRARON";
            }
        }

        private static string FooterText(HalloweenEvent.Phase phase)
        {
            switch (phase)
            {
                case HalloweenEvent.Phase.NotStarted:
                    return "Dieciséis noches de XP, misiones y Dulces. Todo lo que se cobre, al instante.";
                case HalloweenEvent.Phase.Active:
                    return "Gana XP jugando y con las misiones de la velada (botón MISIONES): cada nivel se cobra al instante.";
                default:
                    return "La velada terminó. Los niveles sin cobrar quedaron a oscuras.";
            }
        }

        private void RefreshSangreButton(HalloweenEvent.Phase phase)
        {
            if (SangreUnlocked)
            {
                if (_btnSangre != null)
                {
                    _btnSangre.text = "✓ VÍA SANGRE ACTIVA";
                    _btnSangre.SetEnabled(false);
                }
                if (_laneHintSangre != null)
                    _laneHintSangre.text = "ABIERTA · COBRA LO QUE YA GANASTE EN LAS DOS VÍAS";
                return;
            }

            switch (phase)
            {
                case HalloweenEvent.Phase.NotStarted:
                    if (_btnSangre != null)
                    {
                        _btnSangre.text = $"VÍA SANGRE · SE ABRE EL {HalloweenEvent.Start:dd/MM} · {HalloweenCurrency.Icon} {SangreUnlockCost}";
                        _btnSangre.SetEnabled(false);
                    }
                    if (_laneHintSangre != null)
                        _laneHintSangre.text = $"SE ABRE CON LA VELADA · {HalloweenCurrency.Icon} {SangreUnlockCost} DULCES DE ENTRADA";
                    break;
                case HalloweenEvent.Phase.Active:
                    if (_btnSangre != null)
                    {
                        _btnSangre.text = $"ABRIR VÍA SANGRE · {HalloweenCurrency.Icon} {SangreUnlockCost}";
                        _btnSangre.SetEnabled(true);
                    }
                    if (_laneHintSangre != null)
                        _laneHintSangre.text = $"SE ABRE CON {HalloweenCurrency.Icon} {SangreUnlockCost} DULCES DE LA VELADA";
                    break;
                default:
                    if (_btnSangre != null)
                    {
                        _btnSangre.text = "VÍA SANGRE · CERRADA";
                        _btnSangre.SetEnabled(false);
                    }
                    if (_laneHintSangre != null)
                        _laneHintSangre.text = "SE ABRE CON DULCES DE LA VELADA · LA VELADA TERMINÓ";
                    break;
            }
        }

        // ── Camino de niveles: carril horizontal (escritorio) y lista
        //    vertical (móvil). El UXML trae los dos y el USS muestra el que
        //    toca según .is-portrait, así que ambos se pinta siempre. ──────

        private void BuildTrack(int level, HalloweenEvent.Phase phase)
        {
            if (_trackH == null && _trackV == null) return;

            int stamp = ComputeTrackStamp(level, phase);
            if (stamp == _trackStamp) return;
            _trackStamp = stamp;

            _trackH?.Clear();
            _trackV?.Clear();
            // Las cartas nuevas nacen con las medidas del USS (k = 1): hay que
            // volver a aplicar la escala vigente cuando el carril se repinte.
            _trackScale = 0f;

            for (int tier = 1; tier <= HalloweenProgress.TierCount; tier++)
            {
                _trackH?.Add(BuildColumn(tier, level, phase));
                _trackV?.Add(BuildTierRow(tier, level, phase));
            }

            FitTrack();
        }

        private int ComputeTrackStamp(int level, HalloweenEvent.Phase phase)
        {
            unchecked
            {
                int stamp = 17;
                stamp = stamp * 31 + (int)phase;
                stamp = stamp * 31 + level;
                stamp = stamp * 31 + (SangreUnlocked ? 1 : 0);
                for (int tier = 1; tier <= HalloweenProgress.TierCount; tier++)
                {
                    stamp = stamp * 31 + (IsClaimed(tier, false) ? 1 : 0);
                    stamp = stamp * 31 + (IsClaimed(tier, true) ? 1 : 0);
                }
                return stamp;
            }
        }

        // ── Carril horizontal: columna por nivel, estilo pase de temporada ──

        /// <summary>
        /// Columna de nivel: carta Luna arriba, tick vertical, nudo (media-línea
        /// + medallón SOBRE la barra + media-línea), tick vertical y carta Sangre
        /// abajo. Todo centrado en la columna y con las columnas pegadas para que
        /// la barra quede continua pasando por todos los medallones.
        /// </summary>
        private VisualElement BuildColumn(int tier, int level, HalloweenEvent.Phase phase)
        {
            bool reached = level >= tier;

            var col = new VisualElement { name = $"hw-col-{tier}" };
            col.AddToClassList("hw-col");
            if (reached) col.AddToClassList("hw-col-on");

            col.Add(BuildTallCard(tier, false, level, phase));
            col.Add(BuildTick(reached));
            col.Add(BuildNode(tier, level, reached));
            col.Add(BuildTick(reached));
            col.Add(BuildTallCard(tier, true, level, phase));
            return col;
        }

        /// <summary>Línea vertical que une cada carta con la barra central.</summary>
        private static VisualElement BuildTick(bool done)
        {
            var tick = new VisualElement();
            tick.AddToClassList("hw-tick");
            if (done) tick.AddToClassList("hw-tick-done");
            tick.pickingMode = PickingMode.Ignore;
            return tick;
        }

        /// <summary>Nudo sobre la barra: la línea continua pasa por el medallón.</summary>
        private VisualElement BuildNode(int tier, int level, bool reached)
        {
            var node = new VisualElement();
            node.AddToClassList("hw-node");
            node.pickingMode = PickingMode.Ignore;

            var lineL = new VisualElement();
            lineL.AddToClassList("hw-node-line");
            if (reached) lineL.AddToClassList("hw-node-line-done");
            if (tier == 1) lineL.AddToClassList("hw-node-line-hidden");
            node.Add(lineL);

            // El ✓ marca COBRO REAL (persistido) en cualquiera de las dos vías,
            // no que el nivel esté desbloqueado: el XP puede bajar y el nivel
            // caerse, pero lo cobrado sigue cobrado.
            var medal = new VisualElement();
            medal.AddToClassList("hw-medal-lg");
            if (reached) medal.AddToClassList("hw-medal-lg-on");
            // El medallón usa el mismo sprite que el pase de temporada
            // (seasonpass_tier.png por USS + respaldo por código).
            SeasonPassSprites.Apply(medal, SeasonPassSprites.Tier);

            var num = new Label(tier.ToString("00"));
            num.AddToClassList("hw-medal-lg-num");
            num.pickingMode = PickingMode.Ignore;
            medal.Add(num);

            bool claimed = IsClaimed(tier, false) || IsClaimed(tier, true);
            if (claimed)
            {
                var check = new Label("✓");
                check.AddToClassList("hw-medal-lg-check");
                check.pickingMode = PickingMode.Ignore;
                medal.Add(check);
            }

            medal.tooltip = claimed ? $"Nivel {tier} cobrado"
                : reached ? $"Nivel {tier} desbloqueado"
                : $"Nivel {tier} · te faltan {(tier * HalloweenProgress.XpPerTier - HalloweenProgress.Xp):N0} XP";
            node.Add(medal);

            var lineR = new VisualElement();
            lineR.AddToClassList("hw-node-line");
            if (level > tier) lineR.AddToClassList("hw-node-line-done");
            if (tier == HalloweenProgress.TierCount) lineR.AddToClassList("hw-node-line-hidden");
            node.Add(lineR);

            return node;
        }

        /// <summary>Carta del carril de escritorio: arte, nombre, valor y cobro.</summary>
        private VisualElement BuildTallCard(int tier, bool sangre, int level, HalloweenEvent.Phase phase)
        {
            Reward r = RewardAt(tier, sangre);
            bool claimed = IsClaimed(tier, sangre);
            bool reached = level >= tier;
            bool unlocked = !sangre || SangreUnlocked;

            var card = new VisualElement();
            card.AddToClassList("hw-rw");
            card.AddToClassList(sangre ? "hw-rw-sangre" : "hw-rw-free");
            if (claimed) card.AddToClassList("hw-rw-claimed");
            else if (!reached || !unlocked) card.AddToClassList("hw-rw-locked");
            else card.AddToClassList("hw-rw-ready");

            // El fondo (marco del slot) viene del USS; respaldo por código: los
            // mismos marcos del pase de temporada (Luna → básico, Sangre → premium).
            SeasonPassSprites.Apply(card, sangre ? SeasonPassSprites.SlotPremium : SeasonPassSprites.SlotBasic);

            // Arte del objeto si su categoría trae miniatura; si no, el emoji.
            Sprite art = ArtFor(r);
            if (art != null)
            {
                var artBox = new VisualElement();
                artBox.AddToClassList("hw-rw-art");
                artBox.style.backgroundImage = new StyleBackground(art);
                artBox.pickingMode = PickingMode.Ignore;
                card.Add(artBox);
            }
            else
            {
                var icon = new Label(r.icon);
                icon.AddToClassList("hw-rw-icon");
                icon.pickingMode = PickingMode.Ignore;
                card.Add(icon);
            }

            var name = new Label(r.name.ToUpperInvariant());
            name.AddToClassList("hw-rw-name");
            name.pickingMode = PickingMode.Ignore;
            card.Add(name);

            var amount = new Label(TagFor(r));
            amount.AddToClassList("hw-rw-amount");
            // Cuando el regalo es un objeto, la línea dice categoría/rareza en
            // vez de una cifra: se tiñe para que no parezca un precio.
            if (r.kind != Kind.Gambits && r.kind != Kind.Dulces)
                amount.AddToClassList("hw-rw-amount-tag");
            amount.pickingMode = PickingMode.Ignore;
            card.Add(amount);

            AddClaimControl(card, tier, sangre, r, claimed, reached, unlocked, phase, "hw-claim");

            card.tooltip = $"{r.name} · {TagFor(r)} · Nivel {tier} · {(sangre ? "Vía Sangre" : "Vía Luna")}";
            return card;
        }

        // ── Lista vertical del móvil: fila por nivel ──────────────────────

        private VisualElement BuildTierRow(int tier, int level, HalloweenEvent.Phase phase)
        {
            var row = new VisualElement();
            row.name = $"hw-tier-{tier}";
            row.AddToClassList("hw-row");

            bool reached = level >= tier;

            var medal = new VisualElement();
            medal.AddToClassList("hw-medal");
            if (reached) medal.AddToClassList("hw-medal-on");
            var num = new Label(tier.ToString("00"));
            num.AddToClassList("hw-medal-num");
            medal.Add(num);
            row.Add(medal);

            row.Add(BuildCard(tier, false, level, phase));
            row.Add(BuildCard(tier, true, level, phase));
            return row;
        }

        private VisualElement BuildCard(int tier, bool sangre, int level, HalloweenEvent.Phase phase)
        {
            Reward r = RewardAt(tier, sangre);
            bool claimed = IsClaimed(tier, sangre);
            bool reached = level >= tier;
            bool unlocked = !sangre || SangreUnlocked;

            var card = new VisualElement();
            card.AddToClassList("hw-card");
            card.AddToClassList(sangre ? "hw-card-sangre" : "hw-card-free");
            if (claimed) card.AddToClassList("hw-card-claimed");
            else if (!reached || !unlocked) card.AddToClassList("hw-card-locked");
            else card.AddToClassList("hw-card-ready");

            // Icono o miniatura del regalo.
            Sprite art = ArtFor(r);
            if (art != null)
            {
                var artBox = new VisualElement();
                artBox.AddToClassList("hw-card-art");
                artBox.style.backgroundImage = new StyleBackground(art);
                card.Add(artBox);
            }
            else
            {
                var icon = new Label(r.icon);
                icon.AddToClassList("hw-card-icon");
                card.Add(icon);
            }

            var info = new VisualElement();
            info.AddToClassList("hw-card-info");

            var lane = new Label(sangre ? "VÍA SANGRE" : "VÍA LUNA");
            lane.AddToClassList("hw-card-lane");
            lane.AddToClassList(sangre ? "hw-lane-sangre" : "hw-lane-free");
            info.Add(lane);

            var name = new Label(r.name);
            name.AddToClassList("hw-card-name");
            info.Add(name);

            var amount = new Label(TagFor(r));
            amount.AddToClassList("hw-card-amount");
            info.Add(amount);

            card.Add(info);

            AddClaimControl(card, tier, sangre, r, claimed, reached, unlocked, phase, "hw-pill");

            card.tooltip = $"{r.name} · {TagFor(r)} · Nivel {tier} · {(sangre ? "Vía Sangre" : "Vía Luna")}";
            return card;
        }

        /// <summary>
        /// Cobro o chapa de estado de una carta. La misma lógica sirve a la
        /// carta del carril (hw-claim) y a la de la lista del móvil (hw-pill):
        /// solo cambia la clase base que la pinta.
        /// </summary>
        private void AddClaimControl(VisualElement card, int tier, bool sangre, Reward r,
            bool claimed, bool reached, bool unlocked, HalloweenEvent.Phase phase, string baseClass)
        {
            if (claimed)
            {
                card.Add(StatusPill("✓ COBRADO", baseClass, "hw-pill-done"));
            }
            else if (!unlocked)
            {
                card.Add(StatusPill($"🔒 {HalloweenCurrency.Icon} {SangreUnlockCost}", baseClass, "hw-pill-locked"));
            }
            else if (!reached)
            {
                card.Add(StatusPill($"NIVEL {tier:00}", baseClass, "hw-pill-locked"));
            }
            else if (phase != HalloweenEvent.Phase.Active)
            {
                card.Add(StatusPill(
                    phase == HalloweenEvent.Phase.NotStarted ? "PRÓXIMAMENTE" : "CERRADO",
                    baseClass, "hw-pill-locked"));
            }
            else
            {
                var btn = new Button(() => OnClaim(tier, sangre, r)) { text = "COBRAR" };
                btn.AddToClassList(baseClass);
                btn.AddToClassList("hw-pill-ready");
                btn.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
                card.Add(btn);
            }
        }

        private static Label StatusPill(string text, string baseClass, string stateClass)
        {
            var pill = new Label(text);
            pill.AddToClassList(baseClass);
            pill.AddToClassList(stateClass);
            pill.pickingMode = PickingMode.Ignore;
            return pill;
        }

        // ── Escala del carril: SIN scroll vertical en escritorio ────────
        //
        // El cuerpo de escritorio es una columna fija (misiones + banners +
        // carril) y no scrollea en vertical: para que las dos vías quepan
        // siempre, el carril se mide y se escala, igual que el pase de
        // temporada. Las medidas de abajo son el valor de diseño (k = 1) y se
        // multiplican por k = viewport / StackHeight. El ancho escala con el
        // alto para conservar la proporción de la columna.

        private const float DesignPadTop = 16f;
        private const float DesignPadBottom = 16f;
        private const float DesignCardMargin = 10f;
        private const float DesignTickH = 18f;
        private const float DesignTickW = 3f;
        private const float DesignLineH = 5f;
        private const float DesignMedal = 112f;
        /// <summary>Ancho derivado del marco de temporada (reward_slot_*:
        /// 300×276): misma proporción para que la ventana del PNG caiga justo
        /// donde el relleno la espera (≈228,3).</summary>
        private const float DesignCardW = DesignCardH * (300f / 276f);
        private const float DesignCardH = 210f;
        private const float DesignColW = 292f;

        // Ventana interior de los marcos de temporada escalada a la carta
        // (básico: 16/25 y 24 de temporada; premium: corona 56/26 y 35). Se
        // multiplican por k para que la carta sea copia fiel a cualquier
        // escala; si no, el texto se queda a tamaño fijo y se sale del hueco.
        private const float DesignBasicPadTop = DesignCardH * (16f / 276f);
        private const float DesignBasicPadBottom = DesignCardH * (25f / 276f);
        private const float DesignBasicPadSide = DesignCardW * (24f / 300f);
        private const float DesignPremiumPadTop = DesignCardH * (56f / 276f);
        private const float DesignPremiumPadBottom = DesignCardH * (26f / 276f);
        private const float DesignPremiumPadSide = DesignCardW * (35f / 300f);
        private const float DesignArtH = 70f;
        private const float DesignArtIcon = 54f;
        private const float DesignArtGap = 4f;
        private const float DesignNameFont = 14f;
        private const float DesignNameH = 18f;
        private const float DesignAmountFont = 16f;
        private const float DesignAmountH = 20f;
        private const float DesignClaimH = 26f;
        private const float DesignClaimFont = 12f;
        private const float DesignClaimGap = 4f;
        private const float DesignClaimPadX = 14f;
        private const float DesignMedalFont = 30f;
        // Centro del vidrio del medallón ≈57% del PNG (corona arriba): mismo
        // offset proporcional que el pase de temporada (18 px sobre 128).
        private const float DesignMedalNumOffset = DesignMedal * (18f / 128f);
        private const float DesignCheck = 24f;
        private const float DesignCheckFont = 13f;
        private const float DesignCheckOffset = 7f;

        /// <summary>Alto de la columna completa a escala 1: 620px.</summary>
        private const float StackHeight =
            DesignPadTop + DesignPadBottom + DesignMedal
            + 2f * (DesignCardMargin + DesignTickH + DesignCardH);

        /// <summary>Nunca por debajo del 55%: es el mínimo legible del interior.</summary>
        private const float MinScale = 0.55f;

        /// <summary>Escala aplicada la última vez (0 = pendiente de pintar).</summary>
        private float _trackScale;

        /// <summary>Queda un centrado del carril por aplicar (layout pendiente).</summary>
        private bool _trackScrollPending;

        /// <summary>
        /// Ajusta el carril al alto disponible. Se dispara con la geometría del
        /// ScrollView (primer layout y redimensionado) y tras cada repintado.
        /// Si la escala no cambia, no toca nada. En móvil vertical el carril
        /// está oculto (viewport de 0) y no hay nada que escalar.
        /// </summary>
        private void FitTrack()
        {
            if (_trackH == null || _trackHScroll == null) return;
            var viewport = _trackHScroll.contentViewport;
            if (viewport == null) return;

            float avail = viewport.layout.height;
            if (avail <= 1f) return;

            float k = Mathf.Clamp(avail / StackHeight, MinScale, 1f);
            if (Mathf.Abs(k - _trackScale) < 0.005f) return;
            _trackScale = k;

            _trackH.style.paddingTop = DesignPadTop * k;
            _trackH.style.paddingBottom = DesignPadBottom * k;

            float medal = DesignMedal * k;
            float check = DesignCheck * k;

            foreach (var col in _trackH.Children())
            {
                col.style.width = DesignColW * k;

                foreach (var el in col.Children())
                {
                    if (el.ClassListContains("hw-rw"))
                    {
                        bool premium = el.ClassListContains("hw-rw-sangre");
                        el.style.width = DesignCardW * k;
                        el.style.height = DesignCardH * k;
                        el.style.marginTop = DesignCardMargin * k;
                        el.style.paddingTop = (premium ? DesignPremiumPadTop : DesignBasicPadTop) * k;
                        el.style.paddingBottom = (premium ? DesignPremiumPadBottom : DesignBasicPadBottom) * k;
                        el.style.paddingLeft = (premium ? DesignPremiumPadSide : DesignBasicPadSide) * k;
                        el.style.paddingRight = el.style.paddingLeft;
                        ScaleCardInterior(el, k);
                    }
                    else if (el.ClassListContains("hw-tick"))
                    {
                        el.style.height = DesignTickH * k;
                        el.style.width = DesignTickW * k;
                    }
                    else if (el.ClassListContains("hw-node"))
                    {
                        el.style.height = medal;
                        foreach (var part in el.Children())
                        {
                            if (part.ClassListContains("hw-node-line"))
                            {
                                part.style.height = DesignLineH * k;
                                continue;
                            }
                            if (!part.ClassListContains("hw-medal-lg")) continue;
                            part.style.width = medal;
                            part.style.height = medal;
                            foreach (var inner in part.Children())
                            {
                                if (inner.ClassListContains("hw-medal-lg-num"))
                                {
                                    inner.style.fontSize = DesignMedalFont * k;
                                    inner.style.marginTop = DesignMedalNumOffset * k;
                                }
                                else if (inner.ClassListContains("hw-medal-lg-check"))
                                {
                                    inner.style.width = check;
                                    inner.style.height = check;
                                    inner.style.right = DesignCheckOffset * k;
                                    inner.style.bottom = DesignCheckOffset * k;
                                    inner.style.fontSize = DesignCheckFont * k;
                                    inner.style.borderTopLeftRadius = check * 0.5f;
                                    inner.style.borderTopRightRadius = check * 0.5f;
                                    inner.style.borderBottomLeftRadius = check * 0.5f;
                                    inner.style.borderBottomRightRadius = check * 0.5f;
                                }
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Escala el interior de una carta (arte, nombre, valor y píldora) con
        /// la misma k que la caja: a k = 0,7 el texto mide 0,7 de su tamaño de
        /// diseño, así la carta es una copia fiel y nada se sale de la caja.
        /// </summary>
        private static void ScaleCardInterior(VisualElement card, float k)
        {
            foreach (var child in card.Children())
            {
                if (child.ClassListContains("hw-rw-art"))
                {
                    child.style.height = DesignArtH * k;
                    child.style.marginBottom = DesignArtGap * k;
                }
                else if (child.ClassListContains("hw-rw-icon"))
                {
                    child.style.fontSize = DesignArtIcon * k;
                    child.style.height = DesignArtH * k;
                    child.style.marginBottom = DesignArtGap * k;
                }
                else if (child.ClassListContains("hw-rw-name"))
                {
                    child.style.fontSize = DesignNameFont * k;
                    child.style.height = DesignNameH * k;
                }
                else if (child.ClassListContains("hw-rw-amount"))
                {
                    bool tag = child.ClassListContains("hw-rw-amount-tag");
                    child.style.fontSize = (tag ? DesignAmountFont * 0.72f : DesignAmountFont) * k;
                    child.style.height = DesignAmountH * k;
                }
                else if (child.ClassListContains("hw-claim"))
                {
                    float h = DesignClaimH * k;
                    child.style.fontSize = DesignClaimFont * k;
                    child.style.height = h;
                    child.style.marginTop = DesignClaimGap * k;
                    child.style.paddingLeft = DesignClaimPadX * k;
                    child.style.paddingRight = DesignClaimPadX * k;
                    child.style.borderTopLeftRadius = h * 0.5f;
                    child.style.borderTopRightRadius = h * 0.5f;
                    child.style.borderBottomLeftRadius = h * 0.5f;
                    child.style.borderBottomRightRadius = h * 0.5f;
                }
            }
        }

        // ── Cobro de niveles ──────────────────────────────────────────────

        private void OnClaim(int tier, bool sangre, Reward reward)
        {
            if (_claimAnimating) return;
            if (HalloweenEvent.CurrentPhase != HalloweenEvent.Phase.Active) return;
            if (HalloweenProgress.CurrentLevel < tier) return;
            if (sangre && !SangreUnlocked) return;
            if (IsClaimed(tier, sangre)) return;

            if (!TryGrant(reward, tier, sangre, out string detail))
            {
                _onToast?.Invoke($"Nivel {tier} sin cobrar", detail ?? "El premio no está disponible ahora");
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                return;
            }

            MarkClaimed(tier, sangre);
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            GambitProgress.NotifyChanged(); // repinta la pista vía la suscripción a OnChanged
            ShowClaimOverlay(reward, tier, sangre, detail);
        }

        /// <summary>
        /// Entrega el premio y verifica que quedó en posesión del jugador. Devuelve
        /// false si no se pudo completar: entonces el nivel NO se consume.
        /// Los Gambits de la velada usan la fuente HalloweenPass con bypassCaps.
        /// </summary>
        private bool TryGrant(Reward r, int tier, bool sangre, out string detail)
        {
            detail = null;
            string where = $"Velada N{tier} {(sangre ? "Sangre" : "Luna")}";
            string onFail = $"{r.name} · no se pudo desbloquear; vuelve a intentarlo";

            switch (r.kind)
            {
                case Kind.Gambits:
                {
                    if (r.amount <= 0)
                    {
                        detail = "Recompensa vacía";
                        return false;
                    }
                    GambitPayout payout;
                    try
                    {
                        payout = GambitEconomy.Earn(r.amount, GambitSource.HalloweenPass,
                            meta: "halloween_pass", note: where, bypassCaps: true);
                    }
                    catch (Exception e)
                    {
                        Debug.LogWarning($"[HalloweenPassModal] No se pudo abonar la recompensa: {e.Message}");
                        detail = onFail;
                        return false;
                    }
                    if (payout.granted < r.amount)
                    {
                        detail = payout.limitReason != null ? $"{payout.limitReason} · vuelve a intentarlo" : onFail;
                        return false;
                    }
                    detail = $"{r.amount:N0} Gambits · velada de Halloween";
                    return true;
                }

                case Kind.Dulces:
                {
                    if (r.amount <= 0)
                    {
                        detail = "Recompensa vacía";
                        return false;
                    }
                    HalloweenCurrency.Earn(r.amount, where);
                    detail = $"{r.amount:N0} {HalloweenCurrency.Label} · moneda de la velada";
                    return true;
                }

                case Kind.Reroll:
                    if (!DailyMissions.CanReroll)
                    {
                        detail = "Ya usaste el cambio de hoy: vuelve mañana";
                        return false;
                    }
                    for (int slot = 0; slot < DailyMissions.Slots; slot++)
                    {
                        if (DailyMissions.Reroll(slot))
                        {
                            detail = "Misión diaria cambiada";
                            return true;
                        }
                    }
                    detail = "No hay misiones que cambiar";
                    return false;

                case Kind.Skin:
                {
                    // El índice de la tabla se resuelve al cargar; si el catálogo
                    // cambió, se vuelve a buscar por id antes de rendirse.
                    int idx = string.IsNullOrEmpty(r.refId) ? -1 : PieceSkinManager.GetIndexById(r.refId);
                    if (idx < 0) idx = r.index;
                    if (idx < 0)
                    {
                        Debug.LogWarning($"[HalloweenPassModal] Skin «{r.refId}» no está en el catálogo.");
                        detail = onFail;
                        return false;
                    }
                    if (PieceSkinManager.IsOwned(idx))
                    {
                        detail = $"{r.name} · ya la tenías";
                        return true;
                    }
                    PieceSkinManager.OwnSkin(idx);
                    if (!PieceSkinManager.IsOwned(idx))
                    {
                        Debug.LogError($"[HalloweenPassModal] OwnSkin no quedó persistido para «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · pieza esculpida desbloqueada";
                    return true;
                }

                case Kind.Variant:
                {
                    bool verified;
                    switch (r.refId)
                    {
                        case "vampira":
                            if (PieceLoadoutManager.IsVampireOwned()) { detail = $"{r.name} · ya la tenías"; return true; }
                            PieceLoadoutManager.OwnVampire();
                            verified = PieceLoadoutManager.IsVampireOwned();
                            break;
                        case HalloweenArt.PumpkinPawnId:
                        case HalloweenArt.GhostKnightId:
                            if (HalloweenShop.IsVariantOwned(r.refId)) { detail = $"{r.name} · ya la tenías"; return true; }
                            verified = HalloweenShop.GrantVariant(r.refId);
                            break;
                        default:
                            Debug.LogWarning($"[HalloweenPassModal] Variante desconocida «{r.refId}».");
                            detail = onFail;
                            return false;
                    }
                    if (!verified)
                    {
                        Debug.LogError($"[HalloweenPassModal] Own no quedó persistido para «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    GambitProgress.SyncVariantsOwned();
                    detail = $"{r.name} · variante desbloqueada";
                    return true;
                }

                case Kind.Animation:
                {
                    // Own() y no OwnAndEquip(): regalar una animación no debe
                    // pisar la que el jugador ya tenga equipada.
                    bool owned, verified;
                    if (r.refId == DefeatFx.AnimId)
                    {
                        owned = DefeatFx.IsOwned();
                        if (!owned) DefeatFx.Own();
                        verified = DefeatFx.IsOwned();
                    }
                    else if (r.refId == DoubleCheckFx.AnimId)
                    {
                        owned = DoubleCheckFx.IsOwned();
                        if (!owned) DoubleCheckFx.Own();
                        verified = DoubleCheckFx.IsOwned();
                    }
                    else if (r.refId == BrilliantFx.AnimId)
                    {
                        owned = BrilliantFx.IsOwned();
                        if (!owned) BrilliantFx.Own();
                        verified = BrilliantFx.IsOwned();
                    }
                    else if (r.refId == ForkCometFx.AnimId)
                    {
                        owned = ForkCometFx.IsOwned();
                        if (!owned) ForkCometFx.Own();
                        verified = ForkCometFx.IsOwned();
                    }
                    else
                    {
                        Debug.LogWarning($"[HalloweenPassModal] Animación desconocida «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    if (owned)
                    {
                        detail = $"{r.name} · ya la tenías";
                        return true;
                    }
                    if (!verified)
                    {
                        Debug.LogError($"[HalloweenPassModal] Own() no quedó persistido para «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · animación desbloqueada";
                    return true;
                }

                case Kind.Backdrop:
                {
                    if (r.index < 0 || r.index >= BackdropManager.ThemeCount)
                    {
                        detail = onFail;
                        return false;
                    }
                    if (BackdropManager.IsUnlocked(r.index))
                    {
                        detail = $"{r.name} · ya lo tenías";
                        return true;
                    }
                    BackdropManager.Unlock(r.index);
                    if (!BackdropManager.IsUnlocked(r.index))
                    {
                        Debug.LogError($"[HalloweenPassModal] Unlock no quedó persistido para fondo #{r.index}.");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · fondo desbloqueado";
                    return true;
                }

                case Kind.Board:
                {
                    if (r.index < 0 || r.index >= BoardBackgroundManager.ThemeCount)
                    {
                        detail = onFail;
                        return false;
                    }
                    if (BoardBackgroundManager.IsUnlocked(r.index))
                    {
                        detail = $"{r.name} · ya lo tenías";
                        return true;
                    }
                    BoardBackgroundManager.Unlock(r.index);
                    if (!BoardBackgroundManager.IsUnlocked(r.index))
                    {
                        Debug.LogError($"[HalloweenPassModal] Unlock no quedó persistido para tablero #{r.index}.");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · tablero desbloqueado";
                    return true;
                }

                default:
                    detail = onFail;
                    return false;
            }
        }

        // ── Vía Sangre (se abre con Dulces) ───────────────────────────────

        private void OnSangreClicked()
        {
            if (_claimAnimating || SangreUnlocked) return;

            var phase = HalloweenEvent.CurrentPhase;
            if (phase != HalloweenEvent.Phase.Active)
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                _onToast?.Invoke("Vía Sangre", phase == HalloweenEvent.Phase.NotStarted
                    ? $"Se abre con la velada · el {HalloweenEvent.Start:dd/MM}"
                    : "La velada terminó: la vía quedó cerrada");
                return;
            }

            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            HalloweenSangreConfirm.Show(_root, BuySangre);
        }

        /// <summary>Compra confirmada desde el overlay (ver HalloweenSangreConfirm).</summary>
        private void BuySangre()
        {
            if (SangreUnlocked) return;

            if (!HalloweenLanes.TryBuySangre())
            {
                _onToast?.Invoke("Faltan Dulces",
                    $"Cuesta {SangreUnlockCost} {HalloweenCurrency.Icon} y tienes {HalloweenCurrency.Balance:N0} · se ganan en las misiones y en los pases");
                return;
            }

            GambitProgress.NotifyChanged();
            _onToast?.Invoke("Vía Sangre abierta",
                $"Los niveles que ya ganaste te esperan y las misiones premium quedan disponibles · {HalloweenCurrency.Icon} {HalloweenCurrency.Balance:N0} restantes");
        }

        // ── Misiones de la velada: resumen que abre el modal ──────────────
        //
        // El detalle (progreso jugada a jugada, cobros y las exclusivas de la
        // Vía Sangre) vive en HalloweenMissionsModal. Aquí queda el estado de
        // un vistazo: tres fichas —Luna, Sangre libre y Sangre premium— que
        // abren el modal al tocarlas. Ambas se pintan siempre porque el USS
        // muestra una u otra según .is-portrait.

        private void BuildMissions(HalloweenEvent.Phase phase)
        {
            if (_missions == null && _missionsMob == null) return;

            string stamp = MissionsStamp(phase);
            if (stamp == _missionsStamp) return;
            _missionsStamp = stamp;

            _missions?.Clear();
            _missionsMob?.Clear();

            FillMissionSummaries(_missions, phase, mobile: false);
            FillMissionSummaries(_missionsMob, phase, mobile: true);

            string hints;
            switch (phase)
            {
                case HalloweenEvent.Phase.NotStarted:
                    hints = $"Se encienden el {HalloweenEvent.Start:dd/MM} · abre el tablero completo";
                    break;
                case HalloweenEvent.Phase.Active:
                    hints = $"Hoy {HalloweenMissions.CompletedCount}/{HalloweenMissions.Slots}"
                          + $" · nuevas en {HalloweenMissions.TimeToResetText()}"
                          + $" · {HalloweenMissions.TotalPendingClaims} por cobrar";
                    break;
                default:
                    hints = "La velada terminó: las misiones descansan hasta el próximo octubre";
                    break;
            }
            if (_missionsNoteDesk != null) _missionsNoteDesk.text = hints;
            if (_missionsNoteMob != null) _missionsNoteMob.text = hints;
        }

        /// <summary>
        /// Reparte las tres fichas de resumen en su contenedor (escritorio y
        /// móvil pintan el mismo juego; solo cambia el rótulo de Luna).
        /// </summary>
        private void FillMissionSummaries(VisualElement host, HalloweenEvent.Phase phase, bool mobile)
        {
            if (host == null) return;

            host.Add(BuildMissionSummary(phase, HalloweenMissions.Slots,
                HalloweenMissions.CompletedCount, HalloweenMissions.PendingClaimsCount,
                "🌙", mobile ? "VÍA LUNA · HOY" : "VÍA LUNA", "hw-msum-luna", false,
                $"3 de un pool de {HalloweenMissions.LunaPoolCount}"));

            host.Add(BuildMissionSummary(phase, HalloweenMissions.SangreFreeSlots,
                HalloweenMissions.SangreCompletedCount(false),
                HalloweenMissions.SangrePendingCount(false),
                "🩸", "SANGRE LIBRE", "hw-msum-sangre", true,
                $"5 de un fondo de {HalloweenMissions.SangreFreePoolCount}"));

            host.Add(BuildMissionSummary(phase, HalloweenMissions.SangrePaidSlots,
                HalloweenMissions.SangreCompletedCount(true),
                HalloweenMissions.SangrePendingCount(true),
                HalloweenLanes.SangreUnlocked ? "🩸" : "🔒", "SANGRE PREMIUM", "hw-msum-premium", true,
                HalloweenLanes.SangreUnlocked
                    ? $"5 de un fondo de {HalloweenMissions.SangrePaidPoolCount}"
                    : $"se abre con {HalloweenCurrency.Icon} {SangreUnlockCost}"));
        }

        /// <summary>Ficha de una vía: icono, nombre, hechas/total, barra y estado.</summary>
        private VisualElement BuildMissionSummary(HalloweenEvent.Phase phase, int total, int done,
            int pending, string iconText, string title, string laneClass, bool sangreTab, string hint)
        {
            var tile = new VisualElement();
            tile.AddToClassList("hw-msum");
            tile.AddToClassList(laneClass);
            tile.focusable = true;
            tile.tooltip = "Abrir el tablero de misiones de la velada";

            var head = new VisualElement();
            head.AddToClassList("hw-msum-head");

            var icon = new Label(iconText);
            icon.AddToClassList("hw-msum-icon");
            head.Add(icon);

            var name = new Label(title);
            name.AddToClassList("hw-msum-title");
            head.Add(name);

            var count = new Label($"{done}/{total}");
            count.AddToClassList("hw-msum-count");
            head.Add(count);
            tile.Add(head);

            var bar = new VisualElement();
            bar.AddToClassList("hw-msum-bar");
            var fill = new VisualElement();
            fill.AddToClassList("hw-msum-fill");
            fill.style.width = Length.Percent(total > 0 ? Mathf.Clamp01(done / (float)total) * 100f : 0f);
            bar.Add(fill);
            tile.Add(bar);

            string footer;
            if (phase != HalloweenEvent.Phase.Active)
                footer = phase == HalloweenEvent.Phase.NotStarted
                    ? $"PRÓXIMAMENTE · {HalloweenEvent.Start:dd/MM}"
                    : "CERRADAS";
            else if (pending > 0)
                footer = $"{pending} PARA COBRAR";
            else if (done >= total && total > 0)
                footer = "COMPLETAS";
            else
                footer = hint;

            var note = new Label(footer);
            note.AddToClassList("hw-msum-note");
            if (pending > 0 && phase == HalloweenEvent.Phase.Active)
                note.AddToClassList("hw-msum-note-ready");
            tile.Add(note);

            tile.RegisterCallback<ClickEvent>(_ => OpenMissions(sangreTab));
            tile.RegisterCallback<NavigationSubmitEvent>(_ => OpenMissions(sangreTab));
            return tile;
        }

        private string MissionsStamp(HalloweenEvent.Phase phase)
        {
            var sb = new System.Text.StringBuilder(phase.ToString());
            sb.Append('|').Append(HalloweenMissions.CompletedCount)
              .Append('|').Append(HalloweenMissions.PendingClaimsCount)
              .Append('|').Append(HalloweenMissions.SangreCompletedCount(false))
              .Append('|').Append(HalloweenMissions.SangreCompletedCount(true))
              .Append('|').Append(HalloweenMissions.SangrePendingClaimsCount)
              .Append('|').Append(HalloweenLanes.SangreUnlocked ? 1 : 0);
            if (phase == HalloweenEvent.Phase.Active)
                sb.Append('|').Append(HalloweenMissions.TimeToResetText());
            return sb.ToString();
        }

        // ── Animación de cobro: overlay + pop de la recompensa ────────────

        private void ShowClaimOverlay(Reward reward, int tier, bool sangre, string detail)
        {
            if (_root == null)
            {
                // Sin raíz no hay animación posible: el cobro ya está hecho.
                _onToast?.Invoke($"Nivel {tier} cobrado", detail);
                return;
            }

            _claimTicker?.Pause();
            _claimOverlay?.RemoveFromHierarchy();

            var overlay = new VisualElement();
            overlay.name = "hw-claim-overlay";
            overlay.style.position = Position.Absolute;
            overlay.style.left = 0;
            overlay.style.top = 0;
            overlay.style.right = 0;
            overlay.style.bottom = 0;
            overlay.style.justifyContent = Justify.Center;
            overlay.style.alignItems = Align.Center;
            overlay.style.backgroundColor = new Color(0.024f, 0.012f, 0.055f, 0f);

            var card = new VisualElement();
            card.style.width = 440;
            card.style.maxWidth = Length.Percent(92f);
            card.style.paddingLeft = 30;
            card.style.paddingRight = 30;
            card.style.paddingTop = 24;
            card.style.paddingBottom = 26;
            card.style.alignItems = Align.Center;
            card.style.backgroundColor = new Color(0.075f, 0.043f, 0.129f, 0.97f); // #130B21
            card.style.borderTopWidth = 2;
            card.style.borderBottomWidth = 2;
            card.style.borderLeftWidth = 2;
            card.style.borderRightWidth = 2;
            card.style.borderTopColor = new Color(0.729f, 0.502f, 1f);        // #BA80FF
            card.style.borderBottomColor = new Color(0.494f, 0.235f, 0.659f);  // #7E3CA8
            card.style.borderLeftColor = new Color(0.494f, 0.235f, 0.659f);
            card.style.borderRightColor = new Color(0.494f, 0.235f, 0.659f);
            card.style.borderTopLeftRadius = 20;
            card.style.borderTopRightRadius = 20;
            card.style.borderBottomLeftRadius = 20;
            card.style.borderBottomRightRadius = 20;
            card.style.opacity = 0f;
            card.style.scale = new Scale(new Vector2(0.45f, 0.45f));

            var kicker = new Label(sangre ? "RECOMPENSA DE SANGRE COBRADA" : "RECOMPENSA DE LA VELADA COBRADA");
            kicker.style.fontSize = 11;
            kicker.style.unityFontStyleAndWeight = FontStyle.Bold;
            kicker.style.color = new Color(0.784f, 0.659f, 0.867f); // #C8A8DD
            kicker.style.unityTextAlign = TextAnchor.MiddleCenter;
            kicker.style.marginBottom = 12;
            card.Add(kicker);

            Sprite art = ArtFor(reward);
            if (art != null)
            {
                float sw = Mathf.Max(1f, art.rect.width);
                float sh = Mathf.Max(1f, art.rect.height);
                float boxW = 150f, boxH = 150f;
                if (sw / sh > boxW / boxH) boxH = boxW * sh / sw;
                else boxW = boxH * sw / sh;

                var artBox = new VisualElement();
                artBox.style.width = boxW;
                artBox.style.height = boxH;
                artBox.style.backgroundImage = new StyleBackground(art);
                artBox.style.backgroundSize = new BackgroundSize(BackgroundSizeType.Contain);
                artBox.style.backgroundPositionX = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Center, new Length(0f)));
                artBox.style.backgroundPositionY = new StyleBackgroundPosition(new BackgroundPosition(BackgroundPositionKeyword.Center, new Length(0f)));
                artBox.style.backgroundRepeat = new StyleBackgroundRepeat(new BackgroundRepeat(Repeat.NoRepeat, Repeat.NoRepeat));
                card.Add(artBox);
            }
            else
            {
                var icon = new Label(reward.icon);
                icon.style.fontSize = 64;
                icon.style.color = new Color(0.729f, 0.502f, 1f);
                icon.style.unityTextAlign = TextAnchor.MiddleCenter;
                icon.style.height = 140;
                icon.style.marginTop = 4;
                card.Add(icon);
            }

            var details = new VisualElement();
            details.style.alignItems = Align.Center;
            details.style.width = Length.Percent(100f);

            var name = new Label(reward.name);
            name.style.fontSize = 24;
            name.style.unityFontStyleAndWeight = FontStyle.Bold;
            name.style.color = Color.white;
            name.style.unityTextAlign = TextAnchor.MiddleCenter;
            name.style.marginTop = 12;
            details.Add(name);

            var tag = new Label(TagFor(reward));
            tag.style.fontSize = 14;
            tag.style.unityFontStyleAndWeight = FontStyle.Bold;
            tag.style.color = new Color(0.729f, 0.502f, 1f);
            tag.style.unityTextAlign = TextAnchor.MiddleCenter;
            tag.style.marginTop = 4;
            details.Add(tag);

            if (!string.IsNullOrEmpty(detail))
            {
                var sub = new Label(detail);
                sub.style.fontSize = 13;
                sub.style.color = new Color(0.722f, 0.635f, 0.863f); // #B8A2DC
                sub.style.unityTextAlign = TextAnchor.MiddleCenter;
                sub.style.marginTop = 10;
                sub.style.whiteSpace = WhiteSpace.Normal;
                details.Add(sub);
            }

            var level = new Label($"NIVEL {tier} · {(sangre ? "VÍA SANGRE" : "VÍA LUNA")}");
            level.style.fontSize = 11;
            level.style.unityFontStyleAndWeight = FontStyle.Bold;
            level.style.color = new Color(0.478f, 0.541f, 0.690f);
            level.style.unityTextAlign = TextAnchor.MiddleCenter;
            level.style.marginTop = 12;
            details.Add(level);

            var sparkles = new Label("🕯   🕯   🕯");
            sparkles.style.fontSize = 14;
            sparkles.style.color = new Color(0.729f, 0.502f, 1f);
            sparkles.style.unityTextAlign = TextAnchor.MiddleCenter;
            sparkles.style.marginTop = 14;
            sparkles.style.opacity = 0f;
            details.Add(sparkles);

            card.Add(details);
            overlay.Add(card);
            _root.Add(overlay);

            _claimOverlay = overlay;
            _claimCard = card;
            _claimDetails = details;
            _claimSparkles = sparkles;
            _claimStart = Time.realtimeSinceStartup;
            _claimAnimating = true;

            TickClaimOverlay();
            _claimTicker = overlay.schedule.Execute(TickClaimOverlay).Every(16);
        }

        private void TickClaimOverlay()
        {
            if (_claimOverlay == null)
            {
                _claimTicker?.Pause();
                _claimTicker = null;
                _claimAnimating = false;
                return;
            }

            float t = Time.realtimeSinceStartup - _claimStart;
            float holdEnd = ClaimInTime + ClaimHoldTime;
            float total = holdEnd + ClaimOutTime;

            float bgAlpha, cardAlpha, cardScale, detailsY;

            if (t < holdEnd)
            {
                // Entrada: fondo con fundido cúbico, tarjeta con rebote y textos subiendo.
                float fade = Mathf.Clamp01(t / 0.30f);
                bgAlpha = 0.88f * (1f - Mathf.Pow(1f - fade, 3f));

                float u = Mathf.Clamp01(t / ClaimInTime);
                float c1 = 1.70158f, c3 = c1 + 1f;
                float back = 1f + c3 * Mathf.Pow(u - 1f, 3f) + c1 * Mathf.Pow(u - 1f, 2f);
                cardScale = Mathf.Lerp(0.45f, 1f, back);
                cardAlpha = Mathf.Clamp01(t / 0.22f);

                float du = Mathf.Clamp01((t - 0.10f) / 0.50f);
                detailsY = Mathf.Lerp(26f, 0f, 1f - Mathf.Pow(1f - du, 3f));
            }
            else
            {
                // Salida: fundido del conjunto con ligera contracción.
                float v = Mathf.Clamp01((t - holdEnd) / ClaimOutTime);
                float eased = 1f - Mathf.Pow(1f - v, 3f);
                bgAlpha = 0.88f * (1f - eased);
                cardAlpha = 1f - v;
                cardScale = Mathf.Lerp(1f, 0.94f, eased);
                detailsY = 0f;
            }

            _claimOverlay.style.backgroundColor = new Color(0.024f, 0.012f, 0.055f, bgAlpha);
            _claimCard.style.opacity = cardAlpha;
            _claimCard.style.scale = new Scale(new Vector2(cardScale, cardScale));
            _claimDetails.style.translate = new Translate(
                new Length(0f, LengthUnit.Pixel), new Length(detailsY, LengthUnit.Pixel));

            if (_claimSparkles != null)
            {
                bool sparkling = t > 0.45f && t < holdEnd;
                _claimSparkles.style.opacity = sparkling
                    ? 0.55f + 0.45f * (0.5f + 0.5f * Mathf.Sin((t - 0.45f) * 7f))
                    : 0f;
            }

            if (t >= total) FinishClaimOverlay();
        }

        private void FinishClaimOverlay()
        {
            _claimTicker?.Pause();
            _claimTicker = null;
            _claimOverlay?.RemoveFromHierarchy();
            _claimOverlay = null;
            _claimCard = null;
            _claimDetails = null;
            _claimSparkles = null;
            _claimAnimating = false;
        }
    }
}
