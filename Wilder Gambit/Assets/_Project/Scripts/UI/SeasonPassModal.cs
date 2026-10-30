using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.Services;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// PASE DE TEMPORADA — modal a pantalla completa (patrón shop2: root + backdrop + window).
    /// Usa los 4 artes de <c>Resources/UI/SeasonPass</c>:
    ///   banner (hero), label (título), bar (marco de progreso) y tier (medallón de nivel),
    /// más los slots basic/premium para las dos vías de recompensa.
    ///
    /// La pista son <see cref="TierCount"/> columnas dentro de un <c>ScrollView</c> horizontal
    /// (la temporada completa no cabe en pantalla) y <b>sin scroll vertical</b>: las dos vías siempre
    /// caben porque <see cref="FitTrack"/> mide el alto disponible y escala las cartas
    /// (ancho y alto juntos, para conservar la proporción del marco) hasta que la pila
    /// completa entra en pantalla. Cartas de 300×276 a k = 1, con holgura para piezas,
    /// variantes, skins, animaciones, fondos y tableros, que son cosas con nombre largo.
    ///
    /// Progreso acumulativo por temporada (<see cref="SeasonProgress"/>, monotónico:
    /// no se desinfla con el reseteo semanal) más el bonus de logros. Sin backend:
    /// el Gambito Real es un desbloqueo local verificado contra el servidor.
    /// </summary>
    public class SeasonPassModal : MonoBehaviour
    {
        /// <summary>
        /// Niveles de la temporada. La pista scrollea en horizontal.
        /// 30 niveles (recortada de 75 por la duración corta de la T1) + el pago
        /// en Dulces que pediste para el pase.
        /// </summary>
        public const int TierCount = 30;
        public const int XpPerTier = 60;

        private const string KeyPremium = "WG_SeasonPass_Premium";
        private const string KeyClaimBasic = "WG_SeasonPass_ClaimB_";
        private const string KeyClaimPremium = "WG_SeasonPass_ClaimP_";

        private VisualElement _root;
        private VisualElement _track;
        private ScrollView _trackScroll;
        private Label _levelLabel;
        private Label _xpLabel;
        private Label _seasonLabel;
        private Label _timerLabel;
        private Label _countLabel;
        private Label _premiumBadge;
        private Label _libreHint;
        private Button _btnPremium;
        private VisualElement _scrollBody;
        private VisualElement _laneLibre;
        private VisualElement _laneReal;
        private VisualElement _laneHead;

        /// <summary>Móvil en vertical: la pista pasa a ser una columna de niveles con scroll vertical.</summary>
        private bool _vertical;

        /// <summary>Firma del último repintado: evita rehacer 100 tarjetas en cada refresco.</summary>
        private int _trackStamp = int.MinValue;

        private Action _onClose;
        private Action<string, string> _onToast;
        private bool _subscribed;

        // ── Overlay de reclamación (animación al cobrar) ─────────────────
        private VisualElement _claimOverlay;
        private VisualElement _claimCard;
        private VisualElement _claimDetails;
        private Label _claimSparkles;
        private IVisualElementScheduledItem _claimTicker;
        private float _claimStart;
        private bool _claimAnimating;
        private string _claimToastTitle;
        private string _claimToastDetail;

        private const float ClaimInTime = 0.45f;
        private const float ClaimHoldTime = 1.15f;
        private const float ClaimOutTime = 0.38f;

        // ── Modal de compra del Gambito Real ─────────────────────────────
        //
        // El precio y el cobro no son locales: el servidor manda el precio en
        // Tides (GET) y descuenta el saldo de la cuenta Surface (POST). Aquí
        // solo se pinta, se anima la entrada y se refleja el resultado.

        private VisualElement _buyView;
        private VisualElement _buyWindow;
        private Button _btnBuyConfirm;
        private Button _btnBuyLogin;
        private TextField _buyUser;
        private TextField _buyPass;
        private Label _buyPrice;
        private Label _buyAccount;
        private Label _buyBalance;
        private Label _buyError;
        private VisualElement _buyLoginRow;

        private Coroutine _buyRoutine;
        private IVisualElementScheduledItem _buyAnimTicker;
        private IVisualElementScheduledItem _buyCloseHandle;
        private float _buyAnimStart;
        private float _buyLastSyncAt = -9999f;
        private bool _buyBusy;

        /// <summary>Precio de respaldo (si el servidor no contesta). El real lo manda el servidor.</summary>
        private const int FallbackPriceTides = 450;
        private int _buyPriceTides = FallbackPriceTides;

        private const float BuyInTime = 0.26f;

        // ── API de temporada ──────────────────────────────────────────────

        /// <summary>
        /// El pase está en pretemporada: se puede ver, pero todavía no arrancó.
        /// Sin XP, sin niveles y sin cobros hasta la fecha de inicio.
        /// </summary>
        public static bool IsPreSeason => SeasonCalendar.IsPreSeasonNow;

        /// <summary>Fecha en que arranca la temporada vigente.</summary>
        private static DateTime SeasonStart => SeasonCalendar.CurrentStart;

        /// <summary>XP guardado de la temporada (acumulativo, por temporada).</summary>
        public static int StoredXp => SeasonProgress.Xp;

        /// <summary>Suma XP al pase (las misiones y partidas llaman aquí).</summary>
        public static void AddXP(int amount) => SeasonProgress.AddXp(amount);

        public static bool HasPremium => PlayerPrefs.GetInt(KeyPremium, 0) == 1;

        /// <summary>
        /// Bonus estable de cuenta: logros (no se resetea con la semana, así el
        /// nivel nunca se desinfla los lunes). Misiones y segmentos aportan vía
        /// <see cref="SeasonProgress"/> al cobrarse, no aquí.
        /// </summary>
        private static int DerivedXp()
        {
            if (IsPreSeason) return 0;
            try { return Achievements.UnlockedCount * 20; } catch { return 0; }
        }

        /// <summary>XP total de la temporada. En pretemporada es 0: nada cuenta todavía.</summary>
        public static int EffectiveXp => IsPreSeason ? 0 : StoredXp + DerivedXp();

        public static int LevelFor(int xp) => Mathf.Clamp(xp / XpPerTier, 0, TierCount);

        /// <summary>Claves de cobro por temporada: al rotar, todo arranca sin cobrar.</summary>
        private static string ClaimKey(string prefix, int tier) =>
            prefix + SeasonCalendar.CurrentId + "_" + tier;

        private static bool IsBasicClaimed(int tier) => PlayerPrefs.GetInt(ClaimKey(KeyClaimBasic, tier), 0) == 1;
        private static bool IsPremiumClaimed(int tier) => PlayerPrefs.GetInt(ClaimKey(KeyClaimPremium, tier), 0) == 1;

        private static void SetClaimed(int tier, bool premium)
        {
            PlayerPrefs.SetInt(ClaimKey(premium ? KeyClaimPremium : KeyClaimBasic, tier), 1);
            PlayerPrefs.Save();
        }

        // ── Recompensas (tabla local de temporada demo) ──────────────────

        /// <summary>
        /// Qué entrega el nivel. Todo lo que no sea <see cref="Gambits"/> o
        /// <see cref="Reroll"/> desbloquea de verdad el catálogo del juego:
        /// nada de etiquetas cosméticas que solo pagan moneda.
        /// </summary>
        private enum RewardKind
        {
            /// <summary>Gambits (moneda-corona).</summary>
            Gambits,
            /// <summary>Dulces: la moneda temporal de la velada de Halloween.</summary>
            Dulces,
            /// <summary>Un cambio de misión diaria (1 gratis al día).</summary>
            Reroll,
            /// <summary>Skin de pieza (<see cref="PieceSkinManager.OwnSkin"/>).</summary>
            Skin,
            /// <summary>Variante de pieza (<see cref="PieceLoadoutManager"/>).</summary>
            Variant,
            /// <summary>Animación de efecto (Own sin equipar).</summary>
            Animation,
            /// <summary>Fondo del menú (<see cref="BackdropManager.Unlock"/>).</summary>
            Backdrop,
            /// <summary>Tablero (<see cref="BoardBackgroundManager.Unlock"/>).</summary>
            Board,
        }

        private struct Reward
        {
            public RewardKind kind;
            public string icon;
            public string name;
            public int gambits;
            /// <summary>Dulces (moneda del evento de Halloween); 0 si no aplica.</summary>
            public int dulces;
            /// <summary>Id de skin, variante o animación.</summary>
            public string refId;
            /// <summary>Índice de catálogo: skin, fondo o tablero.</summary>
            public int index;
        }

        private static Reward Gambits(int amount) => new Reward
        {
            kind = RewardKind.Gambits, icon = "♔", name = "Gambits",
            gambits = amount, index = -1,
        };

        private static Reward Dulces(int amount) => new Reward
        {
            kind = RewardKind.Dulces, icon = HalloweenCurrency.Icon, name = HalloweenCurrency.Label,
            dulces = amount, index = -1,
        };

        private static Reward Reroll() => new Reward
        {
            kind = RewardKind.Reroll, icon = "🎲", name = "Cambio de misión", index = -1,
        };

        /// <summary>Skin por id del catálogo: nombre, icono e índice los pone el catálogo.</summary>
        private static Reward Skin(string skinId)
        {
            int index = PieceSkinManager.GetIndexById(skinId);
            string icon = index >= 0 ? PieceSkinManager.GetSkinIcon(index) : "✨";
            string name = index >= 0 ? PieceSkinManager.GetSkinName(index) : skinId;
            return new Reward
            {
                kind = RewardKind.Skin, icon = icon, name = name,
                refId = skinId, index = index,
            };
        }

        private static Reward Variant(string refId, string icon, string name) => new Reward
        {
            kind = RewardKind.Variant, icon = icon, name = name, refId = refId, index = -1,
        };

        private static Reward Animation(string refId, string icon, string name) => new Reward
        {
            kind = RewardKind.Animation, icon = icon, name = name, refId = refId, index = -1,
        };

        private static Reward Backdrop(int index) => new Reward
        {
            kind = RewardKind.Backdrop, icon = "🖼️",
            name = BackdropManager.GetDisplayName(index), index = index,
        };

        private static Reward Board(int index) => new Reward
        {
            kind = RewardKind.Board, icon = "♟️",
            name = BoardBackgroundManager.GetDisplayName(index), index = index,
        };

        // ── Vía libre: moneda y los desbloqueos de entrada ────────────────

        private static readonly Reward[] BasicRewards =
        {
            Gambits(50), Gambits(60), Reroll(), Dulces(4), Gambits(80),
            Skin("skin_pawn_golden"), Gambits(100), Reroll(), Gambits(120), Backdrop(2),
            Dulces(5), Gambits(150), Gambits(170), Reroll(), Gambits(190),
            Skin("skin_pawn_sprout"), Gambits(220), Dulces(6), Gambits(250), Backdrop(3),
            Gambits(280), Reroll(), Gambits(310), Dulces(6), Gambits(340),
            Reroll(), Gambits(380), Board(2), Gambits(420), Skin("skin_king_igneous"),
        };

        // ── Vía real: catálogo premium. Sin Tides: el pase se cobra y paga ─
        //    solo con moneda y desbloqueos del juego.

        private static readonly Reward[] PremiumRewards =
        {
            Gambits(100), Reroll(), Skin("skin_bishop_frost"), Dulces(10), Variant("lancer", "⚔️", "Peón Lancero"),
            Gambits(200), Skin("skin_necro_pulse"), Dulces(12), Skin("skin_rook_abyss"), Animation(DefeatFx.AnimId, "🔥", "Ceniza al Viento"),
            Reroll(), Variant("rider", "🐎", "Dama Jinete"), Skin("skin_knight_obsidian"), Gambits(300), Backdrop(4),
            Skin("skin_king_solar"), Dulces(15), Animation(DoubleCheckFx.AnimId, "⚔️", "Doble Filo"), Skin("skin_queen_shadow"), Board(3),
            Variant("necromancer", "💀", "Alfil Nigromante"), Skin("skin_knight_storm"), Backdrop(5), Animation(ForkCometFx.AnimId, "☄️", "Cometa Ígnea"), Board(5),
            Skin("skin_rook_crimson"), Skin("skin_necro_lunar"), Animation(BrilliantFx.AnimId, "💫", "Destello Táctico"), Gambits(800), Variant("fragua", "🔥", "Torre Fragua"),
        };

        /// <summary>Recompensa de un nivel. Nunca falla: si la tabla es corta, cicla.</summary>
        private static Reward RewardAt(int tier, bool premium)
        {
            Reward[] table = premium ? PremiumRewards : BasicRewards;
            if (table == null || table.Length == 0) return Gambits(0);
            return table[(tier - 1) % table.Length];
        }

        /// <summary>Texto de la línea de valor: cifra o rareza/categoría del objeto.</summary>
        private static string TagFor(Reward r)
        {
            switch (r.kind)
            {
                case RewardKind.Gambits: return $"{r.gambits:N0}";
                case RewardKind.Dulces: return $"{r.dulces:N0} {HalloweenCurrency.Icon}";
                case RewardKind.Reroll: return "1 AL DÍA";
                case RewardKind.Skin:
                    return r.index >= 0 ? RarityLabel(PieceSkinManager.GetSkinRarity(r.index)) : "PIEZA";
                case RewardKind.Variant: return "VARIANTE";
                case RewardKind.Animation: return "ANIMACIÓN";
                case RewardKind.Backdrop: return "FONDO";
                case RewardKind.Board: return "TABLERO";
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

        /// <summary>
        /// Clase interior de jerarquía para el nombre premium (rework visual).
        /// No toca el contenedor: solo tiñe el <c>Label</c> del nombre.
        /// </summary>
        private static string NameClassFor(Reward r)
        {
            switch (r.kind)
            {
                case RewardKind.Gambits: return "season-name-gambits";
                case RewardKind.Dulces: return "season-name-gambits";
                case RewardKind.Reroll: return "season-name-reroll";
                case RewardKind.Variant: return "season-name-variant";
                case RewardKind.Animation: return "season-name-animation";
                case RewardKind.Backdrop:
                case RewardKind.Board: return "season-name-deco";
                case RewardKind.Skin:
                    if (r.index < 0) return "season-name-deco";
                    switch (PieceSkinManager.GetSkinRarity(r.index))
                    {
                        case SkinRarity.Common: return "season-rarity-common";
                        case SkinRarity.Uncommon: return "season-rarity-uncommon";
                        case SkinRarity.Rare: return "season-rarity-rare";
                        case SkinRarity.Epic: return "season-rarity-epic";
                        case SkinRarity.Legendary: return "season-rarity-legendary";
                        case SkinRarity.Mythic: return "season-rarity-mythic";
                        default: return "season-name-deco";
                    }
                default: return "season-name-deco";
            }
        }

        // ── Arte de la tarjeta ────────────────────────────────────────────

        // Las texturas de catálogo no se cachean en sus managers, así que la
        // pista las pediría 2 veces por nivel en cada repintado: se cachean aquí.
        private static readonly Dictionary<string, Sprite> ArtCache = new Dictionary<string, Sprite>();

        // Con "Fast Play Mode" (sin recarga de dominio) los estáticos sobreviven
        // entre Plays; ver el mismo aviso en PieceSkinManager.
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void ResetArtCache() => ArtCache.Clear();

        /// <summary>
        /// Rutas de arte (en StreamingAssets/Pieces) de cada variante del pase.
        /// Clave = refId de la recompensa; valor = rutas en orden de preferencia.
        /// Política visual del pase: SIEMPRE la versión blanca primero (solo visual;
        /// el desbloqueo funcional sirve para blancas y negras). Si la blanca falta,
        /// se cae a la negra blindado (se asimila como blanca, sin romper la tarjeta).
        /// </summary>
        private static readonly Dictionary<string, string[]> PieceVariantArtPaths =
            new Dictionary<string, string[]>
            {
                { "fragua",      new[] { "White/FraguaRook",        "Black/FraguaRook" } },
                { "necromancer", new[] { "White/NecromancerBishop", "Black/NecromancerBishop" } },
                { "lancer",      new[] { "White/LancerPawn",        "Black/LancerPawn" } },
                { "rider",       new[] { "White/RiderQueen",        "Black/RiderQueen" } },
            };

        private static Sprite Wrap(Texture2D tex)
        {
            if (tex == null) return null;
            var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                new Vector2(0.5f, 0.5f), 100f);
            sprite.name = "season-reward-art";
            return sprite;
        }

        /// <summary>
        /// Miniatura del objeto regalado, o <c>null</c> si su categoría no trae
        /// arte (Gambits, reroll…). La tarjeta cae al emoji en ese caso.
        /// Política visual del pase: skins y variantes SIEMPRE se presencian con su
        /// versión blanca (solo visual; el cobro funcional desbloquea la pieza para
        /// blancas y negras). Si una variante o skin no trae versión blanca/negras
        /// separadas, se blinda: se asimila el arte disponible como versión blanca.
        /// </summary>
        private static Sprite ArtFor(Reward r)
        {
            // v1 blanca: invalida la caché anterior (que priorizaba la negra).
            string key = $"W1|{r.kind}|{r.refId}|{r.index}";
            if (ArtCache.TryGetValue(key, out Sprite cached)) return cached;

            Sprite art = null;
            try
            {
                switch (r.kind)
                {
                    case RewardKind.Gambits:
                        // La moneda-corona es el arte (el monto va sin emoji).
                        art = GambitIcon.Sprite;
                        break;
                    case RewardKind.Reroll:
                        // El dado dorado es el arte (solo visual; el cobro no cambia).
                        art = RerollIcon.Sprite;
                        break;
                    case RewardKind.Skin:
                        if (r.index >= 0) art = ArtForSkinWhite(r.index);
                        break;
                    case RewardKind.Backdrop:
                        art = Wrap(BackdropManager.LoadThumbnailForIndex(r.index));
                        break;
                    case RewardKind.Board:
                        art = Wrap(BoardBackgroundManager.LoadThumbnailForIndex(r.index));
                        break;
                    case RewardKind.Animation:
                        if (r.refId == DefeatFx.AnimId) art = DefeatFx.GetArtSprite();
                        else if (r.refId == DoubleCheckFx.AnimId) art = DoubleCheckFx.GetArtSprite();
                        else if (r.refId == BrilliantFx.AnimId) art = BrilliantFx.GetArtSprite();
                        else if (r.refId == ForkCometFx.AnimId) art = ForkCometFx.GetArtSprite();
                        break;
                    case RewardKind.Variant:
                        // Arte directo de la pieza, para las 4 variantes del pase.
                        // Versión blanca primero (solo visual); caída blindada a la
                        // negra si la blanca falta. Los archivos viven en
                        // StreamingAssets (fuente única editor/build). Si faltaran
                        // igual, la tarjeta sigue usando el emoji de respaldo.
                        if (PieceVariantArtPaths.TryGetValue(r.refId, out string[] variantPaths))
                        {
                            foreach (string variantPath in variantPaths)
                            {
                                art = LoadVariantArt(variantPath);
                                if (art != null) break;
                            }
                        }
                        else if (!string.IsNullOrEmpty(r.refId))
                        {
                            // Variante futura sin entrada: intento genérico blanco→negro.
                            art = LoadVariantArt("White/" + r.refId)
                                ?? LoadVariantArt("Black/" + r.refId);
                        }
                        break;
                }
            }
            catch (Exception e)
            {
                Debug.LogWarning($"[SeasonPassModal] Sin arte para «{r.name}»: {e.Message}");
            }

            ArtCache[key] = art;
            return art;
        }

        /// <summary>
        /// Arte blanco de una skin para el pase (solo visual).
        /// 1) Si existe arte sufijado blanco (<c>id_white</c>), se usa ese.
        /// 2) Si no, se asimila el thumbnail del catálogo como versión blanca.
        /// 3) Blindaje final: pieza base blanca del tipo de la skin, o null (emoji).
        /// El desbloqueo funcional (<see cref="TryGrant"/>) no pasa por aquí:
        /// la skin sirve igual para piezas blancas y negras en partida.
        /// </summary>
        private static Sprite ArtForSkinWhite(int skinIndex)
        {
            string skinId = PieceSkinManager.GetSkinId(skinIndex);
            if (!string.IsNullOrEmpty(skinId))
            {
                Sprite white = TryLoadWhiteSuffixedSkin(skinId);
                if (white != null) return white;
            }

            Sprite catalog = null;
            try { catalog = Wrap(PieceSkinManager.GetSkinThumbnail(skinIndex)); }
            catch { catalog = null; }
            if (catalog != null) return catalog;

            // Blindaje: sin thumbnail, mostrar la pieza base blanca del tipo.
            try
            {
                string baseName = SkinBasePieceName(PieceSkinManager.GetSkinPieceType(skinIndex));
                if (!string.IsNullOrEmpty(baseName))
                {
                    Sprite fallback = LoadVariantArt("White/" + baseName);
                    if (fallback != null) return fallback;
                }
            }
            catch { /* el emoji de respaldo cubre */ }
            return null;
        }

        /// <summary>
        /// Busca arte blanco sufijado de skin (<c>Skins/id_white</c>, disco + Resources).
        /// Devuelve null si no existe: el llamador asimila el thumbnail base como blanco.
        /// </summary>
        private static Sprite TryLoadWhiteSuffixedSkin(string skinId)
        {
            string[] suffixes = { "_white", "_White", "-white", "-White", "(White)", "_blanca" };
            foreach (string suffix in suffixes)
            {
                string name = skinId + suffix;
                try
                {
                    string disk = System.IO.Path.Combine(Application.dataPath, "Resources/Skins", name + ".png");
                    if (System.IO.File.Exists(disk))
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(disk);
                        var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                        if (tex.LoadImage(bytes)) return Wrap(tex);
                    }
                }
                catch { /* probar siguiente variante */ }
                try
                {
                    Texture2D tex = Resources.Load<Texture2D>("Skins/" + name);
                    if (tex != null) return Wrap(tex);
                    Sprite spr = Resources.Load<Sprite>("Skins/" + name);
                    if (spr != null && spr.texture != null) return Wrap(spr.texture);
                }
                catch { /* probar siguiente variante */ }
            }
            return null;
        }

        /// <summary>Nombre del PNG base blanco para el tipo de pieza de una skin.</summary>
        private static string SkinBasePieceName(PieceType type)
        {
            switch (type)
            {
                case PieceType.Pawn: return "Pawn";
                case PieceType.Knight: return "Knight";
                case PieceType.Bishop: return "Bishop";
                case PieceType.Rook: return "Rook";
                case PieceType.Queen: return "Queen";
                case PieceType.King: return "King";
                case PieceType.NecromancerBishop: return "NecromancerBishop";
                default: return null;
            }
        }

        /// <summary>
        /// Carga el arte de una variante desde Textures/Pieces en tiempo de ejecución
        /// (mismas rutas que BoardView; el importer de Unity no hace falta porque se
        /// lee el PNG a disco). Devuelve null si el archivo no existe.
        /// </summary>
        private static Sprite LoadVariantArt(string relativePath)
        {
            // Fuente unica: StreamingAssets (funciona igual en Editor y build).
            // Las rutas de proyecto solo existen en el Editor y quedan como fallback.
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

        // ── Ciclo de vida ───────────────────────────────────────────────

        /// <summary>Se llama una vez desde MainMenuController tras cargar el UXML.</summary>
        public void Initialize(VisualElement root, Action onClose, Action<string, string> onToast = null)
        {
            _root = root;
            _onClose = onClose;
            _onToast = onToast;
            if (_root == null) return;

            _track = _root.Q<VisualElement>("season-track");
            _trackScroll = _root.Q<ScrollView>("season-track-scroll");
            _levelLabel = _root.Q<Label>("season-level-label");
            _xpLabel = _root.Q<Label>("season-xp-label");
            _seasonLabel = _root.Q<Label>("season-season-label");
            _timerLabel = _root.Q<Label>("season-timer-label");
            _countLabel = _root.Q<Label>("season-count-label");
            _premiumBadge = _root.Q<Label>("season-premium-badge");
            _libreHint = _root.Q<Label>("season-libre-hint");
            _btnPremium = _root.Q<Button>("btn-season-premium");
            _scrollBody = _root.Q<VisualElement>("season-scroll");
            _laneLibre = _root.Q<VisualElement>("season-lane-libre");
            _laneReal = _root.Q<VisualElement>("season-lane-real");

            // Modal de compra (Gambito Libre vs Gambito Real)
            _buyView = _root.Q<VisualElement>("season-buy-view");
            _buyWindow = _root.Q<VisualElement>("season-buy-window");
            _btnBuyConfirm = _root.Q<Button>("btn-season-buy-confirm");
            _btnBuyLogin = _root.Q<Button>("btn-season-buy-login");
            _buyUser = _root.Q<TextField>("season-buy-username");
            _buyPass = _root.Q<TextField>("season-buy-password");
            _buyPrice = _root.Q<Label>("season-buy-price");
            _buyAccount = _root.Q<Label>("season-buy-account-label");
            _buyBalance = _root.Q<Label>("season-buy-balance");
            _buyError = _root.Q<Label>("season-buy-error");
            _buyLoginRow = _root.Q<VisualElement>("season-buy-login");

            _root.Q<Button>("btn-season-buy-close")?.RegisterCallback<ClickEvent>(_ => CloseBuyView());
            _btnBuyConfirm?.RegisterCallback<ClickEvent>(_ => OnBuyConfirm());
            _btnBuyLogin?.RegisterCallback<ClickEvent>(_ => OnBuyLogin());
            if (_buyPass != null)
            {
                _buyPass.isPasswordField = true;
                _buyPass.maskChar = '•';
            }
            _buyUser?.RegisterCallback<KeyDownEvent>(OnBuyFieldKey);
            _buyPass?.RegisterCallback<KeyDownEvent>(OnBuyFieldKey);
            SetBuyError("");

            _root.Q<Button>("btn-close-season")?.RegisterCallback<ClickEvent>(_ => Close());
            _root.Q<Button>("btn-close-season-foot")?.RegisterCallback<ClickEvent>(_ => Close());
            _btnPremium?.RegisterCallback<ClickEvent>(_ => OnPremiumClicked());

            // Flechas de la pista: la temporada no se recorre entera solo con la rueda.
            _root.Q<Button>("btn-season-track-prev")?.RegisterCallback<ClickEvent>(_ => ScrollTrack(-1f));
            _root.Q<Button>("btn-season-track-next")?.RegisterCallback<ClickEvent>(_ => ScrollTrack(1f));

            // Sin scroll vertical: la pista se escala al alto disponible.
            // El centrado pendiente se aplica aquí (con el layout ya resuelto).
            if (_trackScroll != null)
                _trackScroll.RegisterCallback<GeometryChangedEvent>(_ =>
                {
                    if (SyncOrientation()) Refresh();
                    FitTrack();
                    ApplyPendingTrackScroll();
                });

            // Respaldo por código: si el USS por URL no resolvió, se aplica el sprite.
            SeasonPassSprites.Apply(_root.Q("season-hero"), SeasonPassSprites.Banner);
            SeasonPassSprites.Apply(_root.Q("season-title-art"), SeasonPassSprites.Label);
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

            // El servidor es quien sabe si el Gambito Real ya es tuyo: al abrir
            // se refresca propiedad y precio (si hay sesión y no se acaba de pedir).
            TrySyncSeasonPass();
        }

        public void OnClosed()
        {
            CloseBuyView(false);
            if (_claimAnimating) FinishClaimOverlay();
            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        private void OnDestroy()
        {
            CloseBuyView(false);
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

        // ── Orientación (móvil en vertical) ──────────────────────────────

        private bool IsPortraitLayout()
        {
            for (VisualElement e = _root; e != null; e = e.parent)
                if (e.ClassListContains(UiResponsive.PortraitClass)) return true;
            return false;
        }

        /// <summary>
        /// En móvil vertical la pista deja de ser una fila de columnas y pasa a ser
        /// una columna de niveles (carta libre · medallón · carta real) con scroll
        /// vertical. Devuelve true si cambió el modo (hay que repintar la pista).
        /// </summary>
        private bool SyncOrientation()
        {
            if (_trackScroll == null) return false;
            bool vertical = IsPortraitLayout();
            if (vertical == _vertical) return false;
            _vertical = vertical;

            _trackScroll.mode = vertical ? ScrollViewMode.Vertical : ScrollViewMode.Horizontal;
            _trackScroll.verticalScrollerVisibility = vertical ? ScrollerVisibility.Auto : ScrollerVisibility.Hidden;
            _trackScroll.horizontalScrollerVisibility = vertical ? ScrollerVisibility.Hidden : ScrollerVisibility.Auto;

            ArrangeLanes(vertical);
            _trackStamp = int.MinValue;
            _trackScale = 0f;
            _trackScrollPending = true;
            return true;
        }

        /// <summary>
        /// Horizontal: banner libre arriba y real abajo, envolviendo la pista.
        /// Vertical: los dos banners juntos arriba, cada uno sobre su columna de cartas.
        /// </summary>
        private void ArrangeLanes(bool vertical)
        {
            if (_laneLibre == null || _laneReal == null || _scrollBody == null) return;

            if (vertical)
            {
                if (_laneHead == null)
                {
                    _laneHead = new VisualElement();
                    _laneHead.AddToClassList("season-lane-head");
                    _laneHead.pickingMode = PickingMode.Ignore;
                }
                _laneHead.Add(_laneLibre);
                _laneHead.Add(_laneReal);
                _scrollBody.Insert(0, _laneHead);
            }
            else
            {
                _laneHead?.RemoveFromHierarchy();
                _laneLibre.style.width = StyleKeyword.Null;
                _laneReal.style.width = StyleKeyword.Null;
                _scrollBody.Insert(0, _laneLibre);
                _scrollBody.Add(_laneReal);
            }
        }

        // ── Pintado ─────────────────────────────────────────────────────

        public void Refresh()
        {
            if (_root == null) return;

            SyncOrientation();

            int xp = EffectiveXp;
            int level = LevelFor(xp);
            bool premium = HasPremium;

            if (_seasonLabel != null) _seasonLabel.text = SeasonCalendar.CurrentTitle;
            if (_timerLabel != null)
            {
                try { _timerLabel.text = SeasonCalendar.TimeTextNow.ToUpperInvariant(); }
                catch { _timerLabel.text = "JUEGA MISIONES Y PARTIDAS PARA GANAR XP"; }
            }
            if (_levelLabel != null) _levelLabel.text = $"NIVEL {level}";
            if (_xpLabel != null) _xpLabel.text = $"{xp:N0} / {TierCount * XpPerTier:N0} XP";
            if (_countLabel != null) _countLabel.text = $"{level} / {TierCount} NIVELES";
            if (_libreHint != null)
                _libreHint.text = IsPreSeason
                    ? $"PRE-TEMPORADA · EL XP Y LOS COBROS ABREN EL {SeasonStart:dd/MM}"
                    : $"{TierCount} NIVELES · {XpPerTier} XP CADA UNO · EL XP VIENE DE JUGAR";

            if (_premiumBadge != null)
            {
                _premiumBadge.text = premium ? "◆ GAMBITO REAL" : "◇ GAMBITO LIBRE";
                _premiumBadge.EnableInClassList("season-premium-on", premium);
            }

            if (_btnPremium != null)
            {
                // El precio es el del servidor (o el de respaldo si aún no contestó).
                _btnPremium.text = premium
                    ? "✓ GAMBITO REAL ACTIVO"
                    : $"DESBLOQUEAR GAMBITO REAL · 💧 {_buyPriceTides:N0} TIDES";
                _btnPremium.SetEnabled(!premium);
            }

            BuildTrack(level, premium);
        }

        /// <summary>
        /// Firma de todo lo que afecta al aspecto de la pista. Si no cambia, no se
        /// repinta: con 30 niveles son 60 tarjetas y rehacerlas en cada
        /// <see cref="GambitProgress.OnChanged"/> además tiraría el scroll de lado.
        /// </summary>
        private int TrackStamp(int level, bool premium)
        {
            int hash = 17;
            hash = hash * 31 + level;
            hash = hash * 31 + (premium ? 1 : 0);
            for (int i = 1; i <= TierCount; i++)
            {
                hash = hash * 31 + (IsBasicClaimed(i) ? 1 : 0);
                hash = hash * 31 + (IsPremiumClaimed(i) ? 1 : 0);
            }
            return hash;
        }

        private void BuildTrack(int level, bool premium)
        {
            if (_track == null) return;

            int stamp = TrackStamp(level, premium);
            if (stamp == _trackStamp) return;
            _trackStamp = stamp;

            _track.Clear();
            // Las tarjetas nuevas nacen con las medidas del USS (k = 1):
            // hay que volver a aplicar la escala vigente al terminar.
            _trackScale = 0f;

            // Línea temporal: las columnas van pegadas para que la barra
            // sea continua pasando por todos los medallones.
            for (int i = 1; i <= TierCount; i++)
            {
                bool unlocked = level >= i;
                _track.Add(BuildTier(i, unlocked, premium, level));
            }

            FitTrack();
        }

        /// <summary>Centra la pista en el nivel actual (al abrir el pase).</summary>
        ///
        /// No se usa <c>ScrollView.ScrollTo</c>: si el panel está sucio cuando se
        /// llama (y lo está: las animaciones del menú marcan estilos en cada frame),
        /// Unity deja un <i>scroll diferido</i> que se repite mientras siga sucio y
        /// re-aplica el offset cada frame para mantener visible el nivel actual.
        /// El resultado es que la pista no puede moverse más allá de ese nivel
        /// (ni siquiera arrastrando el pulgar: se resetea el offset y la velocidad).
        /// Se fija el valor del Scroller a mano, igual que hace el resto de la
        /// navegación (flechas, rueda, arrastre).
        private void ScrollToCurrentLevel()
        {
            _trackScrollPending = _track != null && _trackScroll != null;
            if (!_trackScrollPending) return;
            _track.schedule.Execute(ApplyPendingTrackScroll).StartingIn(60);
        }

        /// <summary>
        /// Aplica el centrado pendiente. Solo cuando el layout ya está resuelto
        /// (pista escalada y columnas medidas); si no, vuelve a intentarlo en el
        /// siguiente <c>GeometryChangedEvent</c> del ScrollView.
        /// </summary>
        private void ApplyPendingTrackScroll()
        {
            if (!_trackScrollPending || _track == null || _trackScroll == null) return;
            if (_trackScale <= 0f) return;

            var scroller = _vertical ? _trackScroll.verticalScroller : _trackScroll.horizontalScroller;
            var viewport = _trackScroll.contentViewport;
            if (scroller == null || viewport == null) return;

            int level = Mathf.Max(1, LevelFor(EffectiveXp));
            var target = _track.Q<VisualElement>($"season-tier-{level}");
            if (target == null) return;

            Rect view = viewport.worldBound;
            Rect tier = target.worldBound;
            if (view.width <= 1f || tier.width <= 1f || float.IsNaN(view.x) || float.IsNaN(tier.x))
                return;

            // Offset actual + desplazamiento en pantalla hasta centrar la columna:
            // worldBound ya lleva el translate aplicado, así que la diferencia es
            // lo que hay que mover el contenido. El clamp usa el rango vigente.
            float want = _vertical
                ? scroller.value + (tier.yMin + tier.height * 0.5f) - (view.yMin + view.height * 0.5f)
                : scroller.value + (tier.xMin + tier.width * 0.5f) - (view.xMin + view.width * 0.5f);
            scroller.value = Mathf.Clamp(want, scroller.lowValue, scroller.highValue);
            _trackScrollPending = false;
        }

        private void ScrollTrack(float pages)
        {
            if (_trackScroll == null) return;
            var scroller = _vertical ? _trackScroll.verticalScroller : _trackScroll.horizontalScroller;
            if (scroller == null) return;
            float viewport = _trackScroll.contentViewport != null
                ? (_vertical ? _trackScroll.contentViewport.layout.height : _trackScroll.contentViewport.layout.width)
                : 0f;
            float page = Mathf.Max(240f, viewport * 0.8f);
            scroller.value = Mathf.Clamp(scroller.value + page * pages, scroller.lowValue, scroller.highValue);
        }

        // ── Escala de la pista: SIN scroll vertical ─────────────────────
        //
        // El cuerpo es una columna fija (banners + pista) y no scrollea en
        // vertical: para que las dos vías quepan siempre, la pista se mide y
        // se escala. Las medidas siguientes son el valor de diseño (k = 1) y
        // se multiplican por k = viewport / StackHeight. El ancho escala con
        // el alto para conservar la proporción del marco (reward_slot_*.png
        // con scale-to-fit): si no, el slot saldría con bandas vacías.

        private const float DesignPadTop = 18f;
        private const float DesignPadBottom = 22f;
        private const float DesignCardMargin = 14f;
        private const float DesignTick = 22f;
        private const float DesignTickW = 3f;
        private const float DesignLine = 6f;
        private const float DesignMedal = 128f;
        private const float DesignCardH = 276f;
        private const float DesignCardW = 300f;
        private const float DesignTierW = 330f;

        // Relleno de la carta = ventana segura del marco, medida píxel a
        // píxel sobre reward_slot_basic/premium.png (corona arriba,
        // remate abajo, filigrana lateral). No es estético: es lo que
        // evita que el contenido se monte sobre el oro.
        private const float DesignBasicPadTop = 16f;
        private const float DesignBasicPadBottom = 25f;
        private const float DesignBasicPadSide = 24f;
        private const float DesignPremiumPadTop = 56f;
        private const float DesignPremiumPadBottom = 26f;
        private const float DesignPremiumPadSide = 35f;

        // Interior de la carta (k = 1): se escala entero para que la
        // carta sea una copia fiel del diseño a cualquier escala. Sin
        // esto, el texto se queda a tamaño fijo y en ventanas bajas se
        // sale de la ventana segura del marco.
        private const float DesignArtH = 96f;
        private const float DesignArtMin = 20f;
        private const float DesignArtGap = 4f;
        private const float DesignIconFont = 34f;
        private const float DesignIconFontPremium = 26f;
        private const float DesignIconH = 44f;
        private const float DesignIconHPremium = 36f;
        private const float DesignIconMin = 24f;
        private const float DesignNameFont = 14f;
        private const float DesignNameFontPremium = 12f;
        private const float DesignNameH = 20f;
        private const float DesignNameHPremium = 30f;
        private const float DesignAmountFont = 21f;
        private const float DesignAmountFontPremium = 20f;
        private const float DesignAmountH = 26f;
        private const float DesignAmountHPremium = 24f;
        private const float DesignTagFont = 14f;
        private const float DesignTagFontPremium = 11f;
        private const float DesignTagH = 22f;
        private const float DesignClaimFont = 12f;
        private const float DesignClaimFontPremium = 11f;
        private const float DesignClaimH = 28f;
        private const float DesignClaimHPremium = 26f;
        private const float DesignClaimGap = 4f;
        private const float DesignClaimPadX = 16f;

        private const float DesignNumFont = 34f;
        private const float DesignNumOffset = 18f;
        private const float DesignCheck = 28f;
        private const float DesignCheckOffset = 8f;
        private const float DesignCheckFont = 15f;

        /// <summary>Alto de la pila vertical completa a escala 1: 792px.</summary>
        private const float StackHeight =
            DesignPadTop + DesignPadBottom + DesignMedal
            + 2f * (DesignCardMargin + DesignTick + DesignCardH);

        /// <summary>Nunca por debajo del 50%: es el mínimo legible del interior.</summary>
        private const float MinScale = 0.5f;

        /// <summary>Escala aplicada la última vez (0 = pendiente de pintar).</summary>
        private float _trackScale;

        /// <summary>Queda un centrado de la pista por aplicar (layout pendiente).</summary>
        private bool _trackScrollPending;

        /// <summary>
        /// Ajusta la pista al alto disponible. Se dispara con la geometría del
        /// ScrollView (primer layout y redimensionado) y tras cada repintado.
        /// Si la escala no cambia, no toca nada.
        /// </summary>
        private void FitTrack()
        {
            if (_track == null || _trackScroll == null) return;
            var viewport = _trackScroll.contentViewport;
            if (viewport == null) return;

            if (_vertical)
            {
                FitTrackVertical(viewport);
                return;
            }

            float avail = viewport.layout.height;
            if (avail <= 1f) return;

            float k = Mathf.Clamp(avail / StackHeight, MinScale, 1f);
            if (Mathf.Abs(k - _trackScale) < 0.005f) return;
            _trackScale = k;

            _track.style.paddingTop = DesignPadTop * k;
            _track.style.paddingBottom = DesignPadBottom * k;

            float medal = DesignMedal * k;
            float check = DesignCheck * k;

            foreach (var tier in _track.Children())
            {
                tier.style.width = DesignTierW * k;

                foreach (var el in tier.Children())
                {
                    if (el.ClassListContains("season-reward"))
                    {
                        bool premium = el.ClassListContains("season-reward-premium");
                        el.style.width = DesignCardW * k;
                        el.style.height = DesignCardH * k;
                        el.style.marginTop = DesignCardMargin * k;
                        el.style.paddingTop = (premium ? DesignPremiumPadTop : DesignBasicPadTop) * k;
                        el.style.paddingBottom = (premium ? DesignPremiumPadBottom : DesignBasicPadBottom) * k;
                        el.style.paddingLeft = (premium ? DesignPremiumPadSide : DesignBasicPadSide) * k;
                        el.style.paddingRight = el.style.paddingLeft;
                        ScaleCardInterior(el, premium, k);
                    }
                    else if (el.ClassListContains("season-tick"))
                    {
                        el.style.height = DesignTick * k;
                        el.style.width = DesignTickW * k;
                    }
                    else if (el.ClassListContains("season-node"))
                    {
                        el.style.height = medal;
                        foreach (var part in el.Children())
                        {
                            if (part.ClassListContains("season-node-line"))
                            {
                                part.style.height = DesignLine * k;
                                continue;
                            }
                            if (!part.ClassListContains("season-medal")) continue;
                            part.style.width = medal;
                            part.style.height = medal;
                            foreach (var inner in part.Children())
                            {
                                if (inner.ClassListContains("season-medal-num"))
                                {
                                    inner.style.fontSize = DesignNumFont * k;
                                    inner.style.marginTop = DesignNumOffset * k;
                                }
                                else if (inner.ClassListContains("season-medal-check"))
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

        // ── Pista vertical (móvil en vertical) ──────────────────────────
        //
        // Cada nivel es una fila: carta libre · tick · medallón · tick · carta real.
        // La escala sale del ANCHO disponible (no del alto) y puede pasar de 1
        // para que cartas y textos se lean bien en pantallas pequeñas.

        private const float VerticalRowGap = 10f;
        private const float VerticalRowW = DesignCardW * 2f + DesignTick * 2f + DesignMedal;
        private const float VerticalMaxScale = 1.4f;

        private void FitTrackVertical(VisualElement viewport)
        {
            float avail = viewport.layout.width;
            if (avail <= 1f) return;

            float k = Mathf.Clamp(avail / VerticalRowW, MinScale, VerticalMaxScale);
            if (Mathf.Abs(k - _trackScale) < 0.005f) return;
            _trackScale = k;

            _track.style.paddingTop = 10f * k;
            _track.style.paddingBottom = 24f * k;
            _track.style.paddingLeft = 0f;
            _track.style.paddingRight = 0f;

            float medal = DesignMedal * k;
            float rowH = (DesignCardH + 2f * VerticalRowGap) * k;

            if (_laneHead != null)
            {
                _laneHead.style.width = VerticalRowW * k;
                _laneLibre.style.width = DesignCardW * k;
                _laneReal.style.width = DesignCardW * k;
            }

            foreach (var tier in _track.Children())
            {
                tier.style.width = VerticalRowW * k;
                tier.style.height = rowH;

                foreach (var el in tier.Children())
                {
                    if (el.ClassListContains("season-reward"))
                    {
                        bool premium = el.ClassListContains("season-reward-premium");
                        el.style.width = DesignCardW * k;
                        el.style.height = DesignCardH * k;
                        el.style.marginTop = 0f;
                        el.style.paddingTop = (premium ? DesignPremiumPadTop : DesignBasicPadTop) * k;
                        el.style.paddingBottom = (premium ? DesignPremiumPadBottom : DesignBasicPadBottom) * k;
                        el.style.paddingLeft = (premium ? DesignPremiumPadSide : DesignBasicPadSide) * k;
                        el.style.paddingRight = el.style.paddingLeft;
                        ScaleCardInterior(el, premium, k);
                    }
                    else if (el.ClassListContains("season-tick"))
                    {
                        el.style.width = DesignTick * k;
                        el.style.height = DesignTickW * k;
                    }
                    else if (el.ClassListContains("season-node"))
                    {
                        el.style.width = medal;
                        el.style.height = rowH;
                        foreach (var part in el.Children())
                        {
                            if (part.ClassListContains("season-node-line"))
                            {
                                part.style.width = DesignLine * k;
                                continue;
                            }
                            if (part.ClassListContains("season-medal"))
                            {
                                part.style.width = medal;
                                part.style.height = medal;
                                ScaleMedalInterior(part, k);
                            }
                        }
                    }
                }
            }
        }

        private static void ScaleMedalInterior(VisualElement medalEl, float k)
        {
            float check = DesignCheck * k;
            foreach (var inner in medalEl.Children())
            {
                if (inner.ClassListContains("season-medal-num"))
                {
                    inner.style.fontSize = DesignNumFont * k;
                    inner.style.marginTop = DesignNumOffset * k;
                }
                else if (inner.ClassListContains("season-medal-check"))
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

        /// <summary>
        /// Escala el interior de una carta (arte, nombre, valor y píldora)
        /// con la misma k que la caja: a k = 0,6 el texto mide 0,6 de su
        /// tamaño de diseño, así la carta es una copia fiel y nada se
        /// sale de la ventana segura del marco.
        /// </summary>
        private static void ScaleCardInterior(VisualElement card, bool premium, float k)
        {
            foreach (var child in card.Children())
            {
                if (child.ClassListContains("season-reward-art"))
                {
                    child.style.height = DesignArtH * k;
                    child.style.minHeight = DesignArtMin * k;
                    child.style.marginBottom = DesignArtGap * k;
                }
                else if (child.ClassListContains("season-reward-icon"))
                {
                    child.style.fontSize = (premium ? DesignIconFontPremium : DesignIconFont) * k;
                    child.style.height = (premium ? DesignIconHPremium : DesignIconH) * k;
                    child.style.minHeight = DesignIconMin * k;
                }
                else if (child.ClassListContains("season-reward-name"))
                {
                    child.style.fontSize = (premium ? DesignNameFontPremium : DesignNameFont) * k;
                    child.style.height = (premium ? DesignNameHPremium : DesignNameH) * k;
                }
                else if (child.ClassListContains("season-reward-amount"))
                {
                    bool tag = child.ClassListContains("season-reward-amount-tag");
                    child.style.fontSize = (tag ? (premium ? DesignTagFontPremium : DesignTagFont) : premium ? DesignAmountFontPremium : DesignAmountFont) * k;
                    child.style.height = (tag ? DesignTagH : premium ? DesignAmountHPremium : DesignAmountH) * k;
                }
                else if (child.ClassListContains("season-claim"))
                {
                    float h = (premium ? DesignClaimHPremium : DesignClaimH) * k;
                    child.style.fontSize = (premium ? DesignClaimFontPremium : DesignClaimFont) * k;
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

        /// <summary>
        /// Columna de nivel en línea temporal: carta gratuita arriba, tick
        /// vertical, nudo (media-línea + medallón SOBRE la barra + media-línea),
        /// tick vertical y carta real abajo. Todo centrado en la columna.
        /// </summary>
        private VisualElement BuildTier(int tier, bool unlocked, bool premium, int level)
        {
            var col = new VisualElement { name = $"season-tier-{tier}" };
            col.AddToClassList("season-tier");
            if (unlocked) col.AddToClassList("season-tier-unlocked");
            else col.AddToClassList("season-tier-locked");

            col.Add(BuildRewardCard(tier, premium: false, unlocked: unlocked));

            col.Add(BuildTick(unlocked));

            // Nudo sobre la barra: la línea continua pasa por el medallón.
            var node = new VisualElement();
            node.AddToClassList("season-node");
            node.pickingMode = PickingMode.Ignore;

            var lineL = new VisualElement();
            lineL.AddToClassList("season-node-line");
            if (unlocked) lineL.AddToClassList("season-node-line-done");
            if (tier == 1) lineL.AddToClassList("season-node-line-hidden");
            node.Add(lineL);

            // Medallón del nivel (seasonpass_tier.png por USS + respaldo por código).
            // El ✓ marca COBRO REAL (persistido), no nivel: el XP derivado puede
            // bajar (reseteo semanal) y el nivel caerse, pero lo cobrado sigue cobrado.
            var medal = new VisualElement();
            medal.AddToClassList("season-medal");
            SeasonPassSprites.Apply(medal, SeasonPassSprites.Tier);
            var num = new Label(tier.ToString("00"));
            num.AddToClassList("season-medal-num");
            num.pickingMode = PickingMode.Ignore;
            medal.Add(num);
            bool tierClaimed = IsBasicClaimed(tier) || IsPremiumClaimed(tier);
            if (tierClaimed)
            {
                var check = new Label("✓");
                check.AddToClassList("season-medal-check");
                check.pickingMode = PickingMode.Ignore;
                medal.Add(check);
            }
            medal.tooltip = tierClaimed ? $"Nivel {tier} cobrado"
                : unlocked ? $"Nivel {tier} desbloqueado"
                : $"Nivel {tier} · te faltan {(tier * XpPerTier - EffectiveXp):N0} XP";
            node.Add(medal);

            var lineR = new VisualElement();
            lineR.AddToClassList("season-node-line");
            if (level > tier) lineR.AddToClassList("season-node-line-done");
            if (tier == TierCount) lineR.AddToClassList("season-node-line-hidden");
            node.Add(lineR);

            col.Add(node);

            col.Add(BuildTick(unlocked));

            col.Add(BuildRewardCard(tier, premium: true, unlocked: unlocked && premium, needsPremium: !premium));

            return col;
        }

        /// <summary>Línea vertical que une cada carta con la barra central.</summary>
        private static VisualElement BuildTick(bool done)
        {
            var tick = new VisualElement();
            tick.AddToClassList("season-tick");
            if (done) tick.AddToClassList("season-tick-done");
            tick.pickingMode = PickingMode.Ignore;
            return tick;
        }

        private VisualElement BuildRewardCard(int tier, bool premium, bool unlocked, bool needsPremium = false)
        {
            Reward r = RewardAt(tier, premium);
            bool claimed = premium ? IsPremiumClaimed(tier) : IsBasicClaimed(tier);

            var card = new VisualElement();
            card.AddToClassList("season-reward");
            card.AddToClassList(premium ? "season-reward-premium" : "season-reward-basic");
            if (claimed) card.AddToClassList("season-reward-claimed");
            else if (unlocked) card.AddToClassList("season-reward-ready");
            else card.AddToClassList("season-reward-locked");

            // El fondo (slot basic / premium) viene del USS; respaldo por código.
            SeasonPassSprites.Apply(card, premium ? SeasonPassSprites.SlotPremium : SeasonPassSprites.SlotBasic);

            // Arte del objeto si su categoría trae miniatura; si no, el emoji.
            // Rework premium: el frame lleva marca interior (el contenedor no se toca).
            var art = ArtFor(r);
            if (art != null)
            {
                var frame = new VisualElement();
                frame.AddToClassList("season-reward-art");
                if (premium) frame.AddToClassList("season-reward-art-premium");
                frame.pickingMode = PickingMode.Ignore;
                frame.style.backgroundImage = new StyleBackground(art);
                card.Add(frame);
            }
            else
            {
                var icon = new Label(r.icon);
                icon.AddToClassList("season-reward-icon");
                icon.pickingMode = PickingMode.Ignore;
                card.Add(icon);
            }

            var name = new Label(r.name.ToUpperInvariant());
            name.AddToClassList("season-reward-name");
            if (premium) name.AddToClassList(NameClassFor(r));
            name.pickingMode = PickingMode.Ignore;
            card.Add(name);

            var amount = new Label(TagFor(r));
            amount.AddToClassList("season-reward-amount");
            if (r.kind != RewardKind.Gambits && r.kind != RewardKind.Dulces)
                amount.AddToClassList("season-reward-amount-tag");
            amount.pickingMode = PickingMode.Ignore;
            card.Add(amount);

            if (claimed)
            {
                var done = new Label("✓ COBRADO");
                done.AddToClassList("season-claim");
                done.AddToClassList("season-claim-done");
                card.Add(done);
            }
            else if (needsPremium)
            {
                var lockPill = new Label("🔒 REAL");
                lockPill.AddToClassList("season-claim");
                lockPill.AddToClassList("season-claim-premium");
                card.Add(lockPill);
            }
            else if (unlocked && !IsPreSeason)
            {
                var btn = new Button(() => OnClaim(tier, premium, r)) { text = "COBRAR" };
                btn.AddToClassList("season-claim");
                btn.AddToClassList("season-claim-ready");
                btn.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
                card.Add(btn);
            }
            else
            {
                var locked = new Label($"NIVEL {tier}");
                locked.AddToClassList("season-claim");
                locked.AddToClassList("season-claim-locked");
                card.Add(locked);
            }

            card.tooltip = $"{(premium ? "Real" : "Libre")} · Nivel {tier} · {r.name} · {TagFor(r)}"
                         + (claimed ? " (cobrado)" : unlocked ? "" : " (bloqueado)");
            return card;
        }

        // ── Acciones ────────────────────────────────────────────────────

        /// <summary>
        /// Entrega el premio y <b>verifica</b> que quedó en posesión del jugador
        /// (saldo, propiedad de skin/variante/animación/fondo/tablero). Devuelve
        /// false si no se pudo completar (catálogo, tope o fallo de guardado):
        /// entonces el nivel NO se consume y se puede cobrar de nuevo.
        /// Los Gambits del pase usan la fuente SeasonPass con bypassCaps: son un
        /// derecho ya ganado y los topes diarios de farming no deben recortarlos.
        /// </summary>
        private bool TryGrant(Reward r, int tier, bool premium, out string detail)
        {
            detail = null;
            string where = $"Pase T{tier} {(premium ? "Real" : "Libre")}";
            string onFail = $"{r.name} · no se pudo desbloquear; vuelve a intentarlo";

            switch (r.kind)
            {
                case RewardKind.Gambits:
                {
                    if (r.gambits <= 0)
                    {
                        detail = "Recompensa vacía";
                        return false;
                    }
                    GambitPayout payout;
                    try
                    {
                        payout = GambitEconomy.Earn(r.gambits, GambitSource.SeasonPass,
                            meta: "seasonpass", note: where, bypassCaps: true);
                    }
                    catch (Exception e)
                    {
                        Debug.LogWarning($"[SeasonPassModal] No se pudo abonar la recompensa: {e.Message}");
                        detail = onFail;
                        return false;
                    }
                    if (payout.granted < r.gambits)
                    {
                        detail = payout.limitReason != null ? $"{payout.limitReason} · vuelve a intentarlo" : onFail;
                        return false;
                    }
                    detail = $"{r.gambits:N0} Gambits · {(premium ? "Gambito Real" : "Gambito Libre")}";
                    return true;
                }

                case RewardKind.Dulces:
                {
                    if (r.dulces <= 0)
                    {
                        detail = "Recompensa vacía";
                        return false;
                    }
                    HalloweenCurrency.Earn(r.dulces, where);
                    detail = $"{r.dulces:N0} {HalloweenCurrency.Label} · moneda de la velada de Halloween";
                    return true;
                }

                case RewardKind.Reroll:
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

                case RewardKind.Skin:
                {
                    // El índice de la tabla se resuelve al cargar; si el catálogo
                    // cambió, se vuelve a buscar por id antes de rendirse.
                    int idx = string.IsNullOrEmpty(r.refId) ? -1 : PieceSkinManager.GetIndexById(r.refId);
                    if (idx < 0) idx = r.index;
                    if (idx < 0)
                    {
                        Debug.LogWarning($"[SeasonPassModal] Skin «{r.refId}» no está en el catálogo.");
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
                        Debug.LogError($"[SeasonPassModal] OwnSkin no quedó persistido para «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · pieza desbloqueada";
                    return true;
                }

                case RewardKind.Variant:
                {
                    bool verified;
                    switch (r.refId)
                    {
                        case "necromancer":
                            if (PieceLoadoutManager.IsNecroOwned()) { detail = $"{r.name} · ya la tenías"; return true; }
                            PieceLoadoutManager.OwnNecro();
                            verified = PieceLoadoutManager.IsNecroOwned();
                            break;
                        case "lancer":
                            if (PieceLoadoutManager.IsLancerOwned()) { detail = $"{r.name} · ya la tenías"; return true; }
                            PieceLoadoutManager.OwnLancer();
                            verified = PieceLoadoutManager.IsLancerOwned();
                            break;
                        case "rider":
                            if (PieceLoadoutManager.IsRiderOwned()) { detail = $"{r.name} · ya la tenías"; return true; }
                            PieceLoadoutManager.OwnRider();
                            verified = PieceLoadoutManager.IsRiderOwned();
                            break;
                        case "fragua":
                            if (PieceLoadoutManager.IsFraguaOwned()) { detail = $"{r.name} · ya la tenías"; return true; }
                            PieceLoadoutManager.OwnFragua();
                            verified = PieceLoadoutManager.IsFraguaOwned();
                            break;
                        default:
                            Debug.LogWarning($"[SeasonPassModal] Variante desconocida «{r.refId}».");
                            detail = onFail;
                            return false;
                    }
                    if (!verified)
                    {
                        Debug.LogError($"[SeasonPassModal] Own no quedó persistido para «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    GambitProgress.SyncVariantsOwned();
                    detail = $"{r.name} · variante desbloqueada";
                    return true;
                }

                case RewardKind.Animation:
                {
                    // Own() y no OwnAndEquip(): regalar no debe pisar la equipped.
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
                        Debug.LogWarning($"[SeasonPassModal] Animación desconocida «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    if (owned) { detail = $"{r.name} · ya la tenías"; return true; }
                    if (!verified)
                    {
                        Debug.LogError($"[SeasonPassModal] Own() no quedó persistido para «{r.refId}».");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · animación desbloqueada";
                    return true;
                }

                case RewardKind.Backdrop:
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
                        Debug.LogError($"[SeasonPassModal] Unlock no quedó persistido para fondo #{r.index}.");
                        detail = onFail;
                        return false;
                    }
                    detail = $"{r.name} · fondo desbloqueado";
                    return true;
                }

                case RewardKind.Board:
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
                        Debug.LogError($"[SeasonPassModal] Unlock no quedó persistido para tablero #{r.index}.");
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

        private void OnClaim(int tier, bool premium, Reward reward)
        {
            if (_claimAnimating) return;

            // El pase todavía no empezó: nada es cobrable (ni aunque el nivel
            // esté desbloqueado por XP de antes).
            if (IsPreSeason)
            {
                _onToast?.Invoke("Pase de pretemporada",
                    $"El temporada arranca el {SeasonStart:dd/MM} · el XP empieza a contar ese día");
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                return;
            }

            if (LevelFor(EffectiveXp) < tier) return;
            if (premium && !HasPremium)
            {
                _onToast?.Invoke("Gambito Real", "Activa la vía real para cobrar esta recompensa");
                return;
            }
            if (premium ? IsPremiumClaimed(tier) : IsBasicClaimed(tier)) return;

            if (!TryGrant(reward, tier, premium, out string detail))
            {
                _onToast?.Invoke($"Nivel {tier} sin cobrar", detail ?? "El premio no está disponible ahora");
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                return;
            }

            SetClaimed(tier, premium);
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            GambitProgress.NotifyChanged(); // repinta la pista vía la suscripción a OnChanged
            ShowClaimOverlay(reward, tier, premium, detail);
        }

        // ── Animación de reclamación: overlay + pop de la recompensa ────
        //
        // Al cobrar se superpone una capa oscura a todo el modal y la tarjeta
        // de la recompensa entra con rebote (ease-out-back), los textos suben
        // con desfase, los destellos titilan durante la pausa y todo sale con
        // fundido. Mientras el overlay está vivo no se puede cobrar otra vez.

        private void ShowClaimOverlay(Reward reward, int tier, bool premium, string detail)
        {
            _claimToastTitle = $"Nivel {tier} cobrado";
            _claimToastDetail = detail;

            if (_root == null)
            {
                // Sin raíz no hay animación posible: el cobro ya está hecho.
                FinishClaimOverlay();
                return;
            }

            _claimTicker?.Pause();
            _claimOverlay?.RemoveFromHierarchy();

            var overlay = new VisualElement();
            overlay.name = "season-claim-overlay";
            overlay.style.position = Position.Absolute;
            overlay.style.left = 0;
            overlay.style.top = 0;
            overlay.style.right = 0;
            overlay.style.bottom = 0;
            overlay.style.justifyContent = Justify.Center;
            overlay.style.alignItems = Align.Center;
            overlay.style.backgroundColor = new Color(0.008f, 0.016f, 0.04f, 0f);

            var card = new VisualElement();
            card.style.width = 440;
            card.style.maxWidth = Length.Percent(92f);
            card.style.paddingLeft = 30;
            card.style.paddingRight = 30;
            card.style.paddingTop = 24;
            card.style.paddingBottom = 26;
            card.style.alignItems = Align.Center;
            card.style.backgroundColor = new Color(0.043f, 0.071f, 0.149f, 0.97f); // #0B1226
            card.style.borderTopWidth = 2;
            card.style.borderBottomWidth = 2;
            card.style.borderLeftWidth = 2;
            card.style.borderRightWidth = 2;
            card.style.borderTopColor = new Color(0.941f, 0.824f, 0.478f);         // #F0D27A
            card.style.borderBottomColor = new Color(0.831f, 0.686f, 0.290f);       // #D4B36A
            card.style.borderLeftColor = new Color(0.831f, 0.686f, 0.290f);
            card.style.borderRightColor = new Color(0.831f, 0.686f, 0.290f);
            card.style.borderTopLeftRadius = 20;
            card.style.borderTopRightRadius = 20;
            card.style.borderBottomLeftRadius = 20;
            card.style.borderBottomRightRadius = 20;
            card.style.opacity = 0f;
            card.style.scale = new Scale(new Vector2(0.45f, 0.45f));

            var kicker = new Label(premium ? "RECOMPENSA REAL COBRADA" : "RECOMPENSA COBRADA");
            kicker.style.fontSize = 11;
            kicker.style.unityFontStyleAndWeight = FontStyle.Bold;
            kicker.style.color = new Color(0.478f, 0.541f, 0.690f); // #7A8AB0
            kicker.style.unityTextAlign = TextAnchor.MiddleCenter;
            kicker.style.marginBottom = 12;
            card.Add(kicker);

            // Miniatura del objeto (o emoji de respaldo), siempre centrada.
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
                icon.style.color = new Color(0.941f, 0.824f, 0.478f);
                icon.style.unityTextAlign = TextAnchor.MiddleCenter;
                icon.style.height = 140;
                icon.style.marginTop = 4;
                card.Add(icon);
            }

            // Textos en un bloque para animarlos juntos (entran deslizando).
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
            tag.style.color = new Color(0.941f, 0.824f, 0.478f);
            tag.style.unityTextAlign = TextAnchor.MiddleCenter;
            tag.style.marginTop = 4;
            details.Add(tag);

            if (!string.IsNullOrEmpty(detail))
            {
                var sub = new Label(detail);
                sub.style.fontSize = 13;
                sub.style.color = new Color(0.624f, 0.690f, 0.816f); // #9FB0D0
                sub.style.unityTextAlign = TextAnchor.MiddleCenter;
                sub.style.marginTop = 10;
                sub.style.whiteSpace = WhiteSpace.Normal;
                details.Add(sub);
            }

            var level = new Label($"NIVEL {tier} · {(premium ? "GAMBITO REAL" : "GAMBITO LIBRE")}");
            level.style.fontSize = 11;
            level.style.unityFontStyleAndWeight = FontStyle.Bold;
            level.style.color = new Color(0.478f, 0.541f, 0.690f);
            level.style.unityTextAlign = TextAnchor.MiddleCenter;
            level.style.marginTop = 12;
            details.Add(level);

            var sparkles = new Label("✦   ✦   ✦");
            sparkles.style.fontSize = 14;
            sparkles.style.color = new Color(0.941f, 0.824f, 0.478f);
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

            _claimOverlay.style.backgroundColor = new Color(0.008f, 0.016f, 0.04f, bgAlpha);
            _claimCard.style.opacity = cardAlpha;
            _claimCard.style.scale = new Scale(new Vector2(cardScale, cardScale));
            _claimDetails.style.translate = new Translate(new Length(0f, LengthUnit.Pixel), new Length(detailsY, LengthUnit.Pixel));

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

            string title = _claimToastTitle;
            string text = _claimToastDetail;
            _claimToastTitle = null;
            _claimToastDetail = null;
            if (!string.IsNullOrEmpty(title)) _onToast?.Invoke(title, text);
        }

        // ── Modal de compra: precio y cobro vía servidor + Surface ─────
        //
        // Flujo real: GET → precio vigente, propiedad y saldo de la cuenta;
        // POST → el servidor descuenta los Tides y devuelve el nuevo saldo.
        // Sin sesión no se compra: el pie del modal trae su propio login.

        private void OnPremiumClicked()
        {
            if (HasPremium) return;
            OpenBuyView();
        }

        private void OpenBuyView()
        {
            if (_buyView == null) return;
            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            _buyCloseHandle?.Pause();
            _buyCloseHandle = null;
            _buyView.RemoveFromClassList("hidden");
            SetBuyError("");
            _buyBusy = false;
            RefreshBuyView();
            StartBuyAnimation();
            TrySyncSeasonPass();
        }

        /// <param name="playSound">false al cerrar el modal completo o al destruirlo.</param>
        private void CloseBuyView(bool playSound = true)
        {
            _buyCloseHandle?.Pause();
            _buyCloseHandle = null;
            _buyAnimTicker?.Pause();
            _buyAnimTicker = null;
            if (_buyRoutine != null)
            {
                StopCoroutine(_buyRoutine);
                _buyRoutine = null;
            }
            _buyBusy = false;
            if (_buyView == null || _buyView.ClassListContains("hidden")) return;
            if (playSound) WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            _buyView.AddToClassList("hidden");
        }

        private void StartBuyAnimation()
        {
            _buyAnimTicker?.Pause();
            _buyAnimStart = Time.realtimeSinceStartup;
            if (_buyView != null) _buyView.style.opacity = 0f;
            if (_buyWindow != null) _buyWindow.style.scale = new Scale(new Vector2(0.94f, 0.94f));
            if (_buyView == null) return;
            _buyAnimTicker = _buyView.schedule.Execute(TickBuyAnimation).Every(16);
        }

        private void TickBuyAnimation()
        {
            if (_buyView == null) return;
            float t = (Time.realtimeSinceStartup - _buyAnimStart) / BuyInTime;
            bool last = t >= 1f;
            if (last) t = 1f;
            float e = 1f - Mathf.Pow(1f - t, 3f);

            _buyView.style.opacity = e;
            if (_buyWindow != null)
            {
                float s = Mathf.Lerp(0.94f, 1f, e);
                _buyWindow.style.scale = new Scale(new Vector2(s, s));
            }

            if (last)
            {
                _buyAnimTicker?.Pause();
                _buyAnimTicker = null;
            }
        }

        /// <summary>Pinta sesión, saldo, precio y estado de los botones.</summary>
        private void RefreshBuyView()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            bool logged = svc != null && svc.IsLoggedIn;

            if (_buyPrice != null) _buyPrice.text = $"💧 {_buyPriceTides:N0} Tides";

            if (_buyAccount != null)
            {
                _buyAccount.text = logged
                    ? $"Conectado como {svc.SavedUsername} · el cobro se hace en tu cuenta de Surface."
                    : "Inicia sesión con Surface para comprar el Gambito Real con Tides.";
            }

            if (_buyBalance != null)
            {
                float tides = 0f;
                if (logged && svc.CurrentUser != null) tides = svc.CurrentUser.tides;
                else if (!logged) tides = PlayerPrefs.GetInt("PlayerTides", 0);
                _buyBalance.text = logged ? $"💧 {tides:N0} Tides" : "";
                _buyBalance.style.display = logged ? DisplayStyle.Flex : DisplayStyle.None;
            }

            if (_buyLoginRow != null)
                _buyLoginRow.style.display = logged ? DisplayStyle.None : DisplayStyle.Flex;

            if (_btnBuyConfirm != null)
            {
                bool owned = HasPremium;
                _btnBuyConfirm.text = owned
                    ? "✓ GAMBITO REAL ACTIVO"
                    : logged ? $"PAGAR 💧 {_buyPriceTides:N0} TIDES" : "INICIA SESIÓN PARA COMPRAR";
                _btnBuyConfirm.SetEnabled(!owned && logged && !_buyBusy);
            }

            if (_btnBuyLogin != null) _btnBuyLogin.SetEnabled(!_buyBusy);
        }

        private void SetBuyError(string message)
        {
            if (_buyError == null) return;
            _buyError.text = message ?? "";
            _buyError.style.display = string.IsNullOrEmpty(message) ? DisplayStyle.None : DisplayStyle.Flex;
        }

        /// <summary>Pide estado al servidor si hay sesión y no se acaba de pedir.</summary>
        private void TrySyncSeasonPass()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc == null || !svc.IsLoggedIn) return;
            if (Time.realtimeSinceStartup - _buyLastSyncAt < 30f) return;
            StartBuyRoutine(SyncSeasonPassStatus());
        }

        private IEnumerator SyncSeasonPassStatus()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc == null || !svc.IsLoggedIn) yield break;

            _buyLastSyncAt = Time.realtimeSinceStartup;

            // Sin usuario en memoria (token guardado sin validar aún): se
            // reconstruye antes de pedir el estado, para tener saldo real.
            if (svc.CurrentUser == null)
            {
                bool bootstrapped = false;
                yield return svc.TryAutoLoginAsync(_ => bootstrapped = true, () => bootstrapped = false);
                if (!bootstrapped) yield break;
            }

            OceanPayUser.SeasonPassStatusResponse resp = null;
            string error = null;

            yield return svc.GetSeasonPassStatusAsync(
                r => resp = r,
                e => error = e);

            if (resp == null || !resp.success)
            {
                if (_buyView != null && !_buyView.ClassListContains("hidden"))
                    SetBuyError(error ?? "No se pudo consultar el pase con el servidor.");
                yield break;
            }

            if (resp.priceTides > 0) _buyPriceTides = resp.priceTides;

            // Propiedad real en el servidor: manda sobre la marca local.
            // Así las activaciones de prueba antiguas (hechas cuando el pase
            // se activaba sin pagar) se revocan solas al sincronizar.
            if (resp.owned != HasPremium)
            {
                PlayerPrefs.SetInt(KeyPremium, resp.owned ? 1 : 0);
                PlayerPrefs.Save();
                GambitProgress.NotifyChanged();
                Refresh();
                if (!resp.owned)
                    _onToast?.Invoke("Gambito Real verificado",
                        "Aún no está activo en tu cuenta de Surface · actívalo desde el pase");
            }

            RefreshBuyView();
        }

        private void OnBuyConfirm()
        {
            if (_buyBusy || HasPremium) return;

            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc == null || !svc.IsLoggedIn)
            {
                SetBuyError("Inicia sesión con Surface para pagar con Tides.");
                return;
            }

            // El checkout global muestra la revisión, el saldo y los topes.
            // El cobro lo sigue resolviendo el endpoint del pase, que además
            // deja la ventaja activa en el servidor: así nunca se cobra dos veces.
            _buyBusy = true;
            RefreshBuyView();

            WilderGambit.Services.SurfaceCheckoutBridge.BuySeasonPass(
                _buyPriceTides,
                "Gambito Real",
                "Pase de Temporada · desbloquea la vía real completa",
                result =>
                {
                    _buyBusy = false;

                    if (result.cancelled)
                    {
                        RefreshBuyView();
                        return;
                    }

                    if (!result.success)
                    {
                        SetBuyError(string.IsNullOrEmpty(result.message)
                            ? "No se pudo completar el pago."
                            : result.message);
                        WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                        RefreshBuyView();
                        return;
                    }

                    // Cobro aceptado por el servidor: la vía real queda activa.
                    PlayerPrefs.SetInt(KeyPremium, 1);
                    PlayerPrefs.SetInt("PlayerTides", Mathf.Max(0, Mathf.RoundToInt((float)result.newBalance)));
                    PlayerPrefs.Save();
                    _buyLastSyncAt = Time.realtimeSinceStartup;

                    RefreshBuyView();
                    WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                    GambitProgress.NotifyChanged();
                    Refresh();

                    _onToast?.Invoke(
                        "Gambito Real desbloqueado",
                        result.code == "ALREADY_OWNED"
                            ? "Ya era tuyo en Surface · toda la vía real es reclamable"
                            : $"💧 {result.price:N0} Tides descontados de tu cuenta · toda la vía real es reclamable");

                    // Un momento para leer el comprobante y volver al pase.
                    _buyCloseHandle = _buyView.schedule.Execute(() => CloseBuyView()).StartingIn(1500);
                });
        }

        private void OnBuyLogin()
        {
            if (_buyBusy) return;

            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc == null)
            {
                SetBuyError("Surface no está disponible ahora.");
                return;
            }

            string user = _buyUser?.value?.Trim() ?? "";
            string pass = _buyPass?.value ?? "";
            if (string.IsNullOrEmpty(user)) { SetBuyError("Ingresa tu usuario de Surface."); return; }
            if (string.IsNullOrEmpty(pass)) { SetBuyError("Ingresa tu contraseña de Surface."); return; }

            StartBuyRoutine(DoBuyLogin(user, pass));
        }

        private IEnumerator DoBuyLogin(string user, string pass)
        {
            _buyBusy = true;
            SetBuyError("");
            RefreshBuyView();
            if (_buyAccount != null) _buyAccount.text = "Conectando con Surface…";

            OceanPayUser loggedUser = null;
            string error = null;
            yield return WilderGambit.Services.OceanPayService.Instance.LoginAsync(
                user, pass,
                u => loggedUser = u,
                e => error = e);

            _buyBusy = false;

            if (loggedUser == null || !string.IsNullOrEmpty(error))
            {
                SetBuyError(error ?? "No se pudo iniciar sesión.");
                WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
                RefreshBuyView();
                yield break;
            }

            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            RefreshBuyView();
            yield return SyncSeasonPassStatus();
        }

        private void OnBuyFieldKey(KeyDownEvent evt)
        {
            if (evt.keyCode != KeyCode.Return && evt.keyCode != KeyCode.KeypadEnter) return;
            OnBuyLogin();
            evt.StopPropagation();
        }

        private void StartBuyRoutine(IEnumerator routine)
        {
            if (_buyRoutine != null) StopCoroutine(_buyRoutine);
            _buyBusy = true;
            RefreshBuyView();
            _buyRoutine = StartCoroutine(BuyRoutineWrapper(routine));
        }

        private IEnumerator BuyRoutineWrapper(IEnumerator routine)
        {
            yield return routine;
            _buyRoutine = null;
            _buyBusy = false;
            RefreshBuyView();
        }

        // ── Limpieza de temporada (editor / cambio de temporada) ────────

        public static void DebugReset()
        {
            PlayerPrefs.DeleteKey(SeasonProgress.Key);
            PlayerPrefs.DeleteKey(KeyPremium);
            for (int i = 1; i <= TierCount; i++)
            {
                PlayerPrefs.DeleteKey(ClaimKey(KeyClaimBasic, i));
                PlayerPrefs.DeleteKey(ClaimKey(KeyClaimPremium, i));
            }
            PlayerPrefs.Save();
            GambitProgress.NotifyChanged();
        }
    }
}
