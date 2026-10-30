using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Manager estático para skins animadas. Soporta ScriptableObject + fallback hardcodeado.
    /// Persistencia vía PlayerPrefs: ownership y selección por tipo de pieza.
    /// Moneda: Gambits (int). Usa OceanPayService si existe, fallback a PlayerPrefs local.
    /// </summary>
    public static class PieceSkinManager
    {
        private const string PREF_OWNED_PREFIX = "Skin_Owned_";
        private const string PREF_SELECTED_PREFIX = "Skin_Selected_";
        private const string PREF_LOCAL_GAMBITS = "LocalGambits_Balance";

        private static PieceSkinLibrary _library;
        public static PieceSkinLibrary Library => _library;
        public static void SetLibrary(PieceSkinLibrary lib) => _library = lib;

        // ── Fallback Skins (hardcodeadas, usadas si no hay SO asignado) ──
        public struct FallbackSkin
        {
            public string id;
            public string displayName;
            public PieceType pieceType;
            public string description;
            public int price;
            public bool unlockedByDefault;
            public Color tint;
            public SkinAnimation anim;
            public SkinRarity rarity;
            public string icon;

            public FallbackSkin(string id, string name, PieceType type, string desc, int price, bool unlocked, Color tint, SkinAnimation anim, SkinRarity rarity, string icon)
            {
                this.id = id; this.displayName = name; this.pieceType = type; this.description = desc;
                this.price = price; this.unlockedByDefault = unlocked; this.tint = tint; this.anim = anim; this.rarity = rarity; this.icon = icon;
            }
        }

        public static readonly FallbackSkin[] FallbackSkins = new FallbackSkin[]
        {
            new FallbackSkin("skin_knight_fire",     "Forja Ígnea",        PieceType.Knight, "Caballo envuelto en llamas. Respiración ígnea + brasas flotantes.", 0,    true,  new Color(1f, 0.52f, 0.15f), SkinAnimation.Fire,     SkinRarity.Rare,      "🔥"),
            new FallbackSkin("skin_bishop_frost",    "Escarcha Eterna",    PieceType.Bishop, "Alfil glacial con aura helada y brillo cristalino.",         650,  false, new Color(0.55f, 0.85f, 1f),   SkinAnimation.Ice,      SkinRarity.Rare,      "❄️"),
            new FallbackSkin("skin_queen_shadow",    "Espectro Umbrío",    PieceType.Queen,  "Dama sombría que pulsa con energía espectral.",              1200, false, new Color(0.65f, 0.45f, 0.85f), SkinAnimation.Spectral, SkinRarity.Epic,      "🌫️"),
            new FallbackSkin("skin_king_solar",      "Aura Solar",         PieceType.King,   "Rey dorado con respiración solar y destellos.",               1000, false, new Color(1f, 0.85f, 0.35f),  SkinAnimation.Solar,    SkinRarity.Epic,      "☀️"),
            new FallbackSkin("skin_rook_abyss",      "Vórtice Abisal",     PieceType.Rook,   "Torre abisal con remolino oceánico.",                         700,  false, new Color(0.25f, 0.55f, 0.85f), SkinAnimation.Abyssal,  SkinRarity.Rare,      "🌊"),
            new FallbackSkin("skin_pawn_sprout",     "Brote Silvestre",    PieceType.Pawn,   "Peón silvestre con hojas que brotan y caen.",                 400,  false, new Color(0.45f, 0.85f, 0.35f), SkinAnimation.Breathing, SkinRarity.Common,   "🌿"),
            new FallbackSkin("skin_necro_pulse",     "Luz Necrótica",      PieceType.NecromancerBishop, "Nigromante con pulso necrótico verde esmeralda.",  900,  false, new Color(0.35f, 0.95f, 0.55f), SkinAnimation.Necrotic, SkinRarity.Epic,      "💀"),
            new FallbackSkin("skin_knight_obsidian", "Centinela Obsidiana",PieceType.Knight, "Caballo de obsidiana con ascuas flotantes.",                  750,  false, new Color(0.22f, 0.22f, 0.28f), SkinAnimation.Embers,  SkinRarity.Rare,      "🗿"),
            // ── Colección SKINS (solo visuales, sin pasiva ni ventaja) ──
            new FallbackSkin("skin_pawn_golden",   "Legión Dorada",      PieceType.Pawn,   "Peón con baño dorado de la guardia del palacio. Brillo cálido al respirar.", 350,  false, new Color(1f, 0.78f, 0.30f),  SkinAnimation.Breathing, SkinRarity.Uncommon,  "🛡️"),
            new FallbackSkin("skin_knight_storm", "Corcel de Tormenta", PieceType.Knight, "Caballo envuelto en arcos voltaicos azules. Crepita al moverse.",            1200, false, new Color(0.35f, 0.60f, 1f),   SkinAnimation.Spectral, SkinRarity.Epic,      "⛈️"),
            new FallbackSkin("skin_bishop_gilded","Catedral Dorada",    PieceType.Bishop, "Alfil de vitral consagrado con halo solar suave.",                          1600, false, new Color(0.98f, 0.88f, 0.65f), SkinAnimation.Solar,     SkinRarity.Legendary, "🕯️"),
            new FallbackSkin("skin_rook_crimson", "Bastión Carmesí",    PieceType.Rook,   "Torre de piedra roja con brasas vivas en las almenas.",                      750,  false, new Color(0.78f, 0.20f, 0.24f), SkinAnimation.Embers,    SkinRarity.Rare,      "🏰"),
            new FallbackSkin("skin_queen_roses",  "Jardín de Rosas",     PieceType.Queen,  "Dama coronada de pétalos con respiración primaveral.",                      1800, false, new Color(0.96f, 0.45f, 0.60f), SkinAnimation.Breathing, SkinRarity.Legendary, "🌹"),
            new FallbackSkin("skin_king_eclipse", "Eclipse Eterno",      PieceType.King,   "Rey de obsidiana coronado por un eclipse violeta.",                        2500, false, Color.white, SkinAnimation.None,  SkinRarity.Mythic,    "🌑"),
            new FallbackSkin("skin_king_igneous", "Rey Ígneo",           PieceType.King,   "Rey forjado en el corazón de la fragua. Respiración de fuego y brasas.",     3000, false, new Color(1f, 0.45f, 0.12f),       SkinAnimation.Fire,      SkinRarity.Mythic,    "👑"),
            new FallbackSkin("skin_necro_lunar",  "Marea Lunar",         PieceType.NecromancerBishop, "Nigromante bañado en luz de luna con pulso espectral frío.",   650,  false, new Color(0.70f, 0.85f, 1f),   SkinAnimation.Spectral,  SkinRarity.Rare,      "🌙"),
            // ── Velada de Halloween (esculpidas de la velada; arte en Resources/Skins) ──
            new FallbackSkin("skin_pawn_halloween",  "Peón de Brasa",    PieceType.Pawn,  "Peón esculpido en piedra con vetas de brasa viva.",                500,  false, new Color(1f, 0.52f, 0.22f),    SkinAnimation.Embers,   SkinRarity.Uncommon,  "🎃"),
            new FallbackSkin("skin_rook_halloween",  "Torre de Musgo",   PieceType.Rook,  "Torre de piedra cubierta de musgo con grietas encendidas.",        900,  false, new Color(0.48f, 0.72f, 0.34f), SkinAnimation.Embers,   SkinRarity.Rare,      "🪦"),
            new FallbackSkin("skin_queen_halloween", "Reina Agrietada",  PieceType.Queen, "Dama tallada en roca erosionada; sus grietas respiran luz lunar.", 1500, false, new Color(0.78f, 0.55f, 0.95f), SkinAnimation.Spectral, SkinRarity.Epic,      "🕸️"),
            new FallbackSkin("skin_king_halloween",  "Rey Esqueleto",    PieceType.King,  "Rey tallado en hueso antiguo; un fulgor espectral respira en sus grietas.", 1200, false, new Color(0.88f, 0.85f, 0.70f), SkinAnimation.Spectral, SkinRarity.Rare, "🦴"),
            // ── Velada de Halloween · tienda de Dulces (arte propio en Resources/Pieces/Halloween) ──
            // Estas cuatro reemplazan el sprite de la pieza en partida (no son de tinte):
            // el nombre del lote viaja en ArtSkinPaths y BoardView lo resuelve por bando.
            new FallbackSkin("skin_pawn_spider", "Peón Araña",         PieceType.Pawn,   "Peón tejido en sombra; el lote de la velada le dio patas.",        55,  false, new Color(0.70f, 0.66f, 0.86f), SkinAnimation.Spectral, SkinRarity.Uncommon, "🕷️"),
            new FallbackSkin("skin_rook_crypt",  "Torre Cripta",       PieceType.Rook,   "Torre sellada con lápidas: la cripta respira frío de piedra.",     70,  false, new Color(0.62f, 0.74f, 0.70f), SkinAnimation.Necrotic, SkinRarity.Rare,     "⚰️"),
            new FallbackSkin("skin_knight_bat",  "Caballo Murciélago", PieceType.Knight, "Caballo de alas de murciélago; cruza la noche larga sin ruido.",   75,  false, new Color(0.55f, 0.45f, 0.78f), SkinAnimation.Embers,   SkinRarity.Rare,     "🦇"),
            new FallbackSkin("skin_rook_grave",  "Torre Tumba",        PieceType.Rook,   "Torre levantada sobre una tumba; la hora muerta la ilumina.",      85,  false, new Color(0.80f, 0.74f, 0.56f), SkinAnimation.Embers,   SkinRarity.Rare,     "🪦"),
            // ── Pase de la Velada 21-30 · arte propio (Resources/Pieces/Halloween) ──
            // Full-art: conservan la silueta de la pieza clásica y solo cambian el
            // material. El tinte va en blanco para no ensuciar el PNG.
            new FallbackSkin("skin_bishop_lantern",   "Alfil Farol",          PieceType.Bishop, "Alfil de hierro forjado y vitral ámbar: la mitra es un farol encendido.",            1200, false, Color.white, SkinAnimation.None, SkinRarity.Rare,      "🏮"),
            new FallbackSkin("skin_knight_scarecrow", "Caballo Espantapájaros", PieceType.Knight, "Caballo de arpillera cosida y melena de paja; el ojo es un botón negro.",          2200, false, Color.white, SkinAnimation.None, SkinRarity.Epic,      "🌾"),
            new FallbackSkin("skin_king_crimson",     "Rey Carmesí",          PieceType.King,   "Rey de obsidiana y marfil, rubí en la cruz y terciopelo carmesí.",                   3800, false, Color.white, SkinAnimation.None, SkinRarity.Mythic,    "🩸"),
            // ── Tienda de la velada · «La Corte» (arte propio, se paga con Dulces) ──
            new FallbackSkin("skin_rook_reliquary",   "Torre Relicario",      PieceType.Rook,   "Torre relicario de hueso y plata vieja, con nichos, cera roja y rubíes.",            2000, false, Color.white, SkinAnimation.None, SkinRarity.Epic,      "⚱️"),
            new FallbackSkin("skin_queen_hex",        "Reina Maleficio",      PieceType.Queen,  "Dama de espino negro y fuego de bruja violeta; perlas de brujería en la corona.",   2800, false, Color.white, SkinAnimation.None, SkinRarity.Legendary, "🔮"),
        };

        /// <summary>
        /// Skins con ARTE PROPIO (no solo tinte): el valor es el nombre del lote
        /// <c>Resources/Pieces/Halloween/hwp_*</c>. BoardView reemplaza el sprite de
        /// la pieza cuando la skin equipada está aquí; las demás siguen siendo tinte + aura.
        /// </summary>
        private static readonly Dictionary<string, string> ArtSkinPaths = new Dictionary<string, string>
        {
            { "skin_pawn_spider", HalloweenArt.PawnSpiderArt },
            { "skin_knight_bat",  HalloweenArt.KnightBatArt  },
            { "skin_rook_crypt",  HalloweenArt.RookCryptArt  },
            { "skin_rook_grave",  HalloweenArt.RookGraveArt  },
            // Pase de la Velada 21-30 (Parte 2): full-art con `_black` propio.
            { "skin_bishop_lantern",   HalloweenArt.BishopLanternArt   },
            { "skin_knight_scarecrow", HalloweenArt.KnightScarecrowArt },
            { "skin_king_crimson",     HalloweenArt.KingCrimsonArt     },
            // Eclipse Eterno pasó de tinte a full-art para que el tablero use la
            // misma pieza que los frames de movimiento / jaque mate.
            { "skin_king_eclipse",     HalloweenArt.KingEclipseArt     },
            // Tienda de la velada · «La Corte»: se pagan con Dulces.
            { "skin_rook_reliquary",   HalloweenArt.RookReliquaryArt   },
            { "skin_queen_hex",        HalloweenArt.QueenHexArt        },
        };

        /// <summary>
        /// Skins que solo se consiguen subiendo el Pase de la Velada. No salen en
        /// el Atelier ni se compran con Gambits: el inventario las agrupa aparte
        /// y, mientras no se posean, solo muestran de dónde salen.
        /// </summary>
        private static readonly HashSet<string> PassExclusiveSkinIds = new HashSet<string>
        {
            // ── Pase de Temporada (Vía libre + Vía real) ──
            // Se cobran subiendo de nivel; no deben venderse en el Atelier.
            "skin_pawn_golden",     // Vía libre
            "skin_pawn_sprout",     // Vía libre
            "skin_bishop_frost",    // Vía real
            "skin_necro_pulse",     // Vía real
            "skin_rook_abyss",      // Vía real
            "skin_knight_obsidian", // Vía real
            "skin_king_solar",      // Vía real
            "skin_queen_shadow",    // Vía real
            "skin_knight_storm",    // Vía real
            "skin_rook_crimson",    // Vía real
            "skin_necro_lunar",     // Vía real
            "skin_king_igneous",    // Vía libre · nivel 30
            // ── Pase de la Velada (Halloween) ──
            // Niveles 1-20 (skins de tinte).
            "skin_pawn_halloween",
            "skin_rook_halloween",
            "skin_queen_halloween",
            "skin_king_halloween",
            // Niveles 21-30 (full-art del lote de la Parte 2). El Peón Golosina
            // quedó fuera de circulación: su arte se reserva para los Gummy Bears.
            "skin_bishop_lantern",
            "skin_knight_scarecrow",
            "skin_king_crimson",
        };

        /// <summary>¿La skin es recompensa del Pase de la Velada? (no se vende con Gambits)</summary>
        public static bool IsPassExclusiveSkin(int index) => PassExclusiveSkinIds.Contains(GetSkinId(index) ?? "");

        /// <summary>
        /// Skins que se venden en la tienda de la velada con Dulces. La lista es
        /// explícita —y debe coincidir con <c>HalloweenShop.SkinOffers</c>— porque
        /// no toda skin con arte propio pertenece a la velada: Eclipse Eterno
        /// también lo tiene y se vende en el Atelier como mítica.
        /// </summary>
        private static readonly HashSet<string> HalloweenShopSkinIds = new HashSet<string>
        {
            "skin_pawn_spider",
            "skin_rook_crypt",
            "skin_knight_bat",
            "skin_rook_grave",
            "skin_rook_reliquary",
            "skin_queen_hex",
        };

        /// <summary>Nombre del arte propio (<c>hwp_*</c>) de una skin, o null si es de tinte.</summary>
        public static string GetSkinArtName(string skinId)
        {
            if (string.IsNullOrEmpty(skinId)) return null;
            return ArtSkinPaths.TryGetValue(skinId, out string art) ? art : null;
        }

        /// <summary>¿La skin trae arte propio? (activa el reemplazo de sprite en el tablero)</summary>
        public static bool IsArtSkin(string skinId) => GetSkinArtName(skinId) != null;

        /// <summary>
        /// ¿Es una de las esculpidas que vende la tienda de la velada con Dulces?
        /// Ojo: es «se vende en el evento», no «se vende con Gambits» — el inventario
        /// las agrupa aparte y no les pone el botón de compra con Gambits.
        /// Las del pase también son full-art, pero no se venden: quedan fuera.
        /// </summary>
        public static bool IsHalloweenShopExclusive(int index)
            => HalloweenShopSkinIds.Contains(GetSkinId(index) ?? "");

        public static int Count => _library != null ? _library.Count : FallbackSkins.Length;

        public static string GetSkinId(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.skinId; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].id;
            return null;
        }

        public static string GetSkinName(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.displayName; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].displayName;
            return "Skin";
        }

        public static string GetSkinDescription(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.description; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].description;
            return "";
        }

        public static PieceType GetSkinPieceType(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.pieceType; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].pieceType;
            return PieceType.Knight;
        }

        public static int GetSkinPrice(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.priceGambits; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].price;
            return 9999;
        }

        public static bool GetSkinUnlockedByDefault(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.unlockedByDefault; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].unlockedByDefault;
            return false;
        }

        public static Color GetSkinTint(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.tintColor; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].tint;
            return Color.white;
        }

        public static SkinAnimation GetSkinAnimation(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.animationId; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].anim;
            return SkinAnimation.None;
        }

        public static SkinRarity GetSkinRarity(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.rarity; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].rarity;
            return SkinRarity.Common;
        }

        public static string GetSkinIcon(int index)
        {
            if (_library != null) { var c = _library.GetSkin(index); if (c != null) return c.iconEmoji; }
            if (index >= 0 && index < FallbackSkins.Length) return FallbackSkins[index].icon;
            return "✨";
        }

        // Caché de miniaturas cargadas desde Resources/Skins/<skinId>.png.
        // El fallo también se cachea (null) para no reintentar Resources.Load en caliente.
        private static readonly Dictionary<string, Texture2D> _thumbCache = new Dictionary<string, Texture2D>();
        private static readonly HashSet<string> _thumbMiss = new HashSet<string>();

        // Con "Fast Play Mode" (sin recarga de dominio) los estáticos sobreviven entre
        // Plays: un fallo transitorio (p. ej. reimport de los PNG en curso) envenenaba
        // la caché de fallos y las skins quedaban en sprite base para siempre.
        // Se reintenta limpio en cada ejecución.
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void ResetThumbnailCache()
        {
            _thumbCache.Clear();
            _thumbMiss.Clear();
        }

        public static Texture2D GetSkinThumbnail(int index)
        {
            if (_library != null)
            {
                var c = _library.GetSkin(index);
                if (c != null && c.thumbnailTexture != null) return c.thumbnailTexture;
            }
            // Fallback: arte 2D en Resources/Skins/<skinId>.png (sin .asset ni escena).
            // Orden como BoardBackgroundManager: disco (Editor, no depende del tipo
            // de importación) y luego Resources (builds, vale Textura o Sprite).
            string id = GetSkinId(index);
            if (string.IsNullOrEmpty(id)) return null;
            if (_thumbCache.TryGetValue(id, out Texture2D cached)) return cached;
            if (_thumbMiss.Contains(id)) return null;

            // 1) Skins con arte propio del lote de la velada (Resources/Pieces/Halloween).
            string artName = GetSkinArtName(id);
            Texture2D tex = !string.IsNullOrEmpty(artName) ? HalloweenArt.LoadTexture(artName) : null;
            // 2) Arte 2D en Resources/Skins/<skinId>.png (sin .asset ni escena).
            // Orden como BoardBackgroundManager: disco (Editor, no depende del tipo
            // de importación) y luego Resources (builds, vale Textura o Sprite).
            if (tex == null) tex = LoadSkinArtFromDisk(id) ?? LoadSkinArtFromResources(id);
            if (tex != null) _thumbCache[id] = tex;
            else
            {
                _thumbMiss.Add(id);
                Debug.LogWarning($"[PieceSkinManager] Sin arte para «{id}»: " +
                                 $"se esperaba {(artName != null ? $"Resources/Pieces/{HalloweenArt.Folder}/{artName}.png" : $"Resources/Skins/{id}.png")}: " +
                                 "la tienda muestra el sprite base.");
            }
            return tex;
        }

        /// <summary>Carga directa del PNG desde disco: no depende del tipo de importación.</summary>
        private static Texture2D LoadSkinArtFromDisk(string skinId)
        {
            try
            {
                string path = System.IO.Path.Combine(Application.dataPath, "Resources/Skins", skinId + ".png");
                if (!System.IO.File.Exists(path)) return null;
                byte[] bytes = System.IO.File.ReadAllBytes(path);
                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                if (tex.LoadImage(bytes))
                {
                    tex.filterMode = FilterMode.Bilinear;
                    return tex;
                }
            }
            catch { /* un PNG roto no tumba la tienda */ }
            return null;
        }

        /// <summary>Vía Resources (builds): vale tanto importada como Textura como Sprite.</summary>
        private static Texture2D LoadSkinArtFromResources(string skinId)
        {
            try
            {
                Texture2D tex = Resources.Load<Texture2D>("Skins/" + skinId);
                if (tex != null) return tex;
                Sprite spr = Resources.Load<Sprite>("Skins/" + skinId);
                if (spr != null && spr.texture != null) return spr.texture;
                Sprite[] all = Resources.LoadAll<Sprite>("Skins/" + skinId);
                if (all != null)
                {
                    foreach (Sprite s in all)
                        if (s != null && s.texture != null) return s.texture;
                }
            }
            catch { /* idem */ }
            return null;
        }

        // ── Ownership ──
        public static bool IsOwned(int index)
        {
            if (GetSkinUnlockedByDefault(index)) return true;
            string id = GetSkinId(index);
            if (string.IsNullOrEmpty(id)) return false;
            return PlayerPrefs.GetInt(PREF_OWNED_PREFIX + id, 0) == 1;
        }

        public static bool IsOwnedById(string skinId)
        {
            if (string.IsNullOrEmpty(skinId)) return false;
            int idx = GetIndexById(skinId);
            if (idx >= 0 && GetSkinUnlockedByDefault(idx)) return true;
            return PlayerPrefs.GetInt(PREF_OWNED_PREFIX + skinId, 0) == 1;
        }

        public static int GetIndexById(string skinId)
        {
            if (_library != null) { int i = _library.GetIndexById(skinId); if (i >= 0) return i; }
            for (int i = 0; i < FallbackSkins.Length; i++) if (FallbackSkins[i].id == skinId) return i;
            return -1;
        }

        public static void OwnSkin(int index)
        {
            string id = GetSkinId(index);
            if (!string.IsNullOrEmpty(id))
            {
                PlayerPrefs.SetInt(PREF_OWNED_PREFIX + id, 1);
                PlayerPrefs.Save();
            }
        }

        /// <summary>
        /// QA: revoca la propiedad de una skin (y la quita si estaba puesta) para
        /// poder recomprarla. Solo lo usa «Wilder Gambit › Halloween».
        /// </summary>
        public static void DebugRevokeOwnership(string skinId)
        {
            if (string.IsNullOrEmpty(skinId)) return;

            PlayerPrefs.DeleteKey(PREF_OWNED_PREFIX + skinId);
            PlayerPrefs.Save();

            int index = GetIndexById(skinId);
            if (index >= 0 && IsEquipped(index)) UnequipSkin(GetSkinPieceType(index));
        }

        // ── Selection ──
        private static string SelectedKey(PieceType type) => PREF_SELECTED_PREFIX + type.ToString();

        public static string GetSelectedSkinId(PieceType type)
        {
            return PlayerPrefs.GetString(SelectedKey(type), "");
        }

        public static bool IsEquipped(int index)
        {
            PieceType type = GetSkinPieceType(index);
            string selected = GetSelectedSkinId(type);
            string id = GetSkinId(index);
            return !string.IsNullOrEmpty(selected) && selected == id;
        }

        public static void EquipSkin(int index)
        {
            if (!IsOwned(index)) return;
            PieceType type = GetSkinPieceType(index);
            string id = GetSkinId(index);
            PlayerPrefs.SetString(SelectedKey(type), id);
            PlayerPrefs.Save();
            Debug.Log($"[PieceSkinManager] Equipada skin {id} para {type}");
        }

        public static void UnequipSkin(PieceType type)
        {
            PlayerPrefs.DeleteKey(SelectedKey(type));
            PlayerPrefs.Save();
        }

        public static PieceSkinConfig GetEquippedConfig(PieceType type)
        {
            string id = GetSelectedSkinId(type);
            if (string.IsNullOrEmpty(id)) return null;
            if (_library != null) return _library.GetSkinById(id);
            return null;
        }

        public static FallbackSkin? GetEquippedFallback(PieceType type)
        {
            string id = GetSelectedSkinId(type);
            if (string.IsNullOrEmpty(id)) return null;
            for (int i = 0; i < FallbackSkins.Length; i++)
                if (FallbackSkins[i].id == id) return FallbackSkins[i];
            return null;
        }

        // ── Currency ── sincronizada con Surface ──
        public static int GetLocalGambits()
        {
            // Si hay sesión Surface, usar el saldo real de la cuenta (0 en la captura)
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc != null && svc.IsLoggedIn && svc.CurrentUser != null)
            {
                return Mathf.RoundToInt(svc.CurrentUser.gambits);
            }
            // Fallback offline: PlayerPrefs local (solo si no hay sesión)
            if (!PlayerPrefs.HasKey(PREF_LOCAL_GAMBITS))
            {
                PlayerPrefs.SetInt(PREF_LOCAL_GAMBITS, 0);
                PlayerPrefs.Save();
            }
            return PlayerPrefs.GetInt(PREF_LOCAL_GAMBITS, 0);
        }

        public static void SetLocalGambits(int value)
        {
            // Sincroniza tanto PlayerPrefs como el CurrentUser en memoria para que el HUD se actualice al instante
            PlayerPrefs.SetInt(PREF_LOCAL_GAMBITS, value);
            PlayerPrefs.Save();
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc != null && svc.CurrentUser != null)
            {
                svc.CurrentUser.gambits = value;
            }
        }

        /// <summary>Suma (o resta) Gambits al saldo y lo sincroniza con Surface en memoria.</summary>
        public static void AddLocalGambits(int delta)
        {
            if (delta == 0) return;
            SetLocalGambits(Mathf.Max(0, GetLocalGambits() + delta));
        }

        public static bool CanAfford(int index)
        {
            return GetLocalGambits() >= GetSkinPrice(index);
        }

        public static bool TryPurchase(int index)
        {
            if (IsOwned(index)) return true;
            int price = GetSkinPrice(index);
            int balance = GetLocalGambits();
            if (balance < price) return false;
            // Descontar y sincronizar con Surface + fallback
            SetLocalGambits(balance - price);
            OwnSkin(index);
            Debug.Log($"[PieceSkinManager] Compra skin {GetSkinId(index)} por {price}G. Restante: {balance - price} (saldo Surface sincronizado)");
            return true;
        }

        /// <summary>Refresca el saldo local desde Surface tras login/refresh.</summary>
        public static void SyncFromOceanPay()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc != null && svc.IsLoggedIn && svc.CurrentUser != null)
            {
                int serverGambits = Mathf.RoundToInt(svc.CurrentUser.gambits);
                PlayerPrefs.SetInt(PREF_LOCAL_GAMBITS, serverGambits);
                PlayerPrefs.Save();
            }
        }

        // ── Helpers ──
        // Paleta unificada Atelier: COMÚN gris, POCO COMÚN verde, RARA azul,
        // ÉPICA púrpura, LEGENDARIA amarilla, MÍTICA roja.
        public static string RarityLabel(SkinRarity r)
        {
            switch (r)
            {
                case SkinRarity.Common: return "COMÚN";
                case SkinRarity.Uncommon: return "POCO COMÚN";
                case SkinRarity.Rare: return "RARA";
                case SkinRarity.Epic: return "ÉPICA";
                case SkinRarity.Legendary: return "LEGENDARIA";
                case SkinRarity.Mythic: return "MÍTICA";
                default: return "COMÚN";
            }
        }

        public static Color RarityColor(SkinRarity r)
        {
            switch (r)
            {
                case SkinRarity.Common: return new Color(0.62f, 0.65f, 0.70f);
                case SkinRarity.Uncommon: return new Color(0.20f, 0.83f, 0.60f);
                case SkinRarity.Rare: return new Color(0.35f, 0.65f, 1f);
                case SkinRarity.Epic: return new Color(0.75f, 0.38f, 0.95f);
                case SkinRarity.Legendary: return new Color(1f, 0.78f, 0.20f);
                case SkinRarity.Mythic: return new Color(1f, 0.30f, 0.28f);
                default: return new Color(0.62f, 0.65f, 0.70f);
            }
        }
    }
}
