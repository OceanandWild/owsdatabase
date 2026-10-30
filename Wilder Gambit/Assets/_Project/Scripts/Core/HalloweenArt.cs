using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Arte de la velada de Halloween (<c>Resources/Pieces/Halloween/hwp_*</c>):
    /// el lote de piezas esculpidas de la edición. Aquí viven los nombres y la
    /// carga (disco en el Editor, <c>Resources</c> en builds) con caché; lo
    /// comparten el tablero (que además recorta el padding), la tienda de la
    /// velada y el inventario.
    ///
    /// Convención del lote: <c>hwp_*</c> es la versión blanca/base y
    /// <c>hwp_*_black</c> la negra. Mientras la negra no exista, el lado negro
    /// cae al arte base y lo apaga con tinte (<see cref="BlackTeamTint"/>): soltar
    /// el PNG correspondiente es todo lo que hace falta para el cambio.
    /// </summary>
    public static class HalloweenArt
    {
        /// <summary>Carpeta del lote dentro de <c>Resources/Pieces</c>.</summary>
        public const string Folder = "Halloween";

        /// <summary>Sufijo de la versión negra de una pieza del lote.</summary>
        public const string BlackSuffix = "_black";

        // ── Piezas de la velada usadas por la tienda (el resto del lote sigue fuera) ──

        public const string PawnSpiderArt = "hwp_pawn_spider";
        public const string KnightBatArt = "hwp_knight_bat";
        public const string RookCryptArt = "hwp_rook_crypt";
        public const string RookGraveArt = "hwp_rook_grave";
        public const string PawnPumpkinArt = "hwp_pawn_pumpkin";
        public const string KnightGhostArt = "hwp_knight_ghost";

        // ── Lote del Pase de la Velada 21-30 (Parte 2) ──
        // Estas cinco son full-art: conservan la geometría de la pieza clásica y
        // cambian solo el material. Cada una tiene su `_black` propio.

        public const string BishopLanternArt = "hwp_bishop_lantern";
        public const string KnightScarecrowArt = "hwp_knight_scarecrow";
        public const string RookReliquaryArt = "hwp_rook_reliquary";
        public const string QueenHexArt = "hwp_queen_hex";
        public const string KingCrimsonArt = "hwp_king_crimson";
        /// <summary>Eclipse Eterno: full-art de la skin mítica del Rey, con su propio `_black`.</summary>
        public const string KingEclipseArt = "hwp_king_eclipse";

        // ── Lote de la invasión de los Gummy Bears (reservado) ──
        // La Torre Golosa es la culpable del caos: la torre obsesionada con los
        // dulces. Se produce con el mismo estándar full-art (900 px, `_black`
        // propio) y queda fuera del catálogo hasta definir cómo se entrega.

        /// <summary>Arte reservado para los Gummy Bears: la torre de caramelo. Su PNG y su `_black` viven en el lote, pero no está en el catálogo ni en el pase.</summary>
        public const string RookCandyArt = "hwp_rook_candy";
        /// <summary>Arte reservado para los Gummy Bears: el peón de caramelo que abre la invasión.</summary>
        public const string PawnCandyArt = "hwp_pawn_candy";

        // ── Ids de las variantes que vende la tienda ──

        public const string PumpkinPawnId = "pumpkin_pawn";
        public const string GhostKnightId = "ghost_knight";

        /// <summary>Tinte del lado negro cuando no hay arte <c>_black</c>: el
        /// mismo sprite se apaga a gris-violeta para que los bandos se distingan
        /// (la familia negra del juego es oscura y fría).</summary>
        public static readonly Color BlackTeamTint = new Color(0.55f, 0.53f, 0.62f);

        private static readonly Dictionary<string, string> VariantArts = new Dictionary<string, string>
        {
            { PumpkinPawnId, PawnPumpkinArt },
            { GhostKnightId, KnightGhostArt },
        };

        /// <summary>Nombre del arte (<c>hwp_*</c>) de una variante de la tienda, o null.</summary>
        public static string ArtForVariant(string variantId)
        {
            if (string.IsNullOrEmpty(variantId)) return null;
            return VariantArts.TryGetValue(variantId, out string art) ? art : null;
        }

        /// <summary>Ruta relativa a <c>Resources/Pieces</c> del arte pedido.</summary>
        public static string PiecePath(string artName, bool blackSide = false)
        {
            if (string.IsNullOrEmpty(artName)) return null;
            return $"{Folder}/{artName}{(blackSide ? BlackSuffix : "")}";
        }

        // ── Carga con caché ───────────────────────────────────────────────
        // Con "Fast Play Mode" los estáticos sobreviven entre Plays: se limpia
        // la caché en cada ejecución (misma política que PieceSkinManager).

        private static readonly Dictionary<string, Texture2D> TexCache = new Dictionary<string, Texture2D>();
        private static readonly HashSet<string> TexMiss = new HashSet<string>();
        private static readonly Dictionary<string, Sprite> SpriteCache = new Dictionary<string, Sprite>();

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void ResetCaches()
        {
            TexCache.Clear();
            TexMiss.Clear();
            SpriteCache.Clear();
        }

        /// <summary>Textura del arte (<c>hwp_*</c>, con sufijo <c>_black</c> si toca), o null.</summary>
        public static Texture2D LoadTexture(string artName)
        {
            if (string.IsNullOrEmpty(artName)) return null;
            if (TexCache.TryGetValue(artName, out Texture2D cached)) return cached;
            if (TexMiss.Contains(artName)) return null;

            Texture2D tex = LoadTextureFromDisk(artName) ?? LoadTextureFromResources(artName);
            if (tex != null) TexCache[artName] = tex;
            else
            {
                TexMiss.Add(artName);
                Debug.LogWarning($"[HalloweenArt] Sin PNG en Resources/Pieces/{Folder}/{artName}.png: " +
                                 "el módulo que lo pidió cae a su respaldo.");
            }
            return tex;
        }

        /// <summary>¿Existe el PNG pedido? (sirve para saber si ya llegó el arte negro).</summary>
        public static bool HasArt(string artName) => LoadTexture(artName) != null;

        /// <summary>
        /// ¿Existe el PNG pedido? Sin cargarlo en la caché ni avisar si falta:
        /// para decidir qué enseñar (p. ej. si una skin ya tiene su lado negro
        /// propio). <paramref name="resourcePath"/> es la ruta relativa a
        /// <c>Resources/Pieces</c> —la misma que devuelve <see cref="PiecePath"/>—,
        /// p. ej. <c>Halloween/hwp_queen_hex_black</c>.
        /// </summary>
        public static bool ArtExists(string resourcePath)
        {
            if (string.IsNullOrEmpty(resourcePath)) return false;
            string rel = resourcePath.Replace('\\', '/').Trim('/');

            try
            {
                string file = System.IO.Path.Combine(Application.dataPath, "Resources", "Pieces",
                    rel.Replace('/', System.IO.Path.DirectorySeparatorChar) + ".png");
                if (System.IO.File.Exists(file)) return true;
                return Resources.Load<Texture2D>($"Pieces/{rel}") != null;
            }
            catch { return false; }
        }

        /// <summary>Sprite de UI del arte pedido, o null. No recorta: es para fichas.</summary>
        public static Sprite LoadSprite(string artName)
        {
            if (string.IsNullOrEmpty(artName)) return null;
            if (SpriteCache.TryGetValue(artName, out Sprite cached)) return cached;

            Texture2D tex = LoadTexture(artName);
            if (tex == null) return null;

            var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                new Vector2(0.5f, 0.5f), 100f);
            sprite.name = artName;
            SpriteCache[artName] = sprite;
            return sprite;
        }

        private static Texture2D LoadTextureFromDisk(string artName)
        {
            try
            {
                string path = System.IO.Path.Combine(Application.dataPath,
                    "Resources", "Pieces", Folder, artName + ".png");
                if (!System.IO.File.Exists(path)) return null;
                byte[] bytes = System.IO.File.ReadAllBytes(path);
                // Con mipmaps: la ficha se dibuja muy por debajo de su tamaño
                // nativo (900 px de alto en una casilla de ~78), y sin cadena de
                // mips el filtrado bilineal la deja con bordes duros y sucios.
                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, true);
                if (tex.LoadImage(bytes))
                {
                    tex.filterMode = FilterMode.Trilinear;
                    tex.anisoLevel = 4;
                    tex.Apply(true, false);
                    return tex;
                }
            }
            catch { /* un PNG roto no tumba la tienda */ }
            return null;
        }

        private static Texture2D LoadTextureFromResources(string artName)
        {
            try
            {
                Texture2D tex = Resources.Load<Texture2D>($"Pieces/{Folder}/{artName}");
                if (tex != null) return tex;
                Sprite spr = Resources.Load<Sprite>($"Pieces/{Folder}/{artName}");
                if (spr != null && spr.texture != null) return spr.texture;
            }
            catch { /* idem */ }
            return null;
        }
    }
}
