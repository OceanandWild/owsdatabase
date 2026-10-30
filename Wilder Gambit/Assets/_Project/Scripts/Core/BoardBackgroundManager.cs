using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Static manager for board backgrounds.
    /// Primary: uses a BoardBackgroundLibrary ScriptableObject (assign in a scene MonoBehaviour).
    /// Fallback: hardcoded 14 themes loaded from disk at runtime.
    /// Selection is persisted via PlayerPrefs.
    /// </summary>
    public static class BoardBackgroundManager
    {
        private const string PREF_KEY_INDEX = "SelectedBoardBackgroundIndex";

        // ── Library Reference ────────────────────────────────────────────────

        private static BoardBackgroundLibrary _library;

        /// <summary>Assign the ScriptableObject library at runtime (called by scene bootstrap).</summary>
        public static void SetLibrary(BoardBackgroundLibrary library)
        {
            _library = library;
        }

        public static BoardBackgroundLibrary Library => _library;

        // ── Fallback Themes (hardcoded, used when no ScriptableObject is assigned) ──

        public struct FallbackTheme
        {
            public string id;
            public string displayName;
            public string filename;
            public Color lightTileColor;
            public Color darkTileColor;
            /// <summary>Objeto 8x8 decorado (PNG con alfa) que reemplaza el patron plano
            /// de casillas en partida; null si el tema no lo lleva.</summary>
            public string boardArt;

            public FallbackTheme(string id, string displayName, string filename, Color light, Color dark, string boardArt = null)
            {
                this.id = id;
                this.displayName = displayName;
                this.filename = filename;
                this.lightTileColor = light;
                this.darkTileColor = dark;
                this.boardArt = boardArt;
            }
        }

        // Curated tile palettes matched to each background theme
        public static readonly FallbackTheme[] FallbackThemes = new FallbackTheme[]
        {
            // 0 — Marble Clásico: cream & charcoal (classic tournament)
            new FallbackTheme("marble_classic",  "Marble Clásico",   "bg_marble_classic",
                new Color(0.93f, 0.93f, 0.82f), new Color(0.15f, 0.15f, 0.15f)),
            // 1 — Fuego Volcánico: ember & obsidian
            new FallbackTheme("volcanic_fire",   "Fuego Volcánico",  "bg_volcanic_fire",
                new Color(0.85f, 0.35f, 0.15f), new Color(0.12f, 0.04f, 0.02f)),
            // 2 — Hielo Ancestral: frost & deep ice
            new FallbackTheme("ice_ancestral",   "Hielo Ancestral",  "bg_ice_ancestral",
                new Color(0.82f, 0.92f, 0.97f), new Color(0.15f, 0.22f, 0.35f)),
            // 3 — Bosque Antiguo: moss & dark bark
            new FallbackTheme("ancient_forest",  "Bosque Antiguo",   "bg_ancient_forest",
                new Color(0.55f, 0.65f, 0.35f), new Color(0.08f, 0.12f, 0.05f)),
            // 4 — Abismo Oceánico: shallow water & abyss
            new FallbackTheme("ocean_abyss",     "Abismo Oceánico",  "bg_ocean_abyss",
                new Color(0.40f, 0.60f, 0.72f), new Color(0.04f, 0.06f, 0.14f)),
            // 5 — Celestia Cósmica: violet star & void
            new FallbackTheme("celestial_cosmic","Celestia Cósmica", "bg_celestial_cosmic",
                new Color(0.60f, 0.50f, 0.80f), new Color(0.06f, 0.03f, 0.14f)),
            // 6 — Egipcio Antiguo: sandstone & tomb
            new FallbackTheme("egyptian_ancient","Egipcio Antiguo",  "bg_egyptian_ancient",
                new Color(0.80f, 0.70f, 0.45f), new Color(0.18f, 0.12f, 0.06f)),
            // 7 — Gótico Catedral: grey stone & shadow
            new FallbackTheme("gothic_cathedral","Gótico Catedral",  "bg_gothic_cathedral",
                new Color(0.50f, 0.48f, 0.52f), new Color(0.10f, 0.08f, 0.12f)),
            // 8 — Gruta del Dragón: bone & cave
            new FallbackTheme("dragon_bones",    "Gruta del Dragón", "bg_dragon_bones",
                new Color(0.72f, 0.55f, 0.30f), new Color(0.10f, 0.06f, 0.03f)),
            // 9 — Palacio Real: crimson & burgundy
            new FallbackTheme("royal_palace",    "Palacio Real",     "bg_royal_palace",
                new Color(0.65f, 0.12f, 0.12f), new Color(0.18f, 0.04f, 0.04f)),
            // ── Velada de Halloween 2026 (bg_halloween_moon / bg_halloween_blood) ──
            // 10 — Luna Llena: silver moonlight & night sky
            new FallbackTheme("halloween_moon",  "Luna Llena",       "bg_halloween_moon",
                new Color(0.80f, 0.82f, 0.90f), new Color(0.10f, 0.10f, 0.22f), "bg_halloween_moon_board"),
            // 11 — Luna de Sangre: blood moon crimson & ash
            new FallbackTheme("halloween_blood", "Luna de Sangre",   "bg_halloween_blood",
                new Color(0.78f, 0.30f, 0.28f), new Color(0.16f, 0.05f, 0.07f), "bg_halloween_blood_board"),
            // ── Pase de la Velada 21-30 (Parte 2) ──
            // 12 — Cementerio Olvidado: piedra con musgo, reja y velas (Luna 29)
            new FallbackTheme("halloween_graveyard", "Cementerio Olvidado", "bg_halloween_graveyard",
                new Color(0.45f, 0.50f, 0.44f), new Color(0.12f, 0.15f, 0.12f), "bg_halloween_graveyard_board"),
            // 13 — Cripta de los Cuervos: mármol negro, hueso y rubí (Sangre 25)
            new FallbackTheme("halloween_crypt", "Cripta de los Cuervos", "bg_halloween_crypt",
                new Color(0.78f, 0.72f, 0.60f), new Color(0.09f, 0.06f, 0.07f), "bg_halloween_crypt_board"),
        };

        // ── Propiedad de los tableros ────────────────────────────────────────

        /// <summary>
        /// Precio en Gambits de cada tablero (0 = gratis de entrada), en el orden de
        /// la biblioteca. Lo comparten la tienda (ShopBackgroundSelector) y el
        /// inventario (InventoryModal): aquí vive el único listado. Son cosméticos:
        /// precios bajos y sin rareza.
        /// </summary>
        public static readonly int[] ThemePrices = { 0, 0, 120, 150, 180, 210, 240, 270, 300, 330, 360, 400, 440, 480 };

        // ── Exclusividad de evento ───────────────────────────────────────────

        /// <summary>
        /// Tableros exclusivos del Pase de Halloween: no se venden en la tienda
        /// (su precio queda solo como referencia) y el inventario los marca como
        /// del pase hasta reclamar su recompensa.
        /// </summary>
        private static readonly HashSet<string> PassExclusiveIds = new HashSet<string>
        {
            "halloween_moon", "halloween_blood",
            // Parte 2: Cementerio Olvidado (Luna 29) y Cripta de los Cuervos (Sangre 25).
            "halloween_graveyard", "halloween_crypt",
        };

        /// <summary>True si el tablero solo se consigue como recompensa de evento.</summary>
        public static bool IsPassExclusive(int index)
        {
            string id = GetIdForIndex(index);
            return !string.IsNullOrEmpty(id) && PassExclusiveIds.Contains(id);
        }

        /// <summary>Nombre visible del tablero (biblioteca o catálogo de reserva).</summary>
        public static string GetDisplayName(int index) => GetNameForIndex(index);

        /// <summary>Gratis de entrada o ya comprado (lo persiste la tienda).</summary>
        public static bool IsUnlocked(int index)
        {
            if (index < 0 || index >= ThemeCount) return false;
            if (index < ThemePrices.Length && ThemePrices[index] == 0) return true;
            return PlayerPrefs.GetInt($"bg_unlocked_{index}", 0) == 1;
        }

        /// <summary>Marca el tablero como comprado.</summary>
        public static void Unlock(int index)
        {
            PlayerPrefs.SetInt($"bg_unlocked_{index}", 1);
            PlayerPrefs.Save();
        }

        /// <summary>Cuántos tableros están disponibles (gratis o comprados).</summary>
        public static int UnlockedCount
        {
            get
            {
                int total = 0;
                for (int i = 0; i < ThemeCount; i++)
                    if (IsUnlocked(i)) total++;
                return total;
            }
        }

        // ── Selected Index ───────────────────────────────────────────────────

        // Always read from PlayerPrefs to avoid stale cache across scenes
        public static int ThemeCount => _library != null ? _library.Count : FallbackThemes.Length;

        public static int SelectedIndex
        {
            get { return Mathf.Clamp(PlayerPrefs.GetInt(PREF_KEY_INDEX, 0), 0, ThemeCount - 1); }
        }

        public static string SelectedDisplayName => GetNameForIndex(SelectedIndex);
        public static string SelectedThemeId => GetIdForIndex(SelectedIndex);
        public static Color SelectedLightColor => GetColorForIndex(SelectedIndex, true);
        public static Color SelectedDarkColor => GetColorForIndex(SelectedIndex, false);

        public static void Select(int index)
        {
            int clamped = Mathf.Clamp(index, 0, ThemeCount - 1);
            PlayerPrefs.SetInt(PREF_KEY_INDEX, clamped);
            PlayerPrefs.Save();
            Debug.Log($"[BoardBackgroundManager] Selected: {clamped} ({GetNameForIndex(clamped)})");
        }

        public static void SelectById(string id)
        {
            int idx = _library != null ? _library.GetIndexById(id) : FindFallbackIndex(id);
            Select(idx);
        }

        /// <summary>
        /// Índice de un tema por id (biblioteca o catálogo de reserva). -1 si no existe.
        /// Lo usan las recompensas que citan el tablero por id (p. ej. el pase de Halloween).
        /// </summary>
        public static int GetIndexById(string id)
        {
            if (string.IsNullOrEmpty(id)) return -1;
            if (_library != null)
            {
                int libraryIndex = _library.GetIndexById(id);
                if (libraryIndex >= 0) return libraryIndex;
            }
            return FindFallbackIndex(id);
        }

        // ── Texture Loading ──────────────────────────────────────────────────

        public static Texture2D LoadSelectedTexture()
        {
            return LoadTextureForIndex(SelectedIndex);
        }

        public static Texture2D LoadSelectedThumbnail()
        {
            return LoadThumbnailForIndex(SelectedIndex);
        }

        public static Texture2D LoadTextureForIndex(int index)
        {
            // 1. Try ScriptableObject first
            if (_library != null)
            {
                var theme = _library.GetTheme(index);
                if (theme != null && theme.backgroundTexture != null)
                    return theme.backgroundTexture;
            }

            // 2. Try disk (Editor-only path)
            string filename = GetFilenameForIndex(index);
            Texture2D tex = LoadFromDisk(filename);
            if (tex != null) return tex;

            // 3. Try Resources.Load (works in builds)
            return LoadFromResources(filename);
        }

        public static Texture2D LoadThumbnailForIndex(int index)
        {
            // 1. Try ScriptableObject thumbnail
            if (_library != null)
            {
                var theme = _library.GetTheme(index);
                if (theme != null)
                {
                    if (theme.thumbnailTexture != null) return theme.thumbnailTexture;
                    if (theme.backgroundTexture != null) return theme.backgroundTexture;
                }
            }

            // 2. Tablero decorado (v2): la tarjeta muestra el objeto 8x8 pintado
            //    (pase de Halloween, tienda e inventario) en vez de la capa ambiente.
            Texture2D art = LoadBoardArtForIndex(index);
            if (art != null) return art;

            // 3. Fall back to full texture
            return LoadTextureForIndex(index);
        }

        public static Texture2D LoadMainMenuTexture()
        {
            Texture2D tex = LoadFromDisk("bg_main_menu");
            if (tex != null) return tex;
            return LoadFromResources("bg_main_menu");
        }

        // ── Tableros decorados (v2) ──────────────────────────────────────────

        /// <summary>
        /// Fracción (0-1) del ancho del lienzo que ocupa la grilla pintada de los
        /// tableros decorados v2; el resto es borde ornamental. La comparten el
        /// pipeline de arte (Tools/build_halloween_boards.py) y BoardView, que
        /// escala el objeto para que la grilla pintada mida exactamente 8 casillas.
        /// </summary>
        public const float BoardArtInnerFraction = 0.83f;

        /// <summary>Nombre de archivo del objeto decorado del tema (null si no lleva).</summary>
        public static string GetBoardArtFilename(int index)
        {
            // La biblioteca ScriptableObject no modela el objeto decorado: solo lo
            // llevan los temas de reserva (los que están en juego hoy).
            if (_library != null) return null;
            if (index >= 0 && index < FallbackThemes.Length)
                return FallbackThemes[index].boardArt;
            return null;
        }

        /// <summary>True si el tema pinta su grilla con un objeto decorado (PNG con alfa).</summary>
        public static bool HasDecoratedBoardArt(int index)
        {
            return !string.IsNullOrEmpty(GetBoardArtFilename(index));
        }

        /// <summary>Objeto decorado del tema (o null si no lleva / falta el archivo).</summary>
        public static Texture2D LoadBoardArtForIndex(int index)
        {
            string filename = GetBoardArtFilename(index);
            if (string.IsNullOrEmpty(filename)) return null;
            Texture2D tex = LoadFromDisk(filename);
            if (tex != null) return tex;
            return LoadFromResources(filename);
        }

        // ── Disk Loading ─────────────────────────────────────────────────────

        private static Texture2D LoadFromDisk(string filename)
        {
            string[] extensions = { ".jpeg", ".jpg", ".png" };
            // StreamingAssets primero: existe igual en Editor y en build.
            // Las rutas de proyecto solo resuelven en el Editor (fallback).
            var rootsAndSubPaths = new (string root, string subPath)[]
            {
                (Application.streamingAssetsPath, "Board"),
                (Application.dataPath, "_Project/Textures/Board"),
                (Application.dataPath, "Resources/Board")
            };

            foreach (var entry in rootsAndSubPaths)
            {
                foreach (var ext in extensions)
                {
                    string path = System.IO.Path.Combine(
                        entry.root, entry.subPath, filename + ext);
                    if (System.IO.File.Exists(path))
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(path);
                        Texture2D tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                        if (tex.LoadImage(bytes))
                        {
                            tex.filterMode = FilterMode.Bilinear;
                            tex.anisoLevel = 8;
                            return tex;
                        }
                    }
                }
            }
            return null;
        }

        private static Texture2D LoadFromResources(string filename)
        {
            Sprite sprite = Resources.Load<Sprite>($"Board/{filename}");
            if (sprite != null) return sprite.texture;

            Texture2D tex = Resources.Load<Texture2D>($"Board/{filename}");
            return tex;
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static string GetFilenameForIndex(int index)
        {
            if (_library != null)
            {
                var theme = _library.GetTheme(index);
                if (theme != null) return theme.filename;
            }
            if (index >= 0 && index < FallbackThemes.Length)
                return FallbackThemes[index].filename;
            return "bg_marble_classic";
        }

        private static string GetNameForIndex(int index)
        {
            if (_library != null)
            {
                var theme = _library.GetTheme(index);
                if (theme != null) return theme.displayName;
            }
            if (index >= 0 && index < FallbackThemes.Length)
                return FallbackThemes[index].displayName;
            return "Fondo";
        }

        private static string GetIdForIndex(int index)
        {
            if (_library != null)
            {
                var theme = _library.GetTheme(index);
                if (theme != null) return theme.themeId;
            }
            if (index >= 0 && index < FallbackThemes.Length)
                return FallbackThemes[index].id;
            return "marble_classic";
        }

        private static Color GetColorForIndex(int index, bool light)
        {
            if (_library != null)
            {
                var theme = _library.GetTheme(index);
                if (theme != null)
                    return light ? theme.lightTileColor : theme.darkTileColor;
            }
            if (index >= 0 && index < FallbackThemes.Length)
                return light ? FallbackThemes[index].lightTileColor : FallbackThemes[index].darkTileColor;
            return light ? new Color(0.93f, 0.93f, 0.82f) : new Color(0.15f, 0.15f, 0.15f);
        }

        private static int FindFallbackIndex(string id)
        {
            for (int i = 0; i < FallbackThemes.Length; i++)
                if (FallbackThemes[i].id == id) return i;
            return 0;
        }
    }
}
