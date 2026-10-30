using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Static manager for ambient backdrops (pestaña FONDOS).
    /// Cosmético puro: se paga en Gambits (divisa farmeable), con precios bajos
    /// y sin rareza. Dos gratis de entrada y el resto de 100 a 340 Gambits.
    /// La selección persiste en PlayerPrefs y solo se aplica al menú cuando el
    /// jugador equipa un fondo (BackdropCustomized), para no cambiarle el menú
    /// de golpe a quien nunca tocó la pestaña.
    /// </summary>
    public static class BackdropManager
    {
        private const string PREF_KEY_INDEX = "SelectedBackdropIndex";
        private const string PREF_KEY_CUSTOM = "BackdropCustomized";

        public struct BackdropTheme
        {
            public string id;
            public string displayName;
            public string filename;

            public BackdropTheme(string id, string displayName, string filename)
            {
                this.id = id;
                this.displayName = displayName;
                this.filename = filename;
            }
        }

        public static readonly BackdropTheme[] Themes = new BackdropTheme[]
        {
            new BackdropTheme("noir_tavern",       "Taberna Noir",       "backdrop_noir_tavern"),
            new BackdropTheme("docks_midnight",    "Muelles Medianoche", "backdrop_docks_midnight"),
            new BackdropTheme("storm_cliffs",      "Acantilados Tormenta","backdrop_storm_cliffs"),
            new BackdropTheme("ember_forge",       "Forja Brasas",       "backdrop_ember_forge"),
            new BackdropTheme("moon_garden",       "Jardín Lunar",       "backdrop_moon_garden"),
            new BackdropTheme("abyss_trench",      "Fosa Abisal",        "backdrop_abyss_trench"),
            new BackdropTheme("astral_observatory","Observatorio Astral","backdrop_astral_observatory"),
            new BackdropTheme("caravan_dunes",     "Dunas Caravana",     "backdrop_caravan_dunes"),
            new BackdropTheme("crypt_cathedral",   "Cripta Catedral",    "backdrop_crypt_cathedral"),
            new BackdropTheme("dragon_overlook",   "Mirador Dragón",     "backdrop_dragon_overlook"),
            // ── Velada de Halloween 2026 (backdrop_halloween_night) ──
            new BackdropTheme("halloween_night",   "Noche de Brujas",    "backdrop_halloween_night"),
            // ── Pase de la Velada 21-30 (Parte 2) ──
            new BackdropTheme("halloween_harvest", "Noche de la Cosecha", "backdrop_halloween_harvest"),
            new BackdropTheme("halloween_banquet", "Salón del Banquete",  "backdrop_halloween_banquet"),
        };

        /// <summary>Precio en Gambits de cada fondo (0 = gratis de entrada).</summary>
        public static readonly int[] ThemePrices = { 0, 0, 100, 130, 160, 190, 220, 250, 280, 310, 340, 380, 420 };

        public static int ThemeCount => Themes.Length;

        /// <summary>
        /// Fondos que pertenecen a un evento y no se venden en el Atelier: llegan
        /// al inventario como recompensa (p. ej. Noche de Brujas, del Pase de
        /// Halloween). Se excluyen del catálogo, pero conservan su índice para no
        /// romper las selecciones y desbloqueos ya guardados.
        /// </summary>
        private static readonly HashSet<string> EventExclusiveIds = new HashSet<string>
        {
            "halloween_night",
            // Parte 2: Noche de la Cosecha (Luna 24) y Salón del Banquete (Sangre 27).
            "halloween_harvest", "halloween_banquet",
        };

        public static bool IsEventExclusive(int index)
        {
            if (index < 0 || index >= Themes.Length) return false;
            return EventExclusiveIds.Contains(Themes[index].id);
        }

        public static int ShopCount
        {
            get
            {
                int total = 0;
                for (int i = 0; i < Themes.Length; i++)
                    if (!IsEventExclusive(i)) total++;
                return total;
            }
        }

        public static int SelectedIndex
        {
            get { return Mathf.Clamp(PlayerPrefs.GetInt(PREF_KEY_INDEX, 0), 0, ThemeCount - 1); }
        }

        /// <summary>True cuando el jugador equipó un fondo alguna vez (el menú adopta su fondo).</summary>
        public static bool HasCustomSelection => PlayerPrefs.GetInt(PREF_KEY_CUSTOM, 0) == 1;

        public static string SelectedDisplayName => GetNameForIndex(SelectedIndex);

        /// <summary>Se dispara al equipar un fondo, para que el menú lo repinte sin recargar.</summary>
        public static event System.Action Changed;

        public static void Select(int index)
        {
            int clamped = Mathf.Clamp(index, 0, ThemeCount - 1);
            PlayerPrefs.SetInt(PREF_KEY_INDEX, clamped);
            PlayerPrefs.SetInt(PREF_KEY_CUSTOM, 1);
            PlayerPrefs.Save();
            Changed?.Invoke();
            Debug.Log($"[BackdropManager] Selected: {clamped} ({GetNameForIndex(clamped)})");
        }

        /// <summary>Gratis de entrada o ya comprado.</summary>
        public static bool IsUnlocked(int index)
        {
            if (index < 0 || index >= ThemeCount) return false;
            if (index < ThemePrices.Length && ThemePrices[index] == 0) return true;
            return PlayerPrefs.GetInt($"backdrop_unlocked_{index}", 0) == 1;
        }

        /// <summary>Marca el fondo como comprado.</summary>
        public static void Unlock(int index)
        {
            PlayerPrefs.SetInt($"backdrop_unlocked_{index}", 1);
            PlayerPrefs.Save();
        }

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

        public static string GetDisplayName(int index) => GetNameForIndex(index);

        /// <summary>Índice de un fondo por id. -1 si no existe. Para recompensas que citan el fondo por id.</summary>
        public static int GetIndexById(string id)
        {
            if (string.IsNullOrEmpty(id)) return -1;
            for (int i = 0; i < Themes.Length; i++)
                if (Themes[i].id == id) return i;
            return -1;
        }

        // ── Texture Loading ──────────────────────────────────────────────

        public static Texture2D LoadSelectedTexture()
        {
            return LoadTextureForIndex(SelectedIndex);
        }

        public static Texture2D LoadThumbnailForIndex(int index)
        {
            return LoadTextureForIndex(index);
        }

        public static Texture2D LoadTextureForIndex(int index)
        {
            string filename = GetFilenameForIndex(index);
            Texture2D tex = LoadFromDisk(filename);
            if (tex != null) return tex;
            return LoadFromResources(filename);
        }

        private static Texture2D LoadFromDisk(string filename)
        {
            string[] extensions = { ".jpg", ".jpeg", ".png" };
            // StreamingAssets primero: existe igual en Editor y en build.
            // Las rutas de proyecto solo resuelven en el Editor (fallback).
            var rootsAndSubPaths = new (string root, string subPath)[]
            {
                (Application.streamingAssetsPath, "Backdrop"),
                (Application.dataPath, "_Project/Textures/Backdrop"),
                (Application.dataPath, "Resources/Backdrop")
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
            Sprite sprite = Resources.Load<Sprite>($"Backdrop/{filename}");
            if (sprite != null) return sprite.texture;

            Texture2D tex = Resources.Load<Texture2D>($"Backdrop/{filename}");
            return tex;
        }

        // ── Helpers ──────────────────────────────────────────────────────

        private static string GetFilenameForIndex(int index)
        {
            if (index >= 0 && index < Themes.Length)
                return Themes[index].filename;
            return Themes[0].filename;
        }

        private static string GetNameForIndex(int index)
        {
            if (index >= 0 && index < Themes.Length)
                return Themes[index].displayName;
            return "Fondo";
        }
    }
}
