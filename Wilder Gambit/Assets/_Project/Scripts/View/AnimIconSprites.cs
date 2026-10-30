using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.View
{
    /// <summary>
    /// Iconos ilustrados de las cuatro animaciones (pestaña ANIMACIONES).
    /// Fuente única para tienda, pases y efectos de partida: si el PNG no está
    /// importado como Sprite, cae a la textura y, en editor, al archivo en disco.
    /// Nunca lanza: sin arte, cada FX conserva su respaldo (frames o procedural).
    /// </summary>
    internal static class AnimIconSprites
    {
        public const string CenizaPath = "Animations/ceniza_al_viento";
        public const string DobleFiloPath = "Animations/doble_filo";
        public const string DestelloPath = "Animations/destello_tactico";
        public const string CometaPath = "Animations/cometa_ignea";

        private static readonly Dictionary<string, Sprite> Cache =
            new Dictionary<string, Sprite>();

        public static Sprite Ceniza => Get(CenizaPath);
        public static Sprite DobleFilo => Get(DobleFiloPath);
        public static Sprite Destello => Get(DestelloPath);
        public static Sprite Cometa => Get(CometaPath);

        /// <summary>Sprite del icono o null si todavía no está disponible.</summary>
        public static Sprite Get(string resourcePath)
        {
            if (string.IsNullOrEmpty(resourcePath)) return null;
            if (Cache.TryGetValue(resourcePath, out Sprite cached)) return cached;

            Sprite sprite = LoadFromResources(resourcePath);
            if (sprite == null) sprite = LoadFromDisk(resourcePath);
            if (sprite != null)
            {
                Prepare(sprite);
                Cache[resourcePath] = sprite;
            }
            return sprite;
        }

        private static Sprite LoadFromResources(string resourcePath)
        {
            try
            {
                Sprite s = Resources.Load<Sprite>(resourcePath);
                if (s != null) return s;

                Texture2D t = Resources.Load<Texture2D>(resourcePath);
                if (t != null)
                    return Sprite.Create(t, new Rect(0, 0, t.width, t.height),
                        new Vector2(0.5f, 0.5f), 100f);
            }
            catch { /* arte opcional: el FX sigue con su respaldo */ }
            return null;
        }

        private static Sprite LoadFromDisk(string resourcePath)
        {
            try
            {
                string name = resourcePath.Substring(resourcePath.LastIndexOf('/') + 1);
                string full = System.IO.Path.Combine(
                    Application.dataPath, "_Project/Textures/Animations", name + ".png");
                if (!System.IO.File.Exists(full)) return null;

                byte[] bytes = System.IO.File.ReadAllBytes(full);
                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                if (!tex.LoadImage(bytes)) return null;
                tex.name = name;
                return Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                    new Vector2(0.5f, 0.5f), 100f);
            }
            catch { return null; }
        }

        /// <summary>Calidad Ultra: trilineal + anisotrópico 16 como las piezas.</summary>
        private static void Prepare(Sprite sprite)
        {
            try
            {
                if (sprite == null || sprite.texture == null) return;
                sprite.texture.filterMode = FilterMode.Trilinear;
                sprite.texture.anisoLevel = 16;
            }
            catch { /* textura no modificable en build: se usa tal cual */ }
        }
    }
}
