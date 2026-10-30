using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Arte del <b>Pase de Halloween</b> (<c>Resources/UI/Halloween</c>).
    ///   · <c>chip_nivel</c>  — placa hueso-oro del panel NIVEL (luna y velas)
    ///   · <c>chip_xp</c>     — placa violeta arcano del panel XP DE LA VELADA
    ///   · <c>chip_dulces</c> — placa carmesí caramelo del panel DULCES DE LA VELADA
    ///
    /// Son placas de 374×180 (2× del tamaño de uso) con filigrana en las
    /// esquinas. Se aplican con 9-slice de esquinas fijas a escala 0.5 (cada
    /// píxel del sprite se dibuja a la mitad), así el ornato no se deforma
    /// cuando el chip crece con cifras más largas («1.800 / 1.800 XP»).
    /// Si el PNG no existe todavía, el elemento conserva el estilo USS.
    /// </summary>
    public static class HalloweenSprites
    {
        public const string Folder = "UI/Halloween";

        public const string ChipNivel = "chip_nivel";
        public const string ChipXp = "chip_xp";
        public const string ChipDulces = "chip_dulces";

        /// <summary>Slice al borde de la filigrana, en píxeles del sprite: el
        /// resto del ornato vive en los parches del medio y se estira con el
        /// chip. La escala 0.5 corresponde al arte 2×.</summary>
        private const int SliceX = 88;
        private const int SliceY = 46;
        private const float SliceScale = 0.5f;

        private static readonly Dictionary<string, Sprite> Cache = new Dictionary<string, Sprite>();

        /// <summary>Sprite por nombre base, o <c>null</c> si el PNG no está importado.</summary>
        public static Sprite Get(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (Cache.TryGetValue(name, out var cached)) return cached;

            // 1) Sprite único directo (lo deja así ProgressSpriteImport).
            Sprite sprite = Resources.Load<Sprite>($"{Folder}/{name}");

            // 2) Textura multi-sprite: quedarse con el recorte de mayor área.
            if (sprite == null)
            {
                Sprite[] all = Resources.LoadAll<Sprite>($"{Folder}/{name}");
                if (all != null && all.Length > 0)
                {
                    float bestArea = 0f;
                    foreach (var s in all)
                    {
                        if (s == null) continue;
                        float area = s.rect.width * s.rect.height;
                        if (area > bestArea) { bestArea = area; sprite = s; }
                    }
                }
            }

            // 3) Textura cruda: envolverla en Sprite (red de seguridad).
            if (sprite == null)
            {
                var tex = Resources.Load<Texture2D>($"{Folder}/{name}");
                if (tex != null)
                {
                    sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                        new Vector2(0.5f, 0.5f), 100f);
                    sprite.name = name;
                }
            }

            Cache[name] = sprite; // se cachea también el fallo para no golpear Resources en bucle
            return sprite;
        }

        public static bool Exists(string name) => Get(name) != null;

        /// <summary>Aplica la placa con 9-slice de esquinas fijas (escala 0.5).</summary>
        public static bool Apply(VisualElement element, string name)
        {
            var sprite = Get(name);
            if (element == null || sprite == null) return false;

            Rect rect = sprite.rect;
            int sw = Mathf.Max(1, Mathf.RoundToInt(rect.width));
            int sh = Mathf.Max(1, Mathf.RoundToInt(rect.height));

            element.style.backgroundImage = new StyleBackground(sprite);
            element.style.unitySliceLeft = Mathf.Clamp(SliceX, 1, sw / 2);
            element.style.unitySliceRight = Mathf.Clamp(SliceX, 1, sw / 2);
            element.style.unitySliceTop = Mathf.Clamp(SliceY, 1, sh / 2);
            element.style.unitySliceBottom = Mathf.Clamp(SliceY, 1, sh / 2);
            element.style.unitySliceScale = SliceScale;
            return true;
        }

        /// <summary>Vuelve al estilo USS (quita el sprite aplicado).</summary>
        public static void Clear(VisualElement element)
        {
            if (element == null) return;
            element.style.backgroundImage = new StyleBackground(StyleKeyword.None);
        }
    }
}
