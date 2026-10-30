using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Arte del <b>pase de temporada</b> (<c>Resources/UI/SeasonPass</c>).
    ///   · <c>seasonpass_banner</c> — rey ennegrecido con brasas (hero a pantalla completa)
    ///   · <c>seasonpass_label</c> — título dorado «PASE DE TEMPORADA»
    ///   · <c>seasonpass_tier</c> — medallón circular con corona (nodo sobre la barra)
    ///   · <c>reward_slot_basic</c> — marco acero para el Gambito Libre
    ///   · <c>reward_slot_premium</c> — marco dorado con corona para el Gambito Real
    ///   · <c>halloweenpass_banner</c> — luna, velas y piezas esculpidas (pase de Halloween)
    ///   · <c>halloweenpass_label</c> — título «Pase de Halloween» sobre fondo transparente
    ///
    /// Si un sprite no existe todavía, el elemento conserva el estilo USS.
    /// </summary>
    public static class SeasonPassSprites
    {
        public const string Folder = "UI/SeasonPass";

        public const string Banner = "seasonpass_banner";
        public const string Label = "seasonpass_label";
        public const string Tier = "seasonpass_tier";
        public const string SlotBasic = "reward_slot_basic";
        public const string SlotPremium = "reward_slot_premium";

        /// <summary>Pase de Halloween: luna, velas y piezas esculpidas en roca y erosión.</summary>
        public const string HalloweenBanner = "halloweenpass_banner";

        /// <summary>Título «Pase de Halloween» recortado con fondo transparente.</summary>
        public const string HalloweenLabel = "halloweenpass_label";

        private static readonly Dictionary<string, Sprite> Cache = new Dictionary<string, Sprite>();

        /// <summary>Sprite por nombre base, o <c>null</c> si el PNG no está importado.</summary>
        public static Sprite Get(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (Cache.TryGetValue(name, out var cached)) return cached;

            // 1) Sprite único directo (slots: basic / premium vienen así).
            Sprite sprite = Resources.Load<Sprite>($"{Folder}/{name}");
            if (sprite != null)
            {
                Cache[name] = sprite;
                return sprite;
            }

            // 2) Textura multi-sprite: quedarse con el recorte de mayor área
            //    (bar_4 = barra larga 2566×417, tier_0 = medallón 1288×1316).
            Sprite[] all = Resources.LoadAll<Sprite>($"{Folder}/{name}");
            if (all != null && all.Length > 0)
            {
                Sprite best = all[0];
                float bestArea = 0f;
                foreach (var s in all)
                {
                    if (s == null) continue;
                    float area = s.rect.width * s.rect.height;
                    if (area > bestArea) { bestArea = area; best = s; }
                }
                if (best != null)
                {
                    Cache[name] = best;
                    return best;
                }
            }

            // 3) Textura cruda (banner es .jpg sin sprite): envolverla en Sprite.
            var tex = Resources.Load<Texture2D>($"{Folder}/{name}");
            if (tex != null)
            {
                var wrapped = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                    new Vector2(0.5f, 0.5f), 100f);
                wrapped.name = name;
                Cache[name] = wrapped;
                return wrapped;
            }

            Cache[name] = null; // se cachea el fallo para no golpear Resources en bucle
            return null;
        }

        public static bool Exists(string name) => Get(name) != null;

        /// <summary>Aplica el sprite como fondo (sin 9-slice: el arte es ornamental).</summary>
        public static bool Apply(VisualElement element, string name)
        {
            var sprite = Get(name);
            if (element == null || sprite == null) return false;
            element.style.backgroundImage = new StyleBackground(sprite);
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
