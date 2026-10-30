using UnityEngine;

namespace WilderGambit.UI
{
    /// <summary>
    /// Sprites del rework del Victory HUD (generados por IA, con fondo
    /// calado a transparente). Patrón igual que GambitIcon: disco en Editor,
    /// Resources en build (Sprite directo o Texture2D→Sprite con borde 9-slice).
    /// Si un asset falta, devuelve null y el modal usa el fallback procedural.
    /// </summary>
    public static class VictoryAssets
    {
        private const string BasePath = "UI/Victory/";
        private const string DiskBase = "/Resources/UI/Victory/";

        private static readonly System.Collections.Generic.Dictionary<string, Sprite> _cache =
            new System.Collections.Generic.Dictionary<string, Sprite>();

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void Reset() { _cache.Clear(); }

        // Contenedores diseñados calados (marco dorado / plateado con todo lo
        // demás transparente). Border 9-slice medido: ornamentos hasta 259px
        // lados / 209px arriba-abajo (a 1400x781) → 260/210 sin estirar nada.
        public static Sprite LeftContainer => Get("LeftContainer", new Vector4(260, 210, 260, 210));
        public static Sprite RightContainer => Get("RightContainer", new Vector4(260, 210, 260, 210));
        public static Sprite StrongOverlay => Get("StrongOverlay", Vector4.zero);
        public static Sprite VictoryText => Get("VictoryText", Vector4.zero);
        public static Sprite RewardText => Get("RewardText", Vector4.zero);
        public static Sprite PerformanceText => Get("PerformanceText", Vector4.zero);
        public static Sprite GoldenDivider => Get("GoldenDivider", Vector4.zero);
        // Botones (PNG calados, esquinas 9-slice medidas sobre el arte):
// MajorButton 1800x422 -> ornamentacion entra ~131px por lado y ~108px en
// vertical; SecondaryButton 1800x364 -> ~125 por lado y ~96 en vertical.
        // Con el borde viejo (24) las esquinas se deformaban al estirar el centro.
        public static Sprite MajorButton => Get("MajorButton", new Vector4(130, 108, 130, 108));
        public static Sprite SecondaryButton => Get("SecondaryButton", new Vector4(125, 96, 125, 96));

        private static Sprite Get(string name, Vector4 border)
        {
            if (_cache.TryGetValue(name, out var cached)) return cached;
            var sprite = Load(name, border);
            _cache[name] = sprite;
            return sprite;
        }

        private static Sprite Load(string name, Vector4 border)
        {
            // 1. Disco (Editor, no depende del importador).
            try
            {
                string disk = Application.dataPath + DiskBase + name + ".png";
                if (System.IO.File.Exists(disk))
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(disk);
                    var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                    if (tex.LoadImage(bytes))
                    {
                        tex.filterMode = FilterMode.Bilinear;
                        tex.wrapMode = TextureWrapMode.Clamp;
                        return Wrap(tex, name, border);
                    }
                }
            }
            catch { /* sigue a Resources */ }

            // 2. Resources (builds: vale Sprite o Textura).
            try
            {
                Sprite spr = Resources.Load<Sprite>(BasePath + name);
                if (spr != null) return spr;
                Texture2D tex = Resources.Load<Texture2D>(BasePath + name);
                if (tex != null) return Wrap(tex, name, border);
            }
            catch { /* cae a null: fallback procedural */ }

            return null;
        }

        private static Sprite Wrap(Texture2D tex, string name, Vector4 border)
        {
            // FullRect a propósito: con marcos calados (transparencia exterior)
            // la malla Tight puede recortar el rect y descuadrar el 9-slice.
            var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                new Vector2(0.5f, 0.5f), 100f, 0, SpriteMeshType.FullRect, border);
            sprite.name = "victory-" + name;
            return sprite;
        }
    }
}
