using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Icono de la divisa Gambits: moneda-corona dorada sin fondo
    /// (<c>Resources/UI/gambits_icon.png</c>). Reemplaza al emoji ♔ en todo
    /// el juego (pase, tienda, inventario, progreso, game over, toasts).
    /// Blindaje: si el sprite no carga, las filas caen al glifo ♔ en texto.
    /// </summary>
    public static class GambitIcon
    {
        public const string ResourcePath = "UI/gambits_icon";
        public const string FallbackGlyph = "♔";

        private static Sprite _sprite;
        private static bool _missed;

        // Con "Fast Play Mode" los estáticos sobreviven entre Plays.
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void Reset() { _sprite = null; _missed = false; }

        public static Sprite Sprite
        {
            get
            {
                if (_sprite == null && !_missed) _sprite = Load();
                return _sprite;
            }
        }

        private static Sprite Load()
        {
            // 1. Disco (Editor, no depende del tipo de importación).
            try
            {
                string disk = System.IO.Path.Combine(Application.dataPath, "Resources", "UI", "gambits_icon.png");
                if (System.IO.File.Exists(disk))
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(disk);
                    var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                    if (tex.LoadImage(bytes))
                    {
                        tex.filterMode = FilterMode.Bilinear;
                        return Wrap(tex);
                    }
                }
            }
            catch { /* sigue a Resources */ }

            // 2. Resources (builds: vale Textura o Sprite).
            try
            {
                Texture2D tex = Resources.Load<Texture2D>(ResourcePath);
                if (tex != null) return Wrap(tex);
                Sprite spr = Resources.Load<Sprite>(ResourcePath);
                if (spr != null) return spr;
            }
            catch { /* cae al glifo */ }

            _missed = true;
            return null;
        }

        private static Sprite Wrap(Texture2D tex)
        {
            var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                new Vector2(0.5f, 0.5f), 100f);
            sprite.name = "gambits-icon";
            return sprite;
        }

        /// <summary>Icono suelto del tamaño indicado (px a k = 1).</summary>
        public static VisualElement Icon(float size = 20f)
        {
            var el = new VisualElement();
            el.AddToClassList("gambits-inline-icon");
            el.pickingMode = PickingMode.Ignore;
            el.style.width = size;
            el.style.height = size;
            el.style.flexShrink = 0;
            Sprite sprite = Sprite;
            if (sprite != null)
            {
                el.style.backgroundImage = new StyleBackground(sprite);
            }
            else
            {
                // Blindaje: glifo de texto si el PNG no está.
                var fallback = new Label(FallbackGlyph);
                fallback.pickingMode = PickingMode.Ignore;
                el.Add(fallback);
            }
            return el;
        }

        /// <summary>
        /// Fila icono + texto (texto SIN emoji, p. ej. <c>"1.050"</c> o
        /// <c>"350 Gambits"</c>). El label interno lleva las clases de estilo.
        /// </summary>
        public static VisualElement Row(string text, float iconSize, params string[] labelClasses)
        {
            var row = new VisualElement();
            row.AddToClassList("gambits-inline-row");
            row.pickingMode = PickingMode.Ignore;
            Sprite sprite = Sprite;
            if (sprite != null)
            {
                var icon = Icon(iconSize);
                icon.style.marginRight = 6f;
                row.Add(icon);
                var label = new Label(text);
                foreach (string c in labelClasses) label.AddToClassList(c);
                label.AddToClassList("gambits-inline-text");
                label.pickingMode = PickingMode.Ignore;
                row.Add(label);
            }
            else
            {
                var label = new Label($"{FallbackGlyph} {text}");
                foreach (string c in labelClasses) label.AddToClassList(c);
                label.pickingMode = PickingMode.Ignore;
                row.Add(label);
            }
            return row;
        }

        /// <summary>Monto de Gambits con icono (p. ej. <c>"1.050"</c>).</summary>
        public static VisualElement Amount(int amount, float iconSize, params string[] labelClasses) =>
            Row($"{amount:N0}", iconSize, labelClasses);

        /// <summary>Precio con icono (p. ej. <c>"350 Gambits"</c>).</summary>
        public static VisualElement Price(int price, float iconSize, params string[] labelClasses) =>
            Row($"{price:N0} Gambits", iconSize, labelClasses);
    }
}
