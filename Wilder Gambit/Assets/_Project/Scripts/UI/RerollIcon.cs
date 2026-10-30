using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Icono de Cambio de Misión: dado dorado con flechas de reroll, sin fondo
    /// (<c>Resources/UI/reroll_icon.png</c>). Reemplaza al emoji 🎲 en el pase.
    /// Blindaje: si el sprite no carga, se cae al glifo 🎲 en texto.
    /// </summary>
    public static class RerollIcon
    {
        public const string ResourcePath = "UI/reroll_icon";
        public const string FallbackGlyph = "🎲";

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
                string disk = System.IO.Path.Combine(Application.dataPath, "Resources", "UI", "reroll_icon.png");
                if (System.IO.File.Exists(disk))
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(disk);
                    var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                    if (tex.LoadImage(bytes))
                    {
                        tex.filterMode = FilterMode.Bilinear;
                        var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                            new Vector2(0.5f, 0.5f), 100f);
                        sprite.name = "reroll-icon";
                        return sprite;
                    }
                }
            }
            catch { /* sigue a Resources */ }

            // 2. Resources (builds: vale Textura o Sprite).
            try
            {
                Texture2D tex = Resources.Load<Texture2D>(ResourcePath);
                if (tex != null)
                {
                    var sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                        new Vector2(0.5f, 0.5f), 100f);
                    sprite.name = "reroll-icon";
                    return sprite;
                }
                Sprite spr = Resources.Load<Sprite>(ResourcePath);
                if (spr != null) return spr;
            }
            catch { /* cae al glifo */ }

            _missed = true;
            return null;
        }
    }
}
