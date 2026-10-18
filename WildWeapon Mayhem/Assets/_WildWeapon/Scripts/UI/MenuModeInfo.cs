using UnityEngine;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Franja de detalle del modo elegido en el menu: titulo, bajada y fichas de
    /// datos. Las tarjetas (<see cref="MenuModeCard"/>) la llaman al pasar el raton
    /// o al seleccionarse con mando, y el contenido entra con un fundido + desliz.
    /// </summary>
    public class MenuModeInfo : MonoBehaviour
    {
        [System.Serializable]
        public class Entry
        {
            public string title;
            [TextArea(2, 4)] public string blurb;
            public string[] chips = new string[0];
            public Color accent = Color.white;
        }

        [System.Serializable]
        public class Chip
        {
            public CanvasGroup group;
            public Image bg;
            public Text label;
        }

        public Entry[] modes;
        public CanvasGroup group;
        public Text title;
        public Text blurb;
        public Image accentBar;
        public Image frame;
        public Image watermark;
        public Sprite[] modeIcons = new Sprite[0];
        public Chip[] chips = new Chip[0];

        // El skin de la franja y las fichas es gris neutro: se tintea con el acento del modo.
        private static readonly Color FrameTint = new Color(0.80f, 0.84f, 0.92f, 0.97f);
        private static readonly Color ChipTint = new Color(0.82f, 0.86f, 0.94f, 0.95f);

        [Header("Feel")]
        public float speed = 11f;
        public float slideFrom = -18f;
        /// <summary>Retardo del primer cambio (lo usa el intro del menu para no pisarlo).</summary>
        public float startDelay = 0.8f;

        private RectTransform _rt;
        private Vector2 _home;
        private int _index = -1;
        private float _k = 1f;
        private float _delay;
        private bool _first = true;

        private void Awake()
        {
            _rt = (RectTransform)transform;
            _home = _rt.anchoredPosition;
        }

        private void Start()
        {
            if (modes != null && modes.Length > 0) Show(0);
        }

        /// <summary>Muestra el detalle del modo indicado (0-based).</summary>
        public void Show(int index)
        {
            if (modes == null || index < 0 || index >= modes.Length || index == _index) return;
            _index = index;

            var entry = modes[index];
            if (title != null) title.text = entry.title;
            if (blurb != null) blurb.text = entry.blurb;

            var accent = entry.accent.a > 0f ? entry.accent : Color.white;
            if (accentBar != null) accentBar.color = accent;
            if (frame != null) frame.color = Color.Lerp(FrameTint, accent, 0.30f);
            if (watermark != null)
            {
                if (modeIcons != null && index < modeIcons.Length && modeIcons[index] != null) watermark.sprite = modeIcons[index];
                watermark.color = new Color(accent.r, accent.g, accent.b, 0.16f);
            }

            for (int i = 0; i < chips.Length; i++)
            {
                var chip = chips[i];
                if (chip == null || chip.group == null) continue;
                bool used = entry.chips != null && i < entry.chips.Length && !string.IsNullOrEmpty(entry.chips[i]);
                if (chip.label != null && used) chip.label.text = entry.chips[i];
                if (chip.bg != null) chip.bg.color = Color.Lerp(ChipTint, accent, 0.5f);
                chip.group.alpha = used ? 1f : 0f;
                chip.group.gameObject.SetActive(used);
            }

            _k = 0f;
            _delay = _first ? startDelay : 0f;
            _first = false;
            if (group != null) group.alpha = 0f;
            if (_rt != null) _rt.anchoredPosition = _home + new Vector2(0f, slideFrom);
        }

        private void Update()
        {
            if (_delay > 0f)
            {
                _delay -= Time.unscaledDeltaTime;
                return;
            }
            if (_k >= 1f) return;

            _k = Mathf.Min(1f, _k + Time.unscaledDeltaTime * speed);
            float e = _k * _k * (3f - 2f * _k);

            if (group != null) group.alpha = e;
            if (_rt != null) _rt.anchoredPosition = Vector2.Lerp(_home + new Vector2(0f, slideFrom), _home, e);
        }
    }
}
