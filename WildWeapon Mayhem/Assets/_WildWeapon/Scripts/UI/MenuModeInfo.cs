using UnityEngine;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Globo compacto de detalle del modo elegido en el menu. Las tarjetas
    /// (<see cref="MenuModeCard"/>) lo llaman al pasar el raton o al seleccionarse
    /// con mando. Aparece encima de la tarjeta, con una flecha hacia abajo, y se
    /// oculta al salir para no dejar informacion fija ocupando la pantalla.
    /// </summary>
    public class MenuModeInfo : MonoBehaviour
    {
        [System.Serializable]
        public class Entry
        {
            public string title;
            [TextArea(2, 4)] public string blurb;
            public Color accent = Color.white;
        }

        public Entry[] modes;
        public CanvasGroup group;
        public Text title;
        public Text blurb;
        public Image accentBar;
        public Image frame;
        public Outline frameOutline;
        public Text arrow;

        [Header("Feel")]
        public float speed = 18f;
        public float slideFrom = 10f;

        private RectTransform _rt;
        private RectTransform _parent;
        private float _baseY;
        private Vector2 _home;
        private int _index = -1;
        private bool _visible;
        private float _k;

        private void Awake()
        {
            _rt = (RectTransform)transform;
            _parent = _rt.parent as RectTransform;
            _baseY = _rt.anchoredPosition.y;
            _home = _rt.anchoredPosition;
        }

        private void Start()
        {
            HideImmediate();
        }

        /// <summary>Muestra el detalle de la tarjeta indicada y apunta la flecha hacia ella.</summary>
        public void Show(int index, RectTransform target)
        {
            if (modes == null || index < 0 || index >= modes.Length) return;

            _index = index;
            var entry = modes[index];
            if (title != null) title.text = entry.title;
            if (blurb != null) blurb.text = entry.blurb;

            var accent = entry.accent.a > 0f ? entry.accent : Color.white;
            if (accentBar != null) accentBar.color = accent;
            if (arrow != null) arrow.color = accent;
            if (frame != null)
                frame.color = Color.Lerp(new Color(0.018f, 0.03f, 0.055f, 0.94f), accent, 0.08f);
            if (frameOutline != null)
            {
                var oc = accent;
                oc.a = 0.45f;
                frameOutline.effectColor = oc;
            }

            float x = 0f;
            float targetX = 0f;
            if (target != null && _parent != null)
            {
                Vector3 world = target.TransformPoint(target.rect.center);
                targetX = _parent.InverseTransformPoint(world).x;
                x = targetX;
            }

            float half = _rt != null ? _rt.rect.width * 0.5f : 180f;
            float limit = _parent != null ? _parent.rect.width * 0.5f : 960f;
            x = Mathf.Clamp(x, -limit + half + 24f, limit - half - 24f);
            _home = new Vector2(x, _baseY);

            if (arrow != null)
            {
                var art = arrow.rectTransform;
                var p = art.anchoredPosition;
                p.x = Mathf.Clamp(targetX - x, -half + 36f, half - 36f);
                art.anchoredPosition = p;
            }

            if (!_visible)
            {
                // Si venia desapareciendo, continua desde su alpha actual para
                // que pasar de una tarjeta a otra no produzca un parpadeo.
                if (_k <= 0f)
                {
                    _k = 0f;
                    if (_rt != null) _rt.anchoredPosition = _home + new Vector2(0f, slideFrom);
                    if (group != null) group.alpha = 0f;
                }
            }
            else if (_k >= 1f && _rt != null)
            {
                _rt.anchoredPosition = _home;
            }

            _visible = true;
        }

        /// <summary>Oculta el globo solo si sigue mostrando esa tarjeta.</summary>
        public void Hide(int index)
        {
            if (index == _index) _visible = false;
        }

        public void HideImmediate()
        {
            _visible = false;
            _k = 0f;
            _index = -1;
            if (group != null) group.alpha = 0f;
            if (_rt != null) _rt.anchoredPosition = _home;
        }

        private void Update()
        {
            float target = _visible ? 1f : 0f;
            if (Mathf.Approximately(_k, target)) return;

            _k = Mathf.MoveTowards(_k, target, Time.unscaledDeltaTime * speed);
            float e = _k * _k * (3f - 2f * _k);
            if (group != null) group.alpha = e;
            if (_rt != null)
                _rt.anchoredPosition = Vector2.Lerp(_home + new Vector2(0f, slideFrom), _home, e);
        }
    }
}
