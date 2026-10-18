using UnityEngine;
using UnityEngine.InputSystem;

namespace WildWeapon.UI
{
    /// <summary>
    /// Parallax suave del fondo del menu segun el mouse: cada capa se desplaza un
    /// poco distinto, lo que da sensacion de profundidad sin tocar los botones.
    /// Sirve tambien para el stick del mando si hay uno conectado.
    /// </summary>
    public class MenuParallax : MonoBehaviour
    {
        [System.Serializable]
        public class Layer
        {
            public RectTransform rect;
            public float depth = 1f;
        }

        public Layer[] layers;
        public float maxOffset = 26f;
        public float smooth = 5f;

        private Vector2 _k;
        private Vector2[] _home;

        private void Awake()
        {
            if (layers == null) return;
            _home = new Vector2[layers.Length];
            for (int i = 0; i < layers.Length; i++)
                _home[i] = layers[i] != null && layers[i].rect != null ? layers[i].rect.anchoredPosition : Vector2.zero;
        }

        private void Update()
        {
            if (layers == null || layers.Length == 0) return;

            Vector2 want = Vector2.zero;
            var mouse = Mouse.current;
            if (mouse != null)
            {
                Vector2 p = mouse.position.ReadValue();
                float w = Mathf.Max(1f, Screen.width);
                float h = Mathf.Max(1f, Screen.height);
                want = new Vector2(
                    Mathf.Clamp(p.x / w * 2f - 1f, -1f, 1f),
                    Mathf.Clamp(p.y / h * 2f - 1f, -1f, 1f));
            }
            else
            {
                var pad = Gamepad.current;
                if (pad != null) want = Vector2.ClampMagnitude(pad.leftStick.ReadValue(), 1f);
            }

            _k = Vector2.Lerp(_k, want, 1f - Mathf.Exp(-smooth * Time.unscaledDeltaTime));

            for (int i = 0; i < layers.Length; i++)
            {
                var l = layers[i];
                if (l == null || l.rect == null) continue;
                l.rect.anchoredPosition = _home[i] - _k * (maxOffset * l.depth);
            }
        }
    }
}
