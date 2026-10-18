using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>Animacion de boton: escala + color al pasar el raton o seleccionar con mando.</summary>
    public class MenuButtonFx : MonoBehaviour, IPointerEnterHandler, IPointerExitHandler, ISelectHandler, IDeselectHandler
    {
        public Graphic label;
        public Image accent;
        public Color normalColor = new Color(1f, 1f, 1f, 0.85f);
        public Color hoverColor = new Color(1f, 0.78f, 0.25f, 1f);
        public float hoverScale = 1.08f;

        private bool _hover;
        private bool _selected;
        private float _k;

        public void OnPointerEnter(PointerEventData e) => _hover = true;
        public void OnPointerExit(PointerEventData e) => _hover = false;
        public void OnSelect(BaseEventData e) => _selected = true;
        public void OnDeselect(BaseEventData e) => _selected = false;

        void Update()
        {
            float target = _hover || _selected ? 1f : 0f;
            _k = Mathf.MoveTowards(_k, target, Time.unscaledDeltaTime * 7f);
            float e = _k * _k * (3f - 2f * _k);
            float wobble = target > 0f ? Mathf.Sin(Time.unscaledTime * 6f) * 0.012f : 0f;
            transform.localScale = Vector3.one * (Mathf.Lerp(1f, hoverScale, e) + wobble);
            if (label != null) label.color = Color.Lerp(normalColor, hoverColor, e);
            if (accent != null)
            {
                var c = accent.color;
                c.a = e;
                accent.color = c;
                accent.rectTransform.localScale = new Vector3(Mathf.Lerp(0.2f, 1f, e), 1f, 1f);
            }
        }
    }
}
