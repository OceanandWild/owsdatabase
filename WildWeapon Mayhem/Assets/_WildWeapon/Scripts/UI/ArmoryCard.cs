using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Tarjeta de arma de la armería. Muestra el icono del arma con sus stats y,
    /// al pasar el ratón o seleccionarla con mando, levanta el cuerpo y enciende
    /// el acento. Si el arma ya está equipada, la tarjeta queda marcada con el
    /// número de ranura.
    /// </summary>
    public class ArmoryCard : MonoBehaviour, IPointerEnterHandler, IPointerExitHandler, ISelectHandler, IDeselectHandler
    {
        [Header("Cuerpo")]
        public RectTransform body;
        public Image frame;
        public Outline frameOutline;

        [Header("Acento")]
        public Image accentBar;
        public Image glow;

        [Header("Contenido")]
        public Image icon;
        public Graphic title;
        public Graphic stats;
        public Graphic badge;

        [Header("Datos")]
        public ArmoryController owner;
        public int index;
        public string weaponId = "";
        public string displayName = "";

        [Header("Feel")]
        public float liftY = 12f;
        public float hoverScale = 1.045f;
        public float speed = 9f;

        private static readonly Color FrameTintIdle = new Color(0.72f, 0.78f, 0.9f, 0.92f);
        private static readonly Color TitleIdle = new Color(0.84f, 0.88f, 0.95f, 1f);
        private static readonly Color TitleHot = Color.white;

        private bool _hover;
        private bool _focused;
        private float _k = -1f;
        private bool _notified;

        /// <summary>Color de acento de esta arma (lo define la armería).</summary>
        public Color accentColor { get; private set; } = new Color(1f, 0.62f, 0.18f, 1f);

        public bool Highlighted => _hover || _focused;

        /// <summary>Ranura donde esta el arma (0 o 1), o -1 si no esta equipada.</summary>
        public int EquippedSlot { get; private set; } = -1;

        public void Bind(string id, string displayName, Sprite weaponSprite, Color accentTint)
        {
            weaponId = id ?? "";
            this.displayName = displayName ?? "";
            accentColor = accentTint;

            if (icon != null)
            {
                icon.sprite = weaponSprite;
                icon.enabled = weaponSprite != null;
                icon.preserveAspect = true;
            }
            if (title != null) title.GetComponent<Text>().text = this.displayName.ToUpperInvariant();
            if (accentBar != null) accentBar.color = accentColor;
            if (glow != null) glow.color = new Color(accentColor.r, accentColor.g, accentColor.b, 0f);
            if (frameOutline != null) frameOutline.effectColor = new Color(accentColor.r, accentColor.g, accentColor.b, 0.18f);
        }

        /// <summary>Marca la ranura en la que esta el arma (-1 = sin equipar).</summary>
        public void SetEquippedSlot(int slot)
        {
            EquippedSlot = slot;
            if (badge == null) return;
            var t = badge.GetComponent<Text>();
            if (slot < 0)
            {
                t.text = "";
                badge.enabled = false;
            }
            else
            {
                t.text = (slot + 1).ToString();
                badge.enabled = true;
            }
        }

        public void OnPointerEnter(PointerEventData e) => _hover = true;
        public void OnPointerExit(PointerEventData e) => _hover = false;
        public void OnSelect(BaseEventData e) => _focused = true;
        public void OnDeselect(BaseEventData e) => _focused = false;

        private void Notify()
        {
            if (owner != null) owner.ShowWeapon(index);
        }

        private void Update()
        {
            if (!_notified && Highlighted) { _notified = true; Notify(); }
            else if (_notified && !Highlighted) _notified = false;

            float target = Highlighted ? 1f : 0f;
            bool instant = _k < 0f;
            _k = instant ? target : Mathf.MoveTowards(_k, target, Time.unscaledDeltaTime * speed);
            float e = _k * _k * (3f - 2f * _k);

            if (body != null)
            {
                body.localScale = Vector3.one * Mathf.Lerp(1f, hoverScale, e);
                var p = body.anchoredPosition;
                p.y = Mathf.Lerp(0f, liftY, e);
                body.anchoredPosition = p;
            }

            if (frame != null) frame.color = Color.Lerp(FrameTintIdle, accentColor, e * 0.8f);

            if (frameOutline != null)
            {
                var oc = accentColor;
                oc.a = Mathf.Lerp(0.18f, 0.95f, e);
                frameOutline.effectColor = oc;
            }

            if (accentBar != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.6f, 1f, e);
                accentBar.color = c;
                accentBar.rectTransform.localScale = new Vector3(Mathf.Lerp(0.5f, 1f, e), 1f, 1f);
            }

            if (glow != null)
            {
                var c = accentColor;
                c.a = e * 0.3f;
                glow.color = c;
                glow.rectTransform.localScale = Vector3.one * Mathf.Lerp(0.95f, 1.1f, e);
            }

            if (icon != null)
            {
                var c = Color.Lerp(new Color(0.66f, 0.72f, 0.82f, 1f), Color.white, e);
                icon.color = c;
            }

            if (title != null) title.color = Color.Lerp(TitleIdle, TitleHot, e);

            if (badge != null && badge.enabled)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.55f, 1f, e);
                badge.color = c;
            }
        }
    }
}
