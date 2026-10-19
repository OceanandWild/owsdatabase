using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Ranura de equipamiento de la armería. Muestra el arma equipada y queda
    /// encendida cuando es la ranura activa (la que recibe el próximo clic).
    /// Clickearla la vuelve activa.
    /// </summary>
    public class ArmorySlot : MonoBehaviour, IPointerClickHandler, ISelectHandler
    {
        [Header("Piezas")]
        public Image frame;
        public Outline frameOutline;
        public Image accentBar;
        public Image icon;
        public Graphic label;
        public Graphic caption;

        [Header("Datos")]
        public ArmoryController owner;
        public int slotIndex;

        [Header("Feel")]
        public float speed = 10f;

        private static readonly Color FrameTintIdle = new Color(0.66f, 0.72f, 0.84f, 0.9f);
        private static readonly Color FrameTintHot = new Color(1f, 0.62f, 0.18f, 0.95f);

        private float _k = -1f;

        /// <summary>Color de acento de la ranura.</summary>
        public Color accentColor { get; private set; } = new Color(1f, 0.62f, 0.18f, 1f);

        public bool IsActiveSlot => owner != null && owner.ActiveSlot == slotIndex;

        /// <summary>Pinta el arma de la ranura (id vacio = ranura libre).</summary>
        public void Bind(string weaponId, string displayName, Sprite weaponSprite, Color accentTint)
        {
            accentColor = accentTint;

            if (label != null) label.GetComponent<Text>().text = "RANURA " + (slotIndex + 1);
            if (caption != null) caption.GetComponent<Text>().text = string.IsNullOrEmpty(weaponId)
                ? "VACÍA"
                : displayName.ToUpperInvariant();

            if (icon != null)
            {
                icon.sprite = weaponSprite;
                icon.enabled = weaponSprite != null;
                icon.preserveAspect = true;
            }
            if (accentBar != null) accentBar.color = accentColor;
        }

        public void OnPointerClick(PointerEventData e)
        {
            if (owner != null) owner.SelectSlot(slotIndex);
        }

        public void OnSelect(BaseEventData e)
        {
            if (owner != null) owner.SelectSlot(slotIndex);
        }

        private void Update()
        {
            float target = IsActiveSlot ? 1f : 0f;
            bool instant = _k < 0f;
            _k = instant ? target : Mathf.MoveTowards(_k, target, Time.unscaledDeltaTime * speed);
            float e = _k * _k * (3f - 2f * _k);

            if (frame != null) frame.color = Color.Lerp(FrameTintIdle, FrameTintHot, e);

            if (frameOutline != null)
            {
                var oc = accentColor;
                oc.a = Mathf.Lerp(0.16f, 0.9f, e);
                frameOutline.effectColor = oc;
            }

            if (accentBar != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.35f, 1f, e);
                accentBar.color = c;
            }

            if (icon != null)
            {
                var c = Color.Lerp(new Color(0.6f, 0.66f, 0.76f, 1f), Color.white, e);
                icon.color = c;
            }

            if (label != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.55f, 1f, e);
                label.color = c;
            }

            if (caption != null)
            {
                var c = caption.color;
                c.a = Mathf.Lerp(0.7f, 1f, e);
                caption.color = c;
            }
        }
    }
}
