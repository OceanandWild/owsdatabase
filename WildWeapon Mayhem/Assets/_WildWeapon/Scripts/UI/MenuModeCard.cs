using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Tarjeta de modo del menu principal. Al pasar el raton o seleccionarla con
    /// mando levanta el "cuerpo" de la tarjeta, enciende el acento y el halo, y
    /// avisa al panel de informacion para que muestre el detalle del modo.
    /// El animator de la escena anima la RAIZ de la tarjeta (intro / idle), asi
    /// que todo lo que se mueve en runtime va sobre el hijo "Body".
    /// </summary>
    public class MenuModeCard : MonoBehaviour, IPointerEnterHandler, IPointerExitHandler, ISelectHandler, IDeselectHandler
    {
        [Header("Cuerpo")]
        public RectTransform body;
        public Image frame;
        public Outline frameOutline;

        [Header("Acento")]
        public Image accent;
        public Image underline;
        public Image glow;
        public Color accentColor = new Color(0.25f, 0.88f, 1f, 1f);

        [Header("Textos")]
        public Graphic title;
        public Graphic subtitle;
        public Graphic indexLabel;

        [Header("Skin y emblema")]
        /// <summary>Emblema del modo (fondo, se pinta con el acento).</summary>
        public Image watermark;

        [Header("Detalle")]
        public MenuModeInfo info;
        public int modeIndex;

        [Header("Feel")]
        public float liftY = 18f;
        public float hoverScale = 1.05f;
        public float hoverTilt = 1.6f;
        public float speed = 8f;

        // Skin gris neutro: el tinte del frame lo viste con el acento de cada modo.
        private static readonly Color FrameTintIdle = new Color(0.78f, 0.82f, 0.92f, 0.92f);
        private static readonly Color TitleIdle = new Color(0.80f, 0.85f, 0.92f, 1f);
        private static readonly Color TitleHot = Color.white;

        private bool _hover;
        private bool _selected;
        private float _k = -1f;

        public bool Highlighted => _hover || _selected;

        public void OnPointerEnter(PointerEventData e)
        {
            _hover = true;
            Notify();
        }

        public void OnPointerExit(PointerEventData e) => _hover = false;

        public void OnSelect(BaseEventData e)
        {
            _selected = true;
            Notify();
        }

        public void OnDeselect(BaseEventData e) => _selected = false;

        private void Notify()
        {
            if (info != null) info.Show(modeIndex);
        }

        /// <summary>Usado por el builder/EventSystem para mostrar el modo por defecto.</summary>
        public void ShowInfo() => Notify();

        private void Update()
        {
            float target = Highlighted ? 1f : 0f;
            bool instant = _k < 0f;
            _k = instant ? target : Mathf.MoveTowards(_k, target, Time.unscaledDeltaTime * speed);
            float e = _k * _k * (3f - 2f * _k);

            if (body != null)
            {
                body.localScale = Vector3.one * Mathf.Lerp(1f, hoverScale, e);
                body.localRotation = Quaternion.Euler(0f, 0f, Mathf.Lerp(0f, hoverTilt, e));
                var p = body.anchoredPosition;
                p.y = Mathf.Lerp(0f, liftY, e);
                body.anchoredPosition = p;
            }

            if (frame != null)
            {
                // Skin neutro + acento del modo: reposo sutil, resaltado a color pleno.
                var tint = Color.Lerp(FrameTintIdle, accentColor, 0.28f);
                frame.color = Color.Lerp(tint, accentColor, e);
            }
            if (frameOutline != null)
            {
                var oc = accentColor;
                oc.a = Mathf.Lerp(0.16f, 0.85f, e);
                frameOutline.effectColor = oc;
            }

            if (accent != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.55f, 1f, e);
                accent.color = c;
                accent.rectTransform.localScale = new Vector3(Mathf.Lerp(0.42f, 1f, e), 1f, 1f);
            }

            if (underline != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.10f, 0.42f, e);
                underline.color = c;
                underline.rectTransform.localScale = new Vector3(Mathf.Lerp(0.7f, 1f, e), 1f, 1f);
            }

            if (glow != null)
            {
                var c = accentColor;
                c.a = e * 0.28f;
                glow.color = c;
                glow.rectTransform.localScale = Vector3.one * Mathf.Lerp(0.94f, 1.12f, e);
            }

            if (watermark != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.14f, 0.4f, e);
                watermark.color = c;
                watermark.rectTransform.localScale = Vector3.one * Mathf.Lerp(0.96f, 1.07f, e);
            }

            if (title != null) title.color = Color.Lerp(TitleIdle, TitleHot, e);

            if (subtitle != null)
            {
                var c = subtitle.color;
                c.a = Mathf.Lerp(0.5f, 0.95f, e);
                subtitle.color = c;
            }

            if (indexLabel != null)
            {
                var c = Color.white;
                c.a = Mathf.Lerp(0.14f, 0.4f, e);
                indexLabel.color = c;
            }
        }
    }
}
