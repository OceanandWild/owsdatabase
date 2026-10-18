using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Tarjeta de arena del selector de mapa. Muestra la vista previa del fondo del
    /// mapa y, al pasar el raton o seleccionarla con mando, levanta el cuerpo,
    /// enciende el acento del tema y avisa al selector para que actualice la ficha.
    /// La animacion de entrada la lleva la raiz de la tarjeta (animator de escena),
    /// asi que todo lo que se mueve en runtime vive sobre el hijo "Body".
    /// </summary>
    public class MapSelectCard : MonoBehaviour, IPointerEnterHandler, IPointerExitHandler, ISelectHandler, IDeselectHandler
    {
        [Header("Cuerpo")]
        public RectTransform body;
        public Image frame;
        public Outline frameOutline;

        [Header("Vista previa")]
        public Image preview;
        public Image shade;
        public Image accent;
        public Image glow;

        [Header("Textos")]
        public Graphic title;
        public Graphic subtitle;
        public Graphic indexLabel;
        public Graphic sizeLabel;

        [Header("Datos")]
        public MapSelectController owner;
        public int index;

        [Header("Feel")]
        public float liftY = 14f;
        public float hoverScale = 1.045f;
        public float speed = 9f;

        private static readonly Color FrameTintIdle = new Color(0.72f, 0.78f, 0.9f, 0.94f);
        private static readonly Color TitleIdle = new Color(0.86f, 0.9f, 0.96f, 1f);
        private static readonly Color TitleHot = Color.white;

        public Color accentColor { get; private set; } = new Color(0.26f, 0.88f, 1f);

        private bool _hover;
        private bool _focused;
        private float _k = -1f;

        public MapDef Def { get; private set; }

        /// <summary>Destacada (hover/foco) o elegida por el jugador.</summary>
        public bool Highlighted => _hover || _focused;

        private bool SelectedByOwner => owner != null && owner.SelectedIndex == index;

        public void Bind(MapDef def)
        {
            Def = def;
            if (def == null) return;

            accentColor = def.accent;

            if (preview != null)
            {
                preview.sprite = def.previewSprite != null ? def.previewSprite : def.floorSprite;
                preview.color = Color.white;
                preview.preserveAspect = false;
                preview.enabled = preview.sprite != null;
            }

            if (title != null) title.GetComponent<Text>().text = def.displayName.ToUpperInvariant();
            if (subtitle != null) subtitle.GetComponent<Text>().text = def.subtitle;
            if (sizeLabel != null) sizeLabel.GetComponent<Text>().text = SizeText(def.sizeClass);
            if (indexLabel != null) indexLabel.GetComponent<Text>().text = (index + 1).ToString("00");

            if (accent != null) accent.color = accentColor;
            if (glow != null) glow.color = new Color(accentColor.r, accentColor.g, accentColor.b, 0f);
            if (frameOutline != null) frameOutline.effectColor = new Color(accentColor.r, accentColor.g, accentColor.b, 0.18f);
            if (shade != null) shade.color = new Color(0.02f, 0.03f, 0.05f, 0.5f);
        }

        public static string SizeText(MapSizeClass size)
        {
            switch (size)
            {
                case MapSizeClass.Chico: return "CHICA";
                case MapSizeClass.Grande: return "GRANDE";
                default: return "MEDIANA";
            }
        }

        public void OnPointerEnter(PointerEventData e)
        {
            _hover = true;
            Notify();
        }

        public void OnPointerExit(PointerEventData e) => _hover = false;

        public void OnSelect(BaseEventData e)
        {
            _focused = true;
            Notify();
        }

        public void OnDeselect(BaseEventData e) => _focused = false;

        private void Notify()
        {
            if (owner != null) owner.Highlight(index);
        }

        private void Update()
        {
            float target = SelectedByOwner ? 1f : (Highlighted ? 0.62f : 0f);
            bool instant = _k < 0f;
            _k = instant ? target : Mathf.MoveTowards(_k, target, Time.unscaledDeltaTime * speed);
            float e = _k * _k * (3f - 2f * _k);

            if (body != null)
            {
                body.localScale = Vector3.one * Mathf.Lerp(1f, SelectedByOwner ? hoverScale * 1.01f : hoverScale, e);
                var p = body.anchoredPosition;
                p.y = Mathf.Lerp(0f, liftY, e);
                body.anchoredPosition = p;
            }

            if (frame != null) frame.color = Color.Lerp(FrameTintIdle, accentColor, e * 0.75f);
            if (frameOutline != null)
            {
                var oc = accentColor;
                oc.a = Mathf.Lerp(0.18f, 0.95f, e);
                frameOutline.effectColor = oc;
            }

            if (accent != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.6f, 1f, e);
                accent.color = c;
                accent.rectTransform.localScale = new Vector3(Mathf.Lerp(0.5f, 1f, e), 1f, 1f);
            }

            if (glow != null)
            {
                var c = accentColor;
                c.a = e * 0.3f;
                glow.color = c;
                glow.rectTransform.localScale = Vector3.one * Mathf.Lerp(0.95f, 1.1f, e);
            }

            if (preview != null)
            {
                var c = Color.Lerp(new Color(0.62f, 0.68f, 0.78f, 1f), Color.white, e);
                preview.color = c;
            }

            if (shade != null)
            {
                var c = shade.color;
                c.a = Mathf.Lerp(0.62f, 0.24f, e);
                shade.color = c;
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
                c.a = Mathf.Lerp(0.16f, 0.42f, e);
                indexLabel.color = c;
            }
            if (sizeLabel != null)
            {
                var c = accentColor;
                c.a = Mathf.Lerp(0.35f, 0.95f, e);
                sizeLabel.color = c;
            }
        }
    }
}
