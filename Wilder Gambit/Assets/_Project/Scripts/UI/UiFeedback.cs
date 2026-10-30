using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.UI;
using WilderGambit.Audio;

namespace WilderGambit.UI
{
    /// <summary>
    /// Efectos de hover y click para los botones que se arman por codigo.
    /// Todo el UI del proyecto se construye en runtime (no hay prefabs con
    /// Button), asi que sin esto cada boton cae en el ColorBlock por defecto de
    /// Unity: hover casi blanco, imperceptible sobre un fondo ya de color.
    ///
    /// La mayoria de los botones ya lo traian a mano (PromotionModal,
    /// TributoModal, GameOverModal). Este helper cubre los que faltaban y deja
    /// el criterio (hover = mas claro, click = destello dorado) en un solo lugar.
    /// </summary>
    public static class UiFeedback
    {
        /// <summary>
        /// Aplica hover + click y ASEGURA que el boton tenga targetGraphic.
        /// Esto ultimo importa: si el Button se agrego antes que el Image, el
        /// Awake de Selectable corrio sin ningun Graphic presente, dejo
        /// targetGraphic en null y la transicion no hacia absolutamente nada.
        /// </summary>
        public static void Apply(Button btn, Color normal, Color highlighted, Color pressed, float fade = 0.09f)
        {
            if (btn == null) return;

            if (btn.targetGraphic == null) btn.targetGraphic = btn.GetComponent<Graphic>();
            if (btn.targetGraphic == null) return; // sin Graphic no hay a que teñir

            ColorBlock cb = btn.colors;
            cb.normalColor = normal;
            cb.highlightedColor = highlighted;
            cb.pressedColor = pressed;
            cb.selectedColor = normal;
            cb.disabledColor = new Color(normal.r, normal.g, normal.b, normal.a * 0.45f);
            cb.colorMultiplier = 1f;
            cb.fadeDuration = fade;
            btn.colors = cb;
            btn.transition = Selectable.Transition.ColorTint;
        }

        /// <summary>Hover y click derivados del color base (gana/perdida de brillo).</summary>
        public static void Apply(Button btn, Color normal, float hoverGain = 1.55f, float pressGain = 0.75f, float fade = 0.09f)
        {
            Apply(btn, normal, Gain(normal, hoverGain), Gain(normal, pressGain), fade);
        }

        /// <summary>
        /// Escala SOLO el RGB de un color. Multiplicar el alfa tambien (un
        /// Gain sobre Color.white) volveria el boton invisible de un tirón.
        /// </summary>
        public static Color Gain(Color c, float k)
        {
            return new Color(
                Mathf.Clamp01(c.r * k),
                Mathf.Clamp01(c.g * k),
                Mathf.Clamp01(c.b * k),
                c.a);
        }

        /// <summary>
        /// Engancha el sonido de hover y de click de un boton uGUI. La UI
        /// Toolkit ya los tiene (RegisterSoundEffects en MainMenuController y
        /// PauseMenuController), pero los modales uGUI —que son los que se
        /// arman con new GameObject— no: quedaban mudos.
        ///
        /// El click suena al PRESIONAR y no al soltar, a proposito. Si el boton
        /// navega (ir al menu, reiniciar, reanudar) el clic dispara el cambio de
        /// pantalla en el mismo frame y el sonido se cortaba a los milisegundos:
        /// en el menu de pausa solo se oia en los botones que no navegan
        /// (deshacer, historial). Anticipandolo, arranca antes de que la accion
        /// toque nada y se escucha entero. El precio es que suena tambien al
        /// presionar y soltar fuera, que es el trade-off habitual de esto.
        ///
        /// uGUI no expone ningun evento de hover en Selectable: el Button solo
        /// recibe los eventos del EventSystem a traves de su Graphic.
        /// </summary>
        /// <param name="isBack">El boton "vuelve" en vez de confirmar (menu principal, salir).</param>
        public static void AttachSounds(Button btn, bool isBack = false)
        {
            if (btn == null) return;
            // Sin este tope, llamar dos veces sobre el mismo boton (lo recrea
            // el modal en cada Show) dejaria dos handlers y el sonido duplicado.
            if (btn.GetComponent<UiSfxHook>() != null) return;
            btn.gameObject.AddComponent<UiSfxHook>();

            btn.gameObject.AddComponent<UiPressSfx>().Init(isBack);

            Graphic target = btn.targetGraphic != null ? btn.targetGraphic : btn.GetComponent<Graphic>();
            if (target != null) target.gameObject.AddComponent<UiHoverSfx>();
        }
    }

    /// <summary>Marca de que el boton ya tiene el sonido enganchado (ver UiFeedback.AttachSounds).</summary>
    public sealed class UiSfxHook : MonoBehaviour { }

    /// <summary>
    /// Hover de sonido para uGUI: no hay evento de hover en Selectable, asi que
    /// se resuelve con el handler de puntero que el EventSystem ya le pasa a
    /// los Graphic. Vive en el Graphic (y no en el Button) porque es el Raycast
    /// el que decide que hay puntero encima.
    /// </summary>
    public sealed class UiHoverSfx : MonoBehaviour, IPointerEnterHandler
    {
        public void OnPointerEnter(PointerEventData eventData)
        {
            MusicManager.Instance?.PlayHoverSound();
        }
    }

    /// <summary>Click de sonido al presionar. Ver por que no en el clic: UiFeedback.AttachSounds.</summary>
    public sealed class UiPressSfx : MonoBehaviour, IPointerDownHandler
    {
        private bool _isBack;

        public void Init(bool isBack) => _isBack = isBack;

        public void OnPointerDown(PointerEventData eventData)
        {
            if (_isBack) MusicManager.Instance?.PlayBackSound();
            else MusicManager.Instance?.PlayClickSound();
        }
    }
}