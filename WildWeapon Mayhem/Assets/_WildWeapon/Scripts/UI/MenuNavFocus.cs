using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.InputSystem;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Mantiene el menu sin foco visible al arrancar, para que la primera tarjeta
    /// no parezca hovereada. El foco recien aparece cuando el jugador navega con
    /// teclado o mando; mover el mouse lo vuelve a soltar.
    /// </summary>
    public class MenuNavFocus : MonoBehaviour
    {
        public EventSystem events;
        public Selectable first;

        private Vector2 _mouse;

        private void Start()
        {
            if (events == null) events = EventSystem.current;
            if (Mouse.current != null) _mouse = Mouse.current.position.ReadValue();
            if (events != null) events.SetSelectedGameObject(null);
        }

        private void Update()
        {
            if (events == null || first == null) return;

            if (Mouse.current != null)
            {
                Vector2 p = Mouse.current.position.ReadValue();
                if ((p - _mouse).sqrMagnitude > 4f)
                {
                    _mouse = p;
                    if (events.currentSelectedGameObject != null)
                        events.SetSelectedGameObject(null);
                }
            }

            if (events.currentSelectedGameObject == null && Navigated())
                events.SetSelectedGameObject(first.gameObject);
        }

        private static bool Navigated()
        {
            var kb = Keyboard.current;
            if (kb != null && (kb.leftArrowKey.wasPressedThisFrame || kb.rightArrowKey.wasPressedThisFrame
                || kb.upArrowKey.wasPressedThisFrame || kb.downArrowKey.wasPressedThisFrame))
                return true;

            var gp = Gamepad.current;
            if (gp != null && (gp.dpad.left.wasPressedThisFrame || gp.dpad.right.wasPressedThisFrame
                || gp.dpad.up.wasPressedThisFrame || gp.dpad.down.wasPressedThisFrame
                || gp.leftStick.ReadValue().sqrMagnitude > 0.25f))
                return true;

            return false;
        }
    }
}
