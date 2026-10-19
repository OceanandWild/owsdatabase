using System.Collections.Generic;
using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.InputSystem;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Detecta el hover y el click sobre cualquier boton de la interfaz sin
    /// tocar boton por boton. Hace un raycast con la posicion del mouse y ve que
    /// objeto interactivo hay debajo; el click se dispara con el boton izquierdo
    /// y con el "submit" del mando o del teclado (mismas acciones que usa el
    /// InputSystemUIInputModule).
    ///
    /// Vive en el nodo persistente de UiSfx: se crea solo al arrancar el juego
    /// y sigue funcionando al cambiar de escena.
    /// </summary>
    public class UiSfxListener : MonoBehaviour
    {
        readonly List<RaycastResult> _results = new List<RaycastResult>();

        private PointerEventData _pointer;
        private EventSystem _events;
        private GameObject _hovered;
        private GameObject _selected;

        void Update()
        {
            // El sistema de sonido se autorepara: si hubo una recarga de
            // dominio a mitad de partida, los estaticos se perdieron.
            UiSfx.EnsureReady();

            var events = EventSystem.current;
            if (events == null) return;   // escenas sin interfaz (arena)

            // El EventSystem se recrea al cambiar de escena: el puntero tambien.
            if (_pointer == null || _events != events)
            {
                _events = events;
                _pointer = new PointerEventData(events);
            }

            UpdatePointer(events);
            UpdateSelection(events);
        }

        private void UpdatePointer(EventSystem events)
        {
            var mouse = Mouse.current;
            if (mouse == null) return;

            _pointer.Reset();
            _pointer.position = mouse.position.ReadValue();
            events.RaycastAll(_pointer, _results);

            // Solo se mira el objeto de arriba: si hay algo encima (un fader, un
            // panel modal) el click tampoco llega al boton de abajo, asi que
            // tampoco suena.
            var target = _results.Count > 0 ? Resolve(_results[0].gameObject) : null;

            if (target != _hovered)
            {
                _hovered = target;
                if (target != null) UiSfx.Hover();
            }

            // El click suena al presionar: la respuesta inmediata se siente mas
            // viva que esperar al soltar.
            if (mouse.leftButton.wasPressedThisFrame && target != null)
                UiSfx.Click();
        }

        private void UpdateSelection(EventSystem events)
        {
            var selected = events.currentSelectedGameObject;
            if (selected != _selected)
            {
                _selected = selected;
                if (selected == null) return;
                // Si el mouse ya esta encima, el hover ya sono: no se repite.
                if (_hovered != null && _hovered == selected) return;
                var sel = selected.GetComponent<Selectable>();
                if (sel == null || !sel.IsInteractable()) return;
                UiSfx.Hover();
            }

            // Submit del mando o del teclado: el click del boton que tiene el foco.
            if (SubmitPressed())
            {
                var sel = selected != null ? selected.GetComponent<Selectable>() : null;
                if (sel != null && sel.IsInteractable()) UiSfx.Click();
            }
        }

        /// <summary>
        /// Devuelve el GameObject interactivo bajo el puntero (el Selectable mas
        /// cercano hacia arriba) o null si no hay nada pulsable ahi.
        /// </summary>
        private static GameObject Resolve(GameObject hit)
        {
            var go = hit;
            while (go != null)
            {
                var sel = go.GetComponent<Selectable>();
                if (sel != null) return sel.IsInteractable() ? go : null;
                go = go.transform.parent != null ? go.transform.parent.gameObject : null;
            }
            return null;
        }

        private static bool SubmitPressed()
        {
            var pad = Gamepad.current;
            if (pad != null && pad.buttonSouth.wasPressedThisFrame) return true;

            var kb = Keyboard.current;
            if (kb != null && (kb.enterKey.wasPressedThisFrame || kb.spaceKey.wasPressedThisFrame)) return true;

            return false;
        }
    }
}
