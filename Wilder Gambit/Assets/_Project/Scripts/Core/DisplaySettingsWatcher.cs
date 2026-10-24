using UnityEngine;
#if ENABLE_INPUT_SYSTEM
using UnityEngine.InputSystem;
#endif

namespace WilderGambit.Core
{
    /// <summary>
    /// Escucha F11 / Alt+Enter y corrige el modo que Unity restaura del registro.
    /// Vive en un objeto oculto y persistente creado por <see cref="DisplaySettings"/>.
    /// </summary>
    internal sealed class DisplaySettingsWatcher : MonoBehaviour
    {
        private System.Collections.IEnumerator Start()
        {
            // Un frame: para entonces el motor ya termino de restaurar su modo guardado.
            yield return null;
            DisplaySettings.ReapplyIfNeeded();
        }

        private void Update()
        {
            if (!TogglePressed()) return;
            DisplaySettings.Toggle();
        }

        private static bool TogglePressed()
        {
#if ENABLE_INPUT_SYSTEM
            Keyboard keyboard = Keyboard.current;
            if (keyboard == null) return false;

            if (keyboard.f11Key.wasPressedThisFrame) return true;

            bool alt = keyboard.leftAltKey.isPressed || keyboard.rightAltKey.isPressed;
            bool enter = keyboard.enterKey.wasPressedThisFrame || keyboard.numpadEnterKey.wasPressedThisFrame;
            return alt && enter;
#elif ENABLE_LEGACY_INPUT_MANAGER
            if (Input.GetKeyDown(KeyCode.F11)) return true;

            bool alt = Input.GetKey(KeyCode.LeftAlt) || Input.GetKey(KeyCode.RightAlt);
            bool enter = Input.GetKeyDown(KeyCode.Return) || Input.GetKeyDown(KeyCode.KeypadEnter);
            return alt && enter;
#else
            return false;
#endif
        }
    }
}
