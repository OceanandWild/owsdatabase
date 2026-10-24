using System;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Modo de ventana del juego.
    ///
    /// Unity guarda el ultimo modo en el registro (la clave "Screenmanager Fullscreen mode")
    /// y lo restaura al arrancar por encima de lo que diga PlayerSettings. Por eso una
    /// instalacion que se cerro en ventana seguia abriendo en ventana despues de actualizar,
    /// y como la ventana no era redimensionable el boton de maximizar no hacia nada.
    ///
    /// Aca la preferencia vive aparte (PlayerPrefs), arranca en pantalla completa sin bordes
    /// y se puede alternar con F11 o Alt+Enter.
    /// </summary>
    public static class DisplaySettings
    {
        private const string PrefFullscreen = "WG_Fullscreen";
        private const int WindowedWidth = 1600;
        private const int WindowedHeight = 900;

        /// <summary>Se dispara cuando el modo cambia por la UI o por los atajos.</summary>
        public static event Action Changed;

        /// <summary>
        /// True si el juego esta ocupando toda la pantalla (sin bordes o exclusivo).
        /// En el editor se usa la preferencia guardada, porque la ventana del juego la
        /// maneja el editor.
        /// </summary>
        public static bool IsFullscreen
        {
            get
            {
                if (Application.isEditor)
                    return WantsFullscreen;

                FullScreenMode mode = Screen.fullScreenMode;
                return mode == FullScreenMode.FullScreenWindow ||
                       mode == FullScreenMode.ExclusiveFullScreen;
            }
        }

        /// <summary>Preferencia guardada, independiente del estado que restaura Unity.</summary>
        public static bool WantsFullscreen => PlayerPrefs.GetInt(PrefFullscreen, 1) == 1;

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void Bootstrap()
        {
            if (Application.isEditor) return;

            Apply(WantsFullscreen);

            var host = new GameObject("[DisplaySettings]");
            UnityEngine.Object.DontDestroyOnLoad(host);
            host.hideFlags = HideFlags.HideAndDontSave;
            host.AddComponent<DisplaySettingsWatcher>();
        }

        /// <summary>Alterna entre pantalla completa sin bordes y ventana.</summary>
        public static void Toggle()
        {
            SetFullscreen(!IsFullscreen);
        }

        /// <summary>Guarda la preferencia y la aplica en el mismo momento.</summary>
        public static void SetFullscreen(bool fullscreen)
        {
            PlayerPrefs.SetInt(PrefFullscreen, fullscreen ? 1 : 0);
            PlayerPrefs.Save();

            if (!Application.isEditor)
                Apply(fullscreen);

            Changed?.Invoke();
        }

        /// <summary>
        /// Reaplica la preferencia si el motor restauro el modo guardado en el registro
        /// despues del arranque. Se llama un frame despues de cargar la primera escena.
        /// </summary>
        internal static void ReapplyIfNeeded()
        {
            if (Application.isEditor) return;
            if (WantsFullscreen != IsFullscreen) Apply(WantsFullscreen);
        }

        private static void Apply(bool fullscreen)
        {
            if (fullscreen)
            {
                Vector2Int size = NativeSize();
                Screen.SetResolution(size.x, size.y, FullScreenMode.FullScreenWindow);
                return;
            }

            Vector2Int window = WindowedSize();
            Screen.SetResolution(window.x, window.y, FullScreenMode.Windowed);
        }

        /// <summary>Resolucion nativa del monitor principal, con respaldo por si no esta lista.</summary>
        private static Vector2Int NativeSize()
        {
            Display display = Display.main;
            int width = display != null ? display.systemWidth : 0;
            int height = display != null ? display.systemHeight : 0;

            if (width <= 0 || height <= 0)
            {
                Resolution current = Screen.currentResolution;
                width = current.width;
                height = current.height;
            }

            if (width <= 0) width = 1920;
            if (height <= 0) height = 1080;
            return new Vector2Int(width, height);
        }

        /// <summary>Ventana comoda, sin pasarse del tamano del escritorio.</summary>
        private static Vector2Int WindowedSize()
        {
            Resolution desktop = Screen.currentResolution;
            int width = WindowedWidth;
            int height = WindowedHeight;

            if (desktop.width > 0 && width > desktop.width) width = desktop.width;
            if (desktop.height > 0 && height > desktop.height) height = desktop.height;

            return new Vector2Int(Mathf.Max(800, width), Mathf.Max(600, height));
        }
    }
}
