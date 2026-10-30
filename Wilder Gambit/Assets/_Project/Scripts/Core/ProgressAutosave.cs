using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Red de seguridad de la persistencia. PlayerPrefs vive en memoria y solo se escribe en
    /// disco al llamar a <see cref="PlayerPrefs.Save"/>; si el juego se cierra de golpe, se
    /// pausa en segundo plano o pierde el foco sin pasar por el flujo normal, lo ganado en la
    /// sesión se queda sin guardar. Este guardián vuelca todo en esos momentos.
    ///
    /// No sustituye a guardar en el instante del cambio (economía, misiones y logros ya lo
    /// hacen): es solo la última red.
    /// </summary>
    public class ProgressAutosave : MonoBehaviour
    {
        private static ProgressAutosave _instance;

        /// <summary>Crea el guardián si la escena no lo tiene (lo llama GambitProgress.Init).</summary>
        public static void EnsureExists()
        {
            if (_instance != null) return;
            var go = new GameObject("ProgressAutosave");
            go.AddComponent<ProgressAutosave>();
        }

        private void Awake()
        {
            if (_instance != null && _instance != this) { Destroy(gameObject); return; }
            _instance = this;
            DontDestroyOnLoad(gameObject);
        }

        private void OnApplicationPause(bool paused)
        {
            if (paused) Flush();
        }

        private void OnApplicationFocus(bool focused)
        {
            if (!focused) Flush();
        }

        private void OnApplicationQuit() => Flush();

        /// <summary>Vuelca a disco todo lo escrito en PlayerPrefs.</summary>
        public static void Flush()
        {
            PlayerPrefs.Save();
        }
    }
}
