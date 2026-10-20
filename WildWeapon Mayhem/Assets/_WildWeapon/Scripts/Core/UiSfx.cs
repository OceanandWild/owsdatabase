using UnityEngine;
using WildWeapon.UI;

namespace WildWeapon
{
    /// <summary>
    /// Efectos de sonido de la interfaz. Punto unico de entrada: ningun boton
    /// llama a AudioSource.Play, todo pasa por aca (asi el volumen se ajusta en
    /// un solo sitio y los clips se pueden cambiar sin tocar los menus).
    ///
    /// Pool de AudioSources para que dos clicks seguidos se solapen sin cortarse.
    /// Los clips los sintetiza tools\Generate-UI-Audio.ps1 y se cargan desde
    /// Resources para que no haya que cablear referencias escena por escena.
    /// </summary>
    public static class UiSfx
    {
        const int PoolSize = 6;
        const string Dir = "WW/Audio/UI/";
        const string NodeName = "[UiSfx]";

        /// <summary>Volumen general de los SFX de interfaz (0 = mudo).</summary>
        public static float Volume = 0.6f;

        const float ClickVolume = 1f;    // el click manda
        const float HoverVolume = 0.5f;  // el hover va por debajo, es subliminal
        const float HoverCooldown = 0.05f; // el puntero puede pasar varias cards seguidas

        static AudioClip _click;
        static AudioClip _hover;
        static AudioSource[] _pool;
        static int _next;
        static float _lastHover;

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
        static void Bootstrap() => EnsureReady();

        /// <summary>
        /// Crea (o repara) el sistema de SFX. Es idempotente y el propio
        /// listener la llama en cada frame: asi una recarga de dominio a mitad
        /// de partida (recompilar un script con el juego corriendo) no deja el
        /// menu sin sonido.
        /// </summary>
        public static void EnsureReady()
        {
            if (_pool != null && _pool[0] != null && _click != null && _hover != null) return;

            var node = GameObject.Find(NodeName);
            if (node == null)
            {
                node = new GameObject(NodeName);
                Object.DontDestroyOnLoad(node);
            }

            // Pool: se reaprovechan las fuentes que ya estan (puede quedar una
            // vieja de una recarga de dominio) y se crean las que falten.
            var existing = node.GetComponentsInChildren<AudioSource>(true);
            _pool = new AudioSource[PoolSize];
            int found = 0;
            for (int i = 0; i < existing.Length && found < PoolSize; i++)
            {
                var src = existing[i];
                if (src == null) continue;
                src.playOnAwake = false;
                src.loop = false;
                src.spatialBlend = 0f;   // UI: 2D, no espacial
                _pool[found++] = src;
            }
            for (int i = found; i < PoolSize; i++)
            {
                var go = new GameObject($"Sfx{i}");
                go.transform.SetParent(node.transform, false);
                var src = go.AddComponent<AudioSource>();
                src.playOnAwake = false;
                src.loop = false;
                src.spatialBlend = 0f;
                _pool[i] = src;
            }

            // El escucha global de hover/click vive en el mismo nodo: asi los
            // botones suenan sin tener que cablearlos uno por uno.
            if (node.GetComponent<UiSfxListener>() == null) node.AddComponent<UiSfxListener>();

            _click = Resources.Load<AudioClip>(Dir + "ww_sfx_click");
            _hover = Resources.Load<AudioClip>(Dir + "ww_sfx_hover");
            if (_click == null) Debug.LogWarning("[WW] UiSfx: falta el clip ww_sfx_click.");
            if (_hover == null) Debug.LogWarning("[WW] UiSfx: falta el clip ww_sfx_hover.");
        }

        /// <summary>Click de boton.</summary>
        public static void Click() => Play(_click, ClickVolume);

        /// <summary>Hover de boton. Throttle: el puntero recorre varias cards seguidas.</summary>
        public static void Hover()
        {
            if (Time.unscaledTime - _lastHover < HoverCooldown) return;
            _lastHover = Time.unscaledTime;
            Play(_hover, HoverVolume);
        }

        /// <summary>Reproduce un clip del pool con una variacion de tono leve.</summary>
        public static void Play(AudioClip clip, float volume = 1f, bool pitchJitter = true)
        {
            if (clip == null || _pool == null) return;
            var src = _pool[_next];
            _next = (_next + 1) % _pool.Length;
            if (src == null) return;

            // Sin jitter dos clicks iguales suenan a robot; con jitter suenan
            // a persona picando botones. El pan leve les da un poco de ancho.
            src.pitch = pitchJitter ? Random.Range(0.97f, 1.03f) : 1f;
            src.panStereo = pitchJitter ? Random.Range(-0.12f, 0.12f) : 0f;
            src.PlayOneShot(clip, Mathf.Clamp01(Volume * volume));
        }
    }
}
