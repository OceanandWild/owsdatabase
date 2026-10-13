using UnityEngine;

namespace WildSea.Core
{
    public enum WSfx { Click, Hover, Confirm, Back, Denied }

    /// <summary>
    /// Audio de interfaz. Punto unico de entrada: ningun boton llama a
    /// AudioSource.Play suelto, todo pasa por aca (asi el volumen de Opciones
    /// se respeta en todas partes y los sonidos se pueden cambiar de sitio).
    ///
    /// Pool de AudioSources para que dos clicks seguidos se solapen sin
    /// cortarse. El ambiente va en su propio source con loop.
    /// Los clips son sintetizados por tools/Generate-UI-Audio.ps1.
    /// </summary>
    public static class WSAudio
    {
        const int PoolSize = 6;
        const string Dir = "WS/Audio/UI/";
        const string AmbientClip = "WS_amb_sea";
        const float AmbientBase = 0.35f;   // el ambiente queda por debajo de los SFX
        const float HoverCooldown = 0.06f;

        static readonly string[] ClipNames = {
            "WS_sfx_click", "WS_sfx_hover", "WS_sfx_confirm", "WS_sfx_back", "WS_sfx_denied"
        };

        static AudioClip[] clips;
        static AudioClip ambient;
        static AudioSource[] pool;
        static AudioSource ambientSource;
        static GameObject node;
        static int next;
        static float lastHover;

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
        static void Bootstrap()
        {
            if (node != null) return;
            node = new GameObject("WS_Audio");
            Object.DontDestroyOnLoad(node);

            pool = new AudioSource[PoolSize];
            for (int i = 0; i < PoolSize; i++)
            {
                var go = new GameObject($"WS_Sfx{i}");
                go.transform.SetParent(node.transform, false);
                var src = go.AddComponent<AudioSource>();
                src.playOnAwake = false;
                src.loop = false;
                src.spatialBlend = 0f;   // UI: 2D, no espacial
                pool[i] = src;
            }

            var ag = new GameObject("WS_Ambient");
            ag.transform.SetParent(node.transform, false);
            ambientSource = ag.AddComponent<AudioSource>();
            ambientSource.playOnAwake = false;
            ambientSource.loop = true;
            ambientSource.spatialBlend = 0f;

            Load();
            StartAmbient();
        }

        static void Load()
        {
            clips = new AudioClip[ClipNames.Length];
            for (int i = 0; i < ClipNames.Length; i++)
            {
                clips[i] = Resources.Load<AudioClip>(Dir + ClipNames[i]);
                if (clips[i] == null)
                    Debug.LogWarning($"[WildSea] Audio: falta el clip {ClipNames[i]}.");
            }
            ambient = Resources.Load<AudioClip>(Dir + AmbientClip);
            if (ambient == null)
                Debug.LogWarning($"[WildSea] Audio: falta el ambiente {AmbientClip}.");
        }

        public static void Play(WSfx s)
        {
            if (pool == null || clips == null) return;
            var clip = clips[(int)s];
            if (clip == null) return;
            var src = pool[next];
            next = (next + 1) % pool.Length;
            // Variacion de tono leve: si no, dos clicks iguales suenan a robot.
            src.pitch = Random.Range(0.97f, 1.03f);
            src.PlayOneShot(clip, WSSave.Sfx);
        }

        public static void Click() => Play(WSfx.Click);

        public static void Confirm() => Play(WSfx.Confirm);

        public static void Back() => Play(WSfx.Back);

        public static void Denied() => Play(WSfx.Denied);

        /// <summary>Throttled: el puntero recorre varias cards seguidas.</summary>
        public static void Hover()
        {
            if (Time.unscaledTime - lastHover < HoverCooldown) return;
            lastHover = Time.unscaledTime;
            Play(WSfx.Hover);
        }

        public static void StartAmbient()
        {
            if (ambientSource == null || ambient == null) return;
            if (ambientSource.clip != ambient) ambientSource.clip = ambient;
            ambientSource.volume = WSSave.Music * AmbientBase;
            if (!ambientSource.isPlaying) ambientSource.Play();
        }

        /// <summary>
        /// Reaplica los volúmenes de Opciones. Llamar desde el modal cada vez
        /// que se tocan los sliders o los toggles.
        /// </summary>
        public static void ApplyVolumes()
        {
            if (ambientSource != null) ambientSource.volume = WSSave.Music * AmbientBase;
            if (pool == null) return;
            foreach (var src in pool)
                if (src != null) src.volume = WSSave.Sfx;
        }
    }
}
