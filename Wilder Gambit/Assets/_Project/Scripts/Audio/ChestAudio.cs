using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Audio
{
    /// <summary>
    /// Los 12 SFX del cofre del Atelier.
    ///
    /// Tres decisiones que vienen de los archivos entregados, no del gusto:
    ///
    /// 1. **Un solo AudioSource para los golpes.** Los cues del guion se solapan (fogonazo,
    ///    anillo y rayos suenan a la vez) y <see cref="AudioSource.PlayOneShot"/> mezcla varias
    ///    reproducciones dentro del mismo source, así que no hace falta uno por pieza.
    /// 2. **El latido va aparte y en bucle**, en su propio source: se enciende y se apaga con el
    ///    estado de la fila (<c>Refresh</c>), no con el guion de la apertura.
    /// 3. **<see cref="Master"/> deja margen.** Las capas se suman; sin margen, tres capas
    ///    simultáneas pasan de 1,0. Los archivos ya vienen normalizados **por sonoridad**, así
    ///    que esto baja el set completo sin tocar su balance interno.
    /// </summary>
    public sealed class ChestAudio : MonoBehaviour
    {
        // Nombres de archivo sin el prefijo "SFX_Chest_" que añade el cargador.
        public const string Crack  = "Crack";
        public const string Charge = "Charge";
        public const string Dust   = "Dust";
        public const string Burst  = "Burst";
        public const string Boom   = "Boom";
        public const string Rays   = "Rays";
        public const string Embers = "Embers";
        public const string Coins  = "Coins";
        public const string Tail   = "Tail";
        public const string Card   = "Card";
        public const string Reward = "Reward";
        public const string Idle   = "Idle";

        /// <summary>Margen para que la suma de capas simultáneas no recorte.</summary>
        public const float Master = 0.75f;

        /// <summary>Volumen del latido. Va muy por debajo de los golpes: es fondo.</summary>
        public const float IdleGain = 0.22f;

        private const string Folder = "SFX/SFX_Chest_";
        private const float IdleFade = 0.15f;

        private static readonly string[] Keys =
        {
            Crack, Charge, Dust, Burst, Boom, Rays, Embers, Coins, Tail, Card, Reward, Idle,
        };

        private static ChestAudio _instance;
        private static readonly Dictionary<string, AudioClip> Clips = new Dictionary<string, AudioClip>();

        private AudioSource _oneShot;
        private AudioSource _loop;
        private Coroutine _fade;

        /// <summary>Crea el reproductor si la escena todavía no lo tiene.</summary>
        public static void EnsureExists()
        {
            if (_instance != null) return;
            var go = new GameObject("ChestAudio");
            go.AddComponent<ChestAudio>();
        }

        private void Awake()
        {
            if (_instance != null && _instance != this) { Destroy(gameObject); return; }
            _instance = this;
            DontDestroyOnLoad(gameObject);

            _oneShot = AddSource();
            _oneShot.loop = false;

            _loop = AddSource();
            _loop.loop = true;

            for (int i = 0; i < Keys.Length; i++)
            {
                Clips[Keys[i]] = Resources.Load<AudioClip>(Folder + Keys[i]);
            }
        }

        private AudioSource AddSource()
        {
            var source = gameObject.AddComponent<AudioSource>();
            source.playOnAwake = false;
            source.spatialBlend = 0f;   // es UI: siempre en el centro
            return source;
        }

        // ── Reproducción ──────────────────────────────────────────────────────

        /// <summary>Dispara una pieza del set. Queda en silencio si el archivo no está.</summary>
        public static void Play(string cue, float gain)
        {
            EnsureExists();
            _instance?.PlayInternal(cue, gain);
        }

        private void PlayInternal(string cue, float gain)
        {
            if (_oneShot == null || cue == null) return;
            if (!Clips.TryGetValue(cue, out AudioClip clip) || clip == null) return;
            _oneShot.PlayOneShot(clip, Mathf.Clamp01(gain * Master));
        }

        /// <summary>Enciende el latido en bucle, con un fundido de entrada corto.</summary>
        public static void StartIdle()
        {
            EnsureExists();
            _instance?.FadeIdle(IdleGain * Master);
        }

        /// <summary>Apaga el latido con un fundido corto.</summary>
        public static void StopIdle()
        {
            if (_instance == null) return;
            _instance.FadeIdle(0f);
        }

        /// <summary>
        /// Corta todo, incluidos los golpes a medio sonar. Se llama al cerrar el modal y al
        /// arrancar una apertura nueva, para que no quede sonido de una presentación anterior.
        /// </summary>
        public static void StopAll()
        {
            if (_instance == null) return;

            _instance.StopFades();
            _instance._oneShot?.Stop();
            _instance._loop?.Stop();
        }

        private void FadeIdle(float target)
        {
            if (_loop == null) return;
            if (!Clips.TryGetValue(Idle, out AudioClip clip) || clip == null) return;

            // Repetir StartIdle mientras ya suena no lo reinicia: solo sube el volumen hasta
            // su sitio. Reiniciarlo cortaría el bucle y se oiría el corte.
            if (target > 0f && !_loop.isPlaying)
            {
                _loop.clip = clip;
                _loop.volume = 0f;
                _loop.Play();
            }

            // El estado de la fila se repinta a menudo, así que hay que distinguir los dos casos:
            // apagado (si ya está parado, no hay nada que hacer) y encendido (si ya suena a su
            // volumen, no se reinicia el fundido).
            if (target <= 0f)
            {
                if (!_loop.isPlaying) return;
            }
            else if (_loop.isPlaying && Mathf.Approximately(_loop.volume, target))
            {
                return;
            }

            StopFades();
            _fade = StartCoroutine(FadeRoutine(target));
        }

        private IEnumerator FadeRoutine(float target)
        {
            float start = _loop.volume;
            float elapsed = 0f;

            while (elapsed < IdleFade)
            {
                elapsed += Time.unscaledDeltaTime;
                _loop.volume = Mathf.Lerp(start, target, elapsed / IdleFade);
                yield return null;
            }

            _loop.volume = target;
            if (target <= 0f) _loop.Stop();
            _fade = null;
        }

        private void StopFades()
        {
            if (_fade == null) return;
            StopCoroutine(_fade);
            _fade = null;
        }
    }
}
