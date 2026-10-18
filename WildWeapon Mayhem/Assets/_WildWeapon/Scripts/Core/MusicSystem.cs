using System.Collections;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Musica de fondo persistente con crossfade (menu -> arena -> menu).
    /// Lo crea automaticamente el primer MusicPlayer que aparece; sobrevive a los cambios de escena.
    /// </summary>
    public class MusicSystem : MonoBehaviour
    {
        public static MusicSystem Instance { get; private set; }

        public float fadeTime = 1.2f;

        private AudioSource _a;
        private AudioSource _b;
        private AudioSource _active;
        private AudioClip _current;
        private Coroutine _fade;

        void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }

            Instance = this;
            DontDestroyOnLoad(gameObject);

            _a = gameObject.AddComponent<AudioSource>();
            _b = gameObject.AddComponent<AudioSource>();
            foreach (var src in new[] { _a, _b })
            {
                src.playOnAwake = false;
                src.loop = true;
                src.spatialBlend = 0f;
                src.volume = 0f;
            }
        }

        /// <summary>Reproduce la pista indicada; si hay otra sonando, hace crossfade.</summary>
        public void Play(AudioClip clip, float volume)
        {
            if (clip == null) return;
            if (_current == clip && _active != null && _active.isPlaying &&
                Mathf.Approximately(_active.volume, Mathf.Clamp01(volume))) return;

            _current = clip;

            var prev = _active;
            var next = _active == _a ? _b : _a;
            next.clip = clip;
            next.volume = 0f;
            next.Play();

            if (_fade != null) StopCoroutine(_fade);
            _fade = StartCoroutine(Crossfade(prev, next, Mathf.Clamp01(volume)));
            _active = next;
        }

        private IEnumerator Crossfade(AudioSource prev, AudioSource next, float target)
        {
            float fromPrev = prev != null ? prev.volume : 0f;
            float t = 0f;
            while (t < fadeTime)
            {
                t += Time.unscaledDeltaTime;
                float k = Mathf.Clamp01(t / fadeTime);
                next.volume = Mathf.Lerp(0f, target, k);
                if (prev != null) prev.volume = Mathf.Lerp(fromPrev, 0f, k);
                yield return null;
            }

            next.volume = target;
            if (prev != null)
            {
                prev.Stop();
                prev.clip = null;
            }
            _fade = null;
        }
    }
}
