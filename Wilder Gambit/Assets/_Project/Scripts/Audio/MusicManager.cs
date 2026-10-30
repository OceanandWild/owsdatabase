using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Audio
{
    /// <summary>
    /// Gestor de música ambiental y de batalla para Wilder Gambit.
    /// Alterna automáticamente entre "Endgame Requiem" y "Grandmaster Gambit" al iniciar partidas.
    /// Soporta fundidos suaves (fade-in / fade-out) y persistencia entre escenas.
    /// </summary>
    public class MusicManager : MonoBehaviour
    {
        public static MusicManager Instance { get; private set; }

        [Header("Configuración de Audio")]
        [SerializeField] private float maxVolume = 0.55f;
        [SerializeField] private float fadeDuration = 1.2f;

        [Header("Pistas de Música")]
        [SerializeField] private List<AudioClip> menuTracks = new List<AudioClip>();
        [SerializeField] private List<AudioClip> battleTracks = new List<AudioClip>();

        [Header("Efectos de Sonido (SFX)")]
        [SerializeField] private AudioClip sfxClick;
        [SerializeField] private AudioClip sfxHover;
        [SerializeField] private AudioClip sfxBack;
        [SerializeField] private AudioClip sfxPieceMove;
        [SerializeField] private AudioClip sfxForkComet;

        private AudioSource _audioSource;
        private AudioSource _sfxSource;
        private Coroutine _fadeCoroutine;
        private int _lastBattleTrackIndex = -1;

        public bool IsMusicEnabled { get; private set; } = true;
        public int SelectedMenuTrackIndex { get; private set; } = 0; // -1 = Desactivada, 0..N = Pistas
        public int SelectedBattleTrackIndex { get; private set; } = -1; // -2 = Desactivada, -1 = Alternar, 0..N = Pistas

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }
            Instance = this;
            DontDestroyOnLoad(gameObject);

            _audioSource = GetComponent<AudioSource>();
            if (_audioSource == null)
            {
                _audioSource = gameObject.AddComponent<AudioSource>();
            }

            _audioSource.loop = true;
            _audioSource.playOnAwake = false;
            _audioSource.volume = 0f;

            // AudioSource dedicado para SFX
            var sources = GetComponents<AudioSource>();
            if (sources.Length > 1)
            {
                _sfxSource = sources[1];
            }
            else
            {
                _sfxSource = gameObject.AddComponent<AudioSource>();
            }
            _sfxSource.loop = false;
            _sfxSource.playOnAwake = false;
            _sfxSource.volume = 0.7f;

            LoadDefaultTracksIfEmpty();

            IsMusicEnabled           = PlayerPrefs.GetInt("Pref_MusicEnabled", 1) == 1;
            SelectedMenuTrackIndex   = PlayerPrefs.GetInt("Pref_MenuMusic", 0);
            SelectedBattleTrackIndex = PlayerPrefs.GetInt("Pref_BattleMusic", -1);
        }

        private void LoadDefaultTracksIfEmpty()
        {
            if (menuTracks == null || menuTracks.Count == 0)
            {
                menuTracks = new List<AudioClip>();
                var m1 = Resources.Load<AudioClip>("Music/SovereignGambit");
                if (m1 != null) menuTracks.Add(m1);
            }

            if (battleTracks == null || battleTracks.Count == 0)
            {
                battleTracks = new List<AudioClip>();
                var t1 = Resources.Load<AudioClip>("Music/EndgameRequiem");
                if (t1 != null) battleTracks.Add(t1);

                var t2 = Resources.Load<AudioClip>("Music/GrandmasterGambit");
                if (t2 != null) battleTracks.Add(t2);
            }

            if (sfxClick == null)
                sfxClick = Resources.Load<AudioClip>("SFX/SFX_UI_Click");
            if (sfxHover == null)
                sfxHover = Resources.Load<AudioClip>("SFX/SFX_UI_Hover");
            if (sfxBack == null)
                sfxBack = Resources.Load<AudioClip>("SFX/SFX_UI_Back");
            if (sfxPieceMove == null)
                sfxPieceMove = Resources.Load<AudioClip>("SFX/SFX_Piece_Move");
            if (sfxForkComet == null)
                sfxForkComet = Resources.Load<AudioClip>("SFX/SFX_Fork_Comet");
        }

        // ── Efectos de Sonido (SFX) ───────────────────────────────────────────

        public void PlayClickSound()
        {
            if (sfxClick == null) LoadDefaultTracksIfEmpty();
            if (sfxClick != null && _sfxSource != null)
                _sfxSource.PlayOneShot(sfxClick, 0.75f);
        }

        public void PlayHoverSound()
        {
            if (sfxHover == null) LoadDefaultTracksIfEmpty();
            if (sfxHover != null && _sfxSource != null)
                _sfxSource.PlayOneShot(sfxHover, 0.5f);
        }

        public void PlayBackSound()
        {
            if (sfxBack == null) LoadDefaultTracksIfEmpty();
            if (sfxBack != null && _sfxSource != null)
                _sfxSource.PlayOneShot(sfxBack, 0.75f);
        }

        public void PlayPieceMoveSound()
        {
            if (sfxPieceMove == null) LoadDefaultTracksIfEmpty();
            if (sfxPieceMove != null && _sfxSource != null)
                _sfxSource.PlayOneShot(sfxPieceMove, 0.85f);
        }

        /// <summary> Rugido del cometa de fuego (gatillo fork «Cometa Ígnea»).</summary>
        public void PlayForkCometSound()
        {
            if (sfxForkComet == null) LoadDefaultTracksIfEmpty();
            if (sfxForkComet != null && _sfxSource != null)
                _sfxSource.PlayOneShot(sfxForkComet, 0.9f);
        }

        // ── Preferencias de Selección ──────────────────────────────────────────

        public void SetMusicEnabled(bool enabled)
        {
            IsMusicEnabled = enabled;
            PlayerPrefs.SetInt("Pref_MusicEnabled", enabled ? 1 : 0);
            PlayerPrefs.Save();

            if (!IsMusicEnabled)
            {
                StopMusic(0.4f);
            }
            else
            {
                PlayMenuMusic();
            }
        }

        public List<string> GetMenuTrackNames()
        {
            LoadDefaultTracksIfEmpty();
            var names = new List<string>();
            foreach (var clip in menuTracks)
            {
                names.Add(clip != null ? FormatTrackName(clip.name) : "Sin nombre");
            }
            if (names.Count == 0) names.Add("Sovereign Gambit");
            names.Add("🔇 Desactivada");
            return names;
        }

        public List<string> GetBattleTrackOptions()
        {
            LoadDefaultTracksIfEmpty();
            var options = new List<string> { "🎲 Alternar pistas" };
            foreach (var clip in battleTracks)
            {
                options.Add(clip != null ? FormatTrackName(clip.name) : "Pista de batalla");
            }
            options.Add("🔇 Desactivada");
            return options;
        }

        public void SetMenuTrackPreference(int index)
        {
            LoadDefaultTracksIfEmpty();
            int totalOptions = menuTracks.Count + 1; // 0..menuTracks.Count-1 = tracks, menuTracks.Count = Desactivada (-1)
            if (totalOptions <= 0) return;

            if (index < -1) index = menuTracks.Count - 1;
            if (index >= menuTracks.Count) index = -1; // -1 = Desactivada

            SelectedMenuTrackIndex = index;
            PlayerPrefs.SetInt("Pref_MenuMusic", SelectedMenuTrackIndex);
            PlayerPrefs.Save();

            if (SelectedMenuTrackIndex == -1 || !IsMusicEnabled)
            {
                StopMusic(0.4f);
            }
            else
            {
                PlayMenuMusic();
            }
        }

        public void SetBattleTrackPreference(int optionIndex)
        {
            LoadDefaultTracksIfEmpty();
            int totalOptions = battleTracks.Count + 2; // 0 = Alternar (-1), 1..N = pistas (0..N-1), N+1 = Desactivada (-2)
            if (optionIndex < 0) optionIndex = totalOptions - 1;
            if (optionIndex >= totalOptions) optionIndex = 0;

            if (optionIndex == 0)
                SelectedBattleTrackIndex = -1; // Alternar
            else if (optionIndex == totalOptions - 1)
                SelectedBattleTrackIndex = -2; // Desactivada
            else
                SelectedBattleTrackIndex = optionIndex - 1; // Pista específica

            PlayerPrefs.SetInt("Pref_BattleMusic", SelectedBattleTrackIndex);
            PlayerPrefs.Save();
        }

        private string FormatTrackName(string rawName)
        {
            if (string.IsNullOrEmpty(rawName)) return "Pista";
            return rawName.Replace("SovereignGambit", "Sovereign Gambit")
                          .Replace("EndgameRequiem", "Endgame Requiem")
                          .Replace("GrandmasterGambit", "Grandmaster Gambit");
        }

        private bool IsPlayingMenuMusic()
        {
            if (_audioSource == null || !_audioSource.isPlaying || _audioSource.clip == null) return false;
            return menuTracks.Contains(_audioSource.clip);
        }

        // ── Reproducción ───────────────────────────────────────────────────────

        /// <summary>
        /// Inicia la música del Menú Principal según la preferencia elegida.
        /// </summary>
        public void PlayMenuMusic()
        {
            if (!IsMusicEnabled || SelectedMenuTrackIndex == -1)
            {
                StopMusic(0.3f);
                return;
            }

            LoadDefaultTracksIfEmpty();
            if (menuTracks.Count == 0) return;

            int targetIndex = Mathf.Clamp(SelectedMenuTrackIndex, 0, menuTracks.Count - 1);
            AudioClip chosenClip = menuTracks[targetIndex];

            if (chosenClip == null) return;

            if (_audioSource.isPlaying && _audioSource.clip == chosenClip)
            {
                if (_audioSource.volume < maxVolume)
                {
                    StartFade(maxVolume, fadeDuration);
                }
                return;
            }

            StartCrossFade(chosenClip, maxVolume, fadeDuration);
        }

        /// <summary>
        /// Inicia la música de batalla según la preferencia (fija, alternada o desactivada).
        /// </summary>
        public void PlayBattleMusic(bool forceAlternate = false)
        {
            if (!IsMusicEnabled || SelectedBattleTrackIndex == -2)
            {
                StopMusic(0.3f);
                return;
            }

            LoadDefaultTracksIfEmpty();
            if (battleTracks.Count == 0) return;

            AudioClip chosenClip;

            if (SelectedBattleTrackIndex >= 0 && SelectedBattleTrackIndex < battleTracks.Count)
            {
                // Pista fija seleccionada por el jugador
                chosenClip = battleTracks[SelectedBattleTrackIndex];
            }
            else
            {
                // Alternar pistas automáticamente
                int nextIndex;
                if (battleTracks.Count == 1)
                {
                    nextIndex = 0;
                }
                else if (_lastBattleTrackIndex < 0 || forceAlternate)
                {
                    nextIndex = (_lastBattleTrackIndex + 1) % battleTracks.Count;
                }
                else
                {
                    nextIndex = (_lastBattleTrackIndex + 1) % battleTracks.Count;
                }

                _lastBattleTrackIndex = nextIndex;
                chosenClip = battleTracks[nextIndex];
            }

            if (chosenClip == null) return;

            if (_audioSource.isPlaying && _audioSource.clip == chosenClip)
            {
                if (_audioSource.volume < maxVolume)
                {
                    StartFade(maxVolume, fadeDuration);
                }
                return;
            }

            StartCrossFade(chosenClip, maxVolume, fadeDuration);
        }

        /// <summary>
        /// Detiene la música con un fundido suave.
        /// </summary>
        public void StopMusic(float duration = 1.0f)
        {
            if (!_audioSource.isPlaying) return;
            StartFade(0f, duration, onComplete: () => _audioSource.Stop());
        }

        private void StartFade(float targetVolume, float duration, System.Action onComplete = null)
        {
            if (_fadeCoroutine != null) StopCoroutine(_fadeCoroutine);
            _fadeCoroutine = StartCoroutine(FadeVolumeRoutine(targetVolume, duration, onComplete));
        }

        private void StartCrossFade(AudioClip newClip, float targetVolume, float duration)
        {
            if (_fadeCoroutine != null) StopCoroutine(_fadeCoroutine);
            _fadeCoroutine = StartCoroutine(CrossFadeRoutine(newClip, targetVolume, duration));
        }

        private IEnumerator FadeVolumeRoutine(float targetVolume, float duration, System.Action onComplete = null)
        {
            float startVol = _audioSource.volume;
            float elapsed = 0f;

            while (elapsed < duration)
            {
                elapsed += Time.unscaledDeltaTime;
                _audioSource.volume = Mathf.Lerp(startVol, targetVolume, elapsed / duration);
                yield return null;
            }

            _audioSource.volume = targetVolume;
            onComplete?.Invoke();
            _fadeCoroutine = null;
        }

        private IEnumerator CrossFadeRoutine(AudioClip newClip, float targetVolume, float duration)
        {
            // 1. Fade out si ya está sonando algo
            if (_audioSource.isPlaying && _audioSource.volume > 0.05f)
            {
                float fadeOutTime = duration * 0.4f;
                float startVol = _audioSource.volume;
                float elapsed = 0f;

                while (elapsed < fadeOutTime)
                {
                    elapsed += Time.unscaledDeltaTime;
                    _audioSource.volume = Mathf.Lerp(startVol, 0f, elapsed / fadeOutTime);
                    yield return null;
                }
            }

            // 2. Cambiar clip y reproducir
            _audioSource.clip = newClip;
            _audioSource.volume = 0f;
            _audioSource.Play();

            // 3. Fade in
            float fadeInTime = duration * 0.6f;
            float inElapsed = 0f;

            while (inElapsed < fadeInTime)
            {
                inElapsed += Time.unscaledDeltaTime;
                _audioSource.volume = Mathf.Lerp(0f, targetVolume, inElapsed / fadeInTime);
                yield return null;
            }

            _audioSource.volume = targetVolume;
            _fadeCoroutine = null;
        }
    }
}
