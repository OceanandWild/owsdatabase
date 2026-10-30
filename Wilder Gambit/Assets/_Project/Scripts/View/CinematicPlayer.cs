using System;
using System.Collections;
using UnityEngine;
using UnityEngine.UI;
using UnityEngine.Video;
using WilderGambit.UI;

namespace WilderGambit.View
{
    /// <summary>
    /// Muestra un video MP4 en pantalla completa sobre el tablero en calidad Ultra HD.
    /// Incluye RenderTexture con 8x MSAA y filtrado trilineal, AspectRatioFitter dinámico,
    /// desvanecimiento cinematográfico (Fade In / Out) y AudioSource de alta fidelidad.
    /// </summary>
    public class CinematicPlayer : MonoBehaviour
    {
        public static CinematicPlayer Instance { get; private set; }

        // ── Referencias internas ──────────────────────────────────────────────
        private Canvas              _canvas;
        private CanvasGroup         _canvasGroup;
        private RawImage            _rawImage;
        private AspectRatioFitter   _aspectFitter;
        private VideoPlayer         _videoPlayer;
        private AudioSource         _audioSource;
        private RenderTexture       _renderTexture;
        private Button              _skipButton;

        // ── Estado ────────────────────────────────────────────────────────────
        private Action _onFinished;
        private bool   _isPlaying;
        private Coroutine _playRoutine;

        // ── Ajustes ───────────────────────────────────────────────────────────
        [Tooltip("Clip a reproducir cuando el Caballo Blanco captura un Peón Negro")]
        public VideoClip knightTakesPawnClip;

        // ─────────────────────────────────────────────────────────────────────

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);

            BuildUI();
        }

        // ── Construcción de la UI Ultra HD ───────────────────────────────────

        private void BuildUI()
        {
            // Canvas de overlay que cubre toda la pantalla
            GameObject canvasGO = new GameObject("CinematicCanvas");
            canvasGO.transform.SetParent(transform);

            _canvas = canvasGO.AddComponent<Canvas>();
            _canvas.renderMode   = RenderMode.ScreenSpaceOverlay;
            _canvas.sortingOrder = 999; // Encima de todo

            CanvasScaler scaler = canvasGO.AddComponent<CanvasScaler>();
            scaler.uiScaleMode         = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920, 1080);
            WilderGambit.UI.UiResponsive.ApplyCanvasScaler(scaler);

            canvasGO.AddComponent<GraphicRaycaster>();
            _canvasGroup = canvasGO.AddComponent<CanvasGroup>();
            _canvasGroup.alpha = 0f;

            // Fondo negro cinemático
            GameObject bgGO = new GameObject("Background");
            bgGO.transform.SetParent(canvasGO.transform, false);
            Image bg = bgGO.AddComponent<Image>();
            bg.color = Color.black;
            bg.rectTransform.anchorMin = Vector2.zero;
            bg.rectTransform.anchorMax = Vector2.one;
            bg.rectTransform.offsetMin = Vector2.zero;
            bg.rectTransform.offsetMax = Vector2.zero;

            // RawImage donde se renderiza el video con AspectRatioFitter
            GameObject rawGO = new GameObject("VideoFrame");
            rawGO.transform.SetParent(canvasGO.transform, false);
            _rawImage = rawGO.AddComponent<RawImage>();
            _rawImage.rectTransform.anchorMin = Vector2.zero;
            _rawImage.rectTransform.anchorMax = Vector2.one;
            _rawImage.rectTransform.offsetMin = Vector2.zero;
            _rawImage.rectTransform.offsetMax = Vector2.zero;

            _aspectFitter = rawGO.AddComponent<AspectRatioFitter>();
            _aspectFitter.aspectMode  = AspectRatioFitter.AspectMode.FitInParent;
            _aspectFitter.aspectRatio = 16f / 9f;

            // Botón "Saltar" estilizado
            GameObject skipGO = new GameObject("SkipButton");
            skipGO.transform.SetParent(canvasGO.transform, false);

            // Orden IMPORTA: el Image va antes que el Button. El Awake de Selectable
            // corre al agregarlo y cachea targetGraphic; si todavia no hay
            // ningun Graphic en el GameObject lo deja en null y la transicion
            // de color no hace NADA (ni hover ni click).
            Color skipBase = new Color(0.08f, 0.08f, 0.08f, 0.75f);
            Image skipBg = skipGO.AddComponent<Image>();
            skipBg.color = skipBase;

            _skipButton = skipGO.AddComponent<Button>();
            // Hover y click: antes no tenia ColorBlock, asi que usaba el default.
            UiFeedback.Apply(_skipButton, skipBase,
                new Color(0.22f, 0.24f, 0.29f, 0.92f),  // hover: se aclara
                new Color(0.95f, 0.75f, 0.25f, 1f));     // click: destello dorado
            UiFeedback.AttachSounds(_skipButton);

            RectTransform skipRect = skipGO.GetComponent<RectTransform>();
            skipRect.anchorMin = new Vector2(1f, 0f);
            skipRect.anchorMax = new Vector2(1f, 0f);
            skipRect.pivot     = new Vector2(1f, 0f);
            skipRect.anchoredPosition = new Vector2(-30f, 30f);
            skipRect.sizeDelta = new Vector2(150f, 48f);

            // Texto del botón
            GameObject textGO = new GameObject("Label");
            textGO.transform.SetParent(skipGO.transform, false);
            Text label = textGO.AddComponent<Text>();
            label.text      = "SALTAR  ▶▶";
            label.font      = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            label.fontSize  = 18;
            label.fontStyle = FontStyle.Bold;
            label.color     = new Color(1f, 1f, 1f, 0.95f);
            label.alignment = TextAnchor.MiddleCenter;

            RectTransform labelRect = label.rectTransform;
            labelRect.anchorMin = Vector2.zero;
            labelRect.anchorMax = Vector2.one;
            labelRect.offsetMin = Vector2.zero;
            labelRect.offsetMax = Vector2.zero;

            _skipButton.onClick.AddListener(Skip);

            // AudioSource de alta calidad para el video
            _audioSource = gameObject.AddComponent<AudioSource>();
            _audioSource.playOnAwake  = false;
            _audioSource.spatialBlend = 0f; // 2D Full stereo
            _audioSource.volume       = 1.0f;

            // VideoPlayer en Ultra Quality
            GameObject vpGO = new GameObject("VideoPlayer");
            vpGO.transform.SetParent(transform);
            _videoPlayer = vpGO.AddComponent<VideoPlayer>();
            _videoPlayer.playOnAwake     = false;
            _videoPlayer.renderMode      = VideoRenderMode.RenderTexture;
            _videoPlayer.audioOutputMode = VideoAudioOutputMode.AudioSource;
            _videoPlayer.EnableAudioTrack(0, true);
            _videoPlayer.SetTargetAudioSource(0, _audioSource);
            _videoPlayer.loopPointReached += OnVideoFinished;

            // Ocultar UI inicialmente
            canvasGO.SetActive(false);
        }

        // ── API pública ───────────────────────────────────────────────────────

        /// <summary>
        /// Reproduce el VideoClip en pantalla completa con máxima fidelidad.
        /// </summary>
        public void PlayCinematic(VideoClip clip, Action onFinished)
        {
            if (_isPlaying) return;
            if (clip == null)
            {
                onFinished?.Invoke();
                return;
            }

            _onFinished = onFinished;
            _isPlaying  = true;

            if (_playRoutine != null) StopCoroutine(_playRoutine);
            _playRoutine = StartCoroutine(PlayRoutine(clip));
        }

        // ── Lógica interna ────────────────────────────────────────────────────

        private IEnumerator PlayRoutine(VideoClip clip)
        {
            int w = (int)clip.width;
            int h = (int)clip.height;
            if (w <= 0) w = 1920;
            if (h <= 0) h = 1080;

            // Ajustar AspectRatioFitter
            if (_aspectFitter != null && h > 0)
            {
                _aspectFitter.aspectRatio = (float)w / (float)h;
            }

            // Crear RenderTexture Ultra HD con 8x MSAA y filtrado Trilineal
            if (_renderTexture != null)
            {
                _renderTexture.Release();
                Destroy(_renderTexture);
            }
            _renderTexture = new RenderTexture(w, h, 0, RenderTextureFormat.ARGB32)
            {
                filterMode = FilterMode.Trilinear,
                anisoLevel = 16,
                antiAliasing = 8,
                useMipMap = false,
                autoGenerateMips = false
            };
            _renderTexture.Create();

            _videoPlayer.clip          = clip;
            _videoPlayer.targetTexture = _renderTexture;
            _rawImage.texture          = _renderTexture;

            // Preparar video antes de mostrar la pantalla para evitar cuadros negros
            _videoPlayer.Prepare();
            yield return new WaitUntil(() => _videoPlayer.isPrepared);

            _canvas.gameObject.SetActive(true);
            _videoPlayer.Play();
            if (_audioSource != null && _audioSource.clip != null)
            {
                _audioSource.Play();
            }

            // Fade in cinematográfico suave
            float elapsed = 0f;
            const float fadeDuration = 0.25f;
            while (elapsed < fadeDuration)
            {
                elapsed += Time.unscaledDeltaTime;
                _canvasGroup.alpha = Mathf.Clamp01(elapsed / fadeDuration);
                yield return null;
            }
            _canvasGroup.alpha = 1f;
        }

        private void OnVideoFinished(VideoPlayer vp)
        {
            StartCoroutine(FinishRoutine());
        }

        private void Skip()
        {
            if (!_isPlaying) return;
            StartCoroutine(FinishRoutine());
        }

        private IEnumerator FinishRoutine()
        {
            if (!_isPlaying) yield break;

            // Fade out cinematográfico suave
            float elapsed = 0f;
            const float fadeDuration = 0.25f;
            float startAlpha = _canvasGroup.alpha;

            while (elapsed < fadeDuration)
            {
                elapsed += Time.unscaledDeltaTime;
                _canvasGroup.alpha = Mathf.Lerp(startAlpha, 0f, elapsed / fadeDuration);
                yield return null;
            }
            _canvasGroup.alpha = 0f;

            _isPlaying = false;
            _videoPlayer.Stop();
            if (_audioSource != null) _audioSource.Stop();
            _canvas.gameObject.SetActive(false);

            Action cb = _onFinished;
            _onFinished = null;
            cb?.Invoke();
        }
    }
}
