using System;
using System.Collections;
using UnityEngine;

namespace WilderGambit.View
{
    /// <summary>
    /// Reproduce los frames propios de la skin «Eclipse Eterno» sobre la vista de
    /// una pieza: un pulso de vacío al moverse y una disolución de eclipse al
    /// recibir jaque mate. Los frames viven en <c>Resources/EclipseEterno</c> y
    /// comparten un canvas de 768×768 con el cuerpo del rey a 512 px de alto,
    /// así que la escala se calcula con esa altura de contenido y no con el
    /// tamaño total del PNG (que incluye el halo).
    /// </summary>
    public class EclipseEternoAnimator : MonoBehaviour
    {
        /// <summary>Altura del rey dentro del canvas de los frames (768×768).</summary>
        public const float ContentHeight = 512f;

        /// <summary>El cuerpo del rey ocupa el mismo 82% de casilla que el arte full-art.</summary>
        private const float BodyFill = 0.82f;

        private SpriteRenderer _sr;
        private Sprite _restSprite;
        private Vector3 _restScale;
        private bool _restFlipX;
        private Transform _shadow;
        private bool _shadowWasActive;
        private Coroutine _routine;
        private bool _playing;

        public bool IsPlaying => _playing;

        /// <summary>Pulso corto de movimiento. <paramref name="dir"/> negativo voltea el frame.</summary>
        public void PlayMove(Sprite[] frames, Sprite restSprite, float tileSize, int dir)
        {
            Play(frames, restSprite, tileSize, 30f, 0f, dir, null);
        }

        /// <summary>Disolución de jaque mate. Invoca <paramref name="onComplete"/> al terminar.</summary>
        public void PlayMate(Sprite[] frames, Sprite restSprite, float tileSize, Action onComplete)
        {
            Play(frames, restSprite, tileSize, 12f, 0.35f, 0, onComplete);
        }

        private void Play(Sprite[] frames, Sprite restSprite, float tileSize,
                          float fps, float hold, int dir, Action onComplete)
        {
            if (frames == null || frames.Length == 0) return;

            // Si ya había una animación en curso, se restaura antes de capturar
            // el estado de reposo para no guardar un frame como si fuera la skin.
            if (_routine != null)
            {
                StopCoroutine(_routine);
                Restore();
            }

            CaptureRest(restSprite);
            _playing = true;
            _routine = StartCoroutine(Run(frames, tileSize, fps, hold, dir, onComplete));
        }

        private void CaptureRest(Sprite restSprite)
        {
            _sr = GetComponent<SpriteRenderer>();
            _restSprite = restSprite != null ? restSprite : (_sr != null ? _sr.sprite : null);
            _restScale = transform.localScale;
            _restFlipX = _sr != null && _sr.flipX;

            _shadow = transform.Find("Shadow");
            _shadowWasActive = _shadow != null && _shadow.gameObject.activeSelf;
            if (_shadow != null) _shadow.gameObject.SetActive(false);
        }

        private IEnumerator Run(Sprite[] frames, float tileSize, float fps, float hold,
                                int dir, Action onComplete)
        {
            if (_sr == null) yield break;

            // La altura del rey dentro del frame está en píxeles; se convierte a
            // unidades de mundo con el PPU real del sprite para no depender de la
            // importación (los frames usan 100 PPU y el arte de pieza ~65 PPU).
            Sprite reference = frames[0] != null ? frames[0] : _restSprite;
            float ppu = reference != null && reference.pixelsPerUnit > 0f ? reference.pixelsPerUnit : 100f;
            float bodyWorldHeight = ContentHeight / ppu;
            float scale = bodyWorldHeight > 0f ? tileSize * BodyFill / bodyWorldHeight : 1f;
            transform.localScale = new Vector3(scale, scale, 1f);
            _sr.flipX = dir < 0;

            float frameTime = 1f / Mathf.Max(1f, fps);
            for (int i = 0; i < frames.Length; i++)
            {
                if (_sr == null) yield break;
                if (frames[i] != null) _sr.sprite = frames[i];
                yield return new WaitForSeconds(frameTime);
            }

            if (hold > 0f) yield return new WaitForSeconds(hold);

            Restore();
            onComplete?.Invoke();
        }

        private void Restore()
        {
            if (_sr != null && _restSprite != null) _sr.sprite = _restSprite;
            transform.localScale = _restScale;
            if (_sr != null) _sr.flipX = _restFlipX;
            if (_shadow != null) _shadow.gameObject.SetActive(_shadowWasActive);
            _playing = false;
            _routine = null;
        }

        private void OnDisable()
        {
            if (_playing) Restore();
        }
    }
}
