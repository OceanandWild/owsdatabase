using System.Collections;
using UnityEngine;
using UnityEngine.UI;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Cuenta regresiva 3-2-1-GO del arranque de la batalla PVP,
    /// con los sprites generados por Aura (ww_ui_count_*).
    /// </summary>
    public class PvpCountdown : MonoBehaviour
    {
        public Image digit;
        public Sprite sprite3;
        public Sprite sprite2;
        public Sprite sprite1;
        public Sprite spriteGo;

        [Tooltip("Duracion de cada numero; el ultimo paso (GO) dura un poco menos.")]
        public float stepSeconds = 1f;
        [Tooltip("Duracion del GO (debe arrancar cuando cae el telón del intro).")]
        public float goSeconds = 0.8f;

        public bool IsPlaying { get; private set; }

        public void Play()
        {
            StopAllCoroutines();
            gameObject.SetActive(true);
            StartCoroutine(Run());
        }

        public void Hide()
        {
            StopAllCoroutines();
            IsPlaying = false;
            if (digit != null) SetAlpha(0f);
        }

        private IEnumerator Run()
        {
            IsPlaying = true;
            if (digit == null) { IsPlaying = false; yield break; }

            yield return Show(sprite3, stepSeconds);
            yield return Show(sprite2, stepSeconds);
            yield return Show(sprite1, stepSeconds);
            yield return Show(spriteGo, goSeconds);

            SetAlpha(0f);
            IsPlaying = false;
        }

        private IEnumerator Show(Sprite sprite, float duration)
        {
            if (sprite != null) digit.sprite = sprite;
            var rt = digit.rectTransform;

            SetAlpha(0f);
            float t = 0f;
            const float punchTime = 0.16f;

            // Entrada: pop de escala + fade in
            while (t < punchTime)
            {
                t += Time.unscaledDeltaTime;
                float k = Mathf.Clamp01(t / punchTime);
                float scale = Mathf.Lerp(1.42f, 1f, 1f - (1f - k) * (1f - k));
                rt.localScale = new Vector3(scale, scale, 1f);
                SetAlpha(k);
                yield return null;
            }
            rt.localScale = Vector3.one;
            SetAlpha(1f);

            // Sosten + fade out al final
            float remaining = Mathf.Max(0f, duration - punchTime);
            float fadeTime = Mathf.Min(0.22f, remaining * 0.5f);
            yield return new WaitForSecondsRealtime(remaining - fadeTime);

            t = 0f;
            while (t < fadeTime)
            {
                t += Time.unscaledDeltaTime;
                SetAlpha(1f - Mathf.Clamp01(t / fadeTime));
                yield return null;
            }
            SetAlpha(0f);
        }

        private void SetAlpha(float a)
        {
            if (digit == null) return;
            var c = digit.color;
            c.a = a;
            digit.color = c;
        }
    }
}
