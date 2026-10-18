using System.Collections;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;

namespace WildWeapon.UI
{
    /// <summary>
    /// Controlador de la escena de personalizacion (CharacterSelect). Es una
    /// escena aparte del menu principal: entra con fundido, deja elegir el color
    /// de cada jugador sobre la preview riggeada y vuelve al menu.
    /// </summary>
    public class CharacterSelectController : MonoBehaviour
    {
        public CanvasGroup fader;
        public float fadeTime = 0.45f;

        private bool _leaving;

        private void Start()
        {
            Time.timeScale = 1f;
            if (fader != null) StartCoroutine(Fade(1f, 0f, null));
        }

        private void Update()
        {
            var kb = Keyboard.current;
            var pad = Gamepad.current;
            if ((kb != null && kb.escapeKey.wasPressedThisFrame) ||
                (pad != null && pad.selectButton.wasPressedThisFrame))
                Back();
        }

        /// <summary>Vuelve al menu principal con fundido.</summary>
        public void Back()
        {
            if (_leaving) return;
            _leaving = true;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MenuScene)));
        }

        private IEnumerator Fade(float from, float to, System.Action done)
        {
            if (fader != null)
            {
                fader.blocksRaycasts = true;
                float t = 0f;
                while (t < fadeTime)
                {
                    t += Time.unscaledDeltaTime;
                    fader.alpha = Mathf.Lerp(from, to, t / fadeTime);
                    yield return null;
                }
                fader.alpha = to;
                fader.blocksRaycasts = to > 0.5f;
            }
            done?.Invoke();
        }
    }
}
