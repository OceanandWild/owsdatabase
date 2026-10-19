using System.Collections;
using UnityEngine;
using UnityEngine.SceneManagement;
using WildWeapon.Pvp;

namespace WildWeapon.UI
{
    /// <summary>Menu principal: elige modo y carga la Arena con fundido.</summary>
    public class MainMenuController : MonoBehaviour
    {
        public CanvasGroup fader;
        public float fadeTime = 0.45f;

        private bool _loading;

        void Start()
        {
            Time.timeScale = 1f;
            if (fader != null) StartCoroutine(Fade(1f, 0f, null));
        }

        public void PlayMulti()
{
    if (_loading) return;
    _loading = true;
    GameSession.Mode = GameMode.Multi;
    StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene("MultiplayerLobby")));
}
        public void PlayBots() => OpenMapSelect(GameMode.Bots);

        /// <summary>Abre el overlay de emparejamiento PVP online.</summary>
        public void PlayPvp() => PvpQuickmatchPanel.Open(this);

        /// <summary>Llamado por el panel cuando el server empareja: carga la Arena en modo PVP.</summary>
        public void StartPvpMatch(int seat, string opponentName, int opponentColor, int seed)
        {
            GameSession.PvpSeat = seat;
            GameSession.PvpOpponentName = string.IsNullOrEmpty(opponentName) ? "RIVAL" : opponentName;
            GameSession.PvpOpponentColor = opponentColor;
            GameSession.PvpSeed = seed;
            Launch(GameMode.Pvp);
        }

        public void Quit()
        {
#if UNITY_EDITOR
            UnityEditor.EditorApplication.isPlaying = false;
#else
            Application.Quit();
#endif
        }

        private void Launch(GameMode mode)
        {
            if (_loading) return;
            _loading = true;
            GameSession.Mode = mode;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.ArenaScene)));
        }

        /// <summary>Duelo y Supervivencia pasan por el selector de arena antes de la partida.</summary>
        private void OpenMapSelect(GameMode mode)
        {
            if (_loading) return;
            _loading = true;
            GameSession.Mode = mode;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MapSelectScene)));
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
