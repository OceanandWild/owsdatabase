using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Armería: el jugador elige las dos armas del equipamiento antes de entrar
    /// a la arena. Click en una tarjeta = el arma entra en la ranura activa;
    /// click en una ranura = cambia la ranura activa. "SUPERVIVENCIA" arranca el
    /// modo de oleadas con el equipamiento elegido y "VOLVER" regresa al menú.
    /// </summary>
    public class ArmoryController : MonoBehaviour
    {
        [Header("Fade")]
        public CanvasGroup fader;
        public float fadeTime = 0.45f;

        [Header("Piezas")]
        public ArmoryCard[] cards;
        public ArmorySlot[] slots;

        [Header("Info del arma")]
        public Text infoName;
        public Text infoBlurb;
        public Text infoStats;

        [Header("Acciones")]
        public Button startButton;

        /// <summary>Ranura que recibe el próximo arma que se elija (0 o 1).</summary>
        public int ActiveSlot { get; private set; }

        private bool _loading;

        /// <summary>Bajada de cada arma (la muestra el panel de detalle).</summary>
        private static readonly Dictionary<string, string> Blurbs = new Dictionary<string, string>
        {
            { "katana", "Acero gris, filo limpio y sin glow. El weapon degia: rápido, confiable y con las tres habilidades." },
            { "hacha_gris", "Tajo pesado y lento. El hacha gris castiga de cerca: pega más y abre el guardia del rival." },
            { "mazo_oxidado", "Pesa como un yunque y golpea como un Decreto. Mucho daño, alcance corto, cadencia lenta." },
            { "lanza_plasma", "Estocada a distancia. El plasma magenta empuja al rival y lo desarma antes del contacto." },
            { "sierra_chatarra", "Gira sin parar. El daño por golpe es bajo, pero la cadencia es la más alta del arsenal." },
        };

        void Start()
        {
            Time.timeScale = 1f;
            if (fader != null) StartCoroutine(Fade(1f, 0f, null));
            Refresh();
        }

        private void Update()
        {
            if (_loading) return;
            var kb = UnityEngine.InputSystem.Keyboard.current;
            var pad = UnityEngine.InputSystem.Gamepad.current;
            if ((kb != null && kb.escapeKey.wasPressedThisFrame) || (pad != null && pad.startButton.wasPressedThisFrame))
                Back();
        }

        /// <summary>Equipa el arma de la tarjeta en la ranura activa.</summary>
        public void Pick(int cardIndex)
        {
            if (cards == null || cardIndex < 0 || cardIndex >= cards.Length) return;
            var card = cards[cardIndex];
            if (card == null || string.IsNullOrEmpty(card.weaponId)) return;

            // Si el arma ya está en la otra ranura, se cambia de ranura.
            for (int s = 0; s < GameSession.Equipped.Length; s++)
                if (GameSession.EquippedAt(s) == card.weaponId && s != ActiveSlot)
                {
                    GameSession.Unequip(s);
                    break;
                }

            GameSession.Equip(ActiveSlot, card.weaponId);
            Refresh();
        }

        /// <summary>Cambia la ranura activa.</summary>
        public void SelectSlot(int slotIndex)
        {
            if (slotIndex < 0 || slotIndex > 1) return;
            ActiveSlot = slotIndex;
            Refresh();
        }

        /// <summary>Muestra el detalle de un arma (nombre, bajada y stats).</summary>
        public void ShowWeapon(int cardIndex)
        {
            if (cards == null || cardIndex < 0 || cardIndex >= cards.Length) return;
            var card = cards[cardIndex];
            if (card == null) return;

            if (infoName != null) infoName.text = card.displayName.ToUpperInvariant();
            if (infoBlurb != null)
            {
                Blurbs.TryGetValue(card.weaponId, out string blurb);
                infoBlurb.text = blurb ?? "";
            }
            if (infoStats != null && card.stats != null) infoStats.text = card.stats.GetComponent<Text>().text;
        }

        /// <summary>Arranca el modo de oleadas con el equipamiento elegido.</summary>
        public void StartSurvival()
        {
            if (_loading) return;
            _loading = true;
            GameSession.Mode = GameMode.Bots;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MapSelectScene)));
        }

        /// <summary>Vuelve al menú principal.</summary>
        public void Back()
        {
            if (_loading) return;
            _loading = true;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MenuScene)));
        }

        /// <summary>Repinta las tarjetas y las ranuras con el equipamiento actual.</summary>
        public void Refresh()
        {
            if (cards != null)
            {
                foreach (var card in cards)
                {
                    if (card == null) continue;
                    int slot = -1;
                    for (int s = 0; s < GameSession.Equipped.Length; s++)
                        if (GameSession.EquippedAt(s) == card.weaponId) { slot = s; break; }
                    card.SetEquippedSlot(slot);
                }
            }

            if (slots != null)
            {
                foreach (var slot in slots)
                {
                    if (slot == null) continue;
                    string id = GameSession.EquippedAt(slot.slotIndex);
                    string name = "";
                    Sprite sprite = null;
                    if (!string.IsNullOrEmpty(id) && cards != null)
                    {
                        foreach (var card in cards)
                        {
                            if (card == null || card.weaponId != id) continue;
                            name = card.displayName;
                            sprite = card.icon != null ? card.icon.sprite : null;
                            break;
                        }
                    }
                    slot.Bind(id, name, sprite, slot.accentColor);
                }
            }

            if (startButton != null)
            {
                bool ready = true;
                for (int s = 0; s < GameSession.Equipped.Length; s++)
                    if (string.IsNullOrEmpty(GameSession.EquippedAt(s))) ready = false;
                startButton.interactable = ready;
            }
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
