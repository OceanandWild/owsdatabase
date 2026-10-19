using UnityEngine;
using UnityEngine.UI;
using WildWeapon.Pvp;

namespace WildWeapon.UI
{
    /// <summary>
    /// HUD de la partida 1v1 (duelo local y PvP online): placas de jugador con
    /// vida, marcas de ronda y armas, mas el marcador de ronda/reloj y el aviso
    /// de Overdrive. La jerarquia y los skins (ww_hud_*) los arma
    /// WildWeaponBuilder; este componente solo la mantiene al dia.
    /// Reemplaza al HUD OnGUI de F0 (HudDebug).
    /// </summary>
    public class MatchHud : MonoBehaviour
    {
        [System.Serializable]
        public class PlayerSlot
        {
            public Image panel;                  // placa biselada (skin gris tintable)
            public Text tag;                     // "J1" / "J1 · VOS"
            public Image[] pips = new Image[0];  // marcas de ronda ganada
            public Image hpFill;                 // relleno de vida (ancho = Hp01)
            public Image[] chipBg = new Image[0];
            public Text[] chipLabel = new Text[0];

            [System.NonSerialized] public float hp = 1f;    // valor suavizado
            [System.NonSerialized] public float flash;      // destello al recibir dano
            [System.NonSerialized] public int lastScore;
            [System.NonSerialized] public float pop;        // pop de la marca recien ganada
            [System.NonSerialized] public int popPip = -1;
        }

        [Header("Marcador de ronda")]
        public Text roundLabel;
        public Text clockLabel;

        [Header("Overdrive")]
        public CanvasGroup overdriveGroup;
        public Image overdrivePlate;
        public Text overdriveLabel;

        [Header("Jugadores")]
        public PlayerSlot[] slots = new PlayerSlot[2];
        public Color[] fallbackAccents = { new Color(0.20f, 0.85f, 1f), new Color(1f, 0.30f, 0.28f) };

        [Header("Anuncio central")]
        public CanvasGroup statusGroup;
        public Image statusPlate;
        public RectTransform statusRect;
        public Text statusText;
        public Text statusHint;

        [Header("Pie")]
        public Text footer;

        // El skin de placas y chips es gris neutro: se tintea con el color del personaje.
        private static readonly Color PanelTint = new Color(0.80f, 0.84f, 0.92f, 0.97f);
        private static readonly Color ChipIdle = new Color(0.55f, 0.60f, 0.70f, 0.88f);
        private static readonly Color ChipActive = new Color(0.88f, 0.92f, 0.98f, 1f);
        private static readonly Color StatusTint = new Color(0.84f, 0.88f, 0.95f, 0.98f);
        private static readonly Color HpLow = new Color(0.95f, 0.24f, 0.20f);
        private static readonly Color HpHigh = new Color(0.36f, 0.88f, 0.42f);
        private static readonly Color OdTint = new Color(1f, 0.34f, 0.30f, 1f);

        private const float HpFillWidth = 388f;   // ancho interno del canal de vida
        private const float HpFlashTime = 0.15f;
        private const float PipPopTime = 0.28f;

        private readonly Color[] _accents = { Color.white, Color.white };
        private Vector2 _statusHome;
        private float _statusShow;

        private void Awake()
        {
            if (statusRect != null) _statusHome = statusRect.anchoredPosition;
        }

        private void Start()
        {
            if (overdriveGroup != null) overdriveGroup.alpha = 0f;
            if (statusGroup != null) statusGroup.alpha = 0f;
            if (statusHint != null) statusHint.gameObject.SetActive(false);

            for (int i = 0; i < slots.Length; i++)
            {
                if (slots[i] == null) continue;
                slots[i].hp = 1f;
                slots[i].lastScore = 0;
            }
        }

        private void Update()
        {
            var mgr = DuelManager.Instance;
            if (mgr == null) return;

            float dt = Time.unscaledDeltaTime;   // el HUD no se congela con el hitstop
            var pvp = PvpMatchManager.Instance;
            bool pvpRunning = pvp != null && pvp.Running;

            // ---- Marcador de ronda + reloj ----
            if (roundLabel != null) roundLabel.text = $"RONDA {mgr.RoundNumber}";
            if (clockLabel != null)
                clockLabel.text = $"{Mathf.FloorToInt(mgr.RoundTime / 60f):00}:{Mathf.FloorToInt(mgr.RoundTime % 60f):00}";

            // ---- Aviso de Overdrive (late mientras esta activo) ----
            if (overdriveGroup != null)
            {
                overdriveGroup.alpha = Mathf.MoveTowards(overdriveGroup.alpha, mgr.Overdrive ? 1f : 0f, dt * 5f);
                if (mgr.Overdrive && overdrivePlate != null)
                {
                    var c = OdTint;
                    c.a = 0.72f + 0.28f * Mathf.PingPong(Time.unscaledTime * 2.6f, 1f);
                    overdrivePlate.color = c;
                }
            }

            // ---- Placas de jugador ----
            int slotCount = slots != null ? slots.Length : 0;
            if (mgr.Players != null) slotCount = Mathf.Min(slotCount, mgr.Players.Length);
            for (int i = 0; i < slotCount; i++) UpdateSlot(mgr, pvp, pvpRunning, i, dt);

            // ---- Anuncio central ----
            string status = mgr.StatusText;
            if (status == "!OVERDRIVE!") status = "";   // ya lo cubre el aviso de Overdrive

            bool countdownCovering = pvp != null && pvp.CountdownVisible;
            bool visible = !countdownCovering && !string.IsNullOrEmpty(status);

            _statusShow = Mathf.MoveTowards(_statusShow, visible ? 1f : 0f, dt * 6f);
            float e = _statusShow * _statusShow * (3f - 2f * _statusShow);
            if (statusGroup != null) statusGroup.alpha = e;
            if (statusRect != null) statusRect.anchoredPosition = _statusHome + new Vector2(0f, (1f - e) * -16f);

            if (visible)
            {
                if (statusText != null) statusText.text = status;
                if (statusPlate != null)
                {
                    int winner = status.Contains("J1") ? 0 : status.Contains("J2") ? 1 : -1;
                    statusPlate.color = winner >= 0
                        ? Color.Lerp(StatusTint, _accents[winner], 0.30f)
                        : StatusTint;
                }
                if (statusHint != null)
                {
                    bool matchEnd = mgr.CurrentPhase == DuelManager.Phase.MatchEnd;
                    bool opponentLeft = status.ToUpperInvariant().Contains("RIVAL");
                    statusHint.text = pvpRunning
                        ? "R (teclado) o Start (mando) = pedir revancha · Esc = salir"
                        : "R (teclado) o Start (mando) = revancha";
                    statusHint.gameObject.SetActive(matchEnd && !opponentLeft);
                }
            }

            // ---- Pie con los controles ----
            if (footer != null)
                footer.text = pvpRunning
                    ? "PVP ONLINE - WASD + mouse (click ataca, Shift/Space dash, X cambia arma, Q/E/R habilidades) - Esc sale de la partida"
                    : "DUELO - J1: WASD + mouse (click ataca, Shift/Space dash, X cambia arma) - J2: mando o flechas (',' ataca) - Esc menu";
        }

        private void UpdateSlot(DuelManager mgr, PvpMatchManager pvp, bool pvpRunning, int index, float dt)
        {
            var slot = slots[index];
            if (slot == null) return;
            var pc = mgr.Players != null && index < mgr.Players.Length ? mgr.Players[index] : null;

            // Acento = color elegido del personaje (en PVP el rival llega con el color del server).
            Color accent = fallbackAccents != null && fallbackAccents.Length > 0
                ? fallbackAccents[Mathf.Min(index, fallbackAccents.Length - 1)]
                : Color.white;
            if (pc != null && pc.visual != null) accent = pc.visual.paintColor;
            accent.a = 1f;
            _accents[index] = accent;

            if (slot.panel != null) slot.panel.color = Color.Lerp(PanelTint, accent, 0.22f);

            if (slot.tag != null)
            {
                string tag = $"J{index + 1}";
                if (pvpRunning && pvp != null) tag += index == pvp.LocalIndex ? " · VOS" : " · RIVAL";
                slot.tag.text = tag;
                slot.tag.color = accent;
            }

            // Marcas de ronda ganada: la nueva entra con un pop de escala.
            int score = mgr.Scores != null && index < mgr.Scores.Length ? mgr.Scores[index] : 0;
            if (score > slot.lastScore)
            {
                slot.pop = PipPopTime;
                slot.popPip = score - 1;
            }
            slot.lastScore = score;

            for (int p = 0; p < slot.pips.Length; p++)
            {
                var pip = slot.pips[p];
                if (pip == null) continue;
                bool lit = p < score;
                pip.color = lit ? accent : new Color(1f, 1f, 1f, 0.13f);

                float scale = 1f;
                if (slot.pop > 0f && p == slot.popPip)
                    scale = 1f + 0.55f * Mathf.Clamp01(slot.pop / PipPopTime);
                pip.rectTransform.localScale = new Vector3(scale, scale, 1f);
            }
            if (slot.pop > 0f) slot.pop = Mathf.Max(0f, slot.pop - dt);

            // Vida: el dano baja al toque, la cura sube suave.
            float target = pc != null && pc.Health != null ? pc.Health.Hp01 : 1f;
            if (target < slot.hp - 0.0005f)
            {
                slot.flash = HpFlashTime;
                slot.hp = target;
            }
            else
            {
                slot.hp = Mathf.Lerp(slot.hp, target, 1f - Mathf.Exp(-8f * dt));
            }
            if (slot.flash > 0f) slot.flash = Mathf.Max(0f, slot.flash - dt);

            if (slot.hpFill != null)
            {
                var rt = slot.hpFill.rectTransform;
                var size = rt.sizeDelta;
                size.x = Mathf.Max(2f, HpFillWidth * slot.hp);
                rt.sizeDelta = size;

                Color fill = Color.Lerp(HpLow, HpHigh, slot.hp);
                if (slot.flash > 0f) fill = Color.Lerp(fill, Color.white, slot.flash / HpFlashTime * 0.55f);
                slot.hpFill.color = fill;
            }

            // Armas: la activa levanta el chip.
            string w1 = "-", w2 = "-";
            bool firstActive = true;
            if (pc != null && pc.Loadout != null && pc.Loadout.weapons != null)
            {
                var weapons = pc.Loadout.weapons;
                if (weapons.Length > 0 && weapons[0] != null) w1 = weapons[0].DisplayName;
                if (weapons.Length > 1 && weapons[1] != null) w2 = weapons[1].DisplayName;
                firstActive = pc.Loadout.ActiveIndex == 0;
            }
            string[] names = { w1, w2 };

            for (int c = 0; c < slot.chipLabel.Length && c < 2; c++)
            {
                bool active = (c == 0) == firstActive;
                if (slot.chipLabel[c] != null)
                {
                    slot.chipLabel[c].text = $"[{c + 1}]  {names[c]}";
                    slot.chipLabel[c].color = active ? Color.white : new Color(1f, 1f, 1f, 0.55f);
                }
                if (slot.chipBg != null && c < slot.chipBg.Length && slot.chipBg[c] != null)
                    slot.chipBg[c].color = active
                        ? Color.Lerp(ChipActive, accent, 0.55f)
                        : Color.Lerp(ChipIdle, accent, 0.18f);
            }
        }
    }
}
