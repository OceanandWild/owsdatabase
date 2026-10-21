using UnityEngine;
using UnityEngine.UI;
using WildWeapon.Pvp;

namespace WildWeapon.UI
{
    /// <summary>
    /// Barra de habilidades del jugador local (Q/E/R) al pie de la pantalla.
    ///
    /// Tres cards (placas ww_abil_card) con el emblema de la habilidad, su nombre,
    /// la tecla, el barrido del cooldown y el costo de adrenalina de la definitiva.
    /// La barra se arma en el builder (WildWeaponBuilder.BuildAbilityBar) y este
    /// componente solo la mantiene al dia: cambia de arma, muestra el cooldown que
    /// baja y la adrenalina que se acumula.
    /// </summary>
    public class AbilityBarHud : MonoBehaviour
    {
        [System.Serializable]
        public class Card
        {
            public RectTransform root;     // card completa (para el pulso al quedar lista)
            public Image frame;            // placa ww_abil_card
            public Image icon;             // emblema de la habilidad
            public Image cooldown;         // barrido radial del cooldown
            public Text key;               // "Q" / "E" / "R"
            public Text name;              // "Corte Circular"
            public Text timer;             // segundos que le quedan
        }

        public Card[] cards = new Card[3];
        public Image adrenalineFill;
        public Text adrenalineText;
        public Text weaponText;
        public CanvasGroup root;

        private static readonly Color ReadyIcon = new Color(1f, 1f, 1f, 1f);
        private static readonly Color CooldownIcon = new Color(0.62f, 0.66f, 0.74f, 1f);
        private static readonly Color LockedIcon = new Color(0.85f, 0.35f, 0.30f, 0.85f);
        private static readonly Color ReadyKey = new Color(1f, 0.88f, 0.45f, 1f);
        private static readonly Color IdleKey = new Color(0.70f, 0.74f, 0.82f, 0.9f);
        private static readonly Color AdrenalineLow = new Color(0.85f, 0.35f, 0.25f, 1f);
        private static readonly Color AdrenalineHigh = new Color(1f, 0.80f, 0.28f, 1f);

        private const float PulseTime = 0.35f;

        private readonly bool[] _wasReady = new bool[3];
        private readonly float[] _pulse = new float[3];
        private int _weaponIndex = -1;
        private string _weaponName = "";
        private float _adrenalineMax = 300f;

        private void Start()
        {
            if (root != null) root.alpha = 0f;
            // El ancho maximo del relleno lo deja el builder; se lee una vez.
            if (adrenalineFill != null)
            {
                var rt = adrenalineFill.rectTransform;
                if (rt.sizeDelta.x > 1f) _adrenalineMax = rt.sizeDelta.x;
            }
        }

        private void Update()
        {
            var caster = ResolveCaster();
            if (caster == null)
            {
                if (root != null && root.alpha > 0f) root.alpha = 0f;
                return;
            }

            if (root != null && root.alpha < 1f)
                root.alpha = Mathf.MoveTowards(root.alpha, 1f, Time.unscaledDeltaTime * 5f);

            // El cambio de arma cambia las tres cards: se refresca el encabezado.
            int weaponIndex = caster.loadout != null ? caster.loadout.ActiveIndex : 0;
            if (weaponIndex != _weaponIndex)
            {
                _weaponIndex = weaponIndex;
                RefreshWeaponLabel(caster);
            }

            for (int i = 0; i < cards.Length; i++) UpdateCard(i, caster);
            UpdateAdrenaline(caster);
        }

        // =================================================================
        // Cards
        // =================================================================

        private void UpdateCard(int slot, AbilityCaster caster)
        {
            var card = cards[slot];
            if (card == null) return;

            var def = caster.GetAbility(slot);
            if (def == null)
            {
                // Esa ranura no tiene habilidad (arma sin Q/E/R).
                if (card.icon != null) card.icon.enabled = false;
                if (card.cooldown != null) { card.cooldown.fillAmount = 0f; card.cooldown.enabled = false; }
                if (card.name != null) card.name.text = "-";
                if (card.timer != null) card.timer.text = "";
                if (card.key != null) card.key.color = IdleKey;
                if (card.root != null) card.root.localScale = Vector3.one;
                return;
            }

            if (card.icon != null)
            {
                card.icon.enabled = true;
                var sprite = AbilityIcons.Get(def.kind);
                if (card.icon.sprite != sprite) card.icon.sprite = sprite;
                // El barrido del cooldown usa el mismo emblema: la Image sin sprite
                // no dibuja nada, y asi el cooldown "se come" el icono.
                if (card.cooldown != null && card.cooldown.sprite != sprite) card.cooldown.sprite = sprite;
            }
            if (card.name != null && card.name.text != def.abilityName) card.name.text = def.abilityName;

            float cd = caster.Cooldown01(slot);
            float seconds = caster.CooldownSeconds(slot);
            bool ready = cd <= 0.0001f;

            if (card.cooldown != null)
            {
                card.cooldown.fillAmount = cd;
                card.cooldown.enabled = !ready;
            }
            if (card.timer != null)
            {
                if (ready) card.timer.text = "";
                else card.timer.text = seconds >= 10f ? Mathf.CeilToInt(seconds).ToString() : seconds.ToString("0.0");
            }

            // La definitiva necesita adrenalina: si no la hay, la card avisa.
            bool locked = def.adrenalineCost > 0f && caster.Adrenaline < def.adrenalineCost;
            if (card.icon != null) card.icon.color = locked ? LockedIcon : (ready ? ReadyIcon : CooldownIcon);
            if (card.key != null) card.key.color = ready ? ReadyKey : IdleKey;

            // Pulso cuando la habilidad queda lista otra vez.
            if (ready && !_wasReady[slot]) _pulse[slot] = PulseTime;
            _wasReady[slot] = ready;
            if (card.root != null)
            {
                if (_pulse[slot] > 0f)
                {
                    _pulse[slot] = Mathf.Max(0f, _pulse[slot] - Time.unscaledDeltaTime);
                    float k = 1f + 0.22f * (_pulse[slot] / PulseTime);
                    card.root.localScale = new Vector3(k, k, 1f);
                }
                else if (card.root.localScale != Vector3.one)
                {
                    card.root.localScale = Vector3.one;
                }
            }
        }

        // =================================================================
        // Adrenalina y encabezado
        // =================================================================

        private void UpdateAdrenaline(AbilityCaster caster)
        {
            float a = Mathf.Clamp01(caster.Adrenaline / AbilityCaster.AdrenalineMax);
            if (adrenalineFill != null)
            {
                var rt = adrenalineFill.rectTransform;
                var size = rt.sizeDelta;
                size.x = Mathf.Max(2f, _adrenalineMax * a);
                rt.sizeDelta = size;
                adrenalineFill.color = Color.Lerp(AdrenalineLow, AdrenalineHigh, a);
            }
            if (adrenalineText != null)
                adrenalineText.text = $"ADRENALINA  {Mathf.RoundToInt(caster.Adrenaline)} / {Mathf.RoundToInt(AbilityCaster.AdrenalineMax)}";
        }

        private void RefreshWeaponLabel(AbilityCaster caster)
        {
            if (weaponText == null) return;
            string name = "";
            var loadout = caster.loadout;
            if (loadout != null && loadout.weapons != null && loadout.weapons.Length > 0)
            {
                int i = Mathf.Clamp(loadout.ActiveIndex, 0, loadout.weapons.Length - 1);
                if (loadout.weapons[i] != null) name = loadout.weapons[i].DisplayName;
            }
            if (name == _weaponName) return;
            _weaponName = name;
            weaponText.text = name;
        }

        // =================================================================
        // Jugador local
        // =================================================================

        private AbilityCaster ResolveCaster()
        {
            var pc = LocalPlayer();
            return pc != null ? pc.Abilities : null;
        }

        /// <summary>
        /// El portador que maneja este cliente: en PVP es el asiento local, en el
        /// duelo y en supervivencia es el J1.
        /// </summary>
        private static PlayerController LocalPlayer()
        {
            var pvp = PvpMatchManager.Instance;
            if (pvp != null)
            {
                var local = pvp.LocalIndex == 0 ? pvp.p1 : pvp.p2;
                if (local != null) return local;
            }

            var boot = GameBootstrap.Instance;
            if (boot == null) return null;
            if (GameSession.Mode == GameMode.Multi && boot.MultiPlayers != null && boot.MultiPlayers.Count > 0)
                return boot.MultiPlayers[0];
            return boot.p1;
        }
    }
}
