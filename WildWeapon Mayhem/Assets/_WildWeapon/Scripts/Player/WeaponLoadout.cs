using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Carga de 2 armas con swap (doc 2.4): cooldowns independientes por arma.
    /// Las armas no se desactivan como GameObject (sus cooldowns siguen corriendo);
    /// solo se intercambia la equipada.
    /// </summary>
    public class WeaponLoadout : MonoBehaviour
    {
        public MeleeWeapon[] weapons;

        public int ActiveIndex { get; private set; }
        public float SwapCooldown01 =>
            DuelRules.SwapCooldown <= 0f ? 0f : Mathf.Clamp01(_swapCooldown / DuelRules.SwapCooldown);

        private float _swapCooldown;

        void Awake()
        {
            RefreshEquipped();
        }

        void Update()
        {
            if (_swapCooldown > 0f) _swapCooldown -= Time.deltaTime;
        }

        public bool TrySwap()
        {
            if (weapons == null || weapons.Length < 2) return false;
            if (_swapCooldown > 0f) return false;

            ActiveIndex = (ActiveIndex + 1) % weapons.Length;
            _swapCooldown = DuelRules.SwapCooldown;
            RefreshEquipped();
            return true;
        }

        public void TryAttack(Vector2 aimDir, PlayerHealth self)
        {
            if (weapons == null || weapons.Length == 0) return;
            var w = weapons[ActiveIndex];
            if (w != null) w.TryAttack(aimDir, self);
        }

        public void ResetLoadout()
        {
            ActiveIndex = 0;
            _swapCooldown = 0f;
            RefreshEquipped();

            if (weapons != null)
                foreach (var w in weapons)
                    if (w != null) w.ResetCooldown();
        }

        private void RefreshEquipped()
        {
            if (weapons == null) return;
            for (int i = 0; i < weapons.Length; i++)
                if (weapons[i] != null) weapons[i].SetEquipped(i == ActiveIndex);
        }
    }
}
