using System;
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

        /// <summary>PVP: avisa cuando el portador cambia de arma (se reenvia por red).</summary>
        public event Action<int> Swapped;

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
            Swapped?.Invoke(ActiveIndex);
            return true;
        }

        /// <summary>PVP: aplica el swap que llego por red (sin cooldown local).</summary>
        public void SetActiveIndex(int index)
        {
            if (weapons == null || weapons.Length == 0) return;
            ActiveIndex = Mathf.Clamp(index, 0, weapons.Length - 1);
            RefreshEquipped();
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

        /// <summary>
        /// Cambia el equipamiento (lo usa la armería). Las armas que quedan
        /// afuera se apagan para que no se vean ni se puedan usar.
        /// </summary>
        public void SetWeapons(MeleeWeapon[] newWeapons)
        {
            if (newWeapons == null || newWeapons.Length == 0) return;

            var all = GetComponentsInChildren<MeleeWeapon>(true);
            foreach (var w in all)
            {
                if (w == null) continue;
                bool inside = false;
                for (int i = 0; i < newWeapons.Length; i++)
                    if (newWeapons[i] == w) { inside = true; break; }
                if (!inside) w.SetEquipped(false);
            }

            weapons = newWeapons;
            ActiveIndex = 0;
            _swapCooldown = 0f;
            RefreshEquipped();
        }

        private void RefreshEquipped()
        {
            if (weapons == null) return;
            for (int i = 0; i < weapons.Length; i++)
                if (weapons[i] != null) weapons[i].SetEquipped(i == ActiveIndex);
        }
    }
}
