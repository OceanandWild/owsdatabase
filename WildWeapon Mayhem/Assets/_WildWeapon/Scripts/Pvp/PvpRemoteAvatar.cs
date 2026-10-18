using UnityEngine;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Conduce el pawn del RIVAL en PVP: el gameplay de ese portador corre en la
    /// maquina rival, aca solo se interpolan posiciones/punteria y se reproducen
    /// sus gestos (swing, cast, swap). El daño real lo decide el dueño del pawn.
    /// </summary>
    public class PvpRemoteAvatar : MonoBehaviour
    {
        [Tooltip("Suavizado de posicion por paso fisico (0-1).")]
        public float lerp = 0.25f;

        private PlayerController _pc;
        private Rigidbody2D _rb;

        private Vector2 _targetPos;
        private Vector2 _targetAim = Vector2.right;
        private float _targetSpeed;
        private float _targetZ;
        private float _z;
        private bool _has;

        public void Bind(PlayerController pc)
        {
            _pc = pc;
            _rb = pc != null ? pc.GetComponent<Rigidbody2D>() : null;
            if (pc != null)
            {
                pc.inputSuppressed = true;
                _targetPos = pc.transform.position;
                if (pc.AimDir.sqrMagnitude > 0.0001f) _targetAim = pc.AimDir;
                // La altura del rival la manda la red: este cuerpo no simula saltos.
                var h = Height;
                if (h != null) h.simulate = false;
            }
        }

        /// <summary>Snapshot del rival (mensaje state).</summary>
        public void Apply(PvpMsg m)
        {
            _targetPos = new Vector2(m.x, m.y);
            var aim = new Vector2(m.ax, m.ay);
            if (aim.sqrMagnitude > 0.0001f) _targetAim = aim.normalized;
            _targetSpeed = m.sp;
            _targetZ = m.z;
            _has = true;

            if (_pc != null && _pc.Health != null) _pc.Health.SetNetworkHp(m.hp);
        }

        /// <summary>Teletransporte duro (reset de ronda): corta cualquier interpolacion pendiente.</summary>
        public void Snap()
        {
            if (_pc == null) return;
            _targetPos = _pc.transform.position;
            _z = _targetZ;
            if (_rb != null) _rb.position = _targetPos;
            var h = Height;
            if (h != null) h.SetHeight(_z);
        }

        public void PlayAttack(int weaponIndex)
        {
            if (_pc == null || _pc.Loadout == null) return;
            var weapons = _pc.Loadout.weapons;
            if (weapons == null || weapons.Length == 0) return;
            int idx = weaponIndex >= 0 && weaponIndex < weapons.Length ? weaponIndex : _pc.Loadout.ActiveIndex;
            var weapon = weapons[idx];
            if (weapon != null) weapon.PlaySwingOnly(_targetAim);
        }

        public void PlaySwap(int weaponIndex)
        {
            if (_pc == null || _pc.Loadout == null) return;
            _pc.Loadout.SetActiveIndex(weaponIndex);
        }

        public void PlayCast(int kind)
        {
            if (_pc == null || _pc.Abilities == null) return;
            _pc.Abilities.PlayRemoteCast((AbilityKind)kind);
        }

        void FixedUpdate()
        {
            if (!_has || _rb == null) return;
            var current = _rb.position;
            // Hueco grande (lag o reset): se pega directo.
            if ((_targetPos - current).sqrMagnitude > 9f) _rb.position = _targetPos;
            else _rb.MovePosition(Vector2.Lerp(current, _targetPos, lerp));
        }

        void Update()
        {
            if (!_has || _pc == null) return;
            _pc.SetAimFromNetwork(_targetAim);
            _pc.networkSpeed = _targetSpeed;

            // Altura suavizada: el rival sube/baja plataformas con el mismo paralaje.
            var h = Height;
            if (h != null)
            {
                _z = Mathf.MoveTowards(_z, _targetZ, Time.deltaTime * 9f);
                h.SetHeight(_z);
            }
        }

        private HeightBody Height => _pc != null && _pc.Health != null ? _pc.Health.Height : null;
    }
}
