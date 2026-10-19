using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// IA de un bot de sala PVP. Corre SOLO en la maquina del anfitrion: los demas
    /// clientes ven al bot como un remoto mas (PvpRemoteAvatar) y le interpolan el
    /// estado que el anfitrion manda a 15 Hz. Es una version compacta de
    /// <see cref="EnemyBot"/> adaptada a <see cref="PlayerController"/>: persigue al
    /// enemigo vivo mas cercano, amaga (windup) y golpea con el arma activa; el dano,
    /// la muerte y los VFX los resuelve el pawn local como cualquier otro portador.
    /// </summary>
    [RequireComponent(typeof(Rigidbody2D))]
    public class PvpBotBrain : MonoBehaviour
    {
        private enum State { Chase, Windup, Recover }

        [Tooltip("Los bots no corren igual que una persona.")]
        public float moveScale = 0.78f;
        public float windup = 0.34f;
        public float recover = 0.30f;

        public int Seat { get; private set; }

        private static readonly List<PvpBotBrain> Active = new List<PvpBotBrain>();
        private readonly RaycastHit2D[] _hits = new RaycastHit2D[4];

        private PlayerController _pc;
        private Rigidbody2D _rb;
        private PlayerHealth _health;
        private HeightBody _height;
        private Vector2 _aim = Vector2.right;
        private Vector2 _knockback;
        private State _state;
        private float _timer;
        private float _strafeSign = 1f;
        private float _jumpCooldown;

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            _pc = GetComponent<PlayerController>();
            _health = GetComponent<PlayerHealth>();
            _height = GetComponent<HeightBody>();
            _strafeSign = Random.value < 0.5f ? -1f : 1f;
        }

        void OnEnable() { Active.Add(this); }
        void OnDisable() { Active.Remove(this); }

        public void Bind(int seat)
        {
            Seat = seat;
            if (_pc == null) _pc = GetComponent<PlayerController>();
            if (_health == null) _health = GetComponent<PlayerHealth>();
            if (_rb == null) _rb = GetComponent<Rigidbody2D>();
            if (_pc != null) _pc.inputSuppressed = true;
            if (_pc != null && _pc.Health != null)
            {
                var h = _pc.Health.Height;
                if (h != null) h.simulate = true;   // este cuerpo SI salta: lo conduce la IA
            }
            if (_pc != null) _pc.CanAct = true;
        }

        /// <summary>Reset de ronda (lo pide PvpMatchManager junto al ResetForRound del pawn).</summary>
        public void ResetForRound(Vector2 pos, Vector2 look)
        {
            _state = State.Chase;
            _timer = 0f;
            _knockback = Vector2.zero;
            _aim = look.sqrMagnitude > 0.0001f ? look.normalized : Vector2.right;
            if (Random.value < 0.5f) _strafeSign = -_strafeSign;
        }

        void Update()
        {
            if (_pc == null) return;
            _pc.SetAimFromNetwork(_aim);
            _pc.networkSpeed = _rb != null ? _rb.linearVelocity.magnitude : 0f;
        }

        void FixedUpdate()
        {
            if (_pc == null || _rb == null || _health == null) return;
            float dt = Time.fixedDeltaTime;

            if (_health.IsDead)
            {
                _rb.linearVelocity = Vector2.zero;
                return;
            }

            // Fuera del combate (intro, fin de ronda) el bot se queda quieto.
            bool canAct = _pc.CanAct &&
                (DuelManager.Instance == null || DuelManager.Instance.CurrentPhase == DuelManager.Phase.Fight);
            if (!canAct)
            {
                _state = State.Chase;
                _rb.linearVelocity = Vector2.Lerp(_rb.linearVelocity, Vector2.zero, 1f - Mathf.Exp(-8f * dt));
                return;
            }

            var target = FindTarget();
            Vector2 move = Vector2.zero;
            float speed = DuelRules.MoveSpeed * moveScale * _health.SlowFactor;
            _jumpCooldown -= dt;
            if (_jumpCooldown < 0f) _jumpCooldown = 0f;

            var weapon = ActiveWeapon();

            if (target != null)
            {
                Vector2 to = (Vector2)target.transform.position - _rb.position;
                float dist = to.magnitude;
                Vector2 dir = dist > 0.001f ? to / dist : _aim;
                float reach = (weapon != null ? weapon.Range : 1f) * 0.85f + target.bodyRadius;

                // El objetivo esta en un deck alto: saltar para subir a pelearle arriba.
                if (_height != null && _height.Grounded && _jumpCooldown <= 0f)
                {
                    float dz = PlayerHealth.HeightOf(target) - _height.Z;
                    if (dz > 0.3f && dist < 2.6f && PlayerHealth.HeightOf(target) <= _height.ReachableHeight + 0.05f)
                    {
                        _height.QueueJump();
                        _jumpCooldown = 0.9f;
                    }
                }

                switch (_state)
                {
                    case State.Chase:
                        _aim = Vector2.Lerp(_aim, dir, 1f - Mathf.Exp(-12f * dt)).normalized;
                        if (dist <= reach && weapon != null && weapon.CanAttackNow)
                        {
                            _state = State.Windup;
                            _timer = windup;
                        }
                        else
                        {
                            move = Steer(dist > reach * 0.7f ? dir : Vector2.Perpendicular(dir) * _strafeSign);
                        }
                        break;

                    case State.Windup:
                        _aim = Vector2.Lerp(_aim, dir, 1f - Mathf.Exp(-4f * dt)).normalized;
                        _timer -= dt;
                        if (_timer <= 0f)
                        {
                            if (weapon != null) _pc.Loadout.TryAttack(_aim, _health);
                            _state = State.Recover;
                            _timer = recover;
                        }
                        break;

                    case State.Recover:
                        _timer -= dt;
                        move = -dir * 0.25f;
                        if (_timer <= 0f)
                        {
                            _state = State.Chase;
                            if (Random.value < 0.3f) _strafeSign = -_strafeSign;
                        }
                        break;
                }
            }
            else
            {
                _state = State.Chase;
            }

            move += Separation() * 0.6f;
            if (move.sqrMagnitude > 1f) move.Normalize();

            _rb.linearVelocity = move * speed + _knockback;
            _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-10f * dt));
        }

        private MeleeWeapon ActiveWeapon()
        {
            var loadout = _pc != null ? _pc.Loadout : null;
            if (loadout == null || loadout.weapons == null || loadout.weapons.Length == 0) return null;
            return loadout.weapons[Mathf.Clamp(loadout.ActiveIndex, 0, loadout.weapons.Length - 1)];
        }

        private PlayerHealth FindTarget()
        {
            PlayerHealth best = null;
            float bestD = float.MaxValue;
            int myTeam = _health != null ? _health.team : -1;
            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h.IsDead || h.team == myTeam) continue;
                if (!PlayerHealth.SameLevel(_health, h)) continue;
                float d = ((Vector2)h.transform.position - _rb.position).sqrMagnitude;
                if (d < bestD) { bestD = d; best = h; }
            }
            return best;
        }

        private Vector2 Steer(Vector2 desired)
        {
            if (IsFree(desired)) return desired;
            float[] tries = { 40f, 80f, 120f };
            foreach (float a in tries)
            {
                Vector2 d1 = Rotate(desired, a * _strafeSign);
                if (IsFree(d1)) return d1;
                Vector2 d2 = Rotate(desired, -a * _strafeSign);
                if (IsFree(d2)) { _strafeSign = -_strafeSign; return d2; }
            }
            return desired;
        }

        private bool IsFree(Vector2 dir)
        {
            int n = _rb.Cast(dir, _hits, 0.45f);
            for (int i = 0; i < n; i++)
            {
                var c = _hits[i].collider;
                if (c == null) continue;
                if (c.GetComponent<PlayerHealth>() != null) continue;   // los personajes no bloquean el pathing
                return false;
            }
            return true;
        }

        private Vector2 Separation()
        {
            Vector2 push = Vector2.zero;
            foreach (var b in Active)
            {
                if (b == null || b == this) continue;
                Vector2 d = _rb.position - (Vector2)b.transform.position;
                float m = d.magnitude;
                if (m > 0.001f && m < 0.95f) push += d / m * (1f - m / 0.95f);
            }
            return push;
        }

        private static Vector2 Rotate(Vector2 v, float deg)
        {
            float r = deg * Mathf.Deg2Rad;
            float c = Mathf.Cos(r), s = Mathf.Sin(r);
            return new Vector2(v.x * c - v.y * s, v.x * s + v.y * c);
        }
    }
}
