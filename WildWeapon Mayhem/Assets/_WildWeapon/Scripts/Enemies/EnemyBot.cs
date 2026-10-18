using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// IA de bot: persigue al enemigo vivo mas cercano, esquiva obstaculos,
    /// telegrafia (windup) y golpea con su arma unica.
    /// </summary>
    [RequireComponent(typeof(Rigidbody2D))]
    public class EnemyBot : MonoBehaviour
    {
        private enum State { Chase, Windup, Recover }

        public BotDef def;
        public Transform aimPivot;
        public MeleeWeapon weapon;
        public CharacterVisual visual;
        [Tooltip("Altura (Z) simulada: puede subir a las plataformas saltando")]
        public HeightBody height;

        public PlayerHealth Health { get; private set; }
        public float HpScale { get; set; } = 1f;

        private static readonly List<EnemyBot> Active = new List<EnemyBot>();
        private readonly RaycastHit2D[] _hits = new RaycastHit2D[4];

        private Rigidbody2D _rb;
        private State _state;
        private float _timer;
        private Vector2 _aim = Vector2.right;
        private Vector2 _knockback;
        private float _strafeSign = 1f;
        private float _jumpCooldown;
        private Color _weaponBaseColor = Color.white;

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            Health = GetComponent<PlayerHealth>();
            if (height == null) height = GetComponent<HeightBody>();
            if (weapon != null && weapon.bladeRenderer != null) _weaponBaseColor = weapon.bladeRenderer.color;
            _strafeSign = Random.value < 0.5f ? -1f : 1f;
        }

        void Start()
        {
            if (def != null && Health != null)
            {
                Health.bodyRadius = def.bodyRadius;
                Health.SetMaxHp(def.hp * HpScale);
            }
            if (visual != null && def != null)
            {
                if (visual.animator != null) visual.animator.speed = def.animSpeed;
                visual.SetPaintColor(def.tint);
            }
            if (Health != null) Health.Died += OnDied;
        }

        void OnEnable() { Active.Add(this); }
        void OnDisable() { Active.Remove(this); }

        private void OnDied(PlayerHealth _)
        {
            _rb.linearVelocity = Vector2.zero;
            _rb.simulated = false;
            SetTelegraph(0f);
            if (weapon != null) weapon.SetEquipped(false);
            Destroy(gameObject, 1.1f);
        }

        public void ApplyKnockback(Vector2 dir, float amount)
        {
            _knockback += dir * amount;
        }

        /// <summary>Stun por habilidad (ej. Corte Circular de la Katana).</summary>
        public void Stun(float seconds)
        {
            _stunTimer = Mathf.Max(_stunTimer, seconds);
            SetTelegraph(0f);
            _state = State.Chase;
            _timer = 0f;
        }

        [HideInInspector] public float _stunTimer;

        void Update()
        {
            if (aimPivot != null)
                aimPivot.rotation = Quaternion.Euler(0f, 0f, Mathf.Atan2(_aim.y, _aim.x) * Mathf.Rad2Deg);
            if (visual != null)
            {
                visual.Face(_aim);
                visual.SetSpeed(_rb.linearVelocity.magnitude);
            }
        }

        void FixedUpdate()
        {
            float dt = Time.fixedDeltaTime;
            if (Health != null && Health.IsDead) return;

            if (_stunTimer > 0f)
            {
                _stunTimer -= dt;
                _rb.linearVelocity = _knockback;
                _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-10f * dt));
                if (visual != null) visual.SetSpeed(0f);
                return;
            }

            var target = FindTarget();
            Vector2 move = Vector2.zero;
            float speed = def != null ? def.moveSpeed : 2f;
            if (Health != null) speed *= Health.SlowFactor;
            _jumpCooldown -= dt;
            if (_jumpCooldown < 0f) _jumpCooldown = 0f;

            if (target != null)
            {
                Vector2 to = (Vector2)target.transform.position - _rb.position;
                float dist = to.magnitude;
                Vector2 dir = dist > 0.001f ? to / dist : _aim;
                float reach = (weapon != null ? weapon.Range : 1f) * 0.85f + target.bodyRadius;

                // El objetivo esta en un deck alto: saltar para subir a pelearle arriba.
                if (height != null && height.Grounded && _jumpCooldown <= 0f)
                {
                    float dz = PlayerHealth.HeightOf(target) - height.Z;
                    if (dz > 0.3f && dist < 2.6f && PlayerHealth.HeightOf(target) <= height.ReachableHeight + 0.05f)
                    {
                        height.QueueJump();
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
                            _timer = def != null ? def.windup : 0.3f;
                        }
                        else
                        {
                            move = Steer(dist > reach * 0.7f ? dir : Vector2.Perpendicular(dir) * _strafeSign);
                        }
                        break;

                    case State.Windup:
                        _aim = Vector2.Lerp(_aim, dir, 1f - Mathf.Exp(-4f * dt)).normalized;
                        float total = def != null ? Mathf.Max(0.01f, def.windup) : 0.3f;
                        SetTelegraph(1f - _timer / total);
                        _timer -= dt;
                        if (_timer <= 0f)
                        {
                            SetTelegraph(0f);
                            if (weapon != null) weapon.TryAttack(_aim, Health);
                            _state = State.Recover;
                            _timer = def != null ? def.recover : 0.3f;
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
                SetTelegraph(0f);
            }

            move += Separation() * 0.6f;
            if (move.sqrMagnitude > 1f) move.Normalize();

            _rb.linearVelocity = move * speed + _knockback;
            _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-10f * dt));
        }

        private PlayerHealth FindTarget()
        {
            PlayerHealth best = null;
            float bestD = float.MaxValue;
            int myTeam = Health != null ? Health.team : -1;
            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h.IsDead || h.team == myTeam) continue;
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
                if (c.GetComponent<PlayerHealth>() != null) continue;   // personajes no bloquean el pathing
                return false;
            }
            return true;
        }

        private Vector2 Separation()
        {
            Vector2 push = Vector2.zero;
            foreach (var b in Active)
            {
                if (b == this || b == null) continue;
                Vector2 d = _rb.position - (Vector2)b.transform.position;
                float m = d.magnitude;
                if (m > 0.001f && m < 0.95f) push += d / m * (1f - m / 0.95f);
            }
            return push;
        }

        private void SetTelegraph(float k)
        {
            if (weapon == null || weapon.bladeRenderer == null) return;
            if (k <= 0f) { weapon.bladeRenderer.color = _weaponBaseColor; return; }
            bool blink = Mathf.Repeat(Time.time * 18f, 1f) > 0.5f;
            weapon.bladeRenderer.color = Color.Lerp(_weaponBaseColor, blink ? new Color(1f, 0.25f, 0.2f) : Color.white, k);
        }

        private static Vector2 Rotate(Vector2 v, float deg)
        {
            float r = deg * Mathf.Deg2Rad;
            float c = Mathf.Cos(r), s = Mathf.Sin(r);
            return new Vector2(v.x * c - v.y * s, v.x * s + v.y * c);
        }
    }
}
