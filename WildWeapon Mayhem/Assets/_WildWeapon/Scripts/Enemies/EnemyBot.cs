using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// IA de bot de supervivencia: persigue al enemigo mas conveniente, esquiva
    /// obstaculos, telegrafia (windup) y golpea con su arma unica.
    ///
    /// La decision esta en <see cref="BotCombatBrain"/> (compartida con la IA de la
    /// sala PVP): el bot elige objetivo, mantiene la distancia correcta, castiga el
    /// recovery del rival, esquiva los telegrafos y usa sus habilidades (Q/E/R).
    /// Acá solo esta la locomocion: steering, salto a los decks y separacion.
    /// </summary>
    [RequireComponent(typeof(Rigidbody2D))]
    public class EnemyBot : MonoBehaviour
    {
        private enum State { Chase, Windup, Recover, Cast, Dodge }

        public BotDef def;
        public Transform aimPivot;
        public MeleeWeapon weapon;
        public CharacterVisual visual;
        [Tooltip("Fisica vertical: gravedad, salto y doble salto para subir a los decks")]
        public HeightBody height;
        [Tooltip("Habilidades del bot (Q/E/R). Si es null el bot pelea solo con el arma.")]
        public AbilityCaster abilities;

        public PlayerHealth Health { get; private set; }
        public float HpScale { get; set; } = 1f;

        /// <summary>El bot esta por golpear (telegrafo visible: el rival lo puede leer).</summary>
        public bool IsTelegraphing => _state == State.Windup;
        /// <summary>El bot esta en la pausa posterior al golpe: se puede castigar.</summary>
        public bool IsRecovering => _state == State.Recover;

        private static readonly List<EnemyBot> Active = new List<EnemyBot>();

        private Rigidbody2D _rb;
        private BotSteering _steer;
        private readonly BotCombatBrain _brain = new BotCombatBrain();
        private State _state;
        private float _timer;
        private Vector2 _aim = Vector2.right;
        private Vector2 _knockback;
        private float _strafeSign = 1f;
        private float _jumpCooldown;
        private float _stuckTimer;
        private float _unstickTimer;
        private float _dodgeCooldown;
        private float _castLock;
        private Color _weaponBaseColor = Color.white;

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            Health = GetComponent<PlayerHealth>();
            if (height == null) height = GetComponent<HeightBody>();
            if (abilities == null) abilities = GetComponent<AbilityCaster>();
            if (weapon != null && weapon.bladeRenderer != null) _weaponBaseColor = weapon.bladeRenderer.color;
            _strafeSign = Random.value < 0.5f ? -1f : 1f;
            _steer = new BotSteering(_rb) { StrafeSign = _strafeSign };
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

            // Perfil de la IA: cada tipo de bot pelea distinto (elBruto se come la
            // adrenalina, la Sierra orbita y castiga).
            if (def != null)
            {
                _brain.profile.aggression = def.aggression;
                _brain.profile.skill = def.skill;
                _brain.profile.preferredGap = def.preferredGap;
                _brain.profile.dodgeChance = def.dodgeChance;
                _brain.profile.abilityUse = def.abilityUse;
                _brain.profile.reaction = def.reaction;
            }
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
            _knockback += new Vector2(dir.x, 0f) * amount;
            if (height != null && Mathf.Abs(dir.y) > 0.05f)
                height.AddVerticalImpulse(dir.y * amount * 0.8f);
        }

        /// <summary>Stun por habilidad (ej. Corte Circular de la Katana).</summary>
        public void Stun(float seconds)
        {
            _stunTimer = Mathf.Max(_stunTimer, seconds);
            SetTelegraph(0f);
            _state = State.Chase;
            _timer = 0f;
            _brain.Reset();
        }

        [HideInInspector] public float _stunTimer;

        void Update()
        {
            if (aimPivot != null)
                aimPivot.rotation = Quaternion.Euler(0f, 0f, Mathf.Atan2(_aim.y, _aim.x) * Mathf.Rad2Deg);
            if (visual != null)
            {
                visual.Face(_aim);
                visual.SetSpeed(Mathf.Abs(_rb.linearVelocity.x));
            }
        }

        void FixedUpdate()
        {
            float dt = Time.fixedDeltaTime;
            if (Health != null && Health.IsDead) return;

            if (_stunTimer > 0f)
            {
                _stunTimer -= dt;
                if (height != null) height.SetHorizontalVelocity(_knockback.x);
                else _rb.linearVelocity = new Vector2(_knockback.x, _rb.linearVelocity.y);
                _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-10f * dt));
                if (visual != null) visual.SetSpeed(0f);
                return;
            }

            // ---- El cerebro decide (el arma y las habilidades mandan sobre el) ----
            float speed = def != null ? def.moveSpeed : 2f;
            if (Health != null) speed *= Health.SlowFactor;
            float weaponRange = weapon != null ? weapon.Range : 1f;
            bool weaponReady = weapon != null && weapon.CanAttackNow;
            _brain.Think(dt, Health, _rb.position, speed, weaponRange, weaponReady, abilities, false);

            var target = _brain.Target;
            Vector2 move = Vector2.zero;
            _jumpCooldown -= dt;
            if (_jumpCooldown < 0f) _jumpCooldown = 0f;
            if (_unstickTimer > 0f) _unstickTimer -= dt;
            if (_dodgeCooldown > 0f) _dodgeCooldown -= dt;
            if (_castLock > 0f) _castLock -= dt;

            if (target != null)
            {
                Vector2 to = (Vector2)target.transform.position - _rb.position;
                float dist = to.magnitude;
                Vector2 dir = dist > 0.001f ? to / dist : _aim;

                // El objetivo esta en un deck: saltar para subir a pelearle arriba.
                TryClimb(target, dist);

                switch (_state)
                {
                    case State.Chase:
                        // Apunta a donde va a estar el rival, no a donde esta.
                        Vector2 aimPoint = _brain.AimPoint;
                        _aim = Vector2.Lerp(_aim, (Vector2)(aimPoint - _rb.position).normalized, 1f - Mathf.Exp(-12f * dt)).normalized;

                        // ---- Lanzar habilidad ----
                        if (_brain.Plan == BotCombatBrain.Intent.Cast && _brain.AbilitySlot >= 0 && _castLock <= 0f)
                        {
                            TryCastAbility(dir);
                            break;
                        }

                        // ---- Golpear ----
                        if (_brain.WantAttack && weapon != null && weapon.CanAttackNow)
                        {
                            _state = State.Windup;
                            _timer = def != null ? def.windup : 0.3f;
                            SetTelegraph(0f);
                        }
                        else
                        {
                            // El cerebro dice hacia donde ir; el steering lo esquiva.
                            Vector2 desired = _brain.DesiredMove(_rb.position);
                            if (_brain.Plan == BotCombatBrain.Intent.Retreat)
                            {
                                // Romper el contacto: se aleja rapido.
                                desired = -dir;
                            }
                            if (desired.sqrMagnitude > 0.0001f) move = Steer(desired);
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

                    case State.Cast:
                        // El caster corre solo (windup -> active -> recovery).
                        if (abilities == null || !abilities.IsCasting)
                        {
                            _state = State.Chase;
                            _castLock = 0.12f;
                        }
                        break;

                    case State.Dodge:
                        _timer -= dt;
                        move = -dir;
                        if (_timer <= 0f) _state = State.Chase;
                        break;
                }

                // ---- Esquiva: el cerebro vio un telegraph y el bot se aparta ----
                if (_state == State.Chase && _brain.Plan == BotCombatBrain.Intent.Dodge && _dodgeCooldown <= 0f)
                {
                    _state = State.Dodge;
                    _timer = 0.22f;
                    _dodgeCooldown = 0.9f;
                }
            }
            else
            {
                _state = State.Chase;
                SetTelegraph(0f);
            }

            // El casteo frena al bot (mismo feeling que para el jugador).
            if (abilities != null && abilities.IsCasting) move *= 0.4f;

            move += Separation() * 0.6f;
            if (move.sqrMagnitude > 1f) move.Normalize();

            // Si el bot quiere moverse pero no se mueve, esta trabado contra algo:
            // se despega un momento en otra direccion (antes se quedaba empujando
            // contra el obstaculo para siempre).
            if (move.sqrMagnitude > 0.15f && _rb.linearVelocity.sqrMagnitude < 0.06f) _stuckTimer += dt;
            else _stuckTimer = 0f;
            if (_stuckTimer > 0.7f)
            {
                _stuckTimer = 0f;
                _unstickTimer = 0.45f;
                _strafeSign = -_strafeSign;
                if (_steer != null) _steer.StrafeSign = _strafeSign;
            }
            if (_unstickTimer > 0f && move.sqrMagnitude > 0.01f)
                move = -move;   // retrocede para despegarse y volver a intentarlo

            float vx = move.x * speed + _knockback.x;
            if (height != null) height.SetHorizontalVelocity(vx);
            else _rb.linearVelocity = new Vector2(vx, _rb.linearVelocity.y);
            _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-10f * dt));
        }

        /// <summary>Lanza la habilidad que eligio el cerebro (Q/E/R).</summary>
        private void TryCastAbility(Vector2 dir)
        {
            if (abilities == null) return;
            int slot = _brain.AbilitySlot;
            var def = abilities.GetAbility(slot);
            if (def == null) return;

            abilities.aimOverride = dir;
            switch (slot)
            {
                case 0: abilities.QueueQ(); break;
                case 1: abilities.QueueE(); break;
                case 2: abilities.QueueR(); break;
                default: return;
            }
            _state = State.Cast;
            _timer = 0f;
        }

        /// <summary>
        /// Sube al deck donde esta el objetivo. Desde el piso alcanza con un salto; si
        /// todavia le falta altura usa el doble salto (en el apice, que es cuando mas
        /// alto lleva).
        /// </summary>
        private void TryClimb(PlayerHealth target, float dist)
        {
            if (height == null || _jumpCooldown > 0f) return;
            if (dist > 4.5f) return;   // lejos todavia: primero se acerca por abajo
            float targetY = PlayerHealth.HeightOf(target);
            float dy = targetY - transform.position.y;
            if (dy <= 0.7f) return;    // el objetivo no esta arriba

            bool grounded = height.Grounded;
            if (!grounded && height.AirJumpsLeft <= 0) return;   // en el aire sin saltos: no puede subir

            // Altura maxima a la que llega desde donde esta.
            float maxY = grounded ? height.ReachableHeight : transform.position.y + height.AirJumpHeight;
            if (targetY > maxY + 0.1f) return;                   // fuera de alcance: no gasta el salto

            // En el aire solo gasta el doble salto cuando ya casi termino de subir
            // (en el apice), asi no lo desperdicia.
            if (!grounded && height.VerticalSpeed > 0.5f) return;

            height.QueueJump();
            _jumpCooldown = grounded ? 0.55f : 0.3f;
        }

        private Vector2 Steer(Vector2 desired)
        {
            if (_steer == null) return desired;
            _steer.StrafeSign = _strafeSign;
            float look = _steer.LookAhead(Health != null ? Health.bodyRadius : 0.4f);
            Vector2 result = _steer.Steer(desired, look);
            _strafeSign = _steer.StrafeSign;
            return result;
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
    }
}
