using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// IA de un bot de sala PVP. Corre SOLO en la maquina del anfitrion: los demas
    /// clientes ven al bot como un remoto mas (PvpRemoteAvatar) y le interpolan el
    /// estado que el anfitrion manda a 15 Hz. Es una version compacta de
    /// <see cref="EnemyBot"/> adaptada a <see cref="PlayerController"/>: persigue al
    /// enemigo vivo mas conveniente, amaga (windup) y golpea con el arma activa; el
    /// dano, la muerte y los VFX los resuelve el pawn local como cualquier otro portador.
    ///
    /// La parte inteligente (objetivo, spacing, esquiva, castigo y habilidades) esta
    /// en <see cref="BotCombatBrain"/>, compartida con la IA de supervivencia. Aca se
    /// resuelve la locomocion propia de la sala:
    /// - horizontal: esquiva obstaculos, no pisa los cadaveres que quedan tirados y
    ///   no swings a un rival que esta detras de un muro;
    /// - vertical: sube y baja de los decks para llegar a la altura del rival (de
    ///   deck en deck cuando el rival esta muy arriba), se baja del deck cuando el
    ///   rival esta abajo y se sube a uno para pasar por encima de un cadaver.
    /// </summary>
    [RequireComponent(typeof(Rigidbody2D))]
    public class PvpBotBrain : MonoBehaviour
    {
        private enum State { Chase, Windup, Recover, Cast }

        /// <summary>Como se sube al deck destino: desde abajo o desde el borde de otro deck.</summary>
        private enum HopMode { None, UnderDeck, FromEdge }

        [Tooltip("Los bots no corren igual que una persona.")]
        public float moveScale = 0.78f;
        public float windup = 0.34f;
        public float recover = 0.30f;

        [Header("Dash")]
        [Tooltip("Duracion del dash del bot (s).")]
        public float dashDuration = 0.17f;
        [Tooltip("Velocidad del dash del bot.")]
        public float dashSpeed = 6.4f;
        [Tooltip("Espera entre dos dashes del bot (s).")]
        public float dashCooldown = 1.7f;

        [Header("Cuerpos muertos")]
        [Tooltip("Radio en el que el bot percibe los cadaveres que quedan tirados.")]
        public float corpseSense = 3.2f;
        [Tooltip("Medio ancho del pasillo que tapa un cadaver (a cada lado del centro).")]
        public float corpseWidth = 0.7f;
        [Tooltip("Altura maxima (desde el pie del bot) a la que un cadaver todavia tapa el paso.")]
        public float corpseBlockHeight = 2.1f;
        [Tooltip("Distancia a la que el bot se decide a saltar el cadaver por encima.")]
        public float corpseJumpRange = 2.3f;
        [Tooltip("Espera entre dos saltos por encima de un cadaver.")]
        public float corpseJumpWait = 0.75f;
        [Tooltip("Impulso lateral de la esquiva cuando el cadaver no se puede saltar.")]
        public float corpseAvoid = 1.5f;

        [Header("Plataformas")]
        [Tooltip("Margen de seguridad para que un deck cuente como alcanzable de un salto.")]
        public float deckStepMargin = 0.35f;
        [Tooltip("Distancia horizontal maxima para buscar un deck al que subirse.")]
        public float deckSearchRange = 9f;

        [Header("IA")]
        [Tooltip("Cuanto empuja hacia adelante (0.7 timido - 1.4 agresivo).")]
        public float aggression = 1f;
        [Tooltip("Pericia general (0-1): reaccion, punteria, esquiva y castigo.")]
        public float skill = 0.8f;
        [Tooltip("Distancia que quiere mantener, en multiplos del alcance del arma.")]
        public float preferredGap = 0.95f;
        [Tooltip("Probabilidad de esquivar un telegraph enemigo.")]
        public float dodgeChance = 0.8f;
        [Tooltip("Frecuencia con la que usa las habilidades (0-1).")]
        public float abilityUse = 0.9f;

        public int Seat { get; private set; }

        private static readonly List<PvpBotBrain> Active = new List<PvpBotBrain>();
        private static readonly RaycastHit2D[] LosHits = new RaycastHit2D[6];

        private PlayerController _pc;
        private Rigidbody2D _rb;
        private PlayerHealth _health;
        private HeightBody _height;
        private BotSteering _steer;
        private readonly BotCombatBrain _brain = new BotCombatBrain();
        private Vector2 _aim = Vector2.right;
        private Vector2 _knockback;
        private State _state;
        private float _timer;
        private float _strafeSign = 1f;
        private float _jumpCooldown;
        private float _stuckTimer;
        private float _unstickTimer;
        private float _corpseJumpTimer;
        private float _dashTimer;
        private float _dashCooldownTimer;
        private Vector2 _dashDir = Vector2.right;
        private float _castLock;
        /// <summary>Cadaver que el bot esta salvando con un salto (lo ignora mientras tanto).</summary>
        private PlayerHealth _clearing;
        /// <summary>Deck al que esta yendo el bot (para subir de nivel).</summary>
        private PlatformSurface _deck;
        /// <summary>Como se sube al deck destino.</summary>
        private HopMode _hop = HopMode.None;
        /// <summary>El bot sigue el punto de ruta (deck) en vez de ir directo al rival.</summary>
        private bool _useNav;
        /// <summary>Punto de destino de la ruta (deck al que subir o borde para bajar).</summary>
        private Vector2 _navPoint;
        /// <summary>Intentos de subir al deck actual (si falla, lo descarta y busca otro).</summary>
        private int _deckTries;
        /// <summary>Deck que no le funciono (lo evita un rato para no insistir).</summary>
        private PlatformSurface _deckAvoid;
        private float _deckAvoidTimer;

        /// <summary>Y de los pies del bot (el centro del rigidbody esta a media altura).</summary>
        private float FeetY => _rb.position.y - (_health != null ? _health.bodyRadius : 0.4f);

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            _pc = GetComponent<PlayerController>();
            _health = GetComponent<PlayerHealth>();
            _height = GetComponent<HeightBody>();
            _strafeSign = Random.value < 0.5f ? -1f : 1f;
            _steer = new BotSteering(_rb) { StrafeSign = _strafeSign };

            _brain.profile.aggression = aggression;
            _brain.profile.skill = skill;
            _brain.profile.preferredGap = preferredGap;
            _brain.profile.dodgeChance = dodgeChance;
            _brain.profile.abilityUse = abilityUse;
            _brain.profile.reaction = 0.14f;
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
            _stuckTimer = 0f;
            _unstickTimer = 0f;
            _jumpCooldown = 0f;
            _corpseJumpTimer = 0f;
            _clearing = null;
            _deck = null;
            _hop = HopMode.None;
            _useNav = false;
            _deckTries = 0;
            _deckAvoid = null;
            _deckAvoidTimer = 0f;
            _dashTimer = 0f;
            _dashCooldownTimer = 0f;
            _castLock = 0f;
            _brain.Reset();
            _aim = look.sqrMagnitude > 0.0001f ? look.normalized : Vector2.right;
            if (Random.value < 0.5f) _strafeSign = -_strafeSign;
        }

        void Update()
        {
            if (_pc == null) return;
            _pc.SetAimFromNetwork(_aim);
            _pc.networkSpeed = _rb != null ? Mathf.Abs(_rb.linearVelocity.x) : 0f;
        }

        void FixedUpdate()
        {
            if (_pc == null || _rb == null || _health == null) return;
            float dt = Time.fixedDeltaTime;

            if (_health.IsDead)
            {
                StopHorizontal();
                return;
            }

            // Fuera del combate (intro, fin de ronda) el bot se queda quieto.
            // OJO: no se consulta CanAct. Ese flag lo reinicia DuelManager solo para
            // los dos pawns de la escena, y los bots clonados quedaban en false para
            // siempre (por eso solo reaccionaba uno). La fase del duelo es la
            // autoridad real de "se puede pelear".
            bool canAct = DuelManager.Instance == null || DuelManager.Instance.CurrentPhase == DuelManager.Phase.Fight;
            if (!canAct)
            {
                _state = State.Chase;
                _deck = null;
                _clearing = null;
                StopHorizontal();
                return;
            }

            var weapon = ActiveWeapon();
            float speed = DuelRules.MoveSpeed * moveScale * _health.SlowFactor;
            _jumpCooldown -= dt;
            if (_jumpCooldown < 0f) _jumpCooldown = 0f;
            if (_unstickTimer > 0f) _unstickTimer -= dt;
            if (_corpseJumpTimer > 0f) _corpseJumpTimer -= dt;
            if (_dashCooldownTimer > 0f) _dashCooldownTimer -= dt;
            if (_dashTimer > 0f) _dashTimer -= dt;
            if (_castLock > 0f) _castLock -= dt;
            if (_deckAvoidTimer > 0f)
            {
                _deckAvoidTimer -= dt;
                if (_deckAvoidTimer <= 0f) _deckAvoid = null;
            }
            // El cadaver que se esta salvando se olvida cuando el bot vuelve al piso.
            if (_clearing != null && _corpseJumpTimer <= 0f && _height != null && _height.Grounded) _clearing = null;

            // ---- El cerebro decide (objetivo, spacing, esquiva, habilidades) ----
            float weaponRange = weapon != null ? weapon.Range : 1f;
            bool weaponReady = weapon != null && weapon.CanAttackNow;
            _brain.Think(dt, _health, _rb.position, speed, weaponRange, weaponReady,
                         _pc != null ? _pc.Abilities : null, _dashCooldownTimer <= 0f && _dashTimer <= 0f);

            var target = _brain.Target;
            Vector2 move = Vector2.zero;

            if (target != null)
            {
                Vector2 to = (Vector2)target.transform.position - _rb.position;
                float dist = to.magnitude;
                Vector2 dir = dist > 0.001f ? to / dist : _aim;
                // El desplazamiento es horizontal: la altura se gana saltando.
                Vector2 flat = Mathf.Abs(to.x) > 0.001f ? new Vector2(to.x, 0f).normalized : new Vector2(1f, 0f);

                // ---- Donde tiene que ir el bot (rival o deck) ----
                PlanRoute(target, dir, flat);

                // ---- Saltos ----
                TryClimb(target, dist);      // salto directo a la altura del rival
                TryDeckClimb();               // salto al deck de escalon
                TryHopOverTallCorpse();       // deck por encima de un cadaver demasiado alto

                switch (_state)
                {
                    case State.Chase:
                        // Apunta a donde va a estar el rival (intercepcion), no a donde esta.
                        Vector2 aimPoint = _brain.AimPoint;
                        Vector2 aimDir = (Vector2)(aimPoint - _rb.position);
                        if (aimDir.sqrMagnitude > 0.0001f)
                            _aim = Vector2.Lerp(_aim, aimDir.normalized, 1f - Mathf.Exp(-12f * dt)).normalized;

                        // ---- Lanzar habilidad ----
                        if (_brain.Plan == BotCombatBrain.Intent.Cast && _brain.AbilitySlot >= 0 && _castLock <= 0f)
                        {
                            TryCastAbility(dir);
                            break;
                        }

                        // ---- Golpear ----
                        if (_brain.WantAttack && weapon != null && weapon.CanAttackNow && HasLineOfSight(target))
                        {
                            _state = State.Windup;
                            _timer = windup;
                        }
                        else
                        {
                            Vector2 desired;
                            if (_useNav)
                            {
                                // Va al deck de escalon o al borde para bajar: el
                                // horizontal manda, la altura la gana con el salto.
                                float dx = _navPoint.x - _rb.position.x;
                                desired = Mathf.Abs(dx) > 0.05f ? new Vector2(Mathf.Sign(dx), 0f) : flat;
                            }
                            else
                            {
                                desired = _brain.DesiredMove(_rb.position);
                                if (_brain.Plan == BotCombatBrain.Intent.Retreat) desired = -flat;
                            }
                            if (desired.sqrMagnitude > 0.0001f) move = Steer(desired);

                            // ---- Dash: para cerrar distancia o romper el contacto ----
                            if (_brain.WantDash && _dashCooldownTimer <= 0f && _dashTimer <= 0f)
                            {
                                Vector2 dashDir = _brain.DashDir.sqrMagnitude > 0.0001f ? _brain.DashDir : flat;
                                StartDash(dashDir);
                            }
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
                        move = -flat * 0.25f;
                        if (_timer <= 0f)
                        {
                            _state = State.Chase;
                            if (Random.value < 0.3f) _strafeSign = -_strafeSign;
                        }
                        break;

                    case State.Cast:
                        // El caster corre solo (windup -> active -> recovery).
                        var caster = _pc != null ? _pc.Abilities : null;
                        if (caster == null || !caster.IsCasting)
                        {
                            _state = State.Chase;
                            _castLock = 0.12f;
                        }
                        break;
                }
            }
            else
            {
                _state = State.Chase;
                _deck = null;
            }

            // ---- Cadaveres: el bot no los pisa ----
            if (move.sqrMagnitude > 0.01f)
            {
                Vector2 moveDir = move.normalized;
                Vector2 avoid;
                PlayerHealth corpse = CorpseBlocking(moveDir, out avoid);
                if (corpse != null)
                {
                    // 1) Lo salta por encima (lo natural en una vista lateral).
                    if (!TryJumpOver(corpse) && avoid.sqrMagnitude > 0.0001f)
                    {
                        // 2) Si no se puede saltar, lo esquiva de lado.
                        move += avoid;
                    }
                }
            }

            move += Separation() * 0.6f;
            if (move.sqrMagnitude > 1f) move.Normalize();

            // Si el bot quiere moverse pero no se mueve, esta trabado contra algo:
            // se despega un momento en otra direccion.
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

            // El dash manda sobre la locomocion normal.
            if (_dashTimer > 0f) vx = _dashDir.x * dashSpeed;

            // El casteo frena al bot (mismo feeling que para el jugador).
            var abilityCaster = _pc != null ? _pc.Abilities : null;
            if (abilityCaster != null && abilityCaster.IsCasting) vx *= 0.4f;

            if (_height != null) _height.SetHorizontalVelocity(vx);
            else _rb.linearVelocity = new Vector2(vx, _rb.linearVelocity.y);
            _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-10f * dt));
        }

        // =================================================================
        // Habilidades y dash
        // =================================================================

        /// <summary>Lanza la habilidad que eligio el cerebro (Q/E/R).</summary>
        private void TryCastAbility(Vector2 dir)
        {
            var caster = _pc != null ? _pc.Abilities : null;
            if (caster == null) return;
            int slot = _brain.AbilitySlot;
            if (caster.GetAbility(slot) == null) return;

            caster.aimOverride = dir;
            switch (slot)
            {
                case 0: caster.QueueQ(); break;
                case 1: caster.QueueE(); break;
                case 2: caster.QueueR(); break;
                default: return;
            }
            _state = State.Cast;
            _timer = 0f;
        }

        /// <summary>Arranca el dash del bot (cierre de distancia o ruptura del contacto).</summary>
        private void StartDash(Vector2 dir)
        {
            float x = Mathf.Abs(dir.x) > 0.05f ? Mathf.Sign(dir.x) : 1f;
            _dashDir = new Vector2(x, 0f);
            _dashTimer = dashDuration;
            _dashCooldownTimer = dashCooldown;
            if (_pc != null) _pc.GrantIFrames(0.14f);   // i-frames del dash
        }

        // =================================================================
        // Navegacion vertical (decks)
        // =================================================================

        /// <summary>
        /// Decide a donde camina el bot: al rival, o a un deck cuando hay que
        /// cambiar de nivel. Deja el destino en <see cref="_navPoint"/>.
        /// </summary>
        private void PlanRoute(PlayerHealth target, Vector2 dir, Vector2 flat)
        {
            Vector2 enemy = (Vector2)target.transform.position;
            float myFeet = FeetY;
            float enemyFeet = enemy.y - target.bodyRadius;

            // 1) El rival esta claramente arriba: se busca un deck de escalon
            //    (de a uno, hasta llegar a su altura).
            if (enemyFeet > myFeet + 0.8f)
            {
                var step = FindStepDeck(enemyFeet, dir);
                if (step != null)
                {
                    if (step != _deck) { _deck = step; _deckTries = 0; }
                    _useNav = true;

                    var current = DeckUnderMe();
                    if (current != null && current != step && !OverlapsSpan(current, step))
                    {
                        // Esta parado sobre otro deck: camina hasta el borde y salta
                        // de ahi (el arco lo deja caer sobre el deck de destino).
                        float side = Mathf.Sign(step.center.x - current.center.x);
                        if (side == 0f) side = Mathf.Sign(dir.x);
                        _hop = HopMode.FromEdge;
                        _navPoint = new Vector2(current.center.x + side * (current.size.x * 0.5f + 0.15f), current.SurfaceY);
                    }
                    else
                    {
                        // Va por debajo del deck y lo atraviesa con el salto (es one-way).
                        _hop = HopMode.UnderDeck;
                        _navPoint = new Vector2(step.center.x, step.SurfaceY);
                    }
                    return;
                }

                // No hay deck alcanzable desde aca: si esta parado sobre uno, se baja
                // a buscar otra ruta.
                var under = DeckUnderMe();
                if (under != null)
                {
                    _deck = null;
                    _hop = HopMode.None;
                    _useNav = true;
                    _navPoint = DeckExit(under, flat);
                    return;
                }

                _deck = null;
                _hop = HopMode.None;
                _useNav = false;
                _navPoint = enemy;
                return;
            }

            // 2) El rival esta claramente abajo: si estoy parado sobre un deck,
            //    me acerco al borde para bajar.
            if (enemyFeet < myFeet - 1.1f)
            {
                var under = DeckUnderMe();
                if (under != null)
                {
                    _deck = null;
                    _hop = HopMode.None;
                    _useNav = true;
                    _navPoint = DeckExit(under, flat);
                    return;
                }
                _deck = null;
                _hop = HopMode.None;
                _useNav = false;
                _navPoint = enemy;
                return;
            }

            _deck = null;
            _hop = HopMode.None;
            _useNav = false;
            _navPoint = enemy;
        }

        /// <summary>
        /// Deck de escalon: el mas bajo que el bot alcanza de un salto y que lo deja
        /// mas cerca de la altura del rival (y hacia el mismo lado).
        /// </summary>
        private PlatformSurface FindStepDeck(float enemyFeet, Vector2 dir)
        {
            if (_height == null) return null;
            PlatformSurface best = null;
            float bestTop = float.MaxValue;
            float bestDist = float.MaxValue;
            float maxTop = FeetY + _height.JumpHeight - deckStepMargin;
            float myX = _rb.position.x;
            float side = Mathf.Sign(dir.x);
            var current = DeckUnderMe();

            foreach (var s in PlatformSurface.All)
            {
                if (s == null) continue;
                if (s == _deckAvoid) continue;             // este deck no le funciono
                float top = s.SurfaceY;
                if (top <= FeetY + 0.3f) continue;      // tiene que estar arriba
                if (top > maxTop) continue;             // no llega de un salto
                if (top > enemyFeet + 0.35f) continue;   // no hace falta subir tanto todavia
                if (!CanReachDeck(s, current)) continue; // no hay forma practica de subirlo
                float dx = Mathf.Abs(myX - s.center.x);
                if (dx > deckSearchRange) continue;      // lejos demais
                // el deck tiene que quedar hacia el rival, no al reves
                if (side != 0f && Mathf.Sign(s.center.x - myX) != side) continue;

                if (top < bestTop - 0.01f) { best = s; bestTop = top; bestDist = dx; }
                else if (Mathf.Abs(top - bestTop) < 0.01f && dx < bestDist) { best = s; bestDist = dx; }
            }
            return best;
        }

        /// <summary>
        /// true si el bot tiene una forma practica de subirse a ese deck: desde el
        /// piso (se pone debajo y salta) o desde otro deck (salta desde el borde).
        /// </summary>
        private bool CanReachDeck(PlatformSurface deck, PlatformSurface current)
        {
            if (_height == null) return false;
            if (deck.SurfaceY > FeetY + _height.JumpHeight - deckStepMargin) return false;
            if (current == null || current == deck) return true;    // desde el piso
            if (OverlapsSpan(current, deck)) return true;           // el destino esta arriba del todo

            // Desde otro deck: tiene que saltar desde el borde y caer sobre el destino.
            float side = Mathf.Sign(deck.center.x - current.center.x);
            if (side == 0f) return false;
            float edgeX = current.center.x + side * (current.size.x * 0.5f + 0.15f);
            float gap = (deck.center.x - edgeX) * side;
            if (gap < 0f || gap > 2.6f) return false;               // muy lejos para el salto
            float apexX = edgeX + side * 1.55f;                      // donde esta el apice del salto
            return Mathf.Abs(apexX - deck.center.x) <= deck.size.x * 0.5f + 0.45f;
        }

        /// <summary>true si las huellas de los dos decks se superponen en X.</summary>
        private static bool OverlapsSpan(PlatformSurface a, PlatformSurface b)
            => Mathf.Abs(a.center.x - b.center.x) < (a.size.x + b.size.x) * 0.5f - 0.15f;

        /// <summary>Salta al deck elegido (el que lo deja mas cerca de la altura del rival).</summary>
        private void TryDeckClimb()
        {
            if (_deck == null || _height == null || _jumpCooldown > 0f) return;
            float top = _deck.SurfaceY;
            if (FeetY >= top - 0.15f) { _deck = null; _hop = HopMode.None; _deckTries = 0; return; }  // ya esta arriba
            if (top > FeetY + _height.JumpHeight - deckStepMargin) return;         // fuera de alcance
            if (!_height.Grounded) return;

            bool ok;
            if (_hop == HopMode.FromEdge)
            {
                // Salta desde el borde de su deck: el arco lo lleva al de destino.
                ok = Mathf.Abs(_rb.position.x - _navPoint.x) < 0.55f;
            }
            else
            {
                // Tiene que estar por debajo del deck (es one-way: se atraviesa desde abajo).
                ok = Mathf.Abs(_rb.position.x - _deck.center.x) <= _deck.size.x * 0.5f;
            }
            if (!ok) return;

            _height.QueueJump();
            _jumpCooldown = 0.5f;
            _deckTries++;
            if (_deckTries >= 3)
            {
                // No insiste con el mismo deck: busca otro o va directo al rival.
                _deckAvoid = _deck;
                _deckAvoidTimer = 2.5f;
                _deck = null;
                _hop = HopMode.None;
            }
        }

        /// <summary>Deck sobre el que estoy parado (para poder bajarme de el).</summary>
        private PlatformSurface DeckUnderMe()
        {
            PlatformSurface best = null;
            float bestTop = float.MinValue;
            foreach (var s in PlatformSurface.All)
            {
                if (s == null) continue;
                if (!s.OverlapsX(_rb.position.x, 0.1f)) continue;
                float top = s.SurfaceY;
                if (top > FeetY + 0.25f) continue;   // el deck esta por arriba: no estoy parado en el
                if (top > bestTop) { bestTop = top; best = s; }
            }
            return best;
        }

        /// <summary>Punto del borde por el que el bot se baja del deck (hacia el rival).</summary>
        private Vector2 DeckExit(PlatformSurface deck, Vector2 flat)
        {
            float side = Mathf.Sign(flat.x);
            if (side == 0f) side = _strafeSign;
            float edge = deck.center.x + side * (deck.size.x * 0.5f + 0.55f);
            return new Vector2(edge, deck.SurfaceY);
        }

        /// <summary>
        /// Si un cadaver tapa el paso y es demasiado alto para saltarlo, el bot
        /// busca un deck por encima para pasar por encima.
        /// </summary>
        private void TryHopOverTallCorpse()
        {
            if (_deck != null || _height == null || _jumpCooldown > 0f) return;
            if (!_height.Grounded) return;

            PlayerHealth corpse = null;
            Vector2 flat = new Vector2(Mathf.Abs(_aim.x) > 0.01f ? Mathf.Sign(_aim.x) : 1f, 0f);
            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h == _health || !h.IsDead) continue;
                if (h == _clearing) continue;
                Vector2 d = (Vector2)h.transform.position - _rb.position;
                if (d.magnitude > corpseSense) continue;
                float along = Vector2.Dot(d, flat);
                if (along < 0f || along > corpseSense) continue;
                if (Mathf.Abs(Vector2.Dot(d, Vector2.Perpendicular(flat))) > corpseWidth) continue;
                corpse = h;
                break;
            }
            if (corpse == null) return;

            float corpseTop = CorpseTop(corpse);
            if (corpseTop - FeetY <= corpseBlockHeight) return;   // ese si se puede saltar

            // Un deck que quede por encima del cadaver y al alcance del salto.
            PlatformSurface deck = null;
            float bestTop = float.MaxValue;
            foreach (var s in PlatformSurface.All)
            {
                if (s == null) continue;
                float top = s.SurfaceY;
                if (top < corpseTop + 0.15f) continue;                     // tiene que quedar arriba
                if (top > FeetY + _height.JumpHeight - deckStepMargin) continue;
                if (Mathf.Abs(s.center.x - corpse.transform.position.x) > 2.5f) continue;
                if (top < bestTop) { bestTop = top; deck = s; }
            }
            if (deck == null) return;

            _deck = deck;
            _deckTries = 0;
            _hop = HopMode.UnderDeck;
            _useNav = true;
            _navPoint = new Vector2(deck.center.x, deck.SurfaceY);
            TryDeckClimb();
        }

        // =================================================================
        // Cuerpos muertos
        // =================================================================

        /// <summary>Altura aproximada del cadaver (visual) respecto del mundo.</summary>
        private static float CorpseTop(PlayerHealth corpse)
            => corpse != null ? corpse.transform.position.y + 1f : 0f;

        /// <summary>
        /// Busca un cadaver que tape el paso en la direccion dada y dice hacia que
        /// lado conviene esquivarlo (el lado con mas espacio libre).
        /// </summary>
        private PlayerHealth CorpseBlocking(Vector2 dir, out Vector2 avoid)
        {
            avoid = Vector2.zero;
            PlayerHealth best = null;
            float bestAlong = float.MaxValue;
            float bestLat = 0f;

            Vector2 perp = Vector2.Perpendicular(dir);
            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h == _health || !h.IsDead) continue;
                if (h == _clearing) continue;                     // ya estamos saltando ese
                Vector2 d = (Vector2)h.transform.position - _rb.position;
                if (d.magnitude > corpseSense) continue;         // lejos demais
                float along = Vector2.Dot(d, dir);
                if (along < -0.4f) continue;                      // esta atras
                float lat = Vector2.Dot(d, perp);
                if (Mathf.Abs(lat) > corpseWidth) continue;       // no esta en el pasillo
                float dy = h.transform.position.y - _rb.position.y;
                if (dy > corpseBlockHeight || dy < -1.6f) continue;   // no tapa el paso
                if (along < bestAlong) { bestAlong = along; best = h; bestLat = lat; }
            }

            if (best == null) return null;

            // Se esquiva hacia el lado contrario al cadaver; si ese lado esta tapado
            // (un muro) se prueba el otro.
            Vector2 side = perp * (bestLat >= 0f ? -1f : 1f);
            float look = _steer != null ? _steer.LookAhead(_health.bodyRadius) : 0.5f;
            if (_steer != null && !_steer.IsFree(side, look))
            {
                Vector2 other = -side;
                if (_steer.IsFree(other, look)) side = other;
            }
            avoid = side * corpseAvoid;
            return best;
        }

        /// <summary>Salta por encima del cadaver que le tapa el paso.</summary>
        private bool TryJumpOver(PlayerHealth corpse)
        {
            if (corpse == null || _height == null) return false;
            if (_state != State.Chase) return false;    // no interrumpe un ataque
            if (_corpseJumpTimer > 0f) return false;
            if (!_height.Grounded) return false;         // en el aire: mejor esquivar de lado

            Vector2 d = (Vector2)corpse.transform.position - _rb.position;
            if (d.magnitude > corpseJumpRange) return false;   // todavia lejos: se acerca primero
            if (CorpseTop(corpse) - FeetY > corpseBlockHeight) return false;   // alto demais

            _height.QueueJump();
            _jumpCooldown = 0.45f;
            _corpseJumpTimer = corpseJumpWait;
            _clearing = corpse;
            return true;
        }

        // =================================================================
        // Utilidades
        // =================================================================

        /// <summary>
        /// Sube al deck donde esta el objetivo. Desde el piso alcanza con un salto; si
        /// todavia le falta altura usa el doble salto (en el apice, que es cuando mas
        /// alto lleva).
        /// </summary>
        private void TryClimb(PlayerHealth target, float dist)
        {
            if (_height == null || _jumpCooldown > 0f) return;
            if (_deck != null) return;   // hay una ruta por decks: manda esa
            if (dist > 4.5f) return;   // lejos todavia: primero se acerca por abajo
            float targetY = PlayerHealth.HeightOf(target);
            float dy = targetY - transform.position.y;
            if (dy <= 0.7f) return;    // el objetivo no esta arriba

            bool grounded = _height.Grounded;
            if (!grounded && _height.AirJumpsLeft <= 0) return;   // en el aire sin saltos: no puede subir

            // Altura maxima a la que llega desde donde esta.
            float maxY = grounded ? _height.ReachableHeight : transform.position.y + _height.AirJumpHeight;
            if (targetY > maxY + 0.1f) return;                    // fuera de alcance: no gasta el salto

            // En el aire solo gasta el doble salto cuando ya casi termino de subir
            // (en el apice), asi no lo desperdicia.
            if (!grounded && _height.VerticalSpeed > 0.5f) return;

            _height.QueueJump();
            _jumpCooldown = grounded ? 0.55f : 0.3f;
        }

        /// <summary>
        /// true si no hay nada entre el bot y el rival: evita que el bot pegue
        /// contra un muro creyendo que le esta pegando al enemigo.
        /// </summary>
        private bool HasLineOfSight(PlayerHealth target)
        {
            if (target == null) return false;
            Vector2 from = _rb.position;
            Vector2 to = (Vector2)target.transform.position;
            Vector2 d = to - from;
            float dist = d.magnitude;
            if (dist < 0.05f) return true;

            // Unity 6: los casts con buffer requieren un ContactFilter2D explicito.
            // DefaultRaycastLayers + triggers replican el overload viejo de RaycastNonAlloc.
            var filter = new ContactFilter2D();
            filter.SetLayerMask(Physics2D.DefaultRaycastLayers);
            filter.useTriggers = true;

            int n = Physics2D.Raycast(from, d / dist, filter, LosHits, dist);
            for (int i = 0; i < n; i++)
            {
                var col = LosHits[i].collider;
                if (col == null || col.isTrigger) continue;
                if (col.GetComponent<PlayerHealth>() != null) continue;   // los cuerpos no tapan la vista
                return false;
            }
            return true;
        }

        private MeleeWeapon ActiveWeapon()
        {
            var loadout = _pc != null ? _pc.Loadout : null;
            if (loadout == null || loadout.weapons == null || loadout.weapons.Length == 0) return null;
            return loadout.weapons[Mathf.Clamp(loadout.ActiveIndex, 0, loadout.weapons.Length - 1)];
        }

        private Vector2 Steer(Vector2 desired)
        {
            if (_steer == null) return desired;
            _steer.StrafeSign = _strafeSign;
            float look = _steer.LookAhead(_health.bodyRadius);
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

        private void StopHorizontal()
        {
            if (_height != null) _height.SetHorizontalVelocity(0f);
            else _rb.linearVelocity = new Vector2(0f, _rb.linearVelocity.y);
        }
    }
}
