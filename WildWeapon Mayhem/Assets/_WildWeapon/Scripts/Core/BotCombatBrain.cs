using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Cerebro de combate de los bots: percepcion, eleccion de objetivo, spacing,
    /// esquiva de telegrafos, punteria sobre el rival y uso de habilidades.
    ///
    /// Es la parte "inteligente" compartida por las dos IA del juego:
    /// - supervivencia (<see cref="Enemies.EnemyBot"/>)
    /// - sala PVP (<see cref="Pvp.PvpBotBrain"/>)
    ///
    /// No es un MonoBehaviour: cada IA la usa como libreria y le sigue pasando su
    /// locomocion (velocidad, steering, decks, cadaveres), que es lo que cambia
    /// entre un bot de oleada y un bot de sala. El cerebro solo decide *que*
    /// quiere hacer; *como* se mueve lo resuelve la IA que lo usa.
    /// </summary>
    public class BotCombatBrain
    {
        /// <summary>Plan del bot en este momento.</summary>
        public enum Intent
        {
            Search,      // no hay objetivo
            Approach,    //.acercarse al objetivo
            Strafe,      // orbitar al objetivo manteniendo la distancia
            Attack,      // golpear
            Dodge,       // esquivar el telegraph del rival
            Retreat,     // romper el contacto
            Cast,        // lanzar una habilidad
        }

        [System.Serializable]
        public class Profile
        {
            [Tooltip("Cuanto empuja hacia adelante (0.7 timido - 1.4 agresivo).")]
            public float aggression = 1f;
            [Tooltip("Pericia general: reaccion, punteria y esquiva (0-1).")]
            public float skill = 0.75f;
            [Tooltip("Distancia que quiere mantener, en multiplos del alcance del arma.")]
            public float preferredGap = 0.95f;
            [Tooltip("Probabilidad de esquivar un telegraph enemigo.")]
            public float dodgeChance = 0.75f;
            [Tooltip("Frecuencia con la que usa las habilidades (0-1).")]
            public float abilityUse = 0.9f;
            [Tooltip("Segundos de reaccion antes de golpear (mas pericia = menos espera).")]
            public float reaction = 0.16f;
        }

        public Profile profile = new Profile();

        // ---- Salida (la lee la IA que usa el cerebro) ----
        public PlayerHealth Target { get; private set; }
        public float TargetDistance { get; private set; }
        public bool SameLevel { get; private set; }
        public bool InRange { get; private set; }
        /// <summary>El rival esta por golpear (telegrafo): hay que esquivar.</summary>
        public bool TargetTelegraphed { get; private set; }
        /// <summary>El rival esta en recovery: se puede castigar.</summary>
        public bool TargetVulnerable { get; private set; }
        public Intent Plan { get; private set; } = Intent.Search;
        /// <summary>El bot quiere pegar ahora mismo (el arma tiene que estar lista).</summary>
        public bool WantAttack { get; private set; }
        /// <summary>El bot pide un dash (la IA que lo usa decide si lo puede hacer).</summary>
        public bool WantDash { get; private set; }
        public Vector2 DashDir { get; private set; }
        /// <summary>Punto al que apunta (intercepcion: donde va a estar el rival).</summary>
        public Vector2 AimPoint { get; private set; }
        /// <summary>Slot de habilidad a lanzar (0=Q, 1=E, 2=R, -1 = ninguna).</summary>
        public int AbilitySlot { get; private set; } = -1;
        /// <summary>Distancia de combate que el bot quiere mantener.</summary>
        public float PreferredGap { get; private set; } = 1f;

        private const float ThinkInterval = 0.09f;   // cada cuanto se reevalua el plan
        private const float SwitchMargin = 14f;      // margen para no cambiar de objetivo cada frame

        private float _thinkTimer;
        private float _reactTimer;      // espera de reaccion antes de golpear
        private float _strafeTimer;
        private float _strafeSign = 1f;
        private float _planAge;

        // =================================================================
        // Entrada: la IA llama a Think() en cada FixedUpdate
        // =================================================================

        /// <summary>
        /// Actualiza el plan del bot. <paramref name="weaponRange"/> es el alcance del
        /// arma activa, <paramref name="weaponReady"/> si el arma puede swingear ya y
        /// <paramref name="caster"/> el AbilityCaster del bot (puede ser null).
        /// </summary>
        public void Think(float dt, PlayerHealth self, Vector2 pos, float moveSpeed,
                          float weaponRange, bool weaponReady, AbilityCaster caster,
                          bool dashReady)
        {
            _thinkTimer -= dt;
            _planAge += dt;

            bool reevaluate = _thinkTimer <= 0f;
            if (reevaluate) _thinkTimer = ThinkInterval;

            UpdateTarget(self, pos);

            if (Target == null)
            {
                Plan = Intent.Search;
                WantAttack = false;
                WantDash = false;
                AbilitySlot = -1;
                AimPoint = pos;
                return;
            }

            Vector2 to = (Vector2)Target.transform.position - pos;
            TargetDistance = to.magnitude;
            Vector2 dir = TargetDistance > 0.001f ? to / TargetDistance : Vector2.right;
            SameLevel = PlayerHealth.SameLevel(self, Target);
            InRange = TargetDistance <= weaponRange + Target.bodyRadius * 0.9f;
            TargetTelegraphed = IsTelegraphing(Target);
            TargetVulnerable = IsVulnerable(Target);
            PreferredGap = weaponRange * Mathf.Clamp(profile.preferredGap, 0.6f, 1.6f);
            AimPoint = Predict(Target, pos, moveSpeed);

            if (reevaluate) Decide(self, pos, dir, weaponRange, weaponReady, caster, dashReady);

            // ---- Disparo del ataque (fuera del tick de decision: es la accion) ----
            WantAttack = false;
            if (Plan == Intent.Attack && weaponReady && !TargetTelegraphed && SameLevel)
            {
                if (_reactTimer > 0f)
                {
                    _reactTimer -= dt;
                }
                else if (TargetVulnerable || InRange)
                {
                    // Castigar el recovery del rival no espera: es la ventana buena.
                    WantAttack = true;
                }
            }
        }

        // =================================================================
        // Plan
        // =================================================================

        private void Decide(PlayerHealth self, Vector2 pos, Vector2 dir, float weaponRange,
                            bool weaponReady, AbilityCaster caster, bool dashReady)
        {
            _planAge = 0f;
            _strafeTimer -= ThinkInterval;
            if (_strafeTimer <= 0f)
            {
                _strafeTimer = UnityEngine.Random.Range(0.7f, 1.6f);
                if (UnityEngine.Random.value < 0.45f) _strafeSign = -_strafeSign;
            }

            float gap = PreferredGap;
            float dist = TargetDistance;
            bool same = SameLevel;

            // ---- 1) Habilidad: se decide primero (es la mejor jugada disponible) ----
            int ability = ChooseAbility(self, pos, dist, weaponRange, caster);
            if (ability >= 0)
            {
                Plan = Intent.Cast;
                AbilitySlot = ability;
                WantDash = false;
                return;
            }
            AbilitySlot = -1;

            // ---- 2) El rival esta por pegarnos: esquivar o romper el contacto ----
            if (TargetTelegraphed && same && dist <= weaponRange + Target.bodyRadius + 0.35f)
            {
                if (UnityEngine.Random.value < profile.dodgeChance * Mathf.Clamp01(profile.skill + 0.25f))
                {
                    Plan = Intent.Dodge;
                    WantDash = true;
                    DashDir = -dir;
                    return;
                }
                Plan = Intent.Retreat;
                WantDash = false;
                return;
            }

            // ---- 3) El rival esta en otro nivel: hay que ir hasta el (la IA lo sube) ----
            if (!same)
            {
                Plan = Intent.Approach;
                WantDash = false;
                return;
            }

            // ---- 4) Demasiado lejos: cerrar la distancia (con dash si hace falta) ----
            if (dist > gap * 1.08f)
            {
                Plan = Intent.Approach;
                WantDash = dashReady && dist > gap * 2.3f;
                DashDir = dir;
                return;
            }

            // ---- 5) Dentro del alcance: golpear ----
            float strikeRange = weaponRange * 0.92f + Target.bodyRadius * 0.6f;
            if (dist <= strikeRange && weaponReady)
            {
                Plan = Intent.Attack;
                WantDash = false;
                _reactTimer = Mathf.Max(0f, profile.reaction * (1f - Mathf.Clamp01(profile.skill)) + 0.04f);
                if (TargetVulnerable) _reactTimer = 0f;   // castigo instantaneo
                return;
            }

            // ---- 6) Cerca pero el arma aun no esta lista: orbitear ----
            Plan = Intent.Strafe;
            WantDash = false;
        }

        /// <summary>
        /// Elige la habilidad a lanzar (o -1). La definitiva necesita adrenalina y
        /// enemigos cerca; el corte circular necesita al rival dentro del radio; el
        /// dash-tajo sirve para cerrar distancia con el rival.
        /// </summary>
        private int ChooseAbility(PlayerHealth self, Vector2 pos, float dist, float weaponRange, AbilityCaster caster)
        {
            if (caster == null) return -1;
            if (caster.IsCasting) return -1;
            if (UnityEngine.Random.value > profile.abilityUse) return -1;

            // ---- R: definitiva (adrenalina al maximo) ----
            var r = caster.GetAbility(2);
            if (r != null && r.adrenalineCost > 0f && caster.Adrenaline >= r.adrenalineCost &&
                caster.Cooldown01(2) <= 0f && EnemiesNear(self, pos, 3.2f) >= 1)
                return 2;

            // ---- Q: corte circular (el rival dentro del radio) ----
            var q = caster.GetAbility(0);
            if (q != null && q.kind == AbilityKind.CircularSlash && caster.Cooldown01(0) <= 0f &&
                dist <= q.radius + (Target != null ? Target.bodyRadius : 0.4f))
                return 0;

            // ---- E: dash-tajo (cerrar distancia con el rival) ----
            var e = caster.GetAbility(1);
            if (e != null && e.kind == AbilityKind.DashSlash && caster.Cooldown01(1) <= 0f &&
                dist > weaponRange * 0.9f && dist <= e.dashDistance + weaponRange * 1.8f)
                return 1;

            return -1;
        }

        // =================================================================
        // Objetivo
        // =================================================================

        private void UpdateTarget(PlayerHealth self, Vector2 pos)
        {
            int myTeam = self != null ? self.team : -1;

            PlayerHealth best = null;
            float bestScore = float.MinValue;
            float currentScore = float.MinValue;

            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h == self || h.IsDead) continue;
                if (myTeam >= 0 && h.team == myTeam) continue;

                float d = Vector2.Distance(pos, h.transform.position);
                bool same = PlayerHealth.SameLevel(self, h);

                float score = 100f - d * 6f;
                if (!same) score -= 60f;                // esta en otro nivel: casi no se puede pegar
                score += (1f - h.Hp01) * 26f;          // rematar al que esta lastimado
                if (IsTelegraphing(h)) score += 16f;   // esta por pegar: buen momento
                if (IsVulnerable(h)) score += 22f;      // esta en recovery: castigo
                if (h.Caster != null && h.Caster.IsCasting) score += 8f;

                if (h == Target) currentScore = score;
                if (!same) score -= 1000f;              // el fallback se guarda aparte

                if (score > bestScore)
                {
                    bestScore = score;
                    best = h;
                }
            }

            // Si no hay nadie al mismo nivel, se busca el mas cercano (el bot sube a su deck).
            PlayerHealth fallback = null;
            float fallbackD = float.MaxValue;
            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h == self || h.IsDead) continue;
                if (myTeam >= 0 && h.team == myTeam) continue;
                if (PlayerHealth.SameLevel(self, h)) continue;
                float d = Vector2.Distance(pos, h.transform.position);
                if (d < fallbackD) { fallbackD = d; fallback = h; }
            }

            PlayerHealth chosen = best;
            // Histéresis: no se cambia de objetivo por un detalle (evita dar vueltas).
            if (Target != null && !Target.IsDead && Target != self && currentScore > float.MinValue &&
                currentScore >= bestScore - SwitchMargin)
                chosen = Target;

            if (chosen == null) chosen = fallback;
            Target = chosen;
        }

        // =================================================================
        // Utilidades
        // =================================================================

        /// <summary>Direccion de movimiento que pide el plan (solo X: la altura la sube la IA).</summary>
        public Vector2 DesiredMove(Vector2 pos)
        {
            if (Target == null) return Vector2.zero;
            Vector2 to = (Vector2)Target.transform.position - pos;
            Vector2 dir = to.sqrMagnitude > 0.0001f ? to.normalized : Vector2.right;

            switch (Plan)
            {
                case Intent.Approach: return dir;
                case Intent.Strafe:
                {
                    // Orbitar en vista lateral es un vaiven horizontal: el bot se pasa
                    // al otro lado del rival y vuelve (le abre huecos y lo desordena).
                    // No se aleja demasiado: si se estira, vuelve a cerrar.
                    Vector2 lateral = new Vector2(_strafeSign, 0f);
                    if (Vector2.Dot(lateral, dir) < 0f && TargetDistance > PreferredGap * 1.35f)
                        return dir;
                    return lateral;
                }
                case Intent.Dodge: return -dir;
                case Intent.Retreat: return new Vector2(-dir.x, 0f);
                case Intent.Attack: return Vector2.zero;
                case Intent.Cast: return Vector2.zero;
                default: return Vector2.zero;
            }
        }

        /// <summary>Distancia al borde de la arena: el bot no se arrincona.</summary>
        public static float EnemiesNear(PlayerHealth self, Vector2 pos, float radius)
        {
            int n = 0;
            int myTeam = self != null ? self.team : -1;
            foreach (var h in PlayerHealth.All)
            {
                if (h == null || h == self || h.IsDead) continue;
                if (myTeam >= 0 && h.team == myTeam) continue;
                if (Vector2.Distance(pos, h.transform.position) <= radius) n++;
            }
            return n;
        }

        /// <summary>El rival esta por pegarnos (telegrafo del swing o windup de habilidad).</summary>
        public static bool IsTelegraphing(PlayerHealth h)
        {
            if (h == null) return false;
            if (h.Bot != null) return h.Bot.IsTelegraphing;
            var c = h.Caster;
            return c != null && c.IsPunishable;
        }

        /// <summary>El rival esta en recovery: se puede castigar sin riesgo.</summary>
        public static bool IsVulnerable(PlayerHealth h)
        {
            if (h == null) return false;
            if (h.Bot != null) return h.Bot.IsRecovering;
            var c = h.Caster;
            return c != null && c.IsCasting && !c.IsPunishable;
        }

        /// <summary>
        /// Punto futuro del rival (intercepcion): el bot apunta a donde va a estar,
        /// no a donde esta. Es la diferencia entre "apuntar bien" y "vaciar el aire".
        /// La anticipacion esta acotada: en un cuerpo a cuerpo anticipar de mas es
        /// fallar el golpe.
        /// </summary>
        public static Vector2 Predict(PlayerHealth target, Vector2 pos, float speed)
        {
            if (target == null) return pos;
            var rb = target.GetComponent<Rigidbody2D>();
            Vector2 vel = rb != null ? rb.linearVelocity : Vector2.zero;
            float d = Vector2.Distance(pos, target.transform.position);
            float t = d / Mathf.Max(0.8f, speed);
            Vector2 lead = vel * Mathf.Min(t, 0.6f) * 0.55f;
            const float maxLead = 0.7f;
            if (lead.sqrMagnitude > maxLead * maxLead) lead = lead.normalized * maxLead;
            return (Vector2)target.transform.position + lead;
        }

        /// <summary>Olvida el objetivo (reset de ronda).</summary>
        public void Reset()
        {
            Target = null;
            Plan = Intent.Search;
            WantAttack = false;
            WantDash = false;
            AbilitySlot = -1;
            _thinkTimer = 0f;
            _reactTimer = 0f;
            _planAge = 0f;
        }
    }
}
