using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Ejecutor de habilidades Q/E/R del portador (doc maestro §2.4):
    /// windup -> active -> recovery, con castigo x1.25 durante el windup,
    /// root parcial al 40% y Adrenalina compartida (R = definitiva).
    /// Cooldowns independientes por arma (viven aca, no en el arma).
    /// </summary>
    public class AbilityCaster : MonoBehaviour
    {
        public PlayerController controller;
        public PlayerHealth health;
        public WeaponLoadout loadout;
        public CharacterVisual visual;

        /// <summary>Adrenalina 0-100 (doc: +8 por golpe dado, +5 por dano recibido, +25 por orbe).</summary>
        public float Adrenaline { get; private set; }
        public bool IsCasting { get; private set; }
        public bool IsPunishable { get; private set; }
        public AbilityDef CurrentDef { get; private set; }

        public const float AdrenalinePerHit = 8f;
        public const float AdrenalinePerDamageTaken = 5f;
        public const float AdrenalineMax = 100f;

        /// <summary>PVP: avisa cuando el portador lanza una habilidad (se reenvia por red).</summary>
        public event Action<int, AbilityKind> CastStarted;

        private struct SlotState { public float cooldown; }
        private readonly SlotState[][] _slots = new SlotState[2][];
        private readonly Queue<int> _queued = new Queue<int>(3);

        private Coroutine _cast;
        private Rigidbody2D _rb;
        private float _spinOffset;

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            for (int w = 0; w < _slots.Length; w++)
            {
                _slots[w] = new SlotState[3];
                for (int i = 0; i < 3; i++) _slots[w][i] = new SlotState();
            }
        }

        public float MovementScale => IsCasting ? 0.4f : 1f;

        public float Cooldown01(int slot)
        {
            int w = ActiveWeaponIndex;
            if (w < 0 || w >= _slots.Length || slot < 0 || slot > 2) return 0f;
            var def = GetDef(w, slot);
            if (def == null || def.cooldown <= 0f) return 0f;
            return Mathf.Clamp01(_slots[w][slot].cooldown / def.cooldown);
        }

        public AbilityDef GetAbility(int slot)
        {
            int w = ActiveWeaponIndex;
            return w < 0 ? null : GetDef(w, slot);
        }

        private int ActiveWeaponIndex =>
            loadout != null && loadout.weapons != null && loadout.weapons.Length > 0 ? loadout.ActiveIndex : -1;

        private AbilityDef GetDef(int w, int slot)
        {
            if (loadout == null || loadout.weapons == null || w < 0 || w >= loadout.weapons.Length) return null;
            var weapon = loadout.weapons[w];
            if (weapon == null || weapon.def == null) return null;
            return slot == 0 ? weapon.def.abilityQ : slot == 1 ? weapon.def.abilityE : weapon.def.abilityR;
        }

        void Update()
        {
            for (int w = 0; w < _slots.Length; w++)
                for (int i = 0; i < 3; i++)
                    if (_slots[w][i].cooldown > 0f)
                        _slots[w][i].cooldown -= Time.deltaTime;

            if (IsCasting) return;

            bool dead = health != null && health.IsDead;
            if (dead)
            {
                _queued.Clear();
                Cancel();
                return;
            }

            while (_queued.Count > 0)
            {
                int slot = _queued.Dequeue();
                TryCast(slot);
            }
        }

        // =====================================================================
        // API de entrada (PlayerController / bots)
        // =====================================================================

        public void QueueQ() { if (!IsCasting) _queued.Enqueue(0); }
        public void QueueE() { if (!IsCasting) _queued.Enqueue(1); }
        public void QueueR() { if (!IsCasting) _queued.Enqueue(2); }

        public void NotifyHitDealt() => AddAdrenaline(AdrenalinePerHit);
        public void NotifyDamageTaken() => AddAdrenaline(AdrenalinePerDamageTaken);

        private void AddAdrenaline(float amount)
        {
            Adrenaline = Mathf.Clamp(Adrenaline + amount, 0f, AdrenalineMax);
        }

        public void ResetForRound()
        {
            Adrenaline = 0f;
            Cancel();
            for (int w = 0; w < _slots.Length; w++)
                for (int i = 0; i < 3; i++) _slots[w][i] = new SlotState();
        }

        private void Cancel()
        {
            if (_cast != null) { StopCoroutine(_cast); _cast = null; }
            EndCastState();
        }

        private void EndCastState()
        {
            IsCasting = false;
            IsPunishable = false;
            CurrentDef = null;
            _spinOffset = 0f;
            if (visual != null) visual.SetSpin(0f);
            if (controller != null) { controller.castingSlow = 1f; controller.Casting = false; }
            if (health != null) health.punishMultiplier = 1f;
        }

        // =====================================================================
        // Cast
        // =====================================================================

        private bool TryCast(int slot)
        {
            int w = ActiveWeaponIndex;
            var def = GetDef(w, slot);
            if (def == null || w < 0) return false;
            if (_slots[w][slot].cooldown > 0f) return false;
            if (def.adrenalineCost > 0f && Adrenaline < def.adrenalineCost) return false;
            if (health != null && health.IsDead) return false;
            if (controller != null && !controller.CanAct) return false;

            if (def.adrenalineCost > 0f) Adrenaline -= def.adrenalineCost;

            _slots[w][slot].cooldown = def.cooldown;
            _cast = StartCoroutine(CastRoutine(def, slot));
            CastStarted?.Invoke(slot, def.kind);
            return true;
        }

        /// <summary>PVP: reproduce el cast del rival que llego por red (solo visual, sin dano).</summary>
        public void PlayRemoteCast(AbilityKind kind)
        {
            if (visual != null) visual.PlayCast(kind);

            var def = FindAbilityByKind(kind);
            if (def == null) return;

            if (def.castVfx != null)
            {
                float size = def.kind == AbilityKind.DashSlash ? 1f : Mathf.Max(0.5f, def.radius);
                var fx = Instantiate(def.castVfx, transform.position, Quaternion.identity);
                fx.transform.localScale = new Vector3(size, size, 1f);
            }
            if (kind == AbilityKind.CircularSlash || kind == AbilityKind.RadialBurst)
                StartCoroutine(SpinRoutine(Mathf.Max(0.12f, def.castDuration * 0.35f)));
        }

        private AbilityDef FindAbilityByKind(AbilityKind kind)
        {
            if (loadout == null || loadout.weapons == null) return null;
            foreach (var weapon in loadout.weapons)
            {
                if (weapon == null || weapon.def == null) continue;
                if (weapon.def.abilityQ != null && weapon.def.abilityQ.kind == kind) return weapon.def.abilityQ;
                if (weapon.def.abilityE != null && weapon.def.abilityE.kind == kind) return weapon.def.abilityE;
                if (weapon.def.abilityR != null && weapon.def.abilityR.kind == kind) return weapon.def.abilityR;
            }
            return null;
        }

        private IEnumerator CastRoutine(AbilityDef def, int slot)
        {
            IsCasting = true;
            CurrentDef = def;

            Vector2 aim = controller != null ? controller.AimDir : (Vector2)transform.right;

            if (visual != null) visual.PlayCast(def.kind);

            float windup = def.castDuration * Mathf.Clamp01(def.windupFraction);
            float active = Mathf.Max(0.06f, def.castDuration * 0.35f);
            float recovery = Mathf.Max(0.05f, def.castDuration - windup - active);

            // ---- Windup (castigable x1.25) ----
            IsPunishable = true;
            if (health != null) health.punishMultiplier = 1.25f;
            BeginCastSlow();
            float t = 0f;
            while (t < windup)
            {
                if (health != null && health.IsDead) { Cancel(); yield break; }
                t += Time.deltaTime;
                yield return null;
            }
            IsPunishable = false;
            if (health != null) health.punishMultiplier = 1f;

            // ---- Active ----
            bool spinning = def.kind == AbilityKind.CircularSlash || def.kind == AbilityKind.RadialBurst;
            if (spinning) StartCoroutine(SpinRoutine(active));
            CastEffect(def, aim, slot);
            yield return new WaitForSeconds(active);

            // ---- Recovery ----
            if (!spinning)
            {
                BeginCastSlow();
                t = 0f;
                while (t < recovery)
                {
                    if (health != null && health.IsDead) { Cancel(); yield break; }
                    t += Time.deltaTime;
                    yield return null;
                }
            }

            EndCastState();
            _cast = null;
        }

        private void BeginCastSlow()
        {
            if (controller != null) { controller.castingSlow = 0.4f; controller.Casting = true; }
        }

        // =====================================================================
        // Efectos por tipo
        // =====================================================================

        private void CastEffect(AbilityDef def, Vector2 aim, int slot)
        {
            if (def.castVfx != null)
            {
                float size = def.kind == AbilityKind.DashSlash ? 1f : Mathf.Max(0.5f, def.radius);
                var fx = Instantiate(def.castVfx, transform.position, Quaternion.identity);
                fx.transform.localScale = new Vector3(size, size, 1f);
            }

            switch (def.kind)
            {
                case AbilityKind.CircularSlash: DoCircularSlash(def, aim); break;
                case AbilityKind.DashSlash: DoDashSlash(def, aim); break;
                case AbilityKind.RadialBurst: DoRadialBurst(def, aim); break;
            }
        }

        private void DoCircularSlash(AbilityDef def, Vector2 aim)
        {
            float mult = DamageMultiplier();
            int myTeam = Team();
            bool any = false;

            foreach (var target in Snapshot())
            {
                if (!ValidTarget(target, myTeam)) continue;
                if (Vector2.Distance(transform.position, target.transform.position) > def.radius + target.bodyRadius) continue;

                Vector2 dir = ((Vector2)target.transform.position - (Vector2)transform.position).sqrMagnitude > 0.0001f
                    ? ((Vector2)target.transform.position - (Vector2)transform.position).normalized
                    : aim;
                target.TakeDamage(def.damage * mult, dir, health);
                SpawnHitVfx(def, target, dir);
                if (target.Bot != null && def.stunSeconds > 0f) target.Bot.Stun(def.stunSeconds);
                any = true;
            }

            if (any) ImpactFeedback(def);
        }

        private void DoDashSlash(AbilityDef def, Vector2 aim)
        {
            StartCoroutine(DashRoutine(def, aim));
        }

        private IEnumerator DashRoutine(AbilityDef def, Vector2 aim)
        {
            float dashDuration = Mathf.Clamp(def.dashDistance / 12f, 0.12f, 0.22f);
            float speed = def.dashDistance / dashDuration;
            float mult = DamageMultiplier();
            int myTeam = Team();
            var hitOnce = new HashSet<PlayerHealth>();

            if (controller != null) controller.GrantIFrames(def.castDuration * 0.5f);
            if (visual != null) StartCoroutine(SpinRoutine(dashDuration * 0.6f));

            float t = 0f;
            while (t < dashDuration)
            {
                t += Time.deltaTime;
                Vector2 step = aim * speed * Time.deltaTime;
                if (_rb != null) _rb.MovePosition(_rb.position + step);
                else transform.position += (Vector3)step;

                foreach (var target in Snapshot())
                {
                    if (!ValidTarget(target, myTeam)) continue;
                    if (hitOnce.Contains(target)) continue;
                    if (Vector2.Distance(transform.position, target.transform.position) > 0.65f + target.bodyRadius) continue;

                    hitOnce.Add(target);
                    Vector2 dir = ((Vector2)target.transform.position - (Vector2)transform.position).sqrMagnitude > 0.0001f
                        ? ((Vector2)target.transform.position - (Vector2)transform.position).normalized
                        : aim;
                    target.TakeDamage(def.damage * mult, dir, health);
                    SpawnHitVfx(def, target, dir);
                    if (target.Bot != null && def.stunSeconds > 0f) target.Bot.Stun(def.stunSeconds);
                }
                yield return null;
            }

            if (hitOnce.Count > 0) ImpactFeedback(def);
        }

        private void DoRadialBurst(AbilityDef def, Vector2 aim)
        {
            float baseAngle = Mathf.Atan2(aim.y, aim.x) * Mathf.Rad2Deg;
            int count = Mathf.Max(1, def.projectileCount);
            for (int i = 0; i < count; i++)
            {
                float angle = baseAngle + 360f * i / count;
                var go = new GameObject("Beam_" + i);
                go.transform.position = transform.position;
                go.transform.rotation = Quaternion.Euler(0f, 0f, angle);
                var beam = go.AddComponent<SwordBeam>();
                beam.Init(this, def, health, aim);
            }
            GameFeel.Shake(0.2f);
        }

        private void SpawnHitVfx(AbilityDef def, PlayerHealth target, Vector2 dir)
        {
            if (def.hitVfx == null) return;
            Instantiate(def.hitVfx, (Vector2)target.transform.position - dir * target.bodyRadius * 0.5f,
                Quaternion.Euler(0f, 0f, Mathf.Atan2(dir.y, dir.x) * Mathf.Rad2Deg));
        }

        private void ImpactFeedback(AbilityDef def)
        {
            GameFeel.HitStop(DuelRules.HitStopDuration);
            GameFeel.Shake(0.14f);
        }

        // =====================================================================
        // Helpers
        // =====================================================================

        private static readonly List<PlayerHealth> Buffer = new List<PlayerHealth>(16);

        private List<PlayerHealth> Snapshot()
        {
            Buffer.Clear();
            Buffer.AddRange(PlayerHealth.All);
            return Buffer;
        }

        private bool ValidTarget(PlayerHealth target, int myTeam)
        {
            if (target == null || target == health || target.IsDead || target.team == myTeam) return false;
            if (!PlayerHealth.SameLevel(health, target)) return false;   // no se golpea a traves de un deck
            return true;
        }

        private int Team() => health != null ? health.team : -1;

        private float DamageMultiplier()
        {
            var duel = DuelManager.Instance;
            return duel != null ? duel.DamageMultiplier : 1f;
        }

        // ---- Spin visual (Q/R y dash): gira la capa Visual, no el objeto fisico ----
        private IEnumerator SpinRoutine(float duration)
        {
            float t = 0f;
            while (t < duration)
            {
                t += Time.deltaTime;
                float k = Mathf.Clamp01(t / duration);
                _spinOffset = -360f * (1f - (1f - k) * (1f - k));
                if (visual != null) visual.SetSpin(_spinOffset);
                yield return null;
            }
            _spinOffset = 0f;
            if (visual != null) visual.SetSpin(0f);
        }

        /// <summary>Portador y dano de un beam radial (R).</summary>
        private class SwordBeam : MonoBehaviour
        {
            private AbilityCaster _caster;
            private AbilityDef _def;
            private PlayerHealth _owner;
            private Vector2 _dir;
            private float _life;
            private readonly HashSet<PlayerHealth> _hit = new HashSet<PlayerHealth>();

            public void Init(AbilityCaster caster, AbilityDef def, PlayerHealth owner, Vector2 aim)
            {
                _caster = caster;
                _def = def;
                _owner = owner;
                _dir = new Vector2(Mathf.Cos(transform.eulerAngles.z * Mathf.Deg2Rad),
                    Mathf.Sin(transform.eulerAngles.z * Mathf.Deg2Rad)).normalized;
                _life = def.projectileLife;

                if (def.castVfx != null)
                {
                    var fx = Instantiate(def.castVfx, transform.position, transform.rotation);
                    fx.transform.localScale = new Vector3(1f, 1f, 1f);
                }
            }

            void Update()
            {
                float dt = Time.deltaTime;
                _life -= dt;
                if (_life <= 0f) { Destroy(gameObject); return; }

                transform.position += (Vector3)(_dir * _def.projectileSpeed * dt);

                float myTeam = _owner != null ? _owner.team : -1;
                foreach (var target in PlayerHealth.All)
                {
                    if (target == null || target == _owner || target.IsDead || target.team == myTeam) continue;
                    if (_hit.Contains(target)) continue;
                    if (!PlayerHealth.SameLevel(_owner, target)) continue;   // proyectiles a la altura del caster
                    if (Vector2.Distance(transform.position, target.transform.position) > 0.45f + target.bodyRadius) continue;

                    _hit.Add(target);
                    float mult = DuelManager.Instance != null ? DuelManager.Instance.DamageMultiplier : 1f;
                    target.TakeDamage(_def.projectileDamage * mult, _dir, _owner);
                    if (_def.hitVfx != null)
                        Instantiate(_def.hitVfx, target.transform.position, transform.rotation);
                    if (_caster != null) _caster.NotifyHitDealt();
                }
            }
        }
    }
}
