using System.Collections;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// M1 melee del F0: arco + alcance desde el WeaponDef.
    /// La deteccion es 1 frame (el windup real llega con las animaciones en F1).
    /// </summary>
    public class MeleeWeapon : MonoBehaviour
    {
        public WeaponDef def;
        public Transform blade;
        public SpriteRenderer bladeRenderer;

        public bool Equipped { get; private set; } = true;
        public string DisplayName => def != null ? def.displayName : name;

        private float _nextAttackTime;
        private Coroutine _swing;

        void Awake()
        {
            ApplyBlade();
        }

        public void ApplyBlade()
        {
            if (def == null || blade == null) return;
            blade.localPosition = new Vector3(def.bladeOffset, 0f, 0f);
            blade.localScale = new Vector3(def.bladeSize.x, def.bladeSize.y, 1f);
            if (bladeRenderer != null) bladeRenderer.color = def.color;
        }

        public void SetEquipped(bool value)
        {
            Equipped = value;
            if (bladeRenderer != null) bladeRenderer.enabled = value;
        }

        public void ResetCooldown()
        {
            _nextAttackTime = 0f;
        }

        public bool TryAttack(Vector2 aimDir, PlayerHealth self)
        {
            if (!Equipped || def == null) return false;
            if (Time.time < _nextAttackTime) return false;
            _nextAttackTime = Time.time + def.cadence;

            if (_swing != null) StopCoroutine(_swing);
            _swing = StartCoroutine(SwingRoutine());

            bool hitAny = false;
            var mgr = DuelManager.Instance;
            if (mgr != null && mgr.Players != null)
            {
                Vector2 origin = transform.position;
                foreach (var pc in mgr.Players)
                {
                    if (pc == null || pc.Health == null || pc.Health == self || pc.Health.IsDead) continue;

                    Vector2 toTarget = (Vector2)pc.transform.position - origin;
                    float dist = toTarget.magnitude;
                    if (dist > def.range + pc.BodyRadius) continue;

                    // Con el objetivo pegado el angulo es inestable: se toma como hit.
                    if (dist > 0.05f && Vector2.Angle(aimDir, toTarget) > def.arcDegrees * 0.5f) continue;

                    float dmg = def.damage * mgr.DamageMultiplier;
                    Vector2 dir = toTarget.sqrMagnitude > 0.0001f ? toTarget.normalized : aimDir;
                    pc.Health.TakeDamage(dmg, dir, self);
                    hitAny = true;
                }
            }

            if (hitAny && mgr != null) mgr.RequestHitStop(DuelRules.HitStopDuration);
            return true;
        }

        private IEnumerator SwingRoutine()
        {
            if (blade == null || def == null) yield break;

            const float duration = 0.12f;
            float t = 0f;
            while (t < duration)
            {
                t += Time.deltaTime;
                float k = Mathf.Clamp01(t / duration);
                blade.localRotation = Quaternion.Euler(0f, 0f, Mathf.Lerp(-40f, 55f, k));
                float s = 1f + 0.25f * Mathf.Sin(k * Mathf.PI);
                blade.localScale = new Vector3(def.bladeSize.x * s, def.bladeSize.y, 1f);
                yield return null;
            }

            blade.localRotation = Quaternion.identity;
            blade.localScale = new Vector3(def.bladeSize.x, def.bladeSize.y, 1f);
        }
    }
}
