using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Arma melee: arco + alcance desde el WeaponDef, sprite real, trail y VFX.
    /// Golpea a cualquier PlayerHealth de otro equipo (jugadores o bots).
    /// </summary>
    public class MeleeWeapon : MonoBehaviour
    {
        public WeaponDef def;
        public Transform blade;
        public SpriteRenderer bladeRenderer;
        public TrailRenderer trail;

        public bool Equipped { get; private set; } = true;
        public string DisplayName => def != null ? def.displayName : name;
        public float Range => def != null ? def.range : 1f;
        /// <summary>Angulo actual del swing (grados) para que el brazo del rig lo acompañe.</summary>
        public float SwingOffset { get; private set; }

        /// <summary>PVP: avisa cuando el portador lanza un ataque (se reenvia por red).</summary>
        public event Action<MeleeWeapon, Vector2> Attacked;

        private static readonly List<PlayerHealth> Buffer = new List<PlayerHealth>(16);

        private float _nextAttackTime;
        private Coroutine _swing;
        private float _swingSign = 1f;
        private Vector3 _restPos;
        private Vector3 _restScale = Vector3.one;

        void Awake()
        {
            ApplyBlade();
        }

        void Update()
        {
            if (bladeRenderer != null)
                bladeRenderer.flipY = transform.right.x < 0f;
        }

        public void ApplyBlade()
        {
            if (def == null || blade == null) return;

            if (def.sprite != null && bladeRenderer != null)
            {
                bladeRenderer.sprite = def.sprite;
                bladeRenderer.color = Color.white;
                float w = Mathf.Max(0.01f, def.sprite.bounds.size.x);
                float s = def.spriteLength / w;
                blade.localScale = new Vector3(s, s, 1f);
                if (trail != null)
                    trail.transform.localPosition = new Vector3(def.sprite.bounds.max.x * 0.92f, 0f, 0f);
            }
            else
            {
                blade.localScale = new Vector3(def.bladeSize.x, def.bladeSize.y, 1f);
                if (bladeRenderer != null) bladeRenderer.color = def.color;
            }

            blade.localPosition = new Vector3(def.bladeOffset, 0f, 0f);
            blade.localRotation = Quaternion.identity;
            _restPos = blade.localPosition;
            _restScale = blade.localScale;

            if (trail != null)
            {
                trail.emitting = false;
                trail.startColor = def.trailColor;
                trail.endColor = new Color(def.trailColor.r, def.trailColor.g, def.trailColor.b, 0f);
            }
        }

        public void SetEquipped(bool value)
        {
            Equipped = value;
            if (bladeRenderer != null) bladeRenderer.enabled = value;
            if (!value && trail != null) { trail.emitting = false; trail.Clear(); }
        }

        public void ResetCooldown()
        {
            _nextAttackTime = 0f;
        }

        public bool CanAttackNow => Equipped && def != null && Time.time >= _nextAttackTime;

        public bool TryAttack(Vector2 aimDir, PlayerHealth self)
        {
            if (!CanAttackNow) return false;
            _nextAttackTime = Time.time + def.cadence;

            if (_swing != null) StopCoroutine(_swing);
            _swing = StartCoroutine(SwingRoutine());

            if (self != null && self.Visual != null) self.Visual.PlayAttack();
            Attacked?.Invoke(this, aimDir);

            Vector2 origin = transform.position;
            if (def.swingVfx != null)
            {
                float ang = Mathf.Atan2(aimDir.y, aimDir.x) * Mathf.Rad2Deg;
                var v = Instantiate(def.swingVfx, origin + aimDir * def.range * 0.5f, Quaternion.Euler(0f, 0f, ang));
                var slash = v.GetComponent<SlashVfx>();
                if (slash != null) slash.Init(def.range, _swingSign);
            }

            bool hitAny = false;
            var duel = DuelManager.Instance;
            float mult = duel != null ? duel.DamageMultiplier : 1f;
            int myTeam = self != null ? self.team : -1;

            Buffer.Clear();
            Buffer.AddRange(PlayerHealth.All);
            foreach (var target in Buffer)
            {
                if (target == null || target == self || target.IsDead || target.team == myTeam) continue;
                if (!PlayerHealth.SameLevel(self, target)) continue;   // no se golpea a traves de un deck

                Vector2 toTarget = (Vector2)target.transform.position - origin;
                float dist = toTarget.magnitude;
                if (dist > def.range + target.bodyRadius) continue;

                // Con el objetivo pegado el angulo es inestable: se toma como hit.
                if (dist > 0.05f && Vector2.Angle(aimDir, toTarget) > def.arcDegrees * 0.5f) continue;

                Vector2 dir = toTarget.sqrMagnitude > 0.0001f ? toTarget.normalized : aimDir;
                target.TakeDamage(def.damage * mult, dir, self);
                if (def.hitVfx != null)
                    Instantiate(def.hitVfx, (Vector2)target.transform.position - dir * target.bodyRadius * 0.5f,
                        Quaternion.Euler(0f, 0f, Mathf.Atan2(dir.y, dir.x) * Mathf.Rad2Deg));
                hitAny = true;
            }

            if (hitAny)
            {
                GameFeel.HitStop(DuelRules.HitStopDuration);
                GameFeel.Shake(def.shakeOnHit);
            }
            _swingSign = -_swingSign;
            return true;
        }

        /// <summary>PVP: reproduce el swing del rival que llego por red (sin dano ni cooldown locales).</summary>
        public void PlaySwingOnly(Vector2 aimDir)
        {
            if (def == null) return;

            if (_swing != null) StopCoroutine(_swing);
            _swing = StartCoroutine(SwingRoutine());

            if (def.swingVfx != null)
            {
                float ang = Mathf.Atan2(aimDir.y, aimDir.x) * Mathf.Rad2Deg;
                var v = Instantiate(def.swingVfx, (Vector2)transform.position + aimDir * def.range * 0.5f,
                    Quaternion.Euler(0f, 0f, ang));
                var slash = v.GetComponent<SlashVfx>();
                if (slash != null) slash.Init(def.range, _swingSign);
            }
            _swingSign = -_swingSign;
        }

        private IEnumerator SwingRoutine()
        {
            if (blade == null || def == null) yield break;

            if (trail != null) { trail.Clear(); trail.emitting = true; }

            float duration = Mathf.Max(0.05f, def.swingDuration);
            float half = def.swingAngle * 0.5f;
            float sign = _swingSign;
            float t = 0f;
            while (t < duration)
            {
                t += Time.deltaTime;
                float k = Mathf.Clamp01(t / duration);
                float e = 1f - (1f - k) * (1f - k);   // ease-out

                switch (def.swingStyle)
                {
                    case SwingStyle.Slash:
                        float a = Mathf.Lerp(half, -half, e) * sign;
                        blade.localRotation = Quaternion.Euler(0f, 0f, a);
                        blade.localScale = _restScale * (1f + 0.12f * Mathf.Sin(k * Mathf.PI));
                        SwingOffset = a;
                        break;
                    case SwingStyle.Thrust:
                        float push = Mathf.Sin(k * Mathf.PI) * def.range * 0.45f;
                        blade.localPosition = _restPos + new Vector3(push, 0f, 0f);
                        break;
                    case SwingStyle.Spin:
                        blade.localRotation = Quaternion.Euler(0f, 0f, -360f * e * sign);
                        break;
                }
                yield return null;
            }

            blade.localRotation = Quaternion.identity;
            blade.localPosition = _restPos;
            blade.localScale = _restScale;
            SwingOffset = 0f;

            yield return new WaitForSeconds(0.05f);
            if (trail != null) trail.emitting = false;
        }
    }
}
