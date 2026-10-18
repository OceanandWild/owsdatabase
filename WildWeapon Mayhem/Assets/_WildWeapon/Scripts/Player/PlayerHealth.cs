using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Vida de cualquier combatiente (jugadores y bots).
    /// Los combatientes de distinto 'team' pueden danarse entre si.
    /// </summary>
    public class PlayerHealth : MonoBehaviour
    {
        public static readonly List<PlayerHealth> All = new List<PlayerHealth>();

        public float maxHp = DuelRules.Hp;
        public int team;
        public float bodyRadius = 0.45f;
        public GameObject deathVfx;

        public float CurrentHp { get; private set; }
        public bool IsDead { get; private set; }
        public float Hp01 => maxHp <= 0f ? 0f : Mathf.Clamp01(CurrentHp / maxHp);
        public PlayerController Controller { get; private set; }
        public EnemyBot Bot { get; private set; }
        public CharacterVisual Visual { get; private set; }
        public AbilityCaster Caster { get; private set; }

        /// <summary>Multiplicador de dano recibido (1.25 durante windup de habilidad, doc §2.4).</summary>
        [HideInInspector] public float punishMultiplier = 1f;

        public event Action<PlayerHealth> Died;

        private SpriteRenderer _sr;
        private Color _baseColor = Color.white;
        private Coroutine _flash;

        void Awake()
        {
            Controller = GetComponent<PlayerController>();
            Bot = GetComponent<EnemyBot>();
            Caster = GetComponent<AbilityCaster>();
            Visual = GetComponentInChildren<CharacterVisual>(true);
            if (Visual == null) _sr = GetComponent<SpriteRenderer>();
            if (_sr != null) _baseColor = _sr.color;
            CurrentHp = maxHp;
        }

        void OnEnable() { if (!All.Contains(this)) All.Add(this); }
        void OnDisable() { All.Remove(this); }

        public void SetMaxHp(float hp)
        {
            maxHp = hp;
            CurrentHp = hp;
        }

        public void Heal(float amount)
        {
            if (IsDead) return;
            CurrentHp = Mathf.Min(maxHp, CurrentHp + amount);
        }

        public void ResetHealth()
        {
            CurrentHp = maxHp;
            IsDead = false;
            punishMultiplier = 1f;
            if (_flash != null) { StopCoroutine(_flash); _flash = null; }
            SetTint(Color.white);
            var col = GetComponent<Collider2D>();
            if (col != null) col.enabled = true;
            if (Visual != null) Visual.SetDead(false);
        }

        public void TakeDamage(float amount, Vector2 fromDir, PlayerHealth source)
        {
            if (IsDead) return;
            if (Controller != null && Controller.IsInvulnerable) return;

            CurrentHp -= amount * punishMultiplier;
            if (source != null && source.Caster != null)
            {
                source.Caster.NotifyHitDealt();
                if (Caster != null) Caster.NotifyDamageTaken();
            }
            if (Controller != null) Controller.ApplyKnockback(fromDir, DuelRules.KnockbackSpeed);
            if (Bot != null) Bot.ApplyKnockback(fromDir, DuelRules.KnockbackSpeed * 2.5f);
            if (Visual != null) Visual.PlayHit();

            if (_flash != null) StopCoroutine(_flash);
            _flash = StartCoroutine(FlashRoutine());

            if (CurrentHp <= 0f)
            {
                CurrentHp = 0f;
                Die();
            }
        }

        private IEnumerator FlashRoutine()
        {
            SetTint(new Color(1f, 0.45f, 0.45f, 1f));
            yield return new WaitForSeconds(0.08f);
            if (!IsDead) SetTint(Color.white);
        }

        private void SetTint(Color c)
        {
            if (Visual != null) Visual.SetOverlay(c);
            else if (_sr != null) _sr.color = c == Color.white ? _baseColor : _baseColor * c;
        }

        private void Die()
        {
            IsDead = true;
            if (_flash != null) { StopCoroutine(_flash); _flash = null; }
            SetTint(new Color(0.5f, 0.5f, 0.55f, 1f));
            var col = GetComponent<Collider2D>();
            if (col != null) col.enabled = false;
            if (Visual != null) Visual.SetDead(true);
            if (deathVfx != null) Instantiate(deathVfx, transform.position, Quaternion.identity);
            GameFeel.Shake(0.18f);

            if (DuelManager.Instance != null) DuelManager.Instance.NotifyDeath(this);
            Died?.Invoke(this);
        }
    }
}
