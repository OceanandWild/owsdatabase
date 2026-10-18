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
        /// <summary>Altura (Z) simulada del combatiente: plataformas y peligros la consultan.</summary>
        public HeightBody Height { get; private set; }

        private float _slowFactor = 1f;
        private float _slowUntil;

        /// <summary>Multiplicador de velocidad por peligros (frio, esporas, ventisca). 1 = normal.</summary>
        public float SlowFactor => Time.time < _slowUntil ? _slowFactor : 1f;

        /// <summary>Aplica un frenado temporal (factor 0.45 = 55% mas lento).</summary>
        public void ApplySlow(float factor, float duration)
        {
            factor = Mathf.Clamp(factor, 0.1f, 1f);
            if (Time.time < _slowUntil) _slowFactor = Mathf.Min(_slowFactor, factor);
            else _slowFactor = factor;
            _slowUntil = Mathf.Max(_slowUntil, Time.time + duration);
        }

        /// <summary>Z del combatiente (0 = piso de la arena).</summary>
        public static float HeightOf(PlayerHealth h) => h != null && h.Height != null ? h.Height.Z : 0f;

        /// <summary>Dos combatientes se alcanzan si estan a una altura parecida (no se pega a traves de un deck).</summary>
        public static bool SameLevel(PlayerHealth a, PlayerHealth b, float tolerance = 0.9f)
            => Mathf.Abs(HeightOf(a) - HeightOf(b)) <= tolerance;

        /// <summary>Multiplicador de dano recibido (1.25 durante windup de habilidad, doc §2.4).</summary>
        [HideInInspector] public float punishMultiplier = 1f;

        /// <summary>PVP: esta es la replica del rival. Los golpes no cambian la vida local:
        /// se reenvian por red y el dueno del pawn aplica el dano real.</summary>
        [HideInInspector] public bool networkMirror;

        public event Action<PlayerHealth> Died;

        /// <summary>PVP: golpe detectado localmente sobre una replica (dano, direccion).</summary>
        public event Action<PlayerHealth, float, Vector2> Damaged;

        private SpriteRenderer _sr;
        private Color _baseColor = Color.white;
        private Coroutine _flash;

        void Awake()
        {
            Controller = GetComponent<PlayerController>();
            Bot = GetComponent<EnemyBot>();
            Caster = GetComponent<AbilityCaster>();
            Height = GetComponent<HeightBody>();
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
            _slowFactor = 1f;
            _slowUntil = 0f;
            if (_flash != null) { StopCoroutine(_flash); _flash = null; }
            SetTint(Color.white);
            var col = GetComponent<Collider2D>();
            if (col != null) col.enabled = true;
            if (Visual != null) Visual.SetDead(false);
        }

        /// <summary>PVP: aplica la vida autoritativa que reporta el dueno del pawn (snapshots).</summary>
        public void SetNetworkHp(float hp)
        {
            if (IsDead) return;
            float clamped = Mathf.Clamp(hp, 0f, maxHp);
            if (Mathf.Approximately(clamped, CurrentHp)) return;
            CurrentHp = clamped;
            if (CurrentHp <= 0f) Die();
        }

        public void TakeDamage(float amount, Vector2 fromDir, PlayerHealth source, float knockbackScale = 1f)
        {
            if (IsDead) return;

            // Replica del rival en PVP: se juega el feedback visual, se reenvia el golpe
            // por red y el dueno decide dano real (i-frames, muerte).
            if (networkMirror)
            {
                if (Visual != null) Visual.PlayHit();
                if (_flash != null) StopCoroutine(_flash);
                _flash = StartCoroutine(FlashRoutine());
                Damaged?.Invoke(this, amount, fromDir);
                return;
            }

            if (Controller != null && Controller.IsInvulnerable) return;

            CurrentHp -= amount * punishMultiplier;
            if (source != null && source.Caster != null)
            {
                source.Caster.NotifyHitDealt();
                if (Caster != null) Caster.NotifyDamageTaken();
            }
            if (Controller != null) Controller.ApplyKnockback(fromDir, DuelRules.KnockbackSpeed * knockbackScale);
            if (Bot != null) Bot.ApplyKnockback(fromDir, DuelRules.KnockbackSpeed * 2.5f * knockbackScale);
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
