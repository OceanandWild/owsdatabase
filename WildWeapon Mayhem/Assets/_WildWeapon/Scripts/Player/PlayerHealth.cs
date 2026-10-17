using System.Collections;
using UnityEngine;

namespace WildWeapon
{
    public class PlayerHealth : MonoBehaviour
    {
        public float maxHp = DuelRules.Hp;

        public float CurrentHp { get; private set; }
        public bool IsDead { get; private set; }
        public float Hp01 => maxHp <= 0f ? 0f : Mathf.Clamp01(CurrentHp / maxHp);
        public PlayerController Controller { get; private set; }

        private SpriteRenderer _sr;
        private Color _baseColor;
        private Coroutine _flash;

        void Awake()
        {
            Controller = GetComponent<PlayerController>();
            _sr = GetComponent<SpriteRenderer>();
            if (_sr != null) _baseColor = _sr.color;
            CurrentHp = maxHp;
        }

        public void ResetHealth()
        {
            CurrentHp = maxHp;
            IsDead = false;
            if (_flash != null) { StopCoroutine(_flash); _flash = null; }
            if (_sr != null) _sr.color = _baseColor;
            var col = GetComponent<Collider2D>();
            if (col != null) col.enabled = true;
        }

        public void TakeDamage(float amount, Vector2 fromDir, PlayerHealth source)
        {
            if (IsDead) return;
            if (Controller != null && Controller.IsInvulnerable) return;

            CurrentHp -= amount;
            if (Controller != null) Controller.ApplyKnockback(fromDir, DuelRules.KnockbackSpeed);

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
            if (_sr != null) _sr.color = Color.white;
            yield return new WaitForSeconds(0.07f);
            if (_sr != null && !IsDead) _sr.color = _baseColor;
        }

        private void Die()
        {
            IsDead = true;
            if (_sr != null) _sr.color = new Color(0.22f, 0.22f, 0.25f, 1f);
            var col = GetComponent<Collider2D>();
            if (col != null) col.enabled = false;
            if (DuelManager.Instance != null) DuelManager.Instance.NotifyDeath(this);
        }
    }
}
