using System;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Capa visual riggeada de un personaje (jugador, bot o preview del menu).
    /// Jerarquia: Visual (flip + escala, SortingGroup) > Rig (Animator) > huesos con piezas.
    /// Cada pieza tiene un sprite base y una capa "Paint" que se tiñe con paintColor.
    /// Parametros del Animator: Speed (float), Attack (trigger), Hit (trigger), Dead (bool).
    /// </summary>
    public class CharacterVisual : MonoBehaviour
    {
        [Serializable]
        public struct Part
        {
            public SpriteRenderer renderer;
            public bool paint;
            [Tooltip("Multiplicador de brillo (extremidades traseras mas oscuras)")]
            public float shade;
        }

        public Animator animator;
        public Part[] parts = Array.Empty<Part>();
        public Color paintColor = new Color(0.2f, 0.85f, 1f);
        public float baseScale = 1f;

        private static readonly int SpeedId = Animator.StringToHash("Speed");
        private static readonly int AttackId = Animator.StringToHash("Attack");
        private static readonly int HitId = Animator.StringToHash("Hit");
        private static readonly int DeadId = Animator.StringToHash("Dead");
        private static readonly int AbilityQId = Animator.StringToHash("AbilityQ");
        private static readonly int AbilityEId = Animator.StringToHash("AbilityE");
        private static readonly int AbilityRId = Animator.StringToHash("AbilityR");

        private float _facing = 1f;
        private Color _overlay = Color.white;

        void Awake()
        {
            if (transform.localScale.x < 0f) _facing = -1f;
            Refresh();
        }

        void OnValidate()
        {
            Refresh();
        }

        public void SetPaintColor(Color c)
        {
            paintColor = c;
            Refresh();
        }

        /// <summary>Multiplica todos los colores (flash de dano, oscurecer al morir). Color.white = normal.</summary>
        public void SetOverlay(Color c)
        {
            _overlay = c;
            Refresh();
        }

        public void Refresh()
        {
            if (parts == null) return;
            foreach (var p in parts)
            {
                if (p.renderer == null) continue;
                Color b = p.paint ? paintColor : Color.white;
                float s = p.shade <= 0f ? 1f : p.shade;
                p.renderer.color = new Color(b.r * s * _overlay.r, b.g * s * _overlay.g, b.b * s * _overlay.b, 1f);
            }
        }

        public void SetSpeed(float speed)
        {
            if (animator != null) animator.SetFloat(SpeedId, speed);
        }

        public void Face(Vector2 dir)
        {
            if (Mathf.Abs(dir.x) > 0.15f) _facing = Mathf.Sign(dir.x);
            transform.localScale = new Vector3(baseScale * _facing, baseScale, 1f);
        }

        public void PlayAttack()
        {
            if (animator != null) animator.SetTrigger(AttackId);
        }

        public void PlayHit()
        {
            if (animator != null) animator.SetTrigger(HitId);
        }

        /// <summary>Dispara el trigger de cast segun la habilidad (Q/E/R).</summary>
        public void PlayCast(AbilityKind kind)
        {
            if (animator == null) return;
            switch (kind)
            {
                case AbilityKind.CircularSlash: animator.SetTrigger(AbilityQId); break;
                case AbilityKind.DashSlash: animator.SetTrigger(AbilityEId); break;
                case AbilityKind.RadialBurst: animator.SetTrigger(AbilityRId); break;
            }
        }

        /// <summary>Giro visual del cuerpo (spin de habilidades). Solo rota la capa Visual.</summary>
        public void SetSpin(float degrees)
        {
            if (!_hasBaseRot)
            {
                _baseRot = transform.localEulerAngles.z;
                _hasBaseRot = true;
            }
            transform.localRotation = Quaternion.Euler(0f, 0f, _baseRot + degrees);
        }

        private bool _hasBaseRot;
        private float _baseRot;

        public void SetDead(bool dead)
        {
            if (animator == null) return;
            animator.SetBool(DeadId, dead);
            if (!dead)
            {
                animator.ResetTrigger(AttackId);
                animator.ResetTrigger(HitId);
            }
        }
    }
}
