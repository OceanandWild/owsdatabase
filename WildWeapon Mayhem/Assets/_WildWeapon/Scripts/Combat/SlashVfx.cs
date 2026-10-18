using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// VFX de tajo: el sprite de arco crece, se desvanece y se destruye.
    /// Los ParticleSystem hijos se reproducen solos (playOnAwake).
    /// </summary>
    public class SlashVfx : MonoBehaviour
    {
        public SpriteRenderer arc;
        public float life = 0.2f;
        public float startScale = 0.6f;
        public float endScale = 1.15f;

        private float _t;
        private float _size = 1f;
        private Color _base = Color.white;

        public void Init(float range, float swingSign)
        {
            _size = range;
            if (arc != null) arc.flipY = swingSign < 0f;
            Apply(0f);
        }

        void Awake()
        {
            if (arc != null) _base = arc.color;
        }

        void Update()
        {
            _t += Time.deltaTime;
            float k = Mathf.Clamp01(_t / life);
            Apply(k);
            if (_t >= life + 0.6f) Destroy(gameObject);
        }

        private void Apply(float k)
        {
            if (arc == null) return;
            float s = Mathf.Lerp(startScale, endScale, 1f - (1f - k) * (1f - k)) * _size;
            arc.transform.localScale = new Vector3(s, s, 1f);
            var c = _base;
            c.a = _base.a * (1f - k * k);
            arc.color = c;
            arc.enabled = k < 1f;
        }
    }
}
