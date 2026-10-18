using UnityEngine;

namespace WildWeapon
{
    /// <summary>Destruye el objeto tras 'life' segundos (VFX de impacto / muerte) con flash opcional.</summary>
    public class VfxAutoDestroy : MonoBehaviour
    {
        public float life = 1.2f;
        public SpriteRenderer flash;
        public float flashScale = 1.2f;
        public float flashTime = 0.12f;

        private float _t;
        private Color _flashBase = Color.white;

        void Awake()
        {
            if (flash != null) _flashBase = flash.color;
        }

        void Update()
        {
            _t += Time.deltaTime;
            if (flash != null)
            {
                float k = Mathf.Clamp01(_t / flashTime);
                float s = Mathf.Lerp(0.2f, flashScale, k);
                flash.transform.localScale = new Vector3(s, s, 1f);
                var c = _flashBase;
                c.a = _flashBase.a * (1f - k);
                flash.color = c;
            }
            if (_t >= life) Destroy(gameObject);
        }
    }
}
