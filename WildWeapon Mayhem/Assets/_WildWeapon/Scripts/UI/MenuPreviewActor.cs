using UnityEngine;

namespace WildWeapon.UI
{
    /// <summary>Hace que el personaje de preview del menu ataque de vez en cuando.</summary>
    public class MenuPreviewActor : MonoBehaviour
    {
        public CharacterVisual visual;
        public Vector2 interval = new Vector2(2.5f, 5f);

        private float _next;

        void Start()
        {
            _next = Time.unscaledTime + Random.Range(1.2f, interval.y);
        }

        void Update()
        {
            if (visual == null || Time.unscaledTime < _next) return;
            visual.PlayAttack();
            _next = Time.unscaledTime + Random.Range(interval.x, interval.y);
        }
    }
}
