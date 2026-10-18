using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>Chispas/brasas que suben por el menu (UI, sin particulas).</summary>
    public class MenuEmbers : MonoBehaviour
    {
        public Sprite sprite;
        public int count = 60;
        public Color colorA = new Color(1f, 0.6f, 0.2f, 0.9f);
        public Color colorB = new Color(0.3f, 0.9f, 1f, 0.8f);
        public Vector2 sizeRange = new Vector2(4f, 10f);
        public Vector2 speedRange = new Vector2(30f, 110f);

        private class Ember
        {
            public RectTransform rt;
            public Image img;
            public Color baseColor;
            public float speed, sway, phase, flicker;
        }

        private readonly List<Ember> _items = new List<Ember>();
        private RectTransform _area;

        void Start()
        {
            _area = (RectTransform)transform;
            for (int i = 0; i < count; i++)
            {
                var go = new GameObject("Ember", typeof(RectTransform), typeof(Image));
                go.transform.SetParent(transform, false);
                var e = new Ember
                {
                    rt = (RectTransform)go.transform,
                    img = go.GetComponent<Image>(),
                    speed = Random.Range(speedRange.x, speedRange.y),
                    sway = Random.Range(10f, 45f),
                    phase = Random.Range(0f, 10f),
                    flicker = Random.Range(3f, 9f)
                };
                e.img.sprite = sprite;
                e.img.raycastTarget = false;
                e.baseColor = Random.value < 0.6f ? colorA : colorB;
                float s = Random.Range(sizeRange.x, sizeRange.y);
                e.rt.sizeDelta = new Vector2(s, s);
                Respawn(e, true);
                _items.Add(e);
            }
        }

        void Update()
        {
            if (_area == null) return;
            float dt = Time.unscaledDeltaTime;
            float t = Time.unscaledTime;
            Rect r = _area.rect;
            foreach (var e in _items)
            {
                var p = e.rt.anchoredPosition;
                p.y += e.speed * dt;
                p.x += Mathf.Sin(t * 1.1f + e.phase) * e.sway * dt;
                e.rt.anchoredPosition = p;
                var c = e.baseColor;
                float life = Mathf.InverseLerp(r.yMax, r.yMin, p.y);
                c.a *= (0.55f + 0.45f * Mathf.Sin(t * e.flicker + e.phase)) * Mathf.Clamp01(life * 1.5f);
                e.img.color = c;
                if (p.y > r.yMax + 20f) Respawn(e, false);
            }
        }

        private void Respawn(Ember e, bool anywhere)
        {
            Rect r = _area.rect;
            float x = Random.Range(r.xMin, r.xMax);
            float y = anywhere ? Random.Range(r.yMin, r.yMax) : r.yMin - Random.Range(5f, 60f);
            e.rt.anchoredPosition = new Vector2(x, y);
        }
    }
}
