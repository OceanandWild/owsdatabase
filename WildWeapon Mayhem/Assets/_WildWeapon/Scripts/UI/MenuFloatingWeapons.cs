using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>Armas flotando y girando lentamente en el fondo del menu (parallax).</summary>
    public class MenuFloatingWeapons : MonoBehaviour
    {
        public Sprite[] weapons;
        public int count = 14;
        public Vector2 sizeRange = new Vector2(140f, 300f);
        public Color tint = new Color(0.75f, 0.8f, 0.9f, 0.35f);

        private class Item
        {
            public RectTransform rt;
            public Vector2 vel;
            public float spin, bobPhase, bobAmp;
            public Vector2 basePos;
        }

        private readonly List<Item> _items = new List<Item>();
        private RectTransform _area;

        void Start()
        {
            _area = (RectTransform)transform;
            if (weapons == null || weapons.Length == 0) return;
            for (int i = 0; i < count; i++)
            {
                var go = new GameObject("FloatingWeapon", typeof(RectTransform), typeof(Image));
                go.transform.SetParent(transform, false);
                var img = go.GetComponent<Image>();
                img.sprite = weapons[i % weapons.Length];
                img.preserveAspect = true;
                img.raycastTarget = false;
                float depth = Random.value;                    // 0 = lejos, 1 = cerca
                var c = tint;
                c.a *= Mathf.Lerp(0.45f, 1f, depth);
                c.r *= Mathf.Lerp(0.6f, 1f, depth);
                c.g *= Mathf.Lerp(0.6f, 1f, depth);
                c.b *= Mathf.Lerp(0.7f, 1f, depth);
                img.color = c;

                float size = Mathf.Lerp(sizeRange.x, sizeRange.y, depth);
                var it = new Item
                {
                    rt = (RectTransform)go.transform,
                    vel = new Vector2(Random.Range(-18f, 18f), Random.Range(8f, 22f)) * Mathf.Lerp(0.5f, 1.2f, depth),
                    spin = Random.Range(-14f, 14f),
                    bobPhase = Random.Range(0f, 6.28f),
                    bobAmp = Random.Range(6f, 18f)
                };
                it.rt.sizeDelta = new Vector2(size, size);
                it.rt.localRotation = Quaternion.Euler(0f, 0f, Random.Range(0f, 360f));
                Rect r = _area.rect;
                it.basePos = new Vector2(Random.Range(r.xMin, r.xMax), Random.Range(r.yMin, r.yMax));
                _items.Add(it);
            }
        }

        void Update()
        {
            if (_area == null) return;
            float dt = Time.unscaledDeltaTime;
            float t = Time.unscaledTime;
            Rect r = _area.rect;
            foreach (var it in _items)
            {
                it.basePos += it.vel * dt;
                float pad = it.rt.sizeDelta.x;
                if (it.basePos.y > r.yMax + pad) it.basePos.y = r.yMin - pad;
                if (it.basePos.x > r.xMax + pad) it.basePos.x = r.xMin - pad;
                if (it.basePos.x < r.xMin - pad) it.basePos.x = r.xMax + pad;
                it.rt.anchoredPosition = it.basePos + new Vector2(0f, Mathf.Sin(t * 0.8f + it.bobPhase) * it.bobAmp);
                it.rt.Rotate(0f, 0f, it.spin * dt);
            }
        }
    }
}
