using UnityEngine;

namespace WildWeapon.UI
{
    /// <summary>
    /// Emblemas de habilidad generados por codigo (uno por tipo de habilidad).
    /// Evita depender de arte externo para los iconos de las cards: son glifos
    /// blancos planos que el HUD tiñe con el color del personaje.
    /// </summary>
    public static class AbilityIcons
    {
        private static readonly Sprite[] _cache = new Sprite[3];

        /// <summary>Sprite del emblema de un tipo de habilidad (se cachea).</summary>
        public static Sprite Get(AbilityKind kind)
        {
            int i = (int)kind;
            if (i < 0 || i >= _cache.Length) i = 0;
            if (_cache[i] == null) _cache[i] = Build((AbilityKind)i);
            return _cache[i];
        }

        private static Sprite Build(AbilityKind kind)
        {
            const int size = 128;
            var tex = new Texture2D(size, size, TextureFormat.RGBA32, false);
            tex.name = "WW_AbilityIcon_" + kind;
            tex.wrapMode = TextureWrapMode.Clamp;
            tex.filterMode = FilterMode.Bilinear;

            var px = new Color32[size * size];
            for (int y = 0; y < size; y++)
            {
                for (int x = 0; x < size; x++)
                {
                    float u = ((x + 0.5f) / size) * 2f - 1f;
                    float v = ((y + 0.5f) / size) * 2f - 1f;
                    float a = Shape(kind, u, v);
                    px[y * size + x] = new Color32(255, 255, 255, (byte)Mathf.RoundToInt(Mathf.Clamp01(a) * 255f));
                }
            }
            tex.SetPixels32(px);
            tex.Apply(false, false);

            var sprite = Sprite.Create(tex, new Rect(0f, 0f, size, size), new Vector2(0.5f, 0.5f), 100f,
                                       0, SpriteMeshType.FullRect);
            sprite.name = "WW_AbilityIcon_" + kind;
            return sprite;
        }

        // =================================================================
        // Formas (u,v en -1..1, con la Y hacia arriba)
        // =================================================================

        private static float Shape(AbilityKind kind, float u, float v)
        {
            switch (kind)
            {
                case AbilityKind.CircularSlash: return CircularSlash(u, v);
                case AbilityKind.DashSlash: return DashSlash(u, v);
                default: return RadialBurst(u, v);
            }
        }

        /// <summary>Corte circular: un anillo con una ventana y la hoja cruzando.</summary>
        private static float CircularSlash(float u, float v)
        {
            float r = Mathf.Sqrt(u * u + v * v);
            float ang = Mathf.Atan2(v, u) * Mathf.Rad2Deg;

            float ring = Band(r, 0.60f, 0.115f);
            // Ventana abajo: el corte se lee como una hoja girando.
            if (ang > -128f && ang < -52f) ring = 0f;

            // Hoja: diagonal de abajo-izquierda a arriba-derecha.
            float blade = Band(Mathf.Abs((u - v) * 0.7071f), 0f, 0.09f);
            if (r < 0.16f) blade = 0f;

            return Mathf.Clamp01(Mathf.Max(ring, blade));
        }

        /// <summary>Dash-tajo: dos galones hacia adelante y una estela.</summary>
        private static float DashSlash(float u, float v)
        {
            float a = Mathf.Max(Chevron(u, v, -0.42f), Chevron(u, v, 0.12f));
            // Estela: dos trazos horizontales detras.
            float trail = Band(Mathf.Abs(v - 0.18f), 0f, 0.045f) * Band(u + 0.55f, 0f, 0.42f);
            trail = Mathf.Max(trail, Band(Mathf.Abs(v + 0.18f), 0f, 0.045f) * Band(u + 0.55f, 0f, 0.42f));
            return Mathf.Clamp01(Mathf.Max(a, trail * 0.85f));
        }

        /// <summary>Corte en 8 direcciones: ocho rayos alrededor de un nucleo.</summary>
        private static float RadialBurst(float u, float v)
        {
            float r = Mathf.Sqrt(u * u + v * v);
            float ang = Mathf.Atan2(v, u);
            const int rays = 8;
            float step = Mathf.PI * 2f / rays;
            float a = Mathf.Repeat(ang, step) - step * 0.5f;

            float lateral = Mathf.Abs(Mathf.Sin(a)) * r;
            float ray = 1f - Mathf.Clamp01((lateral - 0.075f) / 0.055f);
            float along = Mathf.Cos(a) * r;
            if (along < 0.24f || along > 0.95f) ray = 0f;

            float core = 1f - Mathf.Clamp01((r - 0.15f) / 0.05f);
            return Mathf.Clamp01(Mathf.Max(ray, core));
        }

        /// <summary>Galon "&gt;" centrado en cx.</summary>
        private static float Chevron(float u, float v, float cx)
        {
            const float halfH = 0.36f;
            const float w = 0.085f;
            float a = Segment(u, v, cx, 0f, cx - 0.30f, halfH, w);
            float b = Segment(u, v, cx, 0f, cx - 0.30f, -halfH, w);
            return Mathf.Max(a, b);
        }

        /// <summary>Distancia con borde suave a un segmento (1 en el segmento, 0 fuera).</summary>
        private static float Segment(float px, float py, float ax, float ay, float bx, float by, float w)
        {
            float dx = bx - ax, dy = by - ay;
            float len2 = dx * dx + dy * dy;
            float t = len2 <= 0f ? 0f : Mathf.Clamp01(((px - ax) * dx + (py - ay) * dy) / len2);
            float qx = ax + dx * t, qy = ay + dy * t;
            float d = Mathf.Sqrt((px - qx) * (px - qx) + (py - qy) * (py - qy));
            return 1f - Mathf.Clamp01(d / w);
        }

        /// <summary>Banda suave alrededor de la distancia d (1 en d, 0 fuera de +-w).</summary>
        private static float Band(float d, float center, float w)
            => 1f - Mathf.Clamp01(Mathf.Abs(d - center) / w);
    }
}
