using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Campo de brasas sutiles para la tienda — versión reducida del sistema del menú
    /// principal (MainMenuController.SpawnMainMenuParticles): polvo dorado en suspensión,
    /// brasas que ascienden desde la mitad inferior y se enfrían al subir
    /// (blanco-ámbar -> naranja -> rojo) y chispas volátiles rápidas.
    /// Se monta detrás del contenido de shop2-root y se anima con el scheduler del
    /// panel (sin coroutines), pausándose con Stop() al cerrar la tienda.
    /// </summary>
    public static class ShopEmberField
    {
        private struct Ember
        {
            public VisualElement element;
            public float x, y, speed, drift, phase, baseOpacity, flickerSpeed;
            public float life, lifeSpeed; // solo brasas: 1 = nacida abajo, 0 = muerta arriba
            public bool isEmber;
        }

        private static readonly List<Ember> _particles = new List<Ember>();
        private static IVisualElementScheduledItem _ticker;
        private static VisualElement _layer;
        private static Texture2D _fadeTex;

        // Paleta de brasa (misma que el menú principal)
        private static readonly Color EmberHot  = new Color(1.00f, 0.86f, 0.55f);
        private static readonly Color EmberWarm = new Color(1.00f, 0.52f, 0.15f);
        private static readonly Color EmberCool = new Color(0.70f, 0.18f, 0.07f);

        /// <summary>Crea la capa de brasas al fondo del elemento y arranca su animación.</summary>
        public static void Start(VisualElement root)
        {
            if (root == null) return;
            Stop();

            _layer = new VisualElement { name = "shop-embers", pickingMode = PickingMode.Ignore };
            _layer.AddToClassList("main-menu-particles");
            _layer.style.opacity = 0.62f; // sutil: por debajo del contenido de la tienda

            // Dentro del catálogo (su fondo es opaco): por encima del suelo en degradado
            // y por debajo de las cards/login/loading.
            var catalog = root.Q<VisualElement>("shop2-catalog");
            if (catalog != null)
            {
                int idx = 0;
                var connected = catalog.Q<VisualElement>("shop-connected-view");
                if (connected != null) idx = catalog.IndexOf(connected);
                catalog.Insert(idx, _layer);
            }
            else
            {
                root.Insert(0, _layer);
            }

            ApplyFloorFade(root);

            // ~40% de la densidad del menú (18 partículas en total)
            SpawnDust(5, "particle-far",  1.4f, 2.6f, 0.08f, 0.14f, 0.35f, 0.60f, 0.6f, 1.1f, 1.4f, 2.6f);
            SpawnDust(3, "particle-mid", 2.4f, 4.4f, 0.10f, 0.16f, 0.55f, 0.95f, 0.9f, 1.6f, 1.8f, 3.2f);
            SpawnEmber(6, "particle-ember-far",  2.0f, 3.4f, 0.30f, 0.45f, 2.6f, 4.2f, 0.7f, 1.3f, 5f, 10f);
            SpawnEmber(4, "particle-ember-mid",  3.4f, 5.6f, 0.34f, 0.48f, 3.4f, 5.2f, 1.0f, 1.8f, 5f, 10f);
            SpawnEmber(3, "particle-spark",      1.4f, 2.6f, 0.50f, 0.75f, 18f,  30f,  2.5f, 5.0f, 14f, 24f);

            _ticker?.Pause();
            _ticker = _layer.schedule.Execute(Tick).Every(16);
        }

        /// <summary>Pausa la animación y retira la capa (llamar al cerrar la tienda).</summary>
        public static void Stop()
        {
            _ticker?.Pause();
            _ticker = null;
            _layer?.RemoveFromHierarchy();
            _layer = null;
            _particles.Clear();
        }

        /// <summary>
        /// Degradado vertical (transparente arriba -> casi negro abajo) sobre la zona
        /// inferior del catálogo: enmascara el espacio muerto bajo la paginación sin
        /// tocar el layout. Textura de 2×64 px generada una sola vez.
        /// </summary>
        private static void ApplyFloorFade(VisualElement root)
        {
            var fade = root.Q<VisualElement>("shop-catalog-fade");
            if (fade == null) return;

            if (_fadeTex == null)
            {
                const int h = 64;
                _fadeTex = new Texture2D(2, h, TextureFormat.RGBA32, false)
                {
                    name = "shop-floor-fade",
                    filterMode = FilterMode.Bilinear,
                    wrapMode = TextureWrapMode.Clamp
                };
                var px = new Color32[2 * h];
                for (int y = 0; y < h; y++)
                {
                    // y = 0 es la fila de ABJO en la textura: ahí va el pico de opacidad
                    float up = 1f - y / (float)(h - 1); // 1 abajo -> 0 arriba
                    byte a = (byte)Mathf.RoundToInt(Mathf.Pow(up, 1.7f) * 240f);
                    px[y * 2] = new Color32(4, 6, 12, a);
                    px[y * 2 + 1] = new Color32(4, 6, 12, a);
                }
                _fadeTex.SetPixels32(px);
                _fadeTex.Apply(false);
            }

            fade.style.backgroundImage = Background.FromTexture2D(_fadeTex);
        }

        private static void AddParticle(string layerClass, float size, float x, float y,
            float baseOpacity, float speed, float drift, float flickerSpeed, bool isEmber)
        {
            var el = new VisualElement { pickingMode = PickingMode.Ignore };
            el.AddToClassList("particle");
            el.AddToClassList(layerClass);
            el.style.position = Position.Absolute;
            el.style.left = new Length(x, LengthUnit.Percent);
            el.style.top = new Length(y, LengthUnit.Percent);
            el.style.width = size;
            el.style.height = size;
            el.style.opacity = baseOpacity;
            _layer.Add(el);

            _particles.Add(new Ember
            {
                element = el,
                x = x, y = y,
                speed = speed, drift = drift,
                phase = Random.Range(0f, Mathf.PI * 2f),
                baseOpacity = baseOpacity,
                flickerSpeed = flickerSpeed,
                isEmber = isEmber,
                life = isEmber ? Mathf.Clamp01((y + 6f) / 112f) : 1f,
                lifeSpeed = isEmber ? speed / 110f : 0f
            });
        }

        private static void SpawnDust(int count, string cls, float minSize, float maxSize,
            float minOpacity, float maxOpacity, float minSpeed, float maxSpeed,
            float minDrift, float maxDrift, float minFlicker, float maxFlicker)
        {
            for (int i = 0; i < count; i++)
            {
                AddParticle(cls, Random.Range(minSize, maxSize),
                    Random.Range(2f, 98f), Random.Range(5f, 95f),
                    Random.Range(minOpacity, maxOpacity),
                    Random.Range(minSpeed, maxSpeed), Random.Range(minDrift, maxDrift),
                    Random.Range(minFlicker, maxFlicker), false);
            }
        }

        private static void SpawnEmber(int count, string cls, float minSize, float maxSize,
            float minOpacity, float maxOpacity, float minSpeed, float maxSpeed,
            float minDrift, float maxDrift, float minFlicker, float maxFlicker)
        {
            for (int i = 0; i < count; i++)
            {
                // Sesgo vertical: las brasas nacen en la mitad inferior
                AddParticle(cls, Random.Range(minSize, maxSize),
                    Random.Range(0f, 100f), Random.Range(35f, 106f),
                    Random.Range(minOpacity, maxOpacity),
                    Random.Range(minSpeed, maxSpeed), Random.Range(minDrift, maxDrift),
                    Random.Range(minFlicker, maxFlicker), true);
            }
        }

        private static void Tick()
        {
            if (_layer == null || _layer.panel == null) return;

            float dt = Time.unscaledDeltaTime;
            float elapsed = Time.unscaledTime;

            for (int i = 0; i < _particles.Count; i++)
            {
                var d = _particles[i];
                var el = d.element;
                if (el == null || el.panel == null) continue;

                if (!d.isEmber)
                {
                    // Polvo: deriva lenta hacia arriba + balanceo + brillo suave
                    d.y -= d.speed * dt;
                    if (d.y < -4f) d.y = 104f;
                    float sway = Mathf.Sin(elapsed * d.drift + d.phase) * (0.8f + d.drift * 0.6f);
                    el.style.top = new Length(d.y, LengthUnit.Percent);
                    el.style.left = new Length(WrapX(d.x + sway), LengthUnit.Percent);
                    el.style.opacity = d.baseOpacity * (0.78f + 0.22f * Mathf.Sin(elapsed * d.flickerSpeed + d.phase));
                }
                else
                {
                    // Brasas y chispas: ascenso continuo; al morir reaparecen bajo el borde
                    d.y -= d.speed * dt;
                    d.life -= d.lifeSpeed * dt;
                    if (d.life <= 0f || d.y < -6f)
                    {
                        d.y = Random.Range(100f, 108f);
                        d.x = Random.Range(0f, 100f);
                        d.life = 1f;
                    }
                    float sway = Mathf.Sin(elapsed * d.drift + d.phase) * (d.speed > 10f ? 0.6f : 1.4f);
                    el.style.top = new Length(d.y, LengthUnit.Percent);
                    el.style.left = new Length(WrapX(d.x + sway), LengthUnit.Percent);

                    float p = 1f - Mathf.Clamp01(d.life); // 0 = recién nacida (abajo) -> 1 = arriba
                    float fadeIn = Mathf.Clamp01(p / 0.10f);
                    float fadeOut = Mathf.Clamp01((1f - p) / 0.30f);
                    float flicker = 0.72f + 0.28f * Mathf.Sin(elapsed * d.flickerSpeed + d.phase);
                    el.style.opacity = d.baseOpacity * fadeIn * fadeOut * flicker;

                    Color c = p < 0.5f
                        ? Color.Lerp(EmberHot, EmberWarm, p * 2f)
                        : Color.Lerp(EmberWarm, EmberCool, (p - 0.5f) * 2f);
                    el.style.backgroundColor = new StyleColor(c);
                }

                _particles[i] = d;
            }
        }

        private static float WrapX(float x)
        {
            if (x < 0f) x += 100f;
            else if (x > 100f) x -= 100f;
            return x;
        }
    }
}
