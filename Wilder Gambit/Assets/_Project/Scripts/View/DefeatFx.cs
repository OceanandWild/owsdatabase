using System.Collections;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.View
{
    /// <summary>
    /// «Ceniza al Viento» — FX de derrota (mate en contra).
    /// Las piezas se apagan en gris, suben brasas con tu ember_soft_64 y una
    /// ráfaga (wind_streak_256) se las lleva a la izquierda sobre niebla
    /// (smoke_grey_256). 2.0 s, no bloquea input ni el modal.
    /// Opt-out: si no hay BoardView/cámara, no hace nada (no rompe partidas ni tests).
    /// Sonido 100% procedural (ruido filtrado + thud): no necesita WAV.
    /// </summary>
    public class DefeatFx : MonoBehaviour
    {
        public static DefeatFx Instance { get; private set; }

        /// <summary>Futuro ajuste de accesibilidad. Hoy no hay setting: queda en false.</summary>
        public static bool ReduceMotion = false;

        // ── Ficha de tienda (pestaña ANIMACIONES) ──
        public const string AnimId = "anim_defeat_ceniza";
        public const int PriceGambits = 650;
        private const string KEY_OWNED = "Anim_Owned_anim_defeat_ceniza";
        private const string KEY_EQUIPPED = "Anim_Equipped_Defeat";

        /// <summary>¿Comprada? Clave estable: no cambia al rehacer catálogos.</summary>
        public static bool IsOwned()
        {
            try { return PlayerPrefs.GetInt(KEY_OWNED, 0) == 1; }
            catch { return false; }
        }

        /// <summary>¿Equipada en la ranura Derrota? (1 animación activa por gatillo).</summary>
        public static bool IsEquipped()
        {
            try { return PlayerPrefs.GetString(KEY_EQUIPPED, "") == AnimId; }
            catch { return false; }
        }

        /// <summary>Compra: desbloquea y equipa (una sola animación por gatillo).</summary>
        public static void OwnAndEquip()
        {
            try
            {
                PlayerPrefs.SetInt(KEY_OWNED, 1);
                PlayerPrefs.SetString(KEY_EQUIPPED, AnimId);
                PlayerPrefs.Save();
            }
            catch { /* persistencia nunca bloquea la compra */ }
        }

        /// <summary>
        /// Desbloquea sin equipar. Para premios que no tocan el loadout del jugador
        /// (p. ej. el pase de temporada): regalar la animación no debe sustituir
        /// la que ya tenía puesta.
        /// </summary>
        public static void Own()
        {
            try { PlayerPrefs.SetInt(KEY_OWNED, 1); PlayerPrefs.Save(); }
            catch { /* persistencia nunca bloquea el premio */ }
        }

        /// <summary>Atajo de QA en editor (sin pasar por caja).</summary>
        public static void DebugGrant() => OwnAndEquip();

        private const float Duration = 2.0f;

        private static Sprite _cachedArt;

        /// <summary>Arte para la card/hero de la tienda y los pases (icono ilustrado).</summary>
        public static Sprite GetArtSprite()
        {
            if (_cachedArt != null) return _cachedArt;

            // Icono propio: tornado de ceniza, el arte oficial de la animación.
            Sprite icon = AnimIconSprites.Ceniza;
            if (icon != null) { _cachedArt = icon; return _cachedArt; }

            // Respaldo: brasa del Atelier o procedural.
            try
            {
                Sprite s = Resources.Load<Sprite>("FX/ember_soft_64");
                if (s != null) { _cachedArt = s; return s; }
                Texture2D t = Resources.Load<Texture2D>("FX/ember_soft_64");
                if (t != null)
                {
                    _cachedArt = Sprite.Create(t, new Rect(0, 0, t.width, t.height),
                        new Vector2(0.5f, 0.5f), 100f);
                    return _cachedArt;
                }
            }
            catch { /* procedural */ }

            _cachedArt = MakeProceduralEmberShared();
            return _cachedArt;
        }

        [Header("Override opcional (si no, carga de Resources/FX)")]
        [SerializeField] private Sprite emberSprite;
        [SerializeField] private Sprite streakSprite;
        [SerializeField] private Sprite smokeSprite;

        private bool _playing;

        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("DefeatFx");
            go.AddComponent<DefeatFx>();
        }

        /// <summary>Entry point seguro para GameManager: nunca lanza.</summary>
        public static void PlayDefeat()
        {
            try
            {
                EnsureExists();
                if (Instance != null) Instance.PlayInternal();
            }
            catch (System.Exception e)
            {
                Debug.LogWarning("[DefeatFx] skip: " + e.Message);
            }
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }

        private void PlayInternal()
        {
            if (_playing) return;
            // Solo se reproduce si está comprada y equipada (se vende en la tienda).
            if (!IsEquipped()) return;
            // Sin tablero ni cámara no hay dónde pintar: salir en silencio.
            if (BoardView.Instance == null && Camera.main == null) return;
            _playing = true;
            StartCoroutine(DefeatRoutine());
        }

        private IEnumerator DefeatRoutine()
        {
            // ── 1. Medir tablero (público, sin tocar BoardView) ──
            Vector3 center = Vector3.zero;
            float half = 7f;
            var bv = BoardView.Instance;
            if (bv != null)
            {
                try
                {
                    Vector3 a = bv.GetWorldPosition(0, 0);
                    Vector3 b = bv.GetWorldPosition(7, 7);
                    center = (a + b) * 0.5f;
                    half = Mathf.Abs(b.x - a.x) * 0.5f * 8f / 7f;
                    half = Mathf.Clamp(half, 3f, 20f);
                }
                catch { /* fallback abajo */ }
            }
            else if (Camera.main != null)
            {
                half = Camera.main.orthographicSize * 0.85f;
                center = Camera.main.transform.position;
                center.z = 0f;
            }

            // ── 2. Sprites (Resources → fichero → procedural) ──
            Sprite ember = emberSprite ?? LoadSprite("FX/ember_soft_64",
                "_Project/Textures/FX/ember_soft_64.png", MakeProceduralEmber());
            Sprite streak = streakSprite ?? LoadSprite("FX/wind_streak_256",
                "_Project/Textures/FX/wind_streak_256.png", null);
            Sprite smoke = smokeSprite ?? LoadSprite("FX/smoke_grey_256",
                "_Project/Textures/FX/smoke_grey_256.jpg", null);

            // El PNG de brasa mide 2048×1143 (no 64 px): se normaliza por su
            // ancho en mundo para que las brasas conserven el tamaño de diseño
            // y no tapen el resto del efecto.
            float emberArtW = 0.64f;
            try
            {
                if (ember != null && ember.bounds.size.x > 0.01f)
                    emberArtW = ember.bounds.size.x * 0.42f; // el brillo ocupa ~42% del lienzo
            }
            catch { /* sprite sin bounds legibles: se usa 0.64 */ }

            GameObject root = new GameObject("CenizaAlViento");
            root.transform.position = new Vector3(center.x, center.y, 0f);

            // ── 2b. Emblema del tornado de ceniza (si el icono está disponible) ──
            Sprite icon = AnimIconSprites.Ceniza;
            GameObject iconGo = null;
            SpriteRenderer iconSr = null;
            float iconBase = 1f;
            if (icon != null)
            {
                float iconWorld = icon.bounds.size.x > 0.01f ? icon.bounds.size.x : 5.12f;
                iconBase = (half * 0.95f) / iconWorld;
                iconGo = new GameObject("Emblem");
                iconGo.transform.SetParent(root.transform, false);
                iconGo.transform.localPosition = new Vector3(0f, 0f, -2.5f);
                iconGo.transform.localScale = new Vector3(iconBase * 0.85f, iconBase * 0.85f, 1f);
                iconSr = iconGo.AddComponent<SpriteRenderer>();
                iconSr.sprite = icon;
                iconSr.sortingOrder = 44; // sobre la niebla, debajo de brasas y ráfagas
                iconSr.color = new Color(1f, 1f, 1f, 0f);
            }

            // ── 3. Niebla gris a pantalla de tablero ──
            SpriteRenderer smokeSr = null;
            if (smoke != null)
            {
                var smokeGo = new GameObject("Smoke");
                smokeGo.transform.SetParent(root.transform, false);
                smokeSr = smokeGo.AddComponent<SpriteRenderer>();
                smokeSr.sprite = smoke;
                smokeSr.sortingOrder = 40;
                smokeSr.color = new Color(0.55f, 0.58f, 0.65f, 0f);
                float w = Mathf.Max(0.001f, smoke.bounds.size.x);
                float cover = (half * 2.2f) / w;
                smokeGo.transform.localScale = new Vector3(cover, cover, 1f);
            }

            // ── 4. Brasas (24 normal / 8 reducido) ──
            int emberCount = ReduceMotion ? 8 : 24;
            var embers = new List<Transform>(emberCount);
            var emberSeed = new List<Vector4>(emberCount); // x0,y0,speed,phase
            var emberSr = new List<SpriteRenderer>(emberCount);
            Material additive = null;
            try
            {
                Shader sh = Shader.Find("Particles/Additive");
                if (sh != null) additive = new Material(sh);
            }
            catch { additive = null; }

            for (int i = 0; i < emberCount; i++)
            {
                var go = new GameObject("Ember_" + i);
                go.transform.SetParent(root.transform, false);
                float px = Random.Range(-half, half);
                float py = Random.Range(-half * 0.7f, half * 0.7f);
                go.transform.localPosition = new Vector3(px, py, -1f);
                float s = Random.Range(0.10f, 0.30f) * half * 0.28f;
                float k = s / Mathf.Max(0.01f, emberArtW);
                go.transform.localScale = new Vector3(k, k, 1f);
                var sr = go.AddComponent<SpriteRenderer>();
                sr.sortingOrder = 45;
                if (ember != null) sr.sprite = ember;
                if (additive != null) sr.material = additive;
                // Oro -> naranja según altura inicial
                float h = Mathf.InverseLerp(-half, half, py);
                sr.color = Color.Lerp(new Color(1f, 0.85f, 0.54f, 0f),
                                      new Color(0.89f, 0.44f, 0.11f, 0f), h);
                embers.Add(go.transform);
                emberSeed.Add(new Vector4(px, py, Random.Range(0.6f, 1.6f), Random.Range(0f, Mathf.PI * 2f)));
                emberSr.Add(sr);
            }

            // ── 5. Ráfagas (0 si reducido) ──
            var streaks = new List<Transform>();
            if (!ReduceMotion && streak != null)
            {
                for (int k = 0; k < 2; k++)
                {
                    var go = new GameObject("Streak_" + k);
                    go.transform.SetParent(root.transform, false);
                    float y = (k == 0 ? 0.25f : -0.30f) * half;
                    go.transform.localPosition = new Vector3(half * 1.2f, y, -2f);
                    float len = (half * 2.4f) / Mathf.Max(0.001f, streak.bounds.size.x);
                    float thi = (half * 0.35f) / Mathf.Max(0.001f, streak.bounds.size.y);
                    go.transform.localScale = new Vector3(len, thi, 1f);
                    var sr = go.AddComponent<SpriteRenderer>();
                    sr.sprite = streak;
                    sr.sortingOrder = 46;
                    sr.color = new Color(1f, 1f, 1f, 0f);
                    streaks.Add(go.transform);
                }
            }

            // ── 6. Viento procedural (no necesita WAV) ──
            try { PlayProceduralWind(); } catch { /* audio nunca bloquea */ }

            // ── 7. Animar 2.0 s ──
            float t = 0f;
            float smokePeak = ReduceMotion ? 0.15f : 0.28f;
            while (t < Duration)
            {
                t += Time.deltaTime;
                float p = Mathf.Clamp01(t / Duration);

                if (smokeSr != null)
                {
                    float aIn = Mathf.Clamp01(p / 0.25f);
                    float aOut = Mathf.Clamp01((1f - p) / 0.25f);
                    Color c = smokeSr.color;
                    c.a = smokePeak * Mathf.Min(aIn, aOut);
                    smokeSr.color = c;
                }

                for (int i = 0; i < embers.Count; i++)
                {
                    Vector4 sd = emberSeed[i];
                    // Deriva a la izquierda + subida leve + sway
                    float dx = sd.x - p * half * (1.1f + sd.z * 0.5f);
                    float dy = sd.y + p * half * 0.45f * sd.z
                             + Mathf.Sin(p * 6f + sd.w) * half * 0.05f;
                    embers[i].localPosition = new Vector3(dx, dy, -1f);
                    Color c = emberSr[i].color;
                    float fadeIn = Mathf.Clamp01(p / 0.15f);
                    float fadeOut = Mathf.Clamp01((1f - p) / 0.35f);
                    c.a = fadeIn * fadeOut * 0.95f;
                    emberSr[i].color = c;
                }

                for (int k = 0; k < streaks.Count; k++)
                {
                    Transform st = streaks[k];
                    float fromX = half * 1.2f;
                    float toX = -half * 1.4f;
                    float pk = Mathf.Clamp01((p - k * 0.15f) / 0.85f);
                    st.localPosition = new Vector3(Mathf.Lerp(fromX, toX, pk),
                        st.localPosition.y, -2f);
                    var sr = st.GetComponent<SpriteRenderer>();
                    if (sr != null)
                    {
                        Color c = sr.color;
                        c.a = Mathf.Sin(pk * Mathf.PI) * 0.7f;
                        sr.color = c;
                    }
                }

                // ── Emblema: se materializa y el viento se lo lleva a la izquierda ──
                if (iconGo != null && iconSr != null)
                {
                    float inA = Mathf.Clamp01((p - 0.06f) / 0.16f);
                    float outA = Mathf.Clamp01((1f - p) / 0.28f);
                    float drift = Mathf.Lerp(0f, -half * 0.55f, Mathf.Clamp01(p / 0.9f));
                    iconGo.transform.localPosition = new Vector3(drift,
                        Mathf.Sin(p * Mathf.PI * 1.2f) * half * 0.02f, -2.5f);
                    float s = iconBase * Mathf.Lerp(0.85f, 1.02f, Mathf.Clamp01(p / 0.7f));
                    iconGo.transform.localScale = new Vector3(s, s, 1f);
                    iconGo.transform.localRotation = Quaternion.Euler(0f, 0f,
                        ReduceMotion ? 0f : Mathf.Sin(p * Mathf.PI * 1.6f) * 3f);
                    Color ci = iconSr.color;
                    ci.a = inA * outA * 0.92f;
                    iconSr.color = ci;
                }

                yield return null;
            }

            Destroy(root);
            _playing = false;
        }

        // ── Carga resiliente: Resources → fichero → fallback ──
        private Sprite LoadSprite(string resourcePath, string projectRelative, Sprite fallback)
        {
            try
            {
                Sprite s = Resources.Load<Sprite>(resourcePath);
                if (s != null) return s;
                Texture2D t = Resources.Load<Texture2D>(resourcePath);
                if (t != null) return Sprite.Create(t,
                    new Rect(0, 0, t.width, t.height), new Vector2(0.5f, 0.5f), 100f);
            }
            catch { /* sigue a fichero */ }

            try
            {
                string full = System.IO.Path.Combine(Application.dataPath, projectRelative);
                if (System.IO.File.Exists(full))
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(full);
                    var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                    if (tex.LoadImage(bytes))
                        return Sprite.Create(tex,
                            new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                }
            }
            catch { /* fallback */ }

            return fallback;
        }

        private Sprite MakeProceduralEmber() => MakeProceduralEmberShared();

        internal static Sprite MakeProceduralEmberShared()
        {
            const int n = 64;
            var tex = new Texture2D(n, n, TextureFormat.RGBA32, false);
            tex.name = "ember_procedural";
            Color hot = new Color(1f, 0.85f, 0.54f, 1f);
            Color mid = new Color(0.89f, 0.44f, 0.11f, 1f);
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float dx = (x - n / 2f) / (n / 2f);
                    float dy = (y - n / 2f) / (n / 2f);
                    float d = Mathf.Clamp01(Mathf.Sqrt(dx * dx + dy * dy));
                    float a = Mathf.Pow(1f - d, 1.8f);
                    Color c = Color.Lerp(hot, mid, d) * a;
                    c.a = a;
                    tex.SetPixel(x, y, c);
                }
            tex.Apply(false);
            return Sprite.Create(tex, new Rect(0, 0, n, n), new Vector2(0.5f, 0.5f), 100f);
        }

        private void PlayProceduralWind()
        {
            const int rate = 22050;
            const float len = 1.8f;
            int n = Mathf.RoundToInt(rate * len);
            var data = new float[n];
            float lp = 0f;
            for (int i = 0; i < n; i++)
            {
                float t = i / (float)rate;
                float noise = Random.Range(-1f, 1f);
                lp += 0.08f * (noise - lp); // whoosh grave
                float env = Mathf.Clamp01(t / 0.3f) * Mathf.Clamp01((len - t) / 0.6f);
                float thud = Mathf.Sin(t * 2f * Mathf.PI * 65f) * Mathf.Exp(-t * 6f) * 0.6f;
                data[i] = Mathf.Clamp((lp * 0.9f + thud) * env * 0.5f, -1f, 1f);
            }
            AudioClip clip = AudioClip.Create("DefeatWind", n, 1, rate, false);
            clip.SetData(data, 0);
            var src = gameObject.AddComponent<AudioSource>();
            src.playOnAwake = false;
            src.spatialBlend = 0f;
            src.volume = 0.5f;
            src.clip = clip;
            src.Play();
            Destroy(src, len + 0.5f);
        }
    }
}
