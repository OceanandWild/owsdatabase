using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.View
{
    /// <summary>
    /// «Destello Táctico» — FX de jugada brillante (!!).
    /// Destello dorado radial + sello «!!» con anillos, sobre la casilla destino.
    /// 43 frames (12 fps de origen, arranque brusco) reproducidos a 30 fps ≈ 1,4 s.
    /// Opt-out: si no hay tablero, no hace nada. Solo se reproduce comprada y equipada.
    /// Arte: frames 2D en Resources/BrilliantFlash/frame_XXXX (+ fallback a disco).
    /// </summary>
    public class BrilliantFx : MonoBehaviour
    {
        public static BrilliantFx Instance { get; private set; }

        public static bool ReduceMotion = false;

        // ── Ficha de tienda (pestaña ANIMACIONES) ──
        public const string AnimId = "anim_brilliant_destello";
        public const int PriceGambits = 1300;
        private const string KEY_OWNED = "Anim_Owned_anim_brilliant_destello";
        private const string KEY_EQUIPPED = "Anim_Equipped_Brilliant";

        public static bool IsOwned()
        {
            try { return PlayerPrefs.GetInt(KEY_OWNED, 0) == 1; }
            catch { return false; }
        }

        public static bool IsEquipped()
        {
            try { return PlayerPrefs.GetString(KEY_EQUIPPED, "") == AnimId; }
            catch { return false; }
        }

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

        private const float FrameRate = 30f;
        private const float OverlayTiles = 2.2f; // ancho del destello en casillas
        private const float IconTiles = 2.0f;     // ancho del icono ilustrado
        private const float IconDuration = 1.4f;

        private bool _playing;
        private static Sprite[] _cachedFrames;
        private static Sprite _cachedArt;
        private static Sprite _cachedIconRing;

        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("BrilliantFx");
            go.AddComponent<BrilliantFx>();
        }

        /// <summary>Entry point seguro para GameManager: nunca lanza.</summary>
        public static void PlayAt(Vector2IntCustom targetPos)
        {
            try
            {
                EnsureExists();
                if (Instance != null) Instance.PlayInternal(targetPos);
            }
            catch (System.Exception e)
            {
                Debug.LogWarning("[BrilliantFx] skip: " + e.Message);
            }
        }

        /// <summary>Frames del clip (cacheados; Resources + fallback a disco como BoardView).</summary>
        internal static Sprite[] Frames()
        {
            if (_cachedFrames != null && _cachedFrames.Length > 0) return _cachedFrames;
            var list = new List<Sprite>();
            try
            {
                var loaded = Resources.LoadAll<Sprite>("BrilliantFlash");
                if (loaded != null)
                {
                    foreach (var s in loaded)
                        if (s != null && s.name.StartsWith("frame_")) list.Add(s);
                }
            }
            catch { /* fallback a disco */ }
            if (list.Count == 0)
            {
                try
                {
                    string folder = System.IO.Path.Combine(Application.dataPath, "Resources", "BrilliantFlash");
                    if (System.IO.Directory.Exists(folder))
                    {
                        foreach (string file in System.IO.Directory.GetFiles(folder, "frame_*.png"))
                        {
                            try
                            {
                                byte[] bytes = System.IO.File.ReadAllBytes(file);
                                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                                if (tex.LoadImage(bytes))
                                {
                                    tex.filterMode = FilterMode.Bilinear;
                                    var spr = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                                    spr.name = System.IO.Path.GetFileNameWithoutExtension(file);
                                    list.Add(spr);
                                }
                            }
                            catch { /* un frame roto no tumba el clip */ }
                        }
                    }
                }
                catch { /* sin frames: el trigger no hace nada */ }
            }
            list.Sort((a, b) => string.Compare(a.name, b.name, System.StringComparison.Ordinal));
            _cachedFrames = list.ToArray();
            Debug.Log($"[BrilliantFx] Frames cargados: {_cachedFrames.Length} " +
                      $"(Resources/Single o disco). Esperados: 43 en Resources/BrilliantFlash/frame_XXXX.png");
            return _cachedFrames;
        }

        /// <summary>Arte para la card/hero de la tienda y los pases (icono ilustrado).</summary>
        public static Sprite GetArtSprite()
        {
            if (_cachedArt != null) return _cachedArt;

            // Icono propio: es el arte oficial de la animación.
            Sprite icon = AnimIconSprites.Destello;
            if (icon != null) { _cachedArt = icon; return _cachedArt; }

            // Respaldo: frame del sello «!!» del clip viejo.
            try
            {
                Sprite[] frames = Frames();
                if (frames != null && frames.Length > 0)
                {
                    _cachedArt = frames[Mathf.Clamp(Mathf.FloorToInt(frames.Length * 0.35f), 0, frames.Length - 1)];
                    return _cachedArt;
                }
            }
            catch { /* sin arte: la card usa el icono de texto */ }
            return null;
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }

        private void PlayInternal(Vector2IntCustom targetPos)
        {
            if (_playing) return;
            // Solo se reproduce si está comprada y equipada (se vende en la tienda).
            if (!IsEquipped()) return;
            var bv = BoardView.Instance;
            if (bv == null) return;

            Vector3 world = bv.GetWorldPosition(targetPos.Row, targetPos.Col);

            // Preferencia: icono ilustrado animado por código. Si falta, clip de frames.
            Sprite icon = AnimIconSprites.Destello;
            if (icon != null)
            {
                _playing = true;
                StartCoroutine(IconRoutine(world, icon));
                return;
            }

            Sprite[] frames = Frames();
            if (frames == null || frames.Length == 0) return;
            _playing = true;
            StartCoroutine(BrilliantRoutine(world, frames));
        }

        /// <summary>
        /// Destello Táctico con el icono ilustrado: entra con rebote, late dos
        /// veces, gira levemente y se funde mientras dos anillos dorados se abren.
        /// </summary>
        private IEnumerator IconRoutine(Vector3 targetWorld, Sprite icon)
        {
            float tile = 1.8f;
            try
            {
                GameObject tiles = GameObject.Find("BoardTiles");
                if (tiles != null && tiles.transform.childCount > 0)
                    tile = tiles.transform.GetChild(0).localScale.x;
            }
            catch { /* 1.8f por defecto */ }

            float iconWorld = icon.bounds.size.x > 0.01f ? icon.bounds.size.x : 5.12f;
            float iconScale = (tile * IconTiles) / iconWorld;

            GameObject root = new GameObject("DestelloTactico");
            root.transform.position = targetWorld;

            var iconGo = new GameObject("Icon");
            iconGo.transform.SetParent(root.transform, false);
            iconGo.transform.localPosition = new Vector3(0f, 0f, -0.2f);
            var iconSr = iconGo.AddComponent<SpriteRenderer>();
            iconSr.sprite = icon;
            iconSr.sortingOrder = 38;
            iconSr.color = new Color(1f, 1f, 1f, 0f);
            iconGo.transform.localScale = Vector3.zero;

            // Dos anillos dorados que abren el destello por detrás.
            Sprite ringSprite = IconRing();
            var rings = new List<SpriteRenderer>(2);
            if (ringSprite != null)
            {
                for (int i = 0; i < 2; i++)
                {
                    var ringGo = new GameObject("Ring_" + i);
                    ringGo.transform.SetParent(root.transform, false);
                    ringGo.transform.localPosition = new Vector3(0f, 0f, 0.1f + i * 0.1f);
                    var sr = ringGo.AddComponent<SpriteRenderer>();
                    sr.sprite = ringSprite;
                    sr.sortingOrder = 37;
                    sr.color = new Color(1f, 0.86f, 0.45f, 0f);
                    rings.Add(sr);
                }
            }

            float t = 0f;
            while (t < IconDuration)
            {
                t += Time.deltaTime;
                float p = Mathf.Clamp01(t / IconDuration);

                // Pop con rebote (0 → 1.18 → 1), luego latido suave y fundido.
                float pop = Mathf.Clamp01(p / 0.16f);
                float ease = 1f - Mathf.Pow(1f - pop, 3f);
                float overshoot = 1f + 0.18f * Mathf.Sin(pop * Mathf.PI);
                float beat = p > 0.28f && p < 0.72f
                    ? 1f + 0.045f * Mathf.Sin((p - 0.28f) * Mathf.PI * 6f)
                    : 1f;
                float fadeOut = 1f - Mathf.Clamp01((p - 0.66f) / 0.28f);
                float scale = Mathf.Max(0.001f, ease * overshoot * beat * Mathf.Lerp(1f, 0.88f, 1f - fadeOut));

                if (iconGo == null || iconSr == null) break;
                iconGo.transform.localScale = new Vector3(iconScale * scale, iconScale * scale, 1f);
                float angle = ReduceMotion ? 0f : Mathf.Sin(p * Mathf.PI * 2f) * 3.5f;
                iconGo.transform.localRotation = Quaternion.Euler(0f, 0f, angle);

                Color c = iconSr.color;
                c.a = Mathf.Clamp01(pop * 1.4f) * fadeOut;
                iconSr.color = c;

                for (int i = 0; i < rings.Count; i++)
                {
                    float rp = Mathf.Clamp01((p - 0.02f - i * 0.10f) / 0.62f);
                    float rScale = (tile * Mathf.Lerp(0.55f, 2.7f, rp)) /
                                   Mathf.Max(0.001f, ringSprite.bounds.size.x);
                    rings[i].transform.localScale = new Vector3(rScale, rScale, 1f);
                    Color rc = rings[i].color;
                    rc.a = Mathf.Sin(rp * Mathf.PI) * (i == 0 ? 0.85f : 0.55f);
                    rings[i].color = rc;
                }

                yield return null;
            }

            if (root != null) Destroy(root);
            _playing = false;
        }

        /// <summary>Anillo suave reutilizado como onda del destello (tintado en oro).</summary>
        private static Sprite IconRing()
        {
            if (_cachedIconRing != null) return _cachedIconRing;
            try
            {
                Texture2D tex = DoubleCheckFx.MakeRingTexture();
                _cachedIconRing = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                    new Vector2(0.5f, 0.5f), 100f);
                _cachedIconRing.name = "destello_ring";
            }
            catch { _cachedIconRing = null; }
            return _cachedIconRing;
        }

        private IEnumerator BrilliantRoutine(Vector3 targetWorld, Sprite[] frames)
        {
            // Tamaño de casilla en mundo (las Tile se escalan exactamente a tileSize)
            float tile = 1.8f;
            try
            {
                GameObject tiles = GameObject.Find("BoardTiles");
                if (tiles != null && tiles.transform.childCount > 0)
                    tile = tiles.transform.GetChild(0).localScale.x;
            }
            catch { /* 1.8f por defecto */ }

            float frameW = 3.41f;
            try
            {
                if (frames[0] != null && frames[0].bounds.size.x > 0.01f)
                    frameW = frames[0].bounds.size.x;
            }
            catch { /* 3.41f por defecto (341px a 100 ppu) */ }
            float s = (tile * OverlayTiles) / frameW;

            GameObject root = new GameObject("DestelloTactico");
            root.transform.position = targetWorld;
            root.transform.localScale = new Vector3(s, s, 1f);
            var sr = root.AddComponent<SpriteRenderer>();
            sr.sortingOrder = 38;
            sr.color = new Color(1f, 1f, 1f, 1f);

            // Movimiento reducido: mitad de frames (el fundido ya viene horneado)
            int step = ReduceMotion ? 2 : 1;
            float frameTime = (1f / FrameRate) * step;
            for (int i = 0; i < frames.Length; i += step)
            {
                if (root == null || sr == null) break;
                if (frames[i] != null) sr.sprite = frames[i];
                yield return new WaitForSeconds(frameTime);
            }

            if (root != null) Destroy(root);
            _playing = false;
        }
    }
}
