using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.View
{
    /// <summary>
    /// «Cometa Ígnea» — FX de fork del caballo.
    /// El cometa de fuego viaja, impacta con onda de choque y lluvia de brasas
    /// sobre la casilla destino del fork. 48 frames a 40 fps ≈ 1,2 s.
    /// Opt-out: si no hay tablero, no hace nada. Solo se reproduce comprada y equipada.
    /// Arte: frames 2D en Resources/ForkComet/frame_XXXX (fondo ya recortado a alfa).
    /// </summary>
    public class ForkCometFx : MonoBehaviour
    {
        public static ForkCometFx Instance { get; private set; }

        public static bool ReduceMotion = false;

        // ── Ficha de tienda (pestaña ANIMACIONES) ──
        public const string AnimId = "anim_fork_cometa";
        public const int PriceTides = 99;
        private const string KEY_OWNED = "Anim_Owned_anim_fork_cometa";
        private const string KEY_EQUIPPED = "Anim_Equipped_Fork";

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

        private const float FrameRate = 40f;
        // El núcleo de fuego ocupa ~1/4 del frame (mucho aire transparente):
        // 4,5 casillas de overlay ≈ 1,5 de fuego visible sobre el fork.
        private const float OverlayTiles = 4.5f; // ancho del cometa en casillas

        private const float IconTiles = 1.9f;    // ancho del icono en el impacto
        private const float IconDuration = 1.2f;
        private const float Travel = 0.45f;      // vuelo hasta la casilla

        private bool _playing;
        private static Sprite[] _cachedFrames;
        private static Sprite _cachedArt;
        private static Sprite _cachedRing;
        private static Sprite _cachedEmber;

        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("ForkCometFx");
            go.AddComponent<ForkCometFx>();
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
                Debug.LogWarning("[ForkCometFx] skip: " + e.Message);
            }
        }

        /// <summary>Frames del clip (cacheados; Resources).</summary>
        internal static Sprite[] Frames()
        {
            if (_cachedFrames != null && _cachedFrames.Length > 0) return _cachedFrames;
            var list = new List<Sprite>();
            try
            {
                var loaded = Resources.LoadAll<Sprite>("ForkComet");
                if (loaded != null)
                {
                    foreach (var s in loaded)
                        if (s != null && s.name.StartsWith("frame_")) list.Add(s);
                }
            }
            catch { /* sin frames: el trigger no hace nada */ }
            list.Sort((a, b) => string.Compare(a.name, b.name, System.StringComparison.Ordinal));
            _cachedFrames = list.ToArray();
            Debug.Log($"[ForkCometFx] Frames cargados: {_cachedFrames.Length} " +
                      $"(Resources/ForkComet/frame_XXXX.png). Esperados: 48.");
            return _cachedFrames;
        }

        /// <summary>Arte para la card/hero de la tienda y los pases (icono ilustrado).</summary>
        public static Sprite GetArtSprite()
        {
            if (_cachedArt != null) return _cachedArt;

            // Icono propio: caballo de fuego, el arte oficial de la animación.
            Sprite icon = AnimIconSprites.Cometa;
            if (icon != null) { _cachedArt = icon; return _cachedArt; }

            // Respaldo: frame del impacto del clip viejo.
            try
            {
                Sprite[] frames = Frames();
                if (frames != null && frames.Length > 0)
                {
                    _cachedArt = frames[Mathf.Clamp(Mathf.FloorToInt(frames.Length * 0.40f), 0, frames.Length - 1)];
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

            try { WilderGambit.Audio.MusicManager.Instance?.PlayForkCometSound(); }
            catch { /* el FX visual nunca depende del audio */ }

            // Preferencia: icono ilustrado viajando y estallando. Si falta, clip de frames.
            Sprite icon = AnimIconSprites.Cometa;
            if (icon != null)
            {
                _playing = true;
                StartCoroutine(IconRoutine(world, icon));
                return;
            }

            Sprite[] frames = Frames();
            if (frames == null || frames.Length == 0) return;
            _playing = true;
            StartCoroutine(ForkCometRoutine(world, frames));
        }

        /// <summary>
        /// Cometa Ígnea con el icono ilustrado: entra desde abajo-izquierda con
        /// estela de brasas, impacta con onda de choque y se funde sobre la casilla.
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
            Vector3 start = targetWorld + new Vector3(-tile * 4.2f, -tile * 3.0f, 0f);

            GameObject root = new GameObject("CometaIgnea");
            root.transform.position = start;

            var iconGo = new GameObject("Icon");
            iconGo.transform.SetParent(root.transform, false);
            var iconSr = iconGo.AddComponent<SpriteRenderer>();
            iconSr.sprite = icon;
            iconSr.sortingOrder = 38;
            iconSr.color = new Color(1f, 1f, 1f, 0f);

            // Estela: brasas detrás del vuelo (se apagan antes del impacto).
            var trail = new List<SpriteRenderer>();
            var trailSeed = new List<Vector3>(); // x0,y0,phase
            if (_cachedEmber == null)
            {
                try { _cachedEmber = DefeatFx.MakeProceduralEmberShared(); }
                catch { _cachedEmber = null; }
            }
            Sprite ember = _cachedEmber;
            if (!ReduceMotion && ember != null)
            {
                for (int i = 0; i < 9; i++)
                {
                    var go = new GameObject("Trail_" + i);
                    go.transform.SetParent(root.transform, false);
                    var sr = go.AddComponent<SpriteRenderer>();
                    sr.sprite = ember;
                    sr.sortingOrder = 37;
                    sr.color = new Color(1f, 0.62f, 0.20f, 0f);
                    float s = tile * Random.Range(0.16f, 0.34f);
                    go.transform.localScale = new Vector3(s, s, 1f);
                    trail.Add(sr);
                    trailSeed.Add(new Vector3(Random.Range(0.6f, 1.9f), Random.Range(-0.9f, 0.4f),
                        Random.Range(0f, 1f)));
                }
            }

            // Onda de choque (anillo del impacto).
            Sprite ringSprite = RingSprite();
            SpriteRenderer shock = null;
            if (ringSprite != null)
            {
                var go = new GameObject("Shockwave");
                go.transform.SetParent(root.transform, false);
                go.transform.localPosition = new Vector3(0f, 0f, 0.1f);
                shock = go.AddComponent<SpriteRenderer>();
                shock.sprite = ringSprite;
                shock.sortingOrder = 37;
                shock.color = new Color(1f, 0.72f, 0.28f, 0f);
            }

            Camera cam = Camera.main;
            Vector3 camBase = cam != null ? cam.transform.position : Vector3.zero;
            bool shaking = false;

            float t = 0f;
            float impactP = Travel / IconDuration;
            while (t < IconDuration)
            {
                t += Time.deltaTime;
                float p = Mathf.Clamp01(t / IconDuration);

                if (root == null || iconGo == null || iconSr == null) break;

                // ── Vuelo ──
                if (p < impactP)
                {
                    float k = Mathf.Clamp01(p / impactP);
                    float ease = 1f - Mathf.Pow(1f - k, 2.2f);
                    root.transform.position = Vector3.Lerp(start, targetWorld, ease);
                    float sc = Mathf.Lerp(1.15f, 1.6f, ease) * tile / iconWorld;
                    iconGo.transform.localScale = new Vector3(sc, sc, 1f);
                    // El morro del caballo apunta arriba-derecha: inclina el icono al viajar.
                    float rot = ReduceMotion ? 0f : Mathf.Lerp(-16f, 0f, ease);
                    iconGo.transform.localRotation = Quaternion.Euler(0f, 0f, rot);
                    Color c = iconSr.color;
                    c.a = Mathf.Clamp01(k * 2f);
                    iconSr.color = c;
                }
                else
                {
                    // ── Impacto: golpe de escala + fundido ──
                    float k = Mathf.Clamp01((p - impactP) / (1f - impactP));
                    float punch = 1f + 0.28f * Mathf.Sin(Mathf.Clamp01(k / 0.35f) * Mathf.PI);
                    float scale = Mathf.Max(0.001f, (IconTiles * tile) / iconWorld * punch);
                    iconGo.transform.localScale = new Vector3(scale, scale, 1f);
                    iconGo.transform.localRotation = Quaternion.identity;
                    Color c = iconSr.color;
                    c.a = 1f - Mathf.Clamp01((k - 0.45f) / 0.55f);
                    iconSr.color = c;

                    if (shock != null && ringSprite != null)
                    {
                        float rp = Mathf.Clamp01(k / 0.55f);
                        float rs = (tile * Mathf.Lerp(0.5f, 3.2f, rp)) /
                                   Mathf.Max(0.001f, ringSprite.bounds.size.x);
                        shock.transform.localScale = new Vector3(rs, rs, 1f);
                        Color rc = shock.color;
                        rc.a = Mathf.Sin(rp * Mathf.PI) * 0.9f;
                        shock.color = rc;
                    }

                    // Micro-sacudida al impactar (0,2 s) y regreso exacto a la cámara.
                    if (!ReduceMotion && cam != null && k < 0.18f)
                    {
                        float mag = 0.05f * (1f - k / 0.18f);
                        shaking = true;
                        cam.transform.position = camBase + new Vector3(
                            Random.Range(-mag, mag), Random.Range(-mag, mag), 0f);
                    }
                    else if (shaking && cam != null)
                    {
                        cam.transform.position = camBase;
                        shaking = false;
                    }
                }

                // ── Estela ──
                for (int i = 0; i < trail.Count; i++)
                {
                    Vector3 seed = trailSeed[i];
                    float appear = Mathf.Clamp01((p - impactP * seed.z * 0.5f) / 0.12f);
                    float gone = 1f - Mathf.Clamp01((p - impactP * 0.9f) / 0.25f);
                    float a = appear * gone;
                    trail[i].transform.localPosition = new Vector3(
                        -tile * seed.x, tile * seed.y, 0.2f);
                    float s = tile * Mathf.Lerp(0.30f, 0.08f, Mathf.Clamp01(p / impactP));
                    trail[i].transform.localScale = new Vector3(s, s, 1f);
                    Color tc = trail[i].color;
                    tc.a = a * 0.8f;
                    trail[i].color = tc;
                }

                yield return null;
            }

            if (cam != null && shaking) cam.transform.position = camBase;
            if (root != null) Destroy(root);
            _playing = false;
        }

        private static Sprite RingSprite()
        {
            if (_cachedRing != null) return _cachedRing;
            try
            {
                Texture2D tex = DoubleCheckFx.MakeRingTexture();
                _cachedRing = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                    new Vector2(0.5f, 0.5f), 100f);
                _cachedRing.name = "cometa_ring";
            }
            catch { _cachedRing = null; }
            return _cachedRing;
        }

        private IEnumerator ForkCometRoutine(Vector3 targetWorld, Sprite[] frames)
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

            float frameW = 12.8f;
            try
            {
                if (frames[0] != null && frames[0].bounds.size.x > 0.01f)
                    frameW = frames[0].bounds.size.x;
            }
            catch { /* 12.8f por defecto (1280px a 100 ppu) */ }
            float s = (tile * OverlayTiles) / frameW;

            GameObject root = new GameObject("CometaIgnea");
            root.transform.position = targetWorld;
            root.transform.localScale = new Vector3(s, s, 1f);
            var sr = root.AddComponent<SpriteRenderer>();
            sr.sortingOrder = 38;
            sr.color = new Color(1f, 1f, 1f, 1f);

            // Movimiento reducido: mitad de frames
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
