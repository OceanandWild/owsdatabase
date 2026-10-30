using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;
using WilderGambit.Pieces;

namespace WilderGambit.View
{
    /// <summary>
    /// «Doble Filo» — FX de doble jaque (dos piezas dan jaque a la vez).
    /// Dos anillos rojos entrelazados (8) sobre el Rey + cruz destellante + sello
    /// «¡DOBLE JAQUE!» + micro-vibración de cámara. 1.4 s, no bloquea input.
    /// Opt-out: si no hay tablero/cámara, no hace nada.
    /// Arte: anillos procedurales; si existe Resources/FX/ring_red_256 (Sprite)
    /// se usa ese. Sonido: snap metálico procedural; si existe
    /// Resources/SFX/SFX_CheckDouble_Snap se usa ese.
    /// </summary>
    public class DoubleCheckFx : MonoBehaviour
    {
        public static DoubleCheckFx Instance { get; private set; }

        public static bool ReduceMotion = false;

        // ── Ficha de tienda (pestaña ANIMACIONES) ──
        public const string AnimId = "anim_check_doblefilo";
        public const int PriceGambits = 750;
        private const string KEY_OWNED = "Anim_Owned_anim_check_doblefilo";
        private const string KEY_EQUIPPED = "Anim_Equipped_Check";

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

        private const float Duration = 1.4f;

        [Header("Override opcional (si no, Resources/FX o procedural)")]
        [SerializeField] private Sprite ringSprite;
        [SerializeField] private AudioClip snapClip;

        private bool _playing;
        private static Sprite _cachedRing;
        private static Sprite _cachedArt;

        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("DoubleCheckFx");
            go.AddComponent<DoubleCheckFx>();
        }

        /// <summary>Entry point seguro para GameManager: nunca lanza.</summary>
        public static void PlayAt(Vector2IntCustom kingPos)
        {
            try
            {
                EnsureExists();
                if (Instance != null) Instance.PlayInternal(kingPos);
            }
            catch (System.Exception e)
            {
                Debug.LogWarning("[DoubleCheckFx] skip: " + e.Message);
            }
        }

        /// <summary>
        /// Cuenta atacantes sobre una casilla con la MISMA lógica que
        /// Board.IsSquareAttacked (peones + Lancero frontal, reyes, resto por
        /// GetValidMoves). Doble jaque si >= 2.
        /// </summary>
        public static int CountAttackers(Board board, Vector2IntCustom targetPos, TeamColor friendlyTeam)
        {
            if (board == null) return 0;
            TeamColor enemyTeam = (friendlyTeam == TeamColor.White) ? TeamColor.Black : TeamColor.White;
            int count = 0;

            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    ChessPiece p = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (p == null || p.Team != enemyTeam) continue;

                    if (p.Type == PieceType.Pawn)
                    {
                        int dir = (p.Team == TeamColor.White) ? 1 : -1;
                        if (p.Position.Row + dir == targetPos.Row &&
                            (p.Position.Col - 1 == targetPos.Col || p.Position.Col + 1 == targetPos.Col))
                            count++;
                        else if (p is LancerPawn &&
                                 p.Position.Row + dir == targetPos.Row &&
                                 p.Position.Col == targetPos.Col)
                            count++;
                    }
                    else if (p.Type == PieceType.King)
                    {
                        int dRow = Mathf.Abs(p.Position.Row - targetPos.Row);
                        int dCol = Mathf.Abs(p.Position.Col - targetPos.Col);
                        if (dRow <= 1 && dCol <= 1) count++;
                    }
                    else
                    {
                        List<Vector2IntCustom> moves = p.GetValidMoves(board);
                        if (moves.Contains(targetPos)) count++;
                    }

                    if (count >= 2) return count;
                }
            }
            return count;
        }

        /// <summary>Arte para la card/hero de la tienda y los pases (icono ilustrado).</summary>
        public static Sprite GetArtSprite()
        {
            if (_cachedArt != null) return _cachedArt;

            // Icono propio: sables cruzados, el arte oficial de la animación.
            Sprite icon = AnimIconSprites.DobleFilo;
            if (icon != null) { _cachedArt = icon; return _cachedArt; }

            // Respaldo: anillo del usuario o procedural.
            try
            {
                Sprite s = Resources.Load<Sprite>("FX/ring_red_256");
                if (s != null) { _cachedArt = s; return s; }
                Texture2D t = Resources.Load<Texture2D>("FX/ring_red_256");
                if (t != null)
                {
                    _cachedArt = Sprite.Create(t, new Rect(0, 0, t.width, t.height),
                        new Vector2(0.5f, 0.5f), 100f);
                    return _cachedArt;
                }
            }
            catch { /* procedural */ }
            _cachedArt = Sprite.Create(MakeRingTexture(),
                new Rect(0, 0, 128, 128), new Vector2(0.5f, 0.5f), 100f);
            return _cachedArt;
        }

        /// <summary>Anillo rojo con borde suave y alpha limpio (128px).</summary>
        public static Texture2D MakeRingTexture()
        {
            const int n = 128;
            var tex = new Texture2D(n, n, TextureFormat.RGBA32, false)
            {
                name = "doblefilo_ring",
                filterMode = FilterMode.Bilinear,
                wrapMode = TextureWrapMode.Clamp
            };
            Color ring = new Color(1f, 0.22f, 0.16f, 1f);
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float dx = (x - n / 2f) / (n / 2f);
                    float dy = (y - n / 2f) / (n / 2f);
                    float d = Mathf.Sqrt(dx * dx + dy * dy); // 0 centro → 1 borde
                    // Anillo entre 0.62 y 0.88, con caída suave en ambos bordes
                    float band = Mathf.Clamp01((d - 0.60f) / 0.08f) * Mathf.Clamp01((0.90f - d) / 0.08f);
                    Color c = ring * band;
                    c.a = band;
                    tex.SetPixel(x, y, c);
                }
            tex.Apply(false);
            return tex;
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }

        private void PlayInternal(Vector2IntCustom kingPos)
        {
            if (_playing) return;
            // Solo se reproduce si está comprada y equipada (se vende en la tienda).
            if (!IsEquipped()) return;
            var bv = BoardView.Instance;
            if (bv == null) return;
            _playing = true;
            StartCoroutine(DoubleCheckRoutine(bv.GetWorldPosition(kingPos.Row, kingPos.Col)));
        }

        private IEnumerator DoubleCheckRoutine(Vector3 kingWorld)
        {
            Sprite ring = ringSprite;
            if (ring == null)
            {
                if (_cachedRing == null)
                {
                    try
                    {
                        _cachedRing = Resources.Load<Sprite>("FX/ring_red_256");
                        if (_cachedRing == null)
                        {
                            Texture2D ringTex = Resources.Load<Texture2D>("FX/ring_red_256");
                            if (ringTex != null) _cachedRing = Sprite.Create(ringTex,
                                new Rect(0, 0, ringTex.width, ringTex.height), new Vector2(0.5f, 0.5f), 100f);
                        }
                    }
                    catch { _cachedRing = null; }
                    if (_cachedRing == null) _cachedRing = Sprite.Create(MakeRingTexture(),
                        new Rect(0, 0, 128, 128), new Vector2(0.5f, 0.5f), 100f);
                }
                ring = _cachedRing;
            }

            // Tamaño de casilla en mundo (misma referencia que el resto de FX).
            float tile = 1.8f;
            try
            {
                GameObject tiles = GameObject.Find("BoardTiles");
                if (tiles != null && tiles.transform.childCount > 0)
                    tile = tiles.transform.GetChild(0).localScale.x;
            }
            catch { /* 1.8f por defecto */ }

            GameObject root = new GameObject("DobleFilo");
            root.transform.position = kingWorld;

            // ── Emblema del doble filo estampado sobre el Rey ──
            Sprite icon = AnimIconSprites.DobleFilo;
            GameObject iconGo = null;
            SpriteRenderer iconSr = null;
            float iconBase = 1f;
            if (icon != null)
            {
                float iconWorld = icon.bounds.size.x > 0.01f ? icon.bounds.size.x : 5.12f;
                iconBase = (tile * 1.55f) / iconWorld;
                iconGo = new GameObject("Emblem");
                iconGo.transform.SetParent(root.transform, false);
                iconGo.transform.localPosition = new Vector3(0f, 0f, -0.5f);
                iconGo.transform.localScale = new Vector3(iconBase * 0.6f, iconBase * 0.6f, 1f);
                iconSr = iconGo.AddComponent<SpriteRenderer>();
                iconSr.sprite = icon;
                iconSr.sortingOrder = 3; // sobre la pieza, debajo de anillos y cruz
                iconSr.color = new Color(1f, 1f, 1f, 0f);
            }

            // ── Anillos entrelazados (8) ──
            var rings = new List<SpriteRenderer>();
            for (int i = 0; i < 2; i++)
            {
                var go = new GameObject("Ring_" + i);
                go.transform.SetParent(root.transform, false);
                float side = (i == 0 ? -0.28f : 0.28f);
                go.transform.localPosition = new Vector3(side, 0f, -1f);
                go.transform.localScale = new Vector3(1.15f, 1.15f, 1f);
                var sr = go.AddComponent<SpriteRenderer>();
                sr.sprite = ring;
                sr.sortingOrder = 35;
                sr.color = new Color(1f, 1f, 1f, 0f);
                rings.Add(sr);
            }

            // ── Cruz destellante (dos barras finas en X) ──
            var bars = new List<SpriteRenderer>();
            Texture2D barTex = MakeBarTexture();
            Sprite barSprite = Sprite.Create(barTex, new Rect(0, 0, 64, 8),
                new Vector2(0.5f, 0.5f), 100f);
            for (int i = 0; i < 2; i++)
            {
                var go = new GameObject("Cross_" + i);
                go.transform.SetParent(root.transform, false);
                go.transform.localPosition = new Vector3(0f, 0f, -2f);
                go.transform.localRotation = Quaternion.Euler(0f, 0f, i == 0 ? 45f : -45f);
                go.transform.localScale = new Vector3(1.6f, 1.6f, 1f);
                var sr = go.AddComponent<SpriteRenderer>();
                sr.sprite = barSprite;
                sr.sortingOrder = 36;
                sr.color = new Color(1f, 0.93f, 0.80f, 0f);
                bars.Add(sr);
            }

            // ── Sello de texto en mundo (con fallback silencioso) ──
            GameObject sealGo = null;
            try
            {
                sealGo = new GameObject("Seal");
                sealGo.transform.SetParent(root.transform, false);
                sealGo.transform.localPosition = new Vector3(0f, 1.35f, -3f);
                var tm = sealGo.AddComponent<TextMesh>();
                tm.text = "¡DOBLE JAQUE!";
                tm.anchor = TextAnchor.MiddleCenter;
                tm.alignment = TextAlignment.Center;
                tm.fontSize = 32;
                tm.characterSize = 0.03f;
                tm.color = new Color(1f, 0.55f, 0.30f, 0f);
                try
                {
                    tm.font = Font.CreateDynamicFontFromOSFont("Arial", 32);
                    if (tm.font == null) tm.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
                }
                catch { /* fuente por defecto */ }
                var mr = sealGo.GetComponent<MeshRenderer>();
                if (mr != null) mr.sortingOrder = 37;
            }
            catch { sealGo = null; }
            TextMesh seal = sealGo != null ? sealGo.GetComponent<TextMesh>() : null;

            // ── Snap metálico (archivo si existe, si no procedural) ──
            try { PlaySnap(); } catch { /* audio nunca bloquea */ }

            // ── Micro-vibración de cámara (0.35 s, salvo movimiento reducido) ──
            Coroutine shake = null;
            if (!ReduceMotion && Camera.main != null)
                shake = StartCoroutine(CameraShake(0.35f, 0.06f));

            // ── Animar 1.4 s ──
            float t = 0f;
            while (t < Duration)
            {
                t += Time.deltaTime;
                float p = Mathf.Clamp01(t / Duration);

                float ringA = Mathf.Sin(Mathf.Min(1f, p / 0.6f) * Mathf.PI);
                for (int i = 0; i < rings.Count; i++)
                {
                    float pi = Mathf.Clamp01((p - i * 0.12f) / 0.88f);
                    Color c = rings[i].color;
                    c.a = Mathf.Sin(pi * Mathf.PI) * 0.95f;
                    rings[i].color = c;
                    float s = 1.15f * (1f + 0.12f * Mathf.Sin(pi * Mathf.PI));
                    rings[i].transform.localScale = new Vector3(s, s, 1f);
                }

                float flash = (p < 0.25f) ? p / 0.25f : Mathf.Clamp01((0.55f - p) / 0.30f);
                foreach (var b in bars)
                {
                    Color c = b.color;
                    c.a = Mathf.Clamp01(flash) * 0.9f;
                    b.color = c;
                }

                if (iconSr != null && iconGo != null)
                {
                    float pop = Mathf.Clamp01(p / 0.18f);
                    float ease = 1f - Mathf.Pow(1f - pop, 3f);
                    float hold = 1f + 0.04f * Mathf.Sin(p * Mathf.PI * 5f);
                    float s = iconBase * Mathf.Lerp(0.6f, 1f, ease) * hold;
                    iconGo.transform.localScale = new Vector3(s, s, 1f);
                    iconGo.transform.localRotation = Quaternion.Euler(0f, 0f,
                        ReduceMotion ? 0f : Mathf.Sin(p * Mathf.PI * 2f) * 2.5f);
                    Color ci = iconSr.color;
                    ci.a = Mathf.Min(pop * 1.6f, 0.96f) * Mathf.Clamp01((1f - p) / 0.22f);
                    iconSr.color = ci;
                }

                if (seal != null)
                {
                    float pop = Mathf.Clamp01(p / 0.22f);
                    float ease = 1f - Mathf.Pow(1f - pop, 3f);
                    sealGo.transform.localScale = new Vector3(ease, ease, 1f);
                    Color c = seal.color;
                    c.a = Mathf.Min(pop * 1.5f, 1f) * Mathf.Clamp01((1f - p) / 0.20f);
                    seal.color = c;
                }

                if (ringA <= 0f && p > 0.6f) break;
                yield return null;
            }

            if (shake != null) StopCoroutine(shake);
            Destroy(root);
            _playing = false;
        }

        private IEnumerator CameraShake(float dur, float mag)
        {
            Camera cam = Camera.main;
            if (cam == null) yield break;
            Vector3 base3 = cam.transform.position;
            float t = 0f;
            while (t < dur)
            {
                t += Time.deltaTime;
                float k = mag * (1f - t / dur);
                cam.transform.position = base3 + new Vector3(
                    Random.Range(-k, k), Random.Range(-k, k), 0f);
                yield return null;
            }
            if (cam != null) cam.transform.position = base3;
        }

        private Texture2D MakeBarTexture()
        {
            var tex = new Texture2D(64, 8, TextureFormat.RGBA32, false)
            {
                name = "doblefilo_bar",
                filterMode = FilterMode.Bilinear,
                wrapMode = TextureWrapMode.Clamp
            };
            for (int y = 0; y < 8; y++)
                for (int x = 0; x < 64; x++)
                {
                    float ex = Mathf.Clamp01((x - 2f) / 6f) * Mathf.Clamp01((61f - x) / 6f);
                    float ey = Mathf.Clamp01((y - 0.5f) / 2f) * Mathf.Clamp01((7.5f - y) / 2f);
                    float a = Mathf.Clamp01(ex) * Mathf.Clamp01(ey);
                    tex.SetPixel(x, y, new Color(1f, 1f, 1f, a));
                }
            tex.Apply(false);
            return tex;
        }

        private void PlaySnap()
        {
            AudioClip clip = snapClip;
            if (clip == null)
            {
                try { clip = Resources.Load<AudioClip>("SFX/SFX_CheckDouble_Snap"); }
                catch { clip = null; }
            }
            var src = gameObject.AddComponent<AudioSource>();
            src.playOnAwake = false;
            src.spatialBlend = 0f;
            if (clip != null)
            {
                src.volume = 0.45f;
                src.clip = clip;
                src.Play();
                Destroy(src, clip.length + 0.3f);
                return;
            }
            // Snap metálico procedural: dos pings + chasquido (0.5 s)
            const int rate = 22050;
            const float len = 0.5f;
            int n = Mathf.RoundToInt(rate * len);
            var data = new float[n];
            for (int i = 0; i < n; i++)
            {
                float t = i / (float)rate;
                float ping = Mathf.Sin(t * 2f * Mathf.PI * 1175f) * Mathf.Exp(-t * 9f) * 0.5f
                           + Mathf.Sin(t * 2f * Mathf.PI * 1760f) * Mathf.Exp(-t * 12f) * 0.3f;
                float snap = Random.Range(-1f, 1f) * Mathf.Exp(-t * 30f) * 0.4f;
                data[i] = Mathf.Clamp((ping + snap) * 0.5f, -1f, 1f);
            }
            AudioClip proc = AudioClip.Create("DoubleCheckSnap", n, 1, rate, false);
            proc.SetData(data, 0);
            src.volume = 0.4f;
            src.clip = proc;
            src.Play();
            Destroy(src, len + 0.3f);
        }
    }
}
