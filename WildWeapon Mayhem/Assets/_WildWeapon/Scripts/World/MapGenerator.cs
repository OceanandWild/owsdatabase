using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Genera el entorno a partir de un MapDef: fondo, muros, plataformas elevadas,
    /// obstaculos, decoracion y peligros. Se puede usar en editor (boton "Generar mapa"
    /// del inspector / menu contextual) o en runtime.
    /// </summary>
    public class MapGenerator : MonoBehaviour
    {
        public MapDef map;
        public Transform spawnP1;
        public Transform spawnP2;
        public bool mirrored = true;

        [SerializeField] private List<Vector2> botSpawnPoints = new List<Vector2>();
        public List<Vector2> BotSpawnPoints => botSpawnPoints;
        public int LastSeed { get; private set; }

        private const string RootName = "_Generated";

        [ContextMenu("Generar mapa")]
        public void GenerateFromInspector() => Generate(map != null ? map.seed : 0, mirrored);

        [ContextMenu("Generar mapa (semilla aleatoria)")]
        public void GenerateRandom() => Generate(Random.Range(1, 999999), mirrored);

        public void Clear()
        {
            var old = transform.Find(RootName);
            if (old == null) return;
            if (Application.isPlaying) { old.SetParent(null); Destroy(old.gameObject); }
            else DestroyImmediate(old.gameObject);
        }

        public void Generate(int seed, bool mirror)
        {
            if (map == null) { Debug.LogWarning("[MapGenerator] Falta MapDef."); return; }
            Clear();
            LastSeed = seed;
            var rng = new System.Random(seed);

            var root = new GameObject(RootName).transform;
            root.SetParent(transform, false);

            Vector2 half = map.arenaSize * 0.5f;

            // Etapa 2: suelo solo en la tira inferior de la arena.
            PlatformSurface.GroundOnlyBottom = true;
            PlatformSurface.ArenaHalfY = half.y;
            float t = map.wallThickness;

            // ---- Camara: la arena ocupa una fraccion del encuadre; el resto es entorno ----
            var cam = Camera.main;
            float aspect = cam != null && cam.aspect > 0.1f ? cam.aspect : 16f / 9f;
            float fraction = Mathf.Clamp(map.backdropArenaFraction, 0.45f, 0.95f);
            float orthoSize = Mathf.Max(half.y / fraction, half.x / (fraction * aspect));
            var view = new Vector2(orthoSize * aspect * 2f, orthoSize * 2f);

            // ---- Decoracion exclusiva del tema: props chicos de fondo ----
            var placed = new List<Vector2>();

            // ---- Fondo: el entorno del lugar cubre todo el encuadre (arte unico, sin tiling) ----
            if (map.floorSprite != null)
            {
                var backdrop = map.floorSingle
                    ? Single("Entorno", root, map.floorSprite, view * 1.02f, Vector2.zero, map.floorTint, -100)
                    : Tiled("Entorno", root, map.floorSprite, map.floorTileSize, view * 1.02f, Vector2.zero, map.floorTint, -100);
                backdrop.GetComponent<SpriteRenderer>().spriteSortPoint = SpriteSortPoint.Center;
            }

            // ---- Muros ----
            var walls = new GameObject("Muros").transform;
            walls.SetParent(root, false);
            Wall(walls, "Muro Norte", new Vector2(map.arenaSize.x + t * 2f, t), new Vector2(0f, half.y + t * 0.5f));
            Wall(walls, "Muro Sur", new Vector2(map.arenaSize.x + t * 2f, t), new Vector2(0f, -half.y - t * 0.5f));
            Wall(walls, "Muro Este", new Vector2(t, map.arenaSize.y), new Vector2(half.x + t * 0.5f, 0f));
            Wall(walls, "Muro Oeste", new Vector2(t, map.arenaSize.y), new Vector2(-half.x - t * 0.5f, 0f));

            // ---- Spawns ----
            if (spawnP1 != null) spawnP1.position = map.p1Spawn;
            if (spawnP2 != null) spawnP2.position = map.p2Spawn;

            // ---- Plataformas elevadas (el fondo y los decks van por separado) ----
            var decks = new GameObject("Plataformas").transform;
            decks.SetParent(root, false);
            if (map.platforms != null)
            {
                foreach (var p in map.platforms)
                {
                    Platform(decks, p, p.center);
                    if (mirror && p.mirrored) Platform(decks, p, -p.center);
                }
            }

            // ---- Obstaculos ----
            var obstRoot = new GameObject("Obstaculos").transform;
            obstRoot.SetParent(root, false);
            Vector2 inner = half - Vector2.one * 1.2f;
            int target = map.obstacleCount;
            int attempts = 0;
            while (placed.Count < target && attempts < 600)
            {
                attempts++;
                var p = new Vector2(Range(rng, -inner.x, inner.x), Range(rng, -inner.y, inner.y));
                if (!ValidObstacle(p, placed)) continue;
                if (mirror && !ValidObstacle(-p, placed)) continue;
                if (mirror && p.sqrMagnitude < 1.2f) continue;
                if (OnPlatform(p, 1.1f, out _)) continue;

                var prop = Pick(rng, map.obstacles);
                if (prop == null || prop.sprite == null) break;
                float size = prop.size * Range(rng, prop.sizeJitter.x, prop.sizeJitter.y);
                bool flip = rng.NextDouble() < 0.5;

                Prop(obstRoot, prop, p, size, flip, root);
                placed.Add(p);
                if (mirror && placed.Count < target)
                {
                    Prop(obstRoot, prop, -p, size, !flip, root);
                    placed.Add(-p);
                }
            }

            // ---- Decoracion ----
            var decorRoot = new GameObject("Decoracion").transform;
            decorRoot.SetParent(root, false);
            for (int i = 0; i < map.decorCount; i++)
            {
                var prop = Pick(rng, map.decor);
                if (prop == null || prop.sprite == null) break;
                var p = new Vector2(Range(rng, -half.x + 0.4f, half.x - 0.4f), Range(rng, -half.y + 0.4f, half.y - 0.4f));
                float size = prop.size * Range(rng, prop.sizeJitter.x, prop.sizeJitter.y);
                var go = SpriteObj(prop.name, decorRoot, prop.sprite, p, size, -60);
                var sr = go.GetComponent<SpriteRenderer>();
                sr.flipX = rng.NextDouble() < 0.5;
                var c = prop.tint;
                c.a = 0.9f;
                sr.color = c;
                go.transform.rotation = Quaternion.Euler(0f, 0f, Range(rng, -25f, 25f));
            }

            // ---- Peligros ----
            var hazards = new GameObject("Peligros").transform;
            hazards.SetParent(root, false);
            if (map.hazards != null)
            {
                foreach (var h in map.hazards)
                {
                    Hazard(hazards, h, h.center);
                    if (mirror && h.mirrored) Hazard(hazards, h, -h.center);
                }
            }

            // ---- Puntos de spawn de bots (perimetro interior, evitando peligros) ----
            botSpawnPoints.Clear();
            int n = Mathf.Max(4, map.botSpawnPoints);
            Vector2 ring = half - Vector2.one * 0.9f;
            for (int i = 0; i < n; i++)
            {
                float a = i / (float)n * Mathf.PI * 2f;
                var dir = new Vector2(Mathf.Cos(a), Mathf.Sin(a));
                float k = Mathf.Min(ring.x / Mathf.Max(0.001f, Mathf.Abs(dir.x)), ring.y / Mathf.Max(0.001f, Mathf.Abs(dir.y)));
                var p = dir * k;
                bool blocked = false;
                foreach (var o in placed) if ((o - p).sqrMagnitude < 1.4f) { blocked = true; break; }
                if (!blocked && InHazard(p)) blocked = true;
                if (!blocked) botSpawnPoints.Add(p);
            }

            // ---- Camara ----
            if (cam != null)
            {
                cam.backgroundColor = map.backgroundColor;
                cam.orthographicSize = orthoSize;
            }
        }

        /// <summary>true si el punto cae dentro de la huella de alguna plataforma (con margen).</summary>
        private bool OnPlatform(Vector2 p, float margin, out float top)
        {
            top = 0f;
            if (map.platforms == null) return false;
            foreach (var pl in map.platforms)
            {
                foreach (var c in new[] { pl.center, -pl.center })
                {
                    var d = p - c;
                    if (Mathf.Abs(d.x) <= pl.size.x * 0.5f + margin && Mathf.Abs(d.y) <= pl.size.y * 0.5f + margin)
                    {
                        top = pl.height;
                        return true;
                    }
                }
            }
            return false;
        }

        private bool InHazard(Vector2 p)
        {
            if (map.hazards == null) return false;
            foreach (var h in map.hazards)
            {
                foreach (var c in new[] { h.center, -h.center })
                {
                    var d = p - c;
                    if (Mathf.Abs(d.x) <= h.size.x * 0.5f + 0.6f && Mathf.Abs(d.y) <= h.size.y * 0.5f + 0.6f) return true;
                }
            }
            return false;
        }

        private bool ValidObstacle(Vector2 p, List<Vector2> placed)
        {
            if ((p - map.p1Spawn).magnitude < map.spawnClearRadius) return false;
            if ((p - map.p2Spawn).magnitude < map.spawnClearRadius) return false;
            foreach (var o in placed)
                if ((o - p).magnitude < map.minObstacleSpacing) return false;
            return true;
        }

        // ------------------------------------------------------------------
        // Piezas
        // ------------------------------------------------------------------

        /// <summary>Deck elevado: sombra al ras, superficie caminable e info de altura para HeightBody.</summary>
        private void Platform(Transform parent, MapPlatform p, Vector2 center)
        {
            var root = new GameObject("Deck_" + p.sizeClass + "_" + p.name);
            root.transform.SetParent(parent, false);
            root.transform.localPosition = center;

            float lift = p.height * HeightBody.LiftPerZ;   // mismo paralaje que el personaje

            // Sombra de elevacion (al ras del piso).
            if (map.platformShadow != null)
            {
                var sh = new GameObject("Sombra");
                sh.transform.SetParent(root.transform, false);
                sh.transform.localPosition = new Vector3(0.06f, -0.09f, 0f);
                var sb = map.platformShadow.bounds.size;
                sh.transform.localScale = new Vector3(
                    p.size.x * 1.12f / Mathf.Max(0.0001f, sb.x),
                    p.size.y * 1.12f / Mathf.Max(0.0001f, sb.y), 1f);
                var shr = sh.AddComponent<SpriteRenderer>();
                shr.sprite = map.platformShadow;
                shr.color = new Color(0f, 0f, 0f, 0.5f);
                shr.sortingOrder = -45;
            }

            // Deck (arte propio, separado del fondo).
            var deck = new GameObject("Deck");
            deck.transform.SetParent(root.transform, false);
            deck.transform.localPosition = new Vector3(0f, lift, 0f);
            deck.transform.localRotation = Quaternion.Euler(0f, 0f, p.rotation);
            var sr = deck.AddComponent<SpriteRenderer>();
            sr.sprite = map.platformSprite;
            sr.color = new Color(map.platformTint, map.platformTint, map.platformTint, 1f);
            sr.sortingOrder = Mathf.RoundToInt(p.height * 50f);
            sr.spriteSortPoint = SpriteSortPoint.Center;
            if (sr.sprite != null)
            {
                if (sr.sprite.border != Vector4.zero)
                {
                    sr.drawMode = SpriteDrawMode.Sliced;
                    sr.size = p.size;
                }
                else
                {
                    float sx = p.size.x / Mathf.Max(0.0001f, sr.sprite.bounds.size.x);
                    float sy = p.size.y / Mathf.Max(0.0001f, sr.sprite.bounds.size.y);
                    deck.transform.localScale = new Vector3(sx, sy, 1f);
                }
            }

            var surf = root.AddComponent<PlatformSurface>();
            surf.center = center;
            surf.size = p.size;
            surf.top = p.height;
        }

        private void Hazard(Transform parent, MapHazard h, Vector2 center)
        {
            var go = new GameObject("Peligro_" + h.kind + "_" + h.name);
            go.transform.SetParent(parent, false);
            var copy = new MapHazard
            {
                name = h.name, kind = h.kind, center = center, size = h.size, damage = h.damage,
                interval = h.interval, telegraph = h.telegraph, active = h.active, knockback = h.knockback,
                slow = h.slow, maxHeight = h.maxHeight, color = h.color, mirrored = false, phase = h.phase,
            };
            go.AddComponent<ArenaHazard>().Setup(copy);
        }

        private void Wall(Transform parent, string name, Vector2 size, Vector2 pos)
        {
            GameObject go;
            if (map.wallSprite != null)
                go = Tiled(name, parent, map.wallSprite, map.wallTileSize, size, pos, map.wallTint, -20);
            else
            {
                go = new GameObject(name);
                go.transform.SetParent(parent, false);
                go.transform.localPosition = pos;
            }
            var col = go.AddComponent<BoxCollider2D>();
            float s = go.transform.localScale.x;
            col.size = size / Mathf.Max(0.0001f, s);
        }

        private void Prop(Transform parent, MapProp prop, Vector2 center, float size, bool flip, Transform mapRoot)
        {
            var go = SpriteObj(prop.name, parent, prop.sprite, Vector2.zero, size, 0);
            var sr = go.GetComponent<SpriteRenderer>();
            sr.flipX = flip;
            sr.color = prop.tint;
            float scale = go.transform.localScale.x;
            float worldR = size * prop.colliderRadius;

            // El pivote del sprite esta en la base; el collider se centra en 'center'.
            go.transform.localPosition = center - new Vector2(0f, worldR);
            if (prop.solid)
            {
                var col = go.AddComponent<CircleCollider2D>();
                col.radius = worldR / scale;
                col.offset = new Vector2(0f, worldR / scale);

                // Techo: si el prop lo declara, se puede saltar encima y deja de bloquear arriba.
                if (prop.height > 0f)
                {
                    var surf = go.AddComponent<PlatformSurface>();
                    surf.center = center;
                    surf.size = Vector2.one * (worldR * 2f);
                    surf.top = prop.height;
                    surf.solid = col;
                }
            }
        }

        private static GameObject SpriteObj(string name, Transform parent, Sprite sprite, Vector2 pos, float width, int order)
        {
            var go = new GameObject(name);
            go.transform.SetParent(parent, false);
            go.transform.localPosition = pos;
            float s = width / Mathf.Max(0.0001f, sprite.bounds.size.x);
            go.transform.localScale = new Vector3(s, s, 1f);
            var sr = go.AddComponent<SpriteRenderer>();
            sr.sprite = sprite;
            sr.sortingOrder = order;
            sr.spriteSortPoint = SpriteSortPoint.Pivot;
            return go;
        }

        /// <summary>Piso de arte unico: un solo sprite estirado a toda el area (sin tiling).</summary>
        private static GameObject Single(string name, Transform parent, Sprite sprite, Vector2 size, Vector2 pos, Color tint, int order)
        {
            var go = new GameObject(name);
            go.transform.SetParent(parent, false);
            go.transform.localPosition = pos;
            go.transform.localScale = new Vector3(size.x / Mathf.Max(0.0001f, sprite.bounds.size.x),
                size.y / Mathf.Max(0.0001f, sprite.bounds.size.y), 1f);
            var sr = go.AddComponent<SpriteRenderer>();
            sr.sprite = sprite;
            sr.color = tint;
            sr.sortingOrder = order;
            return go;
        }

        private static GameObject Tiled(string name, Transform parent, Sprite sprite, float tile, Vector2 size, Vector2 pos, Color tint, int order)
        {
            var go = new GameObject(name);
            go.transform.SetParent(parent, false);
            go.transform.localPosition = pos;
            float s = tile / Mathf.Max(0.0001f, sprite.bounds.size.x);
            go.transform.localScale = new Vector3(s, s, 1f);
            var sr = go.AddComponent<SpriteRenderer>();
            sr.sprite = sprite;
            sr.drawMode = SpriteDrawMode.Tiled;
            sr.tileMode = SpriteTileMode.Continuous;
            sr.size = size / s;
            sr.color = tint;
            sr.sortingOrder = order;
            return go;
        }

        private static MapProp Pick(System.Random rng, MapProp[] props)
        {
            if (props == null || props.Length == 0) return null;
            float total = 0f;
            foreach (var p in props) total += Mathf.Max(0f, p.weight);
            float r = (float)rng.NextDouble() * total;
            foreach (var p in props)
            {
                r -= Mathf.Max(0f, p.weight);
                if (r <= 0f) return p;
            }
            return props[props.Length - 1];
        }

        private static float Range(System.Random rng, float a, float b) => a + (float)rng.NextDouble() * (b - a);
    }
}
