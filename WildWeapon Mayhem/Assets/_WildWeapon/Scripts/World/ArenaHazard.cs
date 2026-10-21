using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Peligro de arena: ciclo idle -> telegrafia -> golpe -> recuperacion, armado por
    /// <see cref="MapGenerator"/> a partir de un <see cref="MapHazard"/>.
    ///
    /// Reglas:
    /// - Solo afecta a quien este por debajo del techo del peligro
    ///   (<see cref="MapHazard.maxHeight"/> sobre su centro): subirse a una
    ///   plataforma te salva del peligro de piso.
    /// - Nunca golpea a la replica de red (el dueno del pawn decide su dano en PVP).
    /// - Los visuales son procedurales (mancha suave + anillo + chispas), tintados por tema.
    /// </summary>
    public class ArenaHazard : MonoBehaviour
    {
        public MapHazard def;

        private SpriteRenderer _blob;       // area/sombra/nube/charco
        private SpriteRenderer _ring;       // ondas y golpes
        private SpriteRenderer _band;       // franja (arco/vendaval)
        private readonly List<SpriteRenderer> _sparks = new List<SpriteRenderer>();
        private float _tick;
        private float _cycle;               // tiempo dentro del ciclo (0..interval)
        private readonly HashSet<PlayerHealth> _pulseHit = new HashSet<PlayerHealth>();

        private static readonly List<PlayerHealth> Buffer = new List<PlayerHealth>(24);

        private float Tele => Mathf.Max(0.0001f, def.telegraph);
        private bool InTelegraph => _cycle < def.telegraph;
        private bool InActive => _cycle >= def.telegraph && _cycle < def.telegraph + def.active;

        public void Setup(MapHazard h)
        {
            def = h;
            name = "Peligro_" + h.kind + "_" + h.name;
            transform.position = h.center;

            var vis = HazardVisuals.Instance;
            if (vis == null) return;

            _blob = MakeSprite("Area", vis.soft, vis.unlit, -52);
            _ring = MakeSprite("Onda", vis.ring ?? vis.soft, vis.unlit, -51);
            _band = MakeSprite("Franja", vis.soft, vis.unlit, -51);
            for (int i = 0; i < 8; i++)
                _sparks.Add(MakeSprite("Chispa" + i, vis.soft, vis.unlit, -50));

            _blob.transform.localPosition = Vector3.zero;
        }

        private SpriteRenderer MakeSprite(string nm, Sprite s, Material mat, int order)
        {
            var go = new GameObject(nm);
            go.transform.SetParent(transform, false);
            var sr = go.AddComponent<SpriteRenderer>();
            sr.sprite = s;
            if (mat != null) sr.sharedMaterial = mat;
            sr.sortingOrder = order;
            sr.color = new Color(1f, 1f, 1f, 0f);
            return sr;
        }

        private void Update()
        {
            if (def == null) return;

            _cycle = Mathf.Repeat(Time.time + def.phase, def.interval);
            _tick -= Time.deltaTime;
            if (_cycle < Time.deltaTime) _pulseHit.Clear();

            float teleK = InTelegraph ? Mathf.Clamp01(_cycle / Tele) : 0f;
            float activeK = InActive ? Mathf.Clamp01((_cycle - def.telegraph) / Mathf.Max(0.0001f, def.active)) : 0f;

            switch (def.kind)
            {
                case HazardKind.Slam: RenderSlam(teleK, activeK); break;
                case HazardKind.Pulse: RenderPulse(teleK, activeK); break;
                case HazardKind.Arc: RenderArc(teleK, activeK); break;
                case HazardKind.Wind: RenderWind(teleK, activeK); break;
                case HazardKind.Coins: RenderCoins(teleK, activeK); break;
                case HazardKind.Ignite: RenderField(teleK, activeK, 0.55f); break;
                case HazardKind.Cold: RenderField(teleK, activeK, 0.30f); break;
                default: RenderField(teleK, activeK, 0.36f); break;   // Zone
            }

            if (!InActive || _tick > 0f) return;

            switch (def.kind)
            {
                case HazardKind.Slam:
                    if (activeK > 0f) HitArea(def.damage, 1f, true);
                    _tick = def.active;
                    break;
                case HazardKind.Pulse:
                    HitRing(def.damage);
                    _tick = def.active;
                    break;
                case HazardKind.Coins:
                    HitArea(def.damage * 0.3f, 0.55f, false);
                    _tick = 0.22f;
                    break;
                case HazardKind.Arc:
                    HitArea(def.damage * 0.55f, 0.6f, false);
                    _tick = 0.35f;
                    break;
                case HazardKind.Wind:
                    HitArea(0f, 0.35f, false, push: true);
                    _tick = 0.12f;
                    break;
                case HazardKind.Ignite:
                    HitArea(def.damage * 0.45f, 0.7f, false, slow: 0.15f);
                    _tick = 0.4f;
                    break;
                case HazardKind.Cold:
                    HitArea(def.damage * 0.25f, 0.25f, false, slow: 0.55f);
                    _tick = 0.5f;
                    break;
                default: // Zone
                    HitArea(def.damage * 0.5f, 0.5f, false, slow: 0.2f);
                    _tick = 0.45f;
                    break;
            }
        }

        // ------------------------------------------------------------------
        // Golpes
        // ------------------------------------------------------------------
        private Rect Area(float scale = 1f)
        {
            var c = (Vector2)transform.position;
            var s = def.size * scale;
            return new Rect(c - s * 0.5f, s);
        }

        private void HitArea(float damage, float knock, bool once, float slow = 0f, bool push = false)
        {
            var r = Area();
            Buffer.Clear();
            Buffer.AddRange(PlayerHealth.All);
            foreach (var v in Buffer)
            {
                if (v == null || v.IsDead || v.networkMirror) continue;
                if (!r.Contains((Vector2)v.transform.position, true)) continue;
                if (HeightOf(v) > transform.position.y + def.maxHeight) continue;

                Vector2 dir = (Vector2)v.transform.position - (Vector2)transform.position;
                if (dir.sqrMagnitude < 0.0001f) dir = Vector2.up;
                dir.Normalize();

                if (slow > 0f) v.ApplySlow(1f - slow, 0.35f);
                if (push) Push(v, dir, def.knockback);
                if (damage > 0f) v.TakeDamage(damage, dir, null, knock);
                if (once && v.Controller != null) v.Controller.ApplyKnockback(dir, def.knockback);
                if (once && v.Bot != null) v.Bot.ApplyKnockback(dir, def.knockback * 2f);
            }
            if (once && damage > 0f) GameFeel.Shake(0.16f);
        }

        private void HitRing(float damage)
        {
            float k = Mathf.Clamp01((_cycle - def.telegraph) / Mathf.Max(0.0001f, def.active));
            float radius = Radius() * k;
            float band = Mathf.Max(0.55f, Radius() * 0.22f);

            Buffer.Clear();
            Buffer.AddRange(PlayerHealth.All);
            foreach (var v in Buffer)
            {
                if (v == null || v.IsDead || v.networkMirror) continue;
                if (_pulseHit.Contains(v)) continue;
                if (HeightOf(v) > transform.position.y + def.maxHeight) continue;

                Vector2 d = (Vector2)v.transform.position - (Vector2)transform.position;
                float dist = Mathf.Abs(d.x) > Mathf.Abs(d.y) ? Mathf.Abs(d.x) : Mathf.Abs(d.y);
                dist = Mathf.Max(dist, 0.01f);
                if (Mathf.Abs(dist - radius) > band) continue;

                _pulseHit.Add(v);
                v.TakeDamage(damage, d.normalized, null, 1f);
            }
        }

        private void Push(PlayerHealth v, Vector2 dir, float amount)
        {
            if (amount <= 0f) return;
            if (v.Controller != null) v.Controller.ApplyKnockback(dir, amount);
            if (v.Bot != null) v.Bot.ApplyKnockback(dir, amount);
        }

        private static float HeightOf(PlayerHealth v) => v != null ? v.transform.position.y : 0f;

        private float Radius()
        {
            var s = def.size;
            return Mathf.Max(s.x, s.y) * 0.5f;
        }

        // ------------------------------------------------------------------
        // Dibujo por familia
        // ------------------------------------------------------------------
        private void Reset()
        {
            Set(_blob, 0f, 0f, Color.clear);
            Set(_ring, 0f, 0f, Color.clear);
            Set(_band, 0f, 0f, Color.clear);
            foreach (var s in _sparks) Set(s, 0f, 0f, Color.clear);
        }

        private static void Set(SpriteRenderer sr, float w, float h, Color c)
        {
            if (sr == null) return;
            sr.enabled = c.a > 0.004f;
            if (!sr.enabled) return;
            sr.color = c;
            if (w > 0f) sr.transform.localScale = new Vector3(w, h > 0f ? h : w, 1f);
        }

        /// <summary>Mancha de area con la huella exacta del peligro.</summary>
        private void Blob(float alpha, float scale, Color tint)
        {
            if (_blob == null) return;
            var c = tint; c.a = alpha;
            Set(_blob, def.size.x * scale * 1.15f, def.size.y * scale * 1.15f, c);
        }

        private void RenderSlam(float teleK, float activeK)
        {
            if (_blob == null) return;
            var dark = Color.Lerp(Color.black, def.color, 0.25f);

            if (InTelegraph)
            {
                float blink = Mathf.Repeat(_cycle * 6f, 1f) > 0.5f ? 1f : 0.55f;
                Blob(0.08f + 0.3f * teleK * blink, Mathf.Lerp(0.35f, 1f, teleK), dark);
                Ring(0.10f + 0.25f * teleK, Mathf.Lerp(0.5f, 1f, teleK), def.color);
            }
            else if (InActive)
            {
                float fade = 1f - activeK;
                Blob(0.5f * fade + 0.1f, 1f + 0.15f * activeK, def.color);
                Ring(0.85f * fade, Mathf.Lerp(0.6f, 1.9f, activeK), def.color);
                SparksRadial(activeK, 0.55f, 1.35f);
            }
            else Reset();
        }

        private void RenderPulse(float teleK, float activeK)
        {
            if (InTelegraph)
            {
                Reset();
                Ring(0.15f + 0.35f * teleK, Mathf.Lerp(0.22f, 0.36f, teleK), def.color);
                Blob(0.06f + 0.1f * teleK, 0.5f + 0.2f * teleK, def.color);
            }
            else if (InActive)
            {
                Ring(1f - activeK, Mathf.Lerp(0.3f, 2f, activeK), def.color);
                Blob((1f - activeK) * 0.25f, 0.5f, def.color);
                SparksRadial(activeK, 0.5f, 1.6f);
            }
            else Reset();
        }

        private void RenderArc(float teleK, float activeK)
        {
            if (_band == null) return;
            var c = def.color;
            bool horizontal = def.size.x >= def.size.y;
            float w = horizontal ? def.size.x : def.size.y;
            float h = (horizontal ? def.size.y : def.size.x) * 0.55f;

            if (InTelegraph)
            {
                Reset();
                c.a = 0.10f + 0.16f * teleK * (Mathf.Repeat(_cycle * 9f, 1f) > 0.5f ? 1f : 0.4f);
                Set(_band, w, h * Mathf.Lerp(0.25f, 0.6f, teleK), c);
                _band.transform.localRotation = Quaternion.Euler(0f, 0f, horizontal ? 0f : 90f);
            }
            else if (InActive)
            {
                Reset();
                c.a = 0.55f * (1f - activeK) + 0.2f * (Mathf.Repeat(_cycle * 24f, 1f) > 0.5f ? 1f : 0.35f);
                Set(_band, w, h, c);
                _band.transform.localRotation = Quaternion.Euler(0f, 0f, horizontal ? 0f : 90f);
                for (int i = 0; i < _sparks.Count; i++)
                {
                    float t = Mathf.Repeat((i / (float)_sparks.Count) + activeK * 1.5f, 1f);
                    float off = Mathf.Lerp(-w * 0.5f, w * 0.5f, t);
                    var p = horizontal ? new Vector3(off, Random.Range(-h, h) * 0.3f, 0f) : new Vector3(Random.Range(-h, h) * 0.3f, off, 0f);
                    Set(_sparks[i], 0.45f, 0f, new Color(1f, 1f, 1f, 0.7f * (1f - activeK)));
                    _sparks[i].transform.localPosition = p;
                }
            }
            else Reset();
        }

        private void RenderWind(float teleK, float activeK)
        {
            if (_band == null) return;
            bool horizontal = def.size.x >= def.size.y;
            float len = (horizontal ? def.size.x : def.size.y) * 1.35f;
            float thick = (horizontal ? def.size.y : def.size.x) * 1.25f;

            if (InTelegraph)
            {
                Reset();
                var c = def.color; c.a = 0.10f + 0.14f * teleK;
                Set(_band, len, thick * 0.5f, c);
                float start = horizontal ? -def.size.x * 0.5f : -def.size.y * 0.5f;
                _band.transform.localPosition = horizontal ? new Vector3(start, 0f, 0f) : new Vector3(0f, start, 0f);
                _band.transform.localRotation = Quaternion.Euler(0f, 0f, horizontal ? 0f : 90f);
            }
            else if (InActive)
            {
                Reset();
                var c = def.color; c.a = 0.3f * (1f - activeK * 0.5f);
                Set(_band, len, thick, c);
                float k = Mathf.SmoothStep(0f, 1f, activeK);
                if (horizontal) _band.transform.localPosition = new Vector3(Mathf.Lerp(-def.size.x * 0.5f, def.size.x * 0.5f, k), 0f, 0f);
                else _band.transform.localPosition = new Vector3(0f, Mathf.Lerp(-def.size.y * 0.5f, def.size.y * 0.5f, k), 0f);
                _band.transform.localRotation = Quaternion.Euler(0f, 0f, horizontal ? 0f : 90f);
            }
            else Reset();
        }

        private void RenderCoins(float teleK, float activeK)
        {
            Blob(InTelegraph ? 0.12f * teleK : 0.18f * (1f - activeK * 0.6f), 1f, def.color);
            for (int i = 0; i < _sparks.Count; i++)
            {
                var s = _sparks[i];
                if (s == null) continue;
                float seed = Mathf.Abs(Mathf.Sin(i * 12.9898f) * 43758.5453f) % 1f;
                float t = Mathf.Repeat(Tele + activeK * Mathf.Max(0.0001f, def.active) - seed * 0.6f, Mathf.Max(0.0001f, def.interval));
                if (InTelegraph || !InActive) { Set(s, 0f, 0f, Color.clear); continue; }
                float k = Mathf.Clamp01(t / Mathf.Max(0.0001f, def.active));
                float x = Mathf.Lerp(-def.size.x * 0.45f, def.size.x * 0.45f, Mathf.Repeat(seed * 7.3f, 1f));
                float y = Mathf.Lerp(def.size.y * 0.6f, -def.size.y * 0.4f, k);
                Set(s, 0.32f, 0.32f, new Color(1f, 1f, 1f, 0.85f * (1f - k * k)));
                s.transform.localPosition = new Vector3(x, y, 0f);
            }
        }

        /// <summary>Zona persistente (esporas / frio / fuego): nube que respira.</summary>
        private void RenderField(float teleK, float activeK, float peak)
        {
            if (InTelegraph)
            {
                Reset();
                Blob(peak * 0.45f * teleK, Mathf.Lerp(0.75f, 1f, teleK), def.color);
            }
            else if (InActive)
            {
                float breath = 0.85f + 0.15f * Mathf.Sin(Time.time * 5f);
                Blob(peak * (1f - activeK * 0.35f) * breath, 1f + 0.04f * Mathf.Sin(Time.time * 3f), def.color);
                for (int i = 0; i < _sparks.Count; i++)
                {
                    var s = _sparks[i];
                    if (s == null) continue;
                    float seed = Mathf.Abs(Mathf.Sin(i * 78.233f) * 43758.5453f) % 1f;
                    float a = seed * Mathf.PI * 2f + Time.time * (0.4f + seed * 0.5f);
                    float r = (0.15f + 0.3f * seed) * Mathf.Max(def.size.x, def.size.y) * 0.5f;
                    Set(s, 0.35f, 0.35f, new Color(1f, 1f, 1f, 0.35f * (1f - activeK * 0.5f)));
                    s.transform.localPosition = new Vector3(Mathf.Cos(a) * r, Mathf.Sin(a) * r * 0.8f, 0f);
                }
            }
            else Reset();
        }

        private void Ring(float alpha, float scale, Color tint)
        {
            if (_ring == null) { Set(_ring, 0f, 0f, Color.clear); return; }
            var c = tint; c.a = alpha;
            float size = Radius() * 2.1f * scale;
            Set(_ring, size, size, c);
        }

        private void SparksRadial(float k, float from, float to)
        {
            for (int i = 0; i < _sparks.Count; i++)
            {
                var s = _sparks[i];
                if (s == null) continue;
                float seed = Mathf.Abs(Mathf.Sin(i * 45.1234f) * 43758.5453f) % 1f;
                float a = seed * Mathf.PI * 2f;
                float r = Mathf.Lerp(from, to, k) * Radius() * (0.7f + seed * 0.5f);
                Set(s, 0.3f * (1f - k), 0.3f * (1f - k), new Color(1f, 1f, 1f, 0.7f * (1f - k)));
                s.transform.localPosition = new Vector3(Mathf.Cos(a) * r, Mathf.Sin(a) * r * 0.75f, 0f);
            }
        }
    }
}
