using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Steering compartido por las dos IA de bot (supervivencia: <see cref="EnemyBot"/> y
    /// sala PVP: <see cref="Pvp.PvpBotBrain"/>).
    ///
    /// Antes el pathing era "si el cast hacia el objetivo choca, prueba a girarlo 40/80/120
    /// grados". Eso se trababa: cuando el bot ya estaba encima del obstaculo el cast
    /// devoltaba impacto en todas las direcciones, no habia ninguna libre y el bot se
    /// quedaba empujando contra el obstaculo para siempre (movimiento congelado).
    ///
    /// Ahora el steering:
    /// - desliza a lo largo del obstaculo (proyecta la direccion sobre la normal del
    ///   impacto), que es la salida natural cuando el paso esta bloqueado;
    /// - se despega del obstaculo si ya esta encimado;
    /// - recien ahi prueba los giros alrededor.
    /// </summary>
    public class BotSteering
    {
        private readonly Rigidbody2D _rb;
        private readonly RaycastHit2D[] _hits = new RaycastHit2D[4];

        /// <summary>Signo del rodeo: alterna para que los bots no se peguen al mismo lado.</summary>
        public float StrafeSign = 1f;

        public BotSteering(Rigidbody2D rb)
        {
            _rb = rb;
        }

        /// <summary>Cuanto mira el bot por delante de su propio cuerpo.</summary>
        public float LookAhead(float bodyRadius) => 0.45f + bodyRadius * 0.25f;

        /// <summary>Primer obstaculo en la direccion (null si el paso esta libre).</summary>
        public RaycastHit2D? Blocked(Vector2 dir, float lookAhead)
        {
            if (_rb == null || dir.sqrMagnitude < 0.0001f) return null;
            int n = _rb.Cast(dir, _hits, lookAhead);
            for (int i = 0; i < n; i++)
            {
                var c = _hits[i].collider;
                if (c == null) continue;
                if (c.GetComponent<PlayerHealth>() != null) continue;   // los personajes no bloquean el pathing
                return _hits[i];
            }
            return null;
        }

        /// <summary>true si se puede avanzar en esa direccion.</summary>
        public bool IsFree(Vector2 dir, float lookAhead) => !Blocked(dir, lookAhead).HasValue;

        /// <summary>
        /// Direccion de avance: la del objetivo si el paso esta libre; si no, desliza
        /// por el obstaculo, se despega de el o lo rodea.
        /// </summary>
        public Vector2 Steer(Vector2 desired, float lookAhead)
        {
            if (_rb == null || desired.sqrMagnitude < 0.0001f) return desired;
            desired.Normalize();

            var hit = Blocked(desired, lookAhead);
            if (!hit.HasValue) return desired;

            Vector2 normal = hit.Value.normal;
            if (normal.sqrMagnitude > 0.0001f)
            {
                // Deslizar a lo largo del obstaculo: se saca la parte de la direccion
                // que va contra la normal (proyeccion sobre el plano tangente).
                Vector2 slide = desired - normal * Vector2.Dot(desired, normal);
                if (slide.sqrMagnitude > 0.0001f)
                {
                    slide.Normalize();
                    if (IsFree(slide, lookAhead)) return slide;
                }

                // Encimado al obstaculo (impacto a distancia 0): alejarse para despegarse.
                if (hit.Value.distance <= 0.05f)
                {
                    Vector2 away = -normal;
                    if (IsFree(away, lookAhead)) return away;
                }
            }

            // Rodear el obstaculo.
            float[] tries = { 40f, 80f, 120f, 160f };
            foreach (float a in tries)
            {
                Vector2 d1 = Rotate(desired, a * StrafeSign);
                if (IsFree(d1, lookAhead)) return d1;
                Vector2 d2 = Rotate(desired, -a * StrafeSign);
                if (IsFree(d2, lookAhead)) { StrafeSign = -StrafeSign; return d2; }
            }
            return desired;
        }

        public static Vector2 Rotate(Vector2 v, float deg)
        {
            float r = deg * Mathf.Deg2Rad;
            float c = Mathf.Cos(r), s = Mathf.Sin(r);
            return new Vector2(v.x * c - v.y * s, v.x * s + v.y * c);
        }
    }
}
