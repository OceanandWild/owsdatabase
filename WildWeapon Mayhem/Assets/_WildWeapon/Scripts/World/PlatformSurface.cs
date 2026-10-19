using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Deck elevado de la arena. Lo registra <see cref="MapGenerator"/> y lo consulta
    /// <see cref="HeightBody"/> para resolver aterrizajes.
    ///
    /// Reglas (mapa puramente 2D, sin salto fisico):
    /// - Por debajo del deck NO hay colision: se camina por debajo sin trabas.
    /// - Se puede saltar desde abajo y atravesar el deck hacia arriba; al caer, se aterriza encima.
    /// - Desde arriba no se baja a traves del deck: hay que caminar hasta el borde y caer.
    /// </summary>
    [DisallowMultipleComponent]
    public class PlatformSurface : MonoBehaviour
    {
        /// <summary>Decks activos de la escena (los registra/desregistra el propio componente).</summary>
        public static readonly List<PlatformSurface> All = new List<PlatformSurface>();

/// <summary>Etapa 2: si es true, el suelo (Z=0) solo existe en la tira inferior de la arena.</summary>
public static bool GroundOnlyBottom = false;
/// <summary>Mitad Y de la arena (para saber que es "abajo").</summary>
public static float ArenaHalfY = 10f;

        public Vector2 center;
        public Vector2 size = new Vector2(4f, 2.5f);
        [Tooltip("Altura del deck en unidades de Z")] public float top = 0.95f;
        [Tooltip("Collider que deja de bloquear cuando el cuerpo esta arriba (obstaculos saltables). Vacio = deck sin laterales")] public Collider2D solid;

        private void OnEnable() { if (!All.Contains(this)) All.Add(this); }
        private void OnDisable() { All.Remove(this); }

        public bool Contains(Vector2 p, float pad)
        {
            Vector2 d = p - center;
            return Mathf.Abs(d.x) <= size.x * 0.5f + pad && Mathf.Abs(d.y) <= size.y * 0.5f + pad;
        }

        /// <summary>Altura de la superficie mas alta que sostiene a un cuerpo en 'p' con altura 'z'. 0 = piso de la arena.</summary>
        public static float HighestTopBelow(Vector2 p, float z, float pad)
        {
            // Etapa 2: suelo solo en la tira inferior cuando GroundOnlyBottom esta activo.
            bool groundHere = !GroundOnlyBottom || p.y <= -ArenaHalfY + 2.5f;
            float best = groundHere ? 0f : float.MinValue;
            for (int i = 0; i < All.Count; i++)
            {
                var s = All[i];
                if (s == null) continue;
                if (s.top > best && s.top <= z + 0.06f && s.Contains(p, pad)) best = s.top;
            }
            return best;
        }

        /// <summary>Superficie mas alta en 'p' (para saber contra que deck choca un golpe aereo).</summary>
        public static PlatformSurface TopAt(Vector2 p, float pad)
        {
            PlatformSurface best = null;
            for (int i = 0; i < All.Count; i++)
            {
                var s = All[i];
                if (s == null || !s.Contains(p, pad)) continue;
                if (best == null || s.top > best.top) best = s;
            }
            return best;
        }

        /// <summary>Plataforma mas cercana a 'p' dentro del radio (para que los bots decidan saltar).</summary>
        public static PlatformSurface Nearest(Vector2 p, float radius)
        {
            PlatformSurface best = null;
            float bestD = radius * radius;
            for (int i = 0; i < All.Count; i++)
            {
                var s = All[i];
                if (s == null) continue;
                Vector2 d = p - s.center;
                float dd = d.sqrMagnitude;
                if (dd < bestD) { bestD = dd; best = s; }
            }
            return best;
        }
    }
}
