using System.Collections.Generic;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Deck elevado de la arena (vista lateral). Lo registra <see cref="MapGenerator"/>
    /// y aporta la huella y la superficie para la camara y la IA.
    ///
    /// La colision real la resuelve un BoxCollider2D + PlatformEffector2D one-way:
    /// - desde abajo se atraviesa saltando,
    /// - desde arriba se aterriza,
    /// - por los costados no bloquea.
    ///
    /// La Y del mundo es la altura: un solo sistema de coordenadas para gameplay,
    /// dibujo (orden por Y) y red.
    /// </summary>
    [DisallowMultipleComponent]
    public class PlatformSurface : MonoBehaviour
    {
        /// <summary>Decks activos de la escena (los registra/desregistra el propio componente).</summary>
        public static readonly List<PlatformSurface> All = new List<PlatformSurface>();

        /// <summary>Y de la superficie del piso de la arena (la fija MapGenerator).</summary>
        public static float FloorY = 0f;

        /// <summary>Mitad Y de la arena (para el orden de dibujo por Y).</summary>
        public static float ArenaHalfY = 10f;

        /// <summary>Centro de la huella del deck, en coordenadas de mundo.</summary>
        public Vector2 center;
        /// <summary>Huella del deck (ancho x alto en unidades de mundo).</summary>
        public Vector2 size = new Vector2(4f, 2.5f);
        [Tooltip("Y de la superficie de apoyo (centro + media altura)")] public float top = 0.95f;

        private void OnEnable() { if (!All.Contains(this)) All.Add(this); }
        private void OnDisable() { All.Remove(this); }

        /// <summary>Y sobre la que se para un personaje encima del deck.</summary>
        public float SurfaceY => center.y + size.y * 0.5f;

        public bool Contains(Vector2 p, float pad)
        {
            Vector2 d = p - center;
            return Mathf.Abs(d.x) <= size.x * 0.5f + pad && Mathf.Abs(d.y) <= size.y * 0.5f + pad;
        }

        public bool OverlapsX(float x, float pad)
            => Mathf.Abs(x - center.x) <= size.x * 0.5f + pad;

        /// <summary>
        /// Orden de dibujo por altura. La Y crece hacia arriba y el fondo esta en
        /// -100, asi que se normaliza contra la arena para que todo quede por
        /// encima del escenario.
        /// </summary>
        public static int OrderAt(float y)
            => Mathf.Max(0, Mathf.RoundToInt((y + ArenaHalfY) * 6f));
    }
}
