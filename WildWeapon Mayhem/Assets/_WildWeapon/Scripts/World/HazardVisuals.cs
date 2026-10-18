using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Skin de los peligros de arena: el builder la cuelga de la escena Arena y los
    /// <see cref="ArenaHazard"/> la levantan en runtime (si falta, el peligro funciona
    /// igual pero sin dibujo).
    /// </summary>
    public class HazardVisuals : MonoBehaviour
    {
        /// <summary>Mancha radial suave (Art/VFX/soft_circle).</summary>
        public Sprite soft;
        /// <summary>Anillo suave (Art/VFX/vfx_ring).</summary>
        public Sprite ring;
        public Material unlit;

        public static HazardVisuals Instance { get; private set; }

        private void Awake() { Instance = this; }
        private void OnDestroy() { if (Instance == this) Instance = null; }
    }
}
