using UnityEngine;

namespace WilderGambit.View
{
    /// <summary>
    /// Spawns particle effects at a position when a piece is captured.
    /// Attach to a GameObject in the scene or use as a static helper.
    /// </summary>
    public class CaptureParticles : MonoBehaviour
    {
        public static CaptureParticles Instance { get; private set; }

        [Header("Prefabs")]
        [SerializeField] private GameObject dustParticlePrefab;
        [SerializeField] private GameObject sparkParticlePrefab;

        [Header("Settings")]
        [SerializeField] private float lifetime = 1.0f;

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
        }

        /// <summary>
        /// Plays capture particles at the given world position.
        /// </summary>
        /// <param name="worldPos">World position of the captured piece.</param>
        /// <param name="isHeavyPiece">True for Rook/Queen/Bishop (sparks), false for Pawn/Knight (dust).</param>
        public void PlayCaptureEffect(Vector3 worldPos, bool isHeavyPiece)
        {
            GameObject prefab = isHeavyPiece ? sparkParticlePrefab : dustParticlePrefab;
            if (prefab == null) return;

            GameObject fx = Instantiate(prefab, worldPos, Quaternion.identity);
            var ps = fx.GetComponent<ParticleSystem>();
            if (ps != null)
            {
                ps.Play();
                Destroy(fx, lifetime);
            }
            else
            {
                Destroy(fx, lifetime);
            }
        }

        /// <summary>Plays a check indicator flash at the king's position.</summary>
        public void PlayCheckEffect(Vector3 worldPos)
        {
            if (sparkParticlePrefab == null) return;

            GameObject fx = Instantiate(sparkParticlePrefab, worldPos, Quaternion.identity);
            var ps = fx.GetComponent<ParticleSystem>();
            if (ps != null)
            {
                var main = ps.main;
                main.startColor = new ParticleSystem.MinMaxGradient(Color.red);
                ps.Play();
                Destroy(fx, lifetime);
            }
            else
            {
                Destroy(fx, lifetime);
            }
        }
    }
}
