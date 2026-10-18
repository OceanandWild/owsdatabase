using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Marca la pista de musica de la escena actual. Al iniciar le pasa el clip al
    /// MusicSystem persistente (lo crea si no existe). Sin clip asignado, no hace nada.
    /// </summary>
    public class MusicPlayer : MonoBehaviour
    {
        public AudioClip clip;
        [Range(0f, 1f)] public float volume = 0.5f;

        void Start()
        {
            if (clip == null) return;

            var system = MusicSystem.Instance;
            if (system == null)
            {
                var go = new GameObject("MusicSystem");
                system = go.AddComponent<MusicSystem>();
            }
            system.Play(clip, volume);
        }
    }
}
