using UnityEngine;

namespace WildWeapon
{
    public enum AbilityKind { CircularSlash, DashSlash, RadialBurst }

    /// <summary>
    /// Definicion de habilidad de arma (Q/E/R), data-driven (doc maestro §2.4 y §9).
    /// Se referencia desde WeaponDef y la ejecuta AbilityCaster.
    /// </summary>
    [CreateAssetMenu(fileName = "AbilityDef", menuName = "WildWeapon/Ability Def")]
    public class AbilityDef : ScriptableObject
    {
        [Header("Identidad")]
        public string abilityName = "Habilidad";
        public AbilityKind kind = AbilityKind.CircularSlash;

        [Header("Juego")]
        public float damage = 20f;
        public float cooldown = 6f;
        [Tooltip("Duracion total del cast: windup -> active -> recovery")]
        public float castDuration = 0.5f;
        [Tooltip("Fraccion del cast que es windup (te golpean ahi = dano x1.25)")]
        [Range(0f, 0.9f)] public float windupFraction = 0.3f;

        [Header("Efecto — CircularSlash")]
        public float radius = 1.2f;
        public float stunSeconds = 0.4f;

        [Header("Efecto — DashSlash")]
        public float dashDistance = 2.5f;

        [Header("Efecto — RadialBurst")]
        public int projectileCount = 8;
        public float projectileSpeed = 9f;
        public float projectileLife = 0.5f;
        public float projectileDamage = 48f;

        [Header("Definitiva")]
        [Tooltip("Adrenalina que consume (100 = definitiva del portador)")]
        public float adrenalineCost = 0f;

        [Header("Visual")]
        [Tooltip("VFX en el portador al iniciar el cast (anillo/telegraph); se escala al radio")]
        public GameObject castVfx;
        [Tooltip("VFX en cada objetivo alcanzado")]
        public GameObject hitVfx;
    }
}
