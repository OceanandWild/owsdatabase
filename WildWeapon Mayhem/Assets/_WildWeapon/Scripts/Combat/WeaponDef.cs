using UnityEngine;

namespace WildWeapon
{
    public enum SwingStyle { Slash, Thrust, Spin }

    /// <summary>
    /// Definicion de arma (data-driven, seccion 9 del documento).
    /// </summary>
    [CreateAssetMenu(fileName = "WeaponDef", menuName = "WildWeapon/Weapon Def")]
    public class WeaponDef : ScriptableObject
    {
        [Header("Juego")]
        public string displayName = "Arma";
        [Tooltip("Id estable del arma (nombre del asset). La armeria lo usa para armar el equipamiento.")]
        public string id = "";
        public float damage = 12f;
        public float cadence = 0.35f;      // segundos entre basicos
        public float range = 0.9f;         // unidades desde el centro
        [Range(30f, 360f)] public float arcDegrees = 120f;

        [Header("Visual")]
        public Sprite sprite;
        [Tooltip("Largo en unidades del sprite del arma")]
        public float spriteLength = 1f;
        public Color color = Color.white;
        public Vector2 bladeSize = new Vector2(0.8f, 0.1f);   // fallback sin sprite
        public float bladeOffset = 0.55f;
        public SwingStyle swingStyle = SwingStyle.Slash;
        public float swingAngle = 140f;
        public float swingDuration = 0.14f;

        [Header("VFX")]
        public GameObject swingVfx;
        public GameObject hitVfx;
        public bool trail;
        public Color trailColor = new Color(0.4f, 0.9f, 1f, 1f);
        public float shakeOnHit = 0.08f;

        [Header("Habilidades (Q/E/R)")]
        public AbilityDef abilityQ;
        public AbilityDef abilityE;
        public AbilityDef abilityR;
    }
}
