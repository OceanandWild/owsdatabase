using UnityEngine;

namespace WildWeapon
{
    /// <summary>Definicion data-driven de un bot enemigo (stats + arma unica + rig).</summary>
    [CreateAssetMenu(fileName = "BotDef", menuName = "WildWeapon/Bot Def")]
    public class BotDef : ScriptableObject
    {
        public string displayName = "Bot";
        public WeaponDef weapon;

        [Header("Stats")]
        public float hp = 40f;
        public float moveSpeed = 2.4f;
        [Tooltip("Telegrafo antes de golpear (s)")]
        public float windup = 0.35f;
        [Tooltip("Pausa tras golpear (s)")]
        public float recover = 0.35f;
        public float bodyRadius = 0.42f;

        [Header("Visual")]
        public float visualScale = 1f;
        public float animSpeed = 1f;
        [Tooltip("Color de las placas pintables del rig")]
        public Color tint = Color.white;
        public GameObject deathVfx;
    }
}
