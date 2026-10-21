using UnityEngine;

namespace WildWeapon
{
    /// <summary>Definicion data-driven de un bot enemigo (stats + arma unica + rig + IA).</summary>
    [CreateAssetMenu(fileName = "BotDef", menuName = "WildWeapon/Bot Def")]
    public class BotDef : ScriptableObject
    {
        public string displayName = "Bot";
        public WeaponDef weapon;

        [Header("Habilidades (Q/E/R)")]
        [Tooltip("Corte circular (Q): golpea alrededor del bot.")]
        public AbilityDef abilityQ;
        [Tooltip("Dash-tajo (E): avanza golpeando (ademas da i-frames).")]
        public AbilityDef abilityE;
        [Tooltip("Definitiva (R): corte en 8 direcciones (cuesta adrenalina).")]
        public AbilityDef abilityR;

        [Header("Stats")]
        public float hp = 40f;
        public float moveSpeed = 2.4f;
        [Tooltip("Telegrafo antes de golpear (s)")]
        public float windup = 0.35f;
        [Tooltip("Pausa tras golpear (s)")]
        public float recover = 0.35f;
        public float bodyRadius = 0.42f;

        [Header("IA")]
        [Tooltip("Cuanto empuja hacia adelante (0.7 timido - 1.4 agresivo).")]
        public float aggression = 1f;
        [Tooltip("Pericia general (0-1): reaccion, punteria, esquiva y castigo.")]
        public float skill = 0.75f;
        [Tooltip("Distancia que quiere mantener, en multiplos del alcance del arma.")]
        public float preferredGap = 0.95f;
        [Tooltip("Probabilidad de esquivar un telegraph enemigo.")]
        public float dodgeChance = 0.75f;
        [Tooltip("Frecuencia con la que usa las habilidades (0-1).")]
        public float abilityUse = 0.9f;
        [Tooltip("Segundos de reaccion antes de golpear.")]
        public float reaction = 0.16f;

        [Header("Visual")]
        public float visualScale = 1f;
        public float animSpeed = 1f;
        [Tooltip("Color de las placas pintables del rig")]
        public Color tint = Color.white;
        public GameObject deathVfx;
    }
}
