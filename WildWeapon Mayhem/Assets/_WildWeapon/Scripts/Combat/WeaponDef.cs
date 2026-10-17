using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Definicion de arma (data-driven, seccion 9 del documento).
    /// F0: solo M1 melee; Q/E/R llegan en F1.
    /// </summary>
    [CreateAssetMenu(fileName = "WeaponDef", menuName = "WildWeapon/Weapon Def")]
    public class WeaponDef : ScriptableObject
    {
        public string displayName = "Arma";
        public float damage = 12f;
        public float cadence = 0.35f;      // segundos entre basicos
        public float range = 0.9f;         // unidades desde el centro
        [Range(30f, 360f)] public float arcDegrees = 120f;
        public Color color = Color.white;
        public Vector2 bladeSize = new Vector2(0.8f, 0.1f);
        public float bladeOffset = 0.55f;
    }
}
