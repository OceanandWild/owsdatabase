using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Rig de brazo: despues del Animator (LateUpdate) orienta el brazo delantero
    /// hacia la direccion de apuntado, acompaña el swing del arma y coloca el
    /// AimPivot (donde cuelga el arma) en la mano.
    /// </summary>
    [DefaultExecutionOrder(100)]
    public class RigAimArm : MonoBehaviour
    {
        public Transform upperArm;
        public Transform forearm;
        public Transform hand;
        public Transform aimPivot;
        public PlayerHealth health;
        public WeaponLoadout loadout;
        public MeleeWeapon fixedWeapon;

        [Tooltip("Flexion del codo en grados")]
        public float elbowBend = 28f;
        [Tooltip("Cuanto acompaña el brazo el giro del arma")]
        public float swingFollow = 0.45f;

        void LateUpdate()
        {
            if (upperArm == null || aimPivot == null) return;
            if (health != null && health.IsDead) return;

            var parent = upperArm.parent;
            Vector2 local = parent != null ? (Vector2)parent.InverseTransformVector(aimPivot.right) : (Vector2)aimPivot.right;
            if (local.sqrMagnitude < 1e-6f) return;
            float ang = Mathf.Atan2(local.y, local.x) * Mathf.Rad2Deg;

            float swing = 0f;
            var w = CurrentWeapon();
            if (w != null) swing = w.SwingOffset * swingFollow;
            // Con el padre espejado el sentido del giro se invierte.
            if (parent != null && parent.lossyScale.x < 0f) swing = -swing;

            // Sprite del brazo en reposo apunta hacia abajo (-90).
            upperArm.localRotation = Quaternion.Euler(0f, 0f, ang + 90f - elbowBend * 0.5f + swing);
            if (forearm != null) forearm.localRotation = Quaternion.Euler(0f, 0f, elbowBend);
            if (hand != null) aimPivot.position = hand.position;
        }

        private MeleeWeapon CurrentWeapon()
        {
            if (fixedWeapon != null) return fixedWeapon;
            if (loadout != null && loadout.weapons != null && loadout.weapons.Length > 0)
                return loadout.weapons[Mathf.Clamp(loadout.ActiveIndex, 0, loadout.weapons.Length - 1)];
            return null;
        }
    }
}
