using UnityEngine;

namespace WildWeapon.UI
{
    /// <summary>
    /// Ancla un objeto de escena (por ejemplo el preview riggeado del menu) arriba de un
    /// elemento de UI, de modo que siga al panel aunque cambie la resolucion.
    /// El offset se expresa en unidades de mundo y se suma a la posicion del target;
    /// la Z del objeto se conserva.
    /// </summary>
    [ExecuteAlways]
    public class MenuPreviewAnchor : MonoBehaviour
    {
        public RectTransform target;
        public Vector2 offset = new Vector2(0f, 0.85f);

        void LateUpdate()
        {
            if (target == null) return;

            Vector3 tPos = target.position;

            // Canvas en Screen Space - Overlay: target.position esta en pixeles de pantalla.
            var canvas = target.GetComponentInParent<Canvas>();
            if (canvas != null && canvas.renderMode == RenderMode.ScreenSpaceOverlay)
            {
                var cam = Camera.main;
                if (cam == null) return;
                float depth = transform.position.z - cam.transform.position.z;
                tPos = cam.ScreenToWorldPoint(new Vector3(tPos.x, tPos.y, depth));
            }

            transform.position = new Vector3(tPos.x + offset.x, tPos.y + offset.y, transform.position.z);
        }
    }
}
