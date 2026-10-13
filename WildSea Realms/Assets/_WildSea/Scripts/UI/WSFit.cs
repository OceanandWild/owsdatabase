using UnityEngine;
using UnityEngine.UIElements;

namespace WildSea.UI
{
    /// <summary>
    /// La raíz del panel no siempre tiene altura fija (flex-grow o absolute contra
    /// left/top/right/bottom no estiran y overflow:hidden recorta el contenido).
    /// Aquí se le da tamaño explícito = tamaño visible del panel en unidades.
    /// Uso: WSFit.Update(root, doc, ref fitW, ref fitH) en Build() y en Update().
    /// </summary>
    public static class WSFit
    {
        public static void Update(VisualElement root, UIDocument doc, ref int fitW, ref int fitH)
        {
            if (root == null || doc == null) return;
            int sw = Screen.width, sh = Screen.height;
            if (sw < 2 || sh < 2 || (sw == fitW && sh == fitH)) return;

            // El tamaño queda cacheado siempre, incluso en los modos donde no
            // podemos derivar unidades: así el llamador no reintenta cada frame.
            fitW = sw;
            fitH = sh;

            float w = sw, h = sh;
            var ps = doc.panelSettings;
            if (ps != null && ps.scaleMode.ToString() == "ScaleWithScreenSize")
            {
                float refW = Mathf.Max(1, ps.referenceResolution.x);
                float refH = Mathf.Max(1, ps.referenceResolution.y);
                float wS = sw / refW, hS = sh / refH;
                string mode = ps.screenMatchMode.ToString();
                float scale = mode == "Expand" ? Mathf.Min(wS, hS)
                            : mode == "Shrink" ? Mathf.Max(wS, hS)
                            : Mathf.Lerp(wS, hS, Mathf.Clamp01(ps.match));
                scale *= ps.scale;
                if (scale < 0.0001f) return;
                w = sw / scale;
                h = sh / scale;
            }
            else if (ps != null && ps.scaleMode.ToString() == "ConstantPhysicalSize")
            {
                return; // resolución física: no podemos derivar unidades con seguridad
            }

            root.style.width = w;
            root.style.height = h;
        }
    }
}
