using UnityEngine;
using UnityEngine.UIElements;

namespace WildSea.UI
{
    /// <summary>
    /// El PanelSettings va sin theme (warning silenciado en el .asset).
    /// Sin theme no hay fuente y ningún Label/Button pinta texto:
    /// aquí asignamos la fuente built-in LegacyRuntime a todo TextElement.
    /// Llamar al final de cada Build y tras crear cards dinámicas.
    /// </summary>
    public static class WSFontFix
    {
        static Font cached;
        static bool warned;

        public static void Apply(VisualElement root)
        {
            if (root == null) return;
            if (cached == null)
                cached = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (cached == null)
            {
                if (!warned) { warned = true; Debug.LogWarning("[WildSea] Sin fuente built-in; el texto puede no verse."); }
                return;
            }
            ApplyRec(root, cached);
        }

        static void ApplyRec(VisualElement e, Font f)
        {
            if (e is TextElement te) te.style.unityFont = new StyleFont(f);
            foreach (var c in e.Children()) ApplyRec(c, f);
        }
    }
}
