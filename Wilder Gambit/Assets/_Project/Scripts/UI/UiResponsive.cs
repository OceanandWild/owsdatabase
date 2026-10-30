using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem.UI;
using UnityEngine.UI;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Breakpoints de UI Toolkit. USS no soporta @media, así que las clases
    /// is-wide / is-narrow / is-small / is-tiny / is-short / is-mobile se alternan
    /// desde C# según el tamaño real del panel (para poder escribir reglas
    /// ".is-narrow .foo"). En pantallas 16:9 o más anchas fija la escala (match = 1) para que siempre
    /// quepa el alto de diseño de 1080, y aplica el safe area de móvil.
    /// </summary>
    public static class UiResponsive
    {
        public const string WideClass = "is-wide";
        public const string NarrowClass = "is-narrow";
        public const string SmallClass = "is-small";
        public const string TinyClass = "is-tiny";
        public const string ShortClass = "is-short";
        public const string MobileClass = "is-mobile";
        public const string PortraitClass = "is-portrait";
        private const string AttachedClass = "has-breakpoints";

        // Umbrales en unidades del panel (la resolución de diseño es 1920x1080)
        public const float WideThreshold = 1960f;
        public const float NarrowThreshold = 1150f;
        public const float SmallThreshold = 950f;
        public const float TinyThreshold = 750f;
        public const float ShortThreshold = 1040f;
        private const float WideAspect = 16f / 9f;

        private static readonly Dictionary<VisualElement, Vector4> _lastPadding =
            new Dictionary<VisualElement, Vector4>();

        public static bool IsWideAspect =>
            Screen.height > 0 && Screen.width / (float)Screen.height >= WideAspect;

        /// <summary>match recomendado: en pantallas anchas el alto de diseño siempre cabe.</summary>
        public static float ResponsiveMatch => IsWideAspect ? 1f : 0.5f;

        public static void Attach(UIDocument document, VisualElement safeAreaTarget = null)
        {
            if (document == null) return;

            PanelSettings settings = document.panelSettings;
            ApplyPanelScale(settings);

            VisualElement root = document.rootVisualElement;
            if (root == null) return;
            if (root.ClassListContains(AttachedClass)) return;
            root.AddToClassList(AttachedClass);

            VisualElement target = safeAreaTarget != null ? safeAreaTarget : root;
            root.RegisterCallback<GeometryChangedEvent>(_ =>
            {
                ApplyPanelScale(settings);
                Apply(root, target);
            });
            Apply(root, target);
        }

        /// <summary>Aplica la misma regla de escala a los CanvasScaler creados por código (modales uGUI, cinemáticas).</summary>
        public static void ApplyCanvasScaler(CanvasScaler scaler)
        {
            if (scaler == null) return;
            scaler.matchWidthOrHeight = ResponsiveMatch;
        }

        private static void ApplyPanelScale(PanelSettings settings)
        {
            if (settings == null) return;
            float target = ResponsiveMatch;
            if (!Mathf.Approximately(settings.match, target))
                settings.match = target;
        }

        private static void Apply(VisualElement root, VisualElement safeAreaTarget)
        {
            float w = root.resolvedStyle.width;
            float h = root.resolvedStyle.height;
            if (w <= 1f || h <= 1f) return;

            SetClass(root, WideClass, w >= WideThreshold);
            SetClass(root, NarrowClass, w <= NarrowThreshold);
            SetClass(root, SmallClass, w <= SmallThreshold);
            SetClass(root, TinyClass, w <= TinyThreshold);
            SetClass(root, ShortClass, h <= ShortThreshold);
            SetClass(root, MobileClass, Application.isMobilePlatform);
            SetClass(root, PortraitClass, h > w);

            ApplySafeArea(safeAreaTarget, w, h);
        }

        private static void SetClass(VisualElement element, string className, bool on)
        {
            if (on && !element.ClassListContains(className)) element.AddToClassList(className);
            else if (!on && element.ClassListContains(className)) element.RemoveFromClassList(className);
        }

        /// <summary>
        /// Insets del safe area (muescas / punch-hole) convertidos a unidades del panel.
        /// Sin insets (escritorio / editor) limpia el padding y no hace nada.
        /// Solo escribe cuando el valor cambia para no provocar bucles de layout.
        /// </summary>
        private static void ApplySafeArea(VisualElement target, float panelW, float panelH)
        {
            Rect safe = Screen.safeArea;
            if (Screen.width <= 0 || Screen.height <= 0 || target == null) return;

            Vector4 wanted;
            bool hasInset = safe.xMin > 0.5f || safe.yMin > 0.5f
                            || safe.xMax < Screen.width - 0.5f || safe.yMax < Screen.height - 0.5f;
            if (hasInset)
            {
                float sx = panelW / Screen.width;
                float sy = panelH / Screen.height;
                wanted = new Vector4(safe.xMin * sx, (Screen.width - safe.xMax) * sx,
                                     (Screen.height - safe.yMax) * sy, safe.yMin * sy);
            }
            else
            {
                wanted = Vector4.zero;
            }

            if (_lastPadding.TryGetValue(target, out Vector4 last) &&
                Mathf.Abs(last.x - wanted.x) < 0.5f && Mathf.Abs(last.y - wanted.y) < 0.5f &&
                Mathf.Abs(last.z - wanted.z) < 0.5f && Mathf.Abs(last.w - wanted.w) < 0.5f)
                return;

            _lastPadding[target] = wanted;
            target.style.paddingLeft = wanted.x;
            target.style.paddingRight = wanted.y;
            target.style.paddingTop = wanted.z;
            target.style.paddingBottom = wanted.w;
        }
    }
}
