#if UNITY_EDITOR
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using UnityEditor;
using UnityEditor.Build;
using UnityEngine;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Aplica la identidad visual al build de Windows: icono del ejecutable y splash screen.
    ///
    /// Icono: se le pasa un PNG por tamano que Unity pida para Standalone, eligiendo el fuente mas
    /// cercano. No se fuerza uno solo porque a 16 px el medallion completo se convierte en una mancha
    /// verde y a 256 px un recorte al wordmark se ve pobre; hay un arte distinto para cada escala.
    ///
    /// Splash: el motor no deja ajustar la duracion, asi que el splash del motor queda reducido a un
    /// color plano (sin imagen de fondo, sin animacion) y el icono que se ve al arrancar lo pone la
    /// escena Boot, que si controla los 3 segundos. Ver <c>BootSetup</c>.
    ///
    /// El logo de Unity si se apago (verificado en un build de Windows: el splash sale limpio).
    /// </summary>
    public static class BrandingSetup
    {
        private const string FOLDER = "Assets/_Project/Branding";
        private const string ICON_PREFIX = "wilder-gambit-icon-";

        /// <summary>Personal obliga a un minimo de 0.5 en el overlay del splash.</summary>
        private const float MIN_OVERLAY_OPACITY = 0.5f;

        /// <summary>
        /// Color del fondo del splash del motor. El mismo azul verdoso que usa la escena Boot, para
        /// que el arranque no de un salto de color entre el splash y el icono.
        /// </summary>
        private static readonly Color SplashBackground = new Color(0.039f, 0.129f, 0.188f, 1f);

        [MenuItem("Wilder Gambit/Aplicar icono y splash screen")]
        public static void Apply()
        {
            ApplyIcons();
            ApplySplash();

            AssetDatabase.SaveAssets();
            AssetDatabase.Refresh();
            Debug.Log("[Branding] Icono y splash screen aplicados.");
        }

        /// <summary>Entrada para <c>-executeMethod</c> en modo batch.</summary>
        public static void ApplyFromCommandLine()
        {
            int exitCode = 0;
            try
            {
                Apply();
            }
            catch (Exception e)
            {
                Debug.LogError("[Branding] " + e);
                exitCode = 1;
            }

            EditorApplication.Exit(exitCode);
        }

        private static void ApplyIcons()
        {
            int[] sizes = PlayerSettings.GetIconSizes(NamedBuildTarget.Standalone, IconKind.Application);
            if (sizes == null || sizes.Length == 0)
            {
                Debug.LogWarning("[Branding] Unity no devolvio tamanos de icono para Standalone.");
                return;
            }

            Dictionary<int, Texture2D> available = LoadAvailableIcons();
            if (available.Count == 0)
            {
                Debug.LogWarning("[Branding] No hay iconos en " + FOLDER + ".");
                return;
            }

            // El orden de `sizes` es el que Unity usa para parejar cada textura: no se reordena.
            Texture2D[] icons = sizes
                .Select(s => available[ClosestSize(available.Keys, s)])
                .ToArray();

            PlayerSettings.SetIcons(NamedBuildTarget.Standalone, icons, IconKind.Application);
            Debug.Log("[Branding] Iconos Standalone: " + string.Join(", ", sizes.Select(s => s + "px")));
        }

        private static Dictionary<int, Texture2D> LoadAvailableIcons()
        {
            var found = new Dictionary<int, Texture2D>();
            foreach (string guid in AssetDatabase.FindAssets("t:Texture2D", new[] { FOLDER }))
            {
                string path = AssetDatabase.GUIDToAssetPath(guid).Replace('\\', '/');
                if (!path.Contains(ICON_PREFIX)) continue;

                int slash = path.LastIndexOf('/');
                string file = slash >= 0 ? path.Substring(slash + 1) : path;
                int dot = file.LastIndexOf('.');
                if (dot > 0) file = file.Substring(0, dot);

                string suffix = file.Substring(file.LastIndexOf('-') + 1);
                if (!int.TryParse(suffix, NumberStyles.Integer, CultureInfo.InvariantCulture, out int size)) continue;

                Texture2D tex = AssetDatabase.LoadAssetAtPath<Texture2D>(path);
                if (tex != null) found[size] = tex;
            }

            return found;
        }

        /// <summary>Fuente mas cercano por tamano: el menor que cubra, y si ninguno cubre el mayor.</summary>
        private static int ClosestSize(IEnumerable<int> candidates, int wanted)
        {
            int[] sorted = candidates.OrderBy(c => c).ToArray();
            foreach (int candidate in sorted)
            {
                if (candidate >= wanted) return candidate;
            }

            return sorted[sorted.Length - 1];
        }

        private static void ApplySplash()
        {
            // El splash del motor no lleva arte: el motor escala la imagen hasta cubrir la pantalla y
            // la pondria a sangre. Lo que se ve al arrancar lo arma la escena Boot (icono centrado
            // 3 segundos), y el splash solo hace de telon con el mismo color de fondo.
            PlayerSettings.SplashScreen.show = true;
            PlayerSettings.SplashScreen.background = null;
            PlayerSettings.SplashScreen.backgroundPortrait = null;
            PlayerSettings.SplashScreen.backgroundColor = SplashBackground;
            PlayerSettings.SplashScreen.animationMode = PlayerSettings.SplashScreen.AnimationMode.Static;
            PlayerSettings.SplashScreen.blurBackgroundImage = false;
            PlayerSettings.SplashScreen.overlayOpacity = MIN_OVERLAY_OPACITY;

            HideUnityLogo();
        }

        /// <summary>
        /// Unity documenta que Personal no deja apagar el logo de Unity, pero el setter lo acepta y el
        /// build sale sin el. Se apaga en vez de dejar el valor a mano para que un rebuild no lo
        /// reintroduzca por sorpresa, y se avisa si en algun momento deja de podererse.
        /// </summary>
        private static void HideUnityLogo()
        {
            if (!PlayerSettings.SplashScreen.showUnityLogo) return;

            PlayerSettings.SplashScreen.showUnityLogo = false;
            if (PlayerSettings.SplashScreen.showUnityLogo)
            {
                Debug.LogWarning("[Branding] La licencia no deja ocultar el logo de Unity; aparecera en el splash.");
                return;
            }

            Debug.Log("[Branding] Logo de Unity oculto.");
        }
    }
}
#endif
