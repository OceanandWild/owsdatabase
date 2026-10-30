#if UNITY_EDITOR
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using UnityEditor;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Verificación headless del tema de UI. Corre en batchmode:
    /// <c>-executeMethod WilderGambit.Editor.WgUiCheck.Run</c> y sale con código 1
    /// si algo falta, así el pipeline (o un agente) detecta el problema sin abrir
    /// el editor. Revisa:
    ///   1. que el kit de sprites exista y se importe como Sprite con alpha,
    ///   2. que WgTheme.uss cargue y que sus url("project://...") apunten a algo,
    ///   3. que MainMenu.uxml y PauseMenu.uxml carguen, instancien y referencien
    ///      el tema, y que los nodos clave del menú existan.
    /// </summary>
    public static class WgUiCheck
    {
        private const string ThemePath = "Assets/_Project/UI/WgTheme.uss";
        private const string MenuUxml = "Assets/_Project/UI/MainMenu.uxml";
        private const string PauseUxml = "Assets/_Project/UI/PauseMenu.uxml";
        private const string WgFolder = "Assets/Resources/UI/Wg";

        private static readonly string[] ExpectedSprites =
        {
            "wg_window", "wg_panel", "wg_card", "wg_btn", "wg_btn_dark",
            "wg_tile", "wg_chip", "wg_divider", "wg_medal"
        };

        // Propiedades que USS no soporta y que romperían la hoja al importar.
        private static readonly string[] UnsupportedProperties =
        {
            "box-shadow", "filter", "backdrop-filter", "animation", "transform-origin"
        };

        public static void Run()
        {
            var problems = new List<string>();

            AssetDatabase.Refresh(ImportAssetOptions.ForceUpdate);
            AssetDatabase.SaveAssets();

            CheckSprites(problems);
            CheckTheme(problems);
            CheckDocument(MenuUxml, true, problems);
            CheckDocument(PauseUxml, false, problems);

            if (problems.Count == 0)
            {
                Debug.Log("[WG-UI-CHECK] OK: kit, tema y documentos de UI en orden.");
            }
            else
            {
                foreach (string problem in problems) Debug.LogError("[WG-UI-CHECK] " + problem);
                Debug.LogError($"[WG-UI-CHECK] FALLOS: {problems.Count}");
            }

            if (Application.isBatchMode)
                EditorApplication.Exit(problems.Count == 0 ? 0 : 1);
        }

        private static void CheckSprites(List<string> problems)
        {
            if (!Directory.Exists(WgFolder))
            {
                problems.Add("no existe la carpeta " + WgFolder);
                return;
            }

            foreach (string name in ExpectedSprites)
            {
                string path = $"{WgFolder}/{name}.png";
                if (!File.Exists(path))
                {
                    problems.Add("falta el sprite " + path);
                    continue;
                }

                var importer = AssetImporter.GetAtPath(path) as TextureImporter;
                if (importer == null)
                {
                    problems.Add("sin TextureImporter: " + name);
                    continue;
                }

                if (importer.textureType != TextureImporterType.Sprite)
                    problems.Add("no se importó como Sprite: " + name);
                if (!importer.alphaIsTransparency)
                    problems.Add("alphaIsTransparency apagado: " + name);
                if (importer.maxTextureSize < 2048)
                    problems.Add("maxTextureSize bajo: " + name);

                var sprite = AssetDatabase.LoadAssetAtPath<Sprite>(path);
                if (sprite == null) problems.Add("no carga como Sprite: " + name);
            }
        }

        private static void CheckTheme(List<string> problems)
        {
            var sheet = AssetDatabase.LoadAssetAtPath<StyleSheet>(ThemePath);
            if (sheet == null) problems.Add("WgTheme.uss no carga como StyleSheet");

            if (!File.Exists(ThemePath))
            {
                problems.Add("falta " + ThemePath);
                return;
            }

            string text = File.ReadAllText(ThemePath);

            foreach (Match m in Regex.Matches(text, "project://database/([^\"\\)\\s]+)"))
            {
                string assetPath = m.Groups[1].Value;
                if (!File.Exists(assetPath)) problems.Add("url() roto en WgTheme.uss: " + assetPath);
            }

            foreach (string prop in UnsupportedProperties)
            {
                if (Regex.IsMatch(text, "(?m)^\\s*" + Regex.Escape(prop) + "\\s*:"))
                    problems.Add($"USS no soporta '{prop}' (está en WgTheme.uss)");
            }
        }

        private static void CheckDocument(string uxmlPath, bool isMenu, List<string> problems)
        {
            var tree = AssetDatabase.LoadAssetAtPath<VisualTreeAsset>(uxmlPath);
            if (tree == null)
            {
                problems.Add("no carga el UXML: " + uxmlPath);
                return;
            }

            string text = File.ReadAllText(uxmlPath);
            if (!text.Contains("WgTheme.uss"))
                problems.Add("el UXML no referencia WgTheme.uss: " + uxmlPath);

            try
            {
                var root = tree.Instantiate();
                if (root == null)
                {
                    problems.Add("no se pudo instanciar: " + uxmlPath);
                    return;
                }

                if (isMenu)
                {
                    foreach (string required in new[] { "btn-play", "btn-shop", "shop-modal-view", "difficulty-view" })
                    {
                        if (root.Q<VisualElement>(required) == null)
                            problems.Add($"falta el nodo '{required}' en MainMenu.uxml");
                    }
                }
                else if (root.Q<VisualElement>("pause-menu-root") == null)
                {
                    problems.Add("falta 'pause-menu-root' en PauseMenu.uxml");
                }
            }
            catch (Exception e)
            {
                problems.Add($"excepción al instanciar {uxmlPath}: {e.Message}");
            }
        }
    }
}
#endif
