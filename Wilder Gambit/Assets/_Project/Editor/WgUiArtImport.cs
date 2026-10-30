#if UNITY_EDITOR
using System;
using System.Collections.Generic;
using UnityEditor;
using UnityEngine;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Deja listos los PNG del kit de UI del tema (<c>Assets/Resources/UI/Wg</c>)
    /// al importarlos, para que el 9-slice de <c>WgTheme.uss</c> no dependa de
    /// tocar texturas a mano: Sprite Single, Full Rect, sin compresión, sin
    /// mipmaps, Wrap Clamp y el borde de 9-slice medido de cada placa.
    ///
    /// El borde del sprite y los valores <c>-unity-slice-*</c> de WgTheme.uss
    /// tienen que decir lo mismo: si se cambia el tamaño de una placa en
    /// <c>Tools/build-ui-kit.ps1</c>, actualizar acá y en el USS.
    /// Para reaplicar: menú <c>Wilder Gambit &gt; Reimportar sprites del TEMA UI</c>.
    /// </summary>
    public sealed class WgUiArtImport : AssetPostprocessor
    {
        public const string FOLDER = "Assets/Resources/UI/Wg/";

        private const string MARKER = "wg-theme-sprite";

        /// <summary>
        /// Borde de 9-slice por archivo, en píxeles del sprite:
        /// (izquierda, abajo, derecha, arriba). Las placas que no están acá se
        /// importan sin borde (ornamentos que se usan con scale-to-fit).
        /// </summary>
        private static readonly Dictionary<string, Vector4> SliceBorders =
            new Dictionary<string, Vector4>(StringComparer.OrdinalIgnoreCase)
            {
                { "wg_window.png",   new Vector4(150f, 150f, 150f, 150f) },
                { "wg_panel.png",    new Vector4(130f, 130f, 130f, 130f) },
                { "wg_card.png",     new Vector4(72f, 72f, 72f, 72f) },
                { "wg_btn.png",      new Vector4(110f, 40f, 110f, 40f) },
                { "wg_btn_dark.png", new Vector4(110f, 40f, 110f, 40f) },
                { "wg_tile.png",     new Vector4(30f, 30f, 30f, 30f) },
                { "wg_chip.png",     new Vector4(26f, 18f, 26f, 18f) },
            };

        private void OnPreprocessTexture()
        {
            string path = assetPath.Replace('\\', '/');
            if (!path.StartsWith(FOLDER, StringComparison.OrdinalIgnoreCase)) return;
            if (!path.EndsWith(".png", StringComparison.OrdinalIgnoreCase)) return;

            TextureImporter importer = assetImporter as TextureImporter;
            if (importer == null) return;
            if (importer.userData == MARKER) return;

            Configure(importer);

            string file = path.Substring(path.LastIndexOf('/') + 1);
            if (SliceBorders.TryGetValue(file, out Vector4 border))
                importer.spriteBorder = border;

            importer.userData = MARKER;
        }

        private static void Configure(TextureImporter importer)
        {
            importer.textureType = TextureImporterType.Sprite;
            importer.spriteImportMode = SpriteImportMode.Single;
            importer.spritePixelsPerUnit = 100f;
            importer.alphaIsTransparency = true;   // evita el filo oscuro al escalar
            importer.mipmapEnabled = false;
            importer.wrapMode = TextureWrapMode.Clamp;
            importer.filterMode = FilterMode.Bilinear;
            importer.textureCompression = TextureImporterCompression.Uncompressed;
            importer.maxTextureSize = 2048;

            // spriteMeshType solo se puede fijar desde TextureImporterSettings.
            TextureImporterSettings settings = new TextureImporterSettings();
            importer.ReadTextureSettings(settings);
            settings.spriteMeshType = SpriteMeshType.FullRect;   // el 9-slice lo necesita
            importer.SetTextureSettings(settings);
        }

        /// <summary>Reaplica los ajustes por si los PNG entraron antes que este script.</summary>
        [MenuItem("Wilder Gambit/Reimportar sprites del TEMA UI")]
        public static void ReimportThemeSprites()
        {
            string[] guids = AssetDatabase.FindAssets("t:Texture2D", new[] { FOLDER.TrimEnd('/') });
            int count = 0;

            foreach (string guid in guids)
            {
                string path = AssetDatabase.GUIDToAssetPath(guid);
                if (!path.EndsWith(".png", StringComparison.OrdinalIgnoreCase)) continue;

                TextureImporter importer = AssetImporter.GetAtPath(path) as TextureImporter;
                if (importer == null) continue;

                importer.userData = string.Empty;   // vuelve a habilitar el postprocesado
                AssetDatabase.ImportAsset(path, ImportAssetOptions.ForceUpdate);
                count++;
            }

            Debug.Log($"[Wilder Gambit] Sprites del TEMA UI reimportados: {count}");
        }
    }
}
#endif
