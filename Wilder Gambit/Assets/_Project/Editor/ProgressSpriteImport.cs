#if UNITY_EDITOR
using System;
using System.Collections.Generic;
using UnityEditor;
using UnityEngine;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Deja listos los PNG de <c>Assets/Resources/UI/Progress</c>,
    /// <c>Assets/Resources/UI/Chest</c>, <c>Assets/Resources/UI/Inventory</c> y
    /// <c>Assets/Resources/UI/Packs</c> y <c>Assets/Resources/UI/Halloween</c> al importarlos,
    /// para que el 9-slice que aplican ProgressSprites.cs y ChestSprites.cs no dependa de
    /// tocar 40 texturas a mano:
    /// Sprite, Single, Mesh Type Full Rect, sin compresión, sin mipmaps y Wrap Clamp.
    ///
    /// Los .meta los genera Unity (no se escriben a mano). El marcador guardado en
    /// <c>userData</c> hace que, una vez configurado un sprite, no se vuelvan a pisar los
    /// ajustes que alguien haya cambiado a mano. Para reaplicarlos: menú
    /// <c>Wilder Gambit &gt; Reimportar sprites de PROGRESO</c>, <c>... del COFRE</c>,
    /// <c>... del INVENTARIO</c> o <c>... de PAQUETES</c> o <c>Wilder Gambit &gt; Reimportar sprites de HALLOWEEN</c>.
    /// </summary>
    public sealed class ProgressSpriteImport : AssetPostprocessor
    {
        private const string PROGRESS_FOLDER = "Assets/Resources/UI/Progress/";
        private const string CHEST_FOLDER = "Assets/Resources/UI/Chest/";
        private const string INVENTORY_FOLDER = "Assets/Resources/UI/Inventory/";
        private const string PACKS_FOLDER = "Assets/Resources/UI/Packs/";
        private const string HALLOWEEN_FOLDER = "Assets/Resources/UI/Halloween/";

        private const string PROGRESS_MARKER = "wg-progress-sprite";
        private const string CHEST_MARKER = "wg-chest-sprite";
        private const string INVENTORY_MARKER = "wg-inventory-sprite";
        private const string PACKS_MARKER = "wg-packs-sprite";
        private const string HALLOWEEN_MARKER = "wg-halloween-sprite";

        /// <summary>
        /// Bordes de 9-slice de los marcos de carta, en píxeles del sprite
        /// (izquierda, abajo, derecha, arriba). Son los medidos sobre los PNG de 320 px:
        /// el ornamento mide 32–33 px por lado en común/rara y algo más en épica
        /// (39 px de arriba) y legendaria (41 px, la corona de laurel).
        /// </summary>
        private static readonly Dictionary<string, Vector4> ChestSliceBorders =
            new Dictionary<string, Vector4>(StringComparer.OrdinalIgnoreCase)
            {
                { "card_reward_frame_common.png", new Vector4(32f, 33f, 32f, 33f) },
                { "card_reward_frame_rare.png", new Vector4(32f, 33f, 32f, 33f) },
                { "card_reward_frame_epic.png", new Vector4(32f, 39f, 32f, 39f) },
                { "card_reward_frame_legendary.png", new Vector4(33f, 41f, 33f, 41f) },
            };

        private void OnPreprocessTexture()
        {
            string path = assetPath.Replace('\\', '/');
            bool progress = path.StartsWith(PROGRESS_FOLDER, StringComparison.OrdinalIgnoreCase);
            bool chest = path.StartsWith(CHEST_FOLDER, StringComparison.OrdinalIgnoreCase);
            bool inventory = path.StartsWith(INVENTORY_FOLDER, StringComparison.OrdinalIgnoreCase);
            bool packs = path.StartsWith(PACKS_FOLDER, StringComparison.OrdinalIgnoreCase);
            bool halloween = path.StartsWith(HALLOWEEN_FOLDER, StringComparison.OrdinalIgnoreCase);
            if (!progress && !chest && !inventory && !packs && !halloween) return;
            if (!path.EndsWith(".png", StringComparison.OrdinalIgnoreCase)) return;

            TextureImporter importer = assetImporter as TextureImporter;
            if (importer == null) return;

            string marker = chest ? CHEST_MARKER
                           : inventory ? INVENTORY_MARKER
                           : packs ? PACKS_MARKER
                           : halloween ? HALLOWEEN_MARKER
                           : PROGRESS_MARKER;
            if (importer.userData == marker) return;

            Configure(importer, marker);

            if (chest)
            {
                string file = path.Substring(path.LastIndexOf('/') + 1);
                if (ChestSliceBorders.TryGetValue(file, out Vector4 border))
                {
                    importer.spriteBorder = border;
                }
            }
        }

        private static void Configure(TextureImporter importer, string marker)
        {
            importer.textureType = TextureImporterType.Sprite;
            importer.spriteImportMode = SpriteImportMode.Single;
            importer.alphaIsTransparency = true;
            importer.mipmapEnabled = false;
            importer.wrapMode = TextureWrapMode.Clamp;           // sin sangrado al estirar
            importer.filterMode = FilterMode.Bilinear;
            importer.textureCompression = TextureImporterCompression.Uncompressed;
            importer.maxTextureSize = 2048;

            // spriteMeshType solo se puede fijar desde TextureImporterSettings
            // (en Unity 6 no existe la propiedad directa en TextureImporter).
            TextureImporterSettings settings = new TextureImporterSettings();
            importer.ReadTextureSettings(settings);
            settings.spriteMeshType = SpriteMeshType.FullRect;   // el 9-slice lo necesita
            importer.SetTextureSettings(settings);

            importer.userData = marker;
        }

        /// <summary>Reaplica los ajustes por si los PNG entraron antes que este script.</summary>
        [MenuItem("Wilder Gambit/Reimportar sprites de PROGRESO")]
        public static void ReimportProgressSprites()
        {
            Reimport(PROGRESS_FOLDER, "PROGRESO");
        }

        [MenuItem("Wilder Gambit/Reimportar sprites del COFRE")]
        public static void ReimportChestSprites()
        {
            Reimport(CHEST_FOLDER, "COFRE");
        }

        [MenuItem("Wilder Gambit/Reimportar sprites del INVENTARIO")]
        public static void ReimportInventorySprites()
        {
            Reimport(INVENTORY_FOLDER, "INVENTARIO");
        }

        [MenuItem("Wilder Gambit/Reimportar sprites de PAQUETES")]
        public static void ReimportPackSprites()
        {
            Reimport(PACKS_FOLDER, "PAQUETES");
        }

        [MenuItem("Wilder Gambit/Reimportar sprites de HALLOWEEN")]
        public static void ReimportHalloweenSprites()
        {
            Reimport(HALLOWEEN_FOLDER, "HALLOWEEN");
        }

        private static void Reimport(string folder, string label)
        {
            string[] guids = AssetDatabase.FindAssets("t:Texture2D", new[] { folder.TrimEnd('/') });
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

            Debug.Log($"[Wilder Gambit] Sprites de {label} reimportados: {count}");
        }
    }
}
#endif
