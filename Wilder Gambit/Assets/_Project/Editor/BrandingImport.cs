#if UNITY_EDITOR
using System;
using UnityEditor;
using UnityEngine;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Fija los ajustes de importacion de la carpeta de branding. No es estetico: el icono del
    /// arranque y los iconos del ejecutable se leen del build antes de que exista una escena, asi
    /// que un PNG reimportado como textura normal (o con mipmaps) hace que Unity rechace la
    /// referencia y el build salga con el icono por defecto.
    ///
    /// El icono del arranque entra como <see cref="TextureImporterType.Sprite"/> porque la escena
    /// Boot lo muestra con un <c>Image</c> de UI Toolkit, que solo acepta sprites; los iconos del
    /// ejecutable como textura normal porque <c>SetIconsForTargetGroup</c> solo acepta
    /// <see cref="Texture2D"/>. El orden de las asignaciones importa: cambiar despues
    /// <c>textureType</c> recrea el sub-asset, asi que se fija el tipo primero.
    ///
    /// Los .meta los genera Unity, no se escriben a mano.
    /// </summary>
    public sealed class BrandingImport : AssetPostprocessor
    {
        private const string FOLDER = "Assets/_Project/Branding/";
        private const string BOOT_ICON_NAME = "ows-icon.jpeg";
        private const string ICON_PREFIX = "wilder-gambit-icon-";

        private void OnPreprocessTexture()
        {
            string path = assetPath.Replace('\\', '/');
            if (!path.StartsWith(FOLDER, StringComparison.OrdinalIgnoreCase)) return;

            TextureImporter importer = (TextureImporter)assetImporter;
            bool isBootIcon = path.EndsWith(BOOT_ICON_NAME, StringComparison.OrdinalIgnoreCase);

            importer.mipmapEnabled = false;
            importer.isReadable = false;
            importer.wrapMode = TextureWrapMode.Clamp;
            importer.filterMode = FilterMode.Bilinear;
            importer.npotScale = TextureImporterNPOTScale.None;
            importer.alphaSource = TextureImporterAlphaSource.None;

            if (isBootIcon)
            {
                importer.textureType = TextureImporterType.Sprite;
                importer.spriteImportMode = SpriteImportMode.Single;
                importer.spritePixelsPerUnit = 100f;
                importer.maxTextureSize = 1024;
                // BC7: el wordmark son serifas finas sobre fondo oscuro y con DXT se
                // dentan; el icono sale una vez por launch, no compensa ahorrar aqui.
                importer.textureCompression = TextureImporterCompression.CompressedHQ;
                importer.compressionQuality = 100;
            }
            else if (path.Contains(ICON_PREFIX))
            {
                importer.textureType = TextureImporterType.Default;
                importer.maxTextureSize = 256;
                importer.textureCompression = TextureImporterCompression.Uncompressed;
            }
        }
    }
}
#endif
