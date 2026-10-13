using System.IO;
using UnityEditor;
using UnityEngine;

namespace WildSea.EditorTools
{
    /// <summary>
    /// Aplica los settings de importacion de WILDSEA-ART-SPRITES.md a todo lo que
    /// cae bajo Assets/_WildSea/Art/UI/. Asi los assets entran correctos al arrastrarlos,
    /// sin editar .meta a mano uno por uno.
    ///
    /// Reglas:
    ///   - UI nunca lleva mipmaps (borde scintilante al escalar).
    ///   - FullRect SIEMPRE: el Tight calcula mal el rect en sprites con alfa suave
    ///     (caso real: WS_logo_title quedo en rect=(0,260,1969,361) sin REALMS, y
    ///     WS_panel_tall en rect=(474,876,11,12)). El background-image de USS usa el
    ///     rect del sprite, asi que un rect mal calculado recorta la pieza.
    ///   - Solo los tiles usan Repeat; el resto Clamp, para que no salga costura.
    ///   - Los glows van Uncompressed: con DXT se ve banding en el degradado.
    /// </summary>
    public sealed class WSArtPostprocessor : AssetPostprocessor
    {
        const string Root = "Assets/_WildSea/Art/UI/";
        const int Ppu = 100;
        const int MaxSize = 4096; // >= 2752 nativo: no downscalea nada del set actual

        void OnPreprocessTexture()
        {
            string p = assetPath.Replace('\\', '/');
            if (!p.StartsWith(Root)) return;

            string name = Path.GetFileNameWithoutExtension(p);
            bool tile = name.Contains("_caustics") || name.Contains("_particles") || name.EndsWith("_grain");
            bool glow = name.Contains("_glow") || name.Contains("glow_soft");

            var ti = (TextureImporter)assetImporter;
            ti.textureType = TextureImporterType.Sprite;
            ti.spriteImportMode = SpriteImportMode.Single;
            ti.spritesheet = new SpriteMetaData[0];
            ti.sRGBTexture = true;
            ti.mipmapEnabled = false;
            ti.filterMode = FilterMode.Bilinear;
            ti.anisoLevel = 0;
            ti.alphaIsTransparency = true;
            ti.npotScale = TextureImporterNPOTScale.None;
            ti.maxTextureSize = MaxSize;
            ti.spritePixelsPerUnit = Ppu;
            ti.wrapMode = tile ? TextureWrapMode.Repeat : TextureWrapMode.Clamp;

            var s = new TextureImporterSettings();
            ti.ReadTextureSettings(s);
            s.spriteMeshType = SpriteMeshType.FullRect;
            s.spriteAlignment = (int)SpriteAlignment.Center;
            s.spritePivot = new Vector2(0.5f, 0.5f);
            s.spriteExtrude = 0;
            s.spriteGenerateFallbackPhysicsShape = false;
            ti.SetTextureSettings(s);

            if (glow) ti.textureCompression = TextureImporterCompression.Uncompressed;
            else ti.textureCompression = TextureImporterCompression.Compressed;
            ti.compressionQuality = 60;
        }

        /// <summary>
        /// Ajustes de importacion del audio de UI (Resources/WS/Audio/UI/).
        /// Los SFX son cortos: descomprimir en memoria para que no haya delay al
        /// primer click. El ambiente son 11 s de loop: va en streaming para no
        /// meter ~2 MB decomprimidos en memoria solo por el fondo del menu.
        /// El postprocessor se llama WSArtPostprocessor por historia, pero tambien
        /// cubre el audio; no tocar el nombre porque otros scripts lo referencian.
        /// </summary>
        void OnPreprocessAudio()
        {
            string p = assetPath.Replace('\\', '/');
            if (!p.StartsWith("Assets/Resources/WS/Audio/")) return;

            bool ambient = Path.GetFileNameWithoutExtension(p).StartsWith("WS_amb_");
            var ai = (AudioImporter)assetImporter;
            ai.loadType = ambient ? AudioClipLoadType.Streaming
                                  : AudioClipLoadType.DecompressOnLoad;
            ai.forceToMono = true;
            ai.preloadAudioData = true;
            ai.loadInBackground = ambient;
        }
    }
}