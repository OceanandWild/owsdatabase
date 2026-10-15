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
    ///   - LAS CARTAS SON LA EXCEPCION: se dibujan a un cuarto de su tamano nativo
    ///     (560 px de arte en una carta de 118-126 px en la mesa y en la mano).
    ///     Sin mipmaps ese minificado se ve como alfileres y herrumbre: el filo dorado
    ///     y el texto chico del arte quedan hechos ruido. Van con mipmaps, Trilinear
    ///     y aniso 4, y con CompressedHQ para que la compresion no les coma el detalle.
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
        // Las cartas viven en Resources porque la UI las carga por id en runtime
        // (Resources.Load("WS/Card/WS_card_" + id)). Fuera de ahi Resources.Load
        // no las ve, asi que este segundo root es lo que les aplica los settings.
        const string CardsRoot = "Assets/Resources/WS/Card/";
        // Idem para el chrome de la partida (escudo, placas, marco del tapete,
        // nebulosa): WSGameUI los carga por codigo con Resources.Load.
        const string GameUIRoot = "Assets/Resources/WS/GameUI/";
        const int Ppu = 100;
        const int MaxSize = 4096; // >= 2752 nativo: no downscalea nada del set actual

        void OnPreprocessTexture()
        {
            string p = assetPath.Replace('\\', '/');
            bool card = p.StartsWith(CardsRoot);
            bool gameBg = p.StartsWith(GameUIRoot)
                          && Path.GetFileNameWithoutExtension(p).StartsWith("WS_bg_");
            if (!p.StartsWith(Root) && !card && !gameBg) return;

            string name = Path.GetFileNameWithoutExtension(p);
            bool tile = name.Contains("_caustics") || name.Contains("_particles") || name.EndsWith("_grain");
            bool glow = name.Contains("_glow") || name.Contains("glow_soft");

            // El fondo del tapete es una foto que se dibuja con Cover sobre un area
            // distinta cada vez: sin mipmaps se ve el aliaseo del enlargement.
            bool photo = gameBg;
            bool mips = card || photo;

            var ti = (TextureImporter)assetImporter;
            ti.textureType = TextureImporterType.Sprite;
            ti.spriteImportMode = SpriteImportMode.Single;
            ti.sRGBTexture = true;
            // La carta se ve SIEMPRE reducida, nunca ampliada: el filtrado tiene que
            // venir de los mipmaps, no del bilinear sobre la textura entera.
            ti.mipmapEnabled = mips;
            ti.filterMode = mips ? FilterMode.Trilinear : FilterMode.Bilinear;
            ti.anisoLevel = mips ? 4 : 0;
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

            if (card) ti.textureCompression = TextureImporterCompression.CompressedHQ;
            else if (glow) ti.textureCompression = TextureImporterCompression.Uncompressed;
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
            var settings = ai.defaultSampleSettings;
            settings.loadType = ambient ? AudioClipLoadType.Streaming
                                       : AudioClipLoadType.DecompressOnLoad;
            settings.preloadAudioData = true;
            ai.defaultSampleSettings = settings;
            ai.forceToMono = true;
            ai.loadInBackground = ambient;
        }
    }
}