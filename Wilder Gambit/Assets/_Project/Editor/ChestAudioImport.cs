#if UNITY_EDITOR
using System;
using UnityEditor;
using UnityEngine;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Deja listos los SFX del cofre al importarlos. No es cosmético:
    ///
    /// 1. **Sin compresión (PCM).** El set incluye un sub-bajo (<c>SFX_Chest_Boom</c>) y una
    ///    cascada de monedas con mucho detalle en agudos; la compresión con pérdida castiga
    ///    justo esos dos extremos, y el set entero pesa 0,74 MB.
    /// 2. **Descomprimidos al cargar y precargados.** Son piezas cortas que se disparan en un
    ///    instante exacto del guion: no pueden pagar la latencia de un decodificador al vuelo ni
    ///    el tirón del primer disparo.
    /// 3. **Mono forzado.** El set ya se entrega en mono; forzarlo evita que una sustitución
    ///    futura de los archivos meta un estéreo con un canal invertido en la mezcla.
    ///
    /// Los .meta los genera Unity, no se escriben a mano.
    /// </summary>
    public sealed class ChestAudioImport : AssetPostprocessor
    {
        private const string FOLDER = "Assets/Resources/SFX/";
        private const string PREFIX = "SFX_Chest_";

        private void OnPreprocessAudio()
        {
            AudioImporter importer = assetImporter as AudioImporter;
            if (importer == null) return;

            string path = assetPath.Replace('\\', '/');
            if (!path.StartsWith(FOLDER, StringComparison.OrdinalIgnoreCase)) return;

            string file = path.Substring(path.LastIndexOf('/') + 1);
            if (!file.StartsWith(PREFIX, StringComparison.OrdinalIgnoreCase)) return;

            AudioImporterSampleSettings settings = importer.defaultSampleSettings;
            settings.loadType = AudioClipLoadType.DecompressOnLoad;
            settings.compressionFormat = AudioCompressionFormat.PCM;
            settings.sampleRateSetting = AudioSampleRateSetting.PreserveSampleRate;
            settings.preloadAudioData = true;
            importer.defaultSampleSettings = settings;

            importer.forceToMono = true;
            importer.loadInBackground = false;
        }
    }
}
#endif
