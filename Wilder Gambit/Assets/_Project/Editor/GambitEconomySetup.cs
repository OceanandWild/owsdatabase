#if UNITY_EDITOR
using UnityEditor;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Crea/abre el asset de configuración de la economía de Gambits para poder tunear
    /// todos los números (pago por partida, bonus, topes diarios) sin recompilar.
    /// Menú: Wilder Gambit > Crear config de economía de Gambits
    /// </summary>
    public static class GambitEconomySetup
    {
        private const string FOLDER    = "Assets/Resources";
        private const string ASSET_PATH = FOLDER + "/GambitEconomyConfig.asset";

        [MenuItem("Wilder Gambit/Crear config de economía de Gambits")]
        public static void CreateOrSelectConfig()
        {
            var existing = AssetDatabase.LoadAssetAtPath<GambitEconomyConfig>(ASSET_PATH);
            if (existing != null)
            {
                GambitEconomyConfig.Reload();
                Selection.activeObject = existing;
                EditorGUIUtility.PingObject(existing);
                Debug.Log($"[WilderGambit] Config de economía ya existente: {ASSET_PATH}");
                return;
            }

            if (!AssetDatabase.IsValidFolder(FOLDER))
                AssetDatabase.CreateFolder("Assets", "Resources");

            var config = ScriptableObject.CreateInstance<GambitEconomyConfig>();
            AssetDatabase.CreateAsset(config, ASSET_PATH);
            AssetDatabase.SaveAssets();
            AssetDatabase.Refresh();

            GambitEconomyConfig.Reload();
            Selection.activeObject = config;
            EditorGUIUtility.PingObject(config);

            Debug.Log(
                "[WilderGambit] Config de economía creada en " + ASSET_PATH +
                ". Desde aquí se ajustan los pagos por partida, los bonus y los topes diarios " +
                "sin tocar código (el juego la carga sola desde Resources).");
        }

        [MenuItem("Wilder Gambit/Crear config de economía de Gambits", true)]
        private static bool ValidateCreate() => !Application.isPlaying;
    }
}
#endif
