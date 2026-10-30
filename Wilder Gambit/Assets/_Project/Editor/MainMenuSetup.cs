#if UNITY_EDITOR
using UnityEditor;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.UI;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Editor helper que configura automáticamente el Main Menu (UI Toolkit) en la escena activa.
    /// Menú: Wilder Gambit > Setup Main Menu
    /// </summary>
    public static class MainMenuSetup
    {
        private const string PANEL_SETTINGS_PATH = "Assets/_Project/UI/MainMenuPanelSettings.asset";
        private const string UXML_PATH           = "Assets/_Project/UI/MainMenu.uxml";
        private const string USS_PATH            = "Assets/_Project/UI/MainMenu.uss";

        [MenuItem("Wilder Gambit/Setup Main Menu")]
        public static void SetupMainMenu()
        {
            // ── 1. Crear PanelSettings si no existe ──────────────────────────
            PanelSettings panelSettings = AssetDatabase.LoadAssetAtPath<PanelSettings>(PANEL_SETTINGS_PATH);
            if (panelSettings == null)
            {
                panelSettings = ScriptableObject.CreateInstance<PanelSettings>();
                panelSettings.scaleMode = PanelScaleMode.ScaleWithScreenSize;
                panelSettings.referenceResolution = new Vector2Int(1920, 1080);
                panelSettings.screenMatchMode = PanelScreenMatchMode.MatchWidthOrHeight;
                panelSettings.match = 0.5f;
                panelSettings.sortingOrder = 100;
                AssetDatabase.CreateAsset(panelSettings, PANEL_SETTINGS_PATH);
                AssetDatabase.SaveAssets();
                Debug.Log($"[WilderGambit] PanelSettings creado en: {PANEL_SETTINGS_PATH}");
            }

            // ── 2. Cargar UXML ────────────────────────────────────────────────
            VisualTreeAsset uxml = AssetDatabase.LoadAssetAtPath<VisualTreeAsset>(UXML_PATH);
            if (uxml == null)
            {
                Debug.LogError($"[WilderGambit] No se encontró el UXML en: {UXML_PATH}");
                return;
            }

            // ── 3. Buscar o crear el GameObject MainMenu en la escena ────────
            MainMenuController existingController = Object.FindAnyObjectByType<MainMenuController>();
            GameObject menuObj;

            if (existingController != null)
            {
                menuObj = existingController.gameObject;
                Debug.Log("[WilderGambit] Se encontró MainMenuController existente, actualizando referencias...");
            }
            else
            {
                menuObj = new GameObject("MainMenu");
                Undo.RegisterCreatedObjectUndo(menuObj, "Create MainMenu");
            }

            // ── 4. Asegurar UIDocument ───────────────────────────────────────
            UIDocument doc = menuObj.GetComponent<UIDocument>();
            if (doc == null)
                doc = Undo.AddComponent<UIDocument>(menuObj);

            doc.panelSettings    = panelSettings;
            doc.visualTreeAsset  = uxml;
            doc.sortingOrder     = 100;

            // ── 5. Asegurar MainMenuController ───────────────────────────────
            MainMenuController ctrl = menuObj.GetComponent<MainMenuController>();
            if (ctrl == null)
                ctrl = Undo.AddComponent<MainMenuController>(menuObj);

            ctrl.mainMenuViewAsset = uxml;
            ctrl.panelSettings     = panelSettings;

            // ── 6. Marcar la escena como modificada ──────────────────────────
            UnityEditor.SceneManagement.EditorSceneManager.MarkSceneDirty(
                UnityEngine.SceneManagement.SceneManager.GetActiveScene());

            EditorUtility.SetDirty(menuObj);
            Selection.activeGameObject = menuObj;

            Debug.Log("[WilderGambit] ✅ Main Menu configurado correctamente en la escena.");
            EditorUtility.DisplayDialog(
                "Wilder Gambit — Main Menu Configurado",
                "✅ El Main Menu ha sido configurado en la escena.\n\n" +
                "• PanelSettings: Assets/_Project/UI/MainMenuPanelSettings.asset\n" +
                "• UXML: Assets/_Project/UI/MainMenu.uxml\n" +
                "• USS: Assets/_Project/UI/MainMenu.uss\n\n" +
                "Guarda la escena (Ctrl+S) para persistir los cambios.",
                "OK");
        }

        [MenuItem("Wilder Gambit/Setup Main Menu", true)]
        public static bool ValidateSetupMainMenu()
        {
            return true;
        }
    }
}
#endif
