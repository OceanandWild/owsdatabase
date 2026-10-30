#if UNITY_EDITOR
using UnityEditor;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.UI;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Editor helper que configura automáticamente el Panel de Pausa (UI Toolkit) en la escena activa.
    /// Menú: Wilder Gambit > Setup Pause Menu
    /// </summary>
    public static class PauseMenuSetup
    {
        private const string PANEL_SETTINGS_PATH = "Assets/_Project/UI/MainMenuPanelSettings.asset";
        private const string UXML_PATH           = "Assets/_Project/UI/PauseMenu.uxml";

        [MenuItem("Wilder Gambit/Setup Pause Menu")]
        public static void SetupPauseMenu()
        {
            // ── 1. Reutilizar el PanelSettings del Main Menu ──────────────────
            PanelSettings panelSettings = AssetDatabase.LoadAssetAtPath<PanelSettings>(PANEL_SETTINGS_PATH);
            if (panelSettings == null)
            {
                Debug.LogError($"[WilderGambit] No se encontró PanelSettings en: {PANEL_SETTINGS_PATH}. Ejecuta primero Wilder Gambit > Setup Main Menu.");
                return;
            }

            // ── 2. Cargar UXML ────────────────────────────────────────────────
            VisualTreeAsset uxml = AssetDatabase.LoadAssetAtPath<VisualTreeAsset>(UXML_PATH);
            if (uxml == null)
            {
                Debug.LogError($"[WilderGambit] No se encontró el UXML en: {UXML_PATH}");
                return;
            }

            // ── 3. Buscar o crear el GameObject PauseMenu en la escena ────────
            PauseMenuController existingController = Object.FindAnyObjectByType<PauseMenuController>();
            GameObject pauseObj;

            if (existingController != null)
            {
                pauseObj = existingController.gameObject;
                Debug.Log("[WilderGambit] Se encontró PauseMenuController existente, actualizando referencias...");
            }
            else
            {
                pauseObj = new GameObject("PauseMenu");
                Undo.RegisterCreatedObjectUndo(pauseObj, "Create PauseMenu");
            }

            // ── 4. Asegurar UIDocument (por encima del Main Menu) ────────────
            UIDocument doc = pauseObj.GetComponent<UIDocument>();
            if (doc == null)
                doc = Undo.AddComponent<UIDocument>(pauseObj);

            doc.panelSettings   = panelSettings;
            doc.visualTreeAsset = uxml;
            doc.sortingOrder    = 200; // por encima del Main Menu (100)

            // ── 5. Asegurar PauseMenuController ──────────────────────────────
            PauseMenuController ctrl = pauseObj.GetComponent<PauseMenuController>();
            if (ctrl == null)
                ctrl = Undo.AddComponent<PauseMenuController>(pauseObj);

            ctrl.pauseMenuViewAsset = uxml;
            ctrl.panelSettings      = panelSettings;

            // ── 6. Marcar la escena como modificada ──────────────────────────
            UnityEditor.SceneManagement.EditorSceneManager.MarkSceneDirty(
                UnityEngine.SceneManagement.SceneManager.GetActiveScene());

            EditorUtility.SetDirty(pauseObj);
            Selection.activeGameObject = pauseObj;

            Debug.Log("[WilderGambit] ✅ Panel de Pausa configurado correctamente en la escena.");
            EditorUtility.DisplayDialog(
                "Wilder Gambit — Pause Menu Configurado",
                "✅ El Panel de Pausa ha sido configurado en la escena.\n\n" +
                "• PanelSettings: Assets/_Project/UI/MainMenuPanelSettings.asset (reutilizado)\n" +
                "• UXML: Assets/_Project/UI/PauseMenu.uxml\n" +
                "• USS: Assets/_Project/UI/PauseMenu.uss\n\n" +
                "Durante la partida pulsa ESC para abrir/cerrar el panel.\n" +
                "Guarda la escena (Ctrl+S) para persistir los cambios.",
                "OK");
        }

        [MenuItem("Wilder Gambit/Setup Pause Menu", true)]
        public static bool ValidateSetupPauseMenu()
        {
            return true;
        }
    }
}
#endif
