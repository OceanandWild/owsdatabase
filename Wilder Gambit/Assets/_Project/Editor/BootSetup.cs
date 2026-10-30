#if UNITY_EDITOR
using System.Collections.Generic;
using System.Linq;
using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Crea la escena de arranque: el icono de OWS centrado durante 3 segundos y despues el juego.
    ///
    /// Unity no deja ajustar la duracion del splash del motor (la decide el motor: un minimo fijo, o
    /// hasta que la primera escena este lista), asi que se mete una escena vacia como escena[0] que
    /// muestra el icono y carga el juego despues.
    ///
    /// Reejecutarlo es idempotente: rehace la escena y la deja de nuevo en la posicion 0.
    /// Menú: Wilder Gambit &gt; Crear escena de splash (Boot).
    /// </summary>
    public static class BootSetup
    {
        private const string SCENE_PATH = "Assets/Scenes/Boot.unity";
        private const string PANEL_PATH = "Assets/_Project/UI/BootPanelSettings.asset";
        private const string ICON_PATH = "Assets/_Project/Branding/ows-icon.jpeg";

        /// <summary>Segundos que el icono queda en pantalla antes de cargar el juego.</summary>
        private const float HOLD_SECONDS = 3f;

        /// <summary>
        /// Fondo de la escena. El mismo azul verdoso del splash del motor (ver BrandingSetup) para
        /// que el paso de uno al otro no se note.
        /// </summary>
        private static readonly Color Background = new Color(0.039f, 0.129f, 0.188f, 1f);

        [MenuItem("Wilder Gambit/Crear escena de splash (Boot)")]
        public static void CreateBootScene()
        {
            if (!EditorSceneManager.SaveCurrentModifiedScenesIfUserWantsTo()) return;

            CreateBootScene(NewSceneMode.Single);
        }

        /// <summary>
        /// Aplica la identidad visual entera (iconos, splash y escena de arranque) sin tocar la
        /// escena que este abierta en el editor: la escena Boot se arma aparte y se cierra apenas
        /// esta guardada. Asi el menu se puede usar con el proyecto abierto y sin perder trabajo.
        /// </summary>
        [MenuItem("Wilder Gambit/Aplicar icono, splash y escena de arranque")]
        public static void ApplyAll()
        {
            BrandingSetup.Apply();
            CreateBootScene(NewSceneMode.Additive);
        }

        /// <summary>
        /// Genera la escena sin preguntar nada: para los builds en batchmode, donde no hay usuario
        /// que conteste el dialogo de guardar y la escena se rehace entera de todos modos.
        /// </summary>
        public static void CreateBootSceneForBuild()
        {
            CreateBootScene(NewSceneMode.Single);
        }

        /// <summary>Entrada para <c>-executeMethod</c> en modo batch.</summary>
        public static void CreateBootSceneFromCommandLine()
        {
            int exitCode = 0;
            try
            {
                BrandingSetup.Apply();
                CreateBootSceneForBuild();
            }
            catch (System.Exception e)
            {
                Debug.LogError("[Boot] " + e);
                exitCode = 1;
            }

            EditorApplication.Exit(exitCode);
        }

        private static void CreateBootScene(NewSceneMode mode)
        {
            Sprite icon = AssetDatabase.LoadAssetAtPath<Sprite>(ICON_PATH);
            if (icon == null)
            {
                Debug.LogError($"[Boot] No se encontro el sprite del icono en {ICON_PATH}.");
                return;
            }

            PanelSettings panel = GetOrCreatePanelSettings();
            string nextScene = FirstGameScene();

            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, mode);

            var cameraObject = new GameObject("Main Camera") { tag = "MainCamera" };
            Camera camera = cameraObject.AddComponent<Camera>();
            camera.clearFlags = CameraClearFlags.SolidColor;
            camera.backgroundColor = Background;
            cameraObject.transform.position = new Vector3(0f, 1f, -10f);

            var bootObject = new GameObject("Boot");
            UIDocument document = bootObject.AddComponent<UIDocument>();
            document.panelSettings = panel;

            // Por nombre, a propósito: si este script referenciara a BootSequence en compilación, el
            // ensamblado del Editor solo compilaría cuando el del runtime ya lo tenga, y Unity compila
            // en un orden que no controlamos. Así el Editor compila solo y acá se exige el tipo en
            // ejecución, con un error legible si el runtime todavía no terminó de compilar.
            System.Type bootType = System.Type.GetType("WilderGambit.UI.BootSequence, Assembly-CSharp");
            if (bootType == null)
            {
                Debug.LogError("[Boot] WilderGambit.UI.BootSequence todavía no está compilado. " +
                               "Esperá a que termine la compilación (o Assets > Refresh) y volvé a correr el menú.");
                if (mode == NewSceneMode.Additive) EditorSceneManager.CloseScene(scene, true);
                return;
            }

            Component boot = bootObject.AddComponent(bootType);

            var serialized = new SerializedObject(boot);
            serialized.FindProperty("iconSprite").objectReferenceValue = icon;
            serialized.FindProperty("panelSettings").objectReferenceValue = panel;
            serialized.FindProperty("holdSeconds").floatValue = HOLD_SECONDS;
            serialized.FindProperty("nextSceneName").stringValue = nextScene;
            serialized.ApplyModifiedPropertiesWithoutUndo();

            EditorSceneManager.MarkSceneDirty(scene);
            EditorSceneManager.SaveScene(scene, SCENE_PATH);

            // En aditiva la escena queda abierta al lado de la del editor: se cierra para no
            // dejarlo con dos escenas en memoria.
            if (mode == NewSceneMode.Additive) EditorSceneManager.CloseScene(scene, true);

            RegisterFirst(SCENE_PATH);

            AssetDatabase.SaveAssets();
            AssetDatabase.Refresh();
            Debug.Log($"[Boot] Escena creada en {SCENE_PATH} como escena[0]; carga '{nextScene}'.");
        }

        private static PanelSettings GetOrCreatePanelSettings()
        {
            PanelSettings panel = AssetDatabase.LoadAssetAtPath<PanelSettings>(PANEL_PATH);
            if (panel != null) return panel;

            panel = ScriptableObject.CreateInstance<PanelSettings>();
            panel.scaleMode = PanelScaleMode.ScaleWithScreenSize;
            panel.referenceResolution = new Vector2Int(1920, 1080);
            panel.screenMatchMode = PanelScreenMatchMode.MatchWidthOrHeight;
            panel.match = 0.5f;
            panel.sortingOrder = -1000;   // por debajo de cualquier UI del juego
            AssetDatabase.CreateAsset(panel, PANEL_PATH);
            AssetDatabase.SaveAssets();
            return panel;
        }

        /// <summary>Primera escena de juego habilitada, ignorando la propia escena Boot.</summary>
        private static string FirstGameScene()
        {
            return EditorBuildSettings.scenes
                .Where(s => s.enabled && s.path != SCENE_PATH)
                .Select(s => System.IO.Path.GetFileNameWithoutExtension(s.path))
                .FirstOrDefault() ?? "SampleScene";
        }

        private static void RegisterFirst(string path)
        {
            List<EditorBuildSettingsScene> scenes = EditorBuildSettings.scenes
                .Where(s => s.path != path)
                .ToList();

            scenes.Insert(0, new EditorBuildSettingsScene(path, true));
            EditorBuildSettings.scenes = scenes.ToArray();
        }
    }
}
#endif
