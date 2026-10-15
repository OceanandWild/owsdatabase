using UnityEngine;
using UnityEngine.UIElements;
using WildSea.Core;

namespace WildSea.UI
{
    /// <summary>
    /// Boot Fase 1: una sola escena (SampleScene). Crea MainMenu + Hub y alterna con fade.
    /// INSTALACIÓN (30 seg): abre SampleScene, crea GameObject "WSApp", añade este script, pulsa Play.
    /// Auto-bootstrap: si la escena no tiene WSApp, se crea solo al cargar (no rompe nada).
    /// Fase 2: partir en escenas Boot/MainMenu/Hub sin tocar los *UI.cs (solo este switch).
    /// </summary>
    [DefaultExecutionOrder(-100)]
    public class WSApp : MonoBehaviour
    {
        WSMainMenuUI menu;
        WSUniverseHubUI hub;
        WSGameUI game;

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
        static void Bootstrap()
        {
            if (FindAnyObjectByType<WSApp>(FindObjectsInactive.Include) != null) return;
            // Solo auto-crea en escenas sin UI previa (no interfiere con otros proyectos OWS)
            if (FindAnyObjectByType<UIDocument>(FindObjectsInactive.Include) != null) return;
            var go = new GameObject("WSApp");
            go.AddComponent<WSApp>();
        }

        void Awake()
        {
            DontDestroyOnLoad(gameObject);
            Screen.fullScreen = WSSave.Fullscreen;

            var cam = Camera.main;
            if (cam != null)
                cam.backgroundColor = new Color(0.024f, 0.1255f, 0.2f); // #062033: mismo tono si el UI tarda un frame

            menu = Build<WSMainMenuUI>("WS_MainMenu", 0);
            hub = Build<WSUniverseHubUI>("WS_Hub", 10);
            game = Build<WSGameUI>("WS_Game", 20);
            menu.OnEnterPressed = ShowHub;
            hub.OnBackPressed = ShowMenu;
            hub.OnPlayRequested = (u, m) => ShowGame(u, m);
            game.OnBackPressed = ShowHub;
            game.Show(false);
            hub.Show(false);
            menu.Show(true);
        }

        T Build<T>(string name, int order) where T : Component
        {
            var go = new GameObject(name);
            go.transform.SetParent(transform, false);
            var doc = go.AddComponent<UIDocument>();
            doc.sortingOrder = order;
            doc.panelSettings = GetOrCreatePanel();
            var ui = go.AddComponent<T>();
            Debug.Log($"[WildSea] {name} creado (panel={(doc.panelSettings != null ? "OK" : "NULL")}, tree={(doc.visualTreeAsset != null ? doc.visualTreeAsset.name : "por Resources")})");
            return ui;
        }

        static PanelSettings sharedPanel;
        static PanelSettings GetOrCreatePanel()
        {
            if (sharedPanel != null) return sharedPanel;
            // 1) Reusa si el proyecto ya tiene uno (ej. copiado de otro OWS)
            var existing = Resources.Load<PanelSettings>("WS/WS_PanelSettings");
            if (existing != null) { sharedPanel = existing; return sharedPanel; }
            // 2) Crea uno en runtime: sin esto el UIDocument no pinta nada (pantalla azul)
            sharedPanel = ScriptableObject.CreateInstance<PanelSettings>();
            sharedPanel.name = "WS_RuntimePanel";
            return sharedPanel;
        }

        void ShowHub() { game.Show(false); hub.Show(true); }
        void ShowMenu() { hub.Show(false); menu.Show(true); }
        void ShowGame(string universeId, string modeId) { menu.Show(false); hub.Show(false); game.StartMatch(universeId, modeId); game.Show(true); }
    }
}
