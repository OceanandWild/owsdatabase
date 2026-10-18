using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;
using WildWeapon.Pvp;

namespace WildWeapon
{
    /// <summary>
    /// Arranque de la Arena: genera el mapa y activa el modo elegido en el menu
    /// (Duelo 1v1, Supervivencia vs Bots o PVP Online). Esc vuelve al menu.
    /// </summary>
    [DefaultExecutionOrder(-100)]
    public class GameBootstrap : MonoBehaviour
    {
        public MapGenerator map;
        public MapCatalog catalog;
        public GameObject duelRoot;
        public GameObject botsRoot;
        public GameObject pvpRoot;
        public PlayerController p1;
        public PlayerController p2;

        void Awake()
        {
            var mode = GameSession.Mode;
            bool duel = mode == GameMode.Duel;
            bool pvp = mode == GameMode.Pvp;

            if (!pvp)
            {
                if (p1 != null && p1.visual != null) p1.visual.SetPaintColor(GameSession.GetColor(0));
                if (p2 != null && p2.visual != null) p2.visual.SetPaintColor(GameSession.GetColor(1));
            }

            if (map != null && map.map != null)
            {
                // El mapa de la partida sale del selector (o de la semilla, en PVP online).
                if (catalog != null && catalog.Count > 0)
                {
                    int index = pvp ? GameSession.PvpMapIndex(catalog.Count) : Mathf.Clamp(GameSession.SelectedMap, 0, catalog.Count - 1);
                    var def = catalog.Get(index);
                    if (def != null) map.map = def;
                }

                // PVP: misma semilla para ambos clientes (la manda el server al emparejar).
                int seed = pvp
                    ? Mathf.Max(1, GameSession.PvpSeed)
                    : (map.map.randomSeedEachMatch ? Random.Range(1, 999999) : map.map.seed);
                map.Generate(seed, (duel || pvp) && map.map.mirroredForDuel);
            }

            if (p2 != null) p2.gameObject.SetActive(duel || pvp);
            if (duelRoot != null) duelRoot.SetActive(duel);   // en PVP lo activa PvpMatchManager
            if (botsRoot != null) botsRoot.SetActive(!duel && !pvp);
            if (pvpRoot != null) pvpRoot.SetActive(pvp);
        }

        void Update()
        {
            var kb = Keyboard.current;
            var pad = Gamepad.current;
            if ((kb != null && kb.escapeKey.wasPressedThisFrame) || (pad != null && pad.selectButton.wasPressedThisFrame))
            {
                if (GameSession.Mode == GameMode.Pvp && PvpClient.Instance != null)
                    PvpClient.Instance.LeaveAndDisconnect();
                SceneManager.LoadScene(GameSession.MenuScene);
            }
        }
    }
}
