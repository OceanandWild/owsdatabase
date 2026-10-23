using System.Collections.Generic;
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
        /// <summary>Instancia activa (la usa la camara para saber a quien seguir).</summary>
        public static GameBootstrap Instance { get; private set; }

        public MapGenerator map;
        public MapCatalog catalog;
        public GameObject duelRoot;
        public GameObject botsRoot;
        public GameObject pvpRoot;
        public PlayerController p1;
        public PlayerController p2;
        public GameObject playerPrefab;

        [HideInInspector] public readonly List<PlayerController> MultiPlayers = new List<PlayerController>();

        void Awake()
        {
            Instance = this;
            var mode = GameSession.Mode;
            bool multi = mode == GameMode.Multi;
            bool duel = multi;
            bool pvp = mode == GameMode.Pvp;
            // Jugar la Arena directo (sin pasar por el menu/lobby) deja Multi sin
            // asientos: en vez de generar un solo pawn sin rival, se juega el duelo
            // local con los dos combatientes de la escena.
            bool localDuel = multi && GameSession.MultiPlayers.Count == 0;

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

            if (p2 != null) p2.gameObject.SetActive(((duel || pvp) && !multi) || localDuel);
            if (p1 != null && multi && !localDuel && p1.gameObject != null) p1.gameObject.SetActive(false);
            if (duelRoot != null) duelRoot.SetActive(duel);   // en PVP lo activa PvpMatchManager
            if (botsRoot != null) botsRoot.SetActive(!duel && !pvp);
            if (pvpRoot != null) pvpRoot.SetActive(pvp);
        }

        void Start()
        {
            if (GameSession.Mode != GameMode.Multi) return;
            // Sin asientos (Arena jugada directo) el duelo local ya tiene a P1 y P2
            // de la escena: no hay que clonar jugadores ni pisar DuelManager.players.
            if (GameSession.MultiPlayers.Count == 0) return;
            if (playerPrefab == null) { Debug.LogWarning("[WW] playerPrefab no asignado"); return; }

            int n = Mathf.Max(1, GameSession.MultiPlayers.Count);
            var spawns = new List<Vector2>();
            if (map != null && map.BotSpawnPoints != null && map.BotSpawnPoints.Count > 0)
                spawns.AddRange(map.BotSpawnPoints);
            // fallback ring
            if (spawns.Count < n)
            {
                Vector2 half = map != null ? map.map.arenaSize * 0.5f : new Vector2(16f, 9f);
                float r = Mathf.Min(half.x, half.y) * 0.6f;
                float floorY = map != null ? map.FloorSpawnY : PlatformSurface.FloorY + 0.55f;
                for (int i = 0; i < n; i++)
                {
                    float a = i / (float)n * Mathf.PI * 2f;
                    // La vista lateral no tiene profundidad: el anillo de respaldo
                    // reparte los asientos en horizontal, todos sobre el piso.
                    spawns.Add(new Vector2(Mathf.Cos(a) * r, floorY));
                }
            }

            MultiPlayers.Clear();
            var dm = DuelManager.Instance;
            if (dm != null) dm.players.Clear();

            for (int i = 0; i < n; i++)
            {
                var slot = (i < GameSession.MultiPlayers.Count) ? GameSession.MultiPlayers[i] : null;
                var go = Instantiate(playerPrefab);
                go.name = "Player_Multi_" + i;
                var pc = go.GetComponent<PlayerController>();
                var health = go.GetComponent<PlayerHealth>();
                if (health != null)
                {
                    health.team = (slot != null) ? slot.team : i % 2;
                    if (pc != null && pc.visual != null && slot != null)
                        pc.visual.SetPaintColor(GameSession.Palette[Mathf.Clamp(slot.colorIndex, 0, GameSession.Palette.Length - 1)]);
                }
                Vector2 pos = (i < spawns.Count) ? spawns[i] : Vector2.zero;
                go.transform.position = pos;
                if (pc != null)
                {
                    // Controles por jugador: el J1 con teclado y mouse (WASD) y los
                    // demas con flechas (o el mando, si lo estan usando). Asi el
                    // teclado del J1 nunca compite con el J2 por el mismo stick.
                    // Si jugan solos, el J1 puede usar tambien el mando.
                    pc.scheme = i == 0 ? InputScheme.KeyboardMouse : InputScheme.KeyboardTwin;
                    pc.acceptGamepad = i > 0 || n == 1;
                    pc.ResetForRound(pos, -pos.normalized);
                    pc.CanAct = true;
                    MultiPlayers.Add(pc);
                }
                if (dm != null && pc != null) dm.players.Add(pc);
            }

            // spawns for DuelManager
            if (dm != null)
            {
                dm.spawns = new Transform[MultiPlayers.Count];
                for (int i = 0; i < MultiPlayers.Count; i++)
                {
                    var t = new GameObject("Spawn_" + i).transform;
                    t.position = MultiPlayers[i].transform.position;
                    dm.spawns[i] = t;
                }
                dm.pvpDriven = false;
                dm.StartMatch();
            }
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

        void OnDestroy()
        {
            if (Instance == this) Instance = null;
        }
    }
}
