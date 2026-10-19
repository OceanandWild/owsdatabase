using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.SceneManagement;
using WildWeapon.Pvp;

namespace WildWeapon
{
    /// <summary>
    /// Hitstop + camera shake globales (sirven en Duelo y en Supervivencia).
    /// Se auto-crea al primer uso.
    /// </summary>
    public class GameFeel : MonoBehaviour
    {
        private static GameFeel _instance;

        private float _hitStopTimer;
        private float _shake;
        private Transform _cam;
        private Vector3 _camBase;

        private static GameFeel Get()
        {
            if (_instance == null)
            {
                var go = new GameObject("[GameFeel]");
                DontDestroyOnLoad(go);
                _instance = go.AddComponent<GameFeel>();
                SceneManager.sceneLoaded += (_, __) =>
                {
                    Time.timeScale = 1f;
                    if (_instance != null) { _instance._hitStopTimer = 0f; _instance._shake = 0f; _instance._cam = null; }
                };
            }
            return _instance;
        }

        public static void HitStop(float duration)
        {
            if (duration <= 0f) return;
            var g = Get();
            Time.timeScale = DuelRules.HitStopTimeScale;
            g._hitStopTimer = Mathf.Max(g._hitStopTimer, duration);
        }

        public static void Shake(float amount)
        {
            var g = Get();
            g._shake = Mathf.Max(g._shake, amount);
        }

        void LateUpdate()
        {
            if (_hitStopTimer > 0f)
            {
                _hitStopTimer -= Time.unscaledDeltaTime;
                if (_hitStopTimer <= 0f) Time.timeScale = 1f;
            }

            if (_cam == null)
            {
                var c = Camera.main;
                if (c == null) return;
                _cam = c.transform;
                _camBase = _cam.position;
            }

            if (_shake > 0.001f)
            {
                Vector2 r = UnityEngine.Random.insideUnitCircle * _shake;
                _cam.position = _camBase + new Vector3(r.x, r.y, 0f);
                _shake = Mathf.MoveTowards(_shake, 0f, Time.unscaledDeltaTime * 1.2f);
            }
            else
            {
                _cam.position = _camBase;
            }
        }
    }

    public enum GameMode { Multi, Bots, Pvp }

    /// <summary>Datos que pasan del menu principal a la arena (modo + mapa + colores de los cyborgs).</summary>
    public static class GameSession
    {
        public static GameMode Mode = GameMode.Multi;

/// <summary>Jugador de la lobby multijugador (nombre + color + control + equipo).</summary>
[Serializable]
public class PlayerSlot
{
    public string name = "Jugador";
    public int colorIndex = 0;
    public int controlIndex = 0;
    public int team = 0;
}
/// <summary>Lista de jugadores de la partida multijugador (hasta 15).</summary>
public static readonly List<PlayerSlot> MultiPlayers = new List<PlayerSlot>();
        public const string MenuScene = "MainMenu";
        public const string MapSelectScene = "MapSelect";
        public const string ArenaScene = "Arena";

        /// <summary>Indice del mapa elegido en el selector (sobre el MapCatalog).</summary>
        public static int SelectedMap = 0;

        /// <summary>
        /// Mapa del PVP online: se deriva de la semilla que manda el server, asi los
        /// dos clientes juegan la misma arena sin tocar el protocolo.
        /// </summary>
        public static int PvpMapIndex(int mapCount)
        {
            if (mapCount <= 0) return 0;
            return Mathf.Abs(PvpSeed) % mapCount;
        }

        // ---- PVP online ----
        /// <summary>Asiento asignado por el server (0..14) en la partida PVP.</summary>
        public static int PvpSeat = 0;
        /// <summary>Este cliente creo la sala (conduce los bots del plantel).</summary>
        public static bool PvpHost = false;
        public static string PvpOpponentName = "RIVAL";
        public static int PvpOpponentColor = 1;
        /// <summary>Semilla compartida para que ambos clientes generen la misma arena.</summary>
        public static int PvpSeed = 1;
        /// <summary>Lista de oponentes del PVP (N jugadores). Llena el lobby privado.</summary>
        public static readonly List<PvpOpp> PvpOpps = new List<PvpOpp>();

        public static readonly Color[] Palette =
        {
            new Color(0.20f, 0.85f, 1.00f),   // cian
            new Color(1.00f, 0.30f, 0.28f),   // rojo
            new Color(0.35f, 0.95f, 0.40f),   // verde
            new Color(1.00f, 0.85f, 0.20f),   // amarillo
            new Color(0.65f, 0.40f, 1.00f),   // morado
            new Color(1.00f, 0.55f, 0.15f),   // naranja
            new Color(1.00f, 0.45f, 0.80f),   // rosa
            new Color(0.92f, 0.94f, 0.97f),   // blanco
        };

        private static readonly int[] Defaults = { 0, 1 };

        public static int GetColorIndex(int player)
        {
            int i = PlayerPrefs.GetInt($"ww_color_p{player}", Defaults[Mathf.Clamp(player, 0, 1)]);
            return Mathf.Clamp(i, 0, Palette.Length - 1);
        }

        public static void SetColorIndex(int player, int index)
        {
            PlayerPrefs.SetInt($"ww_color_p{player}", Mathf.Clamp(index, 0, Palette.Length - 1));
            PlayerPrefs.Save();
        }

        public static Color GetColor(int player) => Palette[GetColorIndex(player)];

        /// <summary>Color del rival PVP (lo manda el server al emparejar).</summary>
        public static Color GetOpponentColor() => Palette[Mathf.Clamp(PvpOpponentColor, 0, Palette.Length - 1)];
    }
}
