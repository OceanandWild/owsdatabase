using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;

namespace WildWeapon
{
    /// <summary>
    /// Modo Supervivencia: oleadas crecientes de bots contra J1.
    /// Composicion: Sierras desde la 1, Lanceros desde la 2, Brutos desde la 3.
    /// </summary>
    public class WaveManager : MonoBehaviour
    {
        public enum Phase { Intro, Spawning, Fighting, Between, GameOver }

        public PlayerController player;
        public Transform playerSpawn;
        public MapGenerator map;
        [Tooltip("0 = Sierra, 1 = Lancero, 2 = Bruto")]
        public EnemyBot[] botPrefabs;
        public GameObject spawnVfx;
        public float timeBetweenWaves = 3f;
        public float healBetweenWaves = 30f;

        public Phase CurrentPhase { get; private set; }
        public int Wave { get; private set; }
        public int Kills { get; private set; }
        public int Alive => _alive.Count + _queue.Count;
        public string StatusText { get; private set; } = "";

        private readonly List<EnemyBot> _alive = new List<EnemyBot>();
        private readonly Queue<EnemyBot> _queue = new Queue<EnemyBot>();
        private float _timer;
        private float _spawnTimer;
        private float _hpScale = 1f;

        private GUIStyle _big, _mid, _small;

        void Start()
        {
            if (player != null && player.Health != null) player.Health.Died += _ => OnPlayerDied();
            StartRun();
        }

        public void StartRun()
        {
            foreach (var b in _alive) if (b != null) Destroy(b.gameObject);
            _alive.Clear();
            _queue.Clear();
            Wave = 0;
            Kills = 0;

            if (player != null)
            {
                Vector2 pos = playerSpawn != null ? (Vector2)playerSpawn.position : Vector2.zero;
                player.ResetForRound(pos, Vector2.right);
                player.CanAct = true;
            }

            CurrentPhase = Phase.Intro;
            StatusText = "SUPERVIVENCIA";
            _timer = 1.6f;
        }

        void Update()
        {
            switch (CurrentPhase)
            {
                case Phase.Intro:
                case Phase.Between:
                    _timer -= Time.deltaTime;
                    if (_timer <= 0f) BeginWave();
                    break;

                case Phase.Spawning:
                    _spawnTimer -= Time.deltaTime;
                    if (_spawnTimer <= 0f && _queue.Count > 0)
                    {
                        SpawnBot(_queue.Dequeue());
                        _spawnTimer = 0.45f;
                    }
                    if (_queue.Count == 0) CurrentPhase = Phase.Fighting;
                    break;

                case Phase.Fighting:
                    _alive.RemoveAll(b => b == null || b.Health == null || b.Health.IsDead);
                    if (_alive.Count == 0)
                    {
                        CurrentPhase = Phase.Between;
                        _timer = timeBetweenWaves;
                        StatusText = $"OLEADA {Wave} SUPERADA";
                        if (player != null && player.Health != null) player.Health.Heal(healBetweenWaves);
                    }
                    break;

                case Phase.GameOver:
                    var kb = Keyboard.current;
                    var pad = Gamepad.current;
                    if ((kb != null && kb.rKey.wasPressedThisFrame) || (pad != null && pad.startButton.wasPressedThisFrame))
                        StartRun();
                    break;
            }
        }

        private void BeginWave()
        {
            Wave++;
            _hpScale = 1f + 0.08f * (Wave - 1);
            StatusText = $"OLEADA {Wave}";
            Invoke(nameof(ClearStatus), 1.3f);

            int count = 2 + Wave;
            for (int i = 0; i < count; i++)
            {
                int type = 0;
                float r = Random.value;
                if (Wave >= 3 && r < 0.18f + 0.03f * Wave) type = 2;
                else if (Wave >= 2 && r < 0.6f) type = 1;
                if (botPrefabs != null && type < botPrefabs.Length && botPrefabs[type] != null)
                    _queue.Enqueue(botPrefabs[type]);
            }
            _spawnTimer = 0.2f;
            CurrentPhase = Phase.Spawning;
        }

        private void ClearStatus()
        {
            if (CurrentPhase != Phase.GameOver && CurrentPhase != Phase.Between) StatusText = "";
        }

        private void SpawnBot(EnemyBot prefab)
        {
            Vector2 pos = PickSpawnPoint();
            var bot = Instantiate(prefab, pos, Quaternion.identity);
            bot.HpScale = _hpScale;
            _alive.Add(bot);
            var h = bot.GetComponent<PlayerHealth>();
            if (h != null) h.Died += _ => Kills++;
            if (spawnVfx != null) Instantiate(spawnVfx, pos, Quaternion.identity);
        }

        private Vector2 PickSpawnPoint()
        {
            Vector2 playerPos = player != null ? (Vector2)player.transform.position : Vector2.zero;
            var points = map != null ? map.BotSpawnPoints : null;
            if (points == null || points.Count == 0)
                return playerPos + Random.insideUnitCircle.normalized * 6f;

            for (int i = 0; i < 12; i++)
            {
                var p = points[Random.Range(0, points.Count)];
                if ((p - playerPos).sqrMagnitude > 16f) return p;
            }
            return points[Random.Range(0, points.Count)];
        }

        private void OnPlayerDied()
        {
            CurrentPhase = Phase.GameOver;
            StatusText = $"CAISTE EN LA OLEADA {Wave}";
            _queue.Clear();
        }

        // ---------------- HUD ----------------
        private void OnGUI()
        {
            if (_big == null)
            {
                _big = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleCenter, fontSize = 40, fontStyle = FontStyle.Bold };
                _mid = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleCenter, fontSize = 18, fontStyle = FontStyle.Bold };
                _small = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleLeft, fontSize = 13 };
            }

            float w = Screen.width;
            var top = new Rect(w * 0.5f - 230f, 10f, 460f, 34f);
            Box(top, new Color(0f, 0f, 0f, 0.55f));
            _mid.normal.textColor = Color.white;
            GUI.Label(top, $"OLEADA {Mathf.Max(1, Wave)}     BAJAS {Kills}     QUEDAN {Alive}", _mid);

            var hpPanel = new Rect(16f, 16f, 360f, 52f);
            Box(hpPanel, new Color(0f, 0f, 0f, 0.5f));
            _small.normal.textColor = new Color(0.55f, 0.75f, 1f);
            string weaponName = "-";
            if (player != null && player.Loadout != null && player.Loadout.weapons != null && player.Loadout.weapons.Length > 0)
                weaponName = player.Loadout.weapons[player.Loadout.ActiveIndex].DisplayName;
            GUI.Label(new Rect(hpPanel.x + 10f, hpPanel.y + 4f, 340f, 20f), $"J1   Arma: {weaponName}", _small);
            var back = new Rect(hpPanel.x + 10f, hpPanel.y + 28f, hpPanel.width - 20f, 14f);
            Box(back, new Color(1f, 1f, 1f, 0.12f));
            if (player != null && player.Health != null)
                Box(new Rect(back.x, back.y, back.width * player.Health.Hp01, back.height),
                    Color.Lerp(new Color(0.9f, 0.25f, 0.2f), new Color(0.35f, 0.85f, 0.4f), player.Health.Hp01));

            if (!string.IsNullOrEmpty(StatusText))
            {
                var mid = new Rect(w * 0.5f - 340f, Screen.height * 0.36f, 680f, 110f);
                Box(mid, new Color(0f, 0f, 0f, 0.55f));
                _big.normal.textColor = CurrentPhase == Phase.GameOver ? new Color(1f, 0.45f, 0.4f) : Color.white;
                GUI.Label(mid, StatusText, _big);
                if (CurrentPhase == Phase.GameOver)
                {
                    _mid.normal.textColor = new Color(1f, 1f, 1f, 0.8f);
                    GUI.Label(new Rect(mid.x, mid.y + 74f, mid.width, 30f), "R / Start = reintentar     Esc = menu", _mid);
                }
            }

            _small.normal.textColor = new Color(1f, 1f, 1f, 0.45f);
            GUI.Label(new Rect(12f, Screen.height - 28f, w - 24f, 22f),
                "WASD mover - mouse apuntar - click atacar - Shift/Space dash - X/rueda cambia arma - Esc menu", _small);
        }

        private static void Box(Rect r, Color c)
        {
            var prev = GUI.color;
            GUI.color = c;
            GUI.DrawTexture(r, Texture2D.whiteTexture);
            GUI.color = prev;
        }
    }
}
