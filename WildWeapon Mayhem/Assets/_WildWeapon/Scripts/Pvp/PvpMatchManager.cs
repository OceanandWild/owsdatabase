using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Orquesta el combate PVP online dentro de la Arena:
    /// elige el pawn local segun el asiento que dio el server, replica a cada oponente
    /// por red (hasta 15: sala del lobby con codigo), conduce los BOTS en la maquina del
    /// anfitrion, sincroniza estado a ~15 Hz y traduce los mensajes del servidor
    /// (round_start/round_end/opp_left/bots_left) al DuelManager (modo pvpDriven).
    /// </summary>
    public class PvpMatchManager : MonoBehaviour
    {
        public static PvpMatchManager Instance { get; private set; }

        [Header("Escena")]
        public DuelManager duel;
        public GameObject duelRoot;
        public PvpCountdown countdown;
        public PlayerController p1;
        public PlayerController p2;
        public GameObject playerPrefab;
        public Transform[] spawns;

        [Serializable]
        public class RemoteEntry
        {
            public int seat;
            public PlayerController pc;
            public PlayerHealth health;
            /// <summary>Replica por red (los humanos y los bots que conduce otro).</summary>
            public PvpRemoteAvatar avatar;
            /// <summary>Bot conducido por ESTA maquina (solo el anfitrion).</summary>
            public bool bot;
            public PvpBotBrain brain;
            [NonSerialized] public Action<MeleeWeapon, Vector2> attackRelay;
            [NonSerialized] public Action<PlayerHealth> diedRelay;
        }
        public readonly List<RemoteEntry> remotes = new List<RemoteEntry>();

        public int LocalIndex { get; private set; }
        public bool Running { get; private set; }
        /// <summary>Anfitrion de la sala: conduce los bots y es la autoridad de su dano.</summary>
        public bool IsHost { get; private set; }
        public bool CountdownVisible => countdown != null && countdown.IsPlaying;

        private PvpClient _client;
        private PlayerController _local;
        private PlayerHealth _localHealth;
        private MapGenerator _map;

        private const float StateInterval = 1f / 15f;
        private float _stateAcc;
        private bool _deathSent;
        private bool _connectionLost;
        private float _leaveTimer = -1f;
        private float _waitFightTimer = -1f;

        void Awake() { Instance = this; }

        void OnDestroy()
        {
            if (Instance == this) Instance = null;
            if (_client != null) _client.Message -= OnMessage;
            if (_localHealth != null) _localHealth.Died -= OnLocalDied;
            UnhookLocalEvents();
            foreach (var r in remotes) UnhookRemoteEvents(r);
            if (duel != null) duel.PvpRematchRequested -= OnRematchPressed;
        }

        void Start()
        {
            if (GameSession.Mode != GameMode.Pvp) { gameObject.SetActive(false); return; }

            _map = FindAnyObjectByType<MapGenerator>();
            IsHost = GameSession.PvpHost;
            LocalIndex = Mathf.Max(0, GameSession.PvpSeat);
            _local = LocalIndex == 0 ? p1 : p2;
            if (_local == null || duel == null)
            {
                ReturnToMenu("La arena no tiene los jugadores configurados.");
                return;
            }

            _localHealth = _local.Health;

            // Colores: el local con su color elegido.
            if (_local.visual != null) _local.visual.SetPaintColor(GameSession.GetColor(0));
            if (_localHealth != null) _localHealth.team = 0;
            _local.scheme = Gamepad.current != null ? InputScheme.Auto : InputScheme.KeyboardMouse;

            // Remotos: uno por cada asiento del lobby (humanos y bots). Los bots que
            // agrego el anfitrion corren aca con IA; en el resto de las maquinas son
            // replicas comunes y se interpolan desde el estado que manda el anfitrion.
            var opps = (GameSession.PvpOpps != null && GameSession.PvpOpps.Count > 0)
                ? GameSession.PvpOpps
                : new List<PvpOpp> { new PvpOpp { name = GameSession.PvpOpponentName, color = GameSession.PvpOpponentColor, seat = LocalIndex == 0 ? 1 : 0 } };

            foreach (var opp in opps)
            {
                int seat = opp != null && opp.seat > 0 ? opp.seat : (remotes.Count + 1);
                while (seat == LocalIndex || remotes.Exists(r => r.seat == seat)) seat++;
                if (seat == LocalIndex) continue;

                var pc = PawnFor(seat);
                if (pc == null) continue;
                AddRemote(seat, pc, opp != null ? opp.color : seat, opp != null && opp.bot && IsHost);
            }

            duel.pvpDriven = true;
            if (duelRoot != null) duelRoot.SetActive(true);

            duel.SetStatus("CONECTANDO...");
            duel.PvpRematchRequested += OnRematchPressed;
            if (_localHealth != null) _localHealth.Died += OnLocalDied;
            HookLocalEvents();

            _client = PvpClient.Ensure();
            if (!_client.IsConnected)
            {
                ReturnToMenu("Se perdio la conexion con el servidor PVP.");
                return;
            }

            _client.Message += OnMessage;
            _client.Send(new PvpMsg { t = PvpMsgType.Ready });
            Running = true;
            _waitFightTimer = 20f;
            Debug.Log($"[WW-PVP] Arena lista - local J{LocalIndex + 1} ({(IsHost ? "anfitrion" : "invitado")}) con {remotes.Count} remotos.");
        }

        // =================================================================
        // Alta de remotos
        // =================================================================

        /// <summary>Elige el pawn del asiento: los dos de la escena y, del 2 en adelante, clones.</summary>
        private PlayerController PawnFor(int seat)
        {
            if (seat == 0 && p1 != null && p1 != _local) return p1;
            if (seat == 1 && p2 != null && p2 != _local) return p2;
            if (playerPrefab == null) return null;

            var go = Instantiate(playerPrefab);
            go.name = "Remote_" + seat;
            go.transform.position = SpawnFor(seat);
            return go.GetComponent<PlayerController>();
        }

        /// <summary>Punto de partida del asiento: los del mapa y, si faltan, un anillo al centro.</summary>
        private Vector2 SpawnFor(int seat)
        {
            var points = _map != null ? _map.BotSpawnPoints : null;
            if (points != null && points.Count > 0) return points[Mathf.Abs(seat) % points.Count];

            float half = _map != null && _map.map != null ? Mathf.Min(_map.map.arenaSize.x, _map.map.arenaSize.y) * 0.5f : 9f;
            float r = half * 0.6f;
            float a = (Mathf.Abs(seat) % 15) / 15f * Mathf.PI * 2f;
            return new Vector2(Mathf.Cos(a) * r, Mathf.Sin(a) * r);
        }

        private RemoteEntry EnsureRemote(int seat)
        {
            var existing = remotes.Find(r => r.seat == seat);
            if (existing != null) return existing;
            if (seat == LocalIndex) return null;

            var pc = PawnFor(seat);
            if (pc == null) return null;

            var opp = GameSession.PvpOpps.Find(o => o != null && o.seat == seat);
            return AddRemote(seat, pc, opp != null ? opp.color : seat, opp != null && opp.bot && IsHost);
        }

        private RemoteEntry AddRemote(int seat, PlayerController pc, int colorIndex, bool botHere)
        {
            var health = pc.Health;
            if (health != null)
            {
                health.team = 1;
                health.networkMirror = !botHere;    // el bot del anfitrion es simulacion local
            }
            if (pc.visual != null)
                pc.visual.SetPaintColor(GameSession.Palette[Mathf.Clamp(colorIndex, 0, GameSession.Palette.Length - 1)]);

            pc.inputSuppressed = true;
            var entry = new RemoteEntry { seat = seat, pc = pc, health = health, bot = botHere };

            if (botHere)
            {
                var brain = pc.gameObject.GetComponent<PvpBotBrain>();
                if (brain == null) brain = pc.gameObject.AddComponent<PvpBotBrain>();
                brain.Bind(seat);
                entry.brain = brain;
                HookBotEvents(entry);
            }
            else
            {
                var avatar = pc.gameObject.GetComponent<PvpRemoteAvatar>();
                if (avatar == null) avatar = pc.gameObject.AddComponent<PvpRemoteAvatar>();
                avatar.Bind(pc);
                entry.avatar = avatar;
                if (health != null) health.Damaged += OnRemoteDamaged;
            }

            remotes.Add(entry);
            return entry;
        }

        private void DestroyRemote(int seat)
        {
            var entry = remotes.Find(r => r.seat == seat);
            if (entry == null) return;

            remotes.Remove(entry);
            UnhookRemoteEvents(entry);
            if (entry.pc == null) return;

            // Los dos pawns de la escena quedan apagados; los clones se destruyen.
            if (entry.pc == p1 || entry.pc == p2) entry.pc.gameObject.SetActive(false);
            else Destroy(entry.pc.gameObject);
        }

        private void HookBotEvents(RemoteEntry entry)
        {
            if (entry.pc != null && entry.pc.Loadout != null)
            {
                entry.attackRelay = (weapon, aim) => SendBotAttack(entry, weapon);
                var weapons = entry.pc.Loadout.weapons;
                if (weapons != null)
                    foreach (var w in weapons)
                        if (w != null) w.Attacked += entry.attackRelay;
            }
            if (entry.health != null)
            {
                entry.diedRelay = _ => OnBotDied(entry);
                entry.health.Died += entry.diedRelay;
            }
        }

        private void UnhookRemoteEvents(RemoteEntry entry)
        {
            if (entry.health != null)
            {
                entry.health.Damaged -= OnRemoteDamaged;
                if (entry.diedRelay != null) entry.health.Died -= entry.diedRelay;
                entry.diedRelay = null;
            }
            if (entry.attackRelay != null && entry.pc != null && entry.pc.Loadout != null)
            {
                var weapons = entry.pc.Loadout.weapons;
                if (weapons != null)
                    foreach (var w in weapons)
                        if (w != null) w.Attacked -= entry.attackRelay;
                entry.attackRelay = null;
            }
        }

        private void SendBotAttack(RemoteEntry entry, MeleeWeapon weapon)
        {
            if (_client == null || !_client.IsConnected || entry == null) return;
            int index = 0;
            var weapons = entry.pc != null && entry.pc.Loadout != null ? entry.pc.Loadout.weapons : null;
            if (weapons != null)
                for (int i = 0; i < weapons.Length; i++)
                    if (weapons[i] == weapon) { index = i; break; }
            _client.Send(new PvpMsg { t = PvpMsgType.Attack, seat = entry.seat, w = index, ax = entry.pc != null ? entry.pc.AimDir.x : 1f, ay = entry.pc != null ? entry.pc.AimDir.y : 0f });
        }

        private void OnBotDied(RemoteEntry entry)
        {
            if (_client == null || !_client.IsConnected || entry == null) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Died, seat = entry.seat });
            Debug.Log($"[WW-PVP] Bot J{entry.seat + 1} eliminado (lo arbitra el anfitrion).");
        }

        // =================================================================
        // Mensajes del server
        // =================================================================

        private void OnMessage(PvpMsg m)
        {
            switch (m.t)
            {
                case PvpMsgType.RoundStart:
                    _deathSent = false;
                    _waitFightTimer = -1f;
                    duel.PvpRoundStart(m.round, m.scores);
                    ResetRemotesForRound();
                    if (m.round <= 1 && countdown != null) countdown.Play();
                    Debug.Log($"[WW-PVP] Ronda {m.round} comienza con {remotes.Count + 1} combatientes.");
                    break;

                case PvpMsgType.RoundEnd:
                    duel.PvpRoundEnd(m.winner, m.scores, m.final);
                    break;

                case PvpMsgType.OppLeft:
                    OnOppLeft(m);
                    break;

                case PvpMsgType.BotsLeft:
                    if (m.seats != null)
                        foreach (int seat in m.seats) DestroyRemote(seat);
                    duel.SetStatus("LOS BOTS DEL ANFITRION SE FUERON");
                    break;

                case PvpMsgType.State:
                    var rs = RemoteFor(m.seat);
                    if (rs != null && rs.avatar != null) rs.avatar.Apply(m);
                    break;

                case PvpMsgType.Attack:
                    var ra = RemoteFor(m.seat);
                    if (ra != null && ra.avatar != null) ra.avatar.PlayAttack(m.w);
                    break;

                case PvpMsgType.Swap:
                    var rw = RemoteFor(m.seat);
                    if (rw != null && rw.avatar != null) rw.avatar.PlaySwap(m.w);
                    break;

                case PvpMsgType.Cast:
                    var rc = RemoteFor(m.seat);
                    if (rc != null && rc.avatar != null) rc.avatar.PlayCast(m.k);
                    break;

                case PvpMsgType.Hit:
                    ApplyIncomingHit(m);
                    break;

                case PvpMsgType.RematchWait:
                    break;

                case PvpMsgType.Error:
                    Debug.LogWarning("[WW-PVP] server: " + m.msg);
                    break;
            }
        }

        /// <summary>Se retiro un combatiente: si era el ultimo remoto, termina la partida.</summary>
        private void OnOppLeft(PvpMsg m)
        {
            int seat = m.seat;
            if (remotes.Exists(r => r.seat == seat))
            {
                DestroyRemote(seat);
                if (remotes.Count > 0)
                {
                    duel.SetStatus($"J{seat + 1} SE RETIRO");
                    return;
                }
            }

            duel.PvpOpponentLeft(m.reason);
            _leaveTimer = 3f;
        }

        /// <summary>Golpe de un remoto: lo aplica el dueno del pawn (o el anfitrion si es su bot).</summary>
        private void ApplyIncomingHit(PvpMsg m)
        {
            if (m.target >= 0 && m.target != LocalIndex)
            {
                // Puede ser un bot de este anfitrion.
                var bot = IsHost ? remotes.Find(r => r.seat == m.target && r.bot) : null;
                if (bot != null && bot.health != null && !bot.health.IsDead)
                    bot.health.TakeDamage(m.dmg, new Vector2(m.dx, m.dy), null);
                return;
            }

            if (_localHealth == null || _localHealth.IsDead) return;
            _localHealth.TakeDamage(m.dmg, new Vector2(m.dx, m.dy), null);
            if (_localHealth.Caster != null) _localHealth.Caster.NotifyDamageTaken();
        }

        private void ResetRemotesForRound()
        {
            foreach (var entry in remotes)
            {
                if (entry.pc == null) continue;
                Vector2 pos = SpawnFor(entry.seat);
                Vector2 look = pos.sqrMagnitude > 0.0001f ? (-pos).normalized : Vector2.right;
                entry.pc.ResetForRound(pos, look);
                if (entry.avatar != null) entry.avatar.Snap();
                if (entry.brain != null) entry.brain.ResetForRound(pos, look);
            }
        }

        private RemoteEntry RemoteFor(int seat)
        {
            if (remotes.Count == 0) return null;
            var r = remotes.Find(x => x.seat == seat);
            return r != null ? r : remotes[0];
        }

        void Update()
        {
            if (!Running) return;

            if (_leaveTimer > 0f)
            {
                _leaveTimer -= Time.unscaledDeltaTime;
                if (_leaveTimer <= 0f) { LoadMenu(); return; }
            }

            if (_waitFightTimer > 0f)
            {
                _waitFightTimer -= Time.unscaledDeltaTime;
                if (_waitFightTimer <= 0f && duel.CurrentPhase == DuelManager.Phase.Intro)
                    duel.SetStatus("ESPERANDO LA RONDA... (Esc para salir)");
            }

            if (!_connectionLost && (_client == null || !_client.IsConnected))
            {
                _connectionLost = true;
                duel.PvpOpponentLeft("disconnect");
                _leaveTimer = 3f;
            }

            if (_client != null && _client.IsConnected)
            {
                _stateAcc += Time.unscaledDeltaTime;
                if (_stateAcc >= StateInterval)
                {
                    _stateAcc = 0f;
                    SendState();
                }
            }
        }

        // =================================================================
        // Estado por red
        // =================================================================

        private void SendState()
        {
            SendPawnState(LocalIndex, _local, _localHealth);
            // El anfitrion tambien manda el estado de cada bot que conduce.
            if (!IsHost) return;
            foreach (var entry in remotes)
                if (entry.bot) SendPawnState(entry.seat, entry.pc, entry.health);
        }

        private void SendPawnState(int seat, PlayerController pc, PlayerHealth health)
        {
            if (pc == null) return;
            var pos = (Vector2)pc.transform.position;
            var aim = pc.AimDir;
            var rb = pc.GetComponent<Rigidbody2D>();
            float speed = rb != null ? rb.linearVelocity.magnitude : 0f;

            _client.Send(new PvpMsg
            {
                t = PvpMsgType.State,
                seat = seat,
                x = pos.x,
                y = pos.y,
                ax = aim.x,
                ay = aim.y,
                sp = speed,
                hp = health != null ? health.CurrentHp : 0f,
                z = health != null && health.Height != null ? health.Height.Z : 0f,
                w = pc.Loadout != null ? pc.Loadout.ActiveIndex : 0
            });
        }

        // =================================================================
        // Eventos del pawn local -> mensajes
        // =================================================================

        private void HookLocalEvents()
        {
            if (_local == null) return;
            if (_local.Loadout != null)
            {
                _local.Loadout.Swapped += OnLocalSwap;
                var weapons = _local.Loadout.weapons;
                if (weapons != null)
                    foreach (var w in weapons)
                        if (w != null) w.Attacked += OnLocalAttack;
            }
            if (_local.Abilities != null) _local.Abilities.CastStarted += OnLocalCast;
        }

        private void UnhookLocalEvents()
        {
            if (_local == null) return;
            if (_local.Loadout != null)
            {
                _local.Loadout.Swapped -= OnLocalSwap;
                var weapons = _local.Loadout.weapons;
                if (weapons != null)
                    foreach (var w in weapons)
                        if (w != null) w.Attacked -= OnLocalAttack;
            }
            if (_local.Abilities != null) _local.Abilities.CastStarted -= OnLocalCast;
        }

        private void OnLocalAttack(MeleeWeapon weapon, Vector2 aim)
        {
            if (_client == null || !_client.IsConnected) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Attack, seat = LocalIndex, w = IndexOfWeapon(weapon), ax = aim.x, ay = aim.y });
        }

        private void OnLocalCast(int slot, AbilityKind kind)
        {
            if (_client == null || !_client.IsConnected) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Cast, seat = LocalIndex, k = (int)kind, w = slot });
        }

        private void OnLocalSwap(int index)
        {
            if (_client == null || !_client.IsConnected) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Swap, seat = LocalIndex, w = index });
        }

        private int IndexOfWeapon(MeleeWeapon weapon)
        {
            var weapons = _local != null && _local.Loadout != null ? _local.Loadout.weapons : null;
            if (weapons == null) return 0;
            for (int i = 0; i < weapons.Length; i++)
                if (weapons[i] == weapon) return i;
            return _local.Loadout.ActiveIndex;
        }

        private void OnLocalDied(PlayerHealth dead)
        {
            if (_deathSent || _client == null || !_client.IsConnected) return;
            _deathSent = true;
            _client.Send(new PvpMsg { t = PvpMsgType.Died });
        }

        /// <summary>Golpe detectado sobre una replica: viaja con el asiento que lo recibe.</summary>
        private void OnRemoteDamaged(PlayerHealth mirror, float amount, Vector2 dir)
        {
            if (_client == null || !_client.IsConnected) return;
            var entry = remotes.Find(r => r.health == mirror);
            if (entry == null) return;
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.Hit,
                seat = LocalIndex,
                target = entry.seat,
                dmg = amount,
                dx = dir.x,
                dy = dir.y
            });
        }

        private void OnRematchPressed()
        {
            if (_client != null && _client.IsConnected)
            {
                _client.Send(new PvpMsg { t = PvpMsgType.Rematch });
                duel.SetStatus("REVANCHA: ESPERANDO AL RIVAL...");
            }
        }

        // =================================================================
        // Salidas
        // =================================================================

        private void ReturnToMenu(string reason)
        {
            Debug.LogWarning("[WW-PVP] " + reason);
            LoadMenu();
        }

        private void LoadMenu()
        {
            Running = false;
            if (_client != null)
            {
                _client.Message -= OnMessage;
                _client.LeaveAndDisconnect();
            }
            SceneManager.LoadScene(GameSession.MenuScene);
        }
    }
}
