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

        [Header("Cuerpos muertos")]
        [Tooltip("Segundos que el cadaver de un combatiente queda tirado antes de desvanecerse. En PVP los cuerpos se acumulan en el piso y hay que limpiarlos.")]
        public float corpseLifetime = 4.5f;
        [Tooltip("Duracion del desvanecido del cadaver.")]
        public float corpseFadeTime = 1f;

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
            [NonSerialized] public Action<int, AbilityKind> castRelay;
        }
        public readonly List<RemoteEntry> remotes = new List<RemoteEntry>();

        /// <summary>Combatientes del tablero (local + remotos), ordenados por asiento.</summary>
        public readonly List<PvpCombatant> Roster = new List<PvpCombatant>();
        /// <summary>Sube cuando cambia el plantel: el HUD reconstruye las tarjetas.</summary>
        public int RosterVersion { get; private set; }
        /// <summary>Bajas por asiento que arbitra el server.</summary>
        public int[] Kills { get; private set; } = new int[0];
        /// <summary>Rondas ganadas por asiento (el HUD suma por equipo).</summary>
        public int[] RoundScores { get; private set; } = new int[0];

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
            ConfigureCorpse(_localHealth);

            // Colores: el local con su color elegido.
            if (_local.visual != null) _local.visual.SetPaintColor(GameSession.GetColor(0));
            if (_localHealth != null) _localHealth.team = TeamForSeat(LocalIndex, GameSession.PvpTeam);
            // El local juega con teclado y mouse (WASD) como dice el HUD. El mando
            // entra solo si el jugador lo esta usando: antes, que hubiera un mando
            // conectado hacia que el teclado se ignorara y el jugador no se moviera.
            _local.scheme = InputScheme.KeyboardMouse;
            _local.acceptGamepad = true;

            // Remotos: uno por cada asiento del lobby (humanos y bots). Los bots que
            // agrego el anfitrion corren aca con IA; en el resto de las maquinas son
            // replicas comunes y se interpolan desde el estado que manda el anfitrion.
            var opps = (GameSession.PvpOpps != null && GameSession.PvpOpps.Count > 0)
                ? GameSession.PvpOpps
                : new List<PvpOpp>
                {
                    new PvpOpp
                    {
                        name = GameSession.PvpOpponentName,
                        color = GameSession.PvpOpponentColor,
                        seat = LocalIndex == 0 ? 1 : 0,
                        team = LocalIndex == 0 ? 1 : 0,
                    }
                };

            foreach (var opp in opps)
            {
                int seat = opp != null && opp.seat > 0 ? opp.seat : (remotes.Count + 1);
                while (seat == LocalIndex || remotes.Exists(r => r.seat == seat)) seat++;
                if (seat == LocalIndex) continue;

                var pc = PawnFor(seat);
                if (pc == null) continue;
                AddRemote(seat, pc, opp != null ? opp.color : seat,
                    opp != null && opp.bot && IsHost,
                    TeamForSeat(seat, opp != null ? opp.team : seat % 4));
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
            RebuildRoster();
            int seats = LocalIndex + 1;
            foreach (var r in remotes) seats = Mathf.Max(seats, r.seat + 1);
            if (Kills == null || Kills.Length < seats) Kills = new int[seats];
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

        /// <summary>Punto de partida del asiento: los del mapa (siempre sobre el piso).</summary>
        private Vector2 SpawnFor(int seat)
        {
            var points = _map != null ? _map.BotSpawnPoints : null;
            if (points != null && points.Count > 0) return points[Mathf.Abs(seat) % points.Count];

            float half = _map != null && _map.map != null ? Mathf.Min(_map.map.arenaSize.x, _map.map.arenaSize.y) * 0.5f : 9f;
            float r = half * 0.6f;
            float a = (Mathf.Abs(seat) % 15) / 15f * Mathf.PI * 2f;
            float y = (_map != null ? _map.FloorSpawnY : PlatformSurface.FloorY + 0.55f);
            return new Vector2(Mathf.Cos(a) * r, y);
        }

        /// <summary>
        /// El cadaver de los caidos se desvanece solo. En una sala PVP los cuerpos
        /// se acumulan en el piso (el que muere no se va hasta el reset de ronda) y
        /// taparian la arena: cada cliente los borra a su ritmo, asi que el efecto
        /// se ve igual en todos.
        /// </summary>
        private void ConfigureCorpse(PlayerHealth health)
        {
            if (health == null) return;
            health.corpseLifetime = corpseLifetime;
            health.corpseFadeTime = corpseFadeTime;
        }

        /// <summary>
        /// Equipo con el que pelea un asiento. Con los equipos apagados (todos contra
        /// todos) cada combatiente recibe un equipo unico: los filtros de fuego amigo
        /// dejan pasar todos los golpes.
        /// </summary>
        private static int TeamForSeat(int seat, int roomTeam)
        {
            if (!GameSession.PvpTeams) return GameSession.FfaTeam(seat);
            return roomTeam >= 0 ? roomTeam : Mathf.Abs(seat) % 4;
        }

        private RemoteEntry EnsureRemote(int seat)
        {
            var existing = remotes.Find(r => r.seat == seat);
            if (existing != null) return existing;
            if (seat == LocalIndex) return null;

            var pc = PawnFor(seat);
            if (pc == null) return null;

            var opp = GameSession.PvpOpps.Find(o => o != null && o.seat == seat);
            return AddRemote(seat, pc, opp != null ? opp.color : seat,
                opp != null && opp.bot && IsHost,
                TeamForSeat(seat, opp != null ? opp.team : seat % 4));
        }

        // =================================================================
        // Tablero PVP (iconos, bajas y rondas)
        // =================================================================

        public int KillsFor(int seat) =>
            Kills != null && seat >= 0 && seat < Kills.Length ? Kills[seat] : 0;

        public int ScoreFor(int seat) =>
            RoundScores != null && seat >= 0 && seat < RoundScores.Length ? RoundScores[seat] : 0;

        private void SetKills(int[] kills)
        {
            if (kills == null) return;
            if (Kills == null || Kills.Length < kills.Length) Kills = new int[kills.Length];
            Array.Copy(kills, Kills, kills.Length);
        }

        private void SetScores(int[] scores)
        {
            if (scores == null) return;
            if (RoundScores == null || RoundScores.Length < scores.Length) RoundScores = new int[scores.Length];
            Array.Copy(scores, RoundScores, scores.Length);
        }

        /// <summary>Rehace el plantel que dibuja el HUD con el local y los remotos vivos.</summary>
        private void RebuildRoster()
        {
            Roster.Clear();

            if (_local != null)
            {
                Roster.Add(new PvpCombatant
                {
                    seat = LocalIndex,
                    name = string.IsNullOrEmpty(GameSession.PvpLocalName) ? "VOS" : GameSession.PvpLocalName,
                    colorIndex = GameSession.GetColorIndex(0),
                    team = _localHealth != null ? _localHealth.team : GameSession.PvpTeam,
                    isLocal = true,
                    health = _localHealth,
                    visual = _local.visual
                });
            }

            foreach (var entry in remotes)
            {
                PvpOpp opp = null;
                if (GameSession.PvpOpps != null)
                {
                    foreach (var o in GameSession.PvpOpps)
                        if (o != null && o.seat == entry.seat) { opp = o; break; }
                }

                Roster.Add(new PvpCombatant
                {
                    seat = entry.seat,
                    name = opp != null && !string.IsNullOrEmpty(opp.name) ? opp.name : "J" + (entry.seat + 1),
                    colorIndex = opp != null ? opp.color : entry.seat,
                    team = entry.health != null ? entry.health.team : (opp != null ? opp.team : 0),
                    bot = entry.bot,
                    health = entry.health,
                    visual = entry.pc != null ? entry.pc.visual : null
                });
            }

            Roster.Sort((a, b) => a.seat.CompareTo(b.seat));
            RosterVersion++;
        }

        private RemoteEntry AddRemote(int seat, PlayerController pc, int colorIndex, bool botHere, int team)
        {
            var health = pc.Health;
            if (health != null)
            {
                health.team = team;
                health.networkMirror = !botHere;    // el bot del anfitrion es simulacion local
            }
            ConfigureCorpse(health);
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
            RebuildRoster();
            return entry;
        }

        private void DestroyRemote(int seat)
        {
            var entry = remotes.Find(r => r.seat == seat);
            if (entry == null) return;

            remotes.Remove(entry);
            RebuildRoster();
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
            // El bot tambien castea habilidades: los demas clientes tienen que verlo.
            if (entry.pc != null && entry.pc.Abilities != null)
            {
                entry.castRelay = (slot, kind) => SendBotCast(entry, slot, kind);
                entry.pc.Abilities.CastStarted += entry.castRelay;
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
            if (entry.castRelay != null && entry.pc != null && entry.pc.Abilities != null)
            {
                entry.pc.Abilities.CastStarted -= entry.castRelay;
                entry.castRelay = null;
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

        /// <summary>Habilidad que lanzo un bot del anfitrion: se reenvia a los demas clientes.</summary>
        private void SendBotCast(RemoteEntry entry, int slot, AbilityKind kind)
        {
            if (_client == null || !_client.IsConnected || entry == null) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Cast, seat = entry.seat, k = (int)kind, w = slot });
        }

        private void OnBotDied(RemoteEntry entry)
        {
            if (_client == null || !_client.IsConnected || entry == null) return;
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.Died,
                seat = entry.seat,
                killer = KillerSeatOf(entry.health)
            });
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
                    SetScores(m.scores);
                    SetKills(m.kills);
                    duel.PvpRoundStart(m.round, m.scores);
                    ResetRemotesForRound();
                    if (m.round <= 1 && countdown != null) countdown.Play();
                    Debug.Log($"[WW-PVP] Ronda {m.round} comienza con {remotes.Count + 1} combatientes.");
                    break;

                case PvpMsgType.RoundEnd:
                    SetScores(m.scores);
                    SetKills(m.kills);
                    duel.PvpRoundEnd(m.winner, m.scores, m.final);
                    break;

                case PvpMsgType.Kills:
                    SetKills(m.kills);
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
                {
                    // Defensa extra: con equipos activos, un companero no puede herir
                    // a otro aunque el mensaje llegue igual.
                    if (GameSession.TeamsActive && TeamOfSeat(m.seat) == bot.health.team) return;
                    bot.health.lastAttackerSeat = m.seat;
                    bot.health.TakeDamage(m.dmg, new Vector2(m.dx, m.dy), null);
                }
                return;
            }

            if (_localHealth == null || _localHealth.IsDead) return;
            if (GameSession.TeamsActive && TeamOfSeat(m.seat) == _localHealth.team) return;
            _localHealth.lastAttackerSeat = m.seat;
            _localHealth.TakeDamage(m.dmg, new Vector2(m.dx, m.dy), null);
            if (_localHealth.Caster != null) _localHealth.Caster.NotifyDamageTaken();
        }

        /// <summary>Equipo del asiento atacante segun la tabla local (local o remoto).</summary>
        private int TeamOfSeat(int seat)
        {
            if (seat == LocalIndex) return _localHealth != null ? _localHealth.team : -999;
            var entry = remotes.Find(r => r.seat == seat);
            return entry != null && entry.health != null ? entry.health.team : -999;
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
            float speed = rb != null ? Mathf.Abs(rb.linearVelocity.x) : 0f;

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
                z = 0f,   // la vista lateral usa la Y del mundo como altura
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
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.Died,
                killer = KillerSeatOf(_localHealth)
            });
        }

        /// <summary>Asiento del que dio el ultimo golpe (para acreditar la baja).</summary>
        private int KillerSeatOf(PlayerHealth victim)
        {
            if (victim == null) return -1;
            if (victim.lastAttackerSeat >= 0) return victim.lastAttackerSeat;

            var source = victim.LastAttacker;
            if (source == null || source == victim) return -1;
            if (source == _localHealth) return LocalIndex;

            var entry = remotes.Find(r => r.health == source);
            return entry != null ? entry.seat : -1;
        }

        /// <summary>Golpe detectado sobre una replica: viaja con el asiento que lo recibe.</summary>
        private void OnRemoteDamaged(PlayerHealth mirror, PlayerHealth source, float amount, Vector2 dir)
        {
            if (_client == null || !_client.IsConnected) return;
            var entry = remotes.Find(r => r.health == mirror);
            if (entry == null) return;
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.Hit,
                seat = SeatOfHealth(source),
                target = entry.seat,
                dmg = amount,
                dx = dir.x,
                dy = dir.y
            });
        }

        /// <summary>Asiento del portador que produjo el golpe (local o bot del anfitrion).</summary>
        private int SeatOfHealth(PlayerHealth source)
        {
            if (source == null || source == _localHealth) return LocalIndex;
            var entry = remotes.Find(r => r.health == source);
            return entry != null ? entry.seat : LocalIndex;
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
