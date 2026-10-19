using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Orquesta el duelo PVP online dentro de la Arena:
    /// elige el pawn local segun el asiento que dio el server, conduce la replica
    /// del rival por red, sincroniza estado a ~15 Hz y traduce los mensajes del
    /// servidor (round_start/round_end/opp_left) al DuelManager (modo pvpDriven).
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
            public PvpRemoteAvatar avatar;
        }
        public readonly List<RemoteEntry> remotes = new List<RemoteEntry>();

        public int LocalIndex { get; private set; }
        public bool Running { get; private set; }
        public bool CountdownVisible => countdown != null && countdown.IsPlaying;

        private PvpClient _client;
        private PlayerController _local, _remote;
        private PlayerHealth _localHealth, _remoteHealth;
        private PvpRemoteAvatar _avatar;

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
            if (_remoteHealth != null) _remoteHealth.Damaged -= OnRemoteDamaged;
            if (duel != null) duel.PvpRematchRequested -= OnRematchPressed;
            UnhookLocalEvents();
        }

        void Start()
        {
            if (GameSession.Mode != GameMode.Pvp) { gameObject.SetActive(false); return; }

            LocalIndex = Mathf.Clamp(GameSession.PvpSeat, 0, 1);
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

            // Remotos: uno por cada oponente del lobby (o el rival unico del quickmatch).
            var opps = (GameSession.PvpOpps != null && GameSession.PvpOpps.Count > 0)
                ? GameSession.PvpOpps
                : new List<PvpOpp> { new PvpOpp { name = GameSession.PvpOpponentName, color = GameSession.PvpOpponentColor } };

            foreach (var opp in opps)
            {
                int seat = opp.seat > 0 ? opp.seat : (remotes.Count + 1);
                // avoid duplicate seats
                while (remotes.Exists(r => r.seat == seat)) seat++;
                if (seat == LocalIndex) continue;

                PlayerController pc = null;
                if (seat == 0 && LocalIndex != 0 && p1 != null) pc = p1;
                else if (seat == 1 && LocalIndex != 1 && p2 != null) pc = p2;

                if (pc == null && playerPrefab != null)
                {
                    var go = Instantiate(playerPrefab);
                    go.name = "Remote_" + seat;
                    pc = go.GetComponent<PlayerController>();
                    if (spawns != null && spawns.Length > 0)
                    {
                        int si = seat % spawns.Length;
                        if (spawns[si] != null) go.transform.position = spawns[si].position;
                    }
                }
                if (pc == null) continue;

                var health = pc.Health;
                if (health != null) { health.team = 1; health.networkMirror = true; }
                if (pc.visual != null) pc.visual.SetPaintColor(GameSession.Palette[Mathf.Clamp(opp.color, 0, GameSession.Palette.Length - 1)]);

                pc.inputSuppressed = true;
                var avatar = pc.gameObject.GetComponent<PvpRemoteAvatar>();
                if (avatar == null) avatar = pc.gameObject.AddComponent<PvpRemoteAvatar>();
                avatar.Bind(pc);

                remotes.Add(new RemoteEntry { seat = seat, pc = pc, health = health, avatar = avatar });
            }

            // alias _remote/_avatar para compatibilidad (primer remoto)
            if (remotes.Count > 0)
            {
                _remote = remotes[0].pc;
                _remoteHealth = remotes[0].health;
                _avatar = remotes[0].avatar;
            }

            // El arbitraje de rondas lo hace el server: DuelManager arranca en modo conducido.
            duel.pvpDriven = true;
            if (duelRoot != null) duelRoot.SetActive(true);

            duel.SetStatus("CONECTANDO...");
            duel.PvpRematchRequested += OnRematchPressed;
            if (_localHealth != null) _localHealth.Died += OnLocalDied;
            if (_remoteHealth != null) _remoteHealth.Damaged += OnRemoteDamaged;
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
            Debug.Log($"[WW-PVP] Arena lista - local J{LocalIndex + 1} vs {GameSession.PvpOpponentName}.");
        }

        private RemoteEntry EnsureRemote(int seat)
    {
        var existing = remotes.Find(r => r.seat == seat);
        if (existing != null) return existing;

        PlayerController pc = null;
        if (seat == 0 && LocalIndex != 0 && p1 != null) pc = p1;
        else if (seat == 1 && LocalIndex != 1 && p2 != null) pc = p2;

        if (pc == null && playerPrefab != null)
        {
            var go = Instantiate(playerPrefab);
            go.name = "Remote_" + seat;
            pc = go.GetComponent<PlayerController>();
            // position ring
            if (spawns != null && spawns.Length > 0)
            {
                int si = seat % spawns.Length;
                if (spawns[si] != null) go.transform.position = spawns[si].position;
            }
        }
        if (pc == null) return null;

        var health = pc.Health;
        if (health != null) { health.team = 1; health.networkMirror = true; }

        pc.inputSuppressed = true;
        var avatar = pc.gameObject.GetComponent<PvpRemoteAvatar>();
        if (avatar == null) avatar = pc.gameObject.AddComponent<PvpRemoteAvatar>();
        avatar.Bind(pc);

        var entry = new RemoteEntry { seat = seat, pc = pc, health = health, avatar = avatar };
        remotes.Add(entry);
        return entry;
    }

    private RemoteEntry RemoteFor(int seat)
    {
        if (remotes.Count == 0) return null;
        if (seat == 0) return remotes[0];
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
                    duel.SetStatus("ESPERANDO AL RIVAL... (Esc para salir)");
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
                    foreach (var r in remotes) if (r.avatar != null) r.avatar.Snap();
                    if (m.round <= 1 && countdown != null) countdown.Play();
                    Debug.Log($"[WW-PVP] Ronda {m.round} comienza ({(m.scores != null && m.scores.Length >= 2 ? m.scores[0] + "-" + m.scores[1] : "0-0")}).");
                    break;

                case PvpMsgType.RoundEnd:
                    duel.PvpRoundEnd(m.winner, m.scores, m.final);
                    break;

                case PvpMsgType.OppLeft:
                    duel.PvpOpponentLeft(m.reason);
                    _leaveTimer = 3f;
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

        /// <summary>Golpe del rival: lo aplica el dueño local (esta maquina decide i-frames y muerte).</summary>
        private void ApplyIncomingHit(PvpMsg m)
        {
            if (_localHealth == null || _localHealth.IsDead) return;
            _localHealth.TakeDamage(m.dmg, new Vector2(m.dx, m.dy), null);
            if (_localHealth.Caster != null) _localHealth.Caster.NotifyDamageTaken();
        }

        private void SendState()
        {
            var pos = (Vector2)_local.transform.position;
            var aim = _local.AimDir;
            var rb = _local.GetComponent<Rigidbody2D>();
            float speed = rb != null ? rb.linearVelocity.magnitude : 0f;

            _client.Send(new PvpMsg
            {
                t = PvpMsgType.State,
                seat = LocalIndex,
                x = pos.x,
                y = pos.y,
                ax = aim.x,
                ay = aim.y,
                sp = speed,
                hp = _localHealth != null ? _localHealth.CurrentHp : 0f,
                z = _localHealth != null && _localHealth.Height != null ? _localHealth.Height.Z : 0f,
                w = _local.Loadout != null ? _local.Loadout.ActiveIndex : 0
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

        private void OnRemoteDamaged(PlayerHealth mirror, float amount, Vector2 dir)
        {
            if (_client == null || !_client.IsConnected) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Hit, seat = LocalIndex, dmg = amount, dx = dir.x, dy = dir.y });
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
