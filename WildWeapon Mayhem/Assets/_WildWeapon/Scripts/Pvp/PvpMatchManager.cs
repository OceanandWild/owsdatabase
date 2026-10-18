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
        public Transform[] spawns;

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
            _remote = LocalIndex == 0 ? p2 : p1;
            if (_local == null || _remote == null || duel == null)
            {
                ReturnToMenu("La arena no tiene los jugadores configurados.");
                return;
            }

            _localHealth = _local.Health;
            _remoteHealth = _remote.Health;

            // Colores: el local con su color elegido; el rival con el que mando el server.
            if (_local.visual != null) _local.visual.SetPaintColor(GameSession.GetColor(0));
            if (_remote.visual != null) _remote.visual.SetPaintColor(GameSession.GetOpponentColor());

            // En cada cliente: local = equipo 0, rival = equipo 1 (el daño cruza solo).
            if (_localHealth != null) _localHealth.team = 0;
            if (_remoteHealth != null) _remoteHealth.team = 1;

            // El local juega con teclado+mouse (o mando si hay); al rival lo mueve la red.
            _local.scheme = Gamepad.current != null ? InputScheme.Auto : InputScheme.KeyboardMouse;

            _avatar = _remote.gameObject.AddComponent<PvpRemoteAvatar>();
            _avatar.Bind(_remote);
            if (_remoteHealth != null) _remoteHealth.networkMirror = true;

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
                    if (_avatar != null) _avatar.Snap();
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
                    if (_avatar != null) _avatar.Apply(m);
                    break;

                case PvpMsgType.Attack:
                    if (_avatar != null) _avatar.PlayAttack(m.w);
                    break;

                case PvpMsgType.Swap:
                    if (_avatar != null) _avatar.PlaySwap(m.w);
                    break;

                case PvpMsgType.Cast:
                    if (_avatar != null) _avatar.PlayCast(m.k);
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
            _client.Send(new PvpMsg { t = PvpMsgType.Attack, w = IndexOfWeapon(weapon), ax = aim.x, ay = aim.y });
        }

        private void OnLocalCast(int slot, AbilityKind kind)
        {
            if (_client == null || !_client.IsConnected) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Cast, k = (int)kind, w = slot });
        }

        private void OnLocalSwap(int index)
        {
            if (_client == null || !_client.IsConnected) return;
            _client.Send(new PvpMsg { t = PvpMsgType.Swap, w = index });
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
            _client.Send(new PvpMsg { t = PvpMsgType.Hit, dmg = amount, dx = dir.x, dy = dir.y });
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
