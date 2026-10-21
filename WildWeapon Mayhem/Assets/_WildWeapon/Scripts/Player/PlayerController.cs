using UnityEngine;
using UnityEngine.InputSystem;

namespace WildWeapon
{
    public enum InputScheme { KeyboardMouse, KeyboardTwin, Gamepad, Auto }

    /// <summary>
    /// Portador F0: movimiento + dash + apuntado + swap + ataque basico.
    /// Lee Input System directo (los Action Maps llegan en F1).
    /// </summary>
    [RequireComponent(typeof(Rigidbody2D))]
    public class PlayerController : MonoBehaviour
    {
        public InputScheme scheme = InputScheme.Auto;

        [Tooltip("Pivote visual que rota hacia donde apuntas (padre de las armas)")]
        public Transform aimPivot;

        [Tooltip("Capa visual animada (Visual > Body)")]
        public CharacterVisual visual;

        [Tooltip("Altura (fisica de plataformas): gravedad, salto y doble salto")]
        public HeightBody height;

        [Tooltip("Acepta tambien el gamepad (stick + botones) ademas del teclado. " +
                 "El mando solo toma el control cuando el jugador lo esta usando: " +
                 "un mando simplemente conectado NO puede dejar sin control al teclado.")]
        public bool acceptGamepad = true;

        public PlayerHealth Health { get; private set; }
        public WeaponLoadout Loadout { get; private set; }
        public AbilityCaster Abilities { get; private set; }

        public Vector2 AimDir { get; private set; } = Vector2.right;
        public bool CanAct { get; set; }

        /// <summary>PVP: el pawn lo conduce la red (replica del rival); se ignora el input local.</summary>
        public bool inputSuppressed;
        /// <summary>PVP: velocidad informada por el rival (solo para la animacion).</summary>
        [HideInInspector] public float networkSpeed;

        /// <summary>Slow de root parcial durante el cast de habilidad (doc §2.4: 40%).</summary>
        [HideInInspector] public float castingSlow = 1f;
        [HideInInspector] public bool Casting;

        /// <summary>i-frames durante los primeros 0.15 s del dash (doc 2.3).</summary>
        public bool IsInvulnerable => _dashTimer > (DuelRules.DashTime - DuelRules.DashIFrameTime) || _invulnTimer > 0f;

        private Rigidbody2D _rb;
        private Camera _cam;

        private Vector2 _moveInput;
        private Vector2 _rawMove;
        private bool _attackHeld;
        private bool _dashQueued;
        private bool _jumpQueued;
        private bool _swapQueued;
        private bool _qQueued;
        private bool _eQueued;
        private bool _rQueued;
        private Vector2 _knockback;

        private float _dashTimer;
        private float _dashCooldown;
        private float _invulnTimer;
        private Vector2 _dashDir;

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            Health = GetComponent<PlayerHealth>();
            Loadout = GetComponent<WeaponLoadout>();
            Abilities = GetComponent<AbilityCaster>();
            if (height == null) height = GetComponent<HeightBody>();
            if (height == null) height = gameObject.AddComponent<HeightBody>();
            _cam = Camera.main;

            // El equipamiento elegido en la armería manda sobre el del prefab.
            GameSession.ApplyLoadout(Loadout);
        }

        void Update()
        {
            if (_cam == null) _cam = Camera.main;
            if (!inputSuppressed) ReadInput();

            if (aimPivot != null)
            {
                float angle = Mathf.Atan2(AimDir.y, AimDir.x) * Mathf.Rad2Deg;
                aimPivot.rotation = Quaternion.Euler(0f, 0f, angle);
            }

            if (visual != null)
            {
                visual.Face(AimDir);
                visual.SetSpeed(inputSuppressed ? networkSpeed : Mathf.Abs(_rb.linearVelocity.x));
            }
        }

        private void ReadInput()
        {
            _moveInput = Vector2.zero;
            _attackHeld = false;
            Vector2 raw = Vector2.zero;   // entrada cruda: el apuntado y el dash la usan

            var kb = Keyboard.current;
            var mouse = Mouse.current;
            var pad = Gamepad.current;

            // "Auto" es teclado y mouse (WASD). El gamepad entra aparte y solo
            // cuando el jugador lo esta usando de verdad: que haya un mando
            // conectado NO puede dejar sin control al teclado (bug: el juego se
            // quedaba sin movimiento porque el mando "ganaba" el control solo).
            var active = scheme == InputScheme.Auto ? InputScheme.KeyboardMouse : scheme;
            bool padOnly = active == InputScheme.Gamepad;
            bool padActive = padOnly
                ? pad != null
                : (acceptGamepad && pad != null && PadInUse(pad));

            // ---- Teclado y mouse ----
            if (!padOnly)
            {
                if (active == InputScheme.KeyboardMouse)
                {
                    if (kb != null)
                    {
                        raw = new Vector2(
                            (kb.dKey.isPressed ? 1f : 0f) - (kb.aKey.isPressed ? 1f : 0f), 0f);
                        if (kb.leftShiftKey.wasPressedThisFrame) _dashQueued = true;
                        if (kb.spaceKey.wasPressedThisFrame || kb.wKey.wasPressedThisFrame) _jumpQueued = true;
                        if (kb.xKey.wasPressedThisFrame) _swapQueued = true;
                        if (kb.qKey.wasPressedThisFrame) _qQueued = true;
                        if (kb.eKey.wasPressedThisFrame) _eQueued = true;
                        if (kb.rKey.wasPressedThisFrame) _rQueued = true;
                    }
                    if (mouse != null)
                    {
                        _attackHeld = mouse.leftButton.isPressed;
                        if (Mathf.Abs(mouse.scroll.ReadValue().y) > 0.01f) _swapQueued = true;
                        // Con el mando en uso el apuntado lo manda el stick derecho.
                        if (!padActive && _cam != null)
                        {
                            Vector3 screen = mouse.position.ReadValue();
                            Vector3 world = _cam.ScreenToWorldPoint(new Vector3(screen.x, screen.y, -_cam.transform.position.z));
                            Vector2 dir = (Vector2)world - (Vector2)transform.position;
                            if (dir.sqrMagnitude > 0.0001f) AimDir = dir.normalized;
                        }
                    }
                }
                else if (active == InputScheme.KeyboardTwin)
                {
                    if (kb != null)
                    {
                        raw = new Vector2(
                            (kb.rightArrowKey.isPressed ? 1f : 0f) - (kb.leftArrowKey.isPressed ? 1f : 0f), 0f);
                        _attackHeld = kb.commaKey.isPressed;
                        if (kb.periodKey.wasPressedThisFrame) _dashQueued = true;
                        if (kb.spaceKey.wasPressedThisFrame || kb.upArrowKey.wasPressedThisFrame) _jumpQueued = true;      // salto (barra espaciadora / flecha arriba)
                        if (kb.slashKey.wasPressedThisFrame) _swapQueued = true;
                        if (kb.uKey.wasPressedThisFrame) _qQueued = true;
                        if (kb.iKey.wasPressedThisFrame) _eQueued = true;
                        if (kb.oKey.wasPressedThisFrame) _rQueued = true;
                    }
                    // Apuntado asistido: la direccion de movimiento marca el aim (doc 5.2).
                    if (!padActive && raw.sqrMagnitude > 0.01f) AimDir = raw.normalized;
                }
            }

            // ---- Gamepad ----
            if (padActive)
            {
                raw = pad.leftStick.ReadValue();
                Vector2 rs = pad.rightStick.ReadValue();
                if (rs.sqrMagnitude > 0.06f) AimDir = rs.normalized;
                else if (raw.sqrMagnitude > 0.02f) AimDir = raw.normalized;

                _attackHeld = _attackHeld || pad.rightTrigger.ReadValue() > 0.5f;
                if (pad.buttonEast.wasPressedThisFrame) _dashQueued = true;
                if (pad.buttonSouth.wasPressedThisFrame) _jumpQueued = true;
                if (pad.leftStickButton.wasPressedThisFrame) _swapQueued = true;
                if (pad.leftTrigger.wasPressedThisFrame) _qQueued = true;
                if (pad.leftShoulder.wasPressedThisFrame) _eQueued = true;
                if (pad.buttonNorth.wasPressedThisFrame) _rQueued = true;
            }

            // Vista lateral: A/D (o el stick horizontal) mueve; la altura se gana
            // saltando. La Y de la arena ya no es profundidad.
            _rawMove = new Vector2(raw.x, 0f);
            _moveInput = _rawMove;
        }

        /// <summary>
        /// true si el mando esta siendo usado ahora (stick fuera de la zona muerta o
        /// boton apretado). Sirve para que el mando no le robe el control al teclado
        /// solo por estar conectado.
        /// </summary>
        private static bool PadInUse(Gamepad pad)
        {
            if (pad == null) return false;
            if (pad.leftStick.ReadValue().sqrMagnitude > 0.06f) return true;
            if (pad.rightStick.ReadValue().sqrMagnitude > 0.06f) return true;
            if (pad.leftTrigger.ReadValue() > 0.2f) return true;
            if (pad.rightTrigger.ReadValue() > 0.2f) return true;
            if (pad.buttonSouth.isPressed || pad.buttonNorth.isPressed) return true;
            if (pad.buttonWest.isPressed || pad.buttonEast.isPressed) return true;
            if (pad.leftShoulder.isPressed || pad.rightShoulder.isPressed) return true;
            if (pad.leftStickButton.isPressed || pad.rightStickButton.isPressed) return true;
            return false;
        }

        void FixedUpdate()
        {
            if (inputSuppressed) return;   // PVP: la replica del rival la mueve PvpRemoteAvatar

            float dt = Time.fixedDeltaTime;
            if (_dashCooldown > 0f) _dashCooldown -= dt;
            if (_invulnTimer > 0f) _invulnTimer -= dt;

            // Salto: lo resuelve HeightBody (gravedad y aterrizaje en plataformas).
            if (_jumpQueued && height != null && !(Health != null && Health.IsDead))
            {
                if (CanAct && !IsStunned) height.QueueJump();
                _jumpQueued = false;
            }

            bool dead = Health != null && Health.IsDead;
            if (!CanAct || dead || controllerStunned > 0f)
            {
                if (controllerStunned > 0f) controllerStunned -= dt;
                _dashQueued = false;
                _jumpQueued = false;
                _swapQueued = false;
                _qQueued = false; _eQueued = false; _rQueued = false;
                if (height != null) height.SetHorizontalVelocity(0f);
                else _rb.linearVelocity = new Vector2(0f, _rb.linearVelocity.y);
                _knockback = Vector2.zero;
                return;
            }

            if (_dashQueued && _dashCooldown <= 0f)
            {
                // El dash es horizontal: la entrada cruda manda y, si no hay, el apuntado.
                float dashX = Mathf.Abs(_rawMove.x) > 0.2f
                    ? Mathf.Sign(_rawMove.x)
                    : (Mathf.Abs(AimDir.x) > 0.2f ? Mathf.Sign(AimDir.x) : 1f);
                _dashDir = new Vector2(dashX, 0f);
                _dashTimer = DuelRules.DashTime;
                _dashCooldown = DuelRules.DashCooldown;
            }
            _dashQueued = false;

            float slow = Health != null ? Health.SlowFactor : 1f;

            float vx;
            if (_dashTimer > 0f)
            {
                _dashTimer -= dt;
                vx = _dashDir.x * DuelRules.DashSpeed;
            }
            else
            {
                vx = _moveInput.x * DuelRules.MoveSpeed * castingSlow * slow;
            }

            vx += _knockback.x;
            if (height != null) height.SetHorizontalVelocity(vx);
            else _rb.linearVelocity = new Vector2(vx, _rb.linearVelocity.y);
            _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-14f * dt));

            if (Loadout != null)
            {
                if (_swapQueued) Loadout.TrySwap();
                _swapQueued = false;
                if (_attackHeld) Loadout.TryAttack(AimDir, Health);
            }

            if (Abilities != null)
            {
                if (_qQueued) Abilities.QueueQ();
                if (_eQueued) Abilities.QueueE();
                if (_rQueued) Abilities.QueueR();
            }
            _qQueued = false; _eQueued = false; _rQueued = false;
        }

        public void ApplyKnockback(Vector2 dir, float amount)
        {
            _knockback += new Vector2(dir.x, 0f) * amount;
            // La componente vertical la resuelve HeightBody como impulso (no se pisa
            // la gravedad ni el salto con una velocidad vertical fija).
            if (height != null && Mathf.Abs(dir.y) > 0.05f)
                height.AddVerticalImpulse(dir.y * amount * 0.8f);
        }

        /// <summary>PVP: fija el apuntado del pawn remoto desde su snapshot de red.</summary>
        public void SetAimFromNetwork(Vector2 dir)
        {
            if (dir.sqrMagnitude > 0.0001f) AimDir = dir.normalized;
        }

        /// <summary>i-frames extra por habilidad (ej. Dash-Tajo de la Katana).</summary>
        public void GrantIFrames(float duration)
        {
            _invulnTimer = Mathf.Max(_invulnTimer, duration);
        }

        /// <summary>Stun por habilidad: congela input hasta que expire.</summary>
        public void Stun(float seconds)
        {
            controllerStunned = Mathf.Max(controllerStunned, seconds);
        }

        [HideInInspector] public float controllerStunned;

        public bool IsStunned => controllerStunned > 0f;

        public void ResetForRound(Vector2 pos, Vector2 lookDir)
        {
            transform.position = pos;
            _rb.position = pos;
            _rb.linearVelocity = Vector2.zero;

            _knockback = Vector2.zero;
            _dashTimer = 0f;
            _dashCooldown = 0f;
            _dashQueued = false;
            _swapQueued = false;
            _moveInput = Vector2.zero;
            _rawMove = Vector2.zero;
            _attackHeld = false;
            controllerStunned = 0f;
            Casting = false;
            castingSlow = 1f;
            _invulnTimer = 0f;

            AimDir = lookDir.sqrMagnitude > 0.0001f ? lookDir.normalized : Vector2.right;

            _jumpQueued = false;
            if (height != null) { height.simulate = true; height.ResetHeight(); }

            if (Health != null) Health.ResetHealth();
            if (Abilities != null) Abilities.ResetForRound();
            if (Loadout != null) Loadout.ResetLoadout();
            CanAct = false;
        }
    }
}
