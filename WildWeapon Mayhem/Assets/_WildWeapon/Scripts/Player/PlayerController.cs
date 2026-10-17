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

        public float BodyRadius = 0.45f;

        public PlayerHealth Health { get; private set; }
        public WeaponLoadout Loadout { get; private set; }

        public Vector2 AimDir { get; private set; } = Vector2.right;
        public bool CanAct { get; set; }

        /// <summary>i-frames durante los primeros 0.15 s del dash (doc 2.3).</summary>
        public bool IsInvulnerable => _dashTimer > (DuelRules.DashTime - DuelRules.DashIFrameTime);

        private Rigidbody2D _rb;
        private Camera _cam;

        private Vector2 _moveInput;
        private bool _attackHeld;
        private bool _dashQueued;
        private bool _swapQueued;
        private Vector2 _knockback;

        private float _dashTimer;
        private float _dashCooldown;
        private Vector2 _dashDir;

        void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            Health = GetComponent<PlayerHealth>();
            Loadout = GetComponent<WeaponLoadout>();
            _cam = Camera.main;
        }

        void Update()
        {
            if (_cam == null) _cam = Camera.main;
            ReadInput();

            if (aimPivot != null)
            {
                float angle = Mathf.Atan2(AimDir.y, AimDir.x) * Mathf.Rad2Deg;
                aimPivot.rotation = Quaternion.Euler(0f, 0f, angle);
            }
        }

        private void ReadInput()
        {
            _moveInput = Vector2.zero;
            _attackHeld = false;

            var kb = Keyboard.current;
            var mouse = Mouse.current;
            var pad = Gamepad.current;

            var active = scheme;
            if (active == InputScheme.Auto)
                active = pad != null ? InputScheme.Gamepad : InputScheme.KeyboardTwin;

            if (active == InputScheme.KeyboardMouse)
            {
                if (kb != null)
                {
                    _moveInput = new Vector2(
                        (kb.dKey.isPressed ? 1f : 0f) - (kb.aKey.isPressed ? 1f : 0f),
                        (kb.wKey.isPressed ? 1f : 0f) - (kb.sKey.isPressed ? 1f : 0f));
                    if (kb.leftShiftKey.wasPressedThisFrame || kb.spaceKey.wasPressedThisFrame) _dashQueued = true;
                    if (kb.xKey.wasPressedThisFrame) _swapQueued = true;
                }
                if (mouse != null)
                {
                    _attackHeld = mouse.leftButton.isPressed;
                    if (Mathf.Abs(mouse.scroll.ReadValue().y) > 0.01f) _swapQueued = true;
                    if (_cam != null)
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
                    _moveInput = new Vector2(
                        (kb.rightArrowKey.isPressed ? 1f : 0f) - (kb.leftArrowKey.isPressed ? 1f : 0f),
                        (kb.upArrowKey.isPressed ? 1f : 0f) - (kb.downArrowKey.isPressed ? 1f : 0f));
                    _attackHeld = kb.commaKey.isPressed;
                    if (kb.periodKey.wasPressedThisFrame) _dashQueued = true;
                    if (kb.slashKey.wasPressedThisFrame) _swapQueued = true;
                }
                // Apuntado asistido: la direccion de movimiento marca el aim (doc 5.2).
                if (_moveInput.sqrMagnitude > 0.01f) AimDir = _moveInput.normalized;
            }
            else // Gamepad
            {
                if (pad != null)
                {
                    _moveInput = pad.leftStick.ReadValue();
                    Vector2 rs = pad.rightStick.ReadValue();
                    if (rs.sqrMagnitude > 0.06f) AimDir = rs.normalized;
                    else if (_moveInput.sqrMagnitude > 0.02f) AimDir = _moveInput.normalized;

                    _attackHeld = pad.rightTrigger.ReadValue() > 0.5f;
                    if (pad.buttonEast.wasPressedThisFrame) _dashQueued = true;
                    if (pad.leftTrigger.ReadValue() > 0.5f || pad.leftStickButton.wasPressedThisFrame) _swapQueued = true;
                }
            }
        }

        void FixedUpdate()
        {
            float dt = Time.fixedDeltaTime;
            if (_dashCooldown > 0f) _dashCooldown -= dt;

            bool dead = Health != null && Health.IsDead;
            if (!CanAct || dead)
            {
                _dashQueued = false;
                _swapQueued = false;
                _rb.linearVelocity = Vector2.zero;
                _knockback = Vector2.zero;
                return;
            }

            if (_dashQueued && _dashCooldown <= 0f)
            {
                _dashDir = _moveInput.sqrMagnitude > 0.01f ? _moveInput.normalized : AimDir;
                _dashTimer = DuelRules.DashTime;
                _dashCooldown = DuelRules.DashCooldown;
            }
            _dashQueued = false;

            Vector2 vel;
            if (_dashTimer > 0f)
            {
                _dashTimer -= dt;
                vel = _dashDir * DuelRules.DashSpeed;
            }
            else
            {
                vel = _moveInput * DuelRules.MoveSpeed;
            }

            vel += _knockback;
            _rb.linearVelocity = vel;
            _knockback = Vector2.Lerp(_knockback, Vector2.zero, 1f - Mathf.Exp(-14f * dt));

            if (Loadout != null)
            {
                if (_swapQueued) Loadout.TrySwap();
                _swapQueued = false;
                if (_attackHeld) Loadout.TryAttack(AimDir, Health);
            }
        }

        public void ApplyKnockback(Vector2 dir, float amount)
        {
            _knockback += dir * amount;
        }

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
            _attackHeld = false;

            AimDir = lookDir.sqrMagnitude > 0.0001f ? lookDir.normalized : Vector2.right;

            if (Health != null) Health.ResetHealth();
            if (Loadout != null) Loadout.ResetLoadout();
            CanAct = false;
        }
    }
}
