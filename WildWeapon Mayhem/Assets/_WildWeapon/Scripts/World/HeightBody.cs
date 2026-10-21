using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Rendering;

namespace WildWeapon
{
    /// <summary>
    /// Cuerpo de plataformas 2D (vista lateral). Es la autoridad vertical del
    /// personaje: aplica gravedad, resuelve salto y doble salto, coyote time,
    /// buffer de salto y deteccion de piso contra colliders reales (el piso de la
    /// arena y los decks one-way).
    ///
    /// Los controladores (jugador, bots y red) solo escriben la velocidad
    /// horizontal con <see cref="SetHorizontalVelocity"/>; este componente corre
    /// despues (DefaultExecutionOrder) y compone la velocidad final del
    /// Rigidbody2D. Los prefabs siguen con gravityScale = 0: la gravedad la
    /// aplica este script para que todos los cuerpos compartan el mismo tuneo.
    /// </summary>
    [DisallowMultipleComponent]
    [DefaultExecutionOrder(100)]
    public class HeightBody : MonoBehaviour
    {
        /// <summary>Personajes con fisica vertical vivos.</summary>
        public static readonly List<HeightBody> All = new List<HeightBody>();

        [Header("Salto")]
        [Tooltip("Gravedad propia (el Rigidbody2D de los prefabs tiene gravityScale 0)")]
        public float gravity = 30f;
        [Tooltip("Velocidad inicial del salto. Con gravity 30 sube ~3.3: llega de sobra al primer deck (2.6)")]
        public float jumpSpeed = 14f;
        [Tooltip("Saltos extra en el aire (1 = doble salto)")] public int airJumps = 1;
        [Tooltip("Impulso del salto en el aire: se SUMA a la velocidad vertical actual, asi el doble salto nunca se pierde")]
        public float doubleJumpSpeed = 11f;
        [Tooltip("Tope de velocidad vertical al encadenar el doble salto")]
        public float doubleJumpCap = 18.5f;
        [Tooltip("Margen para saltar despues de salir de una plataforma")] public float coyoteTime = 0.1f;
        [Tooltip("Margen para que un salto apretado antes de aterrizar se ejecute al tocar el piso")] public float jumpBufferTime = 0.12f;
        [Tooltip("Velocidad de caida maxima")] public float maxFallSpeed = 24f;
        [Tooltip("Velocidad con la que se pega al piso cuando esta apoyado")] public float groundStick = 2f;

        [Header("Deteccion de piso")]
        [Tooltip("Distancia maxima al piso para considerarse apoyado")] public float groundCheckDistance = 0.12f;
        [Tooltip("Ancho del boxcast de piso, como fraccion del ancho del collider")] [Range(0.2f, 1f)] public float footWidth = 0.7f;
        [Tooltip("Capas que cuentan como piso")] public LayerMask groundMask = ~0;

        [Header("Visual")]
        [Tooltip("Sombra que queda al ras de la superficie de apoyo")] public SpriteRenderer shadow;
        [Tooltip("Orden de dibujo base del personaje")] public int baseOrder = 10;
        [Tooltip("Altura maxima a la que se busca la superficie para la sombra")] public float shadowRange = 10f;
        [Tooltip("Multiplicador de opacidad de la sombra (0 = sin sombra: cadaver desvanecido)")] public float shadowAlpha = 1f;

        [Header("Control")]
        [Tooltip("false = el cuerpo lo conduce la red (pawn remoto)")] public bool simulate = true;

        private Rigidbody2D _rb;
        private Collider2D _col;
        private SortingGroup _group;
        private Vector3 _shadowBaseScale;
        private Color _shadowColor;
        private readonly RaycastHit2D[] _hits = new RaycastHit2D[8];

        private float _vx;
        private float _vy;
        private float _coyote;
        private float _jumpBuffer;
        private bool _jumpQueued;
        private int _airJumpsUsed;
        private bool _grounded;
        private bool _hasSupport;
        private float _supportY;
        private float _groundY;

        public bool Grounded => _grounded;
        public bool Airborne => !_grounded;
        public float VerticalSpeed => _vy;
        /// <summary>Saltos en el aire que quedan disponibles (doble salto).</summary>
        public int AirJumpsLeft => Mathf.Max(0, airJumps - _airJumpsUsed);
        /// <summary>Altura que gana un salto normal (sin doble salto).</summary>
        public float JumpHeight => jumpSpeed * jumpSpeed / (2f * gravity);
        /// <summary>Altura que gana el salto en el aire (doble salto).</summary>
        public float AirJumpHeight => doubleJumpSpeed * doubleJumpSpeed / (2f * gravity);
        /// <summary>Y mas alta alcanzable desde la posicion actual (para que la IA decida saltar).</summary>
        public float ReachableHeight => transform.position.y + JumpHeight + (_airJumpsUsed == 0 ? AirJumpHeight : 0f);
        /// <summary>Y de la superficie de apoyo (para efectos y sombra).</summary>
        public float SupportY => _supportY;

        private void Awake()
        {
            _rb = GetComponent<Rigidbody2D>();
            _col = GetComponent<Collider2D>();
            _group = GetComponentInChildren<SortingGroup>();

            if (groundMask.value == 0) groundMask = ~0;

            if (shadow != null)
            {
                _shadowBaseScale = shadow.transform.localScale;
                _shadowColor = shadow.color;
            }

            _groundY = transform.position.y;
        }

        private void OnEnable() { if (!All.Contains(this)) All.Add(this); }
        private void OnDisable() { All.Remove(this); }

        /// <summary>Pide un salto (se consume en el siguiente FixedUpdate).</summary>
        public void QueueJump() => _jumpQueued = true;

        /// <summary>Velocidad horizontal deseada. La velocidad vertical la manda este cuerpo.</summary>
        public void SetHorizontalVelocity(float vx) => _vx = vx;

        /// <summary>Impulso vertical extra (knockback, rebotes, habilidades).</summary>
        public void AddVerticalImpulse(float vy)
        {
            if (!simulate || Mathf.Abs(vy) < 0.001f) return;
            _vy = Mathf.Clamp(_vy + vy, -maxFallSpeed, doubleJumpCap * 1.2f);
            if (vy > 0.01f)
            {
                _grounded = false;
                _coyote = 0f;
            }
        }

        /// <summary>Reinicia el estado vertical (respawn/reset de ronda sin teletransportar).</summary>
        public void ResetHeight()
        {
            _vy = 0f;
            _vx = 0f;
            _coyote = 0f;
            _jumpBuffer = 0f;
            _jumpQueued = false;
            _airJumpsUsed = 0;
            _grounded = false;
            _hasSupport = false;
            _supportY = transform.position.y - 1f;
            _groundY = transform.position.y;
            if (_rb != null) _rb.linearVelocity = Vector2.zero;
        }

        private void FixedUpdate()
        {
            if (!simulate || _rb == null) return;

            float dt = Time.fixedDeltaTime;

            // ---- Piso ----
            bool probe = ProbeGround(groundCheckDistance, out var hit);
            if (_grounded && !probe)
            {
                // Se camino fuera de la plataforma: arranca el margen de coyote.
                _grounded = false;
                _coyote = coyoteTime;
            }
            else if (!_grounded && probe && _vy <= 0.1f)
            {
                _grounded = true;
                _vy = 0f;
                _coyote = 0f;
                _airJumpsUsed = 0;
                _groundY = hit.point.y;
                OnLanded?.Invoke(this, hit.point.y);
            }

            // ---- Salto / doble salto ----
            if (_jumpQueued) { _jumpBuffer = jumpBufferTime; _jumpQueued = false; }
            else if (_jumpBuffer > 0f) _jumpBuffer -= dt;

            if (_jumpBuffer > 0f)
            {
                if (_grounded || _coyote > 0f)
                {
                    _vy = jumpSpeed;
                    _grounded = false;
                    _coyote = 0f;
                    _airJumpsUsed = 0;
                    _jumpBuffer = 0f;
                    OnJumped?.Invoke(this, false);
                }
                else if (_airJumpsUsed < airJumps)
                {
                    // El doble salto se suma a la velocidad actual (si se aprieta
                    // temprano no se pierde) con un tope para no salir disparado.
                    _vy = Mathf.Min(Mathf.Max(_vy, 0f) + doubleJumpSpeed, doubleJumpCap);
                    _airJumpsUsed++;
                    _jumpBuffer = 0f;
                    OnJumped?.Invoke(this, true);
                }
            }

            if (_grounded)
            {
                _airJumpsUsed = 0;
                _vy = -groundStick;   // mantiene el contacto con el piso
            }
            else
            {
                if (_coyote > 0f) _coyote -= dt;
                _vy -= gravity * dt;
                if (_vy < -maxFallSpeed) _vy = -maxFallSpeed;
            }

            _rb.linearVelocity = new Vector2(_vx, _vy);

            if (_grounded) _groundY = hit.point.y;
            _supportY = _grounded ? _groundY : (ProbeGround(shadowRange, out var below) ? below.point.y : transform.position.y - 1f);
            _hasSupport = _grounded || _supportY < transform.position.y - 0.01f;
        }

        /// <summary>Boxcast corto desde los pies contra colliders solidos.</summary>
        private bool ProbeGround(float distance, out RaycastHit2D best)
        {
            best = default;
            if (_col == null) return false;

            // El shape arranca un poco por encima de los pies para no nacer
            // solapado con el piso (Unity ignora los colliders ya solapados).
            const float lift = 0.06f;

            Bounds b = _col.bounds;
            Vector2 origin = new Vector2(b.center.x, b.min.y + lift + 0.02f);
            Vector2 size = new Vector2(Mathf.Max(0.05f, b.size.x * footWidth), 0.04f);

            // Unity 6: los casts con buffer requieren un ContactFilter2D explicito.
            // useTriggers = true replica el ajuste global "Queries Hit Triggers"
            // que usaba el overload viejo; los triggers se descartan igual en IsGround.
            var filter = new ContactFilter2D();
            filter.SetLayerMask(groundMask);
            filter.useTriggers = true;

            int n = Physics2D.BoxCast(origin, size, 0f, Vector2.down, filter, _hits,
                distance + lift + 0.02f);

            float bestDist = float.MaxValue;
            for (int i = 0; i < n; i++)
            {
                var h = _hits[i];
                if (!IsGround(h)) continue;
                if (h.distance < bestDist) { bestDist = h.distance; best = h; }
            }
            return bestDist < float.MaxValue;
        }

        private bool IsGround(RaycastHit2D h)
        {
            var c = h.collider;
            if (c == null || c.isTrigger) return false;
            if (h.normal.y < 0.55f) return false;

            var body = c.attachedRigidbody;
            if (body == _rb) return false;                       // colliders propios
            if (body != null && body.GetComponent<HeightBody>() != null) return false;   // otros personajes
            return true;
        }

        /// <summary>Aterrizaje (segundo parametro = Y de la superficie).</summary>
        public event System.Action<HeightBody, float> OnLanded;

        /// <summary>Salto (segundo parametro = true si fue el salto en el aire).</summary>
        public event System.Action<HeightBody, bool> OnJumped;

        private void LateUpdate()
        {
            // Orden por Y: lo que esta mas abajo se dibuja detras.
            if (_group != null) _group.sortingOrder = baseOrder + PlatformSurface.OrderAt(transform.position.y);

            if (shadow == null) return;

            // Los remotos no simulan: la superficie se busca aca para que la sombra siga bien.
            if (!simulate)
            {
                _supportY = ProbeGround(shadowRange, out var below) ? below.point.y : transform.position.y - 1f;
                _hasSupport = _supportY < transform.position.y - 0.01f;
            }

            if (!_hasSupport)
            {
                shadow.enabled = false;
                return;
            }

            shadow.enabled = true;
            float air = Mathf.Max(0f, transform.position.y - _supportY);
            var lp = shadow.transform.localPosition;
            shadow.transform.localPosition = new Vector3(lp.x, _supportY - transform.position.y + 0.02f, lp.z);
            shadow.transform.localScale = _shadowBaseScale / (1f + air * 0.18f);
            var c = _shadowColor;
            c.a = _shadowColor.a / (1f + air * 0.5f) * Mathf.Clamp01(shadowAlpha);
            shadow.color = c;
            shadow.sortingOrder = PlatformSurface.OrderAt(_supportY) - 2;
        }
    }
}
