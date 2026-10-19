using System.Collections.Generic;
using UnityEngine;
using UnityEngine.Rendering;

namespace WildWeapon
{
    /// <summary>
    /// Altura (Z) simulada de un personaje en un mapa top-down. Modelo 2.5D:
    ///
    /// - Z vive aparte de la fisica 2D (los colliders siguen siendo de piso).
    /// - Salta con gravedad propia y aterriza en el deck mas alto que tenga debajo
    ///   (<see cref="PlatformSurface"/>); el piso de la arena es Z = 0.
    /// - Por debajo de un deck no hay colision: se camina por debajo sin trabas.
    /// - Desde arriba no se puede bajar a traves de un deck (hay que ir al borde).
    /// - Lo visual se desplaza <see cref="visualLift"/> por unidad de Z (paralaje de altura)
    ///   y la sombra queda al ras de la superficie de apoyo.
    /// - El orden de dibujo crece con Z: lo que esta mas alto tapa lo que esta mas abajo.
    /// </summary>
    [DisallowMultipleComponent]
    public class HeightBody : MonoBehaviour
    {
        /// <summary>Personajes con altura vivos (los usan peligros y reglas de golpe).</summary>
        public static readonly List<HeightBody> All = new List<HeightBody>();

        /// <summary>Paralaje vertical por unidad de Z. Lo comparten personajes y decks.</summary>
        public const float LiftPerZ = 0.55f;

        [Header("Salto")]
        public float gravity = 26f;        [Tooltip("Velocidad inicial del salto. Con gravity 26 llega a ~1.6 de altura")] public float jumpSpeed = 9.2f;
        [Tooltip("Margen para saltar despues de salir de una plataforma")] public float coyoteTime = 0.09f;
        [Tooltip("Radio usado para 'estar sobre' una plataforma")] public float pad = 0.3f;

        [Header("Visual")]
        [Tooltip("Desplazamiento vertical por unidad de Z")] public float visualLift = LiftPerZ;
        [Tooltip("Capas que suben con la altura (Visual, AimPivot)")] public Transform[] followers;
        public SpriteRenderer shadow;
        [Tooltip("Orden de dibujo base del personaje")] public int baseOrder = 10;

        [Header("Control")]
        [Tooltip("false = la altura la maneja la red (pawn remoto)")] public bool simulate = true;

        private float _z, _vz, _coyote;
        private bool _jumpQueued;
        private Vector3[] _followerBase;
        private SortingGroup _group;
        private Vector3 _shadowBaseScale;
        private Color _shadowColor;
        private bool _ready;
        private Collider2D _col;
        private Rigidbody2D _rb;
        private readonly HashSet<Collider2D> _ignored = new HashSet<Collider2D>();

        public float Z => _z;
        public float VelocityZ => _vz;
        public bool Grounded { get; private set; } = true;
        /// <summary>Altura de la superficie sobre la que esta parado (0 = piso).</summary>
        public float Support { get; private set; }
        /// <summary>true mientras esta en el aire.</summary>
        public bool Airborne => !Grounded;
        /// <summary>Maximo de altura alcanzable desde el piso actual (para que la IA decida saltar).</summary>
        public float ReachableHeight => _z + jumpSpeed * jumpSpeed / (2f * gravity);

        private void Awake()
        {
            _col = GetComponent<Collider2D>();
            _rb = GetComponent<Rigidbody2D>();
            _followerBase = new Vector3[followers != null ? followers.Length : 0];
            for (int i = 0; i < _followerBase.Length; i++)
                if (followers[i] != null) _followerBase[i] = followers[i].localPosition;

            if (shadow != null)
            {
                _shadowBaseScale = shadow.transform.localScale;
                _shadowColor = shadow.color;
            }

            _group = GetComponentInChildren<SortingGroup>();
            _ready = true;
            ApplyVisual();
        }

        private void OnEnable() { if (!All.Contains(this)) All.Add(this); }
        private void OnDisable() { All.Remove(this); }

        /// <summary>Pide un salto (se consume en el siguiente FixedUpdate).</summary>
        public void QueueJump() => _jumpQueued = true;

        /// <summary>Teletransporte/red: fija la altura sin simular.</summary>
        public void SetHeight(float z, float vz = 0f)
        {
            _z = Mathf.Max(0f, z);
            _vz = vz;
            Support = PlatformSurface.HighestTopBelow(transform.position, _z, pad);
            Grounded = _z <= Support + 0.02f;
            ApplyVisual();
        }

        public void ResetHeight()
        {
            _z = 0f; _vz = 0f; _coyote = 0f; _jumpQueued = false;
            Support = 0f; Grounded = true;
            ApplyVisual();
        }

        private void FixedUpdate()
        {
            if (!simulate) return;

            float dt = Time.fixedDeltaTime;
            Vector2 p = transform.position;

            bool groundedNow = Grounded;
            float support = PlatformSurface.HighestTopBelow(p, _z + 0.02f, pad);

            if (groundedNow)
            {
                if (Mathf.Abs(support - _z) <= 0.06f) { _z = support; _vz = 0f; }
                else { Grounded = false; _coyote = coyoteTime; }   // se camino fuera del deck
            }

            if (_jumpQueued && (Grounded || _coyote > 0f))
            {
                _vz = jumpSpeed;
                Grounded = false;
                _coyote = 0f;
            }
            _jumpQueued = false;

            if (!Grounded)
            {
                if (_coyote > 0f) _coyote -= dt;
                _vz -= gravity * dt;
                _z += _vz * dt;

                if (_vz <= 0f)
                {
                    float land = PlatformSurface.HighestTopBelow(p, _z, pad);
                    if (_z <= land)
                    {
                        bool wasAir = _z < land - 0.001f;
                        _z = land;
                        _vz = 0f;
                        Grounded = true;
                        if (wasAir) OnLanded?.Invoke(this, land);
                    }
                }
                if (PlatformSurface.GroundOnlyBottom && _z <= -1.5f)
{
    // Caida a hueco: respawn al suelo inferior.
    _z = 0f; _vz = 0f; Grounded = true;
    var pos = transform.position;
    pos.y = -PlatformSurface.ArenaHalfY + 1f;
    transform.position = pos;
    if (_rb != null) _rb.position = pos;
}
else if (_z <= 0f && (!PlatformSurface.GroundOnlyBottom || transform.position.y <= -PlatformSurface.ArenaHalfY + 2.5f))
{
    _z = 0f; _vz = 0f; Grounded = true;
}
            }

            Support = Grounded ? _z : PlatformSurface.HighestTopBelow(p, _z, pad);
            SyncSolids();
        }

        /// <summary>Obstaculos saltables: dejan de bloquear cuando el cuerpo esta por encima de su techo.</summary>
        private void SyncSolids()
        {
            if (_col == null) return;
            var all = PlatformSurface.All;
            for (int i = 0; i < all.Count; i++)
            {
                var s = all[i];
                if (s == null || s.solid == null) continue;
                bool ignore = _z >= s.top - 0.06f;
                bool was = _ignored.Contains(s.solid);
                if (ignore == was) continue;
                Physics2D.IgnoreCollision(_col, s.solid, ignore);
                if (ignore) _ignored.Add(s.solid);
                else _ignored.Remove(s.solid);
            }
        }

        /// <summary>Aterrizaje (segundo parametro = altura de la superficie).</summary>
        public event System.Action<HeightBody, float> OnLanded;

        private void LateUpdate() { if (_ready) ApplyVisual(); }

        private void ApplyVisual()
        {
            float lift = _z * visualLift;

            for (int i = 0; i < _followerBase.Length; i++)
            {
                var f = followers[i];
                if (f == null) continue;
                var b = _followerBase[i];
                f.localPosition = new Vector3(b.x, b.y + lift, b.z);
            }

            // Lo mas alto tapa a lo mas bajo.
            if (_group != null) _group.sortingOrder = baseOrder + Mathf.RoundToInt(_z * 50f);

            if (shadow != null)
            {
                float support = Grounded ? _z : PlatformSurface.HighestTopBelow(transform.position, _z, pad);
                if (support > _z) support = _z;
                float air = Mathf.Max(0f, _z - support);
                shadow.transform.localPosition = new Vector3(
                    shadow.transform.localPosition.x,
                    shadow.transform.localPosition.y,
                    0f);
                shadow.transform.localScale = _shadowBaseScale / (1f + air * 0.55f);
                var c = _shadowColor;
                c.a = _shadowColor.a / (1f + air * 1.1f);
                shadow.color = c;
                shadow.sortingOrder = baseOrder - 2 + Mathf.RoundToInt(support * 50f);
            }
        }
    }
}
