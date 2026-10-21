using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Camara de la arena: sigue al jugador local y hace zoom (encuadre cerrado)
    /// en vez de quedarse fija mostrando la arena entera.
    ///
    /// - Sigue al jugador local con suavizado (y una antecipacion hacia donde apunta).
    /// - El zoom se calcula como una fraccion de la arena, asi el duelo se ve igual
    ///   en todos los mapas (chico o grande).
    /// - Se clampa dentro del area generada por el mapa: la vista nunca sale del
    ///   fondo (no se ve el vacio).
    /// - Aplica el temblor de <see cref="GameFeel"/> (la camara se reposiciona
    ///   cada frame, asi que el temblor va por aqui y no por GameFeel).
    /// </summary>
    [DefaultExecutionOrder(-50)]
    [RequireComponent(typeof(Camera))]
    public class PlayerCamera : MonoBehaviour
    {
        [Header("Objetivo")]
        [Tooltip("Jugador que se sigue. Si esta vacio se busca solo (el local del bootstrap).")]
        public Transform target;
        public PlayerController targetController;

        [Header("Encuadre")]
        [Tooltip("Fraccion de la altura de la arena que queda visible (0.6 = 60%).")]
        [Range(0.25f, 1f)] public float zoomFraction = 0.6f;
        [Tooltip("Zoom (tamano ortografico) minimo y maximo en unidades de mundo.")]
        public float minZoom = 4.5f;
        public float maxZoom = 7.6f;
        [Tooltip("Suavizado del seguimiento (mayor = mas pegado al jugador).")]
        public float followSmoothing = 7f;
        [Tooltip("Suavizado del zoom (mayor = mas rapido).")]
        public float zoomSmoothing = 2.5f;
        [Tooltip("Anticipacion hacia donde se apunta (0 = sin anticipacion).")]
        public float lookAhead = 0.9f;

        [Header("Limites")]
        [Tooltip("Mitad del area que se puede ver (lo define el mapa generado).")]
        public Vector2 boundsHalf = new Vector2(24f, 14f);
        [Tooltip("Mitad del tamano de la arena (lo define el mapa generado).")]
        public Vector2 arenaHalf = new Vector2(16f, 9f);

        private Camera _cam;
        private Vector3 _pos;
        private float _zoom;
        private bool _snap = true;

        void Awake()
        {
            _cam = GetComponent<Camera>();
            _zoom = _cam != null ? _cam.orthographicSize : 6f;
            _pos = transform.position;
        }

        /// <summary>El mapa generado avisa el area visible (fondo) y el tamano de la arena.</summary>
        public void SetBounds(Vector2 visibleHalf, Vector2 arena)
        {
            boundsHalf = visibleHalf;
            arenaHalf = arena;
        }

        void LateUpdate()
        {
            if (_cam == null) return;

            var pc = ResolvePlayer();

            Vector3 desired;
            if (pc != null)
            {
                desired = pc.transform.position;
                if (lookAhead > 0f) desired += (Vector3)(pc.AimDir * lookAhead);
            }
            else
            {
                desired = new Vector3(0f, 0f, transform.position.z);
            }

            // Zoom: una fraccion de la arena (asi todos los mapas se encuadran igual).
            float targetZoom = Mathf.Clamp(arenaHalf.y * zoomFraction, minZoom, maxZoom);
            _zoom = Mathf.Lerp(_zoom, targetZoom, 1f - Mathf.Exp(-zoomSmoothing * Time.unscaledDeltaTime));
            _cam.orthographicSize = _zoom;

            // Limites: la vista no puede salirse del fondo generado.
            float halfH = _zoom;
            float halfW = _zoom * _cam.aspect;
            float maxX = Mathf.Max(0f, boundsHalf.x - halfW);
            float maxY = Mathf.Max(0f, boundsHalf.y - halfH);
            desired.x = Mathf.Clamp(desired.x, -maxX, maxX);
            desired.y = Mathf.Clamp(desired.y, -maxY, maxY);
            desired.z = transform.position.z;

            if (_snap)
            {
                _pos = desired;      // primer frame: sin barrido desde el centro
                _snap = false;
            }
            else
            {
                float k = 1f - Mathf.Exp(-followSmoothing * Time.unscaledDeltaTime);
                _pos = Vector3.Lerp(_pos, desired, k);
            }

            // Temblor de camara (lo mantiene GameFeel).
            Vector3 shake = Vector3.zero;
            float amount = GameFeel.ShakeAmount;
            if (amount > 0.001f)
            {
                Vector2 r = UnityEngine.Random.insideUnitCircle * amount;
                shake = new Vector3(r.x, r.y, 0f);
            }

            transform.position = _pos + shake;
        }

        /// <summary>Jugador local al que seguir (el del bootstrap o el primero activo).</summary>
        private PlayerController ResolvePlayer()
        {
            if (targetController != null && targetController.isActiveAndEnabled) return targetController;

            if (target != null && target.gameObject.activeInHierarchy)
            {
                var pc = target.GetComponent<PlayerController>();
                if (pc != null) return pc;
                return null;
            }

            var boot = GameBootstrap.Instance;
            if (boot != null)
            {
                if (boot.p1 != null && boot.p1.isActiveAndEnabled) return boot.p1;
                var list = boot.MultiPlayers;
                for (int i = 0; i < list.Count; i++)
                    if (list[i] != null && list[i].isActiveAndEnabled) return list[i];
            }

            var all = FindObjectsByType<PlayerController>(FindObjectsInactive.Exclude);
            for (int i = 0; i < all.Length; i++)
                if (all[i] != null && !all[i].inputSuppressed) return all[i];
            return all.Length > 0 ? all[0] : null;
        }
    }
}
