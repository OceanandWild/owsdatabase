using System;
using UnityEngine;

namespace WildWeapon
{
    /// <summary>Tamano de arena: chica (duelos rapidos), mediana (estandar) y grande (supervivencia).</summary>
    public enum MapSizeClass { Chico, Mediano, Grande }

    /// <summary>Tamano descriptivo del deck (nombre y orden; el sprite es el propio del mapa).</summary>
    public enum MapPlatformSize { Chica, Mediana, Grande }

    /// <summary>Familia de peligro de arena. La logica vive en <see cref="ArenaHazard"/>.</summary>
    public enum HazardKind
    {
        /// <summary>Golpe vertical (prensa, columna, escombro): telegrafia con sombra y derrumba.</summary>
        Slam,
        /// <summary>Zona persistente (esporas, niebla, acido): dana por pulso a quien este adentro.</summary>
        Zone,
        /// <summary>Onda expansiva desde el centro (eco, plasma): golpea al pasar por encima.</summary>
        Pulse,
        /// <summary>Descarga electrica entre extremos (cables, cartel): franja que chispea.</summary>
        Arc,
        /// <summary>Ventisca/chorro que barre la arena: empuja y frena.</summary>
        Wind,
        /// <summary>Lluvia de MayhemCoins: golpes chicos y muchos, con chispas doradas.</summary>
        Coins,
        /// <summary>Charco de aceite que se enciende por ciclos: fuego con dano y empuje.</summary>
        Ignite,
        /// <summary>Frio de camara: dana poco y congela (frena mucho) mientras dura.</summary>
        Cold,
    }

    [Serializable]
    public class MapProp
    {
        public string name = "Prop";
        public Sprite sprite;
        [Tooltip("Ancho en unidades")] public float size = 1f;
        public bool solid = true;
        [Tooltip("Radio del collider como fraccion del ancho")] public float colliderRadius = 0.4f;
        [Min(0f)] public float weight = 1f;
        public Vector2 sizeJitter = new Vector2(0.9f, 1.1f);
        [Tooltip("Tinte del tema (multiplica el sprite)")] public Color tint = Color.white;
        [Tooltip("Si es > 0 el prop tiene techo: se puede saltar encima y deja de bloquear a esa altura")]
        public float height = 0f;
    }

    /// <summary>
    /// Tramo elevado de la arena. Se comporta como plataforma one-way en vista
    /// lateral: se atraviesa saltando desde abajo, se aterriza arriba y los
    /// costados no bloquean.
    /// </summary>
    [Serializable]
    public class MapPlatform
    {
        public string name = "Plataforma";
        public MapPlatformSize sizeClass = MapPlatformSize.Mediana;
        [Tooltip("Centro del deck, en coordenadas de arena (0,0 = centro)")] public Vector2 center = Vector2.zero;
        [Tooltip("Huella del deck (ancho x alto en unidades)")] public Vector2 size = new Vector2(4.6f, 2.6f);
        [Tooltip("Altura heredada del modelo 2.5D; el gameplay usa la Y del centro")] [Min(0.25f)] public float height = 0.95f;
        [Tooltip("Genera tambien la copia espejada (180 grados), para el duelo 1v1")] public bool mirrored = true;
        [Tooltip("Grados de rotacion del sprite (solo visual)")] public float rotation = 0f;
    }

    /// <summary>Peligro de arena: ciclo idle -> telegrafia -> golpe -> recuperacion.</summary>
    [Serializable]
    public class MapHazard
    {
        public string name = "Peligro";
        public HazardKind kind = HazardKind.Slam;
        [Tooltip("Centro del peligro en coordenadas de arena")] public Vector2 center = Vector2.zero;
        [Tooltip("Area afectada (ancho x alto)")] public Vector2 size = new Vector2(3.2f, 3.2f);
        public float damage = 14f;
        [Tooltip("Duracion total del ciclo (segundos)")] [Min(0.5f)] public float interval = 4.5f;
        [Tooltip("Aviso previo al golpe")] [Min(0f)] public float telegraph = 1f;
        [Tooltip("Ventana en la que el peligro golpea")] [Min(0.05f)] public float active = 0.45f;
        public float knockback = 3f;
        [Tooltip("Frenado aplicado mientras el peligro esta activo (0..0.8)")] [Range(0f, 0.8f)] public float slow = 0f;
        [Tooltip("Altura por encima del centro del peligro a la que ya no afecta: subirse a una plataforma te salva")] public float maxHeight = 0.5f;
        public Color color = new Color(1f, 0.35f, 0.3f);
        [Tooltip("Genera tambien la copia espejada (180 grados)")] public bool mirrored = false;
        [Tooltip("Desfasaje del ciclo (para que no golpeen todos a la vez)")] public float phase = 0f;
    }

    /// <summary>
    /// Asset de mapa: describe el entorno y MapGenerator lo construye
    /// (piso, muros, plataformas, obstaculos, decoracion, peligros y spawns) a partir de una semilla.
    /// </summary>
    [CreateAssetMenu(fileName = "MapDef", menuName = "WildWeapon/Map Def")]
    public class MapDef : ScriptableObject
    {
        [Header("Identidad")]
        [Tooltip("Id estable (nombre del asset y del selector)")] public string mapId = "chatarra";
        public string displayName = "Arena Central";
        [Tooltip("Bajada del selector de mapa")] public string subtitle = "DUELO EN LA CHATARRA";
        public MapSizeClass sizeClass = MapSizeClass.Mediano;
        public Color accent = new Color(0.26f, 0.88f, 1f);
        [Tooltip("Vista previa del selector de mapa (si falta, usa el fondo de arena)")] public Sprite previewSprite;
        [Tooltip("Decoracion exclusiva del mapa (documentacion viva)")] [TextArea] public string decorNote = "";

        [Header("Arena")]
        public Vector2 arenaSize = new Vector2(20f, 11f);
        public Color backgroundColor = new Color(0.06f, 0.05f, 0.07f);
        [Tooltip("Altura del piso jugable sobre el borde inferior de la arena (en unidades)")]
        [Min(0.2f)] public float groundOffsetY = 1.1f;

        [Header("Fondo (entorno del lugar)")]
        [Tooltip("Entorno del mapa: un solo sprite estirado a todo el encuadre de camara (el area de juego es el centro limpio)")] public Sprite floorSprite;
        [Tooltip("Si es true el fondo se estira entero al encuadre (arte unico por mapa)")] public bool floorSingle = true;
        public float floorTileSize = 4f;
        public Color floorTint = Color.white;
        [Tooltip("Fraccion del encuadre que ocupa la arena; el resto es entorno (alinea el borde de la arena con el borde visible del lugar)")]
        [Range(0.45f, 0.95f)] public float backdropArenaFraction = 0.66f;

        [Header("Muros (solo collider: el entorno del fondo los reemplaza)")]
        public Sprite wallSprite;
        public float wallThickness = 0.8f;
        public float wallTileSize = 1.6f;
        public Color wallTint = Color.white;

        [Header("Plataformas (separadas del fondo)")]
        [Tooltip("Sprite propio del mapa: todos los decks de la arena usan este arte (9-slice)")] public Sprite platformSprite;
        [Tooltip("Mancha suave para la sombra de las plataformas")] public Sprite platformShadow;
        public float platformTint = 1f;
        public MapPlatform[] platforms;

        [Header("Obstaculos (con collider)")]
        public MapProp[] obstacles;
        public int obstacleCount = 10;
        public float minObstacleSpacing = 1.8f;

        [Header("Decoracion (sin collider)")]
        public MapProp[] decor;
        public int decorCount = 28;

        [Header("Peligros")]
        public MapHazard[] hazards;

        [Header("Generacion")]
        public int seed = 1234;
        public bool randomSeedEachMatch = true;
        [Tooltip("Simetria puntual: justo para el duelo 1v1")]
        public bool mirroredForDuel = true;
        public float spawnClearRadius = 2.4f;

        [Header("Spawns")]
        public Vector2 p1Spawn = new Vector2(-6f, 0f);
        public Vector2 p2Spawn = new Vector2(6f, 0f);
        public int botSpawnPoints = 14;
    }
}
