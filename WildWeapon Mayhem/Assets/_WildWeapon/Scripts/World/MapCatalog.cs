using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// Catalogo de arenas: lo arma el builder con los 12 mapas (4 chicos, 4 medianos,
    /// 4 grandes). Lo usan la escena Arena (para resolver el mapa de la partida) y el
    /// selector de mapa (para mostrar las tarjetas).
    /// </summary>
    [CreateAssetMenu(fileName = "MapCatalog", menuName = "WildWeapon/Map Catalog")]
    public class MapCatalog : ScriptableObject
    {
        public MapDef[] maps;

        public int Count => maps != null ? maps.Length : 0;

        public MapDef Get(int index)
        {
            if (maps == null || maps.Length == 0) return null;
            return maps[Mathf.Clamp(index, 0, maps.Length - 1)];
        }

        /// <summary>Indice del primer mapa de la clase pedida (para el default por modo).</summary>
        public int FirstOf(MapSizeClass size)
        {
            if (maps == null) return 0;
            for (int i = 0; i < maps.Length; i++)
                if (maps[i] != null && maps[i].sizeClass == size) return i;
            return 0;
        }
    }
}
