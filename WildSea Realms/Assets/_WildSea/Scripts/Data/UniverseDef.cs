using UnityEngine;

namespace WildSea.Data
{
    /// <summary>
    /// Un Universo jugable. El Hub se genera solo leyendo estos assets.
    /// Añadir un Universo en el futuro = crear 1 asset, cero código UI.
    /// </summary>
    [CreateAssetMenu(menuName = "WildSea/Universe", fileName = "Universe_")]
    public class UniverseDef : ScriptableObject
    {
        public string id = "space";
        public string displayName = "Espacio";
        public string tagline = "Cuna de estrellas.";
        [TextArea] public string lore = "Donde nacen las Estrellas y se tejen las Galaxias.";
        public string iconGlyph = "🚀";
        public Color topColor = new Color(0.04f, 0.12f, 0.23f);
        public Color bottomColor = new Color(0.23f, 0.04f, 0.35f);
        public Color accentColor = new Color(1f, 0.84f, 0.35f);
        public bool unlockedInV1 = true;
        public bool isTeased = false; // ??? Próximamente
        public GameModeDef[] modes;
    }
}
