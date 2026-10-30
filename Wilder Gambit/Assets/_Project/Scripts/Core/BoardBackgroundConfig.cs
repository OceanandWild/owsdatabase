using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// ScriptableObject that defines a single board background theme.
    /// Create instances via Assets > Create > Wilder Gambit > Board Background Config.
    /// </summary>
    [CreateAssetMenu(fileName = "NewBoardBackground", menuName = "Wilder Gambit/Board Background Config", order = 1)]
    public class BoardBackgroundConfig : ScriptableObject
    {
        [Header("Identity")]
        public string themeId;
        public string displayName;

        [Header("File")]
        [Tooltip("Filename of the texture on disk (without extension). Used as fallback when backgroundTexture is null.")]
        public string filename;

        [Header("Background")]
        [Tooltip("The background texture (JPEG/PNG). Will be loaded at runtime.")]
        public Texture2D backgroundTexture;

        [Tooltip("Preview thumbnail for the shop UI (smaller resolution).")]
        public Texture2D thumbnailTexture;

        [Header("Tile Colors")]
        [Tooltip("Color for the light squares (even parity)")]
        public Color lightTileColor = new Color(0.93f, 0.93f, 0.82f);

        [Tooltip("Color for the dark squares (odd parity)")]
        public Color darkTileColor = new Color(0.46f, 0.59f, 0.33f);

        [Header("Shop")]
        [Tooltip("Price in Gambits (0 = free/default)")]
        public int priceGambits;

        [Tooltip("Is this background unlocked by default?")]
        public bool unlockedByDefault = true;
    }
}
