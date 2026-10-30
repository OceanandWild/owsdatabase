using UnityEngine;

namespace WilderGambit.Core
{
    public enum SkinRarity { Common, Rare, Epic, Legendary, Uncommon, Mythic }
    public enum SkinAnimation { None, Breathing, Fire, Ice, Spectral, Embers, Necrotic, Solar, Abyssal }

    /// <summary>
    /// ScriptableObject que define una skin animada para una pieza.
    /// Create vía Assets > Create > Wilder Gambit > Piece Skin Config.
    /// </summary>
    [CreateAssetMenu(fileName = "NewPieceSkin", menuName = "Wilder Gambit/Piece Skin Config", order = 2)]
    public class PieceSkinConfig : ScriptableObject
    {
        [Header("Identity")]
        public string skinId;
        public string displayName;
        [TextArea] public string description;

        [Header("Target Piece")]
        public PieceType pieceType = PieceType.Knight;
        public TeamColor teamColor = TeamColor.White;

        [Header("Visual")]
        [Tooltip("Textura de preview (opcional). Si es null, se usa el sprite de la pieza con tinte.")]
        public Texture2D thumbnailTexture;
        public Color tintColor = Color.white;
        public SkinAnimation animationId = SkinAnimation.Breathing;
        public SkinRarity rarity = SkinRarity.Common;

        [Header("Shop")]
        [Tooltip("Precio en Gambits (0 = gratis)")]
        public int priceGambits;
        [Tooltip("Desbloqueada por defecto sin compra")]
        public bool unlockedByDefault = false;

        [Tooltip("Icono emoji para mostrar en la card")]
        public string iconEmoji = "✨";
    }
}
