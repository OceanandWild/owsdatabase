using UnityEngine;

namespace WildSea.Data
{
    /// <summary>
    /// Un modo dentro de un Universo. En v1 solo describe (winCondition legible).
    /// Fase 2 usará futureDeckId + PlayKind para IA/Local/Online.
    /// </summary>
    [CreateAssetMenu(menuName = "WildSea/GameMode", fileName = "Mode_")]
    public class GameModeDef : ScriptableObject
    {
        public string id = "estrella";
        public string universeId = "space";
        public string displayName = "Modo Estrella";
        public string iconGlyph = "⭐";
        [TextArea] public string description = "Primero en obtener 1 Estrella gana.";
        public string winConditionId = "first_to_1_star";
        public string futureDeckId = "deck_space_estrella"; // reservado Fase 2
        public int minPlayers = 2;
        public int maxPlayers = 2;
    }
}
