using UnityEngine;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Un combatiente del tablero PVP (el local o un remoto/bot). Reune lo que el
    /// HUD necesita para dibujar su icono de perfil: nombre, color, equipo y el
    /// pawn del que sale la cabeza y la vida.
    /// </summary>
    public class PvpCombatant
    {
        public int seat;
        public string name;
        public int colorIndex;
        public int team;
        public bool bot;
        public bool isLocal;
        public PlayerHealth health;
        public CharacterVisual visual;

        public Color Accent => GameSession.Palette[
            Mathf.Clamp(colorIndex, 0, GameSession.Palette.Length - 1)];
    }
}
