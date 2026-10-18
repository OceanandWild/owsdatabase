using UnityEngine;

namespace WildWeapon.UI
{
    /// <summary>
    /// Pieles del overlay de emparejamiento PVP ("PVP ONLINE"). Todas las piezas
    /// llegan en gris neutro y se tintean por codigo (acero frio + acento violeta
    /// del modo). Lo completa <c>WildWeaponBuilder</c> dentro de MainMenu; si una
    /// pieza falta, el overlay cae al look plano de siempre.
    /// </summary>
    public class PvpOverlaySkin : MonoBehaviour
    {
        /// <summary>Placa principal del modal (900x380).</summary>
        public Sprite panel;
        /// <summary>Fondo del boton de cancelar (320x64).</summary>
        public Sprite button;
        /// <summary>Regla divisoria bajo el titulo (340x16).</summary>
        public Sprite rule;
        /// <summary>Radar de busqueda de rival (fantasma giratorio).</summary>
        public Sprite radar;
        /// <summary>Veta de luz para el barrido de brillo sobre la placa.</summary>
        public Sprite shine;
    }
}
