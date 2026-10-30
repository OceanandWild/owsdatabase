using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Peón Calabaza — variante del Peón de la velada de Halloween (tienda de Dulces).
    ///
    /// Pasiva «Explosión de Calabaza»: la primera vez que capturan un Peón Calabaza
    /// del bando, el capturador queda aturdido 2 turnos (1 uso por bando y partida;
    /// el Rey es inmune, pero consume la carga). La lógica vive en
    /// <c>GameManager.TryPumpkinExplosion</c>.
    ///
    /// Se mueve exactamente como el peón clásico (avance simple, doble y captura
    /// diagonal) y <c>Type = Pawn</c> mantiene intactos FEN, promoción, notación y
    /// evaluación de la IA.
    /// </summary>
    public class PumpkinPawn : Pawn
    {
        private void Awake()
        {
            // Unity solo invoca el Awake de la clase más derivada:
            // Pawn.Awake no se ejecuta en esta subclase.
            Type = PieceType.Pawn;
        }
    }
}
