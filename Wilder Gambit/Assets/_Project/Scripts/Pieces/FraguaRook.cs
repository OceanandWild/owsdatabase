using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Torre Fragua — variante de la Torre, exclusiva del Pase de Temporada
    /// (nivel 30 de la Vía real).
    ///
    /// PASIVA «Brasas»: cada Dama o Torre enemiga que captura otorga +1 Sentencia
    /// a su bando (máximo 3 por partida, contador compartido por bando).
    /// El contador lo gestiona GameManager.
    ///
    /// ACTIVA «Sentencia de la Fragua»: con ≥1 Sentencia y sin estar en jaque,
    /// puede condenar a una pieza enemiga (nunca al Rey) que esté adyacente o en
    /// su misma fila/columna con camino libre. La condena consume el turno.
    /// El bando condenado decide: afrontar la mecha (la pieza arde en 5 turnos de
    /// su bando si no caza todas las torres condenadoras) o entregarla en Tributo
    /// (pelea 3 turnos para el condenador y vuelve a su ejército con inmunidad
    /// permanente —Indulto—).
    ///
    /// Se mueve exactamente como la Torre clásica y Type = Rook mantiene intactos
    /// FEN, notación y evaluación de la IA. La maquinaria de la condena vive en
    /// GameManager (GetCondemnTargets / TriggerCondemn / TickFragua).
    /// </summary>
    public class FraguaRook : Rook
    {
        private void Awake()
        {
            // Unity solo invoca el Awake de la clase más derivada: hay que fijar
            // el Type aquí (Rook.Awake no se ejecuta en esta subclase).
            Type = PieceType.Rook;
        }
    }
}
