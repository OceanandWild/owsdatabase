using WilderGambit.Core;

namespace WilderGambit.Pieces
{
    /// <summary>
    /// Reina Vampira — variante de la Dama (pasiva «No Muerta»).
    /// Se mueve exactamente como una Dama y conserva Type = PieceType.Queen para
    /// que FEN, notación, promoción y la IA sigan viendo una Dama normal.
    ///
    /// La primera vez que la capturan renace en una casilla libre de su primera
    /// fila que no dé jaque al bando capturador (ver TryRespawnVampire en
    /// GameManager). El estado viaja en el Undo como vampireData: casilla + si
    /// ya renació.
    /// </summary>
    public class VampireQueen : Queen
    {
        /// <summary>¿Le queda la No Muerta en esta partida?</summary>
        public bool CanRise { get; set; } = true;

        /// <summary>¿Ya renació una vez?</summary>
        public bool HasRisen { get; set; }

        private void Awake()
        {
            Type = PieceType.Queen;
        }

        /// <summary>Consume la No Muerta: la próxima captura será definitiva.</summary>
        public void MarkRisen()
        {
            HasRisen = true;
            CanRise = false;
        }

        /// <summary>Restaura el estado desde el Undo (risen = 0/1).</summary>
        public void RestoreState(bool risen)
        {
            HasRisen = risen;
            CanRise = !risen;
        }
    }
}
