namespace WilderGambit.Core
{
    public enum TeamColor
    {
        White,
        Black
    }

    public enum PieceType
    {
        Pawn,
        Knight,
        Bishop,
        NecromancerBishop, // Variante: Alfil Nigromante (Cosecha de Almas + Alzamiento Menor)
        Rook,
        Queen,
        King,
        // Espacio para piezas evolucionadas/futuras (ej. Dragon, Assassin, ManaGolem, etc.)
        Custom
    }

    public struct Vector2IntCustom
    {
        public int Row;
        public int Col;

        public Vector2IntCustom(int row, int col)
        {
            Row = row;
            Col = col;
        }

        public override bool Equals(object obj)
        {
            if (obj is Vector2IntCustom other)
            {
                return Row == other.Row && Col == other.Col;
            }
            return false;
        }

        public override int GetHashCode()
        {
            return (Row * 397) ^ Col;
        }

        public static bool operator ==(Vector2IntCustom a, Vector2IntCustom b) => a.Row == b.Row && a.Col == b.Col;
        public static bool operator !=(Vector2IntCustom a, Vector2IntCustom b) => !(a == b);
    }
}
