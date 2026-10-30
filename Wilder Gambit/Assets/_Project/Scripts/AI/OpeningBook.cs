using System.Collections.Generic;
using WilderGambit.Core;

namespace WilderGambit.AI
{
    public class MoveNode
    {
        public Vector2IntCustom From;
        public Vector2IntCustom To;
        public Dictionary<string, MoveNode> Responses = new Dictionary<string, MoveNode>();

        public MoveNode(int fR, int fC, int tR, int tC)
        {
            From = new Vector2IntCustom(fR, fC);
            To = new Vector2IntCustom(tR, tC);
        }

        public string GetKey(Vector2IntCustom f, Vector2IntCustom t)
        {
            return $"{f.Row},{f.Col}->{t.Row},{t.Col}";
        }
    }

    public static class OpeningBook
    {
        // Libro de respuestas para las Negras (AI) ante aperturas de las Blancas (Jugador)
        private static Dictionary<string, MoveNode> book = new Dictionary<string, MoveNode>();

        static OpeningBook()
        {
            InitBook();
        }

        private static void InitBook()
        {
            // ── 1. Respuesta a 1. e4 (1,4 -> 3,4) ──
            // Opción Defensa Siciliana: 1... c5 (6,2 -> 4,2)
            var nodeE4_Siciliana = new MoveNode(6, 2, 4, 2);
            // 2. Nf3 (0,6 -> 2,5) -> 2... d6 (6,3 -> 5,3)
            var responseNf3 = new MoveNode(6, 3, 5, 3);
            nodeE4_Siciliana.Responses["0,6->2,5"] = responseNf3;
            // 3. d4 (1,3 -> 3,3) -> 3... cxd4 (4,2 -> 3,3)
            var responseD4 = new MoveNode(4, 2, 3, 3);
            responseNf3.Responses["1,3->3,3"] = responseD4;

            book["1,4->3,4"] = nodeE4_Siciliana;

            // ── 2. Respuesta a 1. d4 (1,3 -> 3,3) ──
            // Opción Defensa India: 1... Nf6 (7,6 -> 5,5)
            var nodeD4_Nimzo = new MoveNode(7, 6, 5, 5);
            // 2. c4 (1,2 -> 3,2) -> 2... e6 (6,4 -> 5,4)
            var responseC4 = new MoveNode(6, 4, 5, 4);
            nodeD4_Nimzo.Responses["1,2->3,2"] = responseC4;

            book["1,3->3,3"] = nodeD4_Nimzo;

            // ── 3. Respuesta a 1. c4 (1,2 -> 3,2) ──
            // 1... e5 (6,4 -> 4,4)
            book["1,2->3,2"] = new MoveNode(6, 4, 4, 4);

            // ── 4. Respuesta a 1. Nf3 (0,6 -> 2,5) ──
            // 1... d5 (6,3 -> 4,3)
            book["0,6->2,5"] = new MoveNode(6, 3, 4, 3);

            // ── 5. Respuesta a 1. Nc3 (0,1 -> 2,2) ──
            // 1... d5 (6,3 -> 4,3)
            book["0,1->2,2"] = new MoveNode(6, 3, 4, 3);
        }

        public static bool TryGetBookMove(List<string> moveHistory, out Vector2IntCustom from, out Vector2IntCustom to)
        {
            from = new Vector2IntCustom(-1, -1);
            to = new Vector2IntCustom(-1, -1);

            if (moveHistory == null || moveHistory.Count == 0) return false;

            // Navegar el árbol
            if (!book.TryGetValue(moveHistory[0], out MoveNode currentNode)) return false;

            for (int i = 1; i < moveHistory.Count; i++)
            {
                if (i % 2 == 0) // Turno de Blancas registrado
                {
                    if (!currentNode.Responses.TryGetValue(moveHistory[i], out currentNode))
                    {
                        return false; // El jugador se desvió del libro
                    }
                }
            }

            if (currentNode != null)
            {
                from = currentNode.From;
                to = currentNode.To;
                return true;
            }

            return false;
        }
    }
}
