using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Identifies chess openings from the move sequence played in the game.
    /// Matches the first N moves against a database of known openings.
    /// </summary>
    public static class OpeningExplorer
    {
        public struct OpeningEntry
        {
            public string name;
            public string description;
            public string[] moves; // UCI format moves
        }

        /// <summary>Database of 50 common chess openings.</summary>
        public static readonly OpeningEntry[] Openings = new OpeningEntry[]
        {
            // King's Pawn Openings
            new OpeningEntry { name = "Apertura Italiana", moves = new[] { "e2e4", "e7e5", "g1f3", "b8c6", "f1c4" },
                description = "Desarrollo rápido del alfil a c4, controlando el centro y la diagonal f7." },
            new OpeningEntry { name = "Ruy López (Defensa Española)", moves = new[] { "e2e4", "e7e5", "g1f3", "b8c6", "f1b5" },
                description = "Una de las aperturas más clásicas. Presiona el caballo de c6." },
            new OpeningEntry { name = "Gambito de Rey", moves = new[] { "e2e4", "e7e5", "f2f4" },
                description = "Sacrificio de peón para ganar control del centro. Agresivo y táctico." },
            new OpeningEntry { name = "Defensa Petrov", moves = new[] { "e2e4", "e7e5", "g1f3", "g8f6" },
                description = "Defensa simétrica contra e4. Solid pero pasiva." },
            new OpeningEntry { name = "Defensa Philidor", moves = new[] { "e2e4", "e7e5", "g1f3", "d7d6" },
                description = "Defensa sólida pero pasiva. El peón en d6 bloquea el alfil." },
            new OpeningEntry { name = "Apertura Vienesa", moves = new[] { "e2e4", "e7e5", "b1c3" },
                description = "Desarrollo flexible del caballo. Prepara un gambito de peón." },
            new OpeningEntry { name = "Defensa Nórdica", moves = new[] { "e2e4", "e7e5", "f2f3", "d7d5" },
                description = "Respuesta agresiva a e4. Contraataque inmediato al centro." },
            new OpeningEntry { name = "Gambito Danés", moves = new[] { "e2e4", "e7e5", "d2d4", "e5d4", "c2c3" },
                description = "Doble sacrificio de peón para ataque rápido. Muy táctico." },
            new OpeningEntry { name = "Apertura Ponziani", moves = new[] { "e2e4", "e7e5", "g1f3", "b8c6", "c2c3" },
                description = "Prepara d4 con soporte. Posicional y flexible." },
            new OpeningEntry { name = "Gambito Escocés", moves = new[] { "e2e4", "e7e5", "g1f3", "b8c6", "d2d4" },
                description = "Apertura agresiva que abre el centro inmediatamente." },

            // Sicilian Defenses
            new OpeningEntry { name = "Defensa Siciliana", moves = new[] { "e2e4", "c7c5" },
                description = "La respuesta más popular a e4. Asimétrica y combina defensa con contraataque." },
            new OpeningEntry { name = "Siciliana Najdorf", moves = new[] { "e2e4", "c7c5", "g1f3", "d7d6", "d2d4", "c5d4", "f3d4", "g8f6", "b1c3", "a7a6" },
                description = "La variante más agresiva de la Siciliana. Favorita de Fischer y Kasparov." },
            new OpeningEntry { name = "Siciliana Dragón", moves = new[] { "e2e4", "c7c5", "g1f3", "d7d6", "d2d4", "c5d4", "f3d4", "g8f6", "b1c3", "g7g6" },
                description = "Estructura de peones agresiva con fianchetto del alfil. Ataques de ambos lados." },
            new OpeningEntry { name = "Siciliana Scheveningen", moves = new[] { "e2e4", "c7c5", "g1f3", "e7e6", "d2d4", "c5d4", "f3d4", "d7d6" },
                description = "Estructura flexible y sólida. Base para muchas variantes." },

            // Queen's Pawn Openings
            new OpeningEntry { name = "Apertura de Dama", moves = new[] { "d2d4" },
                description = "Apertura positional. Controla el centro con el peón de dama." },
            new OpeningEntry { name = "Defensa India de Rey", moves = new[] { "d2d4", "g8f6" },
                description = "Flexible. Permite fianchetto del alfil en g7." },
            new OpeningEntry { name = "Defensa Nimzo-India", moves = new[] { "d2d4", "g8f6", "c2c4", "e7e6", "b1c3", "f8b4" },
                description = "Presiona el caballo de c3. Posicional y sólida." },
            new OpeningEntry { name = "Defensa Grünfeld", moves = new[] { "d2d4", "g8f6", "c2c4", "g7g6", "b1c3", "d7d5" },
                description = "Contraataque al centro. Dinámica y moderna." },
            new OpeningEntry { name = "Defensa King's Indian", moves = new[] { "d2d4", "g8f6", "c2c4", "g7g6", "b1c3", "f8g7", "e2e4", "d7d6" },
                description = "Estructura agresiva para Negras. Ataque en el flanco de dama." },
            new OpeningEntry { name = "Defensa Eslava", moves = new[] { "d2d4", "d7d5", "c2c4", "c7c6" },
                description = "Sólida y clásica. Soporta d5 con c6." },
            new OpeningEntry { name = "Defensa Eslava Meran", moves = new[] { "d2d4", "d7d5", "c2c4", "c7c6", "g1f3", "g8f6", "b1c3", "e7e6", "e2e3", "b7b5" },
                description = "Expansión agresiva por el flanco de dama." },
            new OpeningEntry { name = "Gambito de Dama Rechazado", moves = new[] { "d2d4", "d7d5", "c2c4", "e7e6" },
                description = "Rechaza el gambito pero mantiene la tensión. Flexible." },
            new OpeningEntry { name = "Gambito de Dama Aceptado", moves = new[] { "d2d4", "d7d5", "c2c4", "d5c4" },
                description = "Negras aceptan el gambito. Blancas buscan recuperar el peón." },
            new OpeningEntry { name = "Defensa Tarrasch", moves = new[] { "d2d4", "d7d5", "c2c4", "e7e6", "b1c3", "c7c5" },
                description = "Contraataque al centro. Posiciones abiertas y dinámicas." },
            new OpeningEntry { name = "Defensa Chigorin", moves = new[] { "d2d4", "d7d5", "c2c4", "c7c6", "b1c3", "d5c4", "e2e4", "e7e5", "f1c4" },
                description = "Defensa creativa de Chigorin. Sacrifica peón por desarrollo." },

            // Flank Openings
            new OpeningEntry { name = "Apertura Inglesa", moves = new[] { "c2c4" },
                description = "Flank opening flexible. Controla d5 sin comprometer el centro." },
            new OpeningEntry { name = "Sistema Réti", moves = new[] { "g1f3", "d7d5", "c2c4" },
                description = "Fianchetto del alfil. Posicional y moderno." },
            new OpeningEntry { name = "Ataque London", moves = new[] { "d2d4", "d7d5", "c1f4" },
                description = "Sistema sólido para blancas. Fácil de aprender, difícil de refutar." },
            new OpeningEntry { name = "Sistema Colle", moves = new[] { "d2d4", "d7d5", "g1f3", "g8f6", "e2e3" },
                description = "Desarrollo calmado. Prepara e4 con soporte." },
            new OpeningEntry { name = "Ataque Torre", moves = new[] { "d2d4", "d7d5", "c1g5" },
                description = "Desarrollo agresivo del alfil. Presiona el caballo de f6." },
            new OpeningEntry { name = "Sistema Trompowsky", moves = new[] { "d2d4", "g8f6", "c1g5" },
                description = "Variante agresiva del Ataque Torre. Evita teoría de dama." },

            // Uncommon but important
            new OpeningEntry { name = "Defensa Caro-Kann", moves = new[] { "e2e4", "c7c6" },
                description = "Sólida y confiable. Prepara d5 para desafiar el centro." },
            new OpeningEntry { name = "Defensa Francesa", moves = new[] { "e2e4", "e7e6" },
                description = "Posicional y sólida. Estructura de peones cerrada." },
            new OpeningEntry { name = "Defensa Alekhine", moves = new[] { "e2e4", "g8f6" },
                description = "Atrae los peones blancos para atacarlos después." },
            new OpeningEntry { name = "Defensa Pirc", moves = new[] { "e2e4", "d7d6", "d2d4", "g8f6", "b1c3", "g7g6" },
                description = "Fianchetto del alfil. Contraataque flexible." },
            new OpeningEntry { name = "Defensa Moderna", moves = new[] { "e2e4", "g7g6" },
                description = "Similar a Pirc pero más flexible. Permite múltiples sistemas." },
            new OpeningEntry { name = "Defensa Owen", moves = new[] { "e2e4", "b7b6" },
                description = "Fianchetto temprano del alfil. Inusual pero viable." },
            new OpeningEntry { name = "Defensa Nimzowitsch", moves = new[] { "e2e4", "b8c6" },
                description = "Defensa poco común. Busca posiciones asimétricas." },
            new OpeningEntry { name = "Apertura Bird", moves = new[] { "f2f4" },
                description = "Flank opening. Controla e5 pero debilita el rey." },
            new OpeningEntry { name = "Gambito Benko", moves = new[] { "d2d4", "g8f6", "c2c4", "c7c5", "d4d5", "b7b5" },
                description = "Sacrificio de peón por presión a largo plazo en el flanco de dama." },
            new OpeningEntry { name = "Defensa Benoni", moves = new[] { "d2d4", "g8f6", "c2c4", "c7c5", "d4d5", "e7e6" },
                description = "Posiciones asimétricas y dinámicas." },
            new OpeningEntry { name = "Gambito Halloween", moves = new[] { "e2e4", "e7e5", "g1f3", "b8c6", "f3e5", "c6e5" },
                description = "Sacrificio sorpresa del caballo. Puramente táctico." },
            new OpeningEntry { name = "Defensa Scandinavian", moves = new[] { "e2e4", "d7d5" },
                description = "Ataque directo al peón e4. Simple pero objetivamente débil." },
            new OpeningEntry { name = "Ataque Fried Liver", moves = new[] { "e2e4", "e7e5", "g1f3", "b8c6", "f1c4", "g8f6", "f3g5", "d7d5", "e4d5", "f6d5", "g5f7" },
                description = "Sacrificio de caballo en f7. Ataque mortal contra la.defensa Do满a" },
        };

        /// <summary>
        /// Identifies the opening from a list of UCI move strings.
        /// Returns null if no opening matches.
        /// </summary>
        public static OpeningEntry? IdentifyOpening(List<string> uciMoves)
        {
            if (uciMoves == null || uciMoves.Count == 0) return null;

            OpeningEntry? bestMatch = null;
            int bestMatchLength = 0;

            foreach (var opening in Openings)
            {
                if (opening.moves.Length > uciMoves.Count) continue;

                bool match = true;
                for (int i = 0; i < opening.moves.Length; i++)
                {
                    if (uciMoves[i] != opening.moves[i])
                    {
                        match = false;
                        break;
                    }
                }

                if (match && opening.moves.Length > bestMatchLength)
                {
                    bestMatch = opening;
                    bestMatchLength = opening.moves.Length;
                }
            }

            return bestMatch;
        }
    }
}
