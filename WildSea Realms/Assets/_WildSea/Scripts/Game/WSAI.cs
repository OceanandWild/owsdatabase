using System.Linq;

namespace WildSea.Game
{
    /// <summary>
    /// Rival automatico del modo clasico. Juega un turno completo y lo termina.
    ///
    /// Politica, en orden de prioridad:
    ///   1. CANJEAR las Galaxias que ya no hagan falta para el objetivo.
    ///   2. JUGAR todo lo que sirva al objetivo: es gratis y suma progreso.
    ///   3. FUSIONAR lo que acerque al objetivo. Elige el peldan cuyo siguiente
    ///      escalon sirve al objetivo; si ninguno sirve, fusiona el mas bajo que
    ///      tenga trio, que es el que mas veces se repite.
    ///   4. ATACAR una carta que el rival ya jugo, priorizando las que sirven al
    ///      objetivo. Gasta la carta menos util de la mano.
    ///   5. TERMINAR el turno.
    ///
    /// Es un rival sencillo: no planifica a varios turnos y realiza como máximo un
    /// ataque por ronda, priorizando interrumpir el objetivo sin sacrificarlo.
    /// </summary>
    public static class WSAI
    {
        /// <summary>Juega el turno entero del jugador y lo cierra con EndTurn.</summary>
        public static void PlayTurn(MatchState s, int playerIndex)
        {
            if (s == null || s.winner.HasValue || s.pendingAttack != null) return;
            if (playerIndex != s.activePlayer) return;

            var p = s.players[playerIndex];
            s.Log($"{MatchController.Name(playerIndex)} está pensando…");

            // ── 1 a 3: canjear, jugar lo que sirve y fusionar ────────────────
            bool moved = true;
            while (moved && !s.winner.HasValue)
            {
                moved = false;

                int galaxyIndex = p.hand.FindIndex(c => c.category == BodyCategory.Galaxy
                    && !MatchController.IsNeededForObjective(s, p, c));
                var galaxyReward = galaxyIndex >= 0 ? BestGalaxyReward(s, p, galaxyIndex) : (BodyCategory?)null;
                if (galaxyReward.HasValue
                    && MatchController.ExchangeGalaxy(s, playerIndex, galaxyIndex, galaxyReward.Value))
                {
                    moved = true;
                    continue;
                }

                for (int i = p.hand.Count - 1; i >= 0; i--)
                {
                    if (!MatchController.IsNeededForObjective(s, p, p.hand[i])) continue;
                    if (MatchController.Play(s, playerIndex, i)) { moved = true; break; }
                }
                if (s.winner.HasValue) break;

                var tier = BestFusionTier(s, p);
                if (tier.HasValue && MatchController.Fuse(s, playerIndex, tier.Value))
                    moved = true;
            }

            if (s.winner.HasValue) return;

            // ── 4: atacar si tiene sentido ──
            MaybeAttack(s, playerIndex);
            if (s.pendingAttack != null) return; // espera la decisión de la persona atacada

            // ── 5: cerrar ──
            MatchController.EndTurn(s);
        }

        /// <summary>
        /// Que peldan conviene fusionar ahora. Prioriza el que produce una carta
        /// que sirve al objetivo; si no hay ninguno, el mas bajo, que es el que se
        /// puede repetir mas veces.
        /// </summary>
        static BodyCategory? BestFusionTier(MatchState s, PlayerState p)
        {
            BodyCategory? fallback = null;

            foreach (var g in p.hand.GroupBy(c => c.category))
            {
                if (g.Count() < MatchController.FusionCost) continue;
                var next = CardDef.NextTier(g.Key);
                if (next == g.Key) continue;                          // Galaxia no sube
                if (!p.collection.Any(c => c.category == next)) continue;  // no tiene a donde subir

                // El siguiente escalon sirve al objetivo: esta es la fusion buena.
                if (s.objective.rules.Any(r => r.category == next))
                    return g.Key;

                if (!fallback.HasValue || g.Key < fallback.Value)
                    fallback = g.Key;
            }
            return fallback;
        }

        /// <summary>
        /// La IA aprovecha una Galaxia no necesaria para el objetivo. Prioriza la
        /// categoria que le falta; fuera del objetivo prefiere tres Planetas si caben.
        /// </summary>
        static BodyCategory? BestGalaxyReward(MatchState s, PlayerState p, int handIndex)
        {
            bool canStar = MatchController.CanExchangeGalaxy(s, p.index, handIndex, BodyCategory.Star);
            bool canPlanets = MatchController.CanExchangeGalaxy(s, p.index, handIndex, BodyCategory.Planet);
            bool needsStar = s.objective.rules.Any(r => r.category == BodyCategory.Star
                && p.board.Count(r.Matches) < r.count && p.collection.Any(r.Matches));
            bool needsPlanets = s.objective.rules.Any(r => r.category == BodyCategory.Planet
                && p.board.Count(r.Matches) < r.count && p.collection.Any(r.Matches));

            if (needsStar && canStar) return BodyCategory.Star;
            if (needsPlanets && canPlanets) return BodyCategory.Planet;
            if (canPlanets) return BodyCategory.Planet;
            if (canStar) return BodyCategory.Star;
            return null;
        }

        /// <summary>
        /// Ataca una carta ya jugada del rival cada turno en que tenga mano para
        /// hacerlo. Prefiere una carta que sirve al objetivo; si no hay ninguna,
        /// puede atacar cualquier otra carta que ya esté sobre la mesa.
        /// </summary>
        static void MaybeAttack(MatchState s, int playerIndex)
        {
            var p = s.players[playerIndex];
            var vic = s.players[1 - playerIndex];
            if (p.hand.Count == 0 || vic.board.Count == 0) return;

            // Cualquier carta del tablero es un objetivo válido; primero intenta
            // interrumpir el progreso de la meta.
            int victim = 0, best = -1;
            for (int i = 0; i < vic.board.Count; i++)
            {
                int have = s.objective.IsBoardCardRequired(vic.board, i) ? 1 : 0;
                if (have > best) { best = have; victim = i; }
            }

            // Gastar la carta que MENOS sirve: una que no aporta al objetivo.
            int weapon = -1;
            for (int i = 0; i < p.hand.Count; i++)
            {
                if (MatchController.IsNeededForObjective(s, p, p.hand[i])) continue;
                weapon = i; break;
            }
            // Si no tiene nada que tirar, usa la menos importante que tenga.
            if (weapon < 0) weapon = p.hand.Count - 1;

            MatchController.Attack(s, playerIndex, victim, weapon);
        }

    }
}
