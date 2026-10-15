using System.Collections.Generic;
using System.Linq;

namespace WildSea.Game
{
    /// <summary>
    /// El objetivo de la partida en modo clasico. El juego lo elige solo y ambos
    /// jugadores compiten por completarlo.
    ///
    /// Se define por REQUERIMIENTOS (categoria + subcategoria + cantidad), con un
    /// id opcional para objetivos que exigen cartas especificas. Asi el mismo
    /// objetivo sigue funcionando cuando agregas cartas a una categoria abierta.
    /// </summary>
    public sealed class ObjectiveDef
    {
        public readonly string id;
        public readonly string name;
        public readonly ObjectiveRule[] rules;

        public ObjectiveDef(string id, string name, params ObjectiveRule[] rules)
        {
            this.id = id;
            this.name = name;
            this.rules = rules ?? System.Array.Empty<ObjectiveRule>();
        }

        /// <summary>Carta de la que el jugador N, y cuenta de cuantas le faltan.</summary>
        public (int have, int need)[] Progress(IReadOnlyCollection<CardDef> played)
        {
            var res = new (int, int)[rules.Length];
            for (int i = 0; i < rules.Length; i++)
            {
                int have = played.Count(c => rules[i].Matches(c));
                res[i] = (have, rules[i].count);
            }
            return res;
        }

        /// <summary>Ya completo: el jugador tiene jugadas todas las cartas que pide.</summary>
        public bool IsComplete(IReadOnlyCollection<CardDef> played)
        {
            for (int i = 0; i < rules.Length; i++)
            {
                int have = played.Count(rules[i].Matches);
                if (have < rules[i].count) return false;
            }
            return true;
        }

        /// <summary>La carta de esta posicion es una de las que cuenta para la meta.</summary>
        public bool IsBoardCardRequired(IReadOnlyList<CardDef> played, int index)
        {
            if (played == null || index < 0 || index >= played.Count) return false;
            var card = played[index];
            if (card == null) return false;

            foreach (var rule in rules)
            {
                if (!rule.Matches(card)) continue;
                int earlierMatches = 0;
                for (int i = 0; i < index; i++)
                    if (rule.Matches(played[i])) earlierMatches++;
                if (earlierMatches < rule.count) return true;
            }
            return false;
        }

        /// <summary>
        /// Las cartas de este objetivo que estan disponibles en el catalogo.
        /// Sirve para el hint de la UI y para validar que el objetivo sea completable.
        /// </summary>
        public List<CardDef> AllCandidates() =>
            CardPool.Templates.Where(c => rules.Any(r => r.Matches(c))).ToList();

        /// <summary>El objetivo tiene mas cartas pedidas de las que el pool puede dar?</summary>
        public bool IsReachable(out string missing)
        {
            var pool = CardPool.Templates;
            for (int i = 0; i < rules.Length; i++)
            {
                int avail = pool.Count(rules[i].Matches);
                if (avail < rules[i].count)
                {
                    missing = $"{name}: pide {rules[i].count} x {rules[i]} y el pool tiene {avail}";
                    return false;
                }
            }
            missing = null;
            return true;
        }
    }

    /// <summary>Un requisito: "necesito N cartas de esta categoria con esta subcategoria".</summary>
    public readonly struct ObjectiveRule
    {
        public readonly BodyCategory category;
        public readonly string subcategory;   // null = cualquiera
        public readonly int count;
        public readonly string requiredCardId; // null = cualquier carta que coincida

        public ObjectiveRule(BodyCategory category, string subcategory, int count, string requiredCardId = null)
        {
            this.category = category;
            this.subcategory = string.IsNullOrWhiteSpace(subcategory) ? null : subcategory.Trim();
            this.count = count;
            this.requiredCardId = string.IsNullOrWhiteSpace(requiredCardId) ? null : requiredCardId.Trim();
        }

        public bool Matches(CardDef c)
        {
            if (c == null || c.category != category) return false;
            if (subcategory != null && (c.subcategory == null
                || !c.subcategory.Equals(subcategory, System.StringComparison.OrdinalIgnoreCase))) return false;
            return requiredCardId == null
                || requiredCardId.Equals(c.id, System.StringComparison.OrdinalIgnoreCase);
        }

        public override string ToString() =>
            requiredCardId != null ? $"{count} x {requiredCardId}"
                : subcategory == null ? $"{count} x {category}" : $"{count} x {category}/{subcategory}";
    }
}
