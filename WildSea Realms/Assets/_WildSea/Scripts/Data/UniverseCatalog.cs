using System.Collections.Generic;
using UnityEngine;
using WildSea.Data;

namespace WildSea.Data
{
    /// <summary>
    /// Catálogo v1: hardcoded para no exigir .asset en Fase 1.
    /// Fase 2: reemplazar por Resources.LoadAll&lt;UniverseDef&gt; sin tocar la UI.
    /// Universo Espacio activo (Estrella/Galaxia). Resto bloqueados/teased.
    /// </summary>
    public static class UniverseCatalog
    {
        static List<UniverseDef> cache;

        public static IReadOnlyList<UniverseDef> GetAll()
        {
            if (cache != null) return cache;
            cache = new List<UniverseDef>
            {
                MakeSpace(), MakeAbyss(), MakeJungle(), MakeTeased(),
            };
            return cache;
        }

        public static UniverseDef GetById(string id)
        {
            foreach (var u in GetAll())
                if (u.id == id) return u;
            return GetAll()[0];
        }

        static GameModeDef Mode(string id, string uni, string name, string glyph, string desc, string win, string deck)
        {
            var m = ScriptableObject.CreateInstance<GameModeDef>();
            m.id = id; m.universeId = uni; m.displayName = name;
            m.iconGlyph = glyph; m.description = desc;
            m.winConditionId = win; m.futureDeckId = deck;
            return m;
        }

        static UniverseDef MakeSpace()
        {
            var u = ScriptableObject.CreateInstance<UniverseDef>();
            u.id = "space"; u.displayName = "ESPACIO"; u.iconGlyph = "🚀";
            u.tagline = "Cuna de estrellas.";
            u.lore = "Donde nacen las Estrellas y se tejen las Galaxias. Cada duelo usa su propio mazo.";
            u.topColor = new Color(0.04f, 0.12f, 0.23f);
            u.bottomColor = new Color(0.23f, 0.04f, 0.35f);
            u.accentColor = new Color(1f, 0.84f, 0.35f);
            u.unlockedInV1 = true;
            u.modes = new[]
            {
                Mode("estrella", "space", "Modo Estrella", "⭐", "Primero en obtener 1 Estrella gana.", "first_to_1_star", "deck_space_estrella"),
                Mode("galaxia", "space", "Modo Galaxia", "🌌", "Primero en completar 1 Galaxia gana.", "first_to_1_galaxy", "deck_space_galaxia"),
            };
            return u;
        }

        static UniverseDef MakeAbyss()
        {
            var u = ScriptableObject.CreateInstance<UniverseDef>();
            u.id = "abyss"; u.displayName = "ABISMO"; u.iconGlyph = "🌊";
            u.tagline = "Bajo presión.";
            u.lore = "Nuevo Universo en Fase 3 con sus propios modos y cartas.";
            u.topColor = new Color(0.01f, 0.10f, 0.18f);
            u.bottomColor = new Color(0.02f, 0.25f, 0.35f);
            u.accentColor = new Color(0.37f, 0.89f, 0.82f);
            u.unlockedInV1 = false;
            u.modes = new GameModeDef[0];
            return u;
        }

        static UniverseDef MakeJungle()
        {
            var u = ScriptableObject.CreateInstance<UniverseDef>();
            u.id = "jungle"; u.displayName = "SELVA"; u.iconGlyph = "🌿";
            u.tagline = "Espesa y viva.";
            u.lore = "Nuevo Universo en Fase 3 con sus propios modos y cartas.";
            u.topColor = new Color(0.03f, 0.15f, 0.08f);
            u.bottomColor = new Color(0.10f, 0.30f, 0.12f);
            u.accentColor = new Color(0.55f, 1f, 0.55f);
            u.unlockedInV1 = false;
            u.modes = new GameModeDef[0];
            return u;
        }

        static UniverseDef MakeTeased()
        {
            var u = ScriptableObject.CreateInstance<UniverseDef>();
            u.id = "teased"; u.displayName = "???"; u.iconGlyph = "✦";
            u.tagline = "Próximamente.";
            u.lore = "Un nuevo Universo emerge de la niebla...";
            u.topColor = new Color(0.08f, 0.08f, 0.12f);
            u.bottomColor = new Color(0.15f, 0.10f, 0.25f);
            u.accentColor = new Color(0.60f, 0.60f, 0.70f);
            u.unlockedInV1 = false; u.isTeased = true;
            u.modes = new GameModeDef[0];
            return u;
        }
    }
}
