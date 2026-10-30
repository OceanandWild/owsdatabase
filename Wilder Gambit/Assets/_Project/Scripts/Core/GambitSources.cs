using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>De dónde salen los Gambits. Cada fuente tiene su tope diario y su "reason" para Surface.</summary>
    public enum GambitSource
    {
        Match = 0,          // partida vs IA (base + modificadores)
        Puzzle = 1,         // entrenamiento táctico
        DailyChallenge = 2, // reto diario
        DailyMission = 3,   // misión diaria completada
        WeeklyMission = 4,  // misión semanal completada
        WeeklySegment = 5,  // día perfecto en la barra de 7
        WeeklyChest = 6,    // cofre 7/7
        Achievement = 7,    // hito de una sola vez
        Bonus = 8,          // extras (primera victoria del día, regalos)
        SeasonPass = 9,     // recompensas de nivel cobradas en el pase (sin tope)
        HalloweenPass = 10, // recompensas de la velada de Halloween (sin tope)
        HalloweenShop = 11, // Dulces cambiados por Gambits en la tienda de la velada (sin tope)
        Count = 12,
    }

    /// <summary>Ficha de una fuente: cómo se llama, cuánto paga y cuánto se puede sacar al día.</summary>
    public struct GambitSourceInfo
    {
        public GambitSource source;
        public string id;         // se usa en el reason que se manda a Surface
        public string label;      // texto de UI
        public string icon;
        public string hint;       // "hasta 6 partidas/día"
        public int dailyCap;      // tope de Gambits por día (0 = sin tope propio)
        public int maxPayments;   // tope de pagos por día (0 = sin tope)
    }

    /// <summary>Catálogo único de fuentes de Gambits: lo comparten la economía y la vista de Progreso.</summary>
    public static class GambitSources
    {
        public static readonly GambitSourceInfo[] All =
        {
            new GambitSourceInfo { source = GambitSource.Match,          id = "match",          icon = "⚔️", label = "Partidas vs IA",     hint = "Hasta 6 partidas pagadas al día · más difícil, más paga", dailyCap = 320, maxPayments = 6 },
            new GambitSourceInfo { source = GambitSource.Puzzle,         id = "puzzle",         icon = "🧩", label = "Entrenamiento táctico", hint = "5 puzzles con premio al día · después, práctica sin premio", dailyCap = 380, maxPayments = 6 },
            new GambitSourceInfo { source = GambitSource.DailyChallenge, id = "daily_challenge",icon = "🎯", label = "Desafío diario",      hint = "Uno al día · sube con tu racha",                        dailyCap = 120, maxPayments = 1 },
            new GambitSourceInfo { source = GambitSource.DailyMission,   id = "mission",        icon = "📜", label = "Misiones diarias",    hint = "3 al día · llenan la barra semanal",                    dailyCap = 400, maxPayments = 3 },
            new GambitSourceInfo { source = GambitSource.WeeklyMission,  id = "weekly_mission", icon = "🗓️", label = "Misiones semanales",  hint = "3 por semana, se reinician el lunes",                   dailyCap = 900, maxPayments = 3 },
            new GambitSourceInfo { source = GambitSource.WeeklySegment,  id = "weekly_segment", icon = "✦", label = "Días perfectos",      hint = "Completa las 3 misiones del día",                       dailyCap = 200, maxPayments = 1 },
            new GambitSourceInfo { source = GambitSource.WeeklyChest,    id = "weekly_chest",   icon = "🏆", label = "Cofre del Atelier",   hint = "7 días perfectos en la misma semana",                   dailyCap = 2200, maxPayments = 1 },
            new GambitSourceInfo { source = GambitSource.Achievement,    id = "achievement",    icon = "🏅", label = "Logros",              hint = "Se cobra una sola vez",                                 dailyCap = 0,   maxPayments = 0 },
            new GambitSourceInfo { source = GambitSource.Bonus,          id = "bonus",          icon = "✨", label = "Primera del día",     hint = "Primer triunfo diario",                                 dailyCap = 150, maxPayments = 1 },
            new GambitSourceInfo { source = GambitSource.SeasonPass,      id = "season_pass",    icon = "🎴", label = "Pase de temporada",   hint = "Recompensas de nivel cobradas",                         dailyCap = 0,   maxPayments = 0 },
            new GambitSourceInfo { source = GambitSource.HalloweenPass,   id = "halloween_pass", icon = "🎃", label = "Pase de Halloween",   hint = "Recompensas de la velada cobradas",                     dailyCap = 0,   maxPayments = 0 },
            new GambitSourceInfo { source = GambitSource.HalloweenShop,   id = "halloween_shop", icon = "🍬", label = "Tienda de la velada",  hint = "Dulces cambiados por Gambits",                          dailyCap = 0,   maxPayments = 0 },
        };

        public static GambitSourceInfo Get(GambitSource source)
        {
            int i = (int)source;
            if (i >= 0 && i < All.Length) return All[i];
            return All[0];
        }

        public static string Label(GambitSource source) => Get(source).label;
        public static string Icon(GambitSource source) => Get(source).icon;

        /// <summary>Motivo que se envía a Surface (ej: «match_victory_knight»).</summary>
        public static string Reason(GambitSource source, string meta)
        {
            string id = Get(source).id;
            if (string.IsNullOrEmpty(meta)) return id;

            // El backend valida motivos con formato simple: minúsculas, sin espacios
            string clean = meta.Trim().ToLowerInvariant().Replace(' ', '_');
            return $"{id}_{clean}";
        }
    }
}
