using System.Collections.Generic;
using System.Linq;

namespace WildSea.Game
{
    /// <summary>
    /// Objetivos disponibles del modo clasico. La partida elige UNO al azar.
    ///
    /// Solo van objetivos que hoy son completables con el pool de 23 cartas. El
    /// Sistema Solar esta incompleto: faltan Sol, Mercurio, Tierra, Urano y Neptuno,
    /// asi que por ahora pide solo los 4 planetas que existen. Cuando entren esas
    /// cartas, alcanza con subir el count y el objetivo las empieza a exigir solo.
    /// Los objetivos de coleccion completa pueden, en cambio, fijar ids concretos.
    /// </summary>
    public static class ObjectiveCatalog
    {
        static List<ObjectiveDef> _all;
        public static IReadOnlyList<ObjectiveDef> All => _all ??= Build();

        public static ObjectiveDef ById(string id) =>
            All.FirstOrDefault(o => o.id == id);

        /// <summary>Elige un objetivo al azar entre los que si son completables.</summary>
        public static ObjectiveDef PickRandom()
        {
            var ok = All.Where(o => o.IsReachable(out _)).ToList();
            if (ok.Count == 0) ok = All.ToList();
            return ok[UnityEngine.Random.Range(0, ok.Count)];
        }

        static List<ObjectiveDef> Build() => new()
        {
            // 1 Estrella/Sistema Solar (el Sol) + 4 de los 8 Planetas/Sistema Solar.
            // El Sol solo existe como carta desde el Lote 1: antes el pool tenia
            // 0 Estrellas con esa subcategoria, IsReachable daba el objetivo por
            // inalcanzable y PickRandom nunca lo sorteaba. Con la carta adentro
            // reaparece solo, sin tocar nada mas: las reglas matchean por
            // categoria+subcategoria, no por lista de ids.
            new ObjectiveDef(
                "sistema-solar", "Sistema Solar",
                new ObjectiveRule(BodyCategory.Star, CardPool.SUB_SOLAR_SYSTEM, 1),
                new ObjectiveRule(BodyCategory.Planet, CardPool.SUB_SOLAR_SYSTEM, 4)),

            new ObjectiveDef(
                "planetas-enanos", "Planetas Enanos",
                // Requiere una copia de cada planeta enano; las copias de Ceres no
                // sustituyen a Pluton, Eris, Haumea ni Makemake.
                new ObjectiveRule(BodyCategory.Asteroid, CardPool.SUB_DWARF_PLANET, 1, "ceres"),
                new ObjectiveRule(BodyCategory.Asteroid, CardPool.SUB_DWARF_PLANET, 1, "pluton"),
                new ObjectiveRule(BodyCategory.Asteroid, CardPool.SUB_DWARF_PLANET, 1, "eris"),
                new ObjectiveRule(BodyCategory.Asteroid, CardPool.SUB_DWARF_PLANET, 1, "haumea"),
                new ObjectiveRule(BodyCategory.Asteroid, CardPool.SUB_DWARF_PLANET, 1, "makemake")),

            new ObjectiveDef(
                "cinturon-asteroides", "Cinturon de Asteroides",
                // Objetivo sin subcategoria: pide la clase entera. Con la mano inicial
                // de Objetos ya no nace ganado (antes median 1 turno).
                new ObjectiveRule(BodyCategory.Asteroid, null, 3)),

            new ObjectiveDef(
                "lunas-gigantes", "Lunas de Gigantes",
                // Bajó de 3 a 2 por lo mismo que "Planetas Enanos": los counts estaban
                // calibrados contra una mano inicial que ya traia la mitad de la clase.
                new ObjectiveRule(BodyCategory.Moon, null, 2)),
        };
    }
}
