using System;

namespace WildSea.Game
{
    /// <summary>
    /// Las 6 categorias principales. Definen la escalera de fusion:
    /// 3 cartas de la categoria N dan 1 carta de la categoria N+1.
    ///
    ///   Objeto -> Asteroide -> Luna -> Planeta -> Estrella -> Nube -> Galaxia
    ///
    /// Estas NUNCA son subcategorias: son la escalera. Lo que decide si una carta
    /// sirve para un objetivo es la subcategoria, no la categoria.
    /// </summary>
    public enum BodyCategory
    {
        Object = 0,   // sondas, estaciones, motores: lo mas bajo del mazo
        Asteroid = 1,
        Moon = 2,
        Planet = 3,
        Star = 4,
        Nebula = 5,   // nube de gas: region de formacion estelar
        Galaxy = 6,
    }

    /// <summary>
    /// Definicion inmutable de una carta.
    ///
    /// Dos campos de clasificacion, y son independientes:
    ///   - category    : cuerpo fisico. Define la escalera de fusion.
    ///   - subcategory : agrupacion real (Sistema Solar, Planeta Enano). Define si la
    ///                   carta sirve para el objetivo, salvo requisitos por id concreto.
    ///
    /// Lunas y satelites no tienen subcategoria (N/A) por logica real, asi que
    /// subcategory puede ser null.
    /// </summary>
    public sealed class CardDef
    {
        public readonly string id;
        public readonly string name;
        public readonly BodyCategory category;
        public readonly string subcategory;   // "Sistema Solar" | "Planeta Enano" | null
        public readonly string description;

        public CardDef(string id, string name, BodyCategory category, string subcategory, string description)
        {
            this.id = id;
            this.name = name;
            this.category = category;
            // Normalizamos: vacio o guion bajo significan "sin subcategoria".
            this.subcategory = string.IsNullOrWhiteSpace(subcategory) ? null : subcategory.Trim();
            this.description = description ?? "";
        }

        public bool HasSubcategory => subcategory != null;

        /// <summary>Escalon immediately superior. Galaxia es el tope: no sube.</summary>
        public static BodyCategory NextTier(BodyCategory c) =>
            c == BodyCategory.Galaxy ? BodyCategory.Galaxy : (BodyCategory)((int)c + 1);

        /// <summary>
        /// Esta carta cuenta para un objetivo concreto? Compara categoria + subcategoria.
        /// El objetivo define que categoria y que subcategoria pide.
        /// </summary>
        public bool Serves(BodyCategory cat, string sub) =>
            category == cat
            && string.Equals(subcategory, sub, StringComparison.OrdinalIgnoreCase);

        public override string ToString() =>
            HasSubcategory ? $"{name} ({category}/{subcategory})" : $"{name} ({category})";
    }
}
