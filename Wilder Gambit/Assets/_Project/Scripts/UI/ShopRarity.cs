using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Sistema central de rarezas del Atelier (Tienda + Inventario + Enciclopedia).
    /// Paleta única para que TODOS los artículos compartan color:
    /// COMÚN gris, POCO COMÚN verde, RARA azul, ÉPICA púrpura,
    /// LEGENDARIA amarilla, MÍTICA roja.
    /// Las etiquetas de card se reworkean como píldoras (fondo translúcido +
    /// borde + texto en color de rareza) en lugar del texto dorado plano.
    /// Acepta "RARA", "RARO", "ÉPICA", "LEGENDARIA", etc. y normaliza acentos.
    /// </summary>
    public static class ShopRarity
    {
        public static readonly Color Comun      = new Color(0.62f, 0.65f, 0.70f, 1f); // Gris
        public static readonly Color PocoComun  = new Color(0.20f, 0.83f, 0.60f, 1f); // Verde
        public static readonly Color Rara       = new Color(0.35f, 0.65f, 1.00f, 1f); // Azul
        public static readonly Color Epica      = new Color(0.75f, 0.38f, 0.95f, 1f); // Púrpura
        public static readonly Color Legendaria = new Color(1.00f, 0.78f, 0.20f, 1f); // Amarillo
        public static readonly Color Mitica     = new Color(1.00f, 0.30f, 0.28f, 1f); // Rojo

        private static readonly string[] PillClasses =
        {
            "rarity-pill", "rarity-comun", "rarity-poco", "rarity-rara",
            "rarity-epica", "rarity-legendaria", "rarity-mitica"
        };

        /// <summary>Normaliza: mayúsculas, sin acentos, espacios colapsados.</summary>
        public static string Normalize(string rarity)
        {
            if (string.IsNullOrEmpty(rarity)) return "COMUN";
            string s = rarity.Trim().ToUpperInvariant();
            s = s.Replace('Á', 'A').Replace('É', 'E').Replace('Í', 'I')
                 .Replace('Ó', 'O').Replace('Ú', 'U').Replace('Ü', 'U');
            while (s.Contains("  ")) s = s.Replace("  ", " ");
            s = s.Replace("_", " ").Replace("-", " ");
            return s.Trim();
        }

        /// <summary>Color para un nombre libre ("RARA", "ÉPICA", "POCO COMÚN"...).</summary>
        public static Color ColorFor(string rarity)
        {
            string n = Normalize(rarity);
            if (n.Contains("MITIC") || n.Contains("MYTHIC")) return Mitica;
            if (n.Contains("LEGEND")) return Legendaria;
            if (n.Contains("EPIC")) return Epica;
            if (n.Contains("RARA") || n == "RARO" || n.Contains("RARE")) return Rara;
            if (n.Contains("POCO") || n.Contains("UNCOMMON") || n.Contains("INFRECUENTE")) return PocoComun;
            return Comun;
        }

        /// <summary>Etiqueta canónica en español para mostrar.</summary>
        public static string CanonicalLabel(string rarity)
        {
            string n = Normalize(rarity);
            if (n.Contains("MITIC") || n.Contains("MYTHIC")) return "MÍTICA";
            if (n.Contains("LEGEND")) return n.Contains("LEGENDARIA") ? "LEGENDARIA" : "LEGENDARIA";
            if (n.Contains("EPIC")) return "ÉPICA";
            if (n.Contains("RARA") || n == "RARO" || n.Contains("RARE")) return "RARA";
            if (n.Contains("POCO") || n.Contains("UNCOMMON")) return "POCO COMÚN";
            return "COMÚN";
        }

        /// <summary>Clase USS para la píldora (fondo/borde via USS + inline como respaldo).</summary>
        public static string PillClass(string rarity)
        {
            string n = Normalize(rarity);
            if (n.Contains("MITIC") || n.Contains("MYTHIC")) return "rarity-mitica";
            if (n.Contains("LEGEND")) return "rarity-legendaria";
            if (n.Contains("EPIC")) return "rarity-epica";
            if (n.Contains("RARA") || n == "RARO" || n.Contains("RARE")) return "rarity-rara";
            if (n.Contains("POCO") || n.Contains("UNCOMMON")) return "rarity-poco";
            return "rarity-comun";
        }

        // ── SkinRarity ────────────────────────────────────────────────

        public static Color ColorFor(SkinRarity r)
        {
            switch (r)
            {
                case SkinRarity.Common: return Comun;
                case SkinRarity.Uncommon: return PocoComun;
                case SkinRarity.Rare: return Rara;
                case SkinRarity.Epic: return Epica;
                case SkinRarity.Legendary: return Legendaria;
                case SkinRarity.Mythic: return Mitica;
                default: return Comun;
            }
        }

        public static string CanonicalLabel(SkinRarity r)
        {
            switch (r)
            {
                case SkinRarity.Common: return "COMÚN";
                case SkinRarity.Uncommon: return "POCO COMÚN";
                case SkinRarity.Rare: return "RARA";
                case SkinRarity.Epic: return "ÉPICA";
                case SkinRarity.Legendary: return "LEGENDARIA";
                case SkinRarity.Mythic: return "MÍTICA";
                default: return "COMÚN";
            }
        }

        // ── Estilos ───────────────────────────────────────────────────

        /// <summary>
        /// Rework visual completo de la etiqueta de rareza en cards:
        /// píldora con fondo translúcido + borde + texto en color.
        /// Mantiene bg-card-icon por layout y suma rarity-pill + clase por tier.
        /// </summary>
        public static void StyleCardLabel(Label label, string rarity)
        {
            if (label == null) return;
            Color c = ColorFor(rarity);
            label.text = CanonicalLabel(rarity);

            foreach (var cls in PillClasses)
                label.RemoveFromClassList(cls);
            label.AddToClassList("rarity-pill");
            label.AddToClassList(PillClass(rarity));
            label.RemoveFromClassList("bg-card-icon");

            label.style.color = c;
            label.style.backgroundColor = new Color(c.r, c.g, c.b, 0.14f);
            label.style.borderTopColor = c;
            label.style.borderBottomColor = c;
            label.style.borderLeftColor = c;
            label.style.borderRightColor = c;
            label.style.borderTopWidth = 1f;
            label.style.borderBottomWidth = 1f;
            label.style.borderLeftWidth = 1f;
            label.style.borderRightWidth = 1f;
            label.style.borderTopLeftRadius = 6f;
            label.style.borderTopRightRadius = 6f;
            label.style.borderBottomLeftRadius = 6f;
            label.style.borderBottomRightRadius = 6f;
            label.style.paddingTop = 2f;
            label.style.paddingBottom = 2f;
            label.style.paddingLeft = 7f;
            label.style.paddingRight = 7f;
            label.style.marginTop = 0f;
            label.style.marginBottom = 0f;
            label.style.marginLeft = 0f;
            label.style.marginRight = 0f;
            label.style.fontSize = 9f;
            label.style.unityFontStyleAndWeight = FontStyle.Bold;
            label.style.letterSpacing = 0.8f;
            label.style.whiteSpace = WhiteSpace.NoWrap;
            label.style.flexShrink = 0;
            label.style.alignSelf = Align.Center;
            label.pickingMode = PickingMode.Ignore;
        }

        public static void StyleCardLabel(Label label, SkinRarity rarity)
        {
            StyleCardLabel(label, CanonicalLabel(rarity));
        }

        /// <summary>Píldora grande para paneles de detalle / enciclopedia.</summary>
        public static void StyleBadge(Label label, string rarity, float fontSize = 10f)
        {
            StyleCardLabel(label, rarity);
            if (label == null) return;
            label.style.fontSize = fontSize;
            label.style.paddingTop = 4f;
            label.style.paddingBottom = 4f;
            label.style.paddingLeft = 12f;
            label.style.paddingRight = 12f;
            label.style.letterSpacing = 1.5f;
        }

        public static void StyleBadge(Label label, SkinRarity rarity, float fontSize = 10f)
        {
            StyleBadge(label, CanonicalLabel(rarity), fontSize);
        }

        /// <summary>
        /// Tiñe el kicker del detalle ("ANIMACIÓN • RARA") con el color de rareza
        /// sin romper el prefijo: pinta todo el kicker en tono claro legible.
        /// </summary>
        public static void StyleDetailKicker(Label kicker, string rarity)
        {
            if (kicker == null) return;
            Color c = ColorFor(rarity);
            // Aclarar para que se lea sobre fondo oscuro
            Color light = Color.Lerp(c, Color.white, 0.25f);
            kicker.style.color = light;
        }

        /// <summary>Tiñe el borde de la card con el color de rareza (sutil).</summary>
        public static void TintCardBorder(VisualElement card, string rarity, bool active = false)
        {
            if (card == null) return;
            Color c = ColorFor(rarity);
            float a = active ? 1f : 0.45f;
            var border = new Color(c.r, c.g, c.b, a);
            // Solo si la card no está marcada como activa/seleccionada con dorado,
            // aplicamos un glow sutil vía border. No pisamos bg-card-active.
            if (card.ClassListContains("bg-card-active") || card.ClassListContains("bg-card-selected"))
                return;
            card.style.borderTopColor = border;
            card.style.borderBottomColor = border;
            card.style.borderLeftColor = border;
            card.style.borderRightColor = border;
        }
    }
}
