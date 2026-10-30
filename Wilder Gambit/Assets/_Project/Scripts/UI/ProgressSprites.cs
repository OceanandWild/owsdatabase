using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Carga los sprites de contenedores desde <c>Resources/UI/Progress</c> y los aplica como
    /// fondo 9-slice sobre el estilo USS. Si el sprite no existe todavía, el
    /// elemento conserva el aspecto que ya tiene el USS: se pueden ir soltando PNGs sin romper
    /// nada.
    ///
    /// Los PNG llevan filigrana tallada con volutas en las esquinas y emblemas centrados
    /// (coronas, colgantes). El 9-slice se mide al FILETE del borde (el marco recto en el
    /// centro de cada lado), NO a la voluta más ancha: medir a la voluta obligaba a un slice
    /// gigante que se comía el contenido en los tramos donde el marco es fino, y el texto
    /// quedaba cruzado por el oro. Las volutas quedan en los parches de esquina y pisan la
    /// zona de padding en diagonal: por eso el USS deja aire extra (padding-top en las
    /// tarjetas con corona, padding-left en las filas con gema azul, etc.).
    /// Cada lado lleva su propio valor en píxeles del sprite porque los marcos son
    /// asimétricos (la gema azul de row_mission solo está a la izquierda, la píldora de
    /// btn_claim tiene extremos redondos, ...).
    ///
    /// Sprites en Resources/UI/Progress (ver la tabla para los nombres).
    /// </summary>
    public static class ProgressSprites
    {
        public const string Folder = "UI/Progress";

        // ── Tabla 9-slice ───────────────────────────────────────────────────
        // Valores en PÍXELES del sprite, medidos al filete del borde (centro de cada
        // lado), no a la voluta. unitySliceScale = 1: el sprite se dibuja escalado al
        // contenedor y el slice escala con él, así que el filete conserva su proporción.
        private struct Slot
        {
            public int left;
            public int right;
            public int top;
            public int bottom;

            public Slot(int left, int right, int top, int bottom)
            {
                this.left = left;
                this.right = right;
                this.top = top;
                this.bottom = bottom;
            }
        }

        // left/right/top/bottom = filete del borde en píxeles del sprite.
        // Las esquinas con voluta grande (card_week, card_large) quedan en los parches de
        // esquina: el USS les deja aire con padding en vez de agrandar el slice.
        private static readonly Dictionary<string, Slot> Table = new Dictionary<string, Slot>
        {
            // ── Grandes ──
            { "frame_window",      new Slot(32, 32, 30, 30) },
            { "card_week",         new Slot(24, 24, 34, 24) },
            { "card_large",        new Slot(14, 14, 16, 16) },
            { "card_chest",        new Slot(14, 14, 12, 14) },
            { "card_chest_ready",  new Slot(16, 16, 16, 16) },
            { "card_ach",          new Slot(10, 10,  8,  8) },
            { "card_ach_done",     new Slot( 8,  8,  8,  8) },

            // ── Filas chicas ──
            // row_mission/row_weekly llevan la gema azul a la IZQUIERDA: el slice
            // izquierdo la preserva entera y el padding-left del USS la despeja.
            { "row_mission",       new Slot(34, 10,  8,  8) },
            { "row_mission_done",  new Slot( 8,  8,  6,  6) },
            { "row_weekly",        new Slot(34, 10,  8,  8) },
            { "row_weekly_done",   new Slot( 8,  8,  6,  6) },
            // row_challenge es el marco de las filas de Retos del Día (prop. 9,53). La
            // fila real es mucho más ancha (~23), pero el centro es LISO, así que solo se
            // estira el centro y el filete no se deforma. Slice al filete medido sobre el
            // PNG: ~14px por lado dejan las volutas de las esquinas en los parches de
            // esquina; el padding del USS las despeja.
            { "row_challenge",     new Slot(14, 14, 15, 15) },
            { "row_source",        new Slot(12, 12, 10, 10) },
            { "row_source_empty",  new Slot(14, 14, 12, 12) },

            // ── Segmentos de la barra de 7 ──
            // Marco fino + remates solo en las esquinas superiores: el padding-top del
            // USS (no el slice) es lo que despeja el laurel y la moneda.
            { "seg_future",        new Slot( 8,  8, 10, 10) },
            { "seg_today",         new Slot( 8,  8, 10, 10) },
            { "seg_done",          new Slot( 8,  8, 10, 10) },
            { "seg_missed",        new Slot( 8,  8, 10, 10) },

            // ── Chips, botones y detalles ──
            // (valores que ya se veían bien: se conservan tal cual)
            { "chip_gold",         new Slot(32, 32,  3,  3) },
            { "chip_blue",         new Slot(20, 20, 17, 17) },
            { "btn_claim_ready",   new Slot(30, 30,  8,  8) },
            { "btn_claim_locked",  new Slot(30, 30,  8,  8) },
            { "btn_claim_done",    new Slot(30, 30,  8,  8) },
            { "btn_claim",         new Slot(30, 30,  8,  8) },
            { "btn_ghost",         new Slot(12, 12,  8,  8) },
            { "btn_ghost_locked",  new Slot(12, 12,  8,  8) },
            { "btn_menu_progress", new Slot(24, 24,  1,  1) },
            { "toast",             new Slot(30, 30,  4,  4) },
            { "bar_track",         new Slot( 8,  8,  2,  2) },
            { "bar_fill",          new Slot( 8,  8,  2,  2) },
            { "bar_track_v",       new Slot( 6,  6,  6,  6) },
            { "bar_fill_v",        new Slot( 6,  6,  6,  6) },
            { "badge_pending",     new Slot( 0,  0,  0,  0) }, // disco: sin slice
        };

        private static readonly Dictionary<string, Sprite> Cache = new Dictionary<string, Sprite>();

        /// <summary>Devuelve el sprite o null si todavía no está generado.</summary>
        public static Sprite Get(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (Cache.TryGetValue(name, out var cached)) return cached;

            var sprite = Resources.Load<Sprite>($"{Folder}/{name}");
            Cache[name] = sprite; // se cachea también el null para no golpear Resources en bucle
            return sprite;
        }

        public static bool Exists(string name) => Get(name) != null;

        /// <summary>Aplica el sprite del contenedor con el 9-slice de la tabla.</summary>
        public static bool Apply(VisualElement element, string name)
        {
            if (element == null) return false;
            if (!Table.TryGetValue(name, out var slot)) return Apply(element, name, 0, 1f);
            return Apply(element, name, slot);
        }

        private static bool Apply(VisualElement element, string name, Slot slot)
        {
            var sprite = Get(name);
            if (element == null || sprite == null) return false;

            Rect rect = sprite.rect;
            int sw = Mathf.Max(1, Mathf.RoundToInt(rect.width));
            int sh = Mathf.Max(1, Mathf.RoundToInt(rect.height));

            element.style.backgroundImage = new StyleBackground(sprite);

            if (slot.left > 0 || slot.right > 0 || slot.top > 0 || slot.bottom > 0)
            {
                // Slice asimétrico directo en píxeles del sprite: cada lado preserva
                // solo su filete. Las volutas de las esquinas viven en los parches de
                // esquina y pisan el padding en diagonal (el USS les deja aire).
                element.style.unitySliceLeft = Mathf.Clamp(slot.left, 1, sw / 2);
                element.style.unitySliceRight = Mathf.Clamp(slot.right, 1, sw / 2);
                element.style.unitySliceTop = Mathf.Clamp(slot.top, 1, sh / 2);
                element.style.unitySliceBottom = Mathf.Clamp(slot.bottom, 1, sh / 2);
                element.style.unitySliceScale = 1f;
            }

            return true;
        }

        /// <summary>Versión explícita (para pruebas o para un contenedor fuera de la tabla).</summary>
        public static bool Apply(VisualElement element, string name, int slice, float sliceScale = 1f)
        {
            var sprite = Get(name);
            if (element == null || sprite == null) return false;

            element.style.backgroundImage = new StyleBackground(sprite);
            if (slice > 0)
            {
                element.style.unitySliceLeft = slice;
                element.style.unitySliceRight = slice;
                element.style.unitySliceTop = slice;
                element.style.unitySliceBottom = slice;
                element.style.unitySliceScale = sliceScale;
            }
            return true;
        }

        /// <summary>Prueba varios nombres y aplica el primero que exista.</summary>
        public static bool ApplyFirst(VisualElement element, params string[] names)
        {
            if (element == null || names == null) return false;
            foreach (var name in names)
                if (Get(name) != null && Apply(element, name)) return true;
            return false;
        }

        /// <summary>Vuelve al estilo USS (quita el sprite aplicado).</summary>
        public static void Clear(VisualElement element)
        {
            if (element == null) return;
            element.style.backgroundImage = new StyleBackground(StyleKeyword.None);
        }
    }
}
