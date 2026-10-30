using System;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.UI
{
    /// <summary>
    /// Acceso a las piezas del cofre y de las cartas (<c>Resources/UI/Chest</c>) y a las
    /// **secuencias** de frames de los 8 clips de VFX (<c>Resources/UI/Chest/Frames/&lt;clip&gt;</c>).
    ///
    /// Los clips los entrega el generador como vídeo, así que se instalan como 24 PNG numerados
    /// por carpeta y aquí se cargan juntos y ordenados: `Resources.LoadAll` no garantiza el orden,
    /// y un animation que empiece por `f0017` se nota.
    ///
    /// Todo devuelve <c>null</c> o vacío si el PNG no está todavía, para poder ir soltando arte
    /// sin romper la UI: quien lo use debe poder seguir sin él.
    ///
    /// Nombres, medidas y montaje: prefijo reward_ + id, 512×512, carpeta UI/Chest.
    /// </summary>
    public static class ChestSprites
    {
        public const string Folder = "UI/Chest";
        private const string FramesFolder = "UI/Chest/Frames";

        // ── Poses del cofre: son el MISMO cofre en dos estados, no cuerpo y tapa sueltos ──
        /// <summary>Cerrado, con el pasador puesto. Es la pose de la fila del cofre.</summary>
        public const string PoseClosed = "chest_small";
        /// <summary>Abierto (cuerpo + tapa levantada). Es la pose de después de la apertura.</summary>
        public const string PoseOpen = "chest_base";
        /// <summary>Cerrado sin pasador: variante de la misma pose, para reutilizar.</summary>
        public const string PoseClosedAlt = "chest_lid";
        /// <summary>Candado suelto, por si se quiere un estado "cerrado con candado".</summary>
        public const string Lock = "chest_lock";
        /// <summary>Luz interior del cofre, para superponer sobre la pose abierta.</summary>
        public const string Interior = "chest_interior";

        // ── Cartas ──
        public const string CardBack = "card_reward_back";
        public const string CardGlow = "card_reward_glow";
        public const string CardSeal = "reward_seal";

        /// <summary>Rarezas de marco, de menor a mayor.</summary>
        public static readonly string[] Rarities = { "common", "rare", "epic", "legendary" };
        /// <summary>Premios con emblema propio.</summary>
        public static readonly string[] Emblems = { "gambits", "skin", "board", "variant", "animation" };
        /// <summary>Clips de la apertura, tal como se llaman sus carpetas.</summary>
        public static readonly string[] Clips =
        {
            "seal_break", "dust", "shockwave", "halo", "rays", "embers", "coins", "flare",
        };

        private static readonly Dictionary<string, Sprite> Sprites = new Dictionary<string, Sprite>();
        private static readonly Dictionary<string, Sprite[]> Sequences = new Dictionary<string, Sprite[]>();

        /// <summary>
        /// Sprite suelto, o null si el PNG todavía no está. **El fallo no se cachea**: así se
        /// puede soltar arte con la partida en marcha, sin reiniciar. Lo que sí se cachea es el
        /// acierto, que es lo que importa para no golpear Resources en cada repintado.
        /// </summary>
        public static Sprite Get(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (Sprites.TryGetValue(name, out Sprite cached)) return cached;

            Sprite sprite = Resources.Load<Sprite>($"{Folder}/{name}");
            if (sprite != null) Sprites[name] = sprite;
            return sprite;
        }

        public static Sprite Frame(string rarity) => Get($"card_reward_frame_{rarity}");
        public static Sprite Emblem(string emblem) => Get($"reward_emblem_{emblem}");

        /// <summary>Primero de la lista que exista (para degradar de legendaria a común).</summary>
        public static Sprite FirstOf(params string[] names)
        {
            if (names == null) return null;
            foreach (string name in names)
            {
                Sprite sprite = Get(name);
                if (sprite != null) return sprite;
            }
            return null;
        }

        /// <summary>El marco de mayor rareza que tenga PNG instalado.</summary>
        public static Sprite BestFrame()
        {
            for (int i = Rarities.Length - 1; i >= 0; i--)
            {
                Sprite sprite = Frame(Rarities[i]);
                if (sprite != null) return sprite;
            }
            return null;
        }

        /// <summary>Frames de un clip, en orden. Vacío si el clip no está instalado.</summary>
        public static Sprite[] Sequence(string clip)
        {
            if (string.IsNullOrEmpty(clip)) return Array.Empty<Sprite>();
            if (Sequences.TryGetValue(clip, out Sprite[] cached)) return cached;

            Sprite[] list = Resources.LoadAll<Sprite>($"{FramesFolder}/{clip}");
            if (list == null) return Array.Empty<Sprite>();
            Array.Sort(list, (a, b) => string.CompareOrdinal(a.name, b.name));

            if (list.Length > 0) Sequences[clip] = list;   // el vacío no se cachea: ver Get
            return list;
        }

        public static bool HasSequence(string clip) => Sequence(clip).Length > 0;
    }
}
