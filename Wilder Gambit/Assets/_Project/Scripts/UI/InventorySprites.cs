using System;
using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.UI
{
    /// <summary>
    /// Arte del <b>inventario</b> (<c>Resources/UI/Inventory</c>): el macuto del Atelier.
    /// Lo usan el botón girado del menú y el modal de inventario.
    ///
    /// Igual que <see cref="ChestSprites"/>, el fallo no se cachea: si el PNG todavía no
    /// está importado se devuelve <c>null</c> y la UI sigue sin él (el botón tiene su
    /// estilo USS y no se rompe por falta de arte).
    ///
    /// Sprites en Resources/UI/Inventory (ver consts abajo para los nombres).
    /// </summary>
    public static class InventorySprites
    {
        public const string Folder = "UI/Inventory";

        /// <summary>Solo el macuto (pose suelta). Es el arte del botón girado.</summary>
        public const string Backpack = "inv_backpack";
        /// <summary>Macuto + río de piezas: marca de agua del modal.</summary>
        public const string Archive = "inv_archive";

        private static readonly Dictionary<string, Sprite> Sprites = new Dictionary<string, Sprite>();

        /// <summary>Sprite por nombre, o <c>null</c> si el PNG no está instalado todavía.</summary>
        public static Sprite Get(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (Sprites.TryGetValue(name, out Sprite cached)) return cached;

            Sprite sprite = Resources.Load<Sprite>($"{Folder}/{name}");
            if (sprite != null) Sprites[name] = sprite;
            return sprite;
        }

        /// <summary>El macuto, con degradación a <c>null</c> si falta el arte.</summary>
        public static Sprite BackpackSprite => Get(Backpack);

        /// <summary>El arte completo, con degradación a <c>null</c> si falta el arte.</summary>
        public static Sprite ArchiveSprite => Get(Archive);
    }
}
