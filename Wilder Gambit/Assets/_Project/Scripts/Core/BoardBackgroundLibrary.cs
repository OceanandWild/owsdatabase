using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Central registry of all board background themes.
    /// Create a single instance via Assets > Create > Wilder Gambit > Board Background Library.
    /// Assign all BoardBackgroundConfig assets to the themes list in the Inspector.
    /// </summary>
    [CreateAssetMenu(fileName = "BoardBackgroundLibrary", menuName = "Wilder Gambit/Board Background Library", order = 0)]
    public class BoardBackgroundLibrary : ScriptableObject
    {
        [Tooltip("All available board background themes. Order determines display order in the shop.")]
        public List<BoardBackgroundConfig> themes = new List<BoardBackgroundConfig>();

        /// <summary>Gets the theme at the given index (clamped).</summary>
        public BoardBackgroundConfig GetTheme(int index)
        {
            if (themes == null || themes.Count == 0) return null;
            return themes[Mathf.Clamp(index, 0, themes.Count - 1)];
        }

        /// <summary>Finds a theme by its ID string.</summary>
        public BoardBackgroundConfig GetThemeById(string id)
        {
            if (themes == null) return null;
            foreach (var theme in themes)
            {
                if (theme != null && theme.themeId == id)
                    return theme;
            }
            return null;
        }

        /// <summary>Returns the index of a theme, or 0 if not found.</summary>
        public int GetIndexById(string id)
        {
            if (themes == null) return 0;
            for (int i = 0; i < themes.Count; i++)
            {
                if (themes[i] != null && themes[i].themeId == id)
                    return i;
            }
            return 0;
        }

        /// <summary>Total number of themes.</summary>
        public int Count => themes != null ? themes.Count : 0;
    }
}
