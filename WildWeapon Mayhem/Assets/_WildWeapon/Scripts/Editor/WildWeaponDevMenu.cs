using UnityEditor;
using UnityEngine;

namespace WildWeapon.EditorTools
{
    /// <summary>
    /// Atajos de iteración WIP: reconstruye las escenas sin el diálogo modal del
    /// menú principal, para poder dispararlo desde herramientas externas (MCP).
    /// Es el mismo BuildAllSilent que usa "WildWeapon > Construir juego completo".
    /// </summary>
    internal static class WildWeaponDevMenu
    {
        [MenuItem("WildWeapon/Dev/Reconstruir escenas (silencioso)")]
        private static void RebuildSilent()
        {
            WildWeaponBuilder.BuildAllSilent();
            Debug.Log("[WildWeapon] Escenas reconstruidas (modo silencioso).");
        }

        /// <summary>Solo el menu: iterar la UI sin tocar el resto de las escenas.</summary>
        [MenuItem("WildWeapon/Dev/Reconstruir menu (silencioso)")]
        private static void RebuildMenu()
        {
            WildWeaponBuilder.BuildMenuOnly();
            Debug.Log("[WildWeapon] Menu reconstruido (modo silencioso).");
        }

        /// <summary>Solo el lobby: iterar la maqueta sin rehacer el arte ni los prefabs.</summary>
        [MenuItem("WildWeapon/Dev/Reconstruir lobby (silencioso)")]
        private static void RebuildLobby()
        {
            WildWeaponBuilder.BuildLobbyScene();
            Debug.Log("[WildWeapon] Lobby reconstruido (modo silencioso).");
        }
    }
}
