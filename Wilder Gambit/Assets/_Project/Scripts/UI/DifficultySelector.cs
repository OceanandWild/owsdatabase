using UnityEngine;
using WilderGambit.AI;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Stub heredado del selector de dificultad original (uGUI).
    /// La funcionalidad ha sido migrada completamente a MainMenuController (UI Toolkit / UXML+USS).
    /// Esta clase se mantiene sólo para compatibilidad con referencias existentes en la escena.
    /// </summary>
    public class DifficultySelector : MonoBehaviour
    {
        // Ya no genera ningún Canvas uGUI en tiempo de ejecución.
        // Toda la UI se gestiona desde MainMenuController con UIDocument.
    }
}
