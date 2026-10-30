using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Stub heredado del modal de Ajustes (uGUI).
    /// La funcionalidad ha sido migrada a MainMenuController (UI Toolkit / UXML+USS).
    /// Esta clase se mantiene para compatibilidad con cualquier referencia existente en la escena.
    /// Los ajustes de cinemáticas se gestionan ahora en MainMenuController.
    /// </summary>
    public class SettingsModal : MonoBehaviour
    {
        public static SettingsModal Instance { get; private set; }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;

            bool cinematicsOn = PlayerPrefs.GetInt("EnableCinematics", 1) == 1;
            if (GameManager.Instance != null)
                GameManager.Instance.EnableCinematics = cinematicsOn;
        }
    }
}
