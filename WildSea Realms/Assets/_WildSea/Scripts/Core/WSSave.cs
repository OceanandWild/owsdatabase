using UnityEngine;

namespace WildSea.Core
{
    /// <summary>
    /// Fase 1: Solo Menús. Guarda selección + opciones en PlayerPrefs (JSON migra a saveVersion en Fase 2).
    /// </summary>
    public static class WSSave
    {
        const string K_Universe = "WS_SelectedUniverse";
        const string K_Mode = "WS_SelectedMode";
        const string K_Lang = "WS_Lang";
        const string K_Music = "WS_Music";
        const string K_Sfx = "WS_Sfx";
        const string K_Full = "WS_Fullscreen";
        const string K_Flash = "WS_ReducedFlash";

        public static string SelectedUniverseId
        {
            get => PlayerPrefs.GetString(K_Universe, "space");
            set { PlayerPrefs.SetString(K_Universe, value); PlayerPrefs.Save(); }
        }
        public static string SelectedModeId
        {
            get => PlayerPrefs.GetString(K_Mode, "estrella");
            set { PlayerPrefs.SetString(K_Mode, value); PlayerPrefs.Save(); }
        }
        public static string Lang
        {
            get => PlayerPrefs.GetString(K_Lang, "es");
            set { PlayerPrefs.SetString(K_Lang, value); PlayerPrefs.Save(); }
        }
        public static float Music
        {
            get => PlayerPrefs.GetFloat(K_Music, 0.7f);
            set { PlayerPrefs.SetFloat(K_Music, Mathf.Clamp01(value)); PlayerPrefs.Save(); }
        }
        public static float Sfx
        {
            get => PlayerPrefs.GetFloat(K_Sfx, 1f);
            set { PlayerPrefs.SetFloat(K_Sfx, Mathf.Clamp01(value)); PlayerPrefs.Save(); }
        }
        public static bool Fullscreen
        {
            get => PlayerPrefs.GetInt(K_Full, Screen.fullScreen ? 1 : 0) == 1;
            set { PlayerPrefs.SetInt(K_Full, value ? 1 : 0); PlayerPrefs.Save(); Screen.fullScreen = value; }
        }
        public static bool ReducedFlash
        {
            get => PlayerPrefs.GetInt(K_Flash, 0) == 1;
            set { PlayerPrefs.SetInt(K_Flash, value ? 1 : 0); PlayerPrefs.Save(); }
        }
    }
}
