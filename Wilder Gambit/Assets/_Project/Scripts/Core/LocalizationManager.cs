using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Simple localization system supporting Spanish and English.
    /// Load translations from Resources/Localization/ or use built-in defaults.
    /// </summary>
    public class LocalizationManager : MonoBehaviour
    {
        public static LocalizationManager Instance { get; private set; }

        private const string LANG_KEY = "GameLanguage";
        private Dictionary<string, string> _translations = new Dictionary<string, string>();

        public string CurrentLanguage { get; private set; } = "es";

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            CurrentLanguage = PlayerPrefs.GetString(LANG_KEY, "es");
            LoadLanguage(CurrentLanguage);
        }

        /// <summary>Switches language and reloads translations.</summary>
        public void SetLanguage(string lang)
        {
            CurrentLanguage = lang;
            PlayerPrefs.SetString(LANG_KEY, lang);
            PlayerPrefs.Save();
            LoadLanguage(lang);
        }

        /// <summary>Toggles between Spanish and English.</summary>
        public void ToggleLanguage()
        {
            SetLanguage(CurrentLanguage == "es" ? "en" : "es");
        }

        /// <summary>Gets a translated string by key.</summary>
        public string Get(string key)
        {
            return _translations.TryGetValue(key, out string val) ? val : key;
        }

        private void LoadLanguage(string lang)
        {
            _translations.Clear();

            if (lang == "en")
            {
                // English translations
                _translations["play"] = "PLAY";
                _translations["your_pieces"] = "YOUR PIECES";
                _translations["shop"] = "SHOP";
                _translations["settings"] = "SETTINGS";
                _translations["quit"] = "QUIT";
                _translations["back"] = "BACK";
                _translations["resume"] = "RESUME";
                _translations["restart"] = "RESTART";
                _translations["main_menu"] = "MAIN MENU";
                _translations["pause"] = "PAUSE";
                _translations["select_difficulty"] = "SELECT YOUR OPPONENT";
                _translations["novice"] = "Novice";
                _translations["apprentice"] = "Apprentice";
                _translations["knight"] = "Knight";
                _translations["master"] = "Master";
                _translations["grandmaster"] = "Grandmaster";
                _translations["fight"] = "FIGHT";
                _translations["check"] = "CHECK!";
                _translations["checkmate_white"] = "CHECKMATE! White wins!";
                _translations["checkmate_black"] = "CHECKMATE! Black wins!";
                _translations["stalemate"] = "STALEMATE! Draw.";
                _translations["draw"] = "DRAW";
                _translations["time_white"] = "White's time";
                _translations["time_black"] = "Black's time";
                _translations["move_history"] = "HISTORY";
                _translations["undo"] = "Undo last move";
                _translations["accuracy"] = "Accuracy";
                _translations["brilliant"] = "Brilliant";
                _translations["great"] = "Great";
                _translations["good"] = "Good";
                _translations["inaccuracy"] = "Inaccuracy";
                _translations["mistake"] = "Mistake";
                _translations["blunder"] = "Blunder";
                _translations["daily_challenge"] = "Daily Challenge";
                _translations["puzzles"] = "Puzzles";
                _translations["replay"] = "Replay";
                _translations["language"] = "Language";
                _translations["spanish"] = "Español";
                _translations["english"] = "English";
            }
            else
            {
                // Spanish (default) translations
                _translations["play"] = "JUGAR";
                _translations["your_pieces"] = "TUS PIEZAS";
                _translations["shop"] = "TIENDA";
                _translations["settings"] = "AJUSTES";
                _translations["quit"] = "SALIR";
                _translations["back"] = "VOLVER";
                _translations["resume"] = "REANUDAR";
                _translations["restart"] = "REINICIAR";
                _translations["main_menu"] = "MENÚ PRINCIPAL";
                _translations["pause"] = "PAUSA";
                _translations["select_difficulty"] = "SELECCIONA TU RIVAL";
                _translations["novice"] = "Principiante";
                _translations["apprentice"] = "Aprendiz";
                _translations["knight"] = "Caballero";
                _translations["master"] = "Maestro";
                _translations["grandmaster"] = "Gran Maestro";
                _translations["fight"] = "COMBATIR";
                _translations["check"] = "¡JAQUE!";
                _translations["checkmate_white"] = "¡JAQUE MATE! ¡Ganan las Blancas!";
                _translations["checkmate_black"] = "¡JAQUE MATE! ¡Ganan las Negras!";
                _translations["stalemate"] = "¡TABLAS! Empate.";
                _translations["draw"] = "EMPATE";
                _translations["time_white"] = "Tiempo Blancas";
                _translations["time_black"] = "Tiempo Negras";
                _translations["move_history"] = "HISTORIAL";
                _translations["undo"] = "Deshacer último movimiento";
                _translations["accuracy"] = "Precisión";
                _translations["brilliant"] = "Brillante";
                _translations["great"] = "Genial";
                _translations["good"] = "Buena";
                _translations["inaccuracy"] = "Inexactitud";
                _translations["mistake"] = "Error";
                _translations["blunder"] = "Berroque";
                _translations["daily_challenge"] = "Desafío Diario";
                _translations["puzzles"] = "Puzzles";
                _translations["replay"] = "Repetición";
                _translations["language"] = "Idioma";
                _translations["spanish"] = "Español";
                _translations["english"] = "English";
            }
        }
    }
}
