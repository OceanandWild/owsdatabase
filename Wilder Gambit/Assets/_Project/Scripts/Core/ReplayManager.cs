using System.Collections.Generic;
using System.Text;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Saves and replays chess games in PGN format.
    /// Stores the last 20 games in PlayerPrefs.
    /// </summary>
    public class ReplayManager : MonoBehaviour
    {
        public static ReplayManager Instance { get; private set; }

        private List<string> _currentMoves = new List<string>();
        private string _currentResult = "*";
        private string _currentOpponent = "AI";

        private const string STORAGE_KEY = "GameReplays";
        private const int MAX_GAMES = 20;

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
        }

        /// <summary>Records a move in UCI format during the current game.</summary>
        public void RecordMove(string uciMove)
        {
            _currentMoves.Add(uciMove);
        }

        /// <summary>Sets the game result and saves to storage.</summary>
        public void EndGame(string result, string opponent = "AI")
        {
            _currentResult = result;
            _currentOpponent = opponent;
            SaveGame();
        }

        /// <summary>Exports the current game as a PGN string.</summary>
        public string ExportCurrentGamePGN()
        {
            var sb = new StringBuilder();
            sb.AppendLine("[Event \"Wilder Gambit\"]");
            sb.AppendLine("[Site \"Local\"]");
            sb.AppendLine($"[Date \"{System.DateTime.Now:yyyy.MM.dd}\"]");
            sb.AppendLine("[White \"Player\"]");
            sb.AppendLine($"[Black \"{_currentOpponent}\"]");
            sb.AppendLine($"[Result \"{_currentResult}\"]");
            sb.AppendLine();

            for (int i = 0; i < _currentMoves.Count; i += 2)
            {
                int moveNum = (i / 2) + 1;
                sb.Append($"{moveNum}. {_currentMoves[i]}");
                if (i + 1 < _currentMoves.Count)
                    sb.Append($" {_currentMoves[i + 1]}");
                sb.Append(" ");
            }
            sb.Append(_currentResult);

            return sb.ToString();
        }

        /// <summary>Starts recording a new game.</summary>
        public void StartNewGame()
        {
            _currentMoves.Clear();
            _currentResult = "*";
            _currentOpponent = "AI";
        }

        private void SaveGame()
        {
            string pgn = ExportCurrentGamePGN();
            string existing = PlayerPrefs.GetString(STORAGE_KEY, "");

            // Prepend new game, limit to MAX_GAMES
            string[] games = string.IsNullOrEmpty(existing) ? new string[0] : existing.Split('\n');
            var allGames = new List<string>(games);
            allGames.Insert(0, pgn);

            while (allGames.Count > MAX_GAMES)
                allGames.RemoveAt(allGames.Count - 1);

            PlayerPrefs.SetString(STORAGE_KEY, string.Join("\n---\n", allGames));
            PlayerPrefs.Save();
        }

        /// <summary>Returns all saved games as PGN strings.</summary>
        public List<string> GetSavedGames()
        {
            string data = PlayerPrefs.GetString(STORAGE_KEY, "");
            if (string.IsNullOrEmpty(data)) return new List<string>();

            var games = new List<string>(data.Split(new[] { "\n---\n" }, System.StringSplitOptions.None));
            games.RemoveAll(g => string.IsNullOrWhiteSpace(g));
            return games;
        }

        /// <summary>Clears all saved replays.</summary>
        public void ClearAll()
        {
            PlayerPrefs.DeleteKey(STORAGE_KEY);
            PlayerPrefs.Save();
        }
    }
}
