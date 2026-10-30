using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Displays the game's move history in standard algebraic notation.
    /// Each row shows: move number, white move, black move.
    /// </summary>
    public class MoveHistoryPanel : MonoBehaviour
    {
        [SerializeField] private int maxEntries = 200;

        private ScrollView _scrollView;
        private VisualElement _root;
        private List<MoveEntry> _moves = new List<MoveEntry>();
        private int _moveNumber = 1;

        public struct MoveEntry
        {
            public int moveNumber;
            public string whiteMove;
            public string blackMove;
        }

        public static MoveHistoryPanel Instance { get; private set; }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
        }

        /// <summary>Initializes the panel with a UI Toolkit root element.</summary>
        public void Initialize(VisualElement root)
        {
            _root = root;
            _scrollView = root.Q<ScrollView>("move-history-scroll");

            if (_scrollView == null)
            {
                _scrollView = new ScrollView();
                _scrollView.name = "move-history-scroll";
                _scrollView.AddToClassList("move-history-scroll");
                _scrollView.mode = ScrollViewMode.Vertical;
                _scrollView.horizontalScrollerVisibility = ScrollerVisibility.Hidden;
                root.Add(_scrollView);
            }

            Clear();
        }

        /// <summary>Records a white or black move in algebraic notation.</summary>
        /// <param name="notation">Standard algebraic notation (e.g., "e4", "Nf3", "O-O")</param>
        /// <param name="team">Which team made the move.</param>
        public void RecordMove(string notation, TeamColor team)
        {
            if (string.IsNullOrEmpty(notation)) return;

            if (team == TeamColor.White)
            {
                // Start a new row for white's move
                _moves.Add(new MoveEntry
                {
                    moveNumber = _moveNumber,
                    whiteMove = notation,
                    blackMove = ""
                });
            }
            else
            {
                // Fill in black's move on the last row
                if (_moves.Count > 0)
                {
                    var last = _moves[_moves.Count - 1];
                    last.blackMove = notation;
                    _moves[_moves.Count - 1] = last;
                }
                _moveNumber++;
            }

            // Tope de memoria del panel: recorta las filas más viejas.
            while (_moves.Count > maxEntries) _moves.RemoveAt(0);

            RebuildUI();
        }

        /// <summary>Clears all history and resets the move counter.</summary>
        public void Clear()
        {
            _moves.Clear();
            _moveNumber = 1;
            if (_scrollView != null)
                _scrollView.Clear();
        }

        /// <summary>Exports the full move history as a PGN-compatible string.</summary>
        public string ExportPGN()
        {
            var sb = new System.Text.StringBuilder();
            foreach (var entry in _moves)
            {
                sb.Append($"{entry.moveNumber}. {entry.whiteMove}");
                if (!string.IsNullOrEmpty(entry.blackMove))
                    sb.Append($" {entry.blackMove}");
                sb.Append(" ");
            }
            return sb.ToString().Trim();
        }

        private void RebuildUI()
        {
            if (_scrollView == null) return;

            _scrollView.Clear();

            for (int i = 0; i < _moves.Count; i++)
            {
                var entry = _moves[i];
                var row = new VisualElement();
                row.AddToClassList("move-history-row");
                row.AddToClassList(i % 2 == 0 ? "row-even" : "row-odd");
                if (i == _moves.Count - 1) row.AddToClassList("last-move");

                var numLabel = new Label($"{entry.moveNumber}.");
                numLabel.AddToClassList("move-history-num");
                row.Add(numLabel);

                var whiteLabel = new Label(string.IsNullOrEmpty(entry.whiteMove) ? "—" : entry.whiteMove);
                whiteLabel.AddToClassList("move-history-move");
                whiteLabel.AddToClassList("move-white");
                row.Add(whiteLabel);

                var blackLabel = new Label(entry.blackMove);
                blackLabel.AddToClassList("move-history-move");
                if (string.IsNullOrEmpty(entry.blackMove))
                {
                    blackLabel.AddToClassList("move-empty");
                    blackLabel.text = "…";
                }
                else
                {
                    blackLabel.AddToClassList("move-black");
                }
                row.Add(blackLabel);

                _scrollView.Add(row);
            }

            // Auto-scroll to bottom
            if (_scrollView.contentContainer != null && _moves.Count > 0)
            {
                _scrollView.scrollOffset = new Vector2(0, float.MaxValue);
            }
        }
    }
}
