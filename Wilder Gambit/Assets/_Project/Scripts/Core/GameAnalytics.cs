using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Engine;

namespace WilderGambit.Core
{
    /// <summary>Quality rating for a single move.</summary>
    public enum MoveQuality
    {
        Brilliant,   // Sacrifice or deep tactic
        Great,       // Best or near-best move
        Good,        // Solid move
        Book,        // Opening theory
        Inaccuracy,  // Slight mistake
        Mistake,     // Clear mistake
        Blunder      // Major error
    }

    /// <summary>Records analytics for every move in a game.</summary>
    [System.Serializable]
    public class MoveAnalyticsEntry
    {
        public int moveNumber;
        public TeamColor team;
        public string notation;
        public MoveQuality quality;
        public float centipawnLoss; // Eval loss in centipawns
    }

    /// <summary>
    /// Tracks move quality and computes post-game statistics.
    /// </summary>
    public class GameAnalytics : MonoBehaviour
    {
        public static GameAnalytics Instance { get; private set; }

        private List<MoveAnalyticsEntry> _moves = new List<MoveAnalyticsEntry>();

        // Computed stats
        public float Accuracy { get; private set; }
        public int BrilliantCount { get; private set; }
        public int GreatCount { get; private set; }
        public int GoodCount { get; private set; }
        public int InaccuracyCount { get; private set; }
        public int MistakeCount { get; private set; }
        public int BlunderCount { get; private set; }
        public float AvgCentipawnLoss { get; private set; }
        public int TotalMoves => _moves.Count;

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
        }

        /// <summary>Records a move with its quality assessment.</summary>
        public void RecordMove(string notation, TeamColor team, MoveQuality quality, float centipawnLoss = 0f)
        {
            _moves.Add(new MoveAnalyticsEntry
            {
                moveNumber = (_moves.Count / 2) + 1,
                team = team,
                notation = notation,
                quality = quality,
                centipawnLoss = centipawnLoss
            });
        }

        /// <summary>Computes all statistics from recorded moves.</summary>
        public void ComputeStats()
        {
            BrilliantCount = 0; GreatCount = 0; GoodCount = 0;
            InaccuracyCount = 0; MistakeCount = 0; BlunderCount = 0;
            float totalLoss = 0f;

            foreach (var m in _moves)
            {
                switch (m.quality)
                {
                    case MoveQuality.Brilliant: BrilliantCount++; break;
                    case MoveQuality.Great:     GreatCount++; break;
                    case MoveQuality.Good:      GoodCount++; break;
                    case MoveQuality.Book:      GoodCount++; break; // Book counts as good
                    case MoveQuality.Inaccuracy: InaccuracyCount++; break;
                    case MoveQuality.Mistake:   MistakeCount++; break;
                    case MoveQuality.Blunder:   BlunderCount++; break;
                }
                totalLoss += m.centipawnLoss;
            }

            int total = _moves.Count;
            AvgCentipawnLoss = total > 0 ? totalLoss / total : 0f;

            // Accuracy: percentage of good-or-better moves
            int goodOrBetter = BrilliantCount + GreatCount + GoodCount;
            Accuracy = total > 0 ? (goodOrBetter * 100f / total) : 100f;
        }

        /// <summary>Returns all recorded moves.</summary>
        public List<MoveAnalyticsEntry> GetMoves() => new List<MoveAnalyticsEntry>(_moves);

        /// <summary>Clears all recorded data for a new game.</summary>
        public void Clear()
        {
            _moves.Clear();
            Accuracy = 0f;
            BrilliantCount = 0; GreatCount = 0; GoodCount = 0;
            InaccuracyCount = 0; MistakeCount = 0; BlunderCount = 0;
            AvgCentipawnLoss = 0f;
        }

        /// <summary>Polish: Stockfish integration — updates last recorded move with accurate quality.</summary>
        public void UpdateLastMoveQuality(MoveQuality newQuality, float centipawnLoss)
        {
            if (_moves.Count == 0) return;
            var last = _moves[_moves.Count - 1];
            last.quality = newQuality;
            last.centipawnLoss = centipawnLoss;
        }

        /// <summary>Maps Stockfish MoveClassification to analytics MoveQuality.</summary>
        public static MoveQuality MapClassification(MoveClassification c)
        {
            switch (c)
            {
                case MoveClassification.Brilliant: return MoveQuality.Brilliant;
                case MoveClassification.GreatMove:
                case MoveClassification.BestMove: return MoveQuality.Great;
                case MoveClassification.Excellent:
                case MoveClassification.Good:
                case MoveClassification.Book: return MoveQuality.Good;
                case MoveClassification.Inaccuracy: return MoveQuality.Inaccuracy;
                case MoveClassification.Mistake: return MoveQuality.Mistake;
                case MoveClassification.Blunder:
                case MoveClassification.MissedWin: return MoveQuality.Blunder;
                default: return MoveQuality.Good;
            }
        }
    }
}
