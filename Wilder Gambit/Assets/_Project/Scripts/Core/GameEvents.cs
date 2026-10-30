using System;
using UnityEngine;
using WilderGambit.AI;
using WilderGambit.Pieces;

namespace WilderGambit.Core
{
    /// <summary>Una captura: qué pieza, de quién y quién la hizo.</summary>
    public struct CaptureInfo
    {
        public PieceType type;
        public TeamColor capturedColor;
        public TeamColor byColor;
    }

    /// <summary>Resumen de una partida terminada. Lo usan misiones, logros y la economía.</summary>
    public struct MatchSummary
    {
        public DifficultyLevel level;
        public MatchOutcome outcome;
        public int totalTurns;        // jugadas totales (ambos bandos)
        public int playerTurns;
        public float accuracy;        // 0-100
        public int blunders;
        public int playerCaptures;
        public int playerLosses;
        public bool lostQueen;
        public bool usedLancer;
        public bool usedNecromancer;

        public bool IsVictory => outcome == MatchOutcome.Victory;
    }

    /// <summary>Cómo fue una sesión de entrenamiento táctico o el reto diario.</summary>
    public struct TrainingSummary
    {
        public bool dailyChallenge;
        public bool practice;  // sesión sin premio: la pagada del día ya se cobró
        public int target;
        public int resolved;
        public int solved;
        public int gambits;   // Gambits ya cobrados por los puzzles
        public int rating;
        public int reward;    // pago pendiente del reto diario
    }

    /// <summary>
    /// Bus estático de eventos de juego. Gameplay publica (Raise…), los sistemas de
    /// progreso escuchan. Se limpia al entrar en Play para no arrastrar suscriptores
    /// entre sesiones.
    /// </summary>
    public static class GameEvents
    {
        public static event Action<CaptureInfo> OnPieceCaptured;
        public static event Action<MatchSummary> OnMatchFinished;
        public static event Action<Puzzle, bool> OnPuzzleSolved;   // puzzle, true = limpio (sin fallar)
        public static event Action<Puzzle> OnPuzzleFailed;
        public static event Action<Puzzle> OnDailyChallengeCompleted;

        public static void RaisePieceCaptured(CaptureInfo info) => OnPieceCaptured?.Invoke(info);
        public static void RaiseMatchFinished(MatchSummary summary) => OnMatchFinished?.Invoke(summary);
        public static void RaisePuzzleSolved(Puzzle puzzle, bool clean) => OnPuzzleSolved?.Invoke(puzzle, clean);
        public static void RaisePuzzleFailed(Puzzle puzzle) => OnPuzzleFailed?.Invoke(puzzle);
        public static void RaiseDailyChallengeCompleted(Puzzle puzzle) => OnDailyChallengeCompleted?.Invoke(puzzle);

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.SubsystemRegistration)]
        private static void ResetStatics()
        {
            OnPieceCaptured = null;
            OnMatchFinished = null;
            OnPuzzleSolved = null;
            OnPuzzleFailed = null;
            OnDailyChallengeCompleted = null;
        }
    }
}
