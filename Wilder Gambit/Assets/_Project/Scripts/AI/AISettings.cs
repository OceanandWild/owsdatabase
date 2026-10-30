using UnityEngine;

namespace WilderGambit.AI
{
    public enum DifficultyLevel
    {
        Novice = 1,       // Nivel 1: Verde neón
        Apprentice = 2,   // Nivel 2: Azul eléctrico
        Knight = 3,       // Nivel 3: Dorado medieval
        Master = 4,       // Nivel 4: Crimson oscuro
        GrandMaster = 5   // Nivel 5: Cósmico violeta
    }

    [System.Serializable]
    public class AIConfig
    {
        public DifficultyLevel level;
        public string name;
        public Color themeColor;
        public int maxDepth;
        public bool usePST;
        public bool useQuiescence;
        public bool useTranspositionTable;
        public bool useOpeningBook;
        public bool aggressiveStyle;
        public float blunderQueenChance; // 0.8 (Novice), 0.4 (Apprentice), 0.15 (Knight), 0.05 (Master), 0.0 (GrandMaster)
        public int doubleThreatCounterSkill; // 0 (Ignora), 1 (Defensa básica), 2 (Contra-estrategia / Mate trampa)
    }

    public static class AIDifficultyPresets
    {
        public static AIConfig GetConfig(DifficultyLevel level)
        {
            switch (level)
            {
                case DifficultyLevel.Novice:
                    return new AIConfig
                    {
                        level = DifficultyLevel.Novice,
                        name = "Novice (Principiante)",
                        themeColor = new Color(0.1f, 0.9f, 0.3f), // Neon Green
                        maxDepth = 1,
                        usePST = false,
                        useQuiescence = false,
                        useTranspositionTable = false,
                        useOpeningBook = false,
                        aggressiveStyle = false,
                        blunderQueenChance = 0.8f,
                        doubleThreatCounterSkill = 0
                    };
                case DifficultyLevel.Apprentice:
                    return new AIConfig
                    {
                        level = DifficultyLevel.Apprentice,
                        name = "Apprentice (Aprendiz)",
                        themeColor = new Color(0.1f, 0.6f, 1.0f), // Electric Blue
                        maxDepth = 2,
                        usePST = true,
                        useQuiescence = false,
                        useTranspositionTable = false,
                        useOpeningBook = false,
                        aggressiveStyle = false,
                        blunderQueenChance = 0.4f,
                        doubleThreatCounterSkill = 0
                    };
                case DifficultyLevel.Knight:
                    return new AIConfig
                    {
                        level = DifficultyLevel.Knight,
                        name = "Knight (Caballero)",
                        themeColor = new Color(1.0f, 0.8f, 0.1f), // Epic Gold
                        maxDepth = 3,
                        usePST = true,
                        useQuiescence = true,
                        useTranspositionTable = true,
                        useOpeningBook = true,
                        aggressiveStyle = true,
                        blunderQueenChance = 0.08f,
                        doubleThreatCounterSkill = 0
                    };
                case DifficultyLevel.Master:
                    return new AIConfig
                    {
                        level = DifficultyLevel.Master,
                        name = "Master (Maestro)",
                        themeColor = new Color(0.9f, 0.15f, 0.2f), // Dark Crimson
                        maxDepth = 3,
                        usePST = true,
                        useQuiescence = true,
                        useTranspositionTable = true,
                        useOpeningBook = true,
                        aggressiveStyle = true,
                        blunderQueenChance = 0.0f,
                        doubleThreatCounterSkill = 1
                    };
                case DifficultyLevel.GrandMaster:
                default:
                    return new AIConfig
                    {
                        level = DifficultyLevel.GrandMaster,
                        name = "GrandMaster (Gran Maestro)",
                        themeColor = new Color(0.7f, 0.1f, 1.0f), // Cosmic Purple
                        maxDepth = 4,
                        usePST = true,
                        useQuiescence = true,
                        useTranspositionTable = true,
                        useOpeningBook = true,
                        aggressiveStyle = true,
                        blunderQueenChance = 0.0f,
                        doubleThreatCounterSkill = 2
                    };
            }
        }
    }
}
