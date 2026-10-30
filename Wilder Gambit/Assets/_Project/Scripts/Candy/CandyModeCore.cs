using System;
using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;

namespace WilderGambit.Candy
{
    /// <summary>
    /// Definiciones de la Cacería de Dulces, el modo temporal de la Velada.
    ///
    /// Todo el modo vive fuera de <see cref="Board"/> y de GameManager: el
    /// tablero de 12×12, las invocaciones y los Dulces no tocan las reglas de
    /// jaque mate del ajedrez normal. Así el modo se puede apagar el 2/11 sin
    /// dejar cicatrices en la partida clásica.
    /// </summary>
    public enum CandyGameMode
    {
        None = 0,
        Bot = 1,
        Online = 2
    }

    public enum CandyKind
    {
        Deploy = 0,
        Move = 1,
        Pass = 2
    }

    public enum CandyPhase
    {
        Closed = 0,
        Intro = 1,
        Draft = 2,
        Searching = 3,
        Playing = 4,
        Finished = 5
    }

    [Serializable]
    public class CandyVariantChoice
    {
        public string type;
        public string variant;
    }

    [Serializable]
    public class CandyLoadout
    {
        public CandyVariantChoice[] choices;

        public string Get(PieceType type)
        {
            if (choices != null)
            {
                for (int i = 0; i < choices.Length; i++)
                {
                    var c = choices[i];
                    if (c != null && string.Equals(c.type, type.ToString(), StringComparison.Ordinal))
                        return c.variant;
                }
            }
            return CandyCatalog.DefaultVariantFor(type).id;
        }

        public void Set(PieceType type, string variantId)
        {
            if (string.IsNullOrEmpty(variantId)) return;
            if (choices == null || choices.Length == 0)
                choices = new CandyVariantChoice[CandyCatalog.DraftOrder.Length];

            for (int i = 0; i < choices.Length; i++)
            {
                var c = choices[i];
                if (c != null && string.Equals(c.type, type.ToString(), StringComparison.Ordinal))
                {
                    c.variant = variantId;
                    return;
                }
            }

            for (int i = 0; i < choices.Length; i++)
            {
                if (choices[i] == null)
                {
                    choices[i] = new CandyVariantChoice { type = type.ToString(), variant = variantId };
                    return;
                }
            }

            var grown = new CandyVariantChoice[choices.Length + 1];
            Array.Copy(choices, grown, choices.Length);
            grown[choices.Length] = new CandyVariantChoice { type = type.ToString(), variant = variantId };
            choices = grown;
        }

        public CandyLoadout Clone()
        {
            var copy = new CandyLoadout { choices = new CandyVariantChoice[choices != null ? choices.Length : 0] };
            for (int i = 0; i < copy.choices.Length; i++)
            {
                copy.choices[i] = new CandyVariantChoice
                {
                    type = choices[i] != null ? choices[i].type : "",
                    variant = choices[i] != null ? choices[i].variant : ""
                };
            }
            return copy;
        }

        public void Normalize()
        {
            for (int i = 0; i < CandyCatalog.DraftOrder.Length; i++)
            {
                PieceType type = CandyCatalog.DraftOrder[i];
                string id = Get(type);
                if (CandyCatalog.Get(type, id) == null)
                    Set(type, CandyCatalog.DefaultVariantFor(type).id);
            }
        }

        public string ToJson() => JsonUtility.ToJson(this);

        public static CandyLoadout FromJson(string json)
        {
            if (string.IsNullOrEmpty(json)) return Default();
            try
            {
                var parsed = JsonUtility.FromJson<CandyLoadout>(json);
                if (parsed == null || parsed.choices == null || parsed.choices.Length == 0)
                    return Default();
                parsed.Normalize();
                return parsed;
            }
            catch
            {
                return Default();
            }
        }

        public static CandyLoadout Default()
        {
            var loadout = new CandyLoadout { choices = new CandyVariantChoice[CandyCatalog.DraftOrder.Length] };
            for (int i = 0; i < CandyCatalog.DraftOrder.Length; i++)
            {
                PieceType type = CandyCatalog.DraftOrder[i];
                loadout.choices[i] = new CandyVariantChoice
                {
                    type = type.ToString(),
                    variant = CandyCatalog.DefaultVariantFor(type).id
                };
            }
            return loadout;
        }

        public static CandyLoadout LoadSaved()
        {
            return FromJson(PlayerPrefs.GetString(CandyCatalog.LoadoutPrefKey, ""));
        }

        public void Save()
        {
            PlayerPrefs.SetString(CandyCatalog.LoadoutPrefKey, ToJson());
            PlayerPrefs.Save();
        }
    }

    public sealed class CandyVariantDef
    {
        public PieceType type;
        public string id;
        public string name;
        public string art;
        public string description;
        public int captureBonus;
        public bool spiderStep;
        public bool ghostSlide;
        public bool skeletonGuard;

        public CandyVariantDef(
            PieceType type, string id, string name, string art, string description,
            int captureBonus = 0, bool spiderStep = false, bool ghostSlide = false, bool skeletonGuard = false)
        {
            this.type = type;
            this.id = id;
            this.name = name;
            this.art = art;
            this.description = description;
            this.captureBonus = captureBonus;
            this.spiderStep = spiderStep;
            this.ghostSlide = ghostSlide;
            this.skeletonGuard = skeletonGuard;
        }

        public bool IsClassic => string.IsNullOrEmpty(art);
    }

    public struct CandyArmyEntry
    {
        public PieceType type;
        public int count;

        public CandyArmyEntry(PieceType type, int count)
        {
            this.type = type;
            this.count = count;
        }
    }

    /// <summary>
    /// Catálogo de la velada: ejército inicial, variantes desbloqueadas para
    /// este modo y arte de cada una. Las variantes son gratis aquí aunque el
    /// jugador no las tenga compradas.
    /// </summary>
    public static class CandyCatalog
    {
        public const int BoardSize = 12;
        public const float MatchSeconds = 360f;
        public const int InitialCandies = 16;
        public const int MaxCandies = 20;
        public const int DeploymentPerTurn = 1;
        public const string LoadoutPrefKey = "WG_CandyMode_Loadout_2026";

        public static readonly PieceType[] DraftOrder =
        {
            PieceType.Pawn,
            PieceType.Knight,
            PieceType.Bishop,
            PieceType.Rook,
            PieceType.Queen,
            PieceType.King
        };

        public static readonly CandyArmyEntry[] Army =
        {
            new CandyArmyEntry(PieceType.Pawn, 8),
            new CandyArmyEntry(PieceType.Knight, 2),
            new CandyArmyEntry(PieceType.Bishop, 2),
            new CandyArmyEntry(PieceType.Rook, 2),
            new CandyArmyEntry(PieceType.Queen, 1),
            new CandyArmyEntry(PieceType.King, 1)
        };

        private static readonly Dictionary<PieceType, List<CandyVariantDef>> Variants = BuildVariants();

        private static Dictionary<PieceType, List<CandyVariantDef>> BuildVariants()
        {
            var map = new Dictionary<PieceType, List<CandyVariantDef>>();

            map[PieceType.Pawn] = new List<CandyVariantDef>
            {
                new CandyVariantDef(PieceType.Pawn, "classic", "Peón clásico", null,
                    "El peón de siempre. Avanza y captura en diagonal."),
                new CandyVariantDef(PieceType.Pawn, "spider", "Peón Araña", HalloweenArt.PawnSpiderArt,
                    "Telaraña: también puede avanzar en diagonal a casillas vacías. +1 Dulce por captura.",
                    captureBonus: 1, spiderStep: true),
                new CandyVariantDef(PieceType.Pawn, "pumpkin", "Peón Calabaza", HalloweenArt.PawnPumpkinArt,
                    "Truco o trato: +1 Dulce extra por cada captura.", captureBonus: 1)
            };

            map[PieceType.Knight] = new List<CandyVariantDef>
            {
                new CandyVariantDef(PieceType.Knight, "classic", "Caballo clásico", null,
                    "Salto en L. La pieza más impredecible del tablero."),
                new CandyVariantDef(PieceType.Knight, "bat", "Caballo Murciélago", HalloweenArt.KnightBatArt,
                    "Vuelo rasante: +1 Dulce extra por captura.", captureBonus: 1),
                new CandyVariantDef(PieceType.Knight, "ghost", "Caballo Fantasma", HalloweenArt.KnightGhostArt,
                    "Niebla: además del salto en L, se desliza hasta 2 casillas en diagonal.",
                    ghostSlide: true),
                new CandyVariantDef(PieceType.Knight, "skeleton", "Caballo Esqueleto", "hwp_knight_skeleton",
                    "Huesos duros: los peones enemigos no pueden capturarlo.", skeletonGuard: true)
            };

            map[PieceType.Bishop] = new List<CandyVariantDef>
            {
                new CandyVariantDef(PieceType.Bishop, "classic", "Alfil clásico", null,
                    "Se desliza por las diagonales."),
                new CandyVariantDef(PieceType.Bishop, "vampire", "Alfil Vampiro", "hwp_bishop_vampire",
                    "Sed ancestral: +2 Dulces extra por captura.", captureBonus: 2)
            };

            map[PieceType.Rook] = new List<CandyVariantDef>
            {
                new CandyVariantDef(PieceType.Rook, "classic", "Torre clásica", null,
                    "Domina filas y columnas."),
                new CandyVariantDef(PieceType.Rook, "crypt", "Torre Cripta", HalloweenArt.RookCryptArt,
                    "Guardiana de la cripta: +1 Dulce extra por captura.", captureBonus: 1),
                new CandyVariantDef(PieceType.Rook, "grave", "Torre Tumba", HalloweenArt.RookGraveArt,
                    "Lápida pesada: +2 Dulces extra por captura.", captureBonus: 2)
            };

            map[PieceType.Queen] = new List<CandyVariantDef>
            {
                new CandyVariantDef(PieceType.Queen, "classic", "Dama clásica", null,
                    "La pieza más versátil del tablero."),
                new CandyVariantDef(PieceType.Queen, "witch", "Dama Bruja", "hwp_queen_witch",
                    "Brujería: +2 Dulces extra por captura.", captureBonus: 2)
            };

            map[PieceType.King] = new List<CandyVariantDef>
            {
                new CandyVariantDef(PieceType.King, "classic", "Rey clásico", null,
                    "Se mueve una casilla en cualquier dirección. No hay jaque mate aquí."),
                new CandyVariantDef(PieceType.King, "vampire", "Rey Vampiro", "hwp_king_vampire",
                    "Sangre real: +3 Dulces extra por captura.", captureBonus: 3)
            };

            return map;
        }

        public static List<CandyVariantDef> ForType(PieceType type)
        {
            if (Variants.TryGetValue(type, out var list) && list != null && list.Count > 0)
                return list;
            return new List<CandyVariantDef>
            {
                new CandyVariantDef(type, "classic", type.ToString(), null, "")
            };
        }

        public static CandyVariantDef Get(PieceType type, string id)
        {
            var list = ForType(type);
            for (int i = 0; i < list.Count; i++)
            {
                if (string.Equals(list[i].id, id, StringComparison.Ordinal))
                    return list[i];
            }
            return null;
        }

        public static CandyVariantDef DefaultVariantFor(PieceType type)
        {
            var list = ForType(type);
            for (int i = 0; i < list.Count; i++)
            {
                if (!list[i].IsClassic) return list[i];
            }
            return list[0];
        }

        public static Sprite LoadVariantSprite(PieceType type, string variantId, TeamColor side)
        {
            var variant = Get(type, variantId);
            if (variant != null && !string.IsNullOrEmpty(variant.art))
            {
                Sprite halloween = HalloweenArt.LoadSprite(variant.art);
                if (halloween != null) return halloween;
            }

            string folder = side == TeamColor.White ? "White" : "Black";
            Sprite classic = Resources.Load<Sprite>($"Pieces/{folder}/{type}");
            if (classic != null) return classic;

            // Respaldo: si el arte negro faltara, el blanco sigue siendo legible.
            return Resources.Load<Sprite>($"Pieces/White/{type}");
        }

        private static readonly Sprite[] CandySprites = new Sprite[4];
        private static readonly bool[] CandySpritesTried = new bool[4];

        /// <summary>
        /// Dulces del tablero: 1 ámbar, 2 rosa, 3 violeta. Se cargan una sola
        /// vez y, si el arte no está importado, el llamador cae al círculo CSS.
        /// </summary>
        public static Sprite LoadCandySprite(int value)
        {
            if (value < 1 || value > 3) return null;
            if (!CandySpritesTried[value])
            {
                CandySpritesTried[value] = true;
                CandySprites[value] = Resources.Load<Sprite>($"Pieces/Halloween/hwp_candy_{value}");
            }
            return CandySprites[value];
        }

        public static bool UsesHalloweenTint(PieceType type, string variantId, TeamColor side)
        {
            if (side != TeamColor.Black) return false;
            var variant = Get(type, variantId);
            return variant != null && !string.IsNullOrEmpty(variant.art);
        }

        public static int PieceValue(PieceType type)
        {
            switch (type)
            {
                case PieceType.Pawn: return 10;
                case PieceType.Knight: return 20;
                case PieceType.Bishop: return 20;
                case PieceType.Rook: return 28;
                case PieceType.Queen: return 55;
                case PieceType.King: return 75;
                default: return 15;
            }
        }

        public static string PieceLabel(PieceType type)
        {
            switch (type)
            {
                case PieceType.Pawn: return "PEÓN";
                case PieceType.Knight: return "CABALLO";
                case PieceType.Bishop: return "ALFIL";
                case PieceType.Rook: return "TORRE";
                case PieceType.Queen: return "DAMA";
                case PieceType.King: return "REY";
                default: return type.ToString().ToUpperInvariant();
            }
        }
    }

    public class CandyPiece
    {
        public int id;
        public TeamColor side;
        public PieceType type;
        public string variantId;
        public int row;
        public int col;
    }

    [Serializable]
    public class CandyAction
    {
        public string kind;
        public string type;
        public string variant;
        public int pieceId;
        public int row;
        public int col;
        public int side;
        public int seq;

        public static CandyAction Deploy(TeamColor side, PieceType type, string variant, int row, int col)
        {
            return new CandyAction
            {
                kind = "deploy",
                type = type.ToString(),
                variant = variant,
                row = row,
                col = col,
                side = side == TeamColor.White ? 0 : 1
            };
        }

        public static CandyAction Move(TeamColor side, int pieceId, int row, int col)
        {
            return new CandyAction
            {
                kind = "move",
                pieceId = pieceId,
                row = row,
                col = col,
                side = side == TeamColor.White ? 0 : 1
            };
        }

        public static CandyAction Pass(TeamColor side)
        {
            return new CandyAction
            {
                kind = "pass",
                side = side == TeamColor.White ? 0 : 1
            };
        }
    }

    public class CandyActionResult
    {
        public bool ok;
        public string error = "";
        public int candyCollected;
        public int captureBonus;
        public int scoreGained;
        public PieceType? capturedType;
        public bool capturedKing;
        public bool capturedQueen;
        public bool promoted;

        public static CandyActionResult Fail(string message)
        {
            return new CandyActionResult { ok = false, error = message ?? "Jugada inválida." };
        }

        public static CandyActionResult Success()
        {
            return new CandyActionResult { ok = true };
        }
    }
}
