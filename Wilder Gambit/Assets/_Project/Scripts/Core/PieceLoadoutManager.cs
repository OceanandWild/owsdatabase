using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Singleton estático que guarda y recupera la selección de variante de pieza del jugador.
    /// Usa PlayerPrefs para persistir entre sesiones.
    /// </summary>
    public static class PieceLoadoutManager
    {
        private const string KEY_BISHOP_WHITE = "Loadout_Bishop_White";
        private const string KEY_BISHOP_BLACK = "Loadout_Bishop_Black";
        private const string KEY_PAWN_WHITE   = "Loadout_Pawn_White";
        private const string KEY_PAWN_BLACK   = "Loadout_Pawn_Black";

        public const int LOADOUT_CLASSIC     = 0;
        public const int LOADOUT_NECROMANCER = 1;

        public const int LOADOUT_PAWN_CLASSIC = 0;
        public const int LOADOUT_PAWN_LANCER  = 1;

        /// <summary>Precio de la variante en Tides (divisa premium de Surface).</summary>
        public const int LANCER_PRICE_TIDES = 199;
        /// <summary>Precio legacy en Gambits (ya no se usa en tienda; el Lancero es premium).</summary>
        public const int LANCER_PRICE_GAMBITS = 400;
        private const string KEY_LANCER_OWNED = "Variant_Owned_Lancer";

        /// <summary>¿Posee el jugador la variante Peón Lancero? Se compra en la Tienda.</summary>
        public static bool IsLancerOwned()
        {
            return PlayerPrefs.GetInt(KEY_LANCER_OWNED, 0) == 1;
        }

        /// <summary>Marca la variante como comprada (la llama la Tienda al pagar en Gambits).</summary>
        public static void OwnLancer()
        {
            PlayerPrefs.SetInt(KEY_LANCER_OWNED, 1);
            PlayerPrefs.Save();
        }

        public static int GetBishopLoadout(TeamColor team)
        {
            string key = team == TeamColor.White ? KEY_BISHOP_WHITE : KEY_BISHOP_BLACK;
            int loadout = PlayerPrefs.GetInt(key, LOADOUT_CLASSIC);
            // El Alfil Fantasma se retiró del catálogo: cualquier loadout viejo (2)
            // vuelve al clásico para que el jugador no quede sin alfil equipado.
            if (loadout != LOADOUT_CLASSIC && loadout != LOADOUT_NECROMANCER)
            {
                loadout = LOADOUT_CLASSIC;
                PlayerPrefs.SetInt(key, loadout);
                PlayerPrefs.Save();
            }
            return loadout;
        }

        /// <summary>Precio del Alfil Nigromante en Gambits (divisa de juego).</summary>
        public const int NECROMANCER_PRICE_GAMBITS = 1000;
        private const string KEY_NECRO_OWNED = "Variant_Owned_Necromancer";

        /// <summary>¿Posee el jugador la variante Alfil Nigromante? Se compra en la Tienda.</summary>
        public static bool IsNecroOwned()
        {
            return PlayerPrefs.GetInt(KEY_NECRO_OWNED, 0) == 1;
        }

        /// <summary>Marca la variante como comprada (la llama la Tienda al pagar en Gambits).</summary>
        public static void OwnNecro()
        {
            PlayerPrefs.SetInt(KEY_NECRO_OWNED, 1);
            PlayerPrefs.Save();
        }

        public static bool UsesNecromancerBishop(TeamColor team)
        {
            // Gateo de propiedad: sin desbloquear en la Tienda nunca se usa en partida
            return IsNecroOwned() && GetBishopLoadout(team) == LOADOUT_NECROMANCER;
        }

        public static void SetBishopLoadout(TeamColor team, int loadout)
        {
            if (loadout != LOADOUT_CLASSIC && loadout != LOADOUT_NECROMANCER)
                loadout = LOADOUT_CLASSIC;

            if (loadout == LOADOUT_NECROMANCER && !IsNecroOwned())
            {
                Debug.Log("[PieceLoadoutManager] Alfil Nigromante no desbloqueado: cómpralo en la Tienda.");
                return;
            }

            string key = team == TeamColor.White ? KEY_BISHOP_WHITE : KEY_BISHOP_BLACK;
            PlayerPrefs.SetInt(key, loadout);
            PlayerPrefs.Save();
        }

        public static void ToggleBishopLoadout(TeamColor team)
        {
            int current = GetBishopLoadout(team);
            int next = (current == LOADOUT_CLASSIC) ? LOADOUT_NECROMANCER : LOADOUT_CLASSIC;
            SetBishopLoadout(team, next);
        }

        // ── Peón (variante Peón Lancero — pasiva «Lanza») ──────────────────

        public static int GetPawnLoadout(TeamColor team)
        {
            string key = team == TeamColor.White ? KEY_PAWN_WHITE : KEY_PAWN_BLACK;
            return PlayerPrefs.GetInt(key, LOADOUT_PAWN_CLASSIC);
        }

        public static bool UsesLancerPawn(TeamColor team)
        {
            // Gateo de propiedad: sin desbloquear en la Tienda nunca se usa en partida
            return IsLancerOwned() && GetPawnLoadout(team) == LOADOUT_PAWN_LANCER;
        }

        public static void SetPawnLoadout(TeamColor team, int loadout)
        {
            if (loadout == LOADOUT_PAWN_LANCER && !IsLancerOwned())
            {
                Debug.Log("[PieceLoadoutManager] Peón Lancero no desbloqueado: cómpralo en la Tienda.");
                return;
            }
            if (loadout == LOADOUT_PAWN_PUMPKIN && !IsPumpkinPawnOwned())
            {
                Debug.Log("[PieceLoadoutManager] Peón Calabaza no desbloqueado: cómpralo en la tienda de la velada.");
                return;
            }

            string key = team == TeamColor.White ? KEY_PAWN_WHITE : KEY_PAWN_BLACK;
            PlayerPrefs.SetInt(key, loadout);
            PlayerPrefs.Save();
        }

        public static void TogglePawnLoadout(TeamColor team)
        {
            int current = GetPawnLoadout(team);
            int next = (current == LOADOUT_PAWN_CLASSIC) ? LOADOUT_PAWN_LANCER : LOADOUT_PAWN_CLASSIC;
            SetPawnLoadout(team, next);
        }

        // ── Dama (variante Dama Jinete — pasiva «Cabalgada») ─────────────────

        private const string KEY_QUEEN_WHITE = "Loadout_Queen_White";
        private const string KEY_QUEEN_BLACK = "Loadout_Queen_Black";

        public const int LOADOUT_QUEEN_CLASSIC = 0;
        public const int LOADOUT_QUEEN_RIDER   = 1;

        /// <summary>
        /// Precio de la variante en Tides (divisa premium de Surface): es la
        /// primera variante premium de la tienda (las demás van en Gambits).
        /// </summary>
        public const int RIDER_PRICE_TIDES = 1500;
        private const string KEY_RIDER_OWNED = "Variant_Owned_Rider";

        /// <summary>¿Posee el jugador la variante Dama Jinete? Se compra en la Tienda.</summary>
        public static bool IsRiderOwned()
        {
            return PlayerPrefs.GetInt(KEY_RIDER_OWNED, 0) == 1;
        }

        /// <summary>Marca la variante como comprada (la llama la Tienda al pagar en Tides).</summary>
        public static void OwnRider()
        {
            PlayerPrefs.SetInt(KEY_RIDER_OWNED, 1);
            PlayerPrefs.Save();
        }

        public static int GetQueenLoadout(TeamColor team)
        {
            string key = team == TeamColor.White ? KEY_QUEEN_WHITE : KEY_QUEEN_BLACK;
            return PlayerPrefs.GetInt(key, LOADOUT_QUEEN_CLASSIC);
        }

        public static bool UsesRiderQueen(TeamColor team)
        {
            // Gateo de propiedad: sin desbloquear en la Tienda nunca se usa en partida
            return IsRiderOwned() && GetQueenLoadout(team) == LOADOUT_QUEEN_RIDER;
        }

        public static void SetQueenLoadout(TeamColor team, int loadout)
        {
            if (loadout == LOADOUT_QUEEN_RIDER && !IsRiderOwned())
            {
                Debug.Log("[PieceLoadoutManager] Dama Jinete no desbloqueada: cómprala en la Tienda.");
                return;
            }
            if (loadout == LOADOUT_QUEEN_VAMPIRE && !IsVampireOwned())
            {
                Debug.Log("[PieceLoadoutManager] Reina Vampira no desbloqueada: se cobra en la Vía Sangre de la velada.");
                return;
            }

            string key = team == TeamColor.White ? KEY_QUEEN_WHITE : KEY_QUEEN_BLACK;
            PlayerPrefs.SetInt(key, loadout);
            PlayerPrefs.Save();
        }

        /// <summary>
        /// Cicla la Dama entre las variantes que el jugador posee: 0 → 1 → 2 → 0.
        /// Sin la Jinete o la Vampira desbloqueadas, esas paradas se saltan.
        /// </summary>
        public static void ToggleQueenLoadout(TeamColor team)
        {
            int current = GetQueenLoadout(team);
            for (int step = 1; step <= 3; step++)
            {
                int next = (current + step) % 3;
                if (next == LOADOUT_QUEEN_CLASSIC
                    || (next == LOADOUT_QUEEN_RIDER && IsRiderOwned())
                    || (next == LOADOUT_QUEEN_VAMPIRE && IsVampireOwned()))
                {
                    SetQueenLoadout(team, next);
                    return;
                }
            }
        }

        // ── Dama (variante Reina Vampira — pasiva «No Muerta») ────────────────
        //
        // Exclusiva de la Vía Sangre de la velada. Comparte el ciclo de la Dama
        // con la Jinete: 0 clásica, 1 Jinete, 2 Vampira (solo entra si se posee).

        public const int LOADOUT_QUEEN_VAMPIRE = 2;

        private const string KEY_VAMPIRE_OWNED = "Variant_Owned_Vampire";

        /// <summary>¿Posee el jugador la variante Reina Vampira? Solo vía velada (Vía Sangre).</summary>
        public static bool IsVampireOwned()
        {
            return PlayerPrefs.GetInt(KEY_VAMPIRE_OWNED, 0) == 1;
        }

        /// <summary>Marca la variante como conseguida (la llama el pase al cobrar la Vía Sangre).</summary>
        public static void OwnVampire()
        {
            PlayerPrefs.SetInt(KEY_VAMPIRE_OWNED, 1);
            PlayerPrefs.Save();
        }

        /// <summary>
        /// ¿La Reina Vampira entra al tablero? Exige poseerla y tenerla elegida
        /// en el ciclo de la Dama (0 clásica · 1 Jinete · 2 Vampira).
        /// </summary>
        public static bool UsesVampireQueen(TeamColor team)
        {
            // Gateo de propiedad: sin cobrarla en la Vía Sangre nunca se usa en partida
            return IsVampireOwned() && GetQueenLoadout(team) == LOADOUT_QUEEN_VAMPIRE;
        }

        // ── Torre (variante Torre Fragua — pasiva «Sentencia», exclusiva del pase) ──
        //
        // Solo propiedad y equipamiento: la Torre Fragua todavía se genera como
        // torre clásica en el tablero (BoardView no la distingue) hasta que aterrice
        // su mecánica (FraguaRook + Sentencia/Tributo). Desbloquearla y equiparla
        // ahora es seguro: no cambia ninguna partida en curso.

        private const string KEY_ROOK_WHITE = "Loadout_Rook_White";
        private const string KEY_ROOK_BLACK = "Loadout_Rook_Black";

        public const int LOADOUT_ROOK_CLASSIC = 0;
        public const int LOADOUT_ROOK_FRAGUA  = 1;

        private const string KEY_FRAGUA_OWNED = "Variant_Owned_Fragua";

        /// <summary>¿Posee el jugador la variante Torre Fragua? Solo vía pase (Real 30).</summary>
        public static bool IsFraguaOwned()
        {
            return PlayerPrefs.GetInt(KEY_FRAGUA_OWNED, 0) == 1;
        }

        /// <summary>Marca la variante como conseguida (la llama el pase al cobrar el nivel 30 de la Vía real).</summary>
        public static void OwnFragua()
        {
            PlayerPrefs.SetInt(KEY_FRAGUA_OWNED, 1);
            PlayerPrefs.Save();
        }

        public static int GetRookLoadout(TeamColor team)
        {
            string key = team == TeamColor.White ? KEY_ROOK_WHITE : KEY_ROOK_BLACK;
            return PlayerPrefs.GetInt(key, LOADOUT_ROOK_CLASSIC);
        }

        public static bool UsesFraguaRook(TeamColor team)
        {
            // Gateo de propiedad: sin el 75 Real nunca se usa en partida
            return IsFraguaOwned() && GetRookLoadout(team) == LOADOUT_ROOK_FRAGUA;
        }

        public static void SetRookLoadout(TeamColor team, int loadout)
        {
            if (loadout == LOADOUT_ROOK_FRAGUA && !IsFraguaOwned())
            {
                Debug.Log("[PieceLoadoutManager] Torre Fragua no desbloqueada: corona el nivel 30 de la Vía real.");
                return;
            }

            string key = team == TeamColor.White ? KEY_ROOK_WHITE : KEY_ROOK_BLACK;
            PlayerPrefs.SetInt(key, loadout);
            PlayerPrefs.Save();
        }

        public static void ToggleRookLoadout(TeamColor team)
        {
            int current = GetRookLoadout(team);
            int next = (current == LOADOUT_ROOK_CLASSIC) ? LOADOUT_ROOK_FRAGUA : LOADOUT_ROOK_CLASSIC;
            SetRookLoadout(team, next);
        }

        // ══════════════════════════════════════════════════════════════════
        //  Variantes de la velada de Halloween (se compran con Dulces en la
        //  tienda del pase). El Peón Calabaza trae su pasiva y el Caballo
        //  Fantasma su pasiva + activa; un loadout por bando, igual que las
        //  demás variantes.
        // ══════════════════════════════════════════════════════════════════

        // ── Peón Calabaza ────────────────────────────────────────────────

        public const int LOADOUT_PAWN_PUMPKIN = 2;

        private const string KEY_PUMPKIN_OWNED = "Variant_Owned_PumpkinPawn";

        /// <summary>¿Posee el jugador la variante Peón Calabaza? Se compra en la tienda de la velada.</summary>
        public static bool IsPumpkinPawnOwned() => PlayerPrefs.GetInt(KEY_PUMPKIN_OWNED, 0) == 1;

        /// <summary>Marca la variante como comprada (la llama la tienda de la velada).</summary>
        public static void OwnPumpkinPawn()
        {
            PlayerPrefs.SetInt(KEY_PUMPKIN_OWNED, 1);
            PlayerPrefs.Save();
        }

        public static bool UsesPumpkinPawn(TeamColor team)
        {
            // Gateo de propiedad: sin comprarla en la tienda nunca se usa en partida
            return IsPumpkinPawnOwned() && GetPawnLoadout(team) == LOADOUT_PAWN_PUMPKIN;
        }

        // ── Caballo Fantasma ─────────────────────────────────────────────

        private const string KEY_KNIGHT_WHITE = "Loadout_Knight_White";
        private const string KEY_KNIGHT_BLACK = "Loadout_Knight_Black";

        public const int LOADOUT_KNIGHT_CLASSIC = 0;
        public const int LOADOUT_KNIGHT_GHOST   = 1;

        private const string KEY_GHOST_KNIGHT_OWNED = "Variant_Owned_GhostKnight";

        /// <summary>¿Posee el jugador la variante Caballo Fantasma?</summary>
        public static bool IsGhostKnightOwned() => PlayerPrefs.GetInt(KEY_GHOST_KNIGHT_OWNED, 0) == 1;

        /// <summary>Marca la variante como comprada (la llama la tienda de la velada).</summary>
        public static void OwnGhostKnight()
        {
            PlayerPrefs.SetInt(KEY_GHOST_KNIGHT_OWNED, 1);
            PlayerPrefs.Save();
        }

        public static int GetKnightLoadout(TeamColor team)
        {
            string key = team == TeamColor.White ? KEY_KNIGHT_WHITE : KEY_KNIGHT_BLACK;
            return PlayerPrefs.GetInt(key, LOADOUT_KNIGHT_CLASSIC);
        }

        public static bool UsesGhostKnight(TeamColor team)
        {
            // Gateo de propiedad: sin comprarla en la tienda nunca se usa en partida
            return IsGhostKnightOwned() && GetKnightLoadout(team) == LOADOUT_KNIGHT_GHOST;
        }

        public static void SetKnightLoadout(TeamColor team, int loadout)
        {
            if (loadout == LOADOUT_KNIGHT_GHOST && !IsGhostKnightOwned())
            {
                Debug.Log("[PieceLoadoutManager] Caballo Fantasma no desbloqueado: cómpralo en la tienda de la velada.");
                return;
            }

            string key = team == TeamColor.White ? KEY_KNIGHT_WHITE : KEY_KNIGHT_BLACK;
            PlayerPrefs.SetInt(key, loadout);
            PlayerPrefs.Save();
        }

        public static void ToggleKnightLoadout(TeamColor team)
        {
            int current = GetKnightLoadout(team);
            int next = (current == LOADOUT_KNIGHT_CLASSIC) ? LOADOUT_KNIGHT_GHOST : LOADOUT_KNIGHT_CLASSIC;
            SetKnightLoadout(team, next);
        }

        // ── QA de la tienda de la velada ─────────────────────────────────

        /// <summary>
        /// QA: revoca las dos compras de la velada (Peón Calabaza y Caballo
        /// Fantasma) y devuelve los loadouts al clásico para poder recomprarlas.
        /// Solo lo usa «Wilder Gambit › Halloween».
        /// </summary>
        public static void DebugRevokeShopVariants()
        {
            PlayerPrefs.DeleteKey(KEY_PUMPKIN_OWNED);
            PlayerPrefs.DeleteKey(KEY_GHOST_KNIGHT_OWNED);
            PlayerPrefs.Save();

            SetPawnLoadout(TeamColor.White, LOADOUT_PAWN_CLASSIC);
            SetPawnLoadout(TeamColor.Black, LOADOUT_PAWN_CLASSIC);
            SetKnightLoadout(TeamColor.White, LOADOUT_KNIGHT_CLASSIC);
            SetKnightLoadout(TeamColor.Black, LOADOUT_KNIGHT_CLASSIC);
        }

        /// <summary>
        /// QA: revoca la Reina Vampira (propiedad + equipamiento) para probar la
        /// Vía Sangre desde cero. No toca a la Dama Jinete si estaba equipada.
        /// Solo lo usa «Wilder Gambit › Halloween».
        /// </summary>
        public static void DebugRevokeVampire()
        {
            PlayerPrefs.DeleteKey(KEY_VAMPIRE_OWNED);
            PlayerPrefs.Save();

            if (GetQueenLoadout(TeamColor.White) == LOADOUT_QUEEN_VAMPIRE)
                SetQueenLoadout(TeamColor.White, LOADOUT_QUEEN_CLASSIC);
            if (GetQueenLoadout(TeamColor.Black) == LOADOUT_QUEEN_VAMPIRE)
                SetQueenLoadout(TeamColor.Black, LOADOUT_QUEEN_CLASSIC);
        }
    }
}
