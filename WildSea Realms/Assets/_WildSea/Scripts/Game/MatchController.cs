using System.Collections.Generic;
using System.Linq;

namespace WildSea.Game
{
    public class PlayerState
    {
        public int index;
        public bool isHuman;

        /// <summary>
        /// El mazo del jugador: la coleccion de cartas que tiene desbloqueadas del
        /// Universo. Es la fuente de TODO lo que le toca, y es lo unico que existe:
        /// no hay bolsa compartida (ver MatchState).
        /// </summary>
        public List<CardDef> collection = new();

        /// <summary>
        /// Pila de robo. Se vacia a medida que se roba y, cuando se acaba, se
        /// re-baraja ENTERA desde <see cref="collection"/>. Por eso una carta que
        /// ya salio vuelve a salir: no hay forma de quedarse sin ella.
        /// </summary>
        public List<CardDef> deck = new();

        /// <summary>Carta que se robo recien, la que se puede volver a reponer.</summary>
        public List<CardDef> hand = new();

        /// <summary>Cartas jugadas: objetivo o protector.</summary>
        public List<CardDef> board = new();

        /// <summary>
        /// Cartas jugadas que NO sirven para el objetivo: son las que se pueden
        /// sacrificar para defender. Necesita el objetivo porque "sirve" depende
        /// del objetivo de la partida, no de la carta sola.
        /// </summary>
        public List<CardDef> Protectors(ObjectiveDef obj)
        {
            if (obj == null) return board.ToList();
            return board.Where((c, i) => !obj.IsBoardCardRequired(board, i)).ToList();
        }
    }

    public class MatchState
    {
        public ObjectiveDef objective;
        public PlayerState[] players;
        public int activePlayer;
        public int? winner;
        public List<string> log = new();
        public PendingAttack pendingAttack;
        public CombatResolution lastCombat;

        public void Log(string msg)
        {
            log.Add(msg);
            if (log.Count > 40) log.RemoveAt(0);
        }

        public PlayerState Active => players[activePlayer];
    }

    /// <summary>Combate pausado mientras la persona atacada elige su defensa.</summary>
    public sealed class PendingAttack
    {
        public int attackerIndex;
        public int defenderIndex;
        public int victimBoardIndex;
        public CardDef attackerCard;
        public CardDef victimCard;
        public List<CardDef> protectors = new();
    }

    /// <summary>Cartas que vuelven a las pilas de sus respectivos dueños.</summary>
    public sealed class CombatResolution
    {
        public int attackerIndex;
        public CardDef attackerCard;
        public int returnedOwnerIndex;
        public CardDef returnedCard;
        public bool victimSaved;
    }

    /// <summary>
    /// Modo clasico del Universo Espacio.
    ///
    /// Loop: robas 1, y jugas/fusionas/atacas cuantas veces quieras hasta apretar
    /// "Terminar turno". El ataque NO consume el turno.
    ///
    /// Reglas:
    ///   - JUGAR: la carta va al tablero. Si su categoria+subcategoria matchean el
    ///     objetivo, sirve; si no, es protector.
    ///   - GALAXIA: si sirve al objetivo, se juega en la mesa y puede ser atacada como
    ///     cualquier objetivo. Si no hace falta para el objetivo, se puede canjear por
    ///     1 Estrella o 3 Planetas de la coleccion propia; la Galaxia vuelve a su mazo.
    ///   - FUSIONAR: 3 cartas de la misma categoria -> 1 de la categoria siguiente,
    ///     tomada de la propia coleccion del jugador. Las 3 se consumen.
    ///   - ATACAR: el objetivo siempre es una carta ya jugada del rival. La carta
    ///     atacante sale de la mano. Cada carta retirada regresa a la pila del jugador
    ///     al que pertenece; nunca se transfiere ni desbloquea en el otro mazo.
    ///     Si el objetivo sirve para la meta y su dueño tiene protectores, puede elegir
    ///     sacrificar uno para salvarla o sacrificar la carta atacada.
    ///   - VICTORIA: el primero que tenga jugadas todas las cartas que pide el objetivo.
    ///
    /// MAZOS: cada jugador tiene el suyo y se re-baraja cuando se acaba. No hay bolsa
    /// compartida, asi que no existe el bloqueo por falta de cartas: robar siempre
    /// funciona. Los dos jugadores no se pelean por las mismas cartas, y el conflicto
    /// esta en ATAQUEAR el tablero del rival, no en negarle la escalera.
    /// </summary>
    public static class MatchController
    {
        public const int FusionCost = 3;     // 3 cartas de la misma categoria
        public const int HandLimit = 10;     // tope de mano
        public const int DeckDraw = 1;       // 1 carta por turno
        public const int OpeningHand = 5;    // mano inicial garantizada

        public static MatchState NewGame(bool humanFirst = true, ObjectiveDef objective = null)
        {
            var s = new MatchState
            {
                objective = objective ?? ObjectiveCatalog.PickRandom(),
                activePlayer = 0,
            };

            s.players = new PlayerState[2];
            for (int i = 0; i < 2; i++)
            {
                // isHuman vale SOLO para el jugador 1: el rival lo lleva WSAI.
                // Antes era false para el segundo, y como no existia ninguna IA, la
                // UI deshabilitaba el boton de terminar y la partida se trababa en el
                // segundo turno.
                var ps = new PlayerState { index = i, isHuman = (i == 0) };

                // Hoy los dos empiezan con la misma coleccion (el Universo Espacio
                // completo). La capa de desbloqueos, que hara que un jugador nuevo
                // tenga menos cartas, va en el punto de abajo.
                ps.collection = CardPool.BuildPlayerDeck();
                ps.deck = new List<CardDef>(ps.collection);
                CardPool.Shuffle(ps.deck);
                s.players[i] = ps;

                // Mano inicial: 5 OBJETOS garantizados, TOMADOS DE LA PILA (no
                // apilados aparte, asi la coleccion y la pila nunca se separan).
                // Son el pie de la escalera y lo que asegura que un jugador nuevo
                // pueda jugar. Antes salian 5 asteroides, que es el segundo peldan:
                // con ellos el objetivo "Cinturon de Asteroides x3" ya venia completo
                // en la mano y la partida terminaba en el primer clic.
                ps.hand.AddRange(TakeObjects(ps, OpeningHand));
            }

            s.Log($"Objetivo: {s.objective.name}.");
            for (int i = 0; i < s.players.Length; i++)
                s.Log($"{Name(i)} arranca con {s.players[i].hand.Count} cartas.");
            return s;
        }

        /// <summary>
        /// Saca n Objetos de la pila de robo. Si la coleccion del jugador no tiene
        /// tantos (un jugador nuevo con pocos desbloqueos), completa con lo que haya
        /// en vez de romper.
        /// </summary>
        static List<CardDef> TakeObjects(PlayerState p, int n)
        {
            var taken = new List<CardDef>();
            for (int i = 0; i < n; i++)
            {
                int idx = p.deck.FindIndex(c => c.category == BodyCategory.Object);
                if (idx < 0)
                {
                    // No quedan Objetos: se completa con la ultima carta del mazo.
                    if (p.deck.Count == 0) break;
                    taken.Add(p.deck[p.deck.Count - 1]);
                    p.deck.RemoveAt(p.deck.Count - 1);
                    continue;
                }
                taken.Add(p.deck[idx]);
                p.deck.RemoveAt(idx);
            }
            return taken;
        }

        public static void StartTurn(MatchState s)
        {
            if (s.winner.HasValue) return;
            Draw(s.Active, DeckDraw);
        }

        // ── Mazo personal ────────────────────────────────────────────────
        /// <summary>
        /// Roba n cartas del mazo del jugador. Cuando la pila se acaba se re-baraja
        /// entera desde su coleccion y sigue: nunca puede quedar sin cartas para
        /// robar. Ese re-baraje es lo que hace imposible el bloqueo por mazo vacio,
        /// que antes existía porque las cartas se sacaban del mago grande para
        /// siempre y la partida se colgaba en silencio.
        /// </summary>
        public static void Draw(PlayerState p, int n)
        {
            for (int i = 0; i < n; i++)
            {
                if (p.hand.Count >= HandLimit) break;
                if (p.deck.Count == 0) Repile(p);
                p.hand.Add(p.deck[p.deck.Count - 1]);
                p.deck.RemoveAt(p.deck.Count - 1);
            }
        }

        /// <summary>Vuelve a poner toda la coleccion en la pila de robo, barajada.</summary>
        public static void Repile(PlayerState p)
        {
            p.deck.Clear();
            p.deck.AddRange(p.collection);
            CardPool.Shuffle(p.deck);
        }

        // ── JUGAR ────────────────────────────────────────────────────────
        public static bool Play(MatchState s, int playerIndex, int handIndex)
        {
            if (s.winner.HasValue || s.pendingAttack != null) return false;
            if (playerIndex != s.activePlayer) return false;
            var p = s.players[playerIndex];
            if (handIndex < 0 || handIndex >= p.hand.Count) return false;

            var c = p.hand[handIndex];
            p.hand.RemoveAt(handIndex);
            p.board.Add(c);

            bool sirve = IsNeededForObjective(s, p, c);
            // El ternario va entre parentesis: sin ellos el ":" cierra la interpolacion.
            s.Log(playerIndex == 0
                ? $"Jugador juega {c.name} ({(sirve ? "sirve" : "protector")})."
                : "Rival juega una carta.");

            if (s.objective.IsComplete(p.board)) Win(s, playerIndex);
            return true;
        }

        /// <summary>
        /// Puede canjearse una Galaxia que no haga falta para el objetivo por cartas
        /// de la coleccion del mismo jugador. Los Planetas requieren espacio para
        /// las tres cartas recibidas; nunca se desbloquean cartas con este efecto.
        /// </summary>
        public static bool CanExchangeGalaxy(MatchState s, int playerIndex, int handIndex, BodyCategory rewardTier)
        {
            if (s == null || s.players == null || s.objective == null || s.winner.HasValue || s.pendingAttack != null
                || playerIndex != s.activePlayer || playerIndex < 0 || playerIndex >= s.players.Length)
                return false;
            if (rewardTier != BodyCategory.Star && rewardTier != BodyCategory.Planet) return false;

            var p = s.players[playerIndex];
            if (p == null || handIndex < 0 || handIndex >= p.hand.Count) return false;
            var galaxy = p.hand[handIndex];
            if (galaxy == null || galaxy.category != BodyCategory.Galaxy) return false;
            if (IsNeededForObjective(s, p, galaxy)) return false;
            if (!p.collection.Any(c => c.category == rewardTier)) return false;

            int rewardCount = rewardTier == BodyCategory.Planet ? 3 : 1;
            return p.hand.Count - 1 + rewardCount <= HandLimit;
        }

        /// <summary>
        /// True solo mientras sumar esta carta todavía ayuda a completar una regla
        /// del objetivo; las copias que ya sobran pueden convertirse en recursos.
        /// </summary>
        public static bool IsNeededForObjective(MatchState s, PlayerState p, CardDef card)
        {
            if (s == null || s.objective == null || p == null || card == null) return false;
            return s.objective.rules.Any(r => r.Matches(card) && p.board.Count(r.Matches) < r.count);
        }

        /// <summary>
        /// Consume la Galaxia desde la mano, devuelve esa carta al mazo de su dueño
        /// y agrega cartas al azar de su coleccion propia. Los resultados no pueden
        /// venir del mazo rival ni de cartas aun bloqueadas.
        /// </summary>
        public static bool ExchangeGalaxy(MatchState s, int playerIndex, int handIndex, BodyCategory rewardTier)
        {
            if (!CanExchangeGalaxy(s, playerIndex, handIndex, rewardTier)) return false;

            var p = s.players[playerIndex];
            var galaxy = p.hand[handIndex];
            int rewardCount = rewardTier == BodyCategory.Planet ? 3 : 1;
            var rewards = new List<CardDef>(rewardCount);
            for (int i = 0; i < rewardCount; i++)
            {
                var reward = PickResult(p, rewardTier);
                if (reward == null) return false;
                rewards.Add(reward);
            }

            p.hand.RemoveAt(handIndex);
            ReturnToDeck(p, galaxy);
            p.hand.AddRange(rewards);
            s.Log(playerIndex == 0
                ? $"Jugador canjea una Galaxia por {(rewardTier == BodyCategory.Star ? "1 Estrella" : "3 Planetas")}."
                : "Rival canjea una carta por recursos.");
            return true;
        }

        // ── FUSIONAR ─────────────────────────────────────────────────────
        /// <summary>
        /// El resultado sale de la COLECCION del propio jugador, no de una bolsa
        /// comun: si las colecciones se vuelven asimetricas (capa de desbloqueos),
        /// cada uno fusiona con las cartas que el tiene.
        /// </summary>
        static CardDef PickResult(PlayerState p, BodyCategory tier)
        {
            var opts = p.collection.Where(c => c.category == tier).ToList();
            if (opts.Count == 0) return null;
            return opts[UnityEngine.Random.Range(0, opts.Count)];
        }

        public static bool CanFuse(MatchState s, PlayerState p)
        {
            if (s.winner.HasValue || s.pendingAttack != null || p == null) return false;
            foreach (var g in p.hand.GroupBy(c => c.category))
            {
                if (g.Count() < FusionCost) continue;
                var next = CardDef.NextTier(g.Key);
                if (next == g.Key) continue;                 // Galaxia no sube
                if (p.collection.Any(c => c.category == next)) return true;
            }
            return false;
        }

        public static bool Fuse(MatchState s, int playerIndex, BodyCategory tier)
        {
            if (s.winner.HasValue || s.pendingAttack != null || playerIndex != s.activePlayer) return false;
            var p = s.players[playerIndex];

            var trio = p.hand.Where(c => c.category == tier).Take(FusionCost).ToList();
            if (trio.Count < FusionCost) return false;

            var next = CardDef.NextTier(tier);
            if (next == tier) return false;

            var result = PickResult(p, next);
            if (result == null) return false;

            foreach (var c in trio) p.hand.Remove(c);
            p.hand.Add(result);

            s.Log(playerIndex == 0
                ? $"Jugador fusiona {FusionCost} x {tier} -> {result.name} ({next})."
                : $"Rival fusiona {FusionCost} cartas.");
            return true;
        }

        // ── ATACAR ───────────────────────────────────────────────────────
        /// <summary>
        /// Ataca una carta que el rival ya jugo. La carta atacante se consume de la
        /// mano. Si el objetivo sirve para la meta y el defensor es humano, el ataque
        /// queda pendiente para que elija entre gastar un protector o perder el
        /// objetivo. La IA siempre prefiere gastar un protector disponible.
        ///
        /// attackerHandIndex elige con que carta se ataca. Si se pasa -1 se usa la
        /// ultima de la mano, que era el comportamiento anterior (no habia forma de
        /// elegir). La UI pasa el indice de la carta que el jugador tiene seleccionada
        /// en la mano: atacar siempre con la ultima no era decision del jugador.
        /// </summary>
        public static bool Attack(MatchState s, int attackerIndex, int victimBoardIndex, int attackerHandIndex = -1)
        {
            if (s.winner.HasValue || s.pendingAttack != null || attackerIndex != s.activePlayer) return false;
            if (attackerIndex < 0 || attackerIndex > 1) return false;
            var atk = s.players[attackerIndex];
            var vic = s.players[1 - attackerIndex];

            if (victimBoardIndex < 0 || victimBoardIndex >= vic.board.Count) return false;
            if (atk.hand.Count == 0) return false;

            int wi = (attackerHandIndex >= 0 && attackerHandIndex < atk.hand.Count)
                   ? attackerHandIndex
                   : atk.hand.Count - 1;
            var weapon = atk.hand[wi];
            var victim = vic.board[victimBoardIndex];
            bool victimServes = s.objective.IsBoardCardRequired(vic.board, victimBoardIndex);
            atk.hand.Remove(weapon);
            s.lastCombat = null;

            var protectors = victimServes ? vic.Protectors(s.objective) : new List<CardDef>();
            if (victimServes && protectors.Count > 0 && vic.isHuman)
            {
                s.pendingAttack = new PendingAttack
                {
                    attackerIndex = attackerIndex,
                    defenderIndex = vic.index,
                    victimBoardIndex = victimBoardIndex,
                    attackerCard = weapon,
                    victimCard = victim,
                    protectors = protectors,
                };
                s.Log("Te atacaron una carta del objetivo: elegí tu defensa.");
                return true;
            }

            // El rival automático gasta un protector disponible antes que perder
            // una carta que sirve para completar el objetivo.
            var pending = new PendingAttack
            {
                attackerIndex = attackerIndex,
                defenderIndex = vic.index,
                victimBoardIndex = victimBoardIndex,
                attackerCard = weapon,
                victimCard = victim,
                protectors = protectors,
            };
            CompleteAttack(s, pending, protectors.Count > 0);
            return true;
        }

        /// <summary>Resuelve la elección de defensa y devuelve las cartas a sus dueños.</summary>
        public static bool ResolvePendingAttack(MatchState s, bool useProtector)
        {
            if (s == null || s.pendingAttack == null || s.winner.HasValue) return false;
            var pending = s.pendingAttack;
            bool canProtect = pending.protectors != null && pending.protectors.Count > 0;
            CompleteAttack(s, pending, useProtector && canProtect);
            s.pendingAttack = null;
            return true;
        }

        static void CompleteAttack(MatchState s, PendingAttack pending, bool useProtector)
        {
            var attacker = s.players[pending.attackerIndex];
            var defender = s.players[pending.defenderIndex];
            var victimStillOnBoard = defender.board.Contains(pending.victimCard);
            var protector = useProtector && pending.protectors != null
                ? pending.protectors.FirstOrDefault(c => defender.board.Contains(c))
                : null;

            if (protector != null)
            {
                defender.board.Remove(protector);
                ReturnToDeck(defender, protector);
                s.Log(pending.attackerIndex == 0
                    ? "El rival usó un protector; la carta atacada se salvó."
                    : "Usaste un protector; la carta atacada se salvó.");
                s.lastCombat = new CombatResolution
                {
                    attackerIndex = pending.attackerIndex,
                    attackerCard = pending.attackerCard,
                    returnedOwnerIndex = defender.index,
                    returnedCard = protector,
                    victimSaved = true,
                };
            }
            else if (victimStillOnBoard)
            {
                defender.board.Remove(pending.victimCard);
                ReturnToDeck(defender, pending.victimCard);
                s.Log(pending.attackerIndex == 0
                    ? "El ataque retiró una carta del rival."
                    : "El ataque retiró una de tus cartas.");
                s.lastCombat = new CombatResolution
                {
                    attackerIndex = pending.attackerIndex,
                    attackerCard = pending.attackerCard,
                    returnedOwnerIndex = defender.index,
                    returnedCard = pending.victimCard,
                    victimSaved = false,
                };
            }

            ReturnToDeck(attacker, pending.attackerCard);
        }

        /// <summary>
        /// Devuelve la carta a la pila de robo de quien la desbloqueó. El orden de
        /// colecciones queda intacto; al reciclar una pila agotada, la colección de
        /// su dueño vuelve a ser la fuente completa.
        /// </summary>
        static void ReturnToDeck(PlayerState owner, CardDef card)
        {
            if (owner == null || card == null) return;
            owner.deck.Insert(0, card);
        }

        static void Win(MatchState s, int playerIndex)
        {
            s.winner = playerIndex;
            s.Log($"Gana {Name(playerIndex)}: completo {s.objective.name}.");
        }

        public static void EndTurn(MatchState s)
        {
            if (s.winner.HasValue || s.pendingAttack != null) return;
            s.activePlayer = 1 - s.activePlayer;
            StartTurn(s);
        }

        public static string Name(int i) => i == 0 ? "Jugador" : "Rival";
    }
}
