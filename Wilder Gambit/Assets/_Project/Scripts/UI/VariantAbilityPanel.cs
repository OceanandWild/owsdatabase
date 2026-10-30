using System;
using System.Collections.Generic;
using System.Text;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.UIElements;
using WilderGambit.Core;
using WilderGambit.Pieces;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Panel de habilidades en partida: columna de la izquierda, de arriba abajo.
    ///
    /// Cada variante es una fila colapsada (sprite + nombre + tecla). Al pulsarla se
    /// despliega hacia ABAJO en el flujo normal, así que empuja a las filas de abajo en
    /// lugar de flotar encima. La ficha trae sprite grande, nombre, de quién es, qué
    /// hace y —solo si su habilidad es ACTIVA y no pasiva— el botón de activarla.
    ///
    /// Teclas: cada fila tiene una letra en un cuadrado negro. Con el desplegable
    /// cerrado, esa letra lo abre; con el desplegable abierto, pulsarla de nuevo activa
    /// la habilidad si está disponible (y si no, lo cierra).
    ///
    /// IMPORTANTE — por qué NO se reconstruye la lista en cada refresco:
    /// PauseMenuController llama a Refresh() cada 30 frames. Si Refresh() hiciera
    /// _list.Clear() siempre, el botón que el jugador está a punto de pulsar desaparecería
    /// entre el PointerDown y el PointerUp, y UI Toolkit nunca emitiría el ClickEvent.
    /// Aquí la lista solo se reconstruye cuando cambia el ESTADO; si el estado es el
    /// mismo se actualizan in situ los números y los botones, dejando el DOM quieto.
    /// </summary>
    public class VariantAbilityPanel : MonoBehaviour
    {
        public static VariantAbilityPanel Instance { get; private set; }

        /// <summary>Letras disponibles para las teclas, en orden. Se evitan WASD y flechas.</summary>
        private static readonly char[] KeyPool = { 'Q', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', 'A', 'S', 'D', 'F', 'G', 'H' };

        private static readonly Dictionary<char, Key> KeyMap = new Dictionary<char, Key>
        {
            { 'Q', Key.Q }, { 'E', Key.E }, { 'R', Key.R }, { 'T', Key.T }, { 'Y', Key.Y },
            { 'U', Key.U }, { 'I', Key.I }, { 'O', Key.O }, { 'P', Key.P }, { 'A', Key.A },
            { 'S', Key.S }, { 'D', Key.D }, { 'F', Key.F }, { 'G', Key.G }, { 'H', Key.H },
        };

        private VisualElement _root;
        private VisualElement _list;

        /// <summary>Clave del desplegable abierto (vacía = todos cerrados).</summary>
        private string _openKey = "";

        /// <summary>Firma del estado actual; si no cambia, no se toca el DOM.</summary>
        private string _signature = "";

        /// <summary>Nodos vivos por clave, para poder actualizarlos sin reconstruir.</summary>
        private readonly Dictionary<string, Node> _nodes = new Dictionary<string, Node>();

        /// <summary>Letra asignada a cada variante. Persiste aunque se repinte la lista,
        /// para que la tecla de una pieza no cambie mientras dura la partida.</summary>
        private readonly Dictionary<string, char> _letters = new Dictionary<string, char>();

        /// <summary>Piezas vivas de un desplegable: lo único que hay que refrescar.</summary>
        private sealed class Node
        {
            public string Name = "";
            public char Letter;
            public Entry Source;
            public VisualElement Wrap;
            public VisualElement Head;
            public VisualElement Body;
            public Button KeyBadge;
            public Label Chevron;
            public Label Badge;
            public Label Brief;
            public VisualElement Fill;
            public Button Action;
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
        }

        public void Initialize(VisualElement root)
        {
            _root = root;
            if (_root == null) return;
            _list = _root.Q<VisualElement>("ability-list");
            Refresh();
        }

        /// <summary>
        /// Teclas de habilidad. Se leen con el Input System (el mismo que usa el juego).
        /// Se ignoran con la partida parada, en pausa o con el menú de pausa abierto.
        /// </summary>
        private void Update()
        {
            if (_nodes.Count == 0) return;

            var kb = Keyboard.current;
            if (kb == null) return;

            var gm = GameManager.Instance;
            if (gm == null || !gm.IsGameActive || gm.IsPaused) return;
            if (PauseMenuController.Instance != null && PauseMenuController.Instance.IsOpen) return;

            foreach (var kv in _nodes)
            {
                if (!KeyMap.TryGetValue(kv.Value.Letter, out var key)) continue;
                if (!kb[key].wasPressedThisFrame) continue;

                PressKey(kv.Key);
                return;
            }
        }

        // ── Modelo de una variante ──────────────────────────────────────────────

        /// <summary>Todo lo que se pinta en un desplegable. <see cref="HasActive"/> decide
        /// si lleva botón: las habilidades solo pasivas no lo llevan.</summary>
        private sealed class Entry
        {
            public string Key = "";
            public string Name = "";
            public Sprite Sprite;
            public bool IsWhite;

            public string TypeChip = "PASIVA";
            public string TypeTip = "";
            public string CdChip = "";
            public string CdTip = "";
            public string Badge = "";
            public string BadgeTip = "";
            public bool BadgeReady;

            public string Brief = "";
            public string Note = "";

            /// <summary>0..1; negativo = sin barra de progreso.</summary>
            public float Progress = -1f;
            public bool ProgressAlmost;

            public bool HasActive;
            public string ActionText = "";
            public string ActionTip = "";
            public bool ActionEnabled;
            public Action OnAction;
        }

        // ── Refresco ───────────────────────────────────────────────────────────

        public void Refresh()
        {
            if (_root == null || _list == null) return;
            if (GameManager.Instance == null || BoardView.Instance == null) return;

            var board = FindAnyObjectByType<Board>();
            if (board == null) return;

            var entries = BuildEntries(board);

            if (entries.Count == 0)
            {
                Rebuild(new List<Entry>());
                var empty = new Label("Sin variantes activas.\nEquipa el Alfil Nigromante, el Peón Lancero, la Dama Jinete, la Reina Vampira, la Torre Fragua, el Caballo Fantasma o el Peón Calabaza en «Tus Piezas».");
                empty.AddToClassList("ability-empty");
                _list.Add(empty);
                return;
            }

            // ¿Cambió algo? Si no, solo se refrescan los valores in situ y el DOM
            // se queda como está (imprescindible para que el clic llegue al botón).
            string sig = Signature(entries);
            if (sig == _signature && _nodes.Count == entries.Count)
            {
                UpdateLive(entries);
                return;
            }

            Rebuild(entries);
        }

        /// <summary>Firma del estado visible. Si no cambia, no hay que repintar nada.</summary>
        private static string Signature(List<Entry> entries)
        {
            var sb = new StringBuilder();
            foreach (var e in entries)
            {
                sb.Append(e.Key).Append('|')
                  .Append(e.Badge).Append('|')
                  .Append(e.BadgeReady ? '1' : '0').Append('|')
                  .Append(e.CdChip).Append('|')
                  .Append(e.ActionText).Append('|')
                  .Append(e.ActionEnabled ? '1' : '0').Append('|')
                  .Append(e.Progress.ToString("F2")).Append(';');
            }
            return sb.ToString();
        }

        /// <summary>Refresca solo los valores que cambian (contadores, botón, barra).</summary>
        private void UpdateLive(List<Entry> entries)
        {
            foreach (var e in entries)
            {
                if (!_nodes.TryGetValue(e.Key, out var n)) continue;

                if (n.Badge != null)
                {
                    if (n.Badge.text != e.Badge) n.Badge.text = e.Badge;
                    n.Badge.EnableInClassList("ready", e.BadgeReady);
                }

                if (n.Brief != null && n.Brief.text != e.Brief) n.Brief.text = e.Brief;

                if (n.Fill != null && e.Progress >= 0f)
                    n.Fill.style.width = new Length(e.Progress * 100f, LengthUnit.Percent);

                if (n.Action != null)
                {
                    if (n.Action.text != e.ActionText) n.Action.text = e.ActionText;
                    if (n.Action.enabledSelf != e.ActionEnabled) n.Action.SetEnabled(e.ActionEnabled);
                    if (n.Action.tooltip != e.ActionTip) n.Action.tooltip = e.ActionTip;
                }

                // La tecla se ilumina cuando hay algo que activar
                if (n.KeyBadge != null)
                    n.KeyBadge.EnableInClassList("key-badge-ready", e.HasActive && e.ActionEnabled);

                // El botón puede pasar a ser inválido (ej. la pieza deja de tener almas)
                n.Source = e;
            }
        }

        private void Rebuild(List<Entry> entries)
        {
            _list.Clear();
            _nodes.Clear();

            foreach (var e in entries)
            {
                var node = BuildDropdown(e);
                _nodes[e.Key] = node;
                _list.Add(node.Wrap);
            }

            _signature = Signature(entries);
        }

        // ── Teclas ─────────────────────────────────────────────────────────────

        /// <summary>Letra estable de una variante: se asigna la primera vez y ya no cambia.</summary>
        private char LetterFor(string key)
        {
            if (_letters.TryGetValue(key, out char existing)) return existing;

            foreach (char c in KeyPool)
            {
                bool taken = false;
                foreach (var kv in _letters)
                {
                    if (kv.Value == c) { taken = true; break; }
                }
                if (taken) continue;

                _letters[key] = c;
                return c;
            }

            // Sin letras libres: se reutiliza la primera como marcador
            _letters[key] = KeyPool[0];
            return KeyPool[0];
        }

        /// <summary>Abre el desplegable indicado, o cierra todos si la clave es vacía.</summary>
        private void SetOpen(string key)
        {
            _openKey = key;
            foreach (var kv in _nodes)
            {
                bool shouldOpen = (kv.Key == key);
                kv.Value.Body.style.display = shouldOpen ? DisplayStyle.Flex : DisplayStyle.None;
                kv.Value.Chevron.text = shouldOpen ? "▼" : "▶";
                kv.Value.Wrap.EnableInClassList("ability-entry-open", shouldOpen);
                kv.Value.Head.tooltip = shouldOpen ? "Cerrar" : $"Ver {kv.Value.Name}";
            }
        }

        /// <summary>
        /// Pulsación de la tecla (o del cuadrado): cerrada la abre; abierta, activa la
        /// habilidad si está disponible y, si no, la cierra.
        /// </summary>
        private void PressKey(string key)
        {
            if (_openKey != key)
            {
                SetOpen(key);
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                return;
            }

            var n = _nodes[key];
            if (n.Action != null && n.Action.enabledSelf && n.Source?.OnAction != null)
            {
                n.Source.OnAction();
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                Refresh();
            }
            else
            {
                SetOpen("");
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            }
        }

        // ── Lectura del tablero ────────────────────────────────────────────────

        private List<Entry> BuildEntries(Board board)
        {
            var entries = new List<Entry>();

            for (int r = 0; r < Board.BOARD_SIZE; r++)
            for (int c = 0; c < Board.BOARD_SIZE; c++)
            {
                if (board.GetPieceAt(new Vector2IntCustom(r, c)) is NecromancerBishop necro)
                    entries.Add(BuildNecroEntry(necro));
            }

            int lancerW = 0, lancerB = 0, riderW = 0, riderB = 0, vampireW = 0, vampireB = 0;
            bool rideW = false, rideB = false, canRiseW = false, canRiseB = false;
            var fraguasW = new List<FraguaRook>();
            var fraguasB = new List<FraguaRook>();
            var ghosts = new List<GhostKnight>();
            int pumpkinW = 0, pumpkinB = 0;

            for (int r = 0; r < Board.BOARD_SIZE; r++)
            for (int c = 0; c < Board.BOARD_SIZE; c++)
            {
                switch (board.GetPieceAt(new Vector2IntCustom(r, c)))
                {
                    case LancerPawn lp:
                        if (lp.Team == TeamColor.White) lancerW++; else lancerB++;
                        break;
                    case VampireQueen vq:
                        if (vq.Team == TeamColor.White) { vampireW++; canRiseW |= vq.CanRise; }
                        else { vampireB++; canRiseB |= vq.CanRise; }
                        break;
                    case RiderQueen rq:
                        if (rq.Team == TeamColor.White) { riderW++; rideW |= rq.RideAvailable; }
                        else { riderB++; rideB |= rq.RideAvailable; }
                        break;
                    case FraguaRook fr:
                        if (fr.Team == TeamColor.White) fraguasW.Add(fr); else fraguasB.Add(fr);
                        break;
                    case GhostKnight gk:
                        ghosts.Add(gk);
                        break;
                    case PumpkinPawn pp:
                        if (pp.Team == TeamColor.White) pumpkinW++; else pumpkinB++;
                        break;
                }
            }

            if (lancerW > 0) entries.Add(BuildLancerEntry(TeamColor.White, lancerW));
            if (lancerB > 0) entries.Add(BuildLancerEntry(TeamColor.Black, lancerB));
            if (riderW > 0) entries.Add(BuildRiderEntry(TeamColor.White, riderW, rideW));
            if (riderB > 0) entries.Add(BuildRiderEntry(TeamColor.Black, riderB, rideB));
            if (vampireW > 0) entries.Add(BuildVampireEntry(TeamColor.White, vampireW, canRiseW));
            if (vampireB > 0) entries.Add(BuildVampireEntry(TeamColor.Black, vampireB, canRiseB));
            if (fraguasW.Count > 0) entries.Add(BuildFraguaEntry(TeamColor.White, fraguasW));
            if (fraguasB.Count > 0) entries.Add(BuildFraguaEntry(TeamColor.Black, fraguasB));
            foreach (var gk in ghosts) entries.Add(BuildGhostKnightEntry(gk));
            if (pumpkinW > 0) entries.Add(BuildPumpkinEntry(TeamColor.White, pumpkinW));
            if (pumpkinB > 0) entries.Add(BuildPumpkinEntry(TeamColor.Black, pumpkinB));

            return entries;
        }

        /// <summary>Alfil Nigromante: pasiva de cosecha + ACTIVA de resurrección.</summary>
        private Entry BuildNecroEntry(NecromancerBishop necro)
        {
            bool isWhite = necro.Team == TeamColor.White;
            bool can = necro.CanResurrect;
            bool isPlayerTurn = GameManager.Instance.CurrentTurn == TeamColor.White;

            var e = new Entry
            {
                Key = $"necro-{necro.Team}-{necro.Position.Row}-{necro.Position.Col}",
                Name = "Alfil Nigromante",
                Sprite = BoardView.Instance.GetPieceSprite(PieceType.NecromancerBishop, necro.Team),
                IsWhite = isWhite,

                TypeChip = "ACTIVA + PASIVA",
                TypeTip = "Pasiva: Cosecha de Almas · Activa: Alzamiento Menor",
                CdChip = "CD · 1 TURNO",
                CdTip = "Al invocar cedes tu turno (enfriamiento de 1 turno)",

                Badge = $"{necro.SoulCharges}/{necro.MaxCharges}",
                BadgeTip = "Almas acumuladas (hacen falta 4 para resucitar)",
                BadgeReady = can,

                Brief = can
                    ? "¡LISTO! Invoca un Peón Espectral en tu diagonal (cede tu turno)."
                    : "Invoca un Peón Espectral en tu diagonal · Ganas almas al capturar.",

                Progress = necro.SoulProgress,
                ProgressAlmost = necro.IsAlmostReady,

                HasActive = true,
                ActionText = can ? $"⚡ INVOCAR PEÓN — {necro.SoulCharges}/{necro.MaxCharges}" : $"Faltan {necro.MaxCharges - necro.SoulCharges} alma(s)",
                ActionTip = "Invoca un Peón Espectral en una casilla de tu diagonal",
                ActionEnabled = can && isWhite && isPlayerTurn && GameManager.Instance.IsGameActive && !GameManager.Instance.IsPaused,
                OnAction = () => GameManager.Instance?.RequestResurrection(necro),
            };

            if (!isWhite)
            {
                e.ActionText = "— Rival —";
                e.ActionEnabled = false;
                e.ActionTip = "Es una pieza del ejército rival: no puedes activarla";
            }
            else if (can && !isPlayerTurn)
            {
                e.ActionText = "Espera tu turno";
                e.ActionTip = "Solo se activa en tu turno";
            }

            return e;
        }

        /// <summary>Peón Lancero: PASIVA pura (la Lanza). Sin botón.</summary>
        private Entry BuildLancerEntry(TeamColor team, int count)
        {
            return new Entry
            {
                Key = $"lancer-{team}",
                Name = "Peón Lancero",
                Sprite = BoardView.Instance.GetLancerPawnSprite(team),
                IsWhite = team == TeamColor.White,

                TypeChip = "PASIVA",
                TypeTip = "Pasiva «Lanza»: puede capturar hacia adelante",
                CdChip = "SIN CD",
                CdTip = "La Lanza es permanente: no tiene enfriamiento",

                Badge = $"×{count}",
                BadgeTip = "Peones Lanceros en el tablero",

                Brief = "Captura hacia adelante además de en diagonal · Conserva avance simple y doble.",
                Note = "Su amenaza frontal cambia clavadas y jaques a la descubierta.",
                HasActive = false,
            };
        }

        /// <summary>Dama Jinete: pasiva 1×/partida. Sin botón (la Cabalgada se dispara moviendo).</summary>
        private Entry BuildRiderEntry(TeamColor team, int count, bool rideAvailable)
        {
            return new Entry
            {
                Key = $"rider-{team}",
                Name = "Dama Jinete",
                Sprite = BoardView.Instance.GetRiderQueenSprite(team),
                IsWhite = team == TeamColor.White,

                TypeChip = "PASIVA 1×/PARTIDA",
                TypeTip = "Pasiva «Cabalgada»: salta como un Caballo una vez por partida",
                CdChip = rideAvailable ? "LISTA" : "USADA",
                CdTip = rideAvailable
                    ? "La Cabalgada sigue disponible en esta partida"
                    : "La Cabalgada ya se usó en esta partida",

                Badge = $"×{count}",
                BadgeTip = "Damas Jinete en el tablero",
                BadgeReady = rideAvailable,

                Brief = rideAvailable
                    ? "¡LISTA! Mueve la Dama a una casilla de caballo para cabalgar (con captura)."
                    : "Cabalgada usada: juega como Dama clásica lo que queda de partida.",
                Note = "Un solo uso por partida y visible para el rival: el momento de gastarlo es la jugada.",
                HasActive = false,
            };
        }

        /// <summary>Reina Vampira: pasiva 1×/partida («No Muerta»). Sin botón.</summary>
        private Entry BuildVampireEntry(TeamColor team, int count, bool canRise)
        {
            return new Entry
            {
                Key = $"vampire-{team}",
                Name = "Reina Vampira",
                Sprite = BoardView.Instance.GetVampireQueenSprite(team),
                IsWhite = team == TeamColor.White,

                TypeChip = "PASIVA 1×/PARTIDA",
                TypeTip = "Pasiva «No Muerta»: si cae, renace una vez en su primera fila",
                CdChip = canRise ? "LISTA" : "USADA",
                CdTip = canRise
                    ? "La No Muerta sigue disponible en esta partida"
                    : "La No Muerta ya se usó en esta partida",

                Badge = $"×{count}",
                BadgeTip = "Reinas Vampiras en el tablero",
                BadgeReady = canRise,

                Brief = canRise
                    ? "¡LISTA! Si cae, renace en su primera fila una vez por partida."
                    : "Ya renació: si vuelve a caer, no regresa.",
                Note = "El rival puede negarte el regreso ocupando toda la fila.",
                HasActive = false,
            };
        }

        /// <summary>
        /// Caballo Fantasma: pasiva «Salto de Niebla» (tras capturar) + activa
        /// «Posesión» (intercambia casilla con un peón aliado a un salto).
        /// </summary>
        private Entry BuildGhostKnightEntry(GhostKnight knight)
        {
            bool isWhite = knight.Team == TeamColor.White;
            bool isPlayerTurn = GameManager.Instance.CurrentTurn == TeamColor.White;
            bool mist = knight.MistStepAvailable;
            bool poss = knight.PossessionAvailable;
            bool stunned = knight.IsStunned;
            int uses = (mist ? 1 : 0) + (poss ? 1 : 0);
            var targets = GameManager.Instance.GetPossessionTargets(knight);

            string cdChip;
            if (stunned) cdChip = $"ATURDIDO · {knight.StunTurns}";
            else if (mist && poss) cdChip = "SALTO + POSESIÓN";
            else if (mist) cdChip = "SALTO LISTO";
            else if (poss) cdChip = "POSESIÓN LISTA";
            else cdChip = "USADO";

            string brief;
            if (stunned)
                brief = $"Aturdido: no puede usar sus habilidades durante {knight.StunTurns} turno(s).";
            else if (mist && poss)
                brief = "Tras capturar, salta a una casilla libre a un salto de caballo · O cambia tu casilla con un peón aliado.";
            else if (mist)
                brief = "Salto de Niebla disponible · La Posesión ya se usó.";
            else if (poss)
                brief = "Posesión disponible · El Salto de Niebla ya se usó.";
            else
                brief = "Sin habilidades: juega como un Caballo clásico.";

            bool pending = GameManager.Instance.IsPossessionPending(knight);
            string actionText;
            if (!isWhite) actionText = "— Rival —";
            else if (stunned) actionText = $"Aturdido — {knight.StunTurns} turno(s)";
            else if (!poss) actionText = "Posesión usada";
            else if (!isPlayerTurn) actionText = "Espera tu turno";
            else if (targets.Count == 0) actionText = "Sin peones a un salto";
            else if (pending) actionText = "Elige un peón…";
            else actionText = $"POSESIÓN — {targets.Count} PEÓN(ES)";

            var e = new Entry
            {
                Key = $"ghost-{knight.Team}-{knight.GetEntityId()}",
                Name = "Caballo Fantasma",
                Sprite = BoardView.Instance.GetGhostKnightSprite(knight.Team),
                IsWhite = isWhite,

                TypeChip = "PASIVA + ACTIVA",
                TypeTip = "Pasiva «Salto de Niebla»: tras capturar, reaparece a un salto · Activa «Posesión»: cambia casilla con un peón aliado",
                CdChip = cdChip,
                CdTip = "Salto de Niebla: 1 uso por caballo · Posesión: 1 uso por caballo",

                Badge = $"{uses}/2",
                BadgeTip = "Habilidades disponibles: Salto de Niebla + Posesión",
                BadgeReady = uses > 0,

                Brief = brief,
                Note = "La Posesión consume el turno y no puede coronar al peón (la última fila queda vetada). El Salto de Niebla no captura en la segunda casilla.",

                HasActive = true,
                ActionText = actionText,
                ActionTip = "Cambia la casilla del caballo con un peón aliado situado a un salto de caballo",
                ActionEnabled = isWhite && isPlayerTurn && poss && !stunned && targets.Count > 0
                                && !pending
                                && GameManager.Instance.IsGameActive && !GameManager.Instance.IsPaused
                                && !GameManager.Instance.IsMistStepPending(knight),
                OnAction = () => GameManager.Instance?.RequestPossession(knight),
            };

            return e;
        }

        /// <summary>Peón Calabaza: pasiva 1×/bando («Explosión de Calabaza»). Sin botón.</summary>
        private Entry BuildPumpkinEntry(TeamColor team, int count)
        {
            bool exploded = GameManager.Instance.HasPumpkinExploded(team);

            return new Entry
            {
                Key = $"pumpkin-{team}",
                Name = "Peón Calabaza",
                Sprite = BoardView.Instance.GetPumpkinPawnSprite(team),
                IsWhite = team == TeamColor.White,

                TypeChip = "PASIVA 1×/BANDO",
                TypeTip = "Pasiva «Explosión de Calabaza»: el primer peón capturado aturde 2 turnos al capturador",
                CdChip = exploded ? "USADA" : "LISTA",
                CdTip = exploded
                    ? "La explosión de este bando ya se gastó"
                    : "El primer Peón Calabaza capturado explotará",

                Badge = $"×{count}",
                BadgeTip = "Peones Calabaza en el tablero",
                BadgeReady = !exploded,

                Brief = exploded
                    ? "Explosión usada: los Peones Calabaza restantes se capturan sin efecto."
                    : "¡LISTA! El primer Peón Calabaza capturado explota: el capturador queda aturdido 2 turnos.",
                Note = "El Rey es inmune, pero la carga se consume igualmente. Nunca destruye piezas.",
                HasActive = false,
            };
        }

        /// <summary>Torre Fragua: pasiva de brasas + ACTIVA de condena.</summary>
        private Entry BuildFraguaEntry(TeamColor team, List<FraguaRook> rooks)
        {
            bool isWhite = team == TeamColor.White;
            int sentencias = GameManager.Instance.GetSentencias(team);
            bool ready = sentencias > 0;
            bool isPlayerTurn = GameManager.Instance.CurrentTurn == TeamColor.White;

            FraguaRook usable = null;
            foreach (var rk in rooks)
            {
                if (GameManager.Instance.GetCondemnTargets(rk).Count > 0) { usable = rk; break; }
            }

            var e = new Entry
            {
                Key = $"fragua-{team}",
                Name = "Torre Fragua",
                Sprite = BoardView.Instance.GetFraguaRookSprite(team),
                IsWhite = isWhite,

                TypeChip = "PASIVA + ACTIVA",
                TypeTip = "Pasiva «Brasas»: +1 Sentencia por Dama/Torre capturada · Activa «Sentencia»: condena",
                CdChip = ready ? "BRASAS LISTAS" : "SIN BRASAS",
                CdTip = ready
                    ? "Puedes condenar una pieza enemiga (cede tu turno)"
                    : "Captura Damas o Torres con la Torre Fragua para ganar Sentencias",

                Badge = $"{sentencias}/{GameManager.MaxSentencias}",
                BadgeTip = "Sentencias disponibles (máximo por partida, compartidas por bando)",
                BadgeReady = ready,

                Brief = ready && usable != null
                    ? "¡LISTA! Elige torre y casilla: condena adyacente o en línea (cede tu turno)."
                    : "Captura Damas/Torres: +1 Sentencia · Condena piezas adyacentes o en línea.",
                Note = "La pieza condenada arde 5 turnos de su bando si no cazas las torres… o puedes exigir Tributo: 3 turnos al rival y vuelve INMUNE.",

                HasActive = true,
                ActionText = $"CONDENAR — {sentencias}/{GameManager.MaxSentencias}",
                ActionTip = "Elige la pieza enemiga a condenar",
                ActionEnabled = ready && usable != null && isWhite && isPlayerTurn
                                && GameManager.Instance.IsGameActive && !GameManager.Instance.IsPaused,
                OnAction = () => { if (usable != null) GameManager.Instance?.RequestCondemn(usable); },
            };

            if (!isWhite)
            {
                e.ActionText = "— Rival —";
                e.ActionEnabled = false;
                e.ActionTip = "Es una pieza del ejército rival: no puedes activarla";
            }
            else if (!ready)
            {
                e.ActionText = "Sin Sentencias";
            }
            else if (usable == null)
            {
                e.ActionText = "Sin objetivos";
                e.ActionTip = "Ninguna torre tiene piezas enemigas al alcance";
            }
            else if (!isPlayerTurn)
            {
                e.ActionText = "Espera tu turno";
                e.ActionTip = "Solo se activa en tu turno";
            }

            return e;
        }

        // ── Pinta el desplegable ───────────────────────────────────────────────

        private Node BuildDropdown(Entry e)
        {
            bool open = _openKey == e.Key;
            var node = new Node { Name = e.Name, Source = e, Letter = LetterFor(e.Key) };

            var wrap = new VisualElement();
            wrap.AddToClassList("ability-entry");
            wrap.AddToClassList(e.IsWhite ? "ability-entry-white" : "ability-entry-black");
            wrap.EnableInClassList("ability-entry-open", open);
            node.Wrap = wrap;

            // ── Fila colapsada: sprite + nombre + chevron + tecla ──
            // VisualElement y no Button para poder anidar dentro la tecla (un Button
            // dentro de otro Button se come los clics de forma impredecible).
            var head = new VisualElement();
            head.AddToClassList("ability-entry-head");
            head.tooltip = open ? "Cerrar" : $"Ver {e.Name}";
            node.Head = head;

            var headIcon = new VisualElement();
            headIcon.AddToClassList("ability-entry-icon");
            AddSprite(headIcon, e.Sprite, 30);
            head.Add(headIcon);

            var headText = new Label(e.Name);
            headText.AddToClassList("ability-entry-title");
            head.Add(headText);

            var chevron = new Label(open ? "▼" : "▶");
            chevron.AddToClassList("ability-entry-chevron");
            chevron.pickingMode = PickingMode.Ignore;
            head.Add(chevron);
            node.Chevron = chevron;

            // Tecla: cuadrado negro con marco blanco y la letra asignada
            var keyBadge = new Button();
            keyBadge.AddToClassList("key-badge");
            keyBadge.text = node.Letter.ToString();
            keyBadge.EnableInClassList("key-badge-ready", e.HasActive && e.ActionEnabled);
            keyBadge.tooltip = $"{node.Letter}: abre la ficha. Púlsala otra vez para activar si está lista.";
            head.Add(keyBadge);
            node.KeyBadge = keyBadge;

            wrap.Add(head);

            // ── Cuerpo: en el flujo, se abre hacia abajo y empuja a los de abajo ──
            var body = new VisualElement();
            body.AddToClassList("ability-entry-body");
            body.style.display = open ? DisplayStyle.Flex : DisplayStyle.None;
            node.Body = body;

            var detail = new VisualElement();
            detail.AddToClassList("ability-detail-head");

            var bigIcon = new VisualElement();
            bigIcon.AddToClassList("ability-detail-icon");
            AddSprite(bigIcon, e.Sprite, 54);
            detail.Add(bigIcon);

            var names = new VisualElement();
            names.AddToClassList("ability-detail-names");

            var nameRow = new VisualElement();
            nameRow.AddToClassList("ability-detail-name-row");
            var nameLbl = new Label(e.Name);
            nameLbl.AddToClassList("ability-name");
            nameRow.Add(nameLbl);
            var owner = new Label(e.IsWhite ? "TÚ" : "RIVAL");
            owner.AddToClassList("ability-owner");
            owner.AddToClassList(e.IsWhite ? "ability-owner-you" : "ability-owner-rival");
            owner.tooltip = e.IsWhite ? "Variante de tu ejército" : "Variante del ejército rival";
            nameRow.Add(owner);
            names.Add(nameRow);

            if (!string.IsNullOrEmpty(e.Badge))
            {
                var badge = new Label(e.Badge);
                badge.AddToClassList("ability-badge");
                badge.EnableInClassList("ready", e.BadgeReady);
                badge.tooltip = e.BadgeTip;
                names.Add(badge);
                node.Badge = badge;
            }

            if (!string.IsNullOrEmpty(e.TypeChip) || !string.IsNullOrEmpty(e.CdChip))
            {
                var meta = new VisualElement();
                meta.AddToClassList("ability-meta");
                if (!string.IsNullOrEmpty(e.TypeChip))
                {
                    var c = new Label(e.TypeChip);
                    c.AddToClassList("ability-chip");
                    c.AddToClassList("ability-chip-type");
                    c.tooltip = e.TypeTip;
                    meta.Add(c);
                }
                if (!string.IsNullOrEmpty(e.CdChip))
                {
                    var c = new Label(e.CdChip);
                    c.AddToClassList("ability-chip");
                    c.AddToClassList("ability-chip-cd");
                    c.tooltip = e.CdTip;
                    meta.Add(c);
                }
                names.Add(meta);
            }

            detail.Add(names);
            body.Add(detail);

            if (!string.IsNullOrEmpty(e.Brief))
            {
                var brief = new Label(e.Brief);
                brief.AddToClassList("ability-brief");
                body.Add(brief);
                node.Brief = brief;
            }
            if (!string.IsNullOrEmpty(e.Note))
            {
                var note = new Label(e.Note);
                note.AddToClassList("ability-note");
                body.Add(note);
            }

            if (e.Progress >= 0f)
            {
                var bar = new VisualElement();
                bar.AddToClassList("ability-progress-bar");
                var fill = new VisualElement();
                fill.AddToClassList("ability-progress-fill");
                fill.EnableInClassList("almost", e.ProgressAlmost);
                fill.style.width = new Length(e.Progress * 100f, LengthUnit.Percent);
                bar.Add(fill);
                body.Add(bar);
                node.Fill = fill;
            }

            // Botón de activar — SOLO si la habilidad es activa (no pasiva)
            if (e.HasActive)
            {
                var btn = new Button();
                btn.AddToClassList("ability-activate-btn");
                btn.text = e.ActionText;
                btn.tooltip = e.ActionTip;
                btn.SetEnabled(e.ActionEnabled);

                // El callback se registra SIEMPRE que haya acción: un botón que nace
                // deshabilitado (sin almas, rival, fuera de turno) puede habilitarse más
                // tarde, y si solo se suscribiera al construirse nunca respondería.
                if (e.OnAction != null)
                {
                    var captured = e;
                    btn.RegisterCallback<ClickEvent>(_ =>
                    {
                        captured.OnAction?.Invoke();
                        Refresh();
                    });
                }
                body.Add(btn);
                node.Action = btn;
            }

            wrap.Add(body);

            // Fila: abre y cierra la ficha
            string key = e.Key;
            head.RegisterCallback<ClickEvent>(_ =>
            {
                SetOpen(_openKey == key ? "" : key);
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            });

            // Tecla: abre; pulsada otra vez, activa si está lista
            keyBadge.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();   // no debe abrir/cerrar la fila
                PressKey(key);
            });

            return node;
        }

        /// <summary>Mete el sprite (o deja el hueco vacío si no hay arte).</summary>
        private static void AddSprite(VisualElement holder, Sprite spr, int size)
        {
            if (spr == null) return;
            var img = new Image { sprite = spr, scaleMode = ScaleMode.ScaleToFit };
            img.style.width = size;
            img.style.height = size;
            img.pickingMode = PickingMode.Ignore;
            holder.Add(img);
        }

        public void Show() => _root?.RemoveFromClassList("hidden");
        public void Hide() => _root?.AddToClassList("hidden");
    }
}