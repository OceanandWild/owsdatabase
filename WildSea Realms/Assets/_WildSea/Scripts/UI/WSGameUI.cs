using System;
using System.Collections.Generic;
using System.Linq;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.UIElements;
using WildSea.Core;
using WildSea.Game;

namespace WildSea.UI
{
    /// <summary>
    /// Partida del MODO CLASICO. Recibe el control de MatchController, que es el
    /// unico que existe: no hay cosmos, no hay coste, no hay estrellas, no hay
    /// tablero de casillas.
    ///
    /// Diseno, de izquierda a derecha y de arriba hacia abajo:
    ///
    ///   HEADER   placa ornamental CENTRADA con el titulo. A su izquierda el objetivo
    ///            sorteado; a su derecha el avance de los dos y el mazo en juego. El
    ///            boton de volver vive fuera de la placa, en el extremo izquierdo.
    ///            Los grupos laterales ceden espacio con flex-grow para que la placa
    ///            quede de verdad en el centro y no se corra segun el texto.
    ///
    ///   ESCENARIO  tres columnas: riel del rival, tapete, riel del jugador. El
    ///              tapete lleva el fondo de nebulosa, encima el marco de vidrio con
    ///              filigrana dorada, una segunda linea interior fina y la marca de
    ///              agua al centro.
    ///
    ///   MESA     el tapete se parte en HORIZONTAL: RIVAL a la izquierda, TU MESA a
    ///            la derecha y el escudo VS en el medio. Los dos encabezados van en
    ///            una franja propia arriba, en los extremos, y las cartas jugadas al
    ///            centro de cada mitad.
    ///
    ///   RIELES   cada riel apila tres piezas, de arriba hacia abajo: la pila del mazo
    ///            (tres reversos escalonados) con su nombre y su contador, el medallón
    ///            de puntos (avance sobre el objetivo) y la pila de cartas en juego con
    ///            su contador. El medallón es un disco, no un retrato: la partida no
    ///            lleva perfiles.
    ///
    ///   MANO     abanico absoluto, anclado abajo y CENTRADO, montado sobre el borde
    ///            del tapete. Las cartas se pisan y rotan alrededor de su base.
    ///
    ///   BARRA    log a la izquierda, la ayuda en una placa dorada al centro, y a la
    ///            derecha las fusiones disponibles y terminar turno.
    ///
    /// Interaccion: click en una carta de la mano la SELECCIONA: el marco se enciende
    /// en oro y la carta se levanta. Click otra vez y JUEGA: pasa al centro de la mesa.
    /// Con una carta seleccionada, click en una carta del rival ATACA con ella.
    /// El atacante siempre pierde su carta, asi que atacar con algo importante es una
    /// decision y no un click gratis.
    ///
    /// Levantar una carta es lo que hace click DERECHO sobre ella: la copia sale de su
    /// sitio, cruza la mesa hasta el centro y se agranda un poco, con muelle. No hay
    /// overlay ni fondo tapando la pantalla: la mesa sigue siendo la mesa, y lo que se
    /// quiere es ver la carta, no perder de vista el juego. Se guarda con click
    /// izquierdo, con la tecla recomendada ([Espacio]) o con [Esc].
    ///
    ///
    /// El abanico no usa layout: cada carta se posiciona a mano con translate y
    /// rotate sobre transform-origin en la base. Asi el arco es exacto y no depende de
    /// que el contenedor ya tenga ancho resuelto.
    ///
    /// El rival automatico oculta su mesa durante el turno y la revela al terminar.
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class WSGameUI : MonoBehaviour
    {
        public Action OnBackPressed;

        // Anchos nominales. La mano queda subordinada al tapete: las cartas se leen
        // completas sin tapar la mesa, y las jugadas conservan presencia visual.
        const int HandCardWMax = 176;
        const int TableCardWMax = 136;

        // Geometria del abanico (proporciones, se escalan con el ancho de carta).
        // El paso cerrado mantiene la mano compacta y deja libre la mesa.
        const float FanStepXRatio = 0.50f;  // del ancho de carta
        const float FanStepDeg = 2.8f;
        const float FanDroop = 1.05f;
        const float SelectLiftRatio = 0.30f;  // del alto de carta

        // Escenario. Todo el chrome (rieles, escudo, medallones, pilas) sale de la
        // altura de pantalla con este factor, igual que las cartas: asi el conjunto
        // se lee como una sola pieza y no como piezas de tamaños distintos.
        const int RailWMax = 132;      // ancho del riel lateral
        const int CrestWMax = 132;     // ancho del escudo VS
        const int DeckWMax = 78;       // ancho de la pila de reversos del riel
        const int MedallionWMax = 92;  // ancho del medallón de puntos

        // Levantar una carta. No hay tiempos ni curvas: hay un muelle (masa, rigidez,
        // amortiguamiento) y la carta va a donde el muelle la lleva. Asi el viaje se
        // puede interrumpir (click derecho en otra carta, click para guardar) sin que
        // la animacion "salte" a una posicion nueva.
        const float Mass = 1f;
        const float LiftK = 900f;         // rigidez: define la velocidad del viaje
        const float LiftD = 42f;          // amortiguamiento: 2*sqrt(k)=60, asi que
        //                                     oscila apenas y se asienta (~0.2 s)
        const float LiftScaleK = 1150f;   // el tamano entra un poco mas rapido que el
        const float LiftScaleD = 46f;     // traslado, para que la carta "salte" al centro
        const float LiftBackK = 1500f;    // volver es mas seco que salir: guardar una
        const float LiftBackD = 58f;      // carta no puede sentirse lento
        const float LiftHomeScale = 0.15f;// debajo de esto la copia es indistinguible
        const float LiftAngleHome = 7f;   // y de angulo, para el swap final
        const float LiftPressMs = 480;    // mantener el boton en tactil = click derecho

        // Cuanto de la mesa se lleva la carta levantada. No es un tamano fijo: se
        // calcula contra el alto y el ancho que hay disponibles, asi se lee igual en
        // una pantalla chica que en una grande, y nunca se sale de la mesa.
        const float LiftFillH = 0.72f;    // del alto de la mesa
        const float LiftFillW = 0.40f;    // del ancho de la mesa
        const float LiftScaleMin = 1.30f; // ni tan chica que parezca la de la mano
        const float LiftScaleMax = 3.00f; // ni tan grande que no entre nunca

        int handCardW = HandCardWMax;
        int tableCardW = TableCardWMax;
        int handCardH;
        int railW = RailWMax;
        int crestW = CrestWMax;
        int deckW = DeckWMax;
        int medallionW = MedallionWMax;

        UIDocument doc;
        VisualElement root;
        Label titleLabel;
        Label objectiveLabel;
        Label progressLabel;
        Label pileLabel;
        Label turnLabel;
        VisualElement stage;              // riel izq + tapete + riel der
        VisualElement arena;              // el tapete con su fondo y su marco
        VisualElement rivalHalf;
        VisualElement mineHalf;
        VisualElement rivalRow;
        VisualElement mineRow;
        Label rivalCountLabel;
        Label mineCountLabel;
        readonly RailRef[] rails = new RailRef[2];   // 0 = jugador, 1 = rival
        CrestRef crest;                              // el escudo VS
        VisualElement combatLayer;
        VisualElement defenseOverlay;
        Label defenseTitle;
        Label defenseDetails;
        VisualElement defenseCardSlot;
        VisualElement galaxyOverlay;
        Button galaxyStarButton;
        Button galaxyPlanetsButton;
        bool galaxyChoiceOpen;
        bool rivalFacesRevealed = true;
        bool revealAnimating;
        bool combatAnimating;
        bool aiTurnWaitingForDefense;
        int revealSerial;
        IVisualElementScheduledItem combatTicker;
        readonly List<CombatFlight> combatFlights = new();
        VisualElement handZone;
        VisualElement hand;               // contenedor del abanico
        VisualElement liftLayer;           // mesa alta: donde viaja la carta levantada
        VisualElement liftTile;            // la carta en el aire
        Label liftHint;              // "clic para volver"
        VisualElement liftSource;          // el elemento de origen, oculto mientras vuela
        CardDef liftCard;              // carta levantada
        bool lifting;                  // hay carta en el aire
        Vector2 liftPos, liftVel;      // desplazamiento respecto del centro de la mesa
        float liftRot, liftRotVel;     // angulo
        float liftScale, liftScaleVel; // tamano
        float liftScaleUp;            // tamano destino, medido contra la mesa
        Vector2 liftHome, liftHomeVel; // a donde vuelve
        float liftHomeRot;
        bool liftBack;                // true = volviendo a su sitio
        IVisualElementScheduledItem liftTimer, pressTimer;
        Label logLabel;
        VisualElement logDot;
        Label hintLabel;
        VisualElement hintPanel;
        VisualElement fuseRow;
        Button endTurnBtn;
        bool endTurnHasArt;       // el boton llevo sprite: el apagado va por tinte
        VisualElement winOverlay;
        Label winLabel;

        int selectedHand = -1;
        CardDef pressCard;           // carta donde se esta manteniendo el boton
        Vector3 pressAt;               // donde se toco, para distinguir el temblor
        float liftOpenedAt;            // momento de levantar: evita que el click que
        //                                 abrio la carta la guarde en el acto
        MatchState match;
        IVisualElementScheduledItem aiTimer;
        int fitW = -1, fitH = -1;
        bool visible;

        sealed class CombatFlight
        {
            public VisualElement tile;
            public Vector2 start;
            public Vector2 stack;
            public Vector2 target;
            public float width;
            public float height;
            public float startedAt;
            public float duration;
            public float rotation;
        }

        /// <summary>
        /// Un riel lateral: la pila del mazo, el medallón de puntos y la pila de
        /// cartas en juego. Se guardan las piezas por separado porque RecalcLayout
        /// las reescala cuando cambia la resolucion y Refresh solo las actualiza.
        /// </summary>
        sealed class RailRef
        {
            public VisualElement root;
            public VisualElement deckStack;      // la de arriba: destino de las cartas que vuelven
            public VisualElement playedStack;   // la de abajo
            public Label deckCount;
            public Label playedCount;
            public VisualElement medal;
            public Label medalValue;
            public Label medalSub;
        }

        /// <summary>Piezas del escudo VS, para poder reescalarlas a la resolucion.</summary>
        sealed class CrestRef
        {
            public VisualElement root;
            public VisualElement halo;
            public VisualElement ring;
            public VisualElement ring2;
            public VisualElement core;
            public Label vs;
        }

        /// <summary>
        /// Arte de la partida. Vive en Assets/Resources/WS/GameUI/ porque se carga
        /// por codigo con Resources.Load, igual que las cartas. Si falta un sprite
        /// el elemento se queda sin fondo —el marco de USS sigue en pie— para que
        /// la UI no se rompa: avisa una vez y sigue.
        /// </summary>
        static Sprite Art(string name)
        {
            var sp = Resources.Load<Sprite>("WS/GameUI/" + name);
            if (sp == null && !warnedArt.Contains(name))
            {
                warnedArt.Add(name);
                Debug.LogWarning("[WildSea] Falta el arte WS/GameUI/" + name);
            }
            return sp;
        }

        static readonly HashSet<string> warnedArt = new();

        static readonly Color ColBg = new Color(0.016f, 0.031f, 0.071f, 1f);
        static readonly Color ColPanel = new Color(0.075f, 0.11f, 0.21f, 0.98f);
        static readonly Color ColPanelSoft = new Color(0.10f, 0.145f, 0.26f, 1f);
        static readonly Color ColGold = new Color(1f, 0.84f, 0.35f, 1f);
        static readonly Color ColGoldDim = new Color(0.78f, 0.64f, 0.28f, 0.72f);
        static readonly Color ColCyan = new Color(0.35f, 0.85f, 1f, 1f);
        static readonly Color ColText = new Color(0.88f, 0.93f, 1f, 1f);
        static readonly Color ColMuted = new Color(0.58f, 0.68f, 0.85f, 1f);
        static readonly Color ColOk = new Color(0.40f, 0.90f, 0.55f, 1f);
        static readonly Color ColOff = new Color(0.95f, 0.42f, 0.42f, 1f);

        void Awake() => doc = GetComponent<UIDocument>();

        void OnEnable()
        {
            int tries = 0;
            IVisualElementScheduledItem wait = null;
            wait = doc.rootVisualElement.schedule.Execute(() =>
            {
                var r = doc.rootVisualElement;
                if (r != null) { wait?.Pause(); Build(); }
                else if (++tries > 120) { wait?.Pause(); Debug.LogError("[WildSea] Game: root null."); }
            }).Every(16);
        }

        void Build()
        {
            var r = doc.rootVisualElement;
            r.Clear();

            root = new VisualElement { name = "game-root" };
            root.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
            root.style.flexGrow = 1;
            root.style.flexDirection = FlexDirection.Column;
            root.style.minWidth = 0;
            root.style.backgroundColor = ColBg;
            root.style.overflow = Overflow.Hidden;
            root.style.paddingLeft = 18; root.style.paddingRight = 18;
            root.style.paddingTop = 10; root.style.paddingBottom = 8;

            // RecalcLayout deja los anchos calculados; BuildStage crea las piezas con
            // esos numeros, y recien despues ApplyStageLayout las mide y rellena.
            // Al reves, las pilas del riel saldrian vacias.
            BuildHeader();
            RecalcLayout();
            BuildStage();
            ApplyStageLayout();
            BuildHand();
            BuildBottomBar();
            BuildWinOverlay();
            BuildCombatLayer();
            BuildDefenseOverlay();
            BuildGalaxyOverlay();

            r.Add(root);
            FitRoot();
            Refresh();

            // El arbol se reconstruye entero: la carta en el aire, si la habia, se
            // perdio con el arbol viejo (su temporizador sigue enganchado al root viejo).
            EndLift();
            CancelPress();
            BuildLiftLayer();

            // Click derecho = levantar la carta. PointerDown con boton derecho: el evento de
            // menu contextual no existe en esta version de UI Toolkit.
            root.RegisterCallback<PointerDownEvent>(OnInspectRequested, TrickleDown.TrickleDown);

            // Tactil: no hay boton derecho, asi que mantener el dedo reemplaza al click
            // derecho. Se cancela en cuanto el dedo levanta o se mueve (un click normal
            // no llega a los 480 ms).
            root.RegisterCallback<PointerDownEvent>(OnPressDown);
            root.RegisterCallback<PointerUpEvent>(_ => CancelPress());
            root.RegisterCallback<PointerMoveEvent>(OnPressMove);

            // Con una carta en el aire, cualquier click la guarda. TrickleDown para que
            // el click muera antes de llegar a la carta de abajo: si pasara, el click de
            // guardar elegiria o jugaria una carta.
            root.RegisterCallback<ClickEvent>(OnClickWhileLifting, TrickleDown.TrickleDown);

            AuditTree();
        }

        /// <summary>
        /// Comprueba que las tres piezas grandes del escenario esten colgadas y en
        /// orden. Existe porque un `Build*()` que arma un elemento y se olvida de
        /// colgarlo NO da error: compila, corre, y el elemento simplemente no aparece.
        /// Peor todavia si es el del medio, porque los de los costados siguen
        /// viéndose y el flex los amontona de un lado. Un chequeo de dos lineas
        /// convierte ese silencio en un aviso en la consola.
        /// </summary>
        void AuditTree()
        {
            if (stage == null || arena == null) return;
            if (arena.parent != stage)
                Debug.LogError("[WildSea] El tapete no cuelga del escenario: se vera fuera de pantalla.");
            else if (stage.childCount != 3)
                Debug.LogError($"[WildSea] El escenario deberia tener 3 hijos (riel, tapete, riel) y tiene {stage.childCount}.");
            else if (stage[0] != rails[1]?.root || stage[1] != arena || stage[2] != rails[0]?.root)
                Debug.LogError("[WildSea] El orden del escenario no es riel-rival / tapete / riel-jugador.");
        }

        // ── Header ──────────────────────────────────────────────────────────────
        //
        // Tres grupos en fila. Los dos laterales ceden espacio con flex-grow y se
        // pegan a su borde, y la placa del medio tiene flex-shrink 0: eso mantiene el
        // titulo clavado en el centro de verdad, en vez de "casi al centro" segun
        // cuanto texto haya en los chips de los lados (que cambian con el objetivo y
        // con los nombres de las cartas).
        void BuildHeader()
        {
            var bar = new VisualElement { name = "header" };
            bar.style.flexDirection = FlexDirection.Row;
            bar.style.alignItems = Align.Center;
            bar.style.height = 52;
            bar.style.flexShrink = 0;
            bar.style.minWidth = 0;
            bar.style.marginBottom = 6;

            var left = new VisualElement();
            left.style.flexDirection = FlexDirection.Row;
            left.style.alignItems = Align.Center;
            left.style.flexGrow = 1;
            left.style.flexShrink = 1;
            left.style.overflow = Overflow.Hidden;
            bar.Add(left);

            backBtn2(() => { WSAudio.Back(); OnBackPressed?.Invoke(); }, "Volver", left);

            objectiveLabel = Chip("", ColCyan, "◆");
            left.Add(objectiveLabel.parent);

            var mid = new VisualElement();
            mid.style.flexDirection = FlexDirection.Row;
            mid.style.alignItems = Align.Center;
            mid.style.flexShrink = 0;
            bar.Add(mid);
            mid.Add(BuildTitlePlate());

            var right = new VisualElement();
            right.style.flexDirection = FlexDirection.Row;
            right.style.alignItems = Align.Center;
            right.style.justifyContent = Justify.FlexEnd;
            right.style.flexGrow = 1;
            right.style.flexShrink = 1;
            right.style.overflow = Overflow.Hidden;
            bar.Add(right);

            progressLabel = Chip("", ColText, "●");
            pileLabel = Chip("", ColMuted, "▣");
            right.Add(progressLabel.parent);
            right.Add(pileLabel.parent);

            turnLabel = new Label("");
            turnLabel.style.fontSize = 11;
            turnLabel.style.color = ColMuted;
            turnLabel.style.letterSpacing = 1;
            turnLabel.style.whiteSpace = WhiteSpace.NoWrap;
            turnLabel.style.marginLeft = 4;
            turnLabel.style.flexShrink = 1;
            turnLabel.style.minWidth = 0;
            turnLabel.style.overflow = Overflow.Hidden;
            turnLabel.style.unityTextAlign = TextAnchor.MiddleRight;
            right.Add(turnLabel);

            // Los chips se crearon con ancho intrinseco para que el texto largo no
            // se corte. En el encabezado, eso hacia que el grupo derecho desbordara
            // la pantalla en resoluciones estrechas. Ceden espacio conservando el
            // pip y recortando solo el texto del chip que menos espacio tenga.
            MakeHeaderChipFlexible(objectiveLabel);
            MakeHeaderChipFlexible(progressLabel);
            MakeHeaderChipFlexible(pileLabel);

            root.Add(bar);
        }

        /// <summary>
        /// Placa del titulo: dos rombos de punta, una banda con doble filete y el
        /// nombre en oro. Sin sprite: el filete doble son dos anillos concentricos
        /// (UI Toolkit no tiene box-shadow ni degradados, asi que la profundidad se
        /// consigue con capas apiladas) y las puntas son rombos rotados 45 grados.
        /// </summary>
        VisualElement BuildTitlePlate()
        {
            var plate = new VisualElement { name = "title-plate" };
            plate.style.flexDirection = FlexDirection.Row;
            plate.style.alignItems = Align.Center;
            plate.style.flexShrink = 0;

            plate.Add(Diamond(9, ColGoldDim, 0.7f));
            plate.Add(Diamond(4, ColGold, 0.9f, 10));
            plate.Add(Gem(10, ColGoldDim, 0.55f));

            var band = new VisualElement { name = "title-plate-band" };
            band.style.flexDirection = FlexDirection.Row;
            band.style.alignItems = Align.Center;
            band.style.height = 38;
            band.style.paddingLeft = 26; band.style.paddingRight = 26;
            band.style.marginLeft = 8; band.style.marginRight = 8;
            band.style.backgroundColor = new Color(0.055f, 0.094f, 0.184f, 0.95f);
            band.style.borderTopWidth = 2; band.style.borderBottomWidth = 2;
            band.style.borderLeftWidth = 2; band.style.borderRightWidth = 2;
            band.style.borderTopColor = new StyleColor(ColGoldDim);
            band.style.borderBottomColor = new StyleColor(ColGoldDim);
            band.style.borderLeftColor = new StyleColor(ColGoldDim);
            band.style.borderRightColor = new StyleColor(ColGoldDim);
            band.style.borderTopLeftRadius = 5; band.style.borderTopRightRadius = 5;
            band.style.borderBottomLeftRadius = 5; band.style.borderBottomRightRadius = 5;

            // Filete interior: el segundo anillo que hace que la placa tenga grosor.
            var inner = new VisualElement();
            inner.style.position = Position.Absolute;
            inner.style.left = 4; inner.style.right = 4;
            inner.style.top = 4; inner.style.bottom = 4;
            inner.style.borderTopWidth = 1; inner.style.borderBottomWidth = 1;
            inner.style.borderLeftWidth = 1; inner.style.borderRightWidth = 1;
            inner.style.borderTopColor = new StyleColor(new Color(0.35f, 0.55f, 0.85f, 0.35f));
            inner.style.borderBottomColor = new StyleColor(new Color(0.35f, 0.55f, 0.85f, 0.35f));
            inner.style.borderLeftColor = new StyleColor(new Color(0.35f, 0.55f, 0.85f, 0.35f));
            inner.style.borderRightColor = new StyleColor(new Color(0.35f, 0.55f, 0.85f, 0.35f));
            inner.style.borderTopLeftRadius = 3; inner.style.borderTopRightRadius = 3;
            inner.style.borderBottomLeftRadius = 3; inner.style.borderBottomRightRadius = 3;
            inner.pickingMode = PickingMode.Ignore;
            band.Add(inner);

            titleLabel = new Label("WILDSEA — ESPACIO");
            titleLabel.style.fontSize = 21;
            titleLabel.style.unityFontStyleAndWeight = FontStyle.Bold;
            titleLabel.style.color = ColGold;
            titleLabel.style.letterSpacing = 3;
            titleLabel.style.unityTextAlign = TextAnchor.MiddleCenter;
            titleLabel.pickingMode = PickingMode.Ignore;
            band.Add(titleLabel);

            plate.Add(band);

            plate.Add(Gem(10, ColGoldDim, 0.55f, -10));
            plate.Add(Diamond(4, ColGold, 0.9f, 10));
            plate.Add(Diamond(9, ColGoldDim, 0.7f));
            return plate;
        }

        /// <summary>Boton de volver: sprite sin contenedor ni fondo.</summary>
        Button backBtn2(Action onClick, string tip, VisualElement parent)
        {
            var b = new Button(onClick) { text = "" };
            b.tooltip = tip;
            b.style.width = 32; b.style.height = 32;
            b.style.marginRight = 12;
            b.style.flexShrink = 0;
            b.style.backgroundColor = Color.clear;
            b.style.borderTopWidth = 0; b.style.borderBottomWidth = 0;
            b.style.borderLeftWidth = 0; b.style.borderRightWidth = 0;
            b.style.paddingLeft = 0; b.style.paddingRight = 0;
            b.style.paddingTop = 0; b.style.paddingBottom = 0;
            var icon = Resources.Load<Sprite>("WS/Icons/WS_icon_chevron_left");
            if (icon != null)
            {
                b.style.backgroundImage = new StyleBackground(icon);
                b.style.unityBackgroundImageTintColor = Color.white;
                b.style.backgroundSize = new BackgroundSize(BackgroundSizeType.Contain);
                b.style.backgroundPositionX = new BackgroundPosition(BackgroundPositionKeyword.Center);
                b.style.backgroundPositionY = new BackgroundPosition(BackgroundPositionKeyword.Center);
                b.style.backgroundRepeat = new BackgroundRepeat(Repeat.NoRepeat, Repeat.NoRepeat);
            }
            else b.text = "←";
            parent.Add(b);
            return b;
        }

        // Devuelve el Label del TEXTO, no el del pip: eso es lo que refresca Refresh().
        Label Chip(string text, Color color, string pip)
        {
            var chip = new VisualElement { name = "chip" };
            chip.style.flexDirection = FlexDirection.Row;
            chip.style.alignItems = Align.Center;
            chip.style.flexShrink = 0;
            chip.style.height = 26;
            chip.style.marginRight = 8;
            chip.style.paddingLeft = 10; chip.style.paddingRight = 12;
            chip.style.backgroundColor = new Color(0.055f, 0.094f, 0.184f, 0.92f);
            chip.style.borderTopWidth = 1; chip.style.borderBottomWidth = 1;
            chip.style.borderLeftWidth = 1; chip.style.borderRightWidth = 1;
            var edge = new StyleColor(new Color(0.36f, 0.52f, 0.82f, 0.45f));
            chip.style.borderTopColor = edge; chip.style.borderBottomColor = edge;
            chip.style.borderLeftColor = edge; chip.style.borderRightColor = edge;
            chip.style.borderTopLeftRadius = 13; chip.style.borderTopRightRadius = 13;
            chip.style.borderBottomLeftRadius = 13; chip.style.borderBottomRightRadius = 13;

            // El pip va separado del texto: el objetivo puede ser largo, pero el
            // simbolo nunca se parte ni se junta a una palabra.
            var mark = new Label(pip);
            mark.style.fontSize = 9;
            mark.style.color = color;
            mark.style.marginRight = 7;
            mark.style.unityTextAlign = TextAnchor.MiddleCenter;
            mark.pickingMode = PickingMode.Ignore;
            chip.Add(mark);

            var l = new Label(text);
            l.style.fontSize = 11;
            l.style.color = color;
            l.style.whiteSpace = WhiteSpace.NoWrap;
            l.style.unityTextAlign = TextAnchor.MiddleLeft;
            l.style.letterSpacing = 1;
            l.pickingMode = PickingMode.Ignore;
            chip.Add(l);

            return l;
        }

        static void MakeHeaderChipFlexible(Label label)
        {
            if (label == null) return;
            label.style.flexShrink = 1;
            label.style.minWidth = 0;
            label.style.overflow = Overflow.Hidden;
            if (label.parent == null) return;
            label.parent.style.flexShrink = 1;
            label.parent.style.minWidth = 0;
        }

        // ── Piezas ornamentales sueltas ─────────────────────────────────────────
        //
        // UI Toolkit no tiene box-shadow, ni gradiente, ni border-image. Lo que si
        // hay son bordes, radios, opacidad, rotate y capas. Con eso se arman las
        // piezas de filigrana: rombos (un cuadrado rotado 45 grados), halos (el mismo
        // rombo grande con el color al 6 %) y doble filete (dos anillos concentricos).
        // Todas salen planas a proposito: el fondo nebuloso y los paneles del proyecto
        // son los que dan la profundidad.

        /// <summary>Rombo relleno: un cuadrado rotado 45 grados.</summary>
        static VisualElement Diamond(float size, Color color, float alpha, float marginRight = 0)
        {
            var d = new VisualElement { name = "diamond" };
            d.style.width = size; d.style.height = size;
            d.style.flexShrink = 0;
            d.style.rotate = new Rotate(45f);
            d.style.backgroundColor = Tint(color, alpha);
            d.style.marginRight = marginRight;
            d.pickingMode = PickingMode.Ignore;
            return d;
        }

        /// <summary>Rombo hueco: el mismo cuadrado, pero solo el filete.</summary>
        static VisualElement Gem(float size, Color color, float alpha, float marginLeft = 0)
        {
            var d = Diamond(size, color, alpha, 0);
            d.style.backgroundColor = Color.clear;
            d.style.borderTopWidth = 1; d.style.borderBottomWidth = 1;
            d.style.borderLeftWidth = 1; d.style.borderRightWidth = 1;
            d.style.borderTopColor = new StyleColor(Tint(color, alpha));
            d.style.borderBottomColor = new StyleColor(Tint(color, alpha));
            d.style.borderLeftColor = new StyleColor(Tint(color, alpha));
            d.style.borderRightColor = new StyleColor(Tint(color, alpha));
            d.style.marginLeft = marginLeft;
            return d;
        }

        /// <summary>Colorea con alfa: new Color no multiplica, hay que armarlo a mano.</summary>
        static Color Tint(Color c, float a) => new Color(c.r, c.g, c.b, c.a * a);

        /// <summary>
        /// Estirar a la caja entera. BackgroundSizeType no tiene un "stretch":
        /// se pide con 100 % en los dos ejes, que es lo mismo y lo que hace USS.
        /// </summary>
        static readonly BackgroundSize SizeFill = new BackgroundSize(
            new Length(100, LengthUnit.Percent), new Length(100, LengthUnit.Percent));

        // ── Escenario ────────────────────────────────────────────────────────────
        //
        // Tres columnas: riel del rival, tapete, riel del jugador. El tapete es la
        // pieza grande y lleva cuatro capas absolutas apiladas — nebulosa, velo,
        // marco de vidrio con la filigrana del proyecto y filete — y encima el
        // contenido: la marca de agua, una franja de encabezados y las dos mitades
        // de la mesa separadas por el escudo.
        //
        // Los encabezados viven en su propia franja, no flotando sobre el tapete: asi
        // nunca se pisan con las cartas ni hay que compensarlos con margenes, y la
        // fila de la mesa se reparte sola cuando cambia la resolucion.
        void BuildStage()
        {
            stage = new VisualElement { name = "stage" };
            stage.style.flexDirection = FlexDirection.Row;
            stage.style.alignItems = Align.Stretch;
            stage.style.flexGrow = 1;
            stage.style.flexShrink = 1;
            stage.style.minWidth = 0;
            stage.style.minHeight = Mathf.Clamp(Screen.height * 0.30f, 120f, 240f);

            BuildRail(1, "MAZO RIVAL", true);   // riel izquierdo: el rival
            BuildArena();
            BuildRail(0, "TU MAZO", false);     // riel derecho: el jugador

            root.Add(stage);
        }

        void BuildArena()
        {
            arena = new VisualElement { name = "arena" };
            arena.style.position = Position.Relative;
            arena.style.flexGrow = 1;
            arena.style.flexShrink = 1;
            arena.style.minWidth = 0;
            arena.style.flexDirection = FlexDirection.Column;
            arena.style.overflow = Overflow.Hidden;
            arena.style.marginLeft = 8;
            arena.style.marginRight = 8;

            // 1 · Nebulosa. Va primero: es lo que da aire y profundidad al tapete.
            AddLayer(arena, "arena-bg", Art("WS_bg_arena_nebula"),
                new BackgroundSize(BackgroundSizeType.Cover), new Color(1f, 1f, 1f, 1f));

            // 2 · Velo. Sin esto la nebulosa compite con las cartas y el texto chico
            //     no se lee. Al 62 % la nebulosa sigue viva pero el tablero manda.
            var scrim = AddLayer(arena, "arena-scrim", null,
                SizeFill, new Color(1f, 1f, 1f, 1f));
            scrim.style.backgroundColor = new Color(0.016f, 0.043f, 0.106f, 0.62f);

            // 3 · Marco de vidrio: la filigrana dorada del proyecto, estirada. Entra
            //     al 34 % a propósito — si fuera opaca taparía la nebulosa, y si
            //     fuera transparente se vería el doble borde y quedaría sucio.
            AddLayer(arena, "arena-glass", Art("WS_frame_arena_glass"),
                SizeFill, new Color(1f, 1f, 1f, 0.34f));

            // 4 · Filete crisp. El sprite va translúcido, así que la línea que
            //     realmente define el marco la pone USS: nítida a cualquier escala.
            var edge = new VisualElement { name = "arena-edge" };
            edge.style.position = Position.Absolute;
            edge.style.left = 0; edge.style.right = 0;
            edge.style.top = 0; edge.style.bottom = 0;
            edge.style.borderTopWidth = 2; edge.style.borderBottomWidth = 2;
            edge.style.borderLeftWidth = 2; edge.style.borderRightWidth = 2;
            edge.style.borderTopColor = new StyleColor(Tint(ColGold, 0.42f));
            edge.style.borderBottomColor = new StyleColor(Tint(ColGold, 0.42f));
            edge.style.borderLeftColor = new StyleColor(Tint(ColGold, 0.42f));
            edge.style.borderRightColor = new StyleColor(Tint(ColGold, 0.42f));
            edge.style.borderTopLeftRadius = 26; edge.style.borderTopRightRadius = 26;
            edge.style.borderBottomLeftRadius = 26; edge.style.borderBottomRightRadius = 26;
            edge.pickingMode = PickingMode.Ignore;
            arena.Add(edge);

            // 5 · Hilo interior: segunda línea fina que da profundidad sin box-shadow.
            var inner = new VisualElement { name = "arena-inner" };
            inner.style.position = Position.Absolute;
            inner.style.left = 9; inner.style.right = 9;
            inner.style.top = 9; inner.style.bottom = 9;
            inner.style.borderTopWidth = 1; inner.style.borderBottomWidth = 1;
            inner.style.borderLeftWidth = 1; inner.style.borderRightWidth = 1;
            inner.style.borderTopColor = new StyleColor(new Color(0.36f, 0.55f, 0.88f, 0.26f));
            inner.style.borderBottomColor = new StyleColor(new Color(0.36f, 0.55f, 0.88f, 0.26f));
            inner.style.borderLeftColor = new StyleColor(new Color(0.36f, 0.55f, 0.88f, 0.26f));
            inner.style.borderRightColor = new StyleColor(new Color(0.36f, 0.55f, 0.88f, 0.26f));
            inner.style.borderTopLeftRadius = 19; inner.style.borderTopRightRadius = 19;
            inner.style.borderBottomLeftRadius = 19; inner.style.borderBottomRightRadius = 19;
            inner.pickingMode = PickingMode.Ignore;
            arena.Add(inner);

            // Marca de agua: el nombre del juego al fondo, apenas perceptible.
            var watermark = new Label("W I L D S E A");
            watermark.style.position = Position.Absolute;
            watermark.style.left = 0; watermark.style.right = 0;
            watermark.style.top = 0; watermark.style.bottom = 0;
            watermark.style.fontSize = 46;
            watermark.style.unityFontStyleAndWeight = FontStyle.Bold;
            watermark.style.color = new Color(0.62f, 0.76f, 1f, 0.07f);
            watermark.style.letterSpacing = 16;
            watermark.style.unityTextAlign = TextAnchor.MiddleCenter;
            watermark.pickingMode = PickingMode.Ignore;
            arena.Add(watermark);

            arena.Add(BuildArenaHeads());

            var board = new VisualElement { name = "arena-board" };
            board.style.flexDirection = FlexDirection.Row;
            // Cada mitad ocupa todo el alto util del tapete. Asi las filas vacias o
            // cortas quedan centradas dentro de su zona, no pegadas a su borde bajo.
            board.style.alignItems = Align.Stretch;
            board.style.flexGrow = 1;
            board.style.flexShrink = 1;
            board.style.paddingLeft = 20;
            board.style.paddingRight = 20;
            board.style.paddingBottom = 14;

            rivalHalf = BuildHalf("half-rival", out rivalRow);
            mineHalf = BuildHalf("half-mine", out mineRow);
            board.Add(rivalHalf);
            board.Add(BuildCrest());
            board.Add(mineHalf);
            arena.Add(board);

            // El tapete va ENTRE los dos rieles. Esto no es opcional: `stage` es una
            // fila y solo tiene ancho para lo que se le agregue. Sin esta linea el
            // tapete queda descolgado (no se ve) y los dos rieles, que si estan
            // colgados, se amontonan al principio de la fila. El orden de las tres
            // llamadas de BuildStage define cual va a cada lado.
            stage.Add(arena);

            // Click en tu mitad con una carta elegida: la juega. Se registra en la
            // fila y en la mitad porque la fila puede quedar vacía.
            mineRow.RegisterCallback<ClickEvent>(OnMyBoardClicked);
            mineHalf.RegisterCallback<ClickEvent>(OnMyBoardClicked);
        }

        /// <summary>
        /// Capa decorativa a sangre dentro de un padre posicionado. Con sprite null
        /// queda como un velo de color plano: es el mismo camino para las dos cosas y
        /// asi no se duplica el bloque de posicionamiento cinco veces.
        /// </summary>
        static VisualElement AddLayer(VisualElement parent, string name, Sprite sprite,
            BackgroundSize size, Color tint)
        {
            var e = new VisualElement { name = name };
            e.style.position = Position.Absolute;
            e.style.left = 0; e.style.right = 0;
            e.style.top = 0; e.style.bottom = 0;
            if (sprite != null)
            {
                e.style.backgroundImage = new StyleBackground(sprite);
                e.style.backgroundSize = size;
                e.style.backgroundPositionX = new BackgroundPosition(BackgroundPositionKeyword.Center);
                e.style.backgroundPositionY = new BackgroundPosition(BackgroundPositionKeyword.Center);
                e.style.backgroundRepeat = new BackgroundRepeat(Repeat.NoRepeat, Repeat.NoRepeat);
                e.style.unityBackgroundImageTintColor = tint;
            }
            e.pickingMode = PickingMode.Ignore;
            parent.Add(e);
            return e;
        }

        /// <summary>
        /// Franja de encabezados: RIVAL arriba a la izquierda y TU MESA arriba a la
        /// derecha, cada uno con su contador. Es una fila con space-between, asi que
        /// los dos quedan clavados en los extremos sea cual sea el ancho.
        /// </summary>
        VisualElement BuildArenaHeads()
        {
            var strip = new VisualElement { name = "arena-heads" };
            strip.style.flexDirection = FlexDirection.Row;
            strip.style.alignItems = Align.Center;
            strip.style.justifyContent = Justify.SpaceBetween;
            strip.style.flexShrink = 0;
            strip.style.height = 46;
            strip.style.paddingLeft = 26;
            strip.style.paddingRight = 26;
            strip.pickingMode = PickingMode.Ignore;

            strip.Add(BuildZoneHead("RIVAL", "◆", new Color(0.58f, 0.75f, 1f, 1f),
                out rivalCountLabel));
            strip.Add(BuildZoneHead("TU MESA", "◇", ColGold, out mineCountLabel));
            return strip;
        }

        /// <summary>
        /// Encabezado de una mitad: pip, nombre y contador pegado al nombre. El
        /// contador NO va al borde de la pantalla — eso lo marca el space-between de
        /// la franja — sino pegado al texto, asi el par nombre+numero se lee como una
        /// unidad y no como dos cosas sueltas en esquinas opuestas.
        /// </summary>
        VisualElement BuildZoneHead(string title, string pip, Color color, out Label count)
        {
            var head = new VisualElement { name = "zone-head" };
            head.style.flexDirection = FlexDirection.Row;
            head.style.alignItems = Align.Center;
            head.style.flexShrink = 0;

            var dot = new Label(pip);
            dot.style.fontSize = 10;
            dot.style.color = color;
            dot.style.marginRight = 8;
            dot.pickingMode = PickingMode.Ignore;
            head.Add(dot);

            var name = new Label(title);
            name.style.fontSize = 13;
            name.style.unityFontStyleAndWeight = FontStyle.Bold;
            name.style.color = new Color(0.84f, 0.89f, 0.99f, 0.95f);
            name.style.letterSpacing = 4;
            name.pickingMode = PickingMode.Ignore;
            head.Add(name);

            count = new Label("0");
            count.style.fontSize = 11;
            count.style.unityFontStyleAndWeight = FontStyle.Bold;
            count.style.color = ColText;
            count.style.backgroundColor = new Color(0.10f, 0.15f, 0.27f, 1f);
            count.style.paddingLeft = 10; count.style.paddingRight = 10;
            count.style.paddingTop = 2; count.style.paddingBottom = 2;
            count.style.marginLeft = 12;
            count.style.borderTopLeftRadius = 9; count.style.borderTopRightRadius = 9;
            count.style.borderBottomLeftRadius = 9; count.style.borderBottomRightRadius = 9;
            count.style.borderTopWidth = 1; count.style.borderBottomWidth = 1;
            count.style.borderLeftWidth = 1; count.style.borderRightWidth = 1;
            count.style.borderTopColor = new StyleColor(Tint(color, 0.35f));
            count.style.borderBottomColor = new StyleColor(Tint(color, 0.35f));
            count.style.borderLeftColor = new StyleColor(Tint(color, 0.35f));
            count.style.borderRightColor = new StyleColor(Tint(color, 0.35f));
            count.pickingMode = PickingMode.Ignore;
            head.Add(count);
            return head;
        }

        /// <summary>
        /// Una mitad de la mesa: solo la fila de cartas. El fondo del paño ya no
        /// hace falta — el tapete es uno solo y las dos mitades comparten nebulosa —
        /// asi que la mitad es un contenedor transparente que cede el ancho con
        /// flex-basis 0. Sin eso, flexGrow reparte segun el ancho natural del
        /// contenido y las dos mitades nunca salen iguales.
        /// </summary>
        VisualElement BuildHalf(string name, out VisualElement row)
        {
            var half = new VisualElement { name = name };
            half.style.flexDirection = FlexDirection.Column;
            half.style.flexGrow = 1;
            half.style.flexShrink = 1;
            half.style.flexBasis = Length.Percent(0);
            half.style.minWidth = 0;
            half.style.alignItems = Align.Center;
            half.style.overflow = Overflow.Visible;

            row = TableRow();
            row.style.width = Length.Percent(100);
            row.style.flexGrow = 1;
            half.Add(row);
            return half;
        }

        // ── Escudo VS ────────────────────────────────────────────────────────────
        //
        // Sin sprite: son cuatro rombos concéntricos (un cuadrado rotado 45 grados)
        // y cuatro puntas. El contenedor NO va rotado, asi que el texto sale recto
        // dentro de un rombo, que es exactamente lo que hace el escudo de referencia.
        VisualElement BuildCrest()
        {
            crest = new CrestRef();
            var root0 = new VisualElement { name = "crest" };
            root0.style.position = Position.Relative;
            root0.style.alignItems = Align.Center;
            root0.style.justifyContent = Justify.Center;
            root0.style.flexShrink = 0;
            root0.style.marginLeft = 6;
            root0.style.marginRight = 6;
            crest.root = root0;

            // Halo: el anillo exterior, casi transparente. Es el resplandor. Todos
            // los anillos son cuadrados rotados 45 grados: el lado del cuadrado es
            // 1/raiz(2) del ancho en pantalla que ocupa, y por eso ApplyStageLayout
            // los mide con un 0.70 para que ninguno se salga del caja del escudo.
            crest.halo = CrestRing("crest-halo", 1, Tint(ColGold, 0.22f));
            root0.Add(crest.halo);

            // Las cuatro puntas, en los vertices del rombo exterior.
            root0.Add(CrestTip(-0.50f, 8, ColGold, 0.85f));
            root0.Add(CrestTip( 0.50f, 8, ColGold, 0.85f));
            root0.Add(CrestTip(-0.50f, 8, ColGold, 0.85f, horizontal: true));
            root0.Add(CrestTip( 0.50f, 8, ColGold, 0.85f, horizontal: true));

            crest.ring = CrestRing("crest-ring", 2, ColGold);
            root0.Add(crest.ring);
            crest.ring2 = CrestRing("crest-ring-inner", 1, Tint(ColGold, 0.55f));
            root0.Add(crest.ring2);

            // Nucleo relleno: sin esto el VS queda flotando sobre la nebulosa.
            crest.core = CrestRing("crest-core", 1, Tint(ColGold, 0.80f));
            crest.core.style.backgroundColor = new Color(0.024f, 0.055f, 0.125f, 0.92f);
            root0.Add(crest.core);

            var vs = new Label("VS");
            vs.style.position = Position.Absolute;
            vs.style.left = 0; vs.style.right = 0;
            vs.style.top = 0; vs.style.bottom = 0;
            vs.style.unityTextAlign = TextAnchor.MiddleCenter;
            vs.style.unityFontStyleAndWeight = FontStyle.Bold;
            vs.style.color = ColGold;
            vs.style.letterSpacing = 2;
            vs.pickingMode = PickingMode.Ignore;
            crest.vs = vs;
            root0.Add(vs);
            return root0;
        }

        static VisualElement CrestRing(string name, float width, Color color)
        {
            var r = new VisualElement { name = name };
            r.style.position = Position.Absolute;
            r.style.rotate = new Rotate(45f);
            r.style.borderTopWidth = width; r.style.borderBottomWidth = width;
            r.style.borderLeftWidth = width; r.style.borderRightWidth = width;
            r.style.borderTopColor = new StyleColor(color);
            r.style.borderBottomColor = new StyleColor(color);
            r.style.borderLeftColor = new StyleColor(color);
            r.style.borderRightColor = new StyleColor(color);
            r.pickingMode = PickingMode.Ignore;
            return r;
        }

        /// <summary>
        /// Punta del escudo: un rombo pegado a un vertice del anillo exterior.
        /// offset va de -0.5 a 0.5 en su eje (arriba/abajo o izquierda/derecha segun
        /// horizontal), en porcentaje de la caja. Como la caja del escudo es
        /// cuadrada, el mismo porcentaje mide igual en los dos ejes.
        /// </summary>
        static VisualElement CrestTip(float offset, float size,
            Color color, float alpha, bool horizontal = false)
        {
            var t = new VisualElement { name = "crest-tip" };
            t.style.position = Position.Absolute;
            t.style.width = size; t.style.height = size;
            t.style.left = new Length(50, LengthUnit.Percent);
            t.style.top = new Length(50, LengthUnit.Percent);
            t.style.translate = new Translate(
                new Length(horizontal ? offset : -size / 2f, LengthUnit.Percent),
                new Length(horizontal ? -size / 2f : offset, LengthUnit.Percent));
            t.style.rotate = new Rotate(45f);
            t.style.backgroundColor = Tint(color, alpha);
            t.pickingMode = PickingMode.Ignore;
            return t;
        }

        // ── Rieles ───────────────────────────────────────────────────────────────
        //
        // Tres piezas por riel, de arriba hacia abajo: la pila del mazo (tres reversos
        // escalonados con su contador), el medallón de puntos y la pila de cartas en
        // juego. El medallón es un disco con el avance sobre el objetivo — un
        // contador, no un retrato: la partida no lleva perfiles.
        void BuildRail(int ownerIndex, string deckCaption, bool isRival)
        {
            var ref0 = new RailRef();
            rails[ownerIndex] = ref0;

            var rail = new VisualElement { name = isRival ? "rail-rival" : "rail-mine" };
            rail.style.position = Position.Relative;
            rail.style.flexDirection = FlexDirection.Column;
            rail.style.alignItems = Align.Center;
            rail.style.justifyContent = Justify.SpaceEvenly;
            rail.style.flexShrink = 0;
            rail.style.paddingTop = 18;
            rail.style.paddingBottom = 14;
            rail.style.paddingLeft = 5;
            rail.style.paddingRight = 5;
            ref0.root = rail;

            // Doble filete: el exterior cierra el riel y el interior lo separa del
            // fondo. Sin sprite porque el riel es MUY vertical y estirar la
            // filigrana del panel la deformaria en una tira larga.
            var frame = new VisualElement { name = "rail-frame" };
            frame.style.position = Position.Absolute;
            frame.style.left = 0; frame.style.right = 0;
            frame.style.top = 8; frame.style.bottom = 8;
            frame.style.backgroundColor = new Color(0.035f, 0.062f, 0.125f, 0.55f);
            frame.style.borderTopWidth = 1; frame.style.borderBottomWidth = 1;
            frame.style.borderLeftWidth = 1; frame.style.borderRightWidth = 1;
            var railEdge = new StyleColor(isRival
                ? new Color(0.44f, 0.60f, 0.92f, 0.34f)
                : new Color(0.85f, 0.70f, 0.35f, 0.32f));
            frame.style.borderTopColor = railEdge; frame.style.borderBottomColor = railEdge;
            frame.style.borderLeftColor = railEdge; frame.style.borderRightColor = railEdge;
            frame.style.borderTopLeftRadius = 18; frame.style.borderTopRightRadius = 18;
            frame.style.borderBottomLeftRadius = 18; frame.style.borderBottomRightRadius = 18;
            frame.pickingMode = PickingMode.Ignore;
            rail.Add(frame);

            var frameIn = new VisualElement { name = "rail-frame-inner" };
            frameIn.style.position = Position.Absolute;
            frameIn.style.left = 4; frameIn.style.right = 4;
            frameIn.style.top = 4; frameIn.style.bottom = 4;
            frameIn.style.borderTopWidth = 1; frameIn.style.borderBottomWidth = 1;
            frameIn.style.borderLeftWidth = 1; frameIn.style.borderRightWidth = 1;
            var railEdgeIn = new StyleColor(isRival
                ? new Color(0.44f, 0.60f, 0.92f, 0.14f)
                : new Color(0.85f, 0.70f, 0.35f, 0.13f));
            frameIn.style.borderTopColor = railEdgeIn; frameIn.style.borderBottomColor = railEdgeIn;
            frameIn.style.borderLeftColor = railEdgeIn; frameIn.style.borderRightColor = railEdgeIn;
            frameIn.style.borderTopLeftRadius = 15; frameIn.style.borderTopRightRadius = 15;
            frameIn.style.borderBottomLeftRadius = 15; frameIn.style.borderBottomRightRadius = 15;
            frameIn.pickingMode = PickingMode.Ignore;
            rail.Add(frameIn);

            // ── Pila del mazo ──
            ref0.deckStack = new VisualElement { name = "rail-deck-pile" };
            rail.Add(RailSlot(deckCaption, ref0.deckStack, out ref0.deckCount));

            // ── Medallón de puntos ──
            ref0.medal = BuildMedallion(out ref0.medalValue, out ref0.medalSub);
            rail.Add(ref0.medal);

            // ── Pila de cartas en juego ──
            ref0.playedStack = new VisualElement { name = "rail-played-pile" };
            rail.Add(RailSlot("EN JUEGO", ref0.playedStack, out ref0.playedCount));

            stage.Add(rail);
        }

        /// <summary>
        /// Hueco de riel: columna con la pila, su nombre y su contador. El hueco
        /// tiene alto fijo para que las tres piezas del riel se repartan parejo.
        /// </summary>
        VisualElement RailSlot(string caption, VisualElement pile, out Label count)
        {
            var slot = new VisualElement { name = "rail-slot" };
            slot.style.flexDirection = FlexDirection.Column;
            slot.style.alignItems = Align.Center;
            slot.style.flexShrink = 0;

            var holder = new VisualElement { name = "rail-slot-pile" };
            holder.style.alignItems = Align.Center;
            holder.style.justifyContent = Justify.Center;
            holder.style.flexShrink = 0;
            holder.Add(pile);
            slot.Add(holder);

            var label = new Label(caption);
            label.style.fontSize = 9;
            label.style.color = ColMuted;
            label.style.letterSpacing = 2;
            label.style.marginTop = 5;
            label.style.whiteSpace = WhiteSpace.NoWrap;
            label.style.unityTextAlign = TextAnchor.MiddleCenter;
            label.pickingMode = PickingMode.Ignore;
            slot.Add(label);

            count = new Label("0");
            count.style.fontSize = 12;
            count.style.unityFontStyleAndWeight = FontStyle.Bold;
            count.style.color = ColText;
            count.style.marginTop = 1;
            count.style.unityTextAlign = TextAnchor.MiddleCenter;
            count.pickingMode = PickingMode.Ignore;
            slot.Add(count);
            return slot;
        }

        /// <summary>
        /// Medallón de puntos: dos círculos concéntricos (el radio completo hace de
        /// circulo sin necesidad de sprite) y en el medio el avance. Debajo, el
        /// "de 5": el número solo no dice si falta mucho o falta poco.
        /// </summary>
        VisualElement BuildMedallion(out Label value, out Label sub)
        {
            var medal = new VisualElement { name = "medallion" };
            medal.style.alignItems = Align.Center;
            medal.style.justifyContent = Justify.Center;
            medal.style.flexShrink = 0;
            medal.style.borderTopWidth = 2; medal.style.borderBottomWidth = 2;
            medal.style.borderLeftWidth = 2; medal.style.borderRightWidth = 2;
            medal.style.borderTopColor = new StyleColor(Tint(ColGold, 0.75f));
            medal.style.borderBottomColor = new StyleColor(Tint(ColGold, 0.75f));
            medal.style.borderLeftColor = new StyleColor(Tint(ColGold, 0.75f));
            medal.style.borderRightColor = new StyleColor(Tint(ColGold, 0.75f));
            medal.style.borderTopLeftRadius = 100; medal.style.borderTopRightRadius = 100;
            medal.style.borderBottomLeftRadius = 100; medal.style.borderBottomRightRadius = 100;
            medal.style.backgroundColor = new Color(0.047f, 0.078f, 0.153f, 0.88f);

            // Anillo interior: el segundo trazo del disco.
            var ring = new VisualElement { name = "medallion-ring" };
            ring.style.position = Position.Absolute;
            ring.style.left = 7; ring.style.right = 7;
            ring.style.top = 7; ring.style.bottom = 7;
            ring.style.borderTopWidth = 1; ring.style.borderBottomWidth = 1;
            ring.style.borderLeftWidth = 1; ring.style.borderRightWidth = 1;
            ring.style.borderTopColor = new StyleColor(Tint(ColGold, 0.28f));
            ring.style.borderBottomColor = new StyleColor(Tint(ColGold, 0.28f));
            ring.style.borderLeftColor = new StyleColor(Tint(ColGold, 0.28f));
            ring.style.borderRightColor = new StyleColor(Tint(ColGold, 0.28f));
            ring.style.borderTopLeftRadius = 100; ring.style.borderTopRightRadius = 100;
            ring.style.borderBottomLeftRadius = 100; ring.style.borderBottomRightRadius = 100;
            ring.pickingMode = PickingMode.Ignore;
            medal.Add(ring);

            // Joya arriba y colgante abajo: el remate que hace que esto se lea como
            // una medalla y no como un circulo con un numero. Van en absolute para
            // no sumar filas al centro, que es del numero y del rotulo.
            medal.Add(MedalPip(-6, Gem(7, ColGold, 0.60f)));
            medal.Add(MedalPip(6, Diamond(5, ColGold, 0.50f)));

            var stack = new VisualElement { name = "medallion-text" };
            stack.style.flexDirection = FlexDirection.Column;
            stack.style.alignItems = Align.Center;
            stack.style.justifyContent = Justify.Center;
            stack.style.flexShrink = 0;
            stack.pickingMode = PickingMode.Ignore;

            value = new Label("0");
            value.style.unityFontStyleAndWeight = FontStyle.Bold;
            value.style.color = ColGold;
            value.style.unityTextAlign = TextAnchor.MiddleCenter;
            value.pickingMode = PickingMode.Ignore;
            stack.Add(value);

            var cap = new Label("PUNTOS");
            cap.style.fontSize = 7;
            cap.style.color = Tint(ColGold, 0.75f);
            cap.style.letterSpacing = 2;
            cap.style.unityTextAlign = TextAnchor.MiddleCenter;
            cap.pickingMode = PickingMode.Ignore;
            stack.Add(cap);

            medal.Add(stack);

            sub = new Label("de 0");
            sub.style.fontSize = 9;
            sub.style.color = ColMuted;
            sub.style.marginTop = 4;
            sub.style.letterSpacing = 1;
            sub.style.unityTextAlign = TextAnchor.MiddleCenter;
            sub.pickingMode = PickingMode.Ignore;
            medal.Add(sub);
            return medal;
        }

        /// <summary>
        /// Adorno del medallón pegado al borde de arriba o de abajo. Va absolute con
        /// desplazamiento en píxeles: el radio del borde-radius del padre no deja
        /// anclar en porcentajes sin pelearse con el círculo.
        /// </summary>
        static VisualElement MedalPip(float fromEdge, VisualElement pip)
        {
            pip.style.position = Position.Absolute;
            pip.style.left = new Length(50, LengthUnit.Percent);
            pip.style.marginLeft = -3.5f;
            pip.style.translate = new Translate(Length.Percent(0),
                new Length(fromEdge, LengthUnit.Pixel));
            return pip;
        }

        /// <summary>
        /// Rellena una pila de riel con tres reversos escalonados hacia abajo y la
        /// derecha: leidos de perfil parecen una pila de verdad. Se vuelve a pintar
        /// en cada cambio de resolucion porque el reverso se dibuja al ancho que
        /// tenga, no se estira.
        /// </summary>
        void FillRailPile(VisualElement pile, float dim)
        {
            if (pile == null) return;
            pile.Clear();
            pile.style.position = Position.Relative;
            pile.style.flexShrink = 0;
            pile.style.width = deckW + 10;
            pile.style.height = Mathf.RoundToInt(deckW * (float)WSCardArt.CardH / WSCardArt.CardW) + 8;
            for (int i = 0; i < 3; i++)
            {
                var back = WSCardArt.BuildBackTile(deckW);
                back.style.position = Position.Absolute;
                back.style.left = 2 + i * 3;
                back.style.top = 3 + i * 4;
                back.style.opacity = dim * (0.5f + i * 0.25f);
                pile.Add(back);
            }
        }

        void BuildCombatLayer()
        {
            combatLayer = new VisualElement { name = "combat-animation-layer" };
            combatLayer.style.position = Position.Absolute;
            combatLayer.style.left = 0; combatLayer.style.top = 0;
            combatLayer.style.right = 0; combatLayer.style.bottom = 0;
            combatLayer.pickingMode = PickingMode.Ignore;
            root.Add(combatLayer);
        }

        // ── Levantar una carta (click derecho) ──────────────────────────
        //
        // No hay overlay ni fondo: lo que se levanta es una COPIA de la carta que viaja
        // desde donde estaba hasta el centro de la mesa, y el viaje es un muelle (masa,
        // rigidez, amortiguamiento) en vez de un tiempo con curva. El muelle es lo que
        // hace que se pueda interrumpir en cualquier punto sin que la carta "salte" de
        // sitio, y lo que le da el rebote corto al asentarse.
        //
        // La copia vive en `liftLayer`, que es la mesa entera en absolute: el centro de
        // la mesa es (0,0) de esa capa. Se posiciona con translate/rotate/scale desde su
        // propio centro, asi que el unico estado son tres numeros (pos, angulo, escala)
        // y el resto se deriva de ahi.
        void BuildLiftLayer()
        {
            liftLayer = new VisualElement { name = "lift-layer" };
            liftLayer.style.position = Position.Absolute;
            liftLayer.style.left = 0; liftLayer.style.top = 0;
            liftLayer.style.right = 0; liftLayer.style.bottom = 0;
            liftLayer.style.alignItems = Align.Center;
            liftLayer.style.justifyContent = Justify.Center;
            // PickingMode.Ignore: la capa nunca se come un click. Los clicks los corta
            // el handler de TrickleDown de la raiz mientras hay carta en el aire.
            liftLayer.pickingMode = PickingMode.Ignore;

            var stack = new VisualElement { name = "lift-stack" };
            stack.style.alignItems = Align.Center;
            stack.style.flexShrink = 0;
            stack.pickingMode = PickingMode.Ignore;

            // La carta en el aire: se crea una vez y se reutiliza, para que el arte no se
            // recargue en cada viaje.
            liftTile = new VisualElement { name = "lift-card" };
            liftTile.style.flexShrink = 0;
            liftTile.pickingMode = PickingMode.Ignore;
            liftTile.style.display = DisplayStyle.None;
            stack.Add(liftTile);

            liftHint = new Label("Click o [Espacio] para guardar");
            liftHint.style.fontSize = 13;
            liftHint.style.color = ColMuted;
            liftHint.style.letterSpacing = 1;
            liftHint.style.marginTop = 16;
            liftHint.style.display = DisplayStyle.None;
            liftHint.pickingMode = PickingMode.Ignore;
            stack.Add(liftHint);

            liftLayer.Add(stack);
            // Ultimo hijo del tapete: UI Toolkit no tiene zIndex, el orden de pintado es
            // el orden de Add, asi que asi la copia va por encima de las dos mitades.
            arena.Add(liftLayer);
        }

        /// <summary>
        /// Click derecho sobre una carta: a levantar esa carta al centro de la mesa.
        /// Viene por PointerDown y no por el evento de menu contextual, que no existe en
        /// el modulo de UI Toolkit de esta version: el boton se mira en e.button.
        /// </summary>
        void OnInspectRequested(PointerDownEvent e)
        {
            if (combatAnimating || revealAnimating || match?.pendingAttack != null) return;
            if (e.button != (int)MouseButton.RightMouse) return;
            var src = CardUnder(e.target as VisualElement);
            if (src.element == null) return;
            e.StopPropagation();
            Lift(src.element, src.card);
        }

        /// <summary>
        /// Tactil: mantener el dedo hace lo mismo que click derecho. A los 480 ms se
        /// levanta la carta, y un click normal (que levanta antes) nunca llega.
        /// </summary>
        void OnPressDown(PointerDownEvent e)
        {
            if (combatAnimating || revealAnimating || match?.pendingAttack != null) return;
            if (e.button != (int)MouseButton.LeftMouse) return;
            // Ya hay una carta en el aire: cualquier toque es para guardarla, no para
            // dejar otra en pausa.
            if (lifting) return;
            var src = CardUnder(e.target as VisualElement);
            if (src.element == null) return;

            pressCard = src.card;
            pressAt = e.position;
            var captured = src.element;
            pressTimer?.Pause();
            pressTimer = root.schedule.Execute(() =>
            {
                pressTimer = null;
                if (pressCard != null && captured.panel != null) Lift(captured, pressCard);
            }).StartingIn((long)LiftPressMs);
        }

        /// <summary>
        /// Mover el dedo cancela la pulsacion larga: eso ya es un click normal, no una
        /// mirada. El margen de 12 px es lo que cuesta el temblor del dedo; sin el, en
        /// tactil casi nunca se llega a los 480 ms.
        /// </summary>
        void OnPressMove(PointerMoveEvent e)
        {
            if (pressCard == null) return;
            if ((e.position - pressAt).sqrMagnitude > 144f) CancelPress();
        }

        void CancelPress()
        {
            pressTimer?.Pause();
            pressTimer = null;
            pressCard = null;
        }

        /// <summary>Con la carta en el aire, click izquierdo la guarda y nada mas.</summary>
        void OnClickWhileLifting(ClickEvent e)
        {
            if (!lifting) return;

            // El gesto tactil (mantener) termina con un click al soltar el dedo: ese
            // click es el que acaba de levantar la carta, no uno de guardar. Se ignoran
            // los clicks del primer cuarto de segundo.
            if (Time.unscaledTime - liftOpenedAt < 0.25f) return;

            // TrickleDown: el click muere antes de llegar a la carta de abajo, para que
            // el click de guardar no termine elegiendo o jugando por el camino.
            e.StopPropagation();
            e.StopImmediatePropagation();
            PutBack();
        }

        /// <summary>Sube el primer elemento con userData de carta, subiendo por los padres.</summary>
        (VisualElement element, CardDef card) CardUnder(VisualElement under)
        {
            for (var v = under; v != null; v = v.parent)
            {
                var c = v.userData as CardDef;
                if (c != null) return (v, c);
            }
            return (null, null);
        }

        /// <summary>
        /// Levanta la carta. from es el elemento donde estaba (holder del abanico o
        /// columna de la mesa), y se oculta mientras la copia vuela: si no, se verian
        /// las dos cartas una encima de otra durante el viaje.
        /// </summary>
        void Lift(VisualElement from, CardDef c)
        {
            if (match == null || liftLayer == null) return;
            if (from == null || c == null) return;
            if (lifting && liftCard == c) return;    // ya esta levantada: no reinicia el viaje

            // Si ya habia otra carta en el aire se la guarda de una: dos copias a la vez
            // en la misma capa se pisarian y no hay a cual volver.
            if (lifting) EndLift();

            // Angulo de partida: el de la carta en la mesa (el abanico la rota), para
            // que la copia salga con la misma inclinacion y el cambio no se note.
            float startRot = from.resolvedStyle.rotate.angle.value;

            // A donde vuelve: el centro del hueco que ocupa la carta. Se mide con
            // worldBound (todo en coordenadas de panel) y se guarda el desplazamiento
            // respecto del centro de la capa, que es el mismo sistema del viaje.
            var box = from.worldBound;
            var layer = liftLayer.worldBound;
            var center = new Vector2(layer.x + layer.width * 0.5f, layer.y + layer.height * 0.5f);

            liftSource = from;
            liftCard = c;
            lifting = true;
            liftBack = false;

            // Estado inicial: en el hueco de origen, con su inclinacion y su tamano.
            liftPos = liftHome = new Vector2(
                box.x + box.width * 0.5f - center.x,
                box.y + box.height * 0.5f - center.y);
            liftVel = Vector2.zero;
            liftRot = liftHomeRot = startRot;
            liftRotVel = 0f;
            liftScale = 1f;
            liftScaleVel = 0f;

            // El marco cuenta lo mismo que en la mano y en la mesa.
            int w = Mathf.Max(2, Mathf.RoundToInt(box.width));
            // El destino de tamano se mide contra la mesa, no contra la carta: la copia
            // arranca con el ancho del origen y crece hasta ocupar la parte de la mesa
            // que le toca. Asi se lee igual de bien en 720 que en 1440.
            liftScaleUp = TargetLiftScale(layer, w);

            var tile = WSCardArt.BuildTile(c, w);
            bool serves = MatchController.IsNeededForObjective(match, match.Active, c);
            bool sel = selectedHand >= 0 && selectedHand < match.Active.hand.Count
                       && match.Active.hand[selectedHand] == c;
            int bw = sel ? 4 : (serves ? 2 : 1);
            var bc = sel ? ColGold : (serves ? ColOk : WSCardArt.CategoryColor(c.category));
            tile.style.borderTopWidth = bw; tile.style.borderBottomWidth = bw;
            tile.style.borderLeftWidth = bw; tile.style.borderRightWidth = bw;
            tile.style.borderTopColor = new StyleColor(bc);
            tile.style.borderBottomColor = new StyleColor(bc);
            tile.style.borderLeftColor = new StyleColor(bc);
            tile.style.borderRightColor = new StyleColor(bc);
            SetIgnoreRecursive(tile);
            liftTile.Clear();
            liftTile.Add(tile);
            liftTile.style.display = DisplayStyle.Flex;

            // Y se oculta la de abajo, sin sacarla del layout (visibility, no display):
            // el abanico no se reacomoda mientras la copia vuela.
            from.style.visibility = Visibility.Hidden;
            liftHint.style.display = DisplayStyle.Flex;

            liftOpenedAt = Time.unscaledTime;
            liftTimer?.Pause();
            // Cada 8 ms, no cada 16: con la rigidez de ahora la carta recorre bastante camino
            // entre dos pasos y a 16 ms se veria escalonada en un monitor de 60 Hz.
            liftTimer = root.schedule.Execute(TickLift).Every(8);
            WSAudio.Click();
        }

        /// <summary>
        /// Cuanto tiene que crecer la copia para ocupar su parte de la mesa. Se mide en
        /// las dos direcciones y se gana la mas chica: si solo se midiera el alto, en una
        /// pantalla angosta la carta se saldria de los lados; si solo el ancho, en una
        /// pantalla baja taparia las dos filas de la mesa.
        ///
        /// El alto de la carta sale de su proporcion (1030/560), que es la del arte.
        /// </summary>
        float TargetLiftScale(Rect layer, int cardW)
        {
            if (cardW <= 0 || layer.width < 1f || layer.height < 1f) return 2f;

            float cardH = cardW * (float)WSCardArt.CardH / WSCardArt.CardW;
            float byH = layer.height * LiftFillH / cardH;
            float byW = layer.width * LiftFillW / cardW;
            return Mathf.Clamp(Mathf.Min(byH, byW), LiftScaleMin, LiftScaleMax);
        }

        /// <summary>Click en cualquier parte: la carta vuelve a su sitio.</summary>
        void PutBack()
        {
            if (!lifting) return;
            liftBack = true;
            liftHint.style.display = DisplayStyle.None;
            WSAudio.Back();
        }

        /// <summary>
        /// Un paso del muelle. Se integra con subpasos fijos: el paso real puede venir
        /// de 8 ms (144 Hz) o de 200 ms (cambio de foco), y a 200 ms el muelle explota
        /// si se integra de una. dt se recorta igual, por si acaso.
        /// </summary>
        void TickLift()
        {
            if (!lifting) return;

            // Sin dalles: si la partida termino o se corto el juego, la copia se va y
            // no queda colgando a la vista.
            if (match == null || match.winner.HasValue || root.panel == null)
            {
                EndLift();
                return;
            }
            // El tablero se repinta entero en cada jugada: si la carta levantada ya no
            // esta en juego (la jugo el jugador mientras estaba en el aire), no tiene a
            // donde volver.
            if (!StillInPlay(liftCard, match)) { EndLift(); return; }

            float dt = Mathf.Min(Time.unscaledDeltaTime, 0.05f);
            // Subpaso fijo y pequeño: con la rigidez de ahora (k=900, y 1500 volviendo)
            // un paso de 1/60 ya no alcanzaria y el muelle dana saltos. 1/360 deja el
            // margen de sobra y sigue siendo barato (son puros numeros).
            const float step = 1f / 360f;
            bool back = liftBack;
            // Guardar es mas seco que salir: la rigidez sube al volver, para que cerrar
            // una carta se sienta una decision y no una espera.
            float k = back ? LiftBackK : LiftK;
            float d = back ? LiftBackD : LiftD;
            while (dt > 0f)
            {
                float h = Mathf.Min(step, dt);
                dt -= h;

                // Posicion: F = -k(x - x0) - c*v, sobre la masa.
                Vector2 goal = back ? liftHome : Vector2.zero;
                liftVel += (-k * (liftPos - goal) - d * liftVel) / Mass * h;
                liftPos += liftVel * h;

                // Angulo: mismo muelle, un poco mas flojo para que el vaiven se note al
                // salir de la inclinacion del abanico.
                float rotGoal = back ? liftHomeRot : 0f;
                liftRotVel += (-k * 0.8f * (liftRot - rotGoal) - d * 0.8f * liftRotVel) * h;
                liftRot += liftRotVel * h;

                // Tamano: entra un poco mas rapido que el traslado, para que la carta
                // "salte" al llegar al centro en vez de crecer por el camino.
                float scGoal = back ? 1f : liftScaleUp;
                liftScaleVel += (-LiftScaleK * (liftScale - scGoal) - LiftScaleD * liftScaleVel) / Mass * h;
                liftScale += liftScaleVel * h;
            }

            ApplyLift();

            // Vuelta terminada: la copia ya es indistinguible de la de abajo, asi que se
            // la saca y se devuelve la original. Sin este swap la mano tendria una carta
            // de mas.
            if (liftBack
                && (liftPos - liftHome).sqrMagnitude < 1f
                && Mathf.Abs(liftRot - liftHomeRot) < 0.5f
                && Mathf.Abs(liftScale - 1f) < LiftHomeScale)
                EndLift();
        }

        /// <summary>
        /// Vuelve a enganchar la carta levantada despues de un repintado. El abanico y
        /// los tableros se reconstruyen enteros, asi que el elemento de origen es otro
        /// objeto nuevo: hay que buscarlo otra vez y volver a ocultarlo, o la carta se
        /// veria duplicada en la mano mientras la copia esta en el aire.
        /// </summary>
        void RelinkLift()
        {
            if (liftCard == null || !StillInPlay(liftCard, match)) { EndLift(); return; }

            var again = FindCardIn(mineRow, liftCard) ?? FindCardIn(rivalRow, liftCard)
                        ?? FindCardIn(hand, liftCard);
            if (again == null) { EndLift(); return; }
            if (again != liftSource)
            {
                if (liftSource != null && liftSource.parent != null)
                    liftSource.style.visibility = Visibility.Visible;
                liftSource = again;
            }
            if (!liftBack) liftSource.style.visibility = Visibility.Hidden;
        }

        /// <summary>Primer elemento con userData de esa carta dentro de un contenedor.</summary>
        static VisualElement FindCardIn(VisualElement scope, CardDef c)
        {
            if (scope == null) return null;
            foreach (var e in scope.Query<VisualElement>().ToList())
                if (e.userData as CardDef == c) return e;
            return null;
        }

        void ApplyLift()
        {
            if (liftTile == null) return;
            liftTile.style.translate = new Translate(
                new Length(liftPos.x, LengthUnit.Pixel),
                new Length(liftPos.y, LengthUnit.Pixel));
            liftTile.style.rotate = new Rotate(new Angle(liftRot, AngleUnit.Degree));
            liftTile.style.scale = new Scale(new Vector3(liftScale, liftScale, 1f));
        }

        /// <summary>Saca la copia y devuelve la carta original a su hueco.</summary>
        void EndLift()
        {
            if (liftSource != null && liftSource.parent != null)
                liftSource.style.visibility = Visibility.Visible;
            liftSource = null;
            liftCard = null;
            lifting = false;
            liftBack = false;
            liftTimer?.Pause();
            liftTimer = null;
            if (liftTile != null) liftTile.style.display = DisplayStyle.None;
        }

        /// <summary>
        /// Devuelve false si no hay nada abierto, para que la tecla pueda seguir con su
        /// trabajo normal (terminar el turno, salir) cuando no hay carta en el aire.
        /// </summary>
        bool PutBackFromKey()
        {
            if (!lifting) return false;
            PutBack();
            return true;
        }

        /// <summary>Si la carta sigue en la mano o en algun tablero de esta partida.</summary>
        static bool StillInPlay(CardDef c, MatchState m)
        {
            if (c == null || m == null) return false;
            var hand = m.Active.hand;
            for (int i = 0; i < hand.Count; i++)
                if (hand[i] == c) return true;
            foreach (var p in m.players)
                for (int i = 0; i < p.board.Count; i++)
                    if (p.board[i] == c) return true;
            return false;
        }

        /// <summary>
        /// Marca un subarbol como no clickeable. En la carta en el aire es para que el
        /// click la atraviese y lo agarre la de abajo.
        /// </summary>
        static void SetIgnoreRecursive(VisualElement e)
        {
            e.pickingMode = PickingMode.Ignore;
            foreach (var child in e.Children()) SetIgnoreRecursive(child);
        }

        /// <summary>Mitad de la mesa: las cartas jugadas, centradas y con wrap.</summary>
        VisualElement TableRow()
        {
            var row = new VisualElement();
            row.style.flexGrow = 1;
            row.style.flexShrink = 1;
            row.style.flexDirection = FlexDirection.Row;
            row.style.flexWrap = Wrap.Wrap;
            row.style.alignItems = Align.Center;
            row.style.alignContent = Align.Center;
            row.style.justifyContent = Justify.Center;
            row.style.paddingTop = 8;
            row.style.paddingBottom = 8;
            row.style.paddingLeft = 6; row.style.paddingRight = 6;
            return row;
        }

        /// <summary>
        /// Escala las cartas y el chrome del escenario segun la altura de pantalla.
        /// En 1080 se usan los maximos; en pantallas bajas se achica para mantener
        /// visibles la mano, el tapete y la barra inferior.
        /// </summary>
        void RecalcLayout()
        {
            float k = Mathf.Clamp(Screen.height / 1080f, 0.60f, 1f);
            handCardW = Mathf.RoundToInt(HandCardWMax * k);
            tableCardW = Mathf.RoundToInt(TableCardWMax * k);
            handCardH = Mathf.RoundToInt(handCardW * (float)WSCardArt.CardH / WSCardArt.CardW);
            railW = Mathf.RoundToInt(RailWMax * k);
            crestW = Mathf.RoundToInt(CrestWMax * k);
            deckW = Mathf.RoundToInt(DeckWMax * k);
            medallionW = Mathf.RoundToInt(MedallionWMax * k);
            if (stage != null)
                stage.style.minHeight = Mathf.Clamp(Screen.height * 0.30f, 120f, 240f);
            if (handZone != null) handZone.style.height = handCardH + 32;
            ApplyStageLayout();
        }

        /// <summary>
        /// Reaplica los tamaños del escenario. Se llama aparte de RecalcLayout porque
        /// las piezas se miden en pixeles: los rombos del escudo y los reversos de las
        /// pilas se dibujan al ancho que tengan, no se estiran. Durante el Build el
        /// escenario todavia no existe y esto no hace nada.
        /// </summary>
        void ApplyStageLayout()
        {
            for (int i = 0; i < rails.Length; i++)
            {
                var r = rails[i];
                if (r == null || r.root == null) continue;
                r.root.style.width = railW;
                FillRailPile(r.deckStack, 1f);
                FillRailPile(r.playedStack, 0.62f);
                if (r.medal != null)
                {
                    r.medal.style.width = medallionW;
                    r.medal.style.height = medallionW;
                }
                if (r.medalValue != null) r.medalValue.style.fontSize = Mathf.RoundToInt(medallionW * 0.40f);
                if (r.medalSub != null) r.medalSub.style.fontSize = Mathf.RoundToInt(medallionW * 0.14f);
            }

            if (crest?.root == null) return;
            // El escudo es CUADRADO a proposito: los rombos se colocan con
            // porcentajes y un cuadrado es lo unico donde el mismo porcentaje
            // mide igual en horizontal que en vertical.
            crest.root.style.width = crestW;
            crest.root.style.height = crestW;
            // Un cuadrado rotado 45 grados ocupa side * raiz(2) a lo ancho. El 0.70
            // deja el halo dentro de la caja sin tocar los bordes.
            const float diag = 0.7071f;
            CrestSize(crest.halo, crestW * diag);
            CrestSize(crest.ring, crestW * diag * 0.79f);
            CrestSize(crest.ring2, crestW * diag * 0.57f);
            CrestSize(crest.core,  crestW * diag * 0.38f);
            if (crest.vs != null) crest.vs.style.fontSize = Mathf.RoundToInt(crestW * 0.24f);
        }

        static void CrestSize(VisualElement ring, float side)
        {
            if (ring == null) return;
            ring.style.width = side;
            ring.style.height = side;
        }

        // ── Mano: abanico absoluto ───────────────────────────────────────
        void BuildHand()
        {
            // El contenedor ocupa una franja fija abajo y NO recorta: las cartas
            // rotadas se salen de el hacia arriba.
            handZone = new VisualElement();
            handZone.style.flexShrink = 0;
            handZone.style.marginTop = -40;
            handZone.style.height = handCardH + 32;
            handZone.style.overflow = Overflow.Visible;

            hand = new VisualElement { name = "hand" };
            hand.style.position = Position.Absolute;
            hand.style.left = 0; hand.style.right = 0;
            hand.style.bottom = 0; hand.style.top = 0;
            hand.style.overflow = Overflow.Visible;
            handZone.Add(hand);

            root.Add(handZone);
        }

        // ── Barra inferior: estado de la partida ─────────────────────────
        // Tres piezas: EVENTO (ultimo log con punto de color), ACCION (que podes
        // hacer ahora, al centro) y FUSION + TERMINAR TURNO a la derecha.
        // Todo en pastillas sobre el fondo para que se lea sin competir con la mesa.
        void BuildBottomBar()
        {
            var bar = new VisualElement();
            bar.style.flexDirection = FlexDirection.Row;
            bar.style.alignItems = Align.Center;
            bar.style.height = 44;
            bar.style.flexShrink = 0;
            bar.style.marginTop = 4;

            var logPanel = new VisualElement();
            logPanel.style.flexDirection = FlexDirection.Row;
            logPanel.style.alignItems = Align.Center;
            logPanel.style.flexGrow = 1.1f;
            logPanel.style.flexShrink = 1;
            logPanel.style.minWidth = 0;
            logPanel.style.height = 34;
            logPanel.style.backgroundColor = new Color(0.055f, 0.085f, 0.165f, 0.95f);
            logPanel.style.paddingLeft = 12; logPanel.style.paddingRight = 12;
            logPanel.style.marginRight = 8;
            logPanel.style.borderTopLeftRadius = 9; logPanel.style.borderTopRightRadius = 9;
            logPanel.style.borderBottomLeftRadius = 9; logPanel.style.borderBottomRightRadius = 9;
            logPanel.style.borderTopWidth = 1; logPanel.style.borderBottomWidth = 1;
            logPanel.style.borderLeftWidth = 1; logPanel.style.borderRightWidth = 1;
            var logEdge = new StyleColor(new Color(0.28f, 0.38f, 0.60f, 0.45f));
            logPanel.style.borderTopColor = logEdge; logPanel.style.borderBottomColor = logEdge;
            logPanel.style.borderLeftColor = logEdge; logPanel.style.borderRightColor = logEdge;
            logPanel.pickingMode = PickingMode.Ignore;

            logDot = new VisualElement();
            logDot.style.width = 8; logDot.style.height = 8;
            logDot.style.flexShrink = 0;
            logDot.style.marginRight = 9;
            logDot.style.backgroundColor = ColGold;
            logDot.style.borderTopLeftRadius = 100; logDot.style.borderTopRightRadius = 100;
            logDot.style.borderBottomLeftRadius = 100; logDot.style.borderBottomRightRadius = 100;
            logDot.pickingMode = PickingMode.Ignore;
            logPanel.Add(logDot);

            logLabel = new Label("");
            logLabel.style.flexGrow = 1;
            logLabel.style.fontSize = 12;
            logLabel.style.color = ColText;
            logLabel.style.overflow = Overflow.Hidden;
            logLabel.style.whiteSpace = WhiteSpace.NoWrap;
            logLabel.pickingMode = PickingMode.Ignore;
            logPanel.Add(logLabel);
            bar.Add(logPanel);

            // Placa de ayuda. Mismo lenguaje que la del titulo — doble filete y dos
            // rombos de remate en las puntas — y NO el nameplate del proyecto: ese
            // es una banda de 10:1 y la barra es de 26:1, estirada la filigrana de
            // las puntas se convierte en manchas. Sprite queda como prompt pendiente
            // (WS_UI_SPRITE_PROMPTS.md, pieza 6) para cuando haya uno de proporción
            // correcta; hasta entonces, esto.
            hintPanel = new VisualElement { name = "hint-plate" };
            hintPanel.style.position = Position.Relative;
            hintPanel.style.flexDirection = FlexDirection.Row;
            hintPanel.style.alignItems = Align.Center;
            hintPanel.style.justifyContent = Justify.Center;
            hintPanel.style.flexGrow = 1.6f;
            hintPanel.style.flexShrink = 1;
            hintPanel.style.minWidth = 0;
            hintPanel.style.height = 38;
            hintPanel.style.marginRight = 8;
            hintPanel.style.overflow = Overflow.Hidden;
            hintPanel.style.backgroundColor = new Color(0.075f, 0.115f, 0.215f, 0.98f);
            hintPanel.style.borderTopWidth = 1; hintPanel.style.borderBottomWidth = 1;
            hintPanel.style.borderLeftWidth = 1; hintPanel.style.borderRightWidth = 1;
            hintPanel.style.borderTopColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.55f));
            hintPanel.style.borderBottomColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.55f));
            hintPanel.style.borderLeftColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.55f));
            hintPanel.style.borderRightColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.55f));
            hintPanel.style.borderTopLeftRadius = 10; hintPanel.style.borderTopRightRadius = 10;
            hintPanel.style.borderBottomLeftRadius = 10; hintPanel.style.borderBottomRightRadius = 10;
            hintPanel.pickingMode = PickingMode.Ignore;

            // Filete interior: la segunda linea que le da grosor a la chapa.
            var hintInner = new VisualElement { name = "hint-plate-inner" };
            hintInner.style.position = Position.Absolute;
            hintInner.style.left = 4; hintInner.style.right = 4;
            hintInner.style.top = 4; hintInner.style.bottom = 4;
            hintInner.style.borderTopWidth = 1; hintInner.style.borderBottomWidth = 1;
            hintInner.style.borderLeftWidth = 1; hintInner.style.borderRightWidth = 1;
            hintInner.style.borderTopColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.20f));
            hintInner.style.borderBottomColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.20f));
            hintInner.style.borderLeftColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.20f));
            hintInner.style.borderRightColor = new StyleColor(new Color(0.35f, 0.85f, 1f, 0.20f));
            hintInner.style.borderTopLeftRadius = 7; hintInner.style.borderTopRightRadius = 7;
            hintInner.style.borderBottomLeftRadius = 7; hintInner.style.borderBottomRightRadius = 7;
            hintInner.pickingMode = PickingMode.Ignore;
            hintPanel.Add(hintInner);

            hintLabel = new Label("");
            hintLabel.style.position = Position.Relative;
            hintLabel.style.fontSize = 12;
            hintLabel.style.color = ColText;
            hintLabel.style.unityTextAlign = TextAnchor.MiddleCenter;
            hintLabel.style.overflow = Overflow.Hidden;
            hintLabel.style.whiteSpace = WhiteSpace.NoWrap;
            hintLabel.style.flexGrow = 1;
            hintLabel.style.minWidth = 0;
            hintLabel.style.marginLeft = 26;
            hintLabel.style.marginRight = 26;
            hintLabel.pickingMode = PickingMode.Ignore;
            hintPanel.Add(hintLabel);
            bar.Add(hintPanel);

            fuseRow = new VisualElement();
            fuseRow.style.flexDirection = FlexDirection.Row;
            fuseRow.style.alignItems = Align.Center;
            fuseRow.style.flexShrink = 0;
            fuseRow.style.marginRight = 8;
            bar.Add(fuseRow);

            // Terminar turno: la pastilla universal del proyecto teñida de oro. El
            // boton conserva su USS por si el sprite no llegara a importarse.
            var end = new Button(() => OnEndTurn()) { text = "TERMINAR TURNO ▸" };
            end.tooltip = "Terminar turno ([Espacio])";
            end.style.height = 38;
            end.style.flexShrink = 0;
            end.style.fontSize = 12;
            end.style.unityFontStyleAndWeight = FontStyle.Bold;
            end.style.letterSpacing = 1;
            end.style.paddingLeft = 18; end.style.paddingRight = 18;
            end.style.borderTopLeftRadius = 12; end.style.borderTopRightRadius = 12;
            end.style.borderBottomLeftRadius = 12; end.style.borderBottomRightRadius = 12;
            var endArt = Art("WS_btn_plate");
            if (endArt != null)
            {
                end.style.backgroundImage = new StyleBackground(endArt);
                end.style.backgroundSize = SizeFill;
                end.style.backgroundPositionX = new BackgroundPosition(BackgroundPositionKeyword.Center);
                end.style.backgroundPositionY = new BackgroundPosition(BackgroundPositionKeyword.Center);
                end.style.backgroundRepeat = new BackgroundRepeat(Repeat.NoRepeat, Repeat.NoRepeat);
                end.style.unityBackgroundImageTintColor = new Color(1f, 0.82f, 0.42f, 1f);
                endTurnHasArt = true;
            }
            bar.Add(end);
            endTurnBtn = end;

            root.Add(bar);
        }

        void BuildWinOverlay()
        {
            winOverlay = new VisualElement();
            winOverlay.style.display = DisplayStyle.None;
            winOverlay.style.position = Position.Absolute;
            winOverlay.style.left = 0; winOverlay.style.top = 0;
            winOverlay.style.right = 0; winOverlay.style.bottom = 0;
            winOverlay.style.alignItems = Align.Center;
            winOverlay.style.justifyContent = Justify.Center;
            winOverlay.style.backgroundColor = new Color(0.02f, 0.03f, 0.08f, 0.88f);

            var box = new VisualElement();
            box.style.backgroundColor = ColPanel;
            box.style.borderTopLeftRadius = 12; box.style.borderTopRightRadius = 12;
            box.style.borderBottomLeftRadius = 12; box.style.borderBottomRightRadius = 12;
            box.style.paddingLeft = 40; box.style.paddingRight = 40;
            box.style.paddingTop = 28; box.style.paddingBottom = 28;
            box.style.alignItems = Align.Center;
            box.style.borderTopWidth = 2; box.style.borderBottomWidth = 2;
            box.style.borderLeftWidth = 2; box.style.borderRightWidth = 2;
            box.style.borderTopColor = new StyleColor(ColGold);
            box.style.borderBottomColor = new StyleColor(ColGold);
            box.style.borderLeftColor = new StyleColor(ColGold);
            box.style.borderRightColor = new StyleColor(ColGold);

            winLabel = new Label("");
            winLabel.style.fontSize = 26;
            winLabel.style.unityFontStyleAndWeight = FontStyle.Bold;
            winLabel.style.color = ColGold;
            winLabel.style.whiteSpace = WhiteSpace.Normal;
            winLabel.style.unityTextAlign = TextAnchor.MiddleCenter;
            box.Add(winLabel);

            var back = new Button(() => { WSAudio.Back(); OnBackPressed?.Invoke(); }) { text = "VOLVER" };
            back.style.marginTop = 20;
            back.style.fontSize = 14;
            back.style.color = ColText;
            back.style.backgroundColor = ColPanelSoft;
            back.style.paddingLeft = 22; back.style.paddingRight = 22;
            back.style.paddingTop = 8; back.style.paddingBottom = 8;
            back.style.borderTopLeftRadius = 6; back.style.borderTopRightRadius = 6;
            back.style.borderBottomLeftRadius = 6; back.style.borderBottomRightRadius = 6;
            box.Add(back);

            winOverlay.Add(box);
            root.Add(winOverlay);
        }

        void BuildDefenseOverlay()
        {
            defenseOverlay = new VisualElement { name = "attack-defense-overlay" };
            defenseOverlay.style.display = DisplayStyle.None;
            defenseOverlay.style.position = Position.Absolute;
            defenseOverlay.style.left = 0; defenseOverlay.style.top = 0;
            defenseOverlay.style.right = 0; defenseOverlay.style.bottom = 0;
            defenseOverlay.style.alignItems = Align.Center;
            defenseOverlay.style.justifyContent = Justify.Center;
            defenseOverlay.style.backgroundColor = new Color(0.015f, 0.025f, 0.06f, 0.88f);

            var box = new VisualElement { name = "attack-defense-panel" };
            box.style.width = 380;
            box.style.maxWidth = Length.Percent(90);
            box.style.alignItems = Align.Center;
            box.style.backgroundColor = ColPanel;
            box.style.paddingLeft = 24; box.style.paddingRight = 24;
            box.style.paddingTop = 22; box.style.paddingBottom = 22;
            Border(box, ColGold, 2);

            defenseTitle = new Label("¡TE ATACARON!");
            defenseTitle.style.fontSize = 22;
            defenseTitle.style.color = ColGold;
            defenseTitle.style.unityFontStyleAndWeight = FontStyle.Bold;
            defenseTitle.style.marginBottom = 12;
            box.Add(defenseTitle);

            defenseCardSlot = new VisualElement { name = "attacked-card-preview" };
            defenseCardSlot.style.width = 74;
            defenseCardSlot.style.height = Mathf.RoundToInt(74f * 1030f / 560f);
            defenseCardSlot.style.marginBottom = 10;
            box.Add(defenseCardSlot);

            defenseDetails = new Label("");
            defenseDetails.style.maxWidth = 320;
            defenseDetails.style.whiteSpace = WhiteSpace.Normal;
            defenseDetails.style.fontSize = 13;
            defenseDetails.style.color = ColText;
            defenseDetails.style.unityTextAlign = TextAnchor.MiddleCenter;
            defenseDetails.style.marginBottom = 16;
            box.Add(defenseDetails);

            var useProtector = new Button(() => ResolveDefense(true)) { text = "USAR UN PROTECTOR" };
            StyleDefenseButton(useProtector, ColGold, new Color(0.25f, 0.21f, 0.11f, 1f));
            box.Add(useProtector);

            var sacrifice = new Button(() => ResolveDefense(false)) { text = "SACRIFICAR LA CARTA" };
            StyleDefenseButton(sacrifice, ColText, ColPanelSoft);
            sacrifice.style.marginTop = 8;
            box.Add(sacrifice);

            defenseOverlay.Add(box);
            root.Add(defenseOverlay);
        }

        void BuildGalaxyOverlay()
        {
            galaxyOverlay = new VisualElement { name = "galaxy-exchange-overlay" };
            galaxyOverlay.style.display = DisplayStyle.None;
            galaxyOverlay.style.position = Position.Absolute;
            galaxyOverlay.style.left = 0; galaxyOverlay.style.top = 0;
            galaxyOverlay.style.right = 0; galaxyOverlay.style.bottom = 0;
            galaxyOverlay.style.alignItems = Align.Center;
            galaxyOverlay.style.justifyContent = Justify.Center;
            galaxyOverlay.style.backgroundColor = new Color(0.015f, 0.025f, 0.06f, 0.88f);

            var box = new VisualElement { name = "galaxy-exchange-panel" };
            box.style.width = 400;
            box.style.maxWidth = Length.Percent(90);
            box.style.alignItems = Align.Center;
            box.style.backgroundColor = ColPanel;
            box.style.paddingLeft = 24; box.style.paddingRight = 24;
            box.style.paddingTop = 22; box.style.paddingBottom = 22;
            Border(box, new Color(0.75f, 0.55f, 1f, 1f), 2);

            var title = new Label("CANJE DE GALAXIA");
            title.style.fontSize = 20;
            title.style.color = new Color(0.82f, 0.67f, 1f, 1f);
            title.style.unityFontStyleAndWeight = FontStyle.Bold;
            title.style.marginBottom = 10;
            box.Add(title);

            var details = new Label("La Galaxia vuelve a tu mazo. Recibís cartas al azar de tu colección propia y van a tu mano. La opción de Planetas necesita espacio para las tres.");
            details.style.maxWidth = 340;
            details.style.whiteSpace = WhiteSpace.Normal;
            details.style.fontSize = 13;
            details.style.color = ColText;
            details.style.unityTextAlign = TextAnchor.MiddleCenter;
            details.style.marginBottom = 16;
            box.Add(details);

            galaxyStarButton = new Button(() => ResolveGalaxyExchange(BodyCategory.Star))
                { text = "CANJEAR POR 1 ESTRELLA" };
            galaxyStarButton.tooltip = "La Galaxia vuelve a tu mazo y recibís 1 Estrella desbloqueada de tu colección.";
            StyleDefenseButton(galaxyStarButton, ColGold, ColPanelSoft);
            box.Add(galaxyStarButton);

            galaxyPlanetsButton = new Button(() => ResolveGalaxyExchange(BodyCategory.Planet))
                { text = "CANJEAR POR 3 PLANETAS" };
            galaxyPlanetsButton.tooltip = "La Galaxia vuelve a tu mazo y recibís 3 Planetas desbloqueados de tu colección; hace falta espacio para las tres cartas.";
            StyleDefenseButton(galaxyPlanetsButton, ColText, ColPanelSoft);
            galaxyPlanetsButton.style.marginTop = 8;
            box.Add(galaxyPlanetsButton);

            var play = new Button(PlayGalaxyNormally) { text = "JUGAR EN LA MESA" };
            StyleDefenseButton(play, ColCyan, ColPanelSoft);
            play.style.marginTop = 8;
            box.Add(play);

            var cancel = new Button(CloseGalaxyChoice) { text = "CANCELAR" };
            StyleDefenseButton(cancel, ColMuted, ColPanel);
            cancel.style.marginTop = 8;
            box.Add(cancel);

            galaxyOverlay.Add(box);
            root.Add(galaxyOverlay);
        }

        static void StyleDefenseButton(Button button, Color color, Color background)
        {
            button.style.width = 250;
            button.style.height = 40;
            button.style.color = color;
            button.style.unityFontStyleAndWeight = FontStyle.Bold;
            button.style.backgroundColor = background;
            button.style.borderTopWidth = 1; button.style.borderBottomWidth = 1;
            button.style.borderLeftWidth = 1; button.style.borderRightWidth = 1;
            button.style.borderTopColor = new StyleColor(color);
            button.style.borderBottomColor = new StyleColor(color);
            button.style.borderLeftColor = new StyleColor(color);
            button.style.borderRightColor = new StyleColor(color);
        }

        static void StyleStatusButton(Button button, Color color)
        {
            button.style.borderTopWidth = 1; button.style.borderBottomWidth = 1;
            button.style.borderLeftWidth = 1; button.style.borderRightWidth = 1;
            button.style.borderTopColor = new StyleColor(color);
            button.style.borderBottomColor = new StyleColor(color);
            button.style.borderLeftColor = new StyleColor(color);
            button.style.borderRightColor = new StyleColor(color);
        }

        /// <summary>
        /// Punto de color del evento: el log se lee de un vistazo sin leer el texto.
        /// Ataque = rojo, rival = cyan, victoria/fusion = verde, resto = oro.
        /// </summary>
        static Color LogColor(string log)
        {
            if (string.IsNullOrEmpty(log)) return ColMuted;
            if (log.StartsWith("Gana") || log.Contains("fusiona") || log.Contains("completo"))
                return ColOk;
            if (log.Contains("atac") || log.Contains("retir"))
                return ColOff;
            if (log.StartsWith("Rival") || log.Contains("revela"))
                return ColCyan;
            return ColGold;
        }

        static void Border(VisualElement element, Color color, float width)
        {
            element.style.borderTopWidth = width; element.style.borderBottomWidth = width;
            element.style.borderLeftWidth = width; element.style.borderRightWidth = width;
            element.style.borderTopColor = new StyleColor(color);
            element.style.borderBottomColor = new StyleColor(color);
            element.style.borderLeftColor = new StyleColor(color);
            element.style.borderRightColor = new StyleColor(color);
            element.style.borderTopLeftRadius = 4; element.style.borderTopRightRadius = 4;
            element.style.borderBottomLeftRadius = 4; element.style.borderBottomRightRadius = 4;
        }

        // ── Arranque ──────────────────────────────────────────────────────
        /// <summary>
        /// El Hub pasa el id del modo. El unico implementado es el clasico, asi que
        /// cualquier id cae al clasico: el parametro se acepta para no romper el
        /// cableado de WSApp, no para elegir reglas.
        /// </summary>
        public void StartMatch(string universeId, string modeId)
        {
            match = MatchController.NewGame();
            selectedHand = -1;
            galaxyChoiceOpen = false;
            if (galaxyOverlay != null) galaxyOverlay.style.display = DisplayStyle.None;
            rivalFacesRevealed = true;
            revealAnimating = false;
            combatAnimating = false;
            aiTurnWaitingForDefense = false;
            revealSerial++;
            combatTicker?.Pause();
            combatTicker = null;
            combatFlights.Clear();
            combatAfter = null;
            combatLayer?.Clear();
            EndLift();          // de la partida anterior, si quedo una carta en el aire
            CancelPress();
            aiTimer?.Pause();
            aiTimer = null;
            Refresh();
            KickAI();          // por si el turno arrancara en la IA
        }

        void OnEndTurn()
        {
            if (match == null || match.winner.HasValue || combatAnimating || revealAnimating
                || match.pendingAttack != null || galaxyChoiceOpen) return;
            if (!match.Active.isHuman) { WSAudio.Denied(); return; }
            WSAudio.Confirm();
            rivalFacesRevealed = false;
            MatchController.EndTurn(match);
            selectedHand = -1;
            Refresh();
            KickAI();
        }

        // ── Rival automatico ─────────────────────────────────────────────
        /// <summary>
        /// Si el turno activo no es de una persona, se lo damos a la IA. Va con
        /// schedule y no en el click: un turno de IA son varias acciones y si se
        /// ejecutara de golpe el jugador no veria nada de lo que paso.
        /// </summary>
        void KickAI()
        {
            if (match == null || match.winner.HasValue) return;
            if (match.Active.isHuman) return;
            if (aiTimer != null) return;
            aiTimer = root.schedule.Execute(RunAI).StartingIn(500);
        }

        void RunAI()
        {
            aiTimer = null;
            if (match == null || match.winner.HasValue || match.pendingAttack != null) return;

            WSAI.PlayTurn(match, match.activePlayer);
            Refresh();

            if (match.pendingAttack != null)
            {
                aiTurnWaitingForDefense = true;
                return;
            }

            var combat = TakeLastCombat();
            if (!match.winner.HasValue && match.Active.isHuman)
            {
                if (combat != null) AnimateCombat(combat, StartRivalReveal);
                else StartRivalReveal();
                return;
            }

            if (combat != null) AnimateCombat(combat);

            // Si la IA no termino la partida, sigue jugando.
            if (!match.winner.HasValue && !match.Active.isHuman)
                aiTimer = root.schedule.Execute(RunAI).StartingIn(1100);
        }

        // ── Interaccion ───────────────────────────────────────────────────
        void OnHandClicked(int index)
        {
            if (match == null || match.winner.HasValue || combatAnimating || revealAnimating
                || match.pendingAttack != null || galaxyChoiceOpen) return;
            if (!match.Active.isHuman) { WSAudio.Denied(); return; }   // turno de la IA
            var p = match.Active;
            if (index < 0 || index >= p.hand.Count) return;

            // Primera vez: seleccionar (el marco se enciende y la carta sube).
            // Segunda vez sobre la MISMA carta: jugarla, que la lleva al centro.
            if (selectedHand == index) { PlaySelected(); return; }

            selectedHand = index;
            WSAudio.Click();
            Refresh();
        }

        void PlaySelected()
        {
            if (match == null || selectedHand < 0 || selectedHand >= match.Active.hand.Count) return;
            if (combatAnimating || revealAnimating || match.pendingAttack != null || !match.Active.isHuman) { WSAudio.Denied(); return; }
            var card = match.Active.hand[selectedHand];
            bool needed = MatchController.IsNeededForObjective(match, match.Active, card);
            if (card.category == BodyCategory.Galaxy && !needed)
            {
                ShowGalaxyChoice();
                return;
            }

            CommitSelectedPlay();
        }

        void CommitSelectedPlay()
        {
            if (match == null || selectedHand < 0 || selectedHand >= match.Active.hand.Count) return;
            if (MatchController.Play(match, match.activePlayer, selectedHand))
            {
                WSAudio.Confirm();
                selectedHand = -1;
            }
            else WSAudio.Denied();
            Refresh();
        }

        void ShowGalaxyChoice()
        {
            if (match == null || galaxyOverlay == null || selectedHand < 0) return;
            galaxyStarButton.SetEnabled(MatchController.CanExchangeGalaxy(
                match, match.activePlayer, selectedHand, BodyCategory.Star));
            galaxyPlanetsButton.SetEnabled(MatchController.CanExchangeGalaxy(
                match, match.activePlayer, selectedHand, BodyCategory.Planet));
            galaxyChoiceOpen = true;
            galaxyOverlay.style.display = DisplayStyle.Flex;
            WSAudio.Confirm();
            Refresh();
        }

        void CloseGalaxyChoice()
        {
            galaxyChoiceOpen = false;
            if (galaxyOverlay != null) galaxyOverlay.style.display = DisplayStyle.None;
            WSAudio.Back();
            Refresh();
        }

        void ResolveGalaxyExchange(BodyCategory rewardTier)
        {
            if (match == null || selectedHand < 0) return;
            if (!MatchController.ExchangeGalaxy(match, match.activePlayer, selectedHand, rewardTier))
            {
                WSAudio.Denied();
                ShowGalaxyChoice();
                return;
            }

            galaxyChoiceOpen = false;
            galaxyOverlay.style.display = DisplayStyle.None;
            selectedHand = -1;
            WSAudio.Confirm();
            Refresh();
        }

        void PlayGalaxyNormally()
        {
            galaxyChoiceOpen = false;
            if (galaxyOverlay != null) galaxyOverlay.style.display = DisplayStyle.None;
            CommitSelectedPlay();
        }

        /// <summary>Click en la mitad baja de la mesa con una carta elegida: jugarla.</summary>
        void OnMyBoardClicked(ClickEvent e)
        {
            if (match == null || match.winner.HasValue || combatAnimating || revealAnimating
                || match.pendingAttack != null || galaxyChoiceOpen) return;
            if (selectedHand < 0 || !match.Active.isHuman) { WSAudio.Denied(); return; }
            e.StopPropagation();
            PlaySelected();
        }

        /// <summary>Click en una carta del rival: atacar con la seleccionada.</summary>
        void OnRivalBoardClicked(int boardIndex)
        {
            if (match == null || match.winner.HasValue || combatAnimating || revealAnimating
                || match.pendingAttack != null || galaxyChoiceOpen) return;
            if (selectedHand < 0 || !match.Active.isHuman) { WSAudio.Denied(); Refresh(); return; }
            if (MatchController.Attack(match, match.activePlayer, boardIndex, selectedHand))
            {
                WSAudio.Confirm();
                selectedHand = -1;
            }
            else WSAudio.Denied();
            Refresh();
            if (match.pendingAttack != null) ShowDefensePrompt();
            else AnimateLastCombat();
        }

        CombatResolution TakeLastCombat()
        {
            var combat = match != null ? match.lastCombat : null;
            if (match != null) match.lastCombat = null;
            return combat;
        }

        void AnimateLastCombat()
        {
            var combat = TakeLastCombat();
            if (combat != null) AnimateCombat(combat);
        }

        void AnimateCombat(CombatResolution combat, Action after = null)
        {
            if (combat == null || combatLayer == null || root == null)
            {
                after?.Invoke();
                return;
            }

            combatAnimating = true;
            Refresh();
            combatLayer.Clear();
            combatFlights.Clear();

            // Las dos cartas vuelan al centro del tapete y desde ahi a la pila de su
            // dueño. Los rieles quedan fuera del tapete, asi que el punto de encuentro
            // ya no es el medio de la pantalla: es el centro de las dos pilas.
            var arenaCenter = arena.worldBound.center;
            var pileA = rails[0].deckStack.worldBound.center;
            var pileB = rails[1].deckStack.worldBound.center;
            var stackWorld = new Vector2((pileA.x + pileB.x) * 0.5f, arenaCenter.y);
            var handCenter = handZone.worldBound.center;
            var attackerStart = handCenter;
            var defenderStart = combat.attackerIndex == 0 ? rivalRow.worldBound.center : mineRow.worldBound.center;

            AddCombatFlight(combat.attackerCard, attackerStart,
                stackWorld, rails[combat.attackerIndex].deckStack.worldBound.center, -5f);
            AddCombatFlight(combat.returnedCard, defenderStart,
                stackWorld + new Vector2(3, 5), rails[combat.returnedOwnerIndex].deckStack.worldBound.center, 5f);

            if (combatFlights.Count == 0)
            {
                FinishCombatAnimation(after);
                return;
            }

            combatAfter = after;
            combatTicker?.Pause();
            combatTicker = root.schedule.Execute(AnimateCombatFlights).Every(16);
        }

        Action combatAfter;

        void AddCombatFlight(CardDef card, Vector2 startWorld, Vector2 stackWorld,
            Vector2 targetWorld, float rotation)
        {
            if (card == null) return;
            int width = Mathf.Max(44, Mathf.RoundToInt(tableCardW * 0.76f));
            int height = Mathf.RoundToInt(width * 1030f / 560f);
            var tile = WSCardArt.BuildTile(card, width);
            tile.name = "combat-return-card";
            tile.style.position = Position.Absolute;
            tile.style.width = width;
            tile.style.height = height;
            tile.pickingMode = PickingMode.Ignore;
            combatLayer.Add(tile);

            var start = combatLayer.WorldToLocal(startWorld);
            tile.style.left = start.x - width * 0.5f;
            tile.style.top = start.y - height * 0.5f;
            tile.style.rotate = new Rotate(rotation);

            combatFlights.Add(new CombatFlight
            {
                tile = tile,
                start = start,
                stack = combatLayer.WorldToLocal(stackWorld),
                target = combatLayer.WorldToLocal(targetWorld),
                width = width,
                height = height,
                startedAt = Time.unscaledTime,
                duration = 0.72f,
                rotation = rotation,
            });
        }

        void AnimateCombatFlights()
        {
            float now = Time.unscaledTime;
            for (int i = combatFlights.Count - 1; i >= 0; i--)
            {
                var f = combatFlights[i];
                float t = Mathf.Clamp01((now - f.startedAt) / f.duration);
                const float stackAt = 0.62f;
                Vector2 pos;
                if (t < stackAt)
                {
                    float u = Ease(t / stackAt);
                    pos = Vector2.Lerp(f.start, f.stack, u);
                }
                else
                {
                    float u = Ease((t - stackAt) / (1f - stackAt));
                    pos = Vector2.Lerp(f.stack, f.target, u);
                }

                f.tile.style.left = pos.x - f.width * 0.5f;
                f.tile.style.top = pos.y - f.height * 0.5f;
                f.tile.style.rotate = new Rotate(f.rotation * (1f - t));
                float scale = Mathf.Lerp(1f, 0.52f, Ease(t));
                f.tile.style.scale = new Scale(new Vector3(scale, scale, 1f));

                if (t >= 1f)
                {
                    combatLayer.Remove(f.tile);
                    combatFlights.RemoveAt(i);
                }
            }

            if (combatFlights.Count == 0) FinishCombatAnimation(combatAfter);
        }

        static float Ease(float t) => t * t * (3f - 2f * t);

        void FinishCombatAnimation(Action after)
        {
            combatTicker?.Pause();
            combatTicker = null;
            combatFlights.Clear();
            combatLayer?.Clear();
            combatAnimating = false;
            combatAfter = null;
            Refresh();
            after?.Invoke();
        }

        void StartRivalReveal()
        {
            if (match == null || match.winner.HasValue || !match.Active.isHuman) return;
            int serial = ++revealSerial;
            rivalFacesRevealed = false;
            var cards = match.players[1].board.ToList();
            revealAnimating = cards.Count > 0;
            Refresh();
            if (cards.Count == 0)
            {
                rivalFacesRevealed = true;
                revealAnimating = false;
                Refresh();
                return;
            }

            int remaining = cards.Count;
            for (int i = 0; i < cards.Count; i++)
            {
                int index = i;
                rivalRow.schedule.Execute(() =>
                {
                    if (serial != revealSerial) return;
                    FlipRivalCard(index, cards[index], () =>
                    {
                        if (serial != revealSerial || --remaining > 0) return;
                        revealAnimating = false;
                        rivalFacesRevealed = true;
                        Refresh();
                    });
                }).StartingIn(80 + i * 100);
            }
        }

        void FlipRivalCard(int index, CardDef card, Action done)
        {
            if (index < 0 || index >= rivalRow.childCount) { done?.Invoke(); return; }
            var holder = rivalRow[index];
            if (holder.childCount == 0) { done?.Invoke(); return; }
            var back = holder[0];

            TweenScaleX(back, 1f, 0.04f, 150, () =>
            {
                if (holder.panel == null) { done?.Invoke(); return; }
                var face = WSCardArt.BuildTile(card, tableCardW);
                face.style.scale = new Scale(new Vector3(0.04f, 1f, 1f));
                holder.Remove(back);
                holder.Insert(0, face);
                TweenScaleX(face, 0.04f, 1f, 180, done);
            });
        }

        void TweenScaleX(VisualElement element, float from, float to, long durationMs, Action done)
        {
            element.style.scale = new Scale(new Vector3(from, 1f, 1f));
            float startedAt = Time.unscaledTime;
            IVisualElementScheduledItem tween = null;
            tween = root.schedule.Execute(() =>
            {
                if (element.panel == null)
                {
                    tween?.Pause();
                    done?.Invoke();
                    return;
                }

                float t = Mathf.Clamp01((Time.unscaledTime - startedAt) / (durationMs / 1000f));
                element.style.scale = new Scale(new Vector3(Mathf.Lerp(from, to, Ease(t)), 1f, 1f));
                if (t < 1f) return;
                tween?.Pause();
                done?.Invoke();
            }).Every(16);
        }

        void ShowDefensePrompt()
        {
            if (match == null || match.pendingAttack == null || defenseCardSlot == null) return;
            var pending = match.pendingAttack;
            defenseTitle.text = "¡TE ATACARON!";
            defenseCardSlot.Clear();
            defenseCardSlot.Add(WSCardArt.BuildTile(pending.victimCard, 74));
            string protector = pending.protectors.Count > 0 ? pending.protectors[0].name : "un protector";
            defenseDetails.text = $"Usá {protector} para salvar {pending.victimCard.name}. Si la sacrificás, vuelve a tu mazo; en ambos casos la carta atacante vuelve al mazo del rival.";
        }

        void ResolveDefense(bool useProtector)
        {
            if (match == null || match.pendingAttack == null || combatAnimating) return;
            bool finishAiTurn = aiTurnWaitingForDefense;
            if (!MatchController.ResolvePendingAttack(match, useProtector)) return;
            WSAudio.Confirm();
            var combat = TakeLastCombat();
            if (combat != null)
                AnimateCombat(combat, finishAiTurn ? EndAiTurnAfterDefense : null);
            else if (finishAiTurn) EndAiTurnAfterDefense();
            else Refresh();
        }

        void EndAiTurnAfterDefense()
        {
            aiTurnWaitingForDefense = false;
            if (match == null || match.winner.HasValue || match.activePlayer != 1) return;
            MatchController.EndTurn(match);
            rivalFacesRevealed = false;
            Refresh();
            StartRivalReveal();
        }

        // ── Pintado ───────────────────────────────────────────────────────
        void Refresh()
        {
            if (match == null || root == null) return;
            var p = match.Active;
            var you = match.players[0];
            var rival = match.players[1];

            objectiveLabel.text = $"OBJETIVO  {match.objective.name}";
            progressLabel.text = ProgressLine(you, rival);
            pileLabel.text = $"MAZO  {p.deck.Count}";
            turnLabel.text = match.winner.HasValue
                ? $"GANA  {MatchController.Name(match.winner.Value).ToUpper()}"
                : $"TURNO · {MatchController.Name(match.activePlayer).ToUpper()}";

            // La mesa conserva la perspectiva humana durante ambos turnos. Así el
            // jugador nunca pierde de vista sus cartas y el mazo del rival puede
            // ocultarse/revelarse sin invertir las filas.
            DrawBoard(mineRow, you, false);
            DrawBoard(rivalRow, rival, true);
            DrawFan();
            DrawFusions();

            // Rieles. El medallón lleva el avance real de cada lado sobre el
            // objetivo, no un contador de cartas: es el numero que decide quien
            // gana, y va al lado del tapete que le corresponde.
            int need = ObjectiveNeed();
            SetRail(rails[1], rival, CountProgress(rival), need);
            SetRail(rails[0], you, CountProgress(you), need);
            if (mineCountLabel != null) mineCountLabel.text = $"{you.board.Count}";
            if (rivalCountLabel != null) rivalCountLabel.text = $"{rival.board.Count}";

            string lastLog = match.log.Count > 0 ? match.log[match.log.Count - 1] : "";
            logLabel.text = lastLog;
            logLabel.tooltip = lastLog;
            if (logDot != null) logDot.style.backgroundColor = LogColor(lastLog);
            hintLabel.text = Hint(p);
            hintLabel.tooltip = hintLabel.text;

            // La mano y los dos tableros se reconstruyen enteros en cada repintado, asi
            // que el elemento de la carta levantada deja de existir: hay que volver a
            // engancharlo al nuevo para que siga oculto mientras la copia vuela, y si
            // la carta ya no esta en juego, la copia se va.
            if (lifting) RelinkLift();

            // Mientras juega la IA no se puede tocar nada: se ve su tablero moverse.
            bool playerCanAct = match.Active.isHuman && !match.winner.HasValue
                && !combatAnimating && !revealAnimating && match.pendingAttack == null && !galaxyChoiceOpen;
            hand.style.opacity = match.Active.isHuman ? 1f : 0.55f;
            endTurnBtn.SetEnabled(playerCanAct);
            bool endOn = playerCanAct;
            // Con sprite de fondo el apagado va en el tinte, no en backgroundColor:
            // el color queda detras de la imagen y no se veria. Y el TEXTO se pone
            // oscuro, porque la pastilla ya es dorada: oro sobre oro no se lee.
            endTurnBtn.style.opacity = endOn ? 1f : 0.45f;
            if (endTurnHasArt)
            {
                endTurnBtn.style.color = endOn ? new Color(0.10f, 0.07f, 0.02f, 1f) : new Color(0.62f, 0.66f, 0.74f, 1f);
                endTurnBtn.style.unityBackgroundImageTintColor = endOn
                    ? new Color(1f, 0.82f, 0.42f, 1f)
                    : new Color(0.30f, 0.34f, 0.44f, 1f);
            }
            else
            {
                endTurnBtn.style.color = endOn ? ColGold : ColMuted;
                endTurnBtn.style.backgroundColor = endOn
                    ? new Color(0.24f, 0.20f, 0.10f, 1f)
                    : ColPanel;
            }
            StyleStatusButton(endTurnBtn, endOn ? ColGold : ColMuted);
            if (hintPanel != null)
            {
                // La accion actual respira: borde oro cuando hay una carta elegida
                // o una defensa pendiente, tenue en turno rival.
                bool hot = selectedHand >= 0 || match.pendingAttack != null;
                var edge = hot ? ColGold
                    : !match.Active.isHuman ? new Color(0.28f, 0.38f, 0.60f, 0.35f)
                    : new Color(0.35f, 0.85f, 1f, 0.55f);
                hintPanel.style.borderTopColor = new StyleColor(edge);
                hintPanel.style.borderBottomColor = new StyleColor(edge);
                hintPanel.style.borderLeftColor = new StyleColor(edge);
                hintPanel.style.borderRightColor = new StyleColor(edge);
                hintLabel.style.color = match.Active.isHuman ? ColText : ColMuted;
            }

            // El PanelSettings va sin theme: sin fuente no pinta ningun texto.
            WSFontFix.Apply(root);

            bool won = match.winner.HasValue;
            winOverlay.style.display = won ? DisplayStyle.Flex : DisplayStyle.None;
            if (won && winLabel != null)
                winLabel.text = $"{MatchController.Name(match.winner.Value).ToUpper()} COMPLETO\n{match.objective.name.ToUpper()}";

            bool awaitingHumanDefense = match.pendingAttack != null && match.pendingAttack.defenderIndex == 0;
            defenseOverlay.style.display = awaitingHumanDefense ? DisplayStyle.Flex : DisplayStyle.None;
            if (awaitingHumanDefense) ShowDefensePrompt();
        }

        /// <summary>Cuantas cartas pide el objetivo, sumando todas sus reglas.</summary>
        int ObjectiveNeed()
        {
            int need = 0;
            foreach (var r in match.objective.rules) need += r.count;
            return need;
        }

        /// <summary>Cuantas cartas del jugador sirven AHORA para el objetivo.</summary>
        int CountProgress(PlayerState p)
        {
            int n = 0;
            foreach (var r in match.objective.rules)
                n += Mathf.Min(CountMatches(p.board, r), r.count);
            return n;
        }

        void SetRail(RailRef rail, PlayerState p, int progress, int need)
        {
            if (rail == null) return;
            if (rail.deckCount != null) rail.deckCount.text = p.deck.Count.ToString();
            if (rail.playedCount != null) rail.playedCount.text = p.board.Count.ToString();
            if (rail.medalValue == null) return;

            // El medallion se enciende cuando ese lado ya completo el objetivo: el
            // color es la senal de un vistazo, el numero es el dato.
            bool done = need > 0 && progress >= need;
            rail.medalValue.text = progress.ToString();
            rail.medalValue.style.color = done ? ColOk : ColGold;
            rail.medalSub.text = $"de {need}";
            rail.medalSub.style.color = done ? ColOk : ColMuted;
        }

        /// <summary>Avance propio y rival en una linea compacta del encabezado.</summary>
        string ProgressLine(PlayerState me, PlayerState them)
        {
            int need = ObjectiveNeed();
            int mine = CountProgress(me);
            int theirs = CountProgress(them);
            return $"{mine}/{need}  ·  {theirs}/{need}";
        }

        string Hint(PlayerState p)
        {
            if (match.winner.HasValue) return "Partida terminada";
            if (match.pendingAttack != null && match.pendingAttack.defenderIndex == 0)
                return "Elegí si usás un protector o sacrificás la carta atacada";
            if (revealAnimating) return "El rival revela sus cartas…";
            if (combatAnimating) return "Las cartas vuelven a sus mazos…";
            if (!p.isHuman) return "Turno del rival…";
            if (lifting) return "Click o [Espacio] para guardar la carta";
            if (selectedHand < 0) return "Elegí una carta de la mano · click derecho mira una carta · [Espacio] termina el turno";
            var c = p.hand[selectedHand];
            return $"{c.name}: otra vez para jugarla, o click en una carta rival para atacar  ·  [Esc] vuelve";
        }

        void DrawBoard(VisualElement row, PlayerState owner, bool isRival)
        {
            row.Clear();

            if (owner.board.Count == 0)
            {
                DrawEmptySlots(row, isRival);
                return;
            }

            for (int i = 0; i < owner.board.Count; i++)
            {
                var c = owner.board[i];
                bool showRivalFace = isRival && rivalFacesRevealed && match.Active.isHuman;
                bool showFace = !isRival || showRivalFace;
                bool serves = showFace && match.objective.IsBoardCardRequired(owner.board, i);

                var col = new VisualElement();
                col.style.alignItems = Align.Center;

                col.style.marginLeft = 8; col.style.marginRight = 8;
                col.style.marginBottom = 6;

                var tile = showFace
                    ? WSCardArt.BuildTile(c, tableCardW)
                    : WSCardArt.BuildBackTile(tableCardW);
                // El marco del arte ya lleva el color de su categoria. Lo que se
                // agrega es solo lo que el arte no sabe: si sirve al objetivo.
                if (serves)
                {
                    tile.style.borderTopWidth = 3; tile.style.borderBottomWidth = 3;
                    tile.style.borderLeftWidth = 3; tile.style.borderRightWidth = 3;
                    tile.style.borderTopColor = new StyleColor(ColOk);
                    tile.style.borderBottomColor = new StyleColor(ColOk);
                    tile.style.borderLeftColor = new StyleColor(ColOk);
                    tile.style.borderRightColor = new StyleColor(ColOk);
                }

                var tag = new Label(serves ? "sirve" : "");
                tag.style.fontSize = 9;
                tag.style.color = ColOk;
                tag.style.marginTop = 2;
                tag.pickingMode = PickingMode.Ignore;
                col.Add(tile);
                if (serves) col.Add(tag);

                if (isRival)
                {
                    int idx = i;
                    bool armed = showRivalFace && selectedHand >= 0 && !match.winner.HasValue
                        && !combatAnimating && !revealAnimating;
                    col.style.opacity = armed ? 1f : 0.62f;
                    if (armed)
                    {
                        col.RegisterCallback<PointerEnterEvent>(_ => WSAudio.Hover());
                        col.RegisterCallback<ClickEvent>(_ => OnRivalBoardClicked(idx));
                    }
                }

                // La mesa rival boca abajo no guarda CardDef en el árbol visual. La
                // identidad solo aparece en la UI al terminar el turno del rival.
                if (!isRival) col.userData = c;
                row.Add(col);
            }
        }

        /// <summary>
        /// Zona vacia: tres reversos ghosts a tamaño de carta de mesa, con su marco
        /// y su hint. No son rectangulos planos: usan el mismo arte de reverso que las
        /// pilas del riel, asi la mesa vacia ya dice "aqui van cartas" y no "falta un
        /// dibujo". Bajados de opacidad para que no griten contra las cartas reales.
        /// </summary>
        void DrawEmptySlots(VisualElement row, bool isRival)
        {
            var wrap = new VisualElement();
            wrap.style.flexGrow = 1;
            wrap.style.alignItems = Align.Center;
            wrap.style.justifyContent = Justify.Center;
            wrap.style.paddingTop = 2;
            wrap.style.paddingBottom = 2;
            wrap.pickingMode = PickingMode.Ignore;

            var slots = new VisualElement();
            slots.style.flexDirection = FlexDirection.Row;
            slots.style.justifyContent = Justify.Center;
            slots.style.alignItems = Align.Center;
            slots.style.paddingTop = 6;
            slots.pickingMode = PickingMode.Ignore;

            // Fantasmas un poco mas chicos que la carta real y algo mas bajos: el
            // hueco se sugiere sin pedir el alto completo, asi entran en mitades
            // bajas (720p) y no compiten con las cartas que haya jugadas.
            int ghostW = Mathf.RoundToInt(tableCardW * 0.78f);
            int ghostH = Mathf.RoundToInt(ghostW * 1.30f);
            for (int k = 0; k < 3; k++)
            {
                var ghost = new VisualElement { name = "empty-slot" };
                ghost.style.width = ghostW;
                ghost.style.height = ghostH;
                ghost.style.marginLeft = 7; ghost.style.marginRight = 7;
                ghost.style.alignItems = Align.Center;
                ghost.style.justifyContent = Justify.Center;
                ghost.style.overflow = Overflow.Hidden;
                ghost.style.backgroundColor = new Color(0.055f, 0.094f, 0.184f, 0.55f);
                ghost.style.borderTopWidth = 1; ghost.style.borderBottomWidth = 1;
                ghost.style.borderLeftWidth = 1; ghost.style.borderRightWidth = 1;
                var ge = new StyleColor(isRival
                    ? new Color(0.44f, 0.60f, 0.92f, 0.30f)
                    : new Color(0.85f, 0.70f, 0.35f, 0.40f));
                ghost.style.borderTopColor = ge; ghost.style.borderBottomColor = ge;
                ghost.style.borderLeftColor = ge; ghost.style.borderRightColor = ge;
                ghost.style.borderTopLeftRadius = 7; ghost.style.borderTopRightRadius = 7;
                ghost.style.borderBottomLeftRadius = 7; ghost.style.borderBottomRightRadius = 7;
                ghost.style.opacity = isRival ? 0.40f : 0.62f;
                ghost.pickingMode = PickingMode.Ignore;

                // El reverso de verdad, encogido al ancho del hueco. Contain y no
                // stretch: estirado, el 8-puntas del arte se deformaria.
                var back = WSCardArt.BuildBackTile(ghostW);
                back.style.position = Position.Absolute;
                back.style.left = 0; back.style.top = 0;
                back.style.width = ghostW;
                back.style.height = ghostH;
                ghost.Add(back);

                var mark = new Label("◇");
                mark.style.fontSize = ghostW * 0.30f;
                mark.style.color = isRival
                    ? new Color(0.62f, 0.76f, 1f, 0.45f)
                    : new Color(1f, 0.86f, 0.42f, 0.60f);
                mark.style.unityTextAlign = TextAnchor.MiddleCenter;
                mark.pickingMode = PickingMode.Ignore;
                ghost.Add(mark);
                slots.Add(ghost);
            }
            wrap.Add(slots);

            var hint = new Label(isRival ? "MESA RIVAL VACÍA" : "ZONA DE JUEGO — JUGÁ UNA CARTA");
            hint.style.fontSize = 10;
            hint.style.color = ColMuted;
            hint.style.letterSpacing = 3;
            hint.style.unityTextAlign = TextAnchor.MiddleCenter;
            hint.style.marginTop = 12;
            hint.pickingMode = PickingMode.Ignore;
            wrap.Add(hint);

            row.Add(wrap);
        }

        /// <summary>
        /// Armonica a mano. Cada carta se ancla al 50% del ancho y se desplaza con
        /// translate/rotate sobre transform-origin en la BASE, que es como se sostiene
        /// una mano de cartas de verdad.
        ///
        /// UI Toolkit NO tiene zIndex: el orden de pintado es el orden de Add, y lo
        /// que se agrega despues tapa lo de antes. Asi que se agregan de los extremos
        /// hacia el centro, y la seleccionada se trae al frente con BringToFront.
        /// </summary>
        void DrawFan()
        {
            hand.Clear();
            var p = match.Active;
            int n = p.hand.Count;
            if (n == 0) return;
            bool showFaces = p.isHuman;

            int h = handCardH;
            float stepX = handCardW * FanStepXRatio;
            float lift = h * SelectLiftRatio;
            var holders = new VisualElement[n];

            for (int i = 0; i < n; i++)
            {
                var c = p.hand[i];
                bool serves = showFaces && MatchController.IsNeededForObjective(match, p, c);
                bool sel = showFaces && selectedHand == i;

                // off va de -(n-1)/2 a +(n-1)/2: la suma de off es CERO, asi que el
                // abanico sale simetrico alrededor de 0 y x = off*stepX mantiene
                // esa simetria. El 0 es el centro de la pantalla porque el holder se
                // ancla al 50 % del ancho de la mano y se desplaza media carta para
                // que el 0 sea el CENTRO de la carta, no su borde izquierdo. Si se
                // tocara cualquiera de las tres cosas de abajo, la mano se corre.
                float off = i - (n - 1) * 0.5f;
                float ang = off * FanStepDeg;
                float x = off * stepX;
                float y = off * off * FanDroop;          // arco: extremos mas abajo

                var holder = new VisualElement();
                holder.style.position = Position.Absolute;
                holder.style.width = handCardW;
                holder.style.height = h;
                holder.style.bottom = 0;
                holder.style.left = new Length(50, LengthUnit.Percent);
                holder.style.marginLeft = -handCardW / 2f;
                holder.style.transformOrigin = new TransformOrigin(
                    new Length(50, LengthUnit.Percent), new Length(100, LengthUnit.Percent));
                holder.style.translate = new Translate(
                    new Length(x, LengthUnit.Pixel),
                    new Length(sel ? y - lift : y, LengthUnit.Pixel));
                holder.style.rotate = new Rotate(ang);
                if (sel) holder.style.scale = new Scale(new Vector3(1.08f, 1.08f, 1f));

                var tile = showFaces
                    ? WSCardArt.BuildTile(c, handCardW)
                    : WSCardArt.BuildBackTile(handCardW);
                if (showFaces)
                    tile.tooltip = serves
                        ? $"{c.name} — sirve al objetivo"
                        : $"{c.name} — protector";
                // El marco es la unica senal de estado posible aca: UI Toolkit no
                // tiene box-shadow. Seleccionada = oro y grueso; sirve = verde.
                if (showFaces)
                {
                    int bw = sel ? 4 : (serves ? 2 : 1);
                    var bc = sel ? ColGold : (serves ? ColOk : WSCardArt.CategoryColor(c.category));
                    tile.style.borderTopWidth = bw; tile.style.borderBottomWidth = bw;
                    tile.style.borderLeftWidth = bw; tile.style.borderRightWidth = bw;
                    tile.style.borderTopColor = new StyleColor(bc);
                    tile.style.borderBottomColor = new StyleColor(bc);
                    tile.style.borderLeftColor = new StyleColor(bc);
                    tile.style.borderRightColor = new StyleColor(bc);
                }
                holder.Add(tile);

                if (showFaces)
                {
                    int idx = i;
                    holder.RegisterCallback<ClickEvent>(_ => OnHandClicked(idx));
                    holder.RegisterCallback<PointerEnterEvent>(_ =>
                    {
                        if (!match.winner.HasValue && !sel) WSAudio.Hover();
                    });
                    holder.userData = c; // solo las cartas propias admiten inspección
                }

                holders[i] = holder;
            }

            // Orden de pintado: extremos primero, centro despues, asi el centro
            // queda arriba. La seleccionada va al frente pase lo que pase.
            var order = Enumerable.Range(0, n)
                .OrderByDescending(i => Mathf.Abs(i - (n - 1) * 0.5f))
                .ToArray();
            foreach (var i in order) hand.Add(holders[i]);
            if (showFaces && selectedHand >= 0 && selectedHand < n)
                holders[selectedHand].BringToFront();
        }

        /// <summary>Un boton por escalon que se puede fusionar ahora mismo.</summary>
        void DrawFusions()
        {
            fuseRow.Clear();
            if (match.winner.HasValue || !match.Active.isHuman || combatAnimating
                || revealAnimating || match.pendingAttack != null) return;

            var p = match.Active;
            var counts = new System.Collections.Generic.Dictionary<BodyCategory, int>();
            foreach (var c in p.hand)
            {
                counts.TryGetValue(c.category, out int n);
                counts[c.category] = n + 1;
            }

            foreach (var kv in counts)
            {
                if (kv.Value < MatchController.FusionCost) continue;
                var next = CardDef.NextTier(kv.Key);
                if (next == kv.Key) continue;
                // El resultado sale de la coleccion del propio jugador, asi que el
                // boton existe si su mazo tiene alguna carta del escalon siguiente.
                if (!p.collection.Any(c => c.category == next)) continue;

                var tier = kv.Key;
                var b = new Button(() => DoFuse(tier));
                b.text = $"3 {WSCardArt.CellName(tier)} ▸ {WSCardArt.CellName(next)}";
                b.tooltip = $"Consume 3 cartas {tier} y agrega 1 {next} a tu mano";
                b.style.fontSize = 11;
                b.style.unityFontStyleAndWeight = FontStyle.Bold;
                b.style.color = ColGold;
                b.style.backgroundColor = new Color(0.24f, 0.20f, 0.10f, 1f);
                b.style.height = 30;
                b.style.marginRight = 6;
                b.style.paddingLeft = 12; b.style.paddingRight = 12;
                b.style.paddingTop = 2; b.style.paddingBottom = 2;
                b.style.borderTopLeftRadius = 8; b.style.borderTopRightRadius = 8;
                b.style.borderBottomLeftRadius = 8; b.style.borderBottomRightRadius = 8;
                b.style.borderTopWidth = 1; b.style.borderBottomWidth = 1;
                b.style.borderLeftWidth = 1; b.style.borderRightWidth = 1;
                var bc = WSCardArt.CategoryColor(tier);
                b.style.borderTopColor = new StyleColor(bc);
                b.style.borderBottomColor = new StyleColor(bc);
                b.style.borderLeftColor = new StyleColor(bc);
                b.style.borderRightColor = new StyleColor(bc);
                fuseRow.Add(b);
            }
        }

        void DoFuse(BodyCategory tier)
        {
            if (match == null || match.winner.HasValue || combatAnimating || revealAnimating
                || match.pendingAttack != null) return;
            if (MatchController.Fuse(match, match.activePlayer, tier))
            {
                WSAudio.Confirm();
                // La mano cambio de largo: la seleccion por indice ya no es valida.
                selectedHand = -1;
            }
            else WSAudio.Denied();
            Refresh();
        }

        static int CountMatches(System.Collections.Generic.IReadOnlyCollection<CardDef> played, ObjectiveRule r)
        {
            int n = 0;
            foreach (var c in played) if (r.Matches(c)) n++;
            return n;
        }

        // ── Ciclo ─────────────────────────────────────────────────────────
        void FitRoot() => WSFit.Update(root, doc, ref fitW, ref fitH);

        void Update()
        {
            if (!visible) return;
            if (Screen.width != fitW || Screen.height != fitH)
            {
                FitRoot();
                // El ancho de carta depende de la resolucion: hay que repintar.
                RecalcLayout();
                Refresh();
            }
            if (Keyboard.current == null) return;
            if (Keyboard.current.escapeKey.wasPressedThisFrame)
            {
                if (galaxyChoiceOpen) { CloseGalaxyChoice(); return; }
                // Escape primero guarda la carta levantada; si no hay ninguna, cancela
                // la seleccion; si no hay nada que hacer, sale.
                if (PutBackFromKey()) return;
                if (selectedHand >= 0) { selectedHand = -1; Refresh(); return; }
                WSAudio.Back();
                OnBackPressed?.Invoke();
            }
            if (Keyboard.current.spaceKey.wasPressedThisFrame)
            {
                // Con la carta en el aire, [Espacio] la guarda (es la tecla que la
                // propia pantalla anuncia) y no termina el turno: hacen falta dos.
                if (PutBackFromKey()) return;
                OnEndTurn();
            }
        }

        // No se desactiva el GameObject: UIDocument.OnEnable recrea el arbol visual.
        public void Show(bool v)
        {
            visible = v;
            gameObject.SetActive(true);
            if (root == null) return;
            if (!v) { EndLift(); CancelPress(); }
            root.style.display = v ? DisplayStyle.Flex : DisplayStyle.None;
            if (!v)
            {
                galaxyChoiceOpen = false;
                if (galaxyOverlay != null) galaxyOverlay.style.display = DisplayStyle.None;
                return;
            }
            fitW = -1; fitH = -1;
            FitRoot();
            Refresh();
        }
    }
}
