using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Modal de vista previa para las animaciones de la tienda.
    /// Ahora con MINI-TABLERO REALISTA 8x8 dentro del stage: las animaciones
    /// se reproducen sobre el tablero como en partida real (no sobre fondo plano):
    /// - Ceniza al Viento (2.0 s): piezas blancas se apagan en gris + brasas + niebla + ráfagas.
    /// - Doble Filo (1.4 s): Rey blanco en jaque doble (Dama + Alfil negros) + anillos + cruz + sello.
    /// - Destello Táctico (1.4 s): jugada brillante (!!) con destello dorado sobre la casilla.
    /// - Cometa Ígnea (1.2 s): fork de caballo con cometa de fuego sobre la casilla.
    /// Todo construido en código: cero cambios en UXML/USS.
    /// </summary>
    public static class ShopAnimationPreview
    {
        private static string _mode = DefeatFx.AnimId;
        private static float LoopDuration => IsCometa ? 1.2f : (IsDoble || IsBrillo ? 1.4f : 2.0f);

        private static VisualElement _overlay;
        private static Label _title;
        private static Label _sub;
        private static Label _hint;
        private static VisualElement _stage;

        // ── Mini-tablero ──
        private const float BOARD_PX = 264f;
        private static float CellPx => BOARD_PX / 8f;
        private static VisualElement _boardWrap;
        private static readonly VisualElement[,] _cells = new VisualElement[8, 8];
        private static readonly Color[,] _cellBase = new Color[8, 8];
        private static readonly Color LightTile = new Color(0.93f, 0.93f, 0.82f, 1f);
        private static readonly Color DarkTile = new Color(0.46f, 0.59f, 0.33f, 1f);
        private static readonly Color CheckRed = new Color(0.95f, 0.22f, 0.18f, 1f);

        private static VisualElement _kingCell;
        private static int _kingRow = 4, _kingCol = 4;
        private static readonly List<Image> _boardPieces = new List<Image>();
        private static VisualElement _boardDim;
        private static VisualElement _lineV;
        private static VisualElement _lineD;
        private static Label _coordLabel;

        // Ceniza
        private static Image _smokeImg;
        private static Image _streakA;
        private static Image _streakB;
        private static Image _cenizaIcon;
        private static float _cenizaIconCx, _cenizaIconCy, _cenizaIconSize;
        private static readonly List<Image> _embers = new List<Image>();
        private static readonly List<Vector4> _seeds = new List<Vector4>(); // x0, y0, speed, phase01
        private static VisualElement _cenizaGroup;

        // Doble Filo
        private static VisualElement _dobleGroup;
        private static Image _ringA;
        private static Image _ringB;
        private static Image _crossA;
        private static Image _crossB;
        private static Image _dobleIcon;
        private static Label _seal;

        // Destello Táctico (!!)
        private static VisualElement _brilloGroup;
        private static Image _flashImg;
        private static Label _brilloSeal;
        private static bool _brilloUsesIcon;

        // Cometa Ígnea (fork)
        private static VisualElement _cometaGroup;
        private static Image _cometImg;
        private static Label _cometaSeal;
        private static bool _cometaUsesIcon;

        private static IVisualElementScheduledItem _ticker;
        private static VisualElement _tickerOwner;
        private static float _t;
        private static bool _needsRelayout = true;
        private static Texture2D _emberTex;

        public static bool IsShowing =>
            _overlay != null && !_overlay.ClassListContains("hidden");

        /// <summary>Abre el modal en el modo indicado y arranca el loop.</summary>
        public static void Show(VisualElement shopRoot, string animId = null)
        {
            if (shopRoot == null) return;
            if (!string.IsNullOrEmpty(animId)) _mode = animId;
            if (_overlay == null)
            {
                Build(shopRoot);
            }
            else if (_overlay.parent != shopRoot)
            {
                // La tienda reconstruyó su árbol: readopta el overlay en vez de
                // duplicarlo (el duplicado dejaba el ticker atado al overlay
                // viejo y el loop solo pintaba el primer frame).
                _overlay.RemoveFromHierarchy();
                shopRoot.Add(_overlay);
            }

            ApplyMode();
            _t = 0f;
            _overlay.RemoveFromClassList("hidden");
            _overlay.BringToFront();
            EnsureTicker();
            // La vista previa del cometa suena una vez al abrir (el loop visual no repite el audio).
            if (IsCometa)
            {
                try { WilderGambit.Audio.MusicManager.Instance?.PlayForkCometSound(); }
                catch { /* preview silencioso si no hay audio */ }
            }
            Tick();
        }

        /// <summary>
        /// Garantiza que el loop corre sobre el overlay visible: si el ticker
        /// es de un overlay anterior (o no existe), se crea uno nuevo atado al
        /// actual en lugar de reanudar el obsoleto.
        /// </summary>
        private static void EnsureTicker()
        {
            if (_overlay == null) return;
            if (_ticker == null || _tickerOwner != _overlay)
            {
                try { _ticker?.Pause(); } catch { /* ticker huérfano */ }
                _ticker = _overlay.schedule.Execute(Tick).Every(16);
                _tickerOwner = _overlay;
            }
            else
            {
                _ticker.Resume();
            }
        }

        /// <summary>Cierra el modal y pausa el loop (no destruye: se reutiliza).</summary>
        public static void Hide()
        {
            if (_overlay == null) return;
            _ticker?.Pause();
            _overlay.AddToClassList("hidden");
        }

        /// <summary>
        /// Ancho del stage en píxeles, seguro para el primer frame.
        /// UI Toolkit devuelve NaN antes del primer layout: en ese caso se usa
        /// el ancho de referencia para no dejar los elementos en left:0.
        /// </summary>
        private static float StageWidth()
        {
            float w = _stage != null ? _stage.resolvedStyle.width : 600f;
            if (float.IsNaN(w) || float.IsInfinity(w) || w <= 10f) w = 600f;
            return w;
        }

        private static bool IsDoble => _mode == DoubleCheckFx.AnimId;
        private static bool IsBrillo => _mode == BrilliantFx.AnimId;
        private static bool IsCometa => _mode == ForkCometFx.AnimId;

        private static void ApplyMode()
        {
            bool doble = IsDoble;
            bool brillo = IsBrillo;
            bool cometa = IsCometa;
            if (_title != null) _title.text = doble ? "VISTA PREVIA  ·  DOBLE FILO"
                : brillo ? "VISTA PREVIA  ·  DESTELLO TÁCTICO"
                : cometa ? "VISTA PREVIA  ·  COMETA ÍGNEA" : "VISTA PREVIA  ·  CENIZA AL VIENTO";
            if (_sub != null) _sub.text = doble ? "DOBLE JAQUE  •  1,4 S  •  LOOP  •  SOBRE TABLERO"
                : brillo ? "JUGADA BRILLANTE  •  1,4 S  •  LOOP  •  SOBRE TABLERO"
                : cometa ? "FORK  •  1,2 S  •  LOOP  •  SOBRE TABLERO" : "GATILLO DERROTA  •  2,0 S  •  LOOP  •  SOBRE TABLERO";
            if (_hint != null) _hint.text = doble
                ? "Vista real: Rey blanco en e5, Dama y Alfil negros dando doble jaque. Así se ve en partida."
                : brillo
                ? "Vista real: el motor clasifica tu jugada como Brillante y el destello estalla en la casilla. Así se ve en partida."
                : cometa
                ? "Vista real: tu caballo clava horquilla en e5 (Dama + Torre) y el cometa estalla en la casilla. Así se ve en partida."
                : "Vista real: tus piezas se apagan en gris y el viento se las lleva. Así se ve en partida.";
            if (_cenizaGroup != null) _cenizaGroup.style.display = (!doble && !brillo && !cometa) ? DisplayStyle.Flex : DisplayStyle.None;
            if (_dobleGroup != null) _dobleGroup.style.display = doble ? DisplayStyle.Flex : DisplayStyle.None;
            if (_brilloGroup != null) _brilloGroup.style.display = brillo ? DisplayStyle.Flex : DisplayStyle.None;
            if (_cometaGroup != null) _cometaGroup.style.display = cometa ? DisplayStyle.Flex : DisplayStyle.None;

            if (doble) SetupDobleBoard();
            else if (brillo) SetupBrilloBoard();
            else if (cometa) SetupCometaBoard();
            else SetupCenizaBoard();

            PositionCenizaFx();
            PositionDobleFx();
            PositionBrilloFx();
            PositionCometaFx();
        }

        // ── Construcción ──────────────────────────────────────────────────

        private static void Build(VisualElement shopRoot)
        {
            _embers.Clear();
            _seeds.Clear();
            for (int r = 0; r < 8; r++)
                for (int c = 0; c < 8; c++)
                    _cells[r, c] = null;
            _boardPieces.Clear();

            _overlay = new VisualElement { name = "anim-preview-overlay", pickingMode = PickingMode.Position };
            _overlay.style.position = Position.Absolute;
            _overlay.style.left = 0; _overlay.style.top = 0;
            _overlay.style.right = 0; _overlay.style.bottom = 0;
            _overlay.style.backgroundColor = new Color(0.016f, 0.024f, 0.047f, 0.90f);
            _overlay.style.alignItems = Align.Center;
            _overlay.style.justifyContent = Justify.Center;
            _overlay.AddToClassList("hidden");
            _overlay.RegisterCallback<ClickEvent>(evt =>
            {
                if (evt.target == _overlay) Hide();
            });

            var card = new VisualElement { name = "anim-preview-card", pickingMode = PickingMode.Position };
            card.style.width = new Length(90f, LengthUnit.Percent);
            card.style.maxWidth = 700f;
            card.style.backgroundColor = new Color(0.063f, 0.078f, 0.122f, 1f);
            card.style.borderTopWidth = 1.5f; card.style.borderBottomWidth = 1.5f;
            card.style.borderLeftWidth = 1.5f; card.style.borderRightWidth = 1.5f;
            card.style.borderTopColor = new Color(0.79f, 0.66f, 0.29f, 0.55f);
            card.style.borderBottomColor = new Color(0.79f, 0.66f, 0.29f, 0.55f);
            card.style.borderLeftColor = new Color(0.79f, 0.66f, 0.29f, 0.55f);
            card.style.borderRightColor = new Color(0.79f, 0.66f, 0.29f, 0.55f);
            card.style.borderTopLeftRadius = 12f; card.style.borderTopRightRadius = 12f;
            card.style.borderBottomLeftRadius = 12f; card.style.borderBottomRightRadius = 12f;
            card.style.paddingTop = 16f; card.style.paddingBottom = 16f;
            card.style.paddingLeft = 18f; card.style.paddingRight = 18f;
            _overlay.Add(card);

            _title = new Label("VISTA PREVIA");
            _title.style.fontSize = 15f;
            _title.style.color = new Color(0.94f, 0.82f, 0.48f, 1f);
            _title.style.marginBottom = 2f;
            card.Add(_title);

            _sub = new Label("");
            _sub.style.fontSize = 10f;
            _sub.style.color = new Color(0.54f, 0.61f, 0.71f, 1f);
            _sub.style.marginBottom = 12f;
            card.Add(_sub);

            // ── Stage con tablero centrado ──
            _stage = new VisualElement { name = "anim-preview-stage", pickingMode = PickingMode.Ignore };
            _stage.style.height = 320f;
            _stage.style.backgroundColor = new Color(0.030f, 0.055f, 0.115f, 1f);
            _stage.style.borderTopLeftRadius = 8f; _stage.style.borderTopRightRadius = 8f;
            _stage.style.borderBottomLeftRadius = 8f; _stage.style.borderBottomRightRadius = 8f;
            _stage.style.overflow = Overflow.Hidden;
            _stage.style.alignItems = Align.Center;
            _stage.style.justifyContent = Justify.Center;
            _stage.style.flexDirection = FlexDirection.Row;
            // El ancho real llega después del primer layout: marcamos reposición
            // para que los FX no se queden anclados con el ancho de respaldo.
            _stage.RegisterCallback<GeometryChangedEvent>(_ => _needsRelayout = true);
            card.Add(_stage);

            BuildBoard(_stage);
            BuildCenizaGroup(_stage);
            BuildDobleGroup(_stage);
            BuildBrilloGroup(_stage);
            BuildCometaGroup(_stage);

            _coordLabel = new Label("BLANCAS ABAJO  •  VISTA DE PARTIDA");
            _coordLabel.style.fontSize = 9f;
            _coordLabel.style.color = new Color(0.54f, 0.61f, 0.71f, 0.9f);
            _coordLabel.style.marginTop = 6f;
            _coordLabel.style.unityTextAlign = TextAnchor.MiddleCenter;
            card.Add(_coordLabel);

            _hint = new Label("");
            _hint.style.fontSize = 11f;
            _hint.style.color = new Color(0.54f, 0.61f, 0.71f, 1f);
            _hint.style.marginTop = 6f;
            _hint.style.whiteSpace = WhiteSpace.Normal;
            card.Add(_hint);

            var close = new Button(Hide) { text = "CERRAR" };
            // Los estilos (incluido :hover y :active) van en el USS, no por C#:
            // el estilo en linea gana contra el USS y el boton se veria plano.
            close.AddToClassList("btn-inline-gold");
            close.AddToClassList("btn-inline-gold-danger");
            close.style.marginTop = 10f;
            card.Add(close);

            shopRoot.Add(_overlay);
        }

        // ── Mini-tablero 8x8 ─────────────────────────────────────────────

        private static void BuildBoard(VisualElement stage)
        {
            _boardWrap = new VisualElement { name = "anim-preview-board", pickingMode = PickingMode.Ignore };
            _boardWrap.style.width = BOARD_PX;
            _boardWrap.style.height = BOARD_PX;
            _boardWrap.style.flexShrink = 0;
            _boardWrap.style.flexDirection = FlexDirection.Column;
            _boardWrap.style.backgroundColor = new Color(0.02f, 0.03f, 0.06f, 1f);
            _boardWrap.style.borderTopWidth = 2f; _boardWrap.style.borderBottomWidth = 2f;
            _boardWrap.style.borderLeftWidth = 2f; _boardWrap.style.borderRightWidth = 2f;
            _boardWrap.style.borderTopColor = new Color(0.79f, 0.66f, 0.29f, 0.7f);
            _boardWrap.style.borderBottomColor = new Color(0.79f, 0.66f, 0.29f, 0.7f);
            _boardWrap.style.borderLeftColor = new Color(0.79f, 0.66f, 0.29f, 0.7f);
            _boardWrap.style.borderRightColor = new Color(0.79f, 0.66f, 0.29f, 0.7f);
            _boardWrap.style.borderTopLeftRadius = 6f; _boardWrap.style.borderTopRightRadius = 6f;
            _boardWrap.style.borderBottomLeftRadius = 6f; _boardWrap.style.borderBottomRightRadius = 6f;
            _boardWrap.style.overflow = Overflow.Hidden;
            _boardWrap.style.position = Position.Relative;
            stage.Add(_boardWrap);

            for (int r = 0; r < 8; r++)
            {
                var row = new VisualElement { pickingMode = PickingMode.Ignore };
                row.style.flexDirection = FlexDirection.Row;
                row.style.width = new Length(100f, LengthUnit.Percent);
                row.style.height = new Length(12.5f, LengthUnit.Percent);
                row.style.flexShrink = 0;
                _boardWrap.Add(row);
                for (int c = 0; c < 8; c++)
                {
                    bool light = (r + c) % 2 == 0;
                    Color baseCol = light ? LightTile : DarkTile;
                    // Oscurecer un poco para encajar con el Atelier nocturno
                    baseCol = new Color(baseCol.r * 0.92f, baseCol.g * 0.92f, baseCol.b * 0.92f, 1f);
                    var cell = new VisualElement { pickingMode = PickingMode.Ignore };
                    cell.style.width = new Length(12.5f, LengthUnit.Percent);
                    cell.style.height = new Length(100f, LengthUnit.Percent);
                    cell.style.backgroundColor = baseCol;
                    cell.style.alignItems = Align.Center;
                    cell.style.justifyContent = Justify.Center;
                    cell.style.overflow = Overflow.Hidden;
                    row.Add(cell);
                    _cells[r, c] = cell;
                    _cellBase[r, c] = baseCol;
                }
            }

            // Oscurecedor para Ceniza (encima de casillas, debajo de piezas/FX)
            _boardDim = new VisualElement { pickingMode = PickingMode.Ignore };
            _boardDim.style.position = Position.Absolute;
            _boardDim.style.left = 0; _boardDim.style.top = 0;
            _boardDim.style.right = 0; _boardDim.style.bottom = 0;
            _boardDim.style.backgroundColor = new Color(0f, 0f, 0f, 0f);
            _boardWrap.Add(_boardDim);

            // Líneas de jaque (Doble Filo): vertical Dama→Rey y diagonal Alfil→Rey
            _lineV = new VisualElement { pickingMode = PickingMode.Ignore };
            _lineV.style.position = Position.Absolute;
            _lineV.style.backgroundColor = new Color(1f, 0.25f, 0.2f, 0.85f);
            _lineV.style.width = 3f;
            _lineV.style.opacity = 0f;
            _boardWrap.Add(_lineV);

            _lineD = new VisualElement { pickingMode = PickingMode.Ignore };
            _lineD.style.position = Position.Absolute;
            _lineD.style.backgroundColor = new Color(1f, 0.25f, 0.2f, 0.85f);
            _lineD.style.height = 3f;
            _lineD.style.opacity = 0f;
            _boardWrap.Add(_lineD);
        }

        private static void ClearBoardPieces()
        {
            foreach (var img in _boardPieces)
            {
                if (img != null && img.parent != null)
                    img.parent.Remove(img);
            }
            _boardPieces.Clear();
            // Quitar etiquetas de fallback (Label) marcadas como pieza
            var toRemove = new List<VisualElement>();
            for (int r = 0; r < 8; r++)
                for (int c = 0; c < 8; c++)
                {
                    var cell = _cells[r, c];
                    if (cell == null) continue;
                    foreach (var child in cell.Children())
                    {
                        if (child.name == "preview-piece")
                            toRemove.Add(child);
                    }
                    // Restaurar color base
                    cell.style.backgroundColor = _cellBase[r, c];
                }
            foreach (var el in toRemove)
                el.parent?.Remove(el);
            _kingCell = null;
        }

        private static void PlacePiece(int row, int col, string resourcePath, string fallbackGlyph)
        {
            if (row < 0 || row > 7 || col < 0 || col > 7) return;
            var cell = _cells[row, col];
            if (cell == null) return;
            Sprite spr = LoadPieceSprite(resourcePath);
            if (spr != null)
            {
                var img = new Image { name = "preview-piece", pickingMode = PickingMode.Ignore };
                img.sprite = spr;
                img.scaleMode = ScaleMode.ScaleToFit;
                img.style.width = new Length(88f, LengthUnit.Percent);
                img.style.height = new Length(88f, LengthUnit.Percent);
                cell.Add(img);
                _boardPieces.Add(img);
            }
            else
            {
                var lab = new Label(fallbackGlyph) { name = "preview-piece", pickingMode = PickingMode.Ignore };
                lab.style.fontSize = 22f;
                lab.style.color = resourcePath.Contains("White") ? Color.white : new Color(0.1f, 0.1f, 0.12f, 1f);
                lab.style.unityTextAlign = TextAnchor.MiddleCenter;
                cell.Add(lab);
            }
        }

        /// <summary>Posición realista de doble jaque: Rey blanco + Dama y Alfil negros.</summary>
        private static void SetupDobleBoard()
        {
            ClearBoardPieces();
            _kingRow = 3; _kingCol = 4; // e5 aprox, centro visible
            // Rey blanco víctima
            PlacePiece(_kingRow, _kingCol, "Pieces/White/King", "♔");
            _kingCell = _cells[_kingRow, _kingCol];
            // Atacantes negros: Dama misma columna, Alfil en diagonal
            PlacePiece(0, 4, "Pieces/Black/Queen", "♛");   // Dama arriba
            PlacePiece(5, 2, "Pieces/Black/Bishop", "♝");  // Alfil abajo-izq
            // Contexto: peones blancos y rey negro lejos
            // NOTA: (4,3) debe quedar libre: es la casilla intermedia de la diagonal
            // Alfil (5,2) -> Rey (3,4). El peón escudo va a la izquierda del Rey.
            PlacePiece(3, 3, "Pieces/White/Pawn", "♙");
            PlacePiece(4, 5, "Pieces/White/Pawn", "♙");
            PlacePiece(5, 4, "Pieces/White/Knight", "♘");
            PlacePiece(7, 7, "Pieces/Black/King", "♚");
            PlacePiece(1, 2, "Pieces/Black/Pawn", "♟");

            // Líneas de ataque: recalcular geometría
            LayoutAttackLines(0, 4, 5, 2, _kingRow, _kingCol);
            if (_boardDim != null) _boardDim.style.backgroundColor = new Color(0f, 0f, 0f, 0f);
            if (_coordLabel != null) _coordLabel.text = "DOBLE JAQUE  •  DAMA + ALFIL SOBRE EL REY";
        }

        /// <summary>Jugada brillante: Dama blanca que acaba de mover a e5 (casilla dorada).</summary>
        private static void SetupBrilloBoard()
        {
            ClearBoardPieces();
            _kingRow = 3; _kingCol = 4; // e5: destino de la jugada brillante
            // La Dama blanca acaba de llegar a e5 (la protagonista del destello)
            PlacePiece(_kingRow, _kingCol, "Pieces/White/Queen", "♕");
            _kingCell = _cells[_kingRow, _kingCol];
            // Contexto: Rey negro arriba, piezas menores alrededor
            PlacePiece(0, 4, "Pieces/Black/King", "♚");
            PlacePiece(1, 5, "Pieces/Black/Pawn", "♟");
            PlacePiece(5, 2, "Pieces/White/Knight", "♘");
            PlacePiece(6, 3, "Pieces/White/Pawn", "♙");
            PlacePiece(6, 5, "Pieces/White/Pawn", "♙");
            PlacePiece(7, 4, "Pieces/White/King", "♔");
            PlacePiece(2, 6, "Pieces/Black/Rook", "♜");
            if (_lineV != null) _lineV.style.opacity = 0f;
            if (_lineD != null) _lineD.style.opacity = 0f;
            if (_boardDim != null) _boardDim.style.backgroundColor = new Color(0f, 0f, 0f, 0f);
            if (_coordLabel != null) _coordLabel.text = "JUGADA BRILLANTE  •  DAMA A e5";
        }

        /// <summary>Fork de caballo: blanco en e5 atacando Dama y Torre negras.</summary>
        private static void SetupCometaBoard()
        {
            ClearBoardPieces();
            _kingRow = 3; _kingCol = 4; // e5: casilla del fork
            // El Caballo blanco acaba de clavar la horquilla en e5
            PlacePiece(_kingRow, _kingCol, "Pieces/White/Knight", "♘");
            _kingCell = _cells[_kingRow, _kingCol];
            // Víctimas del fork: Dama (1,3) y Torre (1,5), ambas a salto de caballo
            PlacePiece(1, 3, "Pieces/Black/Queen", "♛");
            PlacePiece(1, 5, "Pieces/Black/Rook", "♜");
            // Contexto
            PlacePiece(0, 4, "Pieces/Black/King", "♚");
            PlacePiece(7, 4, "Pieces/White/King", "♔");
            PlacePiece(5, 2, "Pieces/White/Pawn", "♙");
            PlacePiece(5, 6, "Pieces/White/Pawn", "♙");
            PlacePiece(6, 1, "Pieces/Black/Pawn", "♟");
            if (_lineV != null) _lineV.style.opacity = 0f;
            if (_lineD != null) _lineD.style.opacity = 0f;
            if (_boardDim != null) _boardDim.style.backgroundColor = new Color(0f, 0f, 0f, 0f);
            if (_coordLabel != null) _coordLabel.text = "FORK  •  CABALLO A e5 CONTRA DAMA + TORRE";
        }

        /// <summary>Posición de mate: varias piezas blancas que se apagarán en gris.</summary>
        private static void SetupCenizaBoard()
        {
            ClearBoardPieces();
            _kingRow = 7; _kingCol = 4;
            PlacePiece(7, 4, "Pieces/White/King", "♔");
            _kingCell = _cells[_kingRow, _kingCol];
            PlacePiece(7, 3, "Pieces/White/Queen", "♕");
            PlacePiece(7, 0, "Pieces/White/Rook", "♖");
            PlacePiece(7, 7, "Pieces/White/Rook", "♖");
            PlacePiece(6, 3, "Pieces/White/Pawn", "♙");
            PlacePiece(6, 4, "Pieces/White/Pawn", "♙");
            PlacePiece(6, 5, "Pieces/White/Pawn", "♙");
            PlacePiece(5, 5, "Pieces/White/Knight", "♘");
            PlacePiece(0, 4, "Pieces/Black/Queen", "♛");
            PlacePiece(2, 6, "Pieces/Black/Rook", "♜");
            if (_lineV != null) _lineV.style.opacity = 0f;
            if (_lineD != null) _lineD.style.opacity = 0f;
            if (_boardDim != null) _boardDim.style.backgroundColor = new Color(0f, 0f, 0f, 0f);
            if (_coordLabel != null) _coordLabel.text = "MATE EN CONTRA  •  TUS PIEZAS SE APAGAN";
        }

        private static void LayoutAttackLines(int qR, int qC, int bR, int bC, int kR, int kC)
        {
            if (_lineV == null || _lineD == null) return;
            float cp = CellPx;
            // Vertical Dama → Rey (misma columna)
            float xVCenter = (qC + 0.5f) * cp;
            float yQ = (qR + 0.5f) * cp;
            float yK = (kR + 0.5f) * cp;
            float top = Mathf.Min(yQ, yK) + cp * 0.35f;
            float h = Mathf.Abs(yK - yQ) - cp * 0.7f;
            _lineV.style.left = xVCenter - 1.5f;
            _lineV.style.top = top;
            _lineV.style.height = Mathf.Max(8f, h);
            _lineV.style.opacity = 0.9f;

            // Diagonal Alfil → Rey
            float xB = (bC + 0.5f) * cp;
            float yB = (bR + 0.5f) * cp;
            float xK = (kC + 0.5f) * cp;
            float yK2 = (kR + 0.5f) * cp;
            float dx = xK - xB, dy = yK2 - yB;
            float len = Mathf.Sqrt(dx * dx + dy * dy) - cp * 0.7f;
            float midX = (xB + xK) * 0.5f;
            float midY = (yB + yK2) * 0.5f;
            float ang = Mathf.Atan2(dy, dx) * Mathf.Rad2Deg;
            _lineD.style.width = Mathf.Max(8f, len);
            _lineD.style.left = midX - Mathf.Max(8f, len) * 0.5f;
            _lineD.style.top = midY - 1.5f;
            _lineD.style.rotate = new Rotate(ang);
            _lineD.style.opacity = 0.9f;
        }

        // ── FX sobre el tablero ────────────────────────────────────────

        private static void BuildCenizaGroup(VisualElement stage)
        {
            _cenizaGroup = new VisualElement { pickingMode = PickingMode.Ignore };
            _cenizaGroup.style.position = Position.Absolute;
            _cenizaGroup.style.left = 0; _cenizaGroup.style.top = 0;
            _cenizaGroup.style.right = 0; _cenizaGroup.style.bottom = 0;
            stage.Add(_cenizaGroup);

            _smokeImg = new Image { pickingMode = PickingMode.Ignore };
            _smokeImg.sprite = LoadFxSprite("FX/smoke_grey_256");
            _smokeImg.scaleMode = ScaleMode.ScaleAndCrop;
            _smokeImg.style.position = Position.Absolute;
            _smokeImg.style.left = 0; _smokeImg.style.top = 0;
            _smokeImg.style.right = 0; _smokeImg.style.bottom = 0;
            _smokeImg.style.opacity = 0f;
            _cenizaGroup.Add(_smokeImg);

            // Emblema ilustrado del tornado: el arte oficial de la animación.
            _cenizaIcon = new Image { pickingMode = PickingMode.Ignore };
            _cenizaIcon.sprite = AnimIconSprites.Ceniza;
            _cenizaIcon.scaleMode = ScaleMode.ScaleToFit;
            _cenizaIcon.style.position = Position.Absolute;
            _cenizaIcon.style.opacity = 0f;
            if (_cenizaIcon.sprite == null) _cenizaIcon.style.display = DisplayStyle.None;
            _cenizaGroup.Add(_cenizaIcon);

            if (_emberTex == null) _emberTex = MakeEmberTexture();
            Color[] palette =
            {
                new Color(1f, 0.85f, 0.54f, 1f),
                new Color(1f, 0.66f, 0.30f, 1f),
                new Color(0.89f, 0.44f, 0.11f, 1f),
            };
            for (int i = 0; i < 14; i++)
            {
                var e = new Image { pickingMode = PickingMode.Ignore };
                e.image = _emberTex;
                e.scaleMode = ScaleMode.ScaleToFit;
                e.tintColor = palette[i % palette.Length];
                float size = Random.Range(9f, 20f);
                e.style.position = Position.Absolute;
                e.style.width = size; e.style.height = size;
                e.style.opacity = 0f;
                _cenizaGroup.Add(e);
                _embers.Add(e);
                _seeds.Add(new Vector4(
                    Random.Range(5f, 100f),
                    Random.Range(15f, 90f),
                    Random.Range(0.6f, 1.6f),
                    Random.Range(0f, 1f)));
            }

            Sprite streak = LoadFxSprite("FX/wind_streak_256");
            _streakA = MakeStreak(_cenizaGroup, streak, 28f);
            _streakB = MakeStreak(_cenizaGroup, streak, 62f);
        }

        /// <summary>Centra el emblema de ceniza en el tablero del preview.</summary>
        private static void PositionCenizaFx()
        {
            if (_stage == null || _cenizaIcon == null) return;
            float stageW = StageWidth();
            float boardLeft = (stageW - BOARD_PX) * 0.5f;
            float boardTop = (320f - BOARD_PX) * 0.5f;
            _cenizaIconCx = boardLeft + BOARD_PX * 0.5f;
            _cenizaIconCy = boardTop + BOARD_PX * 0.5f;
            _cenizaIconSize = CellPx * 3.6f;
            _cenizaIcon.style.width = _cenizaIconSize;
            _cenizaIcon.style.height = _cenizaIconSize;
            _cenizaIcon.style.left = _cenizaIconCx - _cenizaIconSize * 0.5f;
            _cenizaIcon.style.top = _cenizaIconCy - _cenizaIconSize * 0.5f;
        }

        private static void BuildDobleGroup(VisualElement stage)
        {
            _dobleGroup = new VisualElement { pickingMode = PickingMode.Ignore };
            _dobleGroup.style.position = Position.Absolute;
            _dobleGroup.style.left = 0; _dobleGroup.style.top = 0;
            _dobleGroup.style.right = 0; _dobleGroup.style.bottom = 0;
            _dobleGroup.style.display = DisplayStyle.None;
            stage.Add(_dobleGroup);

            // Emblema ilustrado: sables cruzados sobre el Rey.
            _dobleIcon = new Image { pickingMode = PickingMode.Ignore };
            _dobleIcon.sprite = AnimIconSprites.DobleFilo;
            _dobleIcon.scaleMode = ScaleMode.ScaleToFit;
            _dobleIcon.style.position = Position.Absolute;
            _dobleIcon.style.opacity = 0f;
            if (_dobleIcon.sprite == null) _dobleIcon.style.display = DisplayStyle.None;
            _dobleGroup.Add(_dobleIcon);

            Sprite ring = LoadFxSprite("FX/ring_red_256") ?? DoubleCheckFx.GetArtSprite();

            // Los anillos viven en el stage pero se reposicionan sobre el Rey en PositionDobleFx()
            _ringA = MakeRing(_dobleGroup, ring);
            _ringB = MakeRing(_dobleGroup, ring);

            _crossA = MakeCross(_dobleGroup, 45f);
            _crossB = MakeCross(_dobleGroup, -45f);

            _seal = new Label("¡DOBLE JAQUE!") { pickingMode = PickingMode.Ignore };
            _seal.style.position = Position.Absolute;
            _seal.style.left = 0; _seal.style.right = 0;
            _seal.style.bottom = 8f;
            _seal.style.fontSize = 22f;
            _seal.style.color = new Color(1f, 0.55f, 0.30f, 1f);
            _seal.style.unityTextAlign = TextAnchor.MiddleCenter;
            _seal.style.opacity = 0f;
            // Sombra para legibilidad sobre el tablero
            _seal.style.textShadow = new TextShadow
            {
                color = new Color(0f, 0f, 0f, 0.85f),
                offset = new Vector2(0f, 1f)
            };
            _dobleGroup.Add(_seal);
        }

        /// <summary>Centra anillos y cruz sobre la casilla del Rey del mini-tablero.</summary>
        private static void PositionDobleFx()
        {
            if (_boardWrap == null || _stage == null) return;
            if (_ringA == null || _ringB == null) return;
            // El board está centrado en el stage: calculamos su offset una vez resuelto el layout.
            // Como UIToolkit resuelve en el próximo frame, usamos geometría conocida:
            // stage ~ (ancho card) x 320, board 264 centrado → offsetX = (stageWidth-264)/2.
            // Para no depender del ancho, anclamos por porcentaje del stage:
            // el Rey está en (3,4) del tablero → su centro en el stage es:
            // boardCenter + (col-3.5, row-3.5)*cell. Aproximamos con layout actual si existe.
            float stageW = StageWidth();
            float boardLeft = (stageW - BOARD_PX) * 0.5f;
            float kingCX = boardLeft + (_kingCol + 0.5f) * CellPx;
            float stageH = 320f;
            float boardTop = (stageH - BOARD_PX) * 0.5f;
            float kingCY = boardTop + (_kingRow + 0.5f) * CellPx;

            if (_dobleIcon != null && _dobleIcon.sprite != null)
            {
                float iconSize = CellPx * 1.55f;
                PlaceFxAt(_dobleIcon, kingCX - iconSize * 0.5f, kingCY - iconSize * 0.5f, iconSize);
            }

            float ringSize = CellPx * 2.1f;
            float off = CellPx * 0.32f;
            PlaceFxAt(_ringA, kingCX - ringSize * 0.5f - off, kingCY - ringSize * 0.5f, ringSize);
            PlaceFxAt(_ringB, kingCX - ringSize * 0.5f + off, kingCY - ringSize * 0.5f, ringSize);

            float crossW = CellPx * 2.4f;
            PositionCross(_crossA, kingCX, kingCY, crossW);
            PositionCross(_crossB, kingCX, kingCY, crossW);
        }

        private static void PlaceFxAt(Image img, float leftPx, float topPx, float sizePx)
        {
            img.style.left = leftPx;
            img.style.top = topPx;
            img.style.width = sizePx;
            img.style.height = sizePx;
        }

        private static void PositionCross(Image img, float cx, float cy, float w)
        {
            if (img == null) return;
            img.style.left = cx - w * 0.5f;
            img.style.top = cy - 5f;
            img.style.width = w;
            img.style.height = 10f;
        }

        private static Image MakeRing(VisualElement parent, Sprite ring)
        {
            var img = new Image { pickingMode = PickingMode.Ignore };
            img.sprite = ring;
            img.scaleMode = ScaleMode.ScaleToFit;
            img.style.position = Position.Absolute;
            img.style.width = 70f; img.style.height = 70f;
            img.style.opacity = 0f;
            parent.Add(img);
            return img;
        }

        private static Image MakeCross(VisualElement parent, float angle)
        {
            var img = new Image { pickingMode = PickingMode.Ignore };
            img.scaleMode = ScaleMode.ScaleToFit;
            img.style.position = Position.Absolute;
            img.style.width = 80f;
            img.style.height = 10f;
            img.style.backgroundColor = new Color(1f, 0.93f, 0.80f, 1f);
            img.style.rotate = new Rotate(angle);
            img.style.opacity = 0f;
            parent.Add(img);
            return img;
        }

        private static Image MakeStreak(VisualElement parent, Sprite streak, float topPct)
        {
            var img = new Image { pickingMode = PickingMode.Ignore };
            img.sprite = streak;
            img.scaleMode = ScaleMode.ScaleToFit;
            img.style.position = Position.Absolute;
            img.style.top = new Length(topPct, LengthUnit.Percent);
            img.style.left = new Length(110f, LengthUnit.Percent);
            img.style.width = new Length(120f, LengthUnit.Percent);
            img.style.height = 30f;
            img.style.opacity = 0f;
            if (streak == null) img.style.display = DisplayStyle.None;
            parent.Add(img);
            return img;
        }

        // ── FX Destello Táctico (!!) ────────────────────────────────────

        private static void BuildBrilloGroup(VisualElement stage)
        {
            _brilloGroup = new VisualElement { pickingMode = PickingMode.Ignore };
            _brilloGroup.style.position = Position.Absolute;
            _brilloGroup.style.left = 0; _brilloGroup.style.top = 0;
            _brilloGroup.style.right = 0; _brilloGroup.style.bottom = 0;
            _brilloGroup.style.display = DisplayStyle.None;
            stage.Add(_brilloGroup);

            _flashImg = new Image { pickingMode = PickingMode.Ignore };
            _flashImg.scaleMode = ScaleMode.ScaleToFit;
            _flashImg.style.position = Position.Absolute;
            _flashImg.style.opacity = 1f;
            Sprite icon = AnimIconSprites.Destello;
            _brilloUsesIcon = icon != null;
            if (icon != null) _flashImg.sprite = icon;
            _brilloGroup.Add(_flashImg);

            _brilloSeal = new Label("!!") { pickingMode = PickingMode.Ignore };
            _brilloSeal.style.position = Position.Absolute;
            _brilloSeal.style.left = 0; _brilloSeal.style.right = 0;
            _brilloSeal.style.bottom = 8f;
            _brilloSeal.style.fontSize = 26f;
            _brilloSeal.style.color = new Color(1f, 0.85f, 0.40f, 1f);
            _brilloSeal.style.unityTextAlign = TextAnchor.MiddleCenter;
            _brilloSeal.style.opacity = 0f;
            _brilloSeal.style.textShadow = new TextShadow
            {
                color = new Color(0f, 0f, 0f, 0.85f),
                offset = new Vector2(0f, 1f)
            };
            _brilloGroup.Add(_brilloSeal);
        }

        /// <summary>Centra el destello sobre la casilla destino del mini-tablero.</summary>
        private static void PositionBrilloFx()
        {
            if (_boardWrap == null || _stage == null) return;
            if (_flashImg == null) return;
            float stageW = StageWidth();
            float boardLeft = (stageW - BOARD_PX) * 0.5f;
            float cx = boardLeft + (_kingCol + 0.5f) * CellPx;
            float boardTop = (320f - BOARD_PX) * 0.5f;
            float cy = boardTop + (_kingRow + 0.5f) * CellPx;

            float w, h;
            if (_brilloUsesIcon)
            {
                // Icono cuadrado: 2 casillas de ancho.
                w = CellPx * 2.0f;
                h = w;
            }
            else
            {
                // Clip viejo apaisado 341×192: ancho 3.4 casillas, alto proporcional.
                w = CellPx * 3.4f;
                h = w * 192f / 341f;
            }
            _flashImg.style.left = cx - w * 0.5f;
            _flashImg.style.top = cy - h * 0.5f;
            _flashImg.style.width = w;
            _flashImg.style.height = h;
        }

        // ── FX Cometa Ígnea (fork) ─────────────────────────────────────

        private static void BuildCometaGroup(VisualElement stage)
        {
            _cometaGroup = new VisualElement { pickingMode = PickingMode.Ignore };
            _cometaGroup.style.position = Position.Absolute;
            _cometaGroup.style.left = 0; _cometaGroup.style.top = 0;
            _cometaGroup.style.right = 0; _cometaGroup.style.bottom = 0;
            _cometaGroup.style.display = DisplayStyle.None;
            stage.Add(_cometaGroup);

            _cometImg = new Image { pickingMode = PickingMode.Ignore };
            _cometImg.scaleMode = ScaleMode.ScaleToFit;
            _cometImg.style.position = Position.Absolute;
            _cometImg.style.opacity = 1f;
            Sprite icon = AnimIconSprites.Cometa;
            _cometaUsesIcon = icon != null;
            if (icon != null) _cometImg.sprite = icon;
            _cometaGroup.Add(_cometImg);

            _cometaSeal = new Label("¡HORQUILLA!") { pickingMode = PickingMode.Ignore };
            _cometaSeal.style.position = Position.Absolute;
            _cometaSeal.style.left = 0; _cometaSeal.style.right = 0;
            _cometaSeal.style.bottom = 8f;
            _cometaSeal.style.fontSize = 20f;
            _cometaSeal.style.color = new Color(1f, 0.62f, 0.25f, 1f);
            _cometaSeal.style.unityTextAlign = TextAnchor.MiddleCenter;
            _cometaSeal.style.opacity = 0f;
            _cometaSeal.style.textShadow = new TextShadow
            {
                color = new Color(0f, 0f, 0f, 0.85f),
                offset = new Vector2(0f, 1f)
            };
            _cometaGroup.Add(_cometaSeal);
        }

        /// <summary>Centra el cometa sobre la casilla del fork del mini-tablero.</summary>
        private static void PositionCometaFx()
        {
            if (_boardWrap == null || _stage == null) return;
            if (_cometImg == null) return;
            float stageW = StageWidth();
            float boardLeft = (stageW - BOARD_PX) * 0.5f;
            float cx = boardLeft + (_kingCol + 0.5f) * CellPx;
            float boardTop = (320f - BOARD_PX) * 0.5f;
            float cy = boardTop + (_kingRow + 0.5f) * CellPx;

            float w, h;
            if (_cometaUsesIcon)
            {
                // Icono cuadrado: 2 casillas de ancho.
                w = CellPx * 2.0f;
                h = w;
            }
            else
            {
                // Clip viejo apaisado 1280×720 con mucho aire: 4,6 casillas.
                w = CellPx * 4.6f;
                h = w * 720f / 1280f;
            }
            _cometImg.style.left = cx - w * 0.5f;
            _cometImg.style.top = cy - h * 0.5f;
            _cometImg.style.width = w;
            _cometImg.style.height = h;
        }

        // ── Loop ──────────────────────────────────────────────────────────

        private static void Tick()
        {
            if (_overlay == null || _overlay.ClassListContains("hidden")) return;
            if (_overlay.panel == null) return;

            _t += Time.unscaledDeltaTime;
            float p = (_t % LoopDuration) / LoopDuration;

            // Reposicionar una vez que el layout ya resolvió (primeros ticks
            // y cada cambio real de tamaño del stage).
            if (_t < 0.1f || _needsRelayout)
            {
                _needsRelayout = false;
                PositionCenizaFx();
                PositionDobleFx();
                PositionBrilloFx();
                PositionCometaFx();
            }

            if (IsDoble) TickDoble(p);
            else if (IsBrillo) TickBrillo(p);
            else if (IsCometa) TickCometa(p);
            else TickCeniza(p);
        }

        private static void TickCeniza(float p)
        {
            // 1) El tablero se apaga: piezas a gris + velo oscuro
            float gray = Clamp01(p / 0.4f);
            Color grayTint = Color.Lerp(Color.white, new Color(0.42f, 0.42f, 0.45f, 1f), gray);
            foreach (var piece in _boardPieces)
            {
                if (piece == null) continue;
                piece.tintColor = grayTint;
                // Leve subida como en la animación real
                piece.style.translate = new Translate(
                    new Length(0f, LengthUnit.Pixel),
                    new Length(-6f * gray, LengthUnit.Pixel));
            }
            if (_boardDim != null)
            {
                float dimPeak = 0.28f;
                float a = dimPeak * Mathf.Min(Clamp01(p / 0.3f), Clamp01((1f - p) / 0.25f) + 0.4f);
                _boardDim.style.backgroundColor = new Color(0f, 0f, 0f, Clamp01(a));
            }
            // Casilla del Rey en rojo mate al final del loop
            if (_kingCell != null)
            {
                float mate = Clamp01((p - 0.55f) / 0.2f) * Clamp01((1f - p) / 0.15f + 0.3f);
                Color baseCol = _cellBase[_kingRow, _kingCol];
                _kingCell.style.backgroundColor = Color.Lerp(baseCol, new Color(0.55f, 0.12f, 0.10f, 1f), mate * 0.85f);
            }

            // 2) Niebla sobre el tablero
            if (_smokeImg != null)
                _smokeImg.style.opacity = 0.38f * Mathf.Min(Clamp01(p / 0.25f), Clamp01((1f - p) / 0.25f) + 0.25f);

            // 2b) Emblema del tornado: se materializa y el viento se lo lleva
            if (_cenizaIcon != null && _cenizaIcon.sprite != null && _cenizaIconSize > 1f)
            {
                float inA = Clamp01((p - 0.06f) / 0.16f);
                float outA = Clamp01((1f - p) / 0.28f);
                float drift = -CellPx * 4.2f * Clamp01(p / 0.9f);
                float s = Mathf.Lerp(0.88f, 1.02f, Clamp01(p / 0.7f));
                _cenizaIcon.style.left = _cenizaIconCx - _cenizaIconSize * 0.5f + drift;
                _cenizaIcon.style.top = _cenizaIconCy - _cenizaIconSize * 0.5f;
                _cenizaIcon.style.scale = new Scale(new Vector2(s, s));
                _cenizaIcon.style.rotate = new Rotate(Mathf.Sin(p * Mathf.PI * 1.6f) * 3f);
                _cenizaIcon.style.opacity = inA * outA * 0.92f;
            }

            // 3) Brasas a la izquierda + subida leve
            for (int i = 0; i < _embers.Count; i++)
            {
                Vector4 s = _seeds[i];
                float pi = (p + s.w) % 1f;
                float x = Mod(s.x - pi * 120f * s.z * 0.5f, 115f) - 7.5f;
                float y = s.y - pi * 12f + Mathf.Sin(pi * 6f + s.w * 6.28f) * 2f;
                var e = _embers[i];
                e.style.left = new Length(x, LengthUnit.Percent);
                e.style.top = new Length(y, LengthUnit.Percent);
                e.style.opacity = Clamp01(pi / 0.15f) * Clamp01((1f - pi) / 0.35f) * 0.95f;
            }

            AnimateStreak(_streakA, p, 0f);
            AnimateStreak(_streakB, p, 0.35f);
        }

        private static void TickDoble(float p)
        {
            // 1) Casilla del Rey parpadea en rojo jaque + líneas de ataque
            if (_kingCell != null)
            {
                float pulse = 0.5f + 0.5f * Mathf.Sin(p * Mathf.PI * 4f);
                Color baseCol = _cellBase[_kingRow, _kingCol];
                float mix = 0.35f + 0.55f * pulse * Clamp01(p / 0.1f) * Clamp01((1f - p) / 0.15f + 0.5f);
                _kingCell.style.backgroundColor = Color.Lerp(baseCol, CheckRed, Clamp01(mix));
            }
            float lineFlash = 0.55f + 0.45f * Mathf.Sin(p * Mathf.PI * 4f);
            if (_lineV != null) _lineV.style.opacity = lineFlash * Clamp01(p / 0.08f) * Clamp01((1f - p) / 0.2f + 0.4f);
            if (_lineD != null) _lineD.style.opacity = lineFlash * Clamp01(p / 0.08f) * Clamp01((1f - p) / 0.2f + 0.4f);

            // 2) Micro-vibración del tablero (como el CameraShake real, 0.35 s)
            if (_boardWrap != null)
            {
                float shakeDur = 0.35f / LoopDuration; // en unidades de p
                if (p < shakeDur)
                {
                    float k = 3.5f * (1f - p / shakeDur);
                    _boardWrap.style.translate = new Translate(
                        new Length(Random.Range(-k, k), LengthUnit.Pixel),
                        new Length(Random.Range(-k, k), LengthUnit.Pixel));
                }
                else
                {
                    _boardWrap.style.translate = new Translate(
                        new Length(0f, LengthUnit.Pixel), new Length(0f, LengthUnit.Pixel));
                }
            }

            // 2b) Emblema de sables: aparece con rebote y se funde con los anillos
            if (_dobleIcon != null && _dobleIcon.sprite != null)
            {
                float pop = Clamp01(p / 0.18f);
                float ease = 1f - Mathf.Pow(1f - pop, 3f);
                float hold = 1f + 0.04f * Mathf.Sin(p * Mathf.PI * 5f);
                float s = Mathf.Max(0.01f, Mathf.Lerp(0.6f, 1f, ease) * hold);
                _dobleIcon.style.scale = new Scale(new Vector2(s, s));
                _dobleIcon.style.rotate = new Rotate(Mathf.Sin(p * Mathf.PI * 2f) * 2.5f);
                _dobleIcon.style.opacity = Mathf.Min(pop * 1.6f, 0.96f) * Clamp01((1f - p) / 0.22f);
            }

            // 3) Anillos entrelazados sobre el Rey
            AnimateRing(_ringA, p, 0f);
            AnimateRing(_ringB, p, 0.12f);

            float flash = (p < 0.25f) ? p / 0.25f : Clamp01((0.55f - p) / 0.30f);
            if (_crossA != null) _crossA.style.opacity = Clamp01(flash) * 0.9f;
            if (_crossB != null) _crossB.style.opacity = Clamp01(flash) * 0.9f;

            if (_seal != null)
            {
                float pop = Clamp01(p / 0.22f);
                float ease = 1f - Mathf.Pow(1f - pop, 3f);
                float s = Mathf.Max(0.01f, ease);
                _seal.style.scale = new Scale(new Vector2(s, s));
                _seal.style.opacity = Mathf.Min(pop * 1.5f, 1f) * Clamp01((1f - p) / 0.20f);
            }
        }

        private static void TickBrillo(float p)
        {
            // 1) Casilla destino parpadea en dorado brillante
            if (_kingCell != null)
            {
                float pulse = 0.5f + 0.5f * Mathf.Sin(p * Mathf.PI * 4f);
                Color baseCol = _cellBase[_kingRow, _kingCol];
                float mix = 0.30f + 0.60f * pulse * Clamp01(p / 0.08f) * Clamp01((1f - p) / 0.15f + 0.4f);
                _kingCell.style.backgroundColor = Color.Lerp(baseCol,
                    new Color(1f, 0.80f, 0.30f, 1f), Clamp01(mix));
            }

            // 2) Icono ilustrado: pop con rebote, latido y fundido (como en partida)
            if (_flashImg != null)
            {
                if (_brilloUsesIcon)
                {
                    float pop = Clamp01(p / 0.16f);
                    float ease = 1f - Mathf.Pow(1f - pop, 3f);
                    float over = 1f + 0.18f * Mathf.Sin(pop * Mathf.PI);
                    float beat = (p > 0.28f && p < 0.72f)
                        ? 1f + 0.045f * Mathf.Sin((p - 0.28f) * Mathf.PI * 6f) : 1f;
                    float outA = 1f - Clamp01((p - 0.66f) / 0.28f);
                    float s = Mathf.Max(0.01f, ease * over * beat * Mathf.Lerp(1f, 0.88f, 1f - outA));
                    _flashImg.style.scale = new Scale(new Vector2(s, s));
                    _flashImg.style.rotate = new Rotate(Mathf.Sin(p * Mathf.PI * 2f) * 3.5f);
                    _flashImg.style.opacity = Clamp01(pop * 1.4f) * outA;
                }
                else
                {
                    // Respaldo: secuencia real de frames del clip viejo.
                    try
                    {
                        Sprite[] frames = BrilliantFx.Frames();
                        if (frames != null && frames.Length > 0)
                        {
                            int idx = Mathf.Clamp(Mathf.FloorToInt(p * frames.Length), 0, frames.Length - 1);
                            if (frames[idx] != null) _flashImg.sprite = frames[idx];
                            _flashImg.style.opacity = 1f;
                        }
                        else _flashImg.style.opacity = 0f;
                    }
                    catch { _flashImg.style.opacity = 0f; }
                }
            }

            // 3) Sello «!!» con pop elástico + fundido (como en partida)
            if (_brilloSeal != null)
            {
                float pop = Clamp01(p / 0.20f);
                float ease = 1f - Mathf.Pow(1f - pop, 3f);
                float s = Mathf.Max(0.01f, ease);
                _brilloSeal.style.scale = new Scale(new Vector2(s, s));
                _brilloSeal.style.opacity = Mathf.Min(pop * 1.5f, 1f) * Clamp01((1f - p) / 0.20f);
            }
        }

        private static void TickCometa(float p)
        {
            // 1) Casilla del fork parpadea en naranja ígneo
            if (_kingCell != null)
            {
                float pulse = 0.5f + 0.5f * Mathf.Sin(p * Mathf.PI * 4f);
                Color baseCol = _cellBase[_kingRow, _kingCol];
                float mix = 0.30f + 0.60f * pulse * Clamp01(p / 0.08f) * Clamp01((1f - p) / 0.15f + 0.4f);
                _kingCell.style.backgroundColor = Color.Lerp(baseCol,
                    new Color(1f, 0.55f, 0.15f, 1f), Clamp01(mix));
            }

            // 2) Icono ilustrado: vuelo desde abajo-izquierda + impacto (como en partida)
            if (_cometImg != null)
            {
                if (_cometaUsesIcon)
                {
                    const float impactP = 0.45f / 1.2f; // 0,45 s de vuelo dentro del loop
                    float stageW = StageWidth();
                    float boardLeft = (stageW - BOARD_PX) * 0.5f;
                    float boardTop = (320f - BOARD_PX) * 0.5f;
                    float cx = boardLeft + (_kingCol + 0.5f) * CellPx;
                    float cy = boardTop + (_kingRow + 0.5f) * CellPx;
                    float w = CellPx * 2.0f;
                    float left0 = cx - w * 0.5f;
                    float top0 = cy - w * 0.5f;

                    if (p < impactP)
                    {
                        float k = Clamp01(p / impactP);
                        float ease = 1f - Mathf.Pow(1f - k, 2.2f);
                        _cometImg.style.left = left0 - CellPx * 4.2f * (1f - ease);
                        _cometImg.style.top = top0 + CellPx * 3.0f * (1f - ease);
                        float sc = Mathf.Lerp(1.15f, 1.6f, ease);
                        _cometImg.style.scale = new Scale(new Vector2(sc, sc));
                        _cometImg.style.rotate = new Rotate(Mathf.Lerp(-16f, 0f, ease));
                        _cometImg.style.opacity = Clamp01(k * 2f);
                    }
                    else
                    {
                        float k = Clamp01((p - impactP) / (1f - impactP));
                        float punch = 1f + 0.28f * Mathf.Sin(Clamp01(k / 0.35f) * Mathf.PI);
                        _cometImg.style.left = left0;
                        _cometImg.style.top = top0;
                        _cometImg.style.scale = new Scale(new Vector2(punch, punch));
                        _cometImg.style.rotate = new Rotate(0f);
                        _cometImg.style.opacity = 1f - Clamp01((k - 0.45f) / 0.55f);
                    }
                }
                else
                {
                    // Respaldo: secuencia real de frames del clip viejo.
                    try
                    {
                        Sprite[] frames = ForkCometFx.Frames();
                        if (frames != null && frames.Length > 0)
                        {
                            int idx = Mathf.Clamp(Mathf.FloorToInt(p * frames.Length), 0, frames.Length - 1);
                            if (frames[idx] != null) _cometImg.sprite = frames[idx];
                            _cometImg.style.opacity = 1f;
                        }
                        else _cometImg.style.opacity = 0f;
                    }
                    catch { _cometImg.style.opacity = 0f; }
                }
            }

            // 3) Sello «¡HORQUILLA!» con pop elástico + fundido
            if (_cometaSeal != null)
            {
                float pop = Clamp01(p / 0.20f);
                float ease = 1f - Mathf.Pow(1f - pop, 3f);
                float s = Mathf.Max(0.01f, ease);
                _cometaSeal.style.scale = new Scale(new Vector2(s, s));
                _cometaSeal.style.opacity = Mathf.Min(pop * 1.5f, 1f) * Clamp01((1f - p) / 0.20f);
            }
        }

        private static void AnimateRing(Image img, float p, float offset)
        {
            if (img == null) return;
            float pi = Clamp01((p - offset) / 0.88f);
            img.style.opacity = Mathf.Sin(pi * Mathf.PI) * 0.95f;
            float s = 1f + 0.12f * Mathf.Sin(pi * Mathf.PI);
            img.style.scale = new Scale(new Vector2(s, s));
        }

        private static void AnimateStreak(Image img, float p, float offset)
        {
            if (img == null || img.style.display == DisplayStyle.None) return;
            float pk = Clamp01((p - offset) / 0.65f);
            img.style.left = new Length(Mathf.Lerp(110f, -45f, pk), LengthUnit.Percent);
            img.style.opacity = Mathf.Sin(pk * Mathf.PI) * 0.8f;
        }

        // ── Recursos ──────────────────────────────────────────────────────

        private static Sprite LoadFxSprite(string resourcePath)
        {
            try
            {
                Sprite s = Resources.Load<Sprite>(resourcePath);
                if (s != null) return s;
                Texture2D t = Resources.Load<Texture2D>(resourcePath);
                if (t != null) return Sprite.Create(t,
                    new Rect(0, 0, t.width, t.height), new Vector2(0.5f, 0.5f), 100f);
            }
            catch { /* capa omitida, el preview sigue */ }
            return null;
        }

        private static Sprite LoadPieceSprite(string resourcePath)
        {
            // 1) BoardView vivo: respeta variantes equipadas y recorte de padding
            try
            {
                var bv = BoardView.Instance;
                if (bv != null)
                {
                    // Mapeo rápido sin tocar enums: solo Reyes/Dama/etc. del preview
                    if (resourcePath == "Pieces/White/King")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.King, WilderGambit.Core.TeamColor.White);
                    if (resourcePath == "Pieces/Black/King")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.King, WilderGambit.Core.TeamColor.Black);
                    if (resourcePath == "Pieces/White/Queen")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Queen, WilderGambit.Core.TeamColor.White);
                    if (resourcePath == "Pieces/Black/Queen")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Queen, WilderGambit.Core.TeamColor.Black);
                    if (resourcePath == "Pieces/White/Rook")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Rook, WilderGambit.Core.TeamColor.White);
                    if (resourcePath == "Pieces/Black/Rook")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Rook, WilderGambit.Core.TeamColor.Black);
                    if (resourcePath == "Pieces/White/Bishop")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Bishop, WilderGambit.Core.TeamColor.White);
                    if (resourcePath == "Pieces/Black/Bishop")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Bishop, WilderGambit.Core.TeamColor.Black);
                    if (resourcePath == "Pieces/White/Knight")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Knight, WilderGambit.Core.TeamColor.White);
                    if (resourcePath == "Pieces/Black/Knight")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Knight, WilderGambit.Core.TeamColor.Black);
                    if (resourcePath == "Pieces/White/Pawn")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Pawn, WilderGambit.Core.TeamColor.White);
                    if (resourcePath == "Pieces/Black/Pawn")
                        return bv.GetPieceSprite(WilderGambit.Core.PieceType.Pawn, WilderGambit.Core.TeamColor.Black);
                }
            }
            catch { /* fallback a Resources */ }
            try
            {
                Sprite s = Resources.Load<Sprite>(resourcePath);
                if (s != null) return s;
                Texture2D t = Resources.Load<Texture2D>(resourcePath);
                if (t != null) return Sprite.Create(t,
                    new Rect(0, 0, t.width, t.height), new Vector2(0.5f, 0.5f), 100f);
            }
            catch { }
            return null;
        }

        /// <summary>Brasa radial con alpha limpio (la PNG trae fondo negro: aquí no sirve).</summary>
        private static Texture2D MakeEmberTexture()
        {
            const int n = 64;
            var tex = new Texture2D(n, n, TextureFormat.RGBA32, false)
            {
                name = "anim_preview_ember",
                filterMode = FilterMode.Bilinear,
                wrapMode = TextureWrapMode.Clamp
            };
            Color hot = new Color(1f, 0.85f, 0.54f, 1f);
            Color mid = new Color(0.89f, 0.44f, 0.11f, 1f);
            for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float dx = (x - n / 2f) / (n / 2f);
                    float dy = (y - n / 2f) / (n / 2f);
                    float d = Mathf.Clamp01(Mathf.Sqrt(dx * dx + dy * dy));
                    float a = Mathf.Pow(1f - d, 1.8f);
                    Color c = Color.Lerp(hot, mid, d) * a;
                    c.a = a;
                    tex.SetPixel(x, y, c);
                }
            tex.Apply(false);
            return tex;
        }

        private static float Clamp01(float v) => v < 0f ? 0f : (v > 1f ? 1f : v);

        private static float Mod(float v, float m)
        {
            float r = v % m;
            return r < 0f ? r + m : r;
        }
    }
}
