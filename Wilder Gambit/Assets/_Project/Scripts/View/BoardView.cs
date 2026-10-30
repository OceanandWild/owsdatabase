using System.Collections.Generic;
using UnityEngine;
using WilderGambit.Core;
using WilderGambit.Pieces;

namespace WilderGambit.View
{
    public class BoardView : MonoBehaviour
    {
        [Header("Board Settings")]
        [SerializeField] private float tileSize = 1.8f;
        [SerializeField] private Color lightTileColor = new Color(0.93f, 0.93f, 0.82f);
        [SerializeField] private Color darkTileColor  = new Color(0.46f, 0.59f, 0.33f);

        [Header("Board Background")]
        [SerializeField] private SpriteRenderer backgroundRenderer;
        [SerializeField] private Color selectedColor  = new Color(1f, 0.87f, 0f, 0.75f);
        [SerializeField] private Color validMoveColor = new Color(0.15f, 0.75f, 0.15f, 0.7f);
        [SerializeField] private Color captureColor   = new Color(0.95f, 0.15f, 0.15f, 0.85f);

        [Header("Piece Sprites - White")]
        [SerializeField] private Sprite whitePawnSprite;
        [SerializeField] private Sprite whiteKnightSprite;
        [SerializeField] private Sprite whiteBishopSprite;
        [SerializeField] private Sprite whiteRookSprite;
        [SerializeField] private Sprite whiteQueenSprite;
        [SerializeField] private Sprite whiteKingSprite;

        [Header("Piece Sprites - Black")]
        [SerializeField] private Sprite blackPawnSprite;
        [SerializeField] private Sprite blackKnightSprite;
        [SerializeField] private Sprite blackBishopSprite;
        [SerializeField] private Sprite blackRookSprite;
        [SerializeField] private Sprite blackQueenSprite;
        [SerializeField] private Sprite blackKingSprite;

        [Header("Piece Sprites - Variants")]
        [SerializeField] private Sprite whiteNecromancerBishopSprite;
        [SerializeField] private Sprite blackNecromancerBishopSprite;
        [SerializeField] private Sprite whiteSpectralPawnSprite;
        [SerializeField] private Sprite blackSpectralPawnSprite;
        [SerializeField] private Sprite whiteLancerPawnSprite;
        [SerializeField] private Sprite blackLancerPawnSprite;
        [SerializeField] private Sprite whiteRiderQueenSprite;
        [SerializeField] private Sprite blackRiderQueenSprite;
        [SerializeField] private Sprite whiteVampireQueenSprite;
        [SerializeField] private Sprite blackVampireQueenSprite;
        // ── Torre Fragua (variante de la Vía real, nivel 30) ──
        [SerializeField] private Sprite whiteFraguaRookSprite;
        [SerializeField] private Sprite blackFraguaRookSprite;

        // ── Peón Lancero (variante V4) ─────────────────────────────────────────
        // El arte del Lancero incluye la lanza y el pendón por encima y a un costado
        // del cuerpo del peón (cuerpo = 744 de los 900 px de alto; centro del cuerpo
        // en 0.423 / 0.413 del bbox, con origen de pivot abajo-izquierda como en Unity).
        // Estas constantes hacen que en el tablero el cuerpo del peón se vea igual de
        // grande y en el mismo sitio que el Peón clásico; solo la punta de la lanza
        // sobresale (~0.08 casilla) por arriba.
        private const float LANCER_BODY_SCALE = 1.21f; // 900 / 744
        private static readonly Vector2 LANCER_BODY_PIVOT = new Vector2(0.423f, 0.413f);

        // ── Dama Jinete (variante 3D) ──────────────────────────────────────────
        // El arte lleva espada + puño a la derecha del cuerpo de la dama: el pivot
        // se centra en la masa de la base (medido 0.34 en el PNG instalado) para
        // que el cuerpo quede en el centro de la casilla como la Dama clásica.
        // Sin compensación de escala: el sprite ya mide 810 px de alto, igual que
        // el contenido de la Dama clásica, así que la altura visual coincide sola.
        private static readonly Vector2 RIDER_BODY_PIVOT = new Vector2(0.34f, 0.5f);

        [Header("UI Indicator Sprites")]
        [SerializeField] private Sprite validMoveDotSprite;
        [SerializeField] private Sprite captureRingSprite;

        [Header("King Check Animation Frames")]
        [SerializeField] private Sprite[] kingCheckFrames;

        [Header("Eclipse Eterno Animation Frames")]
        [SerializeField] private Sprite[] eclipseMoveFrames;
        [SerializeField] private Sprite[] eclipseMateFrames;

        [Header("Knight Fork Animation Frames")]
        [SerializeField] private Sprite[] whiteKnightForkFrames;
        [SerializeField] private Sprite[] whiteKnightForkAttackFrames;
        [SerializeField] private Sprite whiteKnightForkStatic;

        public static BoardView Instance { get; private set; }

        // Lookup: posición lógica -> GameObject visual de la pieza
        private Dictionary<Vector2IntCustom, GameObject> pieceViews = new Dictionary<Vector2IntCustom, GameObject>();

        // Overlays de selección / movimientos válidos
        private List<GameObject> overlays = new List<GameObject>();

        // Indicadores persistentes del Nigromante (aura + contador)
        private List<GameObject> necromancerIndicators = new List<GameObject>();
        private Dictionary<ChessPiece, int> _lastSoulByPiece = new Dictionary<ChessPiece, int>();

        // Tinte base de cada pieza aturdida, para restaurarlo al recuperarse.
        private readonly Dictionary<GameObject, Color> _stunBaseColors = new Dictionary<GameObject, Color>();
        // Marcador «STUN» en espacio de mundo (no hijo: la escala de la pieza lo encogería).
        private readonly Dictionary<GameObject, GameObject> _stunMarkers = new Dictionary<GameObject, GameObject>();

        private SpriteRenderer[,] tileRenderers = new SpriteRenderer[Board.BOARD_SIZE, Board.BOARD_SIZE];
        private Color[,] tileBaseColors          = new Color[Board.BOARD_SIZE, Board.BOARD_SIZE];

        // Tablero decorado v2 (Luna Llena / Luna de Sangre): objeto 8x8 pintado que
        // reemplaza el patron plano de casillas; lo crea ApplyBoardBackground.
        private SpriteRenderer decoratedBoardRenderer;
        private bool _decoratedBoardArt;

        private Board board;
        private bool _isAnimating;
        public bool IsAnimating => _isAnimating;

        private void Awake()
        {
            if (Instance == null) Instance = this;
            else if (Instance != this) { Destroy(gameObject); return; }
        }

        private void Start()
        {
            // Calidad Ultra Máxima en tiempo de ejecución
            QualitySettings.SetQualityLevel(QualitySettings.names.Length - 1, true);
            QualitySettings.anisotropicFiltering = AnisotropicFiltering.ForceEnable;
            QualitySettings.antiAliasing = 8;
            QualitySettings.globalTextureMipmapLimit = 0; // Texturas a máxima resolución nativa sin downsampling
            QualitySettings.vSyncCount = 1;

            // Cargar automáticamente los frames de KingCheck si no están asignados en el Inspector
            if (kingCheckFrames == null || kingCheckFrames.Length == 0)
            {
                kingCheckFrames = LoadFrames("KingCheck", "frame_");
            }

            // Cargar automáticamente los frames de KnightFork Idle si no están asignados
            if (whiteKnightForkFrames == null || whiteKnightForkFrames.Length == 0)
            {
                whiteKnightForkFrames = LoadFrames("KnightFork", "frame_");
            }

            // Eclipse Eterno: pulso de movimiento y disolución de jaque mate.
            if (eclipseMoveFrames == null || eclipseMoveFrames.Length == 0)
            {
                eclipseMoveFrames = LoadFrames("EclipseEterno/Move", "frame_");
            }
            if (eclipseMateFrames == null || eclipseMateFrames.Length == 0)
            {
                eclipseMateFrames = LoadFrames("EclipseEterno/Mate", "frame_");
            }

            // Cargar automáticamente los frames de KnightFork Attack si no están asignados
            if (whiteKnightForkAttackFrames == null || whiteKnightForkAttackFrames.Length == 0)
            {
                whiteKnightForkAttackFrames = LoadFrames("KnightForkAttack", "frame_");
            }

            if (whiteKnightForkStatic == null)
            {
                whiteKnightForkStatic = Resources.Load<Sprite>("KnightFork/static");
                if (whiteKnightForkStatic == null)
                {
                    string staticPath = System.IO.Path.Combine(Application.dataPath, "Resources", "KnightFork", "static.png");
                    if (System.IO.File.Exists(staticPath))
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(staticPath);
                        Texture2D tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                        if (tex.LoadImage(bytes))
                        {
                            whiteKnightForkStatic = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                        }
                    }
                }
            }

            // Auto-fit: calcular tileSize para que el tablero llene el 92% de la pantalla
            Camera cam = Camera.main;
            if (cam != null && cam.orthographic)
            {
                float screenHeight = cam.orthographicSize * 2f;
                float screenWidth  = screenHeight * cam.aspect;
                float fitByHeight  = (screenHeight * 0.92f) / Board.BOARD_SIZE;
                float fitByWidth   = (screenWidth  * 0.92f) / Board.BOARD_SIZE;
                tileSize = Mathf.Min(fitByHeight, fitByWidth);

                // Ajustar cámara para que el tablero entero quepa (alto y ancho)
                FitCameraToBoard();
            }

            board = GetComponent<Board>();
            ApplyBoardBackground();
            CreateBoardTiles();
            LoadPieceSpritesIfMissing();
            SetupInitialPieces();
        }

        private int _lastScreenW, _lastScreenH;

        /// <summary>
        /// Encuadra la cámara para que el tablero se vea ENTERO en cualquier proporción:
        /// en horizontal manda el alto; en móvil vertical manda el ancho (antes solo se
        /// miraba el alto y en vertical se cortaban columnas). Lo que sobra queda para el fondo.
        /// </summary>
        private void FitCameraToBoard()
        {
            Camera cam = Camera.main;
            if (cam == null || !cam.orthographic) return;

            float aspect = Mathf.Max(0.1f, cam.aspect);
            float boardSize = Board.BOARD_SIZE * tileSize;
            float halfNeededH = boardSize / 2f + tileSize * 0.1f;
            float halfNeededW = boardSize / 2f + tileSize * 0.25f;

            if (_decoratedBoardArt)
            {
                // El objeto decorado trae borde ornamental alrededor de la grilla:
                // debe entrar completo (grilla + borde) con un pequeño margen.
                float artHalf = (boardSize / BoardBackgroundManager.BoardArtInnerFraction) / 2f
                                + tileSize * 0.1f;
                halfNeededH = Mathf.Max(halfNeededH, artHalf);
                halfNeededW = Mathf.Max(halfNeededW, artHalf);
            }

            cam.orthographicSize = Mathf.Max(halfNeededH, halfNeededW / aspect);

            _lastScreenW = Screen.width;
            _lastScreenH = Screen.height;
            ScaleBackgroundToCamera();
        }

        private void LateUpdate()
        {
            if (Screen.width != _lastScreenW || Screen.height != _lastScreenH)
                FitCameraToBoard();
        }

        private void LoadPieceSpritesIfMissing()
        {
            // Siempre se cargan desde archivo con recorte de padding transparente:
            // garantiza escala uniforme aunque el Inspector tenga sprites antiguos asignados.
            whitePawnSprite   = GetPieceSprite("White/Pawn");
            whiteKnightSprite = GetPieceSprite("White/Knight");
            whiteBishopSprite = GetPieceSprite("White/Bishop");
            whiteRookSprite   = GetPieceSprite("White/Rook");
            whiteQueenSprite  = GetPieceSprite("White/Queen");
            whiteKingSprite   = GetPieceSprite("White/King");

            blackPawnSprite   = GetPieceSprite("Black/Pawn");
            blackKnightSprite = GetPieceSprite("Black/Knight");
            blackBishopSprite = GetPieceSprite("Black/Bishop");
            blackRookSprite   = GetPieceSprite("Black/Rook");
            blackQueenSprite  = GetPieceSprite("Black/Queen");
            blackKingSprite   = GetPieceSprite("Black/King");

            // Variantes
            whiteNecromancerBishopSprite = GetPieceSprite("White/NecromancerBishop");
            blackNecromancerBishopSprite = GetPieceSprite("Black/NecromancerBishop");
            whiteSpectralPawnSprite      = GetPieceSprite("White/SpectralPawn");
            blackSpectralPawnSprite      = GetPieceSprite("Black/SpectralPawn");
            whiteLancerPawnSprite        = GetPieceSprite("White/LancerPawn");
            blackLancerPawnSprite        = GetPieceSprite("Black/LancerPawn");
            whiteRiderQueenSprite        = GetPieceSprite("White/RiderQueen");
            blackRiderQueenSprite        = GetPieceSprite("Black/RiderQueen");
            whiteVampireQueenSprite      = GetPieceSprite("White/VampireQueen");
            blackVampireQueenSprite      = GetPieceSprite("Black/VampireQueen");
            whiteFraguaRookSprite        = GetPieceSprite("White/FraguaRook");
            blackFraguaRookSprite        = GetPieceSprite("Black/FraguaRook");
        }

        private Sprite GetPieceSprite(string relativePath)
        {
            var __sw = System.Diagnostics.Stopwatch.StartNew();
            Debug.Log($"[PieceLoad] INICIO {relativePath}");
            // 1. Try loading directly from file (Assets/StreamingAssets/Pieces/ — fuente unica,
            //    disponible igual en Editor y en build) y recortar el padding transparente para
            //    que todas las piezas escalen de forma uniforme.
            //    Rutas legacy (Resources/, _Project/Textures/) quedan como fallback: solo
            //    resuelven en el Editor, NUNCA en un build.
            string[] candidatePaths = new string[]
            {
                System.IO.Path.Combine(Application.streamingAssetsPath, "Pieces", relativePath + ".png"),
                System.IO.Path.Combine(Application.dataPath, "Resources", "Pieces", relativePath + ".png"),
                System.IO.Path.Combine(Application.dataPath, "_Project", "Textures", "Pieces", relativePath + ".png")
            };

            foreach (var path in candidatePaths)
            {
                if (System.IO.File.Exists(path))
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(path);
                    Texture2D tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                    if (tex.LoadImage(bytes))
                    {
                        tex.filterMode = FilterMode.Bilinear;
                        tex.anisoLevel = 8;
                        // Los sprites espectrales vienen en PNG RGB sin alfa (fondo negro opaco):
                        // quitar el fondo conectado a los bordes antes de recortar.
                        Debug.Log($"[PieceLoad] {relativePath}: LoadImage OK {tex.width}x{tex.height} ({__sw.ElapsedMilliseconds} ms)");
                        if (relativePath.Contains("SpectralPawn"))
                            tex = RemoveEdgeConnectedBackground(tex, 0.18f, relativePath);
                        Debug.Log($"[PieceLoad] {relativePath}: post-fondo ({__sw.ElapsedMilliseconds} ms)");

                        // El Lancero lleva lanza + pendón: su pivot se centra en el cuerpo
                        // del peón para que la pieza no quede desplazada en la casilla.
                        Vector2 pivot = relativePath.Contains("LancerPawn")
                            ? LANCER_BODY_PIVOT
                            : relativePath.Contains("RiderQueen")
                            ? RIDER_BODY_PIVOT
                            : new Vector2(0.5f, 0.5f);
                        Sprite __spr = CreateTrimmedSprite(tex, pivot);
                        Debug.Log($"[PieceLoad] FIN {relativePath} ({__sw.ElapsedMilliseconds} ms)");
                        return __spr;
                    }
                }
            }

            // 2. Fallback: Resources.Load (sin recorte posible si la textura no es legible)
            Sprite resSprite = Resources.Load<Sprite>($"Pieces/{relativePath}");
            if (resSprite != null) return resSprite;

            return null;
        }

        /// <summary>
        /// Hace transparente el fondo negro de texturas sin canal alfa (ej. Peón Espectral).
        /// Flood-fill desde todos los píxeles del borde con luminancia por debajo del umbral,
        /// de modo que las zonas oscuras del interior del dibujo NO se ven afectadas.
        /// </summary>
        private Texture2D RemoveEdgeConnectedBackground(Texture2D tex, float luminanceThreshold, string path = null)
        {
            int w = tex.width, h = tex.height;
            var pixels = tex.GetPixels32();
            bool[] isBackground = new bool[w * h];
            var stack = new System.Collections.Generic.Stack<int>();

            byte ThresholdByte() => (byte)(luminanceThreshold * 255f);
            byte threshold = ThresholdByte();

            System.Func<int, bool> isDark = (int idx) =>
            {
                Color32 p = pixels[idx];
                // Fondo negro: los tres canales por debajo del umbral
                return p.r < threshold && p.g < threshold && p.b < threshold;
            };

            // Semillas: píxeles oscuros en el borde
            for (int x = 0; x < w; x++)
            {
                if (isDark(x))                 { isBackground[x] = true; stack.Push(x); }
                if (isDark((h - 1) * w + x))   { isBackground[(h - 1) * w + x] = true; stack.Push((h - 1) * w + x); }
            }
            for (int y = 0; y < h; y++)
            {
                if (isDark(y * w))             { isBackground[y * w] = true; stack.Push(y * w); }
                if (isDark(y * w + w - 1))     { isBackground[y * w + w - 1] = true; stack.Push(y * w + w - 1); }
            }

            while (stack.Count > 0)
            {
                int idx = stack.Pop();
                int x = idx % w, y = idx / w;

                if (x > 0     && !isBackground[idx - 1] && isDark(idx - 1)) { isBackground[idx - 1] = true; stack.Push(idx - 1); }
                if (x < w - 1 && !isBackground[idx + 1] && isDark(idx + 1)) { isBackground[idx + 1] = true; stack.Push(idx + 1); }
                if (y > 0     && !isBackground[idx - w] && isDark(idx - w)) { isBackground[idx - w] = true; stack.Push(idx - w); }
                if (y < h - 1 && !isBackground[idx + w] && isDark(idx + w)) { isBackground[idx + w] = true; stack.Push(idx + w); }
            }

            int removed = 0;
            for (int i = 0; i < pixels.Length; i++)
            {
                if (isBackground[i])
                {
                    pixels[i] = new Color32(0, 0, 0, 0);
                    removed++;
                }
            }

            tex.SetPixels32(pixels);
            tex.Apply();
            Debug.Log($"[BoardView] Fondo negro eliminado de {path ?? "??"}: {removed}/{w * h} píxeles transparentes.");
            return tex;
        }

        /// <summary>
        /// Crea un sprite recortando el padding transparente de la textura para que
        /// los bounds reflejen solo el dibujo real de la pieza (escala uniforme).
        /// </summary>
        private Sprite CreateTrimmedSprite(Texture2D tex, Vector2 pivot)
        {
            Rect rect = new Rect(0, 0, tex.width, tex.height);
            try
            {
                Color32[] pixels = tex.GetPixels32();
                int minX = tex.width, minY = tex.height, maxX = -1, maxY = -1;
                for (int y = 0; y < tex.height; y++)
                {
                    for (int x = 0; x < tex.width; x++)
                    {
                        if (pixels[y * tex.width + x].a > 2)
                        {
                            if (x < minX) minX = x;
                            if (x > maxX) maxX = x;
                            if (y < minY) minY = y;
                            if (y > maxY) maxY = y;
                        }
                    }
                }
                if (maxX > minX && maxY > minY)
                    rect = new Rect(minX, minY, maxX - minX + 1, maxY - minY + 1);
            }
            catch (UnityException)
            {
                // Textura no legible: usar la textura completa
            }
            return Sprite.Create(tex, rect, pivot, 100f);
        }

        private Sprite[] LoadFrames(string resourceFolder, string prefix)
        {
            var loaded = Resources.LoadAll<Sprite>(resourceFolder);
            var frameList = new List<Sprite>();
            if (loaded != null)
            {
                foreach (var s in loaded)
                {
                    if (s != null && s.name.StartsWith(prefix))
                        frameList.Add(s);
                }
            }

            if (frameList.Count == 0)
            {
                string folderPath = System.IO.Path.Combine(Application.dataPath, "Resources", resourceFolder);
                if (System.IO.Directory.Exists(folderPath))
                {
                    string[] files = System.IO.Directory.GetFiles(folderPath, prefix + "*.png");
                    foreach (string file in files)
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(file);
                        Texture2D tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                        if (tex.LoadImage(bytes))
                        {
                            tex.filterMode = FilterMode.Bilinear;
                            tex.anisoLevel = 8;
                            string name = System.IO.Path.GetFileNameWithoutExtension(file);
                            Sprite spr = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                            spr.name = name;
                            frameList.Add(spr);
                        }
                    }
                }
            }

            frameList.Sort((a, b) => string.Compare(a.name, b.name, System.StringComparison.Ordinal));
            return frameList.ToArray();
        }

        // ─── Tablero ───────────────────────────────────────────────────────────

        private void CreateBoardTiles()
        {
            GameObject boardHolder = new GameObject("BoardTiles");
            boardHolder.transform.SetParent(transform);

            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    GameObject tile = new GameObject($"Tile_{r}_{c}");
                    tile.transform.SetParent(boardHolder.transform);
                    tile.transform.position = GetWorldPosition(r, c);
                    // Escalar la casilla exactamente al tileSize para eliminar gaps
                    tile.transform.localScale = new Vector3(tileSize, tileSize, 1f);

                    SpriteRenderer sr = tile.AddComponent<SpriteRenderer>();
                    sr.sprite = CreateSquareSprite();
                    Color col = (r + c) % 2 == 0 ? darkTileColor : lightTileColor;
                    sr.color = col;

                    tileRenderers[r, c]  = sr;
                    tileBaseColors[r, c] = col;

                    BoxCollider2D collider = tile.AddComponent<BoxCollider2D>();
                    collider.size = Vector2.one; // El collider es 1x1 pero el scale hace el resto
                }
            }
        }

        // ─── Piezas iniciales ──────────────────────────────────────────────────

        private void SetupInitialPieces()
        {
            // ─── Blancas (Fila 0) ─────────────────────────────────────────────
            bool whiteNecro = WilderGambit.Core.PieceLoadoutManager.UsesNecromancerBishop(TeamColor.White);
            bool whiteFragua = WilderGambit.Core.PieceLoadoutManager.UsesFraguaRook(TeamColor.White);
            // Variantes de la velada (tienda de Dulces): esculturas propias, mismos movimientos.
            bool whitePumpkin = WilderGambit.Core.PieceLoadoutManager.UsesPumpkinPawn(TeamColor.White);
            bool whiteGhostKnight = WilderGambit.Core.PieceLoadoutManager.UsesGhostKnight(TeamColor.White);

            if (whiteFragua)
                SpawnPiece<WilderGambit.Pieces.FraguaRook>(TeamColor.White, GetFraguaRookSprite(TeamColor.White), 0, 0);
            else
                SpawnPiece<Rook>(TeamColor.White, whiteRookSprite, 0, 0);

            if (whiteGhostKnight)
                SpawnPiece<WilderGambit.Pieces.GhostKnight>(TeamColor.White, GetGhostKnightSprite(TeamColor.White), 0, 1);
            else
                SpawnPiece<Knight>(TeamColor.White, whiteKnightSprite, 0, 1);

            if (whiteNecro)
                SpawnPiece<WilderGambit.Pieces.NecromancerBishop>(TeamColor.White, whiteNecromancerBishopSprite, 0, 2);
            else
                SpawnPiece<Bishop>(TeamColor.White, whiteBishopSprite, 0, 2);

            if (WilderGambit.Core.PieceLoadoutManager.UsesVampireQueen(TeamColor.White))
                SpawnPiece<WilderGambit.Pieces.VampireQueen>(TeamColor.White, GetVampireQueenSprite(TeamColor.White), 0, 3);
            else if (WilderGambit.Core.PieceLoadoutManager.UsesRiderQueen(TeamColor.White))
                SpawnPiece<WilderGambit.Pieces.RiderQueen>(TeamColor.White, GetRiderQueenSprite(TeamColor.White), 0, 3);
            else
                SpawnPiece<Queen>(TeamColor.White, whiteQueenSprite, 0, 3);
            SpawnPiece<King> (TeamColor.White, whiteKingSprite,  0, 4);

            if (whiteNecro)
                SpawnPiece<WilderGambit.Pieces.NecromancerBishop>(TeamColor.White, whiteNecromancerBishopSprite, 0, 5);
            else
                SpawnPiece<Bishop>(TeamColor.White, whiteBishopSprite, 0, 5);

            if (whiteGhostKnight)
                SpawnPiece<WilderGambit.Pieces.GhostKnight>(TeamColor.White, GetGhostKnightSprite(TeamColor.White), 0, 6);
            else
                SpawnPiece<Knight>(TeamColor.White, whiteKnightSprite, 0, 6);

            if (whiteFragua)
                SpawnPiece<WilderGambit.Pieces.FraguaRook>(TeamColor.White, GetFraguaRookSprite(TeamColor.White), 0, 7);
            else
                SpawnPiece<Rook>(TeamColor.White, whiteRookSprite, 0, 7);

            bool whiteLancer = WilderGambit.Core.PieceLoadoutManager.UsesLancerPawn(TeamColor.White);

            for (int c = 0; c < 8; c++)
            {
                if (whiteLancer)
                    SpawnPiece<WilderGambit.Pieces.LancerPawn>(TeamColor.White, GetLancerPawnSprite(TeamColor.White), 1, c);
                else if (whitePumpkin)
                    SpawnPiece<WilderGambit.Pieces.PumpkinPawn>(TeamColor.White, GetPumpkinPawnSprite(TeamColor.White), 1, c);
                else
                    SpawnPiece<Pawn>(TeamColor.White, whitePawnSprite, 1, c);
            }

            // ─── Negras (Fila 7) ──────────────────────────────────────────────
            bool blackNecro = WilderGambit.Core.PieceLoadoutManager.UsesNecromancerBishop(TeamColor.Black);
            bool blackFragua = WilderGambit.Core.PieceLoadoutManager.UsesFraguaRook(TeamColor.Black);
            bool blackPumpkin = WilderGambit.Core.PieceLoadoutManager.UsesPumpkinPawn(TeamColor.Black);
            bool blackGhostKnight = WilderGambit.Core.PieceLoadoutManager.UsesGhostKnight(TeamColor.Black);

            if (blackFragua)
                SpawnPiece<WilderGambit.Pieces.FraguaRook>(TeamColor.Black, GetFraguaRookSprite(TeamColor.Black), 7, 0);
            else
                SpawnPiece<Rook>(TeamColor.Black, blackRookSprite, 7, 0);

            if (blackGhostKnight)
                SpawnPiece<WilderGambit.Pieces.GhostKnight>(TeamColor.Black, GetGhostKnightSprite(TeamColor.Black), 7, 1);
            else
                SpawnPiece<Knight>(TeamColor.Black, blackKnightSprite, 7, 1);

            if (blackNecro)
                SpawnPiece<WilderGambit.Pieces.NecromancerBishop>(TeamColor.Black, blackNecromancerBishopSprite, 7, 2);
            else
                SpawnPiece<Bishop>(TeamColor.Black, blackBishopSprite, 7, 2);

            if (WilderGambit.Core.PieceLoadoutManager.UsesVampireQueen(TeamColor.Black))
                SpawnPiece<WilderGambit.Pieces.VampireQueen>(TeamColor.Black, GetVampireQueenSprite(TeamColor.Black), 7, 3);
            else if (WilderGambit.Core.PieceLoadoutManager.UsesRiderQueen(TeamColor.Black))
                SpawnPiece<WilderGambit.Pieces.RiderQueen>(TeamColor.Black, GetRiderQueenSprite(TeamColor.Black), 7, 3);
            else
                SpawnPiece<Queen>(TeamColor.Black, blackQueenSprite, 7, 3);
            SpawnPiece<King> (TeamColor.Black, blackKingSprite,  7, 4);

            if (blackNecro)
                SpawnPiece<WilderGambit.Pieces.NecromancerBishop>(TeamColor.Black, blackNecromancerBishopSprite, 7, 5);
            else
                SpawnPiece<Bishop>(TeamColor.Black, blackBishopSprite, 7, 5);

            if (blackGhostKnight)
                SpawnPiece<WilderGambit.Pieces.GhostKnight>(TeamColor.Black, GetGhostKnightSprite(TeamColor.Black), 7, 6);
            else
                SpawnPiece<Knight>(TeamColor.Black, blackKnightSprite, 7, 6);

            if (blackFragua)
                SpawnPiece<WilderGambit.Pieces.FraguaRook>(TeamColor.Black, GetFraguaRookSprite(TeamColor.Black), 7, 7);
            else
                SpawnPiece<Rook>(TeamColor.Black, blackRookSprite, 7, 7);

            bool blackLancer = WilderGambit.Core.PieceLoadoutManager.UsesLancerPawn(TeamColor.Black);

            for (int c = 0; c < 8; c++)
            {
                if (blackLancer)
                    SpawnPiece<WilderGambit.Pieces.LancerPawn>(TeamColor.Black, GetLancerPawnSprite(TeamColor.Black), 6, c);
                else if (blackPumpkin)
                    SpawnPiece<WilderGambit.Pieces.PumpkinPawn>(TeamColor.Black, GetPumpkinPawnSprite(TeamColor.Black), 6, c);
                else
                    SpawnPiece<Pawn>(TeamColor.Black, blackPawnSprite, 6, c);
            }
        }

        /// <summary>
        /// Reinicia completamente todas las piezas del tablero visual y lógico al estado inicial.
        /// </summary>
        public void ResetBoard()
        {
            foreach (var kvp in pieceViews)
            {
                if (kvp.Value != null)
                {
                    Destroy(kvp.Value);
                }
            }
            pieceViews.Clear();
            ClearStunVisuals();
            ClearOverlays();

            if (board != null)
            {
                board.ClearBoard();
            }

            SetupInitialPieces();
        }
        /// <summary>
        /// Reconstruye la vista a partir del estado lógico actual del Board (usado por Undo).
        /// Destruye las vistas previas y crea sprites para las piezas lógicas existentes.
        /// </summary>
        public void RebuildFromBoard()
        {
            foreach (var kvp in pieceViews)
            {
                if (kvp.Value != null) Destroy(kvp.Value);
            }
            pieceViews.Clear();
            ClearStunVisuals();
            ClearOverlays();
            if (board == null) board = GetComponent<Board>();
            if (board == null) return;
            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    var pos = new Vector2IntCustom(r, c);
                    ChessPiece logical = board.GetPieceAt(pos);
                    if (logical != null)
                    {
                        GameObject go = logical.gameObject;
                        go.transform.position = GetWorldPosition(r, c);
                        go.transform.SetParent(transform);
                        if (go.GetComponent<SpriteRenderer>() == null)
                        {
                            // Las variantes tienen arte propio: reconstruir con su sprite
                            Sprite sprite = BaseSpriteForPiece(logical);
                            float targetHeight = tileSize * 0.82f;
                            float scale = 1f;
                            if (sprite != null && sprite.bounds.size.y > 0) scale = targetHeight / sprite.bounds.size.y;
                            if (IsLancerArt(sprite)) scale *= LANCER_BODY_SCALE;
                            if (sprite != null)
                            {
                                GameObject shadow = new GameObject("Shadow");
                                shadow.transform.SetParent(go.transform);
                                shadow.transform.localPosition = new Vector3(0.02f * tileSize, -0.02f * tileSize, 0f);
                                shadow.transform.localScale = Vector3.one;
                                var srShadow = shadow.AddComponent<SpriteRenderer>();
                                srShadow.sprite = sprite;
                                srShadow.color = new Color(0f, 0f, 0f, 0.35f);
                                srShadow.sortingOrder = 1;
                            }
                            var sr = go.AddComponent<SpriteRenderer>();
                            sr.sprite = sprite;
                            sr.sortingOrder = 2;
                            go.transform.localScale = new Vector3(scale, scale, 1f);
                            // Aplicar tinte de skin + aura si existe
                            ApplyEquippedSkin(go, logical.Type, logical.Team);
                        }
                        else
                        {
                            go.transform.position = GetWorldPosition(r, c);
                            // La vista ya existía: se devuelve al arte base de la pieza
                            // (pudo quedar con el arte de una skin anterior) y se repinta
                            // la skin, que si no se quedaría con el tinte de la jugada previa.
                            Sprite baseSprite = BaseSpriteForPiece(logical);
                            if (baseSprite != null)
                            {
                                var srBase = go.GetComponent<SpriteRenderer>();
                                if (srBase != null) srBase.sprite = baseSprite;

                                Transform shadowT = go.transform.Find("Shadow");
                                var shadowSr = shadowT != null ? shadowT.GetComponent<SpriteRenderer>() : null;
                                if (shadowSr != null) shadowSr.sprite = baseSprite;

                                float baseHeight = tileSize * 0.82f;
                                float baseScale = baseSprite.bounds.size.y > 0 ? baseHeight / baseSprite.bounds.size.y : 1f;
                                if (IsLancerArt(baseSprite)) baseScale *= LANCER_BODY_SCALE;
                                go.transform.localScale = new Vector3(baseScale, baseScale, 1f);
                            }
                            ApplyEquippedSkin(go, logical.Type, logical.Team);
                        }
                        pieceViews[pos] = go;
                    }
                }
            }

            // Reaplicar aturdimientos sobre las vistas recién reconstruidas (Undo).
            RefreshStunIndicators(board);
        }



        private void SpawnPiece<T>(TeamColor team, Sprite sprite, int row, int col) where T : ChessPiece
        {
            var pos = new Vector2IntCustom(row, col);

            GameObject pieceObj = new GameObject($"{team}_{typeof(T).Name}");
            pieceObj.transform.position = GetWorldPosition(row, col);

            // La skin se aplica más abajo, cuando ya existe el SpriteRenderer.
            PieceType inferredType = InferPieceType<T>();

            // Aplicar calidad Ultra Trilinear y máxima filtración anisotrópica (16x) a las texturas
            if (sprite != null && sprite.texture != null)
            {
                sprite.texture.filterMode = FilterMode.Trilinear;
                sprite.texture.anisoLevel = 16;
            }

            // Normalización exacta de escala: Se usa un tamaño unificado del 82% del tamaño de la casilla
            // ajustado según el contenedor delimitador (bounds) para que todas las piezas tengan la misma altura visual uniforme
            float targetHeight = tileSize * 0.82f;
            float scale = 1f;
            if (sprite != null && sprite.bounds.size.y > 0)
            {
                scale = targetHeight / sprite.bounds.size.y;
            }
            // El Lancero incluye lanza + pendón en el sprite: compensar para que el
            // cuerpo del peón mida lo mismo que el Peón clásico en la casilla.
            if (IsLancerArt(sprite)) scale *= LANCER_BODY_SCALE;

            // ── Sombra elegante drop shadow ──
            if (sprite != null)
            {
                GameObject shadow = new GameObject("Shadow");
                shadow.transform.SetParent(pieceObj.transform);
                shadow.transform.localPosition = new Vector3(0.02f * tileSize, -0.02f * tileSize, 0f);
                shadow.transform.localScale = Vector3.one;

                SpriteRenderer shadowSr = shadow.AddComponent<SpriteRenderer>();
                shadowSr.sprite       = sprite;
                shadowSr.color        = new Color(0f, 0f, 0f, 0.35f);
                shadowSr.sortingOrder = 1; // Entre el tablero (0) y la pieza (2)
            }

            // ── Sprite principal de la pieza ──
            SpriteRenderer sr = pieceObj.AddComponent<SpriteRenderer>();
            sr.sprite       = sprite;
            sr.sortingOrder = 2;

            pieceObj.transform.localScale = new Vector3(scale, scale, 1f);

            // Tinte + aura de la skin equipada para este tipo de pieza
            ApplyEquippedSkin(pieceObj, inferredType, team);

            T piece = pieceObj.AddComponent<T>();
            piece.Init(team, pos);
            board.SetPieceAt(pos, piece);

            pieceViews[pos] = pieceObj;
        }

        // ─── API pública llamada por GameManager ───────────────────────────────

        /// <summary>Mueve visualmente la pieza de 'from' a 'to' y destruye la capturada si hubiera.</summary>
        private const float MOVE_ANIM_DURATION = 0.18f;

        /// <summary>
        /// Moves a piece visually from 'from' to 'to' with smooth animation.
        /// Destroys the captured piece at destination if any.
        /// </summary>
        public void MovePieceView(Vector2IntCustom from, Vector2IntCustom to)
        {
            if (pieceViews.TryGetValue(from, out GameObject movingObj))
            {
                // Remove any existing animator to avoid conflicts
                var existingAnim = movingObj.GetComponent<PieceAnimator>();
                if (existingAnim != null) Destroy(existingAnim);

                // Destroy captured piece immediately
                if (pieceViews.TryGetValue(to, out GameObject capturedObj))
                {
                    if (capturedObj != null)
                    {
                        RemoveStunMarker(capturedObj);
                        _stunBaseColors.Remove(capturedObj);
                    }
                    Destroy(capturedObj);
                    pieceViews.Remove(to);
                }

                // Handle castling rook movement (instant, no animation)
                ChessPiece kingPiece = board.GetPieceAt(to);
                if (kingPiece != null && kingPiece.Type == PieceType.King && Mathf.Abs(to.Col - from.Col) == 2)
                {
                    int row = from.Row;
                    if (to.Col == 6) // Short castle
                    {
                        Vector2IntCustom rookFrom = new Vector2IntCustom(row, 7);
                        Vector2IntCustom rookTo   = new Vector2IntCustom(row, 5);
                        if (pieceViews.TryGetValue(rookFrom, out GameObject rookObj))
                        {
                            rookObj.transform.position = GetWorldPosition(rookTo.Row, rookTo.Col);
                            pieceViews.Remove(rookFrom);
                            pieceViews[rookTo] = rookObj;
                        }
                    }
                    else if (to.Col == 2) // Long castle
                    {
                        Vector2IntCustom rookFrom = new Vector2IntCustom(row, 0);
                        Vector2IntCustom rookTo   = new Vector2IntCustom(row, 3);
                        if (pieceViews.TryGetValue(rookFrom, out GameObject rookObj))
                        {
                            rookObj.transform.position = GetWorldPosition(rookTo.Row, rookTo.Col);
                            pieceViews.Remove(rookFrom);
                            pieceViews[rookTo] = rookObj;
                        }
                    }
                }

                // Update dictionary immediately
                pieceViews.Remove(from);
                pieceViews[to] = movingObj;

                // Animate the piece to its destination
                Vector3 targetPos = GetWorldPosition(to.Row, to.Col);
                _isAnimating = true;

                var animator = movingObj.AddComponent<PieceAnimator>();
                animator.AnimateTo(targetPos, MOVE_ANIM_DURATION, () =>
                {
                    _isAnimating = false;
                });

                // El Rey con Eclipse Eterno deja un pulso de vacío mientras viaja.
                // El frame se voltea si el movimiento va hacia la izquierda.
                if (kingPiece != null && kingPiece.Type == PieceType.King && HasEclipseEternoEquipped)
                {
                    PlayEclipseMoveAnimation(movingObj, kingPiece.Team, System.Math.Sign(to.Col - from.Col));
                }
            }
        }

        /// <summary>
        /// Intercambia visualmente dos piezas (Posesión del Caballo Fantasma): cada
        /// vista viaja a la casilla de la otra. Si falta alguna vista, se reconstruye
        /// el tablero desde el estado lógico, que ya está intercambiado.
        /// </summary>
        public void SwapPieceViews(Vector2IntCustom a, Vector2IntCustom b)
        {
            if (!pieceViews.TryGetValue(a, out GameObject objA) || objA == null ||
                !pieceViews.TryGetValue(b, out GameObject objB) || objB == null)
            {
                RebuildFromBoard();
                return;
            }

            var animA = objA.GetComponent<PieceAnimator>();
            if (animA != null) Destroy(animA);
            var animB = objB.GetComponent<PieceAnimator>();
            if (animB != null) Destroy(animB);

            // Actualizar el lookup antes de animar: el estado lógico ya está intercambiado.
            pieceViews[a] = objB;
            pieceViews[b] = objA;

            // Los marcadores de aturdimiento viven en espacio de mundo: moverlos
            // con su pieza (un peón aturdido puede ser poseído).
            RepositionStunMarker(objA, b);
            RepositionStunMarker(objB, a);

            Vector3 posA = GetWorldPosition(a.Row, a.Col);
            Vector3 posB = GetWorldPosition(b.Row, b.Col);

            _isAnimating = true;
            int remaining = 2;
            System.Action done = () =>
            {
                remaining--;
                if (remaining <= 0) _isAnimating = false;
            };

            var moveA = objA.AddComponent<PieceAnimator>();
            moveA.AnimateTo(posB, MOVE_ANIM_DURATION, done);
            var moveB = objB.AddComponent<PieceAnimator>();
            moveB.AnimateTo(posA, MOVE_ANIM_DURATION, done);
        }

        /// <summary>
        /// Promueve visual y lógicamente un peón a una nueva pieza (Dama, Torre, Alfil o Caballo).
        /// </summary>
        public void PromotePieceView(Vector2IntCustom pos, PieceType newType, TeamColor team)
        {
            if (pieceViews.TryGetValue(pos, out GameObject pieceObj))
            {
                // La pieza promovida es una pieza nueva: no hereda aturdimiento.
                RemoveStunMarker(pieceObj);
                _stunBaseColors.Remove(pieceObj);

                // Eliminar el componente de peón anterior
                ChessPiece oldPiece = pieceObj.GetComponent<ChessPiece>();
                if (oldPiece != null)
                {
                    Destroy(oldPiece);
                }

                // Determinar el nuevo componente y sprite
                Sprite newSprite = GetPieceSprite(newType, team);
                ChessPiece newPiece = null;

                switch (newType)
                {
                    case PieceType.Queen:
                        newPiece = pieceObj.AddComponent<Queen>();
                        break;
                    case PieceType.Rook:
                        newPiece = pieceObj.AddComponent<Rook>();
                        break;
                    case PieceType.Bishop:
                        newPiece = pieceObj.AddComponent<Bishop>();
                        break;
                    case PieceType.Knight:
                        newPiece = pieceObj.AddComponent<Knight>();
                        break;
                }

                if (newPiece != null)
                {
                    newPiece.Init(team, pos);
                    newPiece.HasMoved = true;
                    if (board != null) board.SetPieceAt(pos, newPiece);
                }

                // Actualizar sprite principal
                SpriteRenderer sr = pieceObj.GetComponent<SpriteRenderer>();
                if (sr != null && newSprite != null)
                {
                    sr.sprite = newSprite;
                    float targetHeight = tileSize * 0.82f;
                    float scale = 1f;
                    if (newSprite.bounds.size.y > 0)
                    {
                        scale = targetHeight / newSprite.bounds.size.y;
                    }
                    pieceObj.transform.localScale = new Vector3(scale, scale, 1f);
                }

                // Actualizar sprite de sombra
                Transform shadowT = pieceObj.transform.Find("Shadow");
                if (shadowT != null && newSprite != null)
                {
                    SpriteRenderer shadowSr = shadowT.GetComponent<SpriteRenderer>();
                    if (shadowSr != null) shadowSr.sprite = newSprite;
                }

                // La skin del peón no puede quedarse pegada a la pieza promovida: se
                // retira su tinte/aura y se aplica la que le corresponde al tipo nuevo.
                ApplyEquippedSkin(pieceObj, newType, team);
            }
        }

        public Sprite GetPieceSprite(PieceType type, TeamColor team)
        {
            if (team == TeamColor.White)
            {
                switch (type)
                {
                    case PieceType.Queen:            return whiteQueenSprite;
                    case PieceType.Rook:             return whiteRookSprite;
                    case PieceType.Bishop:           return whiteBishopSprite;
                    case PieceType.NecromancerBishop:return whiteNecromancerBishopSprite;
                    case PieceType.Knight:           return whiteKnightSprite;
                    case PieceType.Pawn:             return whitePawnSprite;
                    case PieceType.King:             return whiteKingSprite;
                }
            }
            else
            {
                switch (type)
                {
                    case PieceType.Queen:            return blackQueenSprite;
                    case PieceType.Rook:             return blackRookSprite;
                    case PieceType.Bishop:           return blackBishopSprite;
                    case PieceType.NecromancerBishop:return blackNecromancerBishopSprite;
                    case PieceType.Knight:           return blackKnightSprite;
                    case PieceType.Pawn:             return blackPawnSprite;
                    case PieceType.King:             return blackKingSprite;
                }
            }
            return null;
        }

        /// <summary>
        /// Sprite del Peón Lancero (variante V4) para el equipo indicado.
        /// Si el arte propio aún no existe, cae al sprite del Peón clásico.
        /// </summary>
        public Sprite GetLancerPawnSprite(TeamColor team)
        {
            if (team == TeamColor.White)
            {
                if (whiteLancerPawnSprite == null) whiteLancerPawnSprite = GetPieceSprite("White/LancerPawn");
                return whiteLancerPawnSprite != null ? whiteLancerPawnSprite : whitePawnSprite;
            }

            if (blackLancerPawnSprite == null) blackLancerPawnSprite = GetPieceSprite("Black/LancerPawn");
            return blackLancerPawnSprite != null ? blackLancerPawnSprite : blackPawnSprite;
        }

        /// <summary>¿Es este el arte propio del Lancero? (activa escala y pivot especiales)</summary>
        private bool IsLancerArt(Sprite sprite)
        {
            return sprite != null && (sprite == whiteLancerPawnSprite || sprite == blackLancerPawnSprite);
        }

        /// <summary>
        /// Sprite de la Dama Jinete (variante 3D) para el equipo indicado.
        /// Si el arte propio aún no existe, cae al sprite de la Dama clásica.
        /// </summary>
        public Sprite GetRiderQueenSprite(TeamColor team)
        {
            if (team == TeamColor.White)
            {
                if (whiteRiderQueenSprite == null) whiteRiderQueenSprite = GetPieceSprite("White/RiderQueen");
                return whiteRiderQueenSprite != null ? whiteRiderQueenSprite : whiteQueenSprite;
            }

            if (blackRiderQueenSprite == null) blackRiderQueenSprite = GetPieceSprite("Black/RiderQueen");
            return blackRiderQueenSprite != null ? blackRiderQueenSprite : blackQueenSprite;
        }

        /// <summary>
        /// Sprite de la Reina Vampira para el equipo indicado. El lote solo trae
        /// el arte blanco: el lado negro se hornea una vez con el tinte del bando
        /// (mismo criterio que las esculturas de la velada). Si falta todo, cae
        /// a la Dama clásica.
        /// </summary>
        public Sprite GetVampireQueenSprite(TeamColor team)
        {
            if (whiteVampireQueenSprite == null)
                whiteVampireQueenSprite = GetPieceSprite("White/VampireQueen");
            if (whiteVampireQueenSprite != null)
                _variantArtSprites.Add(whiteVampireQueenSprite);

            if (team == TeamColor.White)
                return whiteVampireQueenSprite != null ? whiteVampireQueenSprite : whiteQueenSprite;

            if (blackVampireQueenSprite == null)
            {
                blackVampireQueenSprite = GetPieceSprite("Black/VampireQueen");
                if (blackVampireQueenSprite == null && whiteVampireQueenSprite != null)
                    blackVampireQueenSprite = BakeTeamTint(whiteVampireQueenSprite, HalloweenArt.BlackTeamTint);
            }

            // También se registra cuando el PNG negro ya venía cargado en LoadSprites:
            // las skins de arte nunca deben pisar el arte propio de la variante.
            if (blackVampireQueenSprite != null)
                _variantArtSprites.Add(blackVampireQueenSprite);

            return blackVampireQueenSprite != null ? blackVampireQueenSprite : blackQueenSprite;
        }

        /// <summary>
        /// Sprite de la Torre Fragua (variante de la Vía real, nivel 30) para el
        /// equipo indicado. Si el arte propio aún no existe, cae al sprite de la
        /// Torre clásica.
        /// </summary>
        public Sprite GetFraguaRookSprite(TeamColor team)
        {
            if (team == TeamColor.White)
            {
                if (whiteFraguaRookSprite == null) whiteFraguaRookSprite = GetPieceSprite("White/FraguaRook");
                if (whiteFraguaRookSprite != null) _variantArtSprites.Add(whiteFraguaRookSprite);
                return whiteFraguaRookSprite != null ? whiteFraguaRookSprite : whiteRookSprite;
            }

            if (blackFraguaRookSprite == null) blackFraguaRookSprite = GetPieceSprite("Black/FraguaRook");
            if (blackFraguaRookSprite != null) _variantArtSprites.Add(blackFraguaRookSprite);
            return blackFraguaRookSprite != null ? blackFraguaRookSprite : blackRookSprite;
        }

        /// <summary>
        /// Sprite base (sin skin) de una pieza lógica: clásico o arte de su variante.
        /// Es la única puerta que decide el arte por tipo, así el spawn, el Undo y el
        /// cambio de bando pintan siempre lo mismo.
        /// </summary>
        private Sprite BaseSpriteForPiece(ChessPiece piece)
        {
            if (piece == null) return null;

            if (piece is WilderGambit.Pieces.LancerPawn)
                return GetLancerPawnSprite(piece.Team);
            if (piece is WilderGambit.Pieces.RiderQueen)
                return GetRiderQueenSprite(piece.Team);
            if (piece is WilderGambit.Pieces.VampireQueen)
                return GetVampireQueenSprite(piece.Team);
            if (piece is WilderGambit.Pieces.FraguaRook)
                return GetFraguaRookSprite(piece.Team);
            if (piece is WilderGambit.Pieces.SpectralPawn)
                return (piece.Team == TeamColor.White) ? whiteSpectralPawnSprite : blackSpectralPawnSprite;
            if (piece is WilderGambit.Pieces.PumpkinPawn)
                return GetPumpkinPawnSprite(piece.Team);
            if (piece is WilderGambit.Pieces.GhostKnight)
                return GetGhostKnightSprite(piece.Team);

            // Nigromante y clásicas: el tipo lógico ya resuelve su sprite.
            return GetPieceSprite(piece.Type, piece.Team);
        }

        // ─── Esculturas de la velada (tienda de Dulces) ────────────────────────
        //
        // El lote hwp_* vive en Resources/Pieces/Halloween y se resuelve con la
        // misma tubería que las piezas (disco primero, recorte de padding incluido).
        // El lado negro usa hwp_*_black cuando exista; mientras no esté, se hornea
        // una copia apagada del arte base (una sola vez por pieza) para que los
        // bandos sigan distinguiéndose sin depender del color del renderer — así
        // el tinte de las skins y el color de los overlays no se pisan.

        private readonly Dictionary<string, Sprite> _hwArtCache = new Dictionary<string, Sprite>();
        private readonly HashSet<string> _hwArtMiss = new HashSet<string>();

        /// <summary>Arte de variante ya resuelto: sirve para no pisarlo con skins de arte.</summary>
        private readonly HashSet<Sprite> _variantArtSprites = new HashSet<Sprite>();

        public Sprite GetPumpkinPawnSprite(TeamColor team) =>
            HalloweenVariantSprite(HalloweenArt.PawnPumpkinArt, team, whitePawnSprite, blackPawnSprite);

        public Sprite GetGhostKnightSprite(TeamColor team) =>
            HalloweenVariantSprite(HalloweenArt.KnightGhostArt, team, whiteKnightSprite, blackKnightSprite);

        /// <summary>Arte de la escultura para el bando, o el clásico si el PNG todavía no está.</summary>
        private Sprite HalloweenVariantSprite(string artName, TeamColor team, Sprite whiteFallback, Sprite blackFallback)
        {
            Sprite art = HalloweenArtForTeam(artName, team);
            if (art != null)
            {
                // Solo el arte de variante entra aquí: es el que las skins no deben pisar.
                _variantArtSprites.Add(art);
                return art;
            }
            return team == TeamColor.White ? whiteFallback : blackFallback;
        }

        /// <summary>¿El sprite es arte de una variante? (las skins de arte no lo pisan)</summary>
        private bool IsVariantArtSprite(Sprite sprite) => sprite != null && _variantArtSprites.Contains(sprite);

        private Sprite HalloweenArtForTeam(string artName, TeamColor team)
        {
            if (string.IsNullOrEmpty(artName)) return null;

            if (team == TeamColor.Black)
            {
                Sprite blackArt = LoadHalloweenArt(HalloweenArt.PiecePath(artName, true));
                if (blackArt != null) return blackArt;

                string basePath = HalloweenArt.PiecePath(artName, false);
                Sprite baseArt = LoadHalloweenArt(basePath);
                return baseArt != null ? BakedBlackSide(baseArt, basePath) : null;
            }

            return LoadHalloweenArt(HalloweenArt.PiecePath(artName, false));
        }

        /// <summary>Carga (con caché) una ruta del lote; null si el PNG no está.</summary>
        private Sprite LoadHalloweenArt(string resourcePath)
        {
            if (string.IsNullOrEmpty(resourcePath)) return null;
            if (_hwArtCache.TryGetValue(resourcePath, out Sprite cached)) return cached;
            if (_hwArtMiss.Contains(resourcePath)) return null;

            Sprite art = GetPieceSprite(resourcePath);
            if (art != null)
            {
                _hwArtCache[resourcePath] = art;
            }
            else
            {
                _hwArtMiss.Add(resourcePath);
                Debug.LogWarning($"[BoardView] Sin arte en Resources/Pieces/{resourcePath}.png: " +
                                 "la escultura cae al sprite clásico de la pieza.");
            }
            return art;
        }

        /// <summary>
        /// Versión del lado negro cuando no hay arte <c>_black</c>: copia apagada del
        /// arte base (se hornea una sola vez y queda cacheada).
        /// </summary>
        private Sprite BakedBlackSide(Sprite baseArt, string basePath)
        {
            string key = basePath + "|blackside";
            if (_hwArtCache.TryGetValue(key, out Sprite cached)) return cached;

            Sprite baked = BakeTeamTint(baseArt, HalloweenArt.BlackTeamTint) ?? baseArt;
            _hwArtCache[key] = baked;
            return baked;
        }

        /// <summary>Multiplica los píxeles del arte por el tinte (conserva el alfa).</summary>
        private static Sprite BakeTeamTint(Sprite source, Color tint)
        {
            if (source == null || source.texture == null) return source;
            try
            {
                Texture2D tex = source.texture;
                Color32[] pixels = tex.GetPixels32();
                for (int i = 0; i < pixels.Length; i++)
                {
                    if (pixels[i].a == 0) continue;
                    pixels[i] = new Color32(
                        (byte)(pixels[i].r * tint.r),
                        (byte)(pixels[i].g * tint.g),
                        (byte)(pixels[i].b * tint.b),
                        pixels[i].a);
                }

                var copy = new Texture2D(tex.width, tex.height, TextureFormat.RGBA32, false)
                {
                    filterMode = tex.filterMode,
                    anisoLevel = tex.anisoLevel,
                };
                copy.SetPixels32(pixels);
                copy.Apply();

                var sprite = Sprite.Create(copy, source.rect,
                    new Vector2(source.rect.width > 0 ? source.pivot.x / source.rect.width : 0.5f,
                                source.rect.height > 0 ? source.pivot.y / source.rect.height : 0.5f),
                    100f);
                sprite.name = source.name + "_black";
                return sprite;
            }
            catch
            {
                // Un arte no legible no rompe el tablero: queda el arte base.
                return source;
            }
        }

        /// <summary>
        /// Invoca visualmente un Peón Espectral en la posición dada (llamado por GameManager).
        /// </summary>
        public void SpawnSpectralPawn(TeamColor team, Vector2IntCustom pos)
        {
            Sprite sprite = (team == TeamColor.White) ? whiteSpectralPawnSprite : blackSpectralPawnSprite;
            // Fallback al sprite de peón normal si no cargó el espectral
            if (sprite == null)
                sprite = (team == TeamColor.White) ? whitePawnSprite : blackPawnSprite;

            SpawnPiece<WilderGambit.Pieces.SpectralPawn>(team, sprite, pos.Row, pos.Col);
        }

        /// <summary>Reproduce la animación de Jaque en la posición del Rey.</summary>
        public void PlayKingCheckAnimation(Vector2IntCustom kingPos)
        {
            if (kingCheckFrames != null && kingCheckFrames.Length > 0)
            {
                StartCoroutine(AnimateKingCheck(kingPos));
            }
        }

        private System.Collections.IEnumerator AnimateKingCheck(Vector2IntCustom kingPos)
        {
            if (!pieceViews.TryGetValue(kingPos, out GameObject kingObj)) yield break;
            if (kingObj == null) yield break;

            SpriteRenderer sr = kingObj.GetComponent<SpriteRenderer>();
            if (sr == null) yield break;

            // Guardar estado original
            Sprite  originalSprite = sr.sprite;
            Vector3 originalScale  = kingObj.transform.localScale;
            float   frameRate      = 1f / 24f; // 24 FPS

            // Ocultar el Shadow (outline negro) para que no se vea a través
            // de los frames transparentes y convierta el rey blanco en negro
            Transform shadowTransform = kingObj.transform.Find("Shadow");
            if (shadowTransform != null)
                shadowTransform.gameObject.SetActive(false);

            // Escalar el frame al tileSize completo (los frames son 1280x720)
            float frameMaxDim = Mathf.Max(
                kingCheckFrames[0].bounds.size.x,
                kingCheckFrames[0].bounds.size.y);
            float   targetScale = frameMaxDim > 0 ? tileSize / frameMaxDim : originalScale.x;
            Vector3 animScale   = new Vector3(targetScale, targetScale, 1f);

            foreach (Sprite frame in kingCheckFrames)
            {
                if (kingObj == null || sr == null) yield break;

                if (frame != null)
                {
                    sr.sprite = frame;
                    kingObj.transform.localScale = animScale;
                }

                yield return new WaitForSeconds(frameRate);
            }

            // Restaurar sprite, escala y Shadow originales del Rey
            if (kingObj != null && sr != null)
            {
                sr.sprite = originalSprite;
                kingObj.transform.localScale = originalScale;

                if (shadowTransform != null)
                    shadowTransform.gameObject.SetActive(true);
            }
        }

        /// <summary>¿La skin equipada del Rey es Eclipse Eterno (full-art + frames)?</summary>
        public bool HasEclipseEternoEquipped =>
            PieceSkinManager.GetSelectedSkinId(PieceType.King) == "skin_king_eclipse";

        /// <summary>
        /// Dispara el pulso de movimiento sobre la vista que ya está viajando.
        /// Silencioso si faltan frames: el movimiento normal sigue igual.
        /// </summary>
        private void PlayEclipseMoveAnimation(GameObject movingObj, TeamColor team, int dir)
        {
            if (movingObj == null || eclipseMoveFrames == null || eclipseMoveFrames.Length == 0) return;

            var anim = movingObj.GetComponent<EclipseEternoAnimator>();
            if (anim == null) anim = movingObj.AddComponent<EclipseEternoAnimator>();
            anim.PlayMove(eclipseMoveFrames, ResolveSkinArt("skin_king_eclipse", team), tileSize, dir);
        }

        /// <summary>
        /// Disolución de jaque mate para el Rey con Eclipse Eterno. Devuelve true si
        /// la animación arrancó; el llamador decide cuándo enseñar el game-over.
        /// </summary>
        public bool PlayEclipseMateAnimation(Vector2IntCustom kingPos, System.Action onComplete)
        {
            if (!HasEclipseEternoEquipped) return false;
            if (eclipseMateFrames == null || eclipseMateFrames.Length == 0) return false;
            if (!pieceViews.TryGetValue(kingPos, out GameObject kingObj) || kingObj == null) return false;

            ChessPiece piece = board != null ? board.GetPieceAt(kingPos) : null;
            TeamColor team = piece != null ? piece.Team : TeamColor.White;

            var anim = kingObj.GetComponent<EclipseEternoAnimator>();
            if (anim == null) anim = kingObj.AddComponent<EclipseEternoAnimator>();
            anim.PlayMate(eclipseMateFrames, ResolveSkinArt("skin_king_eclipse", team), tileSize, onComplete);
            return true;
        }

        /// <summary>Transforma el Caballo Blanco al estado Fork con animación Idle de fuego continua.</summary>
        public void TriggerKnightForkTransformation(Vector2IntCustom pos)
        {
            if (pieceViews.TryGetValue(pos, out GameObject pieceObj))
            {
                KnightForkAnimator existingAnim = pieceObj.GetComponent<KnightForkAnimator>();
                if (existingAnim == null)
                {
                    existingAnim = pieceObj.AddComponent<KnightForkAnimator>();
                }
                existingAnim.Initialize(whiteKnightForkFrames, whiteKnightForkAttackFrames, whiteKnightForkStatic != null ? whiteKnightForkStatic : whiteKnightSprite, tileSize);
            }
        }

        /// <summary>Restaura el Caballo Blanco a su estado normal eliminando la transformación de Fork.</summary>
        public void RevertKnightForkTransformation(Vector2IntCustom pos)
        {
            if (pieceViews.TryGetValue(pos, out GameObject pieceObj))
            {
                KnightForkAnimator anim = pieceObj.GetComponent<KnightForkAnimator>();
                if (anim != null)
                {
                    anim.Revert(whiteKnightSprite, tileSize);
                    Destroy(anim);
                }
                else
                {
                    SpriteRenderer sr = pieceObj.GetComponent<SpriteRenderer>();
                    if (sr != null && whiteKnightSprite != null)
                    {
                        sr.sprite = whiteKnightSprite;
                    }
                    Transform shadowT = pieceObj.transform.Find("Shadow");
                    if (shadowT != null)
                        shadowT.gameObject.SetActive(true);
                }
            }
        }

        /// <summary>
        /// Reproduce la animación de ataque del Caballo transformado hacia la casilla objetivo.
        /// </summary>
        public void PlayKnightForkAttack(Vector2IntCustom from, Vector2IntCustom to, System.Action onComplete)
        {
            if (pieceViews.TryGetValue(from, out GameObject movingObj))
            {
                KnightForkAnimator anim = movingObj.GetComponent<KnightForkAnimator>();
                if (anim == null)
                {
                    anim = movingObj.AddComponent<KnightForkAnimator>();
                    anim.Initialize(whiteKnightForkFrames, whiteKnightForkAttackFrames, whiteKnightForkStatic, tileSize);
                }

                Vector3 targetWorldPos = GetWorldPosition(to.Row, to.Col);

                anim.PlayAttack(
                    targetWorldPos,
                    onPieceDestroyed: () =>
                    {
                        // Destruir la pieza capturada exactamente cuando impacta el cometa / implosión
                        if (pieceViews.TryGetValue(to, out GameObject capturedObj))
                        {
                            if (capturedObj != null)
                            {
                                RemoveStunMarker(capturedObj);
                                _stunBaseColors.Remove(capturedObj);
                            }
                            Destroy(capturedObj);
                            pieceViews.Remove(to);
                        }
                    },
                    onAnimationFinished: () =>
                    {
                        // Actualizar el diccionario de vistas
                        pieceViews.Remove(from);
                        pieceViews[to] = movingObj;
                        onComplete?.Invoke();
                    }
                );
            }
            else
            {
                MovePieceView(from, to);
                onComplete?.Invoke();
            }
        }



        /// <summary>Muestra resaltados de selección y movimientos/capturas válidas.</summary>
        public void ShowSelection(Vector2IntCustom selected, List<Vector2IntCustom> validMoves, Board board)
        {
            ClearOverlays();

            // Casilla seleccionada — highlight amarillo
            SetTileOverlay(selected.Row, selected.Col, selectedColor, null);

            // Casillas de movimiento o captura
            foreach (var move in validMoves)
            {
                ChessPiece target = board.GetPieceAt(move);
                if (target != null)
                {
                    // Captura: ring rojo grande sobre la pieza enemiga
                    SetTileOverlay(move.Row, move.Col, captureColor, captureRingSprite, isCapture: true);
                }
                else
                {
                    // Movimiento libre: dot verde centrado
                    SetTileOverlay(move.Row, move.Col, validMoveColor, validMoveDotSprite, isCapture: false);
                }
            }
        }

        /// <summary>
        /// Destello rojo sobre la casilla de una jugada rechazada (entrenamiento táctico: el
        /// movimiento no es la solución del puzzle). Se autodestruye y no ensucia los overlays.
        /// </summary>
        public void PlayInvalidMoveFlash(Vector2IntCustom pos)
        {
            GameObject overlay = new GameObject($"InvalidMove_{pos.Row}_{pos.Col}");
            overlay.transform.position = GetWorldPosition(pos.Row, pos.Col);

            SpriteRenderer sr = overlay.AddComponent<SpriteRenderer>();
            sr.sprite       = CreateSquareSprite();
            sr.color        = new Color(1f, 0.22f, 0.22f, 0.6f);
            sr.sortingOrder = 5; // Por encima de piezas y overlays de selección

            overlay.transform.localScale = new Vector3(tileSize, tileSize, 1f);
            Destroy(overlay, 0.45f);
        }

        /// <summary>Resalta una casilla disponible para la invocación del Peón Espectral.
        /// Usa un anillo esmeralda GRANDE y PULSANTE para diferenciarse claramente
        /// de los puntos verdes de movimiento normal.</summary>
        public void ShowResurrectionSquare(Vector2IntCustom pos)
        {
            Color resColor = new Color(0.2f, 1f, 0.5f, 0.95f);
            GameObject overlay = CreateSpriteOverlay(pos.Row, pos.Col, resColor, captureRingSprite,
                                                     tilePct: 0.85f, sortingOrder: 4);
            overlay.AddComponent<PulsingOverlay>().minScaleFactor = 0.75f;
            overlays.Add(overlay);
        }

        /// <summary>Muestra un aura pulsante flotante sobre el Nigromante para señalar
        /// a simple vista que el Alzamiento Menor está listo. Se limpia con ClearOverlays.</summary>
        public void ShowSoulReadyIndicator(ChessPiece piece)
        {
            if (piece == null) return;

            Color auraColor = new Color(0.4f, 1f, 0.6f, 0.9f);
            GameObject aura = CreateSpriteOverlay(piece.Position.Row, piece.Position.Col, auraColor,
                                                   captureRingSprite, tilePct: 0.60f, sortingOrder: 6);
            aura.transform.position += Vector3.up * (tileSize * 0.55f);
            aura.AddComponent<PulsingOverlay>().minScaleFactor = 0.7f;
            overlays.Add(aura);
        }

        /// <summary>Resalta una pieza elegible para la Sentencia de la Fragua:
        /// anillo ígneo pulsante (naranja) para distinguirlo del ring rojo de captura.
        /// Se limpia con ClearOverlays.</summary>
        public void ShowCondemnTarget(Vector2IntCustom pos)
        {
            Color condemnColor = new Color(1f, 0.45f, 0.05f, 0.95f);
            GameObject overlay = CreateSpriteOverlay(pos.Row, pos.Col, condemnColor, captureRingSprite,
                                                     tilePct: 0.85f, sortingOrder: 4);
            overlay.AddComponent<PulsingOverlay>().minScaleFactor = 0.75f;
            overlays.Add(overlay);
        }

        /// <summary>Aura ígnea pulsante sobre la Torre Fragua en modo Sentencia
        /// (equivalente al aura del Nigromante). Se limpia con ClearOverlays.</summary>
        public void ShowCondemnReadyIndicator(ChessPiece piece)
        {
            if (piece == null) return;

            Color auraColor = new Color(1f, 0.55f, 0.1f, 0.9f);
            GameObject aura = CreateSpriteOverlay(piece.Position.Row, piece.Position.Col, auraColor,
                                                   captureRingSprite, tilePct: 0.60f, sortingOrder: 6);
            aura.transform.position += Vector3.up * (tileSize * 0.55f);
            aura.AddComponent<PulsingOverlay>().minScaleFactor = 0.7f;
            overlays.Add(aura);
        }

        // ─── Caballo Fantasma: overlays de Salto de Niebla y Posesión ────────

        /// <summary>Casilla de salida del Salto de Niebla: anillo espectral pulsante.</summary>
        public void ShowMistStepSquare(Vector2IntCustom pos)
        {
            Color mistColor = new Color(0.55f, 0.75f, 1f, 0.95f);
            GameObject overlay = CreateSpriteOverlay(pos.Row, pos.Col, mistColor, captureRingSprite,
                                                     tilePct: 0.82f, sortingOrder: 4);
            overlay.AddComponent<PulsingOverlay>().minScaleFactor = 0.72f;
            overlays.Add(overlay);
        }

        /// <summary>Aura espectral sobre el Caballo Fantasma cuando el salto está listo.</summary>
        public void ShowMistReadyIndicator(ChessPiece piece)
        {
            if (piece == null) return;

            Color auraColor = new Color(0.55f, 0.8f, 1f, 0.9f);
            GameObject aura = CreateSpriteOverlay(piece.Position.Row, piece.Position.Col, auraColor,
                                                   captureRingSprite, tilePct: 0.62f, sortingOrder: 6);
            aura.transform.position += Vector3.up * (tileSize * 0.55f);
            aura.AddComponent<PulsingOverlay>().minScaleFactor = 0.7f;
            overlays.Add(aura);
        }

        /// <summary>Peón aliado elegible para la Posesión: anillo violeta pulsante.</summary>
        public void ShowPossessionTarget(Vector2IntCustom pos)
        {
            Color possColor = new Color(0.85f, 0.4f, 1f, 0.95f);
            GameObject overlay = CreateSpriteOverlay(pos.Row, pos.Col, possColor, captureRingSprite,
                                                     tilePct: 0.82f, sortingOrder: 4);
            overlay.AddComponent<PulsingOverlay>().minScaleFactor = 0.72f;
            overlays.Add(overlay);
        }

        /// <summary>Aura violeta sobre el Caballo Fantasma en modo Posesión.</summary>
        public void ShowPossessionReadyIndicator(ChessPiece piece)
        {
            if (piece == null) return;

            Color auraColor = new Color(0.85f, 0.45f, 1f, 0.9f);
            GameObject aura = CreateSpriteOverlay(piece.Position.Row, piece.Position.Col, auraColor,
                                                   captureRingSprite, tilePct: 0.62f, sortingOrder: 6);
            aura.transform.position += Vector3.up * (tileSize * 0.55f);
            aura.AddComponent<PulsingOverlay>().minScaleFactor = 0.7f;
            overlays.Add(aura);
        }

        /// <summary>
        /// NUEVO: Indicadores persistentes del Nigromante — aura siempre visible + contador de almas.
        /// Se actualiza cada turno y no se limpia con ClearOverlays.
        /// </summary>
        public void RefreshNecromancerIndicators(Board board)
        {
            // Limpiar anteriores
            foreach (var go in necromancerIndicators) if (go != null) Destroy(go);
            necromancerIndicators.Clear();

            if (board == null) return;

            for (int r = 0; r < Board.BOARD_SIZE; r++)
            {
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    var piece = board.GetPieceAt(new Vector2IntCustom(r, c)) as WilderGambit.Pieces.NecromancerBishop;
                    if (piece == null) continue;

                    int cur = piece.SoulCharges;
                    int max = piece.MaxCharges;
                    bool ready = piece.CanResurrect;
                    bool almost = piece.IsAlmostReady;

                    // ¿Acaba de volverse listo? Toast
                    if (_lastSoulByPiece.TryGetValue(piece, out int prev) && prev < max && cur >= max)
                    {
                        ShowNecromancerToast(piece, "¡Nigromante listo! 4/4 almas");
                    }
                    _lastSoulByPiece[piece] = cur;

                    // Aura persistente solo si listo o casi listo
                    if (ready || almost)
                    {
                        Color auraCol = ready ? new Color(0.15f, 1f, 0.55f, 0.95f) : new Color(1f, 0.85f, 0.2f, 0.85f);
                        float tilePct = ready ? 1.05f : 0.85f;
                        GameObject aura = CreateSpriteOverlay(r, c, auraCol, captureRingSprite, tilePct: tilePct, sortingOrder: 2);
                        aura.name = $"NecroAura_{r}_{c}";
                        var pulse = aura.AddComponent<PulsingOverlay>();
                        pulse.pulseSpeed = ready ? 4.5f : 2.5f;
                        pulse.minScaleFactor = ready ? 0.72f : 0.82f;
                        // Oscurecer casilla base levemente para resaltar
                        necromancerIndicators.Add(aura);
                    }

                    // Contador flotante 3/4, 4/4 etc. — siempre visible
                    GameObject counter = new GameObject($"SoulCounter_{r}_{c}");
                    counter.transform.position = GetWorldPosition(r, c) + new Vector3(0f, tileSize * 0.42f, 0f);
                    var tm = counter.AddComponent<TextMesh>();
                    tm.text = ready ? "4/4 ¡Listo!" : $"{cur}/{max}";
                    tm.fontSize = ready ? 28 : 22;
                    tm.characterSize = 0.11f;
                    tm.anchor = TextAnchor.MiddleCenter;
                    tm.alignment = TextAlignment.Center;
                    tm.color = ready ? new Color(0.2f, 1f, 0.6f) : (almost ? new Color(1f, 0.9f, 0.3f) : new Color(0.75f, 0.85f, 0.95f));
                    tm.fontStyle = ready ? FontStyle.Bold : FontStyle.Normal;
                    // Sombra para legibilidad
                    var bg = new GameObject("CounterBG");
                    bg.transform.SetParent(counter.transform);
                    bg.transform.localPosition = new Vector3(0f, 0f, 0.01f);
                    var bgSr = bg.AddComponent<SpriteRenderer>();
                    bgSr.sprite = CreateSquareSprite();
                    bgSr.color = ready ? new Color(0f, 0.18f, 0.1f, 0.82f) : new Color(0f, 0f, 0f, 0.55f);
                    bgSr.sortingOrder = tm.GetComponent<Renderer>().sortingOrder - 1;
                    bg.transform.localScale = new Vector3(tileSize * 0.55f, tileSize * 0.18f, 1f);
                    // Pequeño pulso si listo
                    if (ready)
                    {
                        counter.AddComponent<PulsingOverlay>().pulseSpeed = 3f;
                    }
                    necromancerIndicators.Add(counter);
                }
            }
        }

        private void ShowNecromancerToast(ChessPiece piece, string msg)
        {
            GameObject toast = new GameObject("NecroToast");
            toast.transform.position = GetWorldPosition(piece.Position.Row, piece.Position.Col) + new Vector3(0f, tileSize * 0.85f, 0f);
            var tm = toast.AddComponent<TextMesh>();
            tm.text = msg;
            tm.fontSize = 26;
            tm.characterSize = 0.11f;
            tm.anchor = TextAnchor.MiddleCenter;
            tm.color = new Color(0.2f, 1f, 0.65f);
            tm.fontStyle = FontStyle.Bold;
            necromancerIndicators.Add(toast);
            // Auto-destruir en 2.2s con fade
            var fade = toast.AddComponent<ToastFade>();
            fade.duration = 2.2f;
        }

        /// <summary>
        /// Toast independiente de la Fragua (Sentencia, Tributo, quema…): NO entra en la
        /// lista del Nigromante, así que sobrevive a RefreshNecromancerIndicators y se
        /// autodestruye solo con un fade tipo ToastFade.
        /// </summary>
        public void ShowFraguaToast(Vector2IntCustom pos, string msg)
        {
            GameObject toast = new GameObject("FraguaToast");
            toast.transform.position = GetWorldPosition(pos.Row, pos.Col) + new Vector3(0f, tileSize * 0.9f, 0f);
            var tm = toast.AddComponent<TextMesh>();
            tm.text = msg;
            tm.fontSize = 24;
            tm.characterSize = 0.11f;
            tm.anchor = TextAnchor.MiddleCenter;
            tm.alignment = TextAlignment.Center;
            tm.color = new Color(1f, 0.62f, 0.15f);
            tm.fontStyle = FontStyle.Bold;
            var fade = toast.AddComponent<ToastFade>();
            fade.duration = 2.6f;
        }

        /// <summary>
        /// Toast independiente de la Reina Vampira (renacimiento / fila llena).
        /// No entra en la lista del Nigromante: se autodestruye con fade.
        /// </summary>
        public void ShowVampireToast(Vector2IntCustom pos, string msg)
        {
            GameObject toast = new GameObject("VampireToast");
            toast.transform.position = GetWorldPosition(pos.Row, pos.Col) + new Vector3(0f, tileSize * 0.9f, 0f);
            var tm = toast.AddComponent<TextMesh>();
            tm.text = msg;
            tm.fontSize = 24;
            tm.characterSize = 0.11f;
            tm.anchor = TextAnchor.MiddleCenter;
            tm.alignment = TextAlignment.Center;
            tm.color = new Color(0.95f, 0.35f, 0.75f);
            tm.fontStyle = FontStyle.Bold;
            var fade = toast.AddComponent<ToastFade>();
            fade.duration = 2.8f;
        }

        /// <summary>Toast espectral del Caballo Fantasma (Salto de Niebla / Posesión).</summary>
        public void ShowGhostToast(Vector2IntCustom pos, string msg)
        {
            GameObject toast = new GameObject("GhostToast");
            toast.transform.position = GetWorldPosition(pos.Row, pos.Col) + new Vector3(0f, tileSize * 0.9f, 0f);
            var tm = toast.AddComponent<TextMesh>();
            tm.text = msg;
            tm.fontSize = 24;
            tm.characterSize = 0.11f;
            tm.anchor = TextAnchor.MiddleCenter;
            tm.alignment = TextAlignment.Center;
            tm.color = new Color(0.6f, 0.85f, 1f);
            tm.fontStyle = FontStyle.Bold;
            var fade = toast.AddComponent<ToastFade>();
            fade.duration = 2.6f;
        }

        /// <summary>Toast naranja de la Explosión de Calabaza.</summary>
        public void ShowPumpkinToast(Vector2IntCustom pos, string msg)
        {
            GameObject toast = new GameObject("PumpkinToast");
            toast.transform.position = GetWorldPosition(pos.Row, pos.Col) + new Vector3(0f, tileSize * 0.9f, 0f);
            var tm = toast.AddComponent<TextMesh>();
            tm.text = msg;
            tm.fontSize = 24;
            tm.characterSize = 0.11f;
            tm.anchor = TextAnchor.MiddleCenter;
            tm.alignment = TextAlignment.Center;
            tm.color = new Color(1f, 0.55f, 0.12f);
            tm.fontStyle = FontStyle.Bold;
            var fade = toast.AddComponent<ToastFade>();
            fade.duration = 2.8f;
        }

        /// <summary>
        /// Explosión de Calabaza: anillo naranja que se expande y se desvanece sobre
        /// la casilla del capturador. Puramente cosmético.
        /// </summary>
        public void PlayPumpkinExplosion(Vector2IntCustom pos)
        {
            GameObject fx = new GameObject($"PumpkinExplosion_{pos.Row}_{pos.Col}");
            fx.transform.position = GetWorldPosition(pos.Row, pos.Col);

            SpriteRenderer sr = fx.AddComponent<SpriteRenderer>();
            sr.sprite = captureRingSprite != null ? captureRingSprite : CreateSquareSprite();
            sr.color = new Color(1f, 0.55f, 0.1f, 0.95f);
            sr.sortingOrder = 8;

            float spriteWidth = sr.sprite.bounds.size.x;
            float baseScale = spriteWidth > 0 ? (tileSize * 0.55f) / spriteWidth : 1f;
            fx.transform.localScale = new Vector3(baseScale, baseScale, 1f);

            var anim = fx.AddComponent<PumpkinExplosionFx>();
            anim.duration = 0.55f;
            anim.maxScale = 2.4f;
            anim.startColor = sr.color;
        }

        /// <summary>Elimina la vista de una pieza en una casilla (usado para desvanecimiento espectral).</summary>
        public void RemovePieceView(Vector2IntCustom pos)
        {
            if (pieceViews.TryGetValue(pos, out GameObject go))
            {
                if (go != null)
                {
                    RemoveStunMarker(go);
                    _stunBaseColors.Remove(go);
                }
                Destroy(go);
                pieceViews.Remove(pos);
            }
        }

        /// <summary>
        /// Saca la vista de una casilla SIN destruirla. La usa la Reina Vampira
        /// capturada: su GameObject se oculta y se vuelve a enganchar si renace
        /// (AttachPieceView). Si no hay vista, devuelve null.
        /// </summary>
        public GameObject DetachPieceView(Vector2IntCustom pos)
        {
            if (!pieceViews.TryGetValue(pos, out GameObject go)) return null;
            pieceViews.Remove(pos);
            if (go != null)
            {
                // El marcador es un objeto de mundo: no debe quedarse flotando.
                RemoveStunMarker(go);
                _stunBaseColors.Remove(go);
                go.SetActive(false);
            }
            return go;
        }

        /// <summary>Registra, recoloca y muestra una vista separada en su casilla de renacimiento.</summary>
        public void AttachPieceView(Vector2IntCustom pos, GameObject go)
        {
            if (go == null) return;
            go.transform.SetParent(transform);
            go.transform.position = GetWorldPosition(pos.Row, pos.Col);
            go.SetActive(true);
            pieceViews[pos] = go;

            // Si renació aturdida, recuperar su tinte y marcador.
            ChessPiece piece = go.GetComponent<ChessPiece>();
            if (piece != null && piece.IsStunned) SetPieceStunned(pos, true);
        }

        /// <summary>Destruye una vista separada que ya no vuelve al tablero.</summary>
        public void DiscardDetachedPieceView(GameObject go)
        {
            if (go != null)
            {
                RemoveStunMarker(go);
                _stunBaseColors.Remove(go);
                Destroy(go);
            }
        }

        /// <summary>
        /// Repinta la vista existente de una pieza tras cambiar su bando (Tributo de la
        /// Torre Fragua): sprite del equipo nuevo + sombra + skin equipada. RebuildFromBoard
        /// no sirve aquí porque la pieza no cambia de casilla y conserva su vista previa.
        /// </summary>
        public void RefreshPieceViewTeam(ChessPiece piece)
        {
            if (piece == null) return;
            if (!pieceViews.TryGetValue(piece.Position, out GameObject go) || go == null) return;

            Sprite sprite = BaseSpriteForPiece(piece);
            if (sprite == null) return;

            SpriteRenderer sr = go.GetComponent<SpriteRenderer>();
            if (sr != null) sr.sprite = sprite;

            Transform shadowT = go.transform.Find("Shadow");
            if (shadowT != null)
            {
                var shadowSr = shadowT.GetComponent<SpriteRenderer>();
                if (shadowSr != null) shadowSr.sprite = sprite;
            }

            // Reescalar como en el spawn: el arte de cada equipo puede medir distinto
            float targetHeight = tileSize * 0.82f;
            float scale = sprite.bounds.size.y > 0 ? targetHeight / sprite.bounds.size.y : 1f;
            if (IsLancerArt(sprite)) scale *= LANCER_BODY_SCALE;
            go.transform.localScale = new Vector3(scale, scale, 1f);

            ApplyEquippedSkin(go, piece.Type, piece.Team);

            // Si estaba aturdida, el tinte/marcador debe sobrevivir al cambio de bando.
            if (piece.IsStunned) SetPieceStunned(piece.Position, true);
        }

        // ─── Explosión de Calabaza: tinte y marcador de aturdimiento ─────────

        /// <summary>
        /// Aplica o retira el aspecto de aturdimiento de una pieza: tinte azul-gris y
        /// un marcador «STUN» en espacio de mundo sobre su casilla.
        /// </summary>
        public void SetPieceStunned(Vector2IntCustom pos, bool stunned)
        {
            if (!pieceViews.TryGetValue(pos, out GameObject go) || go == null) return;
            SpriteRenderer sr = go.GetComponent<SpriteRenderer>();
            if (sr == null) return;

            if (stunned)
            {
                if (!_stunBaseColors.ContainsKey(go)) _stunBaseColors[go] = sr.color;
                sr.color = new Color(0.55f, 0.62f, 0.88f, 1f);

                if (!_stunMarkers.TryGetValue(go, out GameObject marker) || marker == null)
                {
                    marker = new GameObject("StunMarker");
                    var tm = marker.AddComponent<TextMesh>();
                    tm.text = "STUN";
                    tm.fontSize = 26;
                    tm.characterSize = 0.11f;
                    tm.anchor = TextAnchor.MiddleCenter;
                    tm.alignment = TextAlignment.Center;
                    tm.color = new Color(1f, 0.85f, 0.2f);
                    tm.fontStyle = FontStyle.Bold;
                    var renderer = marker.GetComponent<Renderer>();
                    if (renderer != null) renderer.sortingOrder = 10;
                    _stunMarkers[go] = marker;
                }

                marker.transform.position = GetWorldPosition(pos.Row, pos.Col) +
                                            new Vector3(0f, tileSize * 0.62f, 0f);
            }
            else
            {
                if (_stunBaseColors.TryGetValue(go, out Color baseColor))
                {
                    sr.color = baseColor;
                    _stunBaseColors.Remove(go);
                }
                RemoveStunMarker(go);
            }
        }

        /// <summary>Destruye el marcador «STUN» asociado a una vista (si existe).</summary>
        private void RemoveStunMarker(GameObject go)
        {
            if (go == null) return;
            if (_stunMarkers.TryGetValue(go, out GameObject marker))
            {
                if (marker != null) Destroy(marker);
                _stunMarkers.Remove(go);
            }
        }

        /// <summary>Recoloca el marcador de una pieza que cambió de casilla (Posesión).</summary>
        private void RepositionStunMarker(GameObject go, Vector2IntCustom pos)
        {
            if (go == null) return;
            if (_stunMarkers.TryGetValue(go, out GameObject marker) && marker != null)
                marker.transform.position = GetWorldPosition(pos.Row, pos.Col) +
                                            new Vector3(0f, tileSize * 0.62f, 0f);
        }

        /// <summary>Destruye marcadores y tintes de aturdimiento al reconstruir el tablero.</summary>
        private void ClearStunVisuals()
        {
            foreach (var kv in _stunMarkers)
                if (kv.Value != null) Destroy(kv.Value);
            _stunMarkers.Clear();
            _stunBaseColors.Clear();
        }

        /// <summary>
        /// Reaplica el aspecto de aturdimiento a todas las piezas del tablero. Se usa
        /// tras reconstruir (Undo) para que el estado lógico y el visual coincidan.
        /// </summary>
        public void RefreshStunIndicators(Board board)
        {
            // Restaurar tintes previos antes de limpiar los marcadores.
            foreach (var kv in _stunBaseColors)
            {
                if (kv.Key == null) continue;
                var sr = kv.Key.GetComponent<SpriteRenderer>();
                if (sr != null) sr.color = kv.Value;
            }
            _stunBaseColors.Clear();

            foreach (var kv in _stunMarkers)
                if (kv.Value != null) Destroy(kv.Value);
            _stunMarkers.Clear();

            if (board == null) return;

            for (int r = 0; r < Board.BOARD_SIZE; r++)
                for (int c = 0; c < Board.BOARD_SIZE; c++)
                {
                    ChessPiece piece = board.GetPieceAt(new Vector2IntCustom(r, c));
                    if (piece != null && piece.IsStunned)
                        SetPieceStunned(new Vector2IntCustom(r, c), true);
                }
        }

        /// <summary>Limpia solo los indicadores persistentes del nigromante.</summary>
        public void ClearNecromancerIndicators()
        {
            foreach (var go in necromancerIndicators) if (go != null) Destroy(go);
            necromancerIndicators.Clear();
            _lastSoulByPiece.Clear();
        }

        /// <summary>Limpia todos los overlays de selección y movimientos.</summary>
        public void ClearOverlays()
        {
            foreach (var o in overlays) Destroy(o);
            overlays.Clear();
        }

        // ─── Helpers internos ──────────────────────────────────────────────────

        private void SetTileOverlay(int row, int col, Color color, Sprite icon, bool isCapture = false)
        {
            GameObject overlay = new GameObject($"Overlay_{row}_{col}");
            overlay.transform.position = GetWorldPosition(row, col);

            if (icon != null)
            {
                SpriteRenderer sr = overlay.AddComponent<SpriteRenderer>();
                sr.sprite       = icon;
                sr.color        = color;
                // Capture ring: sortingOrder 4 (por encima de piezas) | dot: 3
                sr.sortingOrder = isCapture ? 4 : 3;

                float spriteWidth = icon.bounds.size.x;
                if (spriteWidth > 0)
                {
                    // Dot: 50% de la casilla · Capture ring: 95% (casi toda la casilla)
                    float pct   = isCapture ? 0.95f : 0.50f;
                    float scale = (tileSize * pct) / spriteWidth;
                    overlay.transform.localScale = new Vector3(scale, scale, 1f);
                }
            }
            else
            {
                // Highlight de selección: cuadro semitransparente usando localScale
                SpriteRenderer sr = overlay.AddComponent<SpriteRenderer>();
                sr.sprite       = CreateSquareSprite();
                sr.color        = color;
                sr.sortingOrder = 1;
                overlay.transform.localScale = new Vector3(tileSize, tileSize, 1f);
            }

            overlays.Add(overlay);
        }

        public Vector3 GetWorldPosition(int row, int col)
        {
            float x = col * tileSize - (Board.BOARD_SIZE * tileSize) / 2f + tileSize / 2f;
            float y = row * tileSize - (Board.BOARD_SIZE * tileSize) / 2f + tileSize / 2f;
            return new Vector3(x, y, 0f);
        }

        /// <summary>Crea un overlay de sprite con escala relativa al tamaño de casilla.
        /// Reutilizado por los resaltados de movimiento, captura y resurrección.</summary>
        private GameObject CreateSpriteOverlay(int row, int col, Color color, Sprite icon,
                                               float tilePct, int sortingOrder)
        {
            GameObject overlay = new GameObject($"Overlay_{row}_{col}");
            overlay.transform.position = GetWorldPosition(row, col);

            SpriteRenderer sr = overlay.AddComponent<SpriteRenderer>();
            sr.sprite       = icon;
            sr.color        = color;
            sr.sortingOrder = sortingOrder;

            float spriteWidth = icon.bounds.size.x;
            if (spriteWidth > 0)
                overlay.transform.localScale = new Vector3((tileSize * tilePct) / spriteWidth,
                                                           (tileSize * tilePct) / spriteWidth, 1f);
            return overlay;
        }

        /// <summary>
        /// Loads the selected board background and renders it as a sprite
        /// behind the chess tiles, scaled to fill the camera view.
        /// Also applies the theme's tile colors.
        /// </summary>
        private void ApplyBoardBackground()
        {
            // Apply theme tile colors from the manager
            int idx = BoardBackgroundManager.SelectedIndex;
            lightTileColor = BoardBackgroundManager.SelectedLightColor;
            darkTileColor = BoardBackgroundManager.SelectedDarkColor;
            Debug.Log($"[BoardView] Background idx={idx} light={lightTileColor} dark={darkTileColor}");

            // Tablero decorado v2 (Luna Llena / Luna de Sangre): objeto 8x8 pintado
            // que reemplaza el patron plano de las casillas. Capas: ambiente (-2),
            // arte decorado (-1), casillas (0), sombras (1), piezas (2), overlays (3+).
            Texture2D artTex = BoardBackgroundManager.LoadBoardArtForIndex(idx);
            _decoratedBoardArt = artTex != null;
            if (_decoratedBoardArt)
            {
                // Reaplicable sin duplicar capas.
                if (decoratedBoardRenderer != null)
                {
                    Destroy(decoratedBoardRenderer.gameObject);
                    decoratedBoardRenderer = null;
                }

                // Las casillas siguen existiendo (colliders e indicadores) pero ya
                // no pintan color: el patron visible es el arte.
                lightTileColor.a = 0f;
                darkTileColor.a = 0f;

                GameObject artObj = new GameObject("DecoratedBoardArt");
                artObj.transform.SetParent(transform);
                artObj.transform.localPosition = Vector3.zero;

                decoratedBoardRenderer = artObj.AddComponent<SpriteRenderer>();
                decoratedBoardRenderer.sortingOrder = -1; // Encima del ambiente, debajo del resto

                Sprite artSprite = Sprite.Create(
                    artTex,
                    new Rect(0, 0, artTex.width, artTex.height),
                    new Vector2(0.5f, 0.5f),
                    100f
                );
                decoratedBoardRenderer.sprite = artSprite;

                // La grilla pintada ocupa BoardArtInnerFraction del lienzo: escalar
                // el objeto para que mida exactamente el tablero jugable (8 * tileSize).
                float artWorld = (Board.BOARD_SIZE * tileSize) / BoardBackgroundManager.BoardArtInnerFraction;
                float artScale = artWorld / (artTex.width / 100f);
                artObj.transform.localScale = new Vector3(artScale, artScale, 1f);
            }

            // Load background texture
            Texture2D bgTex = BoardBackgroundManager.LoadSelectedTexture();

            if (bgTex != null)
            {
                // Create the background GameObject
                GameObject bgObj = new GameObject("BoardBackground");
                bgObj.transform.SetParent(transform);
                bgObj.transform.localPosition = Vector3.zero;
                bgObj.transform.localScale = Vector3.one;
                bgObj.transform.SetAsFirstSibling(); // Render behind everything

                backgroundRenderer = bgObj.AddComponent<SpriteRenderer>();
                backgroundRenderer.sortingOrder = -2; // Detras del arte decorado y de las casillas

                Sprite bgSprite = Sprite.Create(
                    bgTex,
                    new Rect(0, 0, bgTex.width, bgTex.height),
                    new Vector2(0.5f, 0.5f),
                    100f
                );
                backgroundRenderer.sprite = bgSprite;
            }

            // Con arte decorado la camara abre un poco (borde completo a la vista);
            // FitCameraToBoard vuelve a encuadrar y a escalar el fondo.
            if (_decoratedBoardArt)
                FitCameraToBoard();
            else if (bgTex != null)
                ScaleBackgroundToCamera();
        }

        /// <summary>El fondo cubre siempre la vista completa de la cámara (se reaplica al cambiar la proporción).</summary>
        private void ScaleBackgroundToCamera()
        {
            if (backgroundRenderer == null || backgroundRenderer.sprite == null) return;
            Texture2D bgTex = backgroundRenderer.sprite.texture;
            Transform bgObj = backgroundRenderer.transform;

            Camera cam = Camera.main;
            if (cam != null && cam.orthographic)
            {
                float screenHeight = cam.orthographicSize * 2f;
                float screenWidth = screenHeight * cam.aspect;
                float spriteAspect = (float)bgTex.width / bgTex.height;
                float screenAspect = screenWidth / screenHeight;

                float bgHeight, bgWidth;
                if (spriteAspect > screenAspect)
                {
                    // Sprite is wider than screen — fit by height
                    bgHeight = screenHeight;
                    bgWidth = bgHeight * spriteAspect;
                }
                else
                {
                    // Sprite is taller — fit by width
                    bgWidth = screenWidth;
                    bgHeight = bgWidth / spriteAspect;
                }

                // Apply world-unit scale (sprite created at 100 PPU)
                float worldPPU = 100f;
                bgObj.transform.localScale = new Vector3(
                    bgWidth / (bgTex.width / worldPPU),
                    bgHeight / (bgTex.height / worldPPU),
                    1f
                );
            }
        }

        private Sprite CreateSquareSprite()
        {
            Texture2D tex = new Texture2D(1, 1);
            tex.SetPixel(0, 0, Color.white);
            tex.Apply();
            return Sprite.Create(tex, new Rect(0, 0, 1, 1), new Vector2(0.5f, 0.5f), 1f);
        }

        private PieceType InferPieceType<T>() where T : ChessPiece
        {
            if (typeof(T) == typeof(Pawn)) return PieceType.Pawn;
            if (typeof(T) == typeof(Knight)) return PieceType.Knight;
            if (typeof(T) == typeof(Bishop)) return PieceType.Bishop;
            if (typeof(T) == typeof(Rook)) return PieceType.Rook;
            if (typeof(T) == typeof(Queen)) return PieceType.Queen;
            if (typeof(T) == typeof(King)) return PieceType.King;
            if (typeof(T) == typeof(WilderGambit.Pieces.NecromancerBishop)) return PieceType.NecromancerBishop;
            if (typeof(T) == typeof(WilderGambit.Pieces.SpectralPawn)) return PieceType.Pawn;
            if (typeof(T) == typeof(WilderGambit.Pieces.LancerPawn)) return PieceType.Pawn;
            if (typeof(T) == typeof(WilderGambit.Pieces.RiderQueen)) return PieceType.Queen;
            if (typeof(T) == typeof(WilderGambit.Pieces.VampireQueen)) return PieceType.Queen;
            if (typeof(T) == typeof(WilderGambit.Pieces.FraguaRook)) return PieceType.Rook;
            if (typeof(T) == typeof(WilderGambit.Pieces.PumpkinPawn)) return PieceType.Pawn;
            if (typeof(T) == typeof(WilderGambit.Pieces.GhostKnight)) return PieceType.Knight;
            return PieceType.Pawn;
        }

        /// <summary>
        /// Aplica (o retira) la skin equipada del tipo indicado sobre una vista de pieza ya
        /// construida: limpia el tinte anterior, reconstruye el aura y deja el sprite intacto.
        /// Se usa al spawnear, al reconstruir el tablero y al promover un peón, para que el
        /// resultado sea siempre el mismo y ninguna vía se quede sin pintar.
        /// </summary>
        private void ApplyEquippedSkin(GameObject pieceObj, PieceType type, TeamColor team)
        {
            if (pieceObj == null) return;

            // El aura pertenece a la skin anterior: si no se retira, sigue pulsando
            // con la silueta de la pieza que ya no es (p. ej. tras una promoción).
            Transform oldAura = pieceObj.transform.Find("SkinAura");
            if (oldAura != null) Destroy(oldAura.gameObject);

            SpriteRenderer sr = pieceObj.GetComponent<SpriteRenderer>();
            if (sr == null) return;
            sr.color = Color.white;

            // Las variantes mandan: su arte propio no se tiñe ni se pisa con la
            // skin equipada. Sin esta salida, una skin de torre con tinte
            // coloreaba la Torre Fragua aunque su sprite ya fuera el correcto.
            if (IsVariantArtSprite(sr.sprite)) return;

            string equippedSkinId = PieceSkinManager.GetSelectedSkinId(type);
            if (string.IsNullOrEmpty(equippedSkinId)) return;

            int skinIdx = PieceSkinManager.GetIndexById(equippedSkinId);
            if (skinIdx < 0) return;

            Color tint = PieceSkinManager.GetSkinTint(skinIdx);
            SkinAnimation anim = PieceSkinManager.GetSkinAnimation(skinIdx);

            // ── Skins con arte propio (lote de la velada): reemplazan el sprite de
            // la pieza. Las variantes mandan: el arte de Peón Calabaza y Caballo
            // Fantasma no se pisa con ninguna skin.
            Sprite skinArt = ResolveSkinArt(equippedSkinId, team);
            if (skinArt != null && !IsVariantArtSprite(sr.sprite))
            {
                Transform shadowT = pieceObj.transform.Find("Shadow");
                var shadowSr = shadowT != null ? shadowT.GetComponent<SpriteRenderer>() : null;

                sr.sprite = skinArt;
                if (shadowSr != null) shadowSr.sprite = skinArt;

                // El arte nuevo puede medir distinto: se reescala como en el spawn.
                float artHeight = tileSize * 0.82f;
                float artScale = skinArt.bounds.size.y > 0 ? artHeight / skinArt.bounds.size.y : 1f;
                pieceObj.transform.localScale = new Vector3(artScale, artScale, 1f);
            }

            // Mezclar tinte conservando luminancia para piezas blancas/negras
            if (tint != Color.white && tint.a > 0.01f)
            {
                sr.color = team == TeamColor.White
                    ? Color.Lerp(Color.white, tint, 0.55f)
                    : Color.Lerp(Color.white, tint * 0.9f, 0.45f);
            }

            if (anim != SkinAnimation.None)
            {
                ApplySkinAnimation(pieceObj, anim, tint, tileSize);
            }
        }

        /// <summary>Arte propio de la skin equipada para el bando, o null si es de tinte.</summary>
        private Sprite ResolveSkinArt(string skinId, TeamColor team)
        {
            string artName = PieceSkinManager.GetSkinArtName(skinId);
            return string.IsNullOrEmpty(artName) ? null : HalloweenArtForTeam(artName, team);
        }

        private void ApplySkinAnimation(GameObject pieceObj, SkinAnimation anim, Color tint, float tileSz)
        {
            // Capa de aura pulsante detrás de la pieza
            GameObject aura = new GameObject("SkinAura");
            aura.transform.SetParent(pieceObj.transform);
            aura.transform.localPosition = new Vector3(0f, 0f, 0.01f);
            aura.transform.localScale = new Vector3(1.15f, 1.15f, 1f);

            SpriteRenderer auraSr = aura.AddComponent<SpriteRenderer>();
            // Reusar sprite principal con tinte translúcido
            SpriteRenderer mainSr = pieceObj.GetComponent<SpriteRenderer>();
            if (mainSr != null) auraSr.sprite = mainSr.sprite;
            auraSr.sortingOrder = 1;
            Color auraColor = new Color(tint.r, tint.g, tint.b, 0.22f);
            if (anim == SkinAnimation.Fire) auraColor = new Color(1f, 0.45f, 0.12f, 0.28f);
            else if (anim == SkinAnimation.Ice) auraColor = new Color(0.5f, 0.85f, 1f, 0.25f);
            else if (anim == SkinAnimation.Spectral) auraColor = new Color(0.65f, 0.45f, 0.95f, 0.22f);
            else if (anim == SkinAnimation.Necrotic) auraColor = new Color(0.35f, 0.95f, 0.55f, 0.26f);
            else if (anim == SkinAnimation.Embers) auraColor = new Color(0.95f, 0.55f, 0.18f, 0.20f);
            else if (anim == SkinAnimation.Solar) auraColor = new Color(1f, 0.85f, 0.35f, 0.24f);
            else if (anim == SkinAnimation.Abyssal) auraColor = new Color(0.25f, 0.55f, 0.85f, 0.23f);
            auraSr.color = auraColor;

            var pulse = aura.AddComponent<PulsingOverlay>();
            pulse.pulseSpeed = (anim == SkinAnimation.Breathing || anim == SkinAnimation.Spectral) ? 2.2f : 3.5f;
            pulse.pulseAmplitude = 0.12f;
            pulse.minScaleFactor = 0.88f;
        }
    }

    /// <summary>
    /// Anima un overlay de sprite con una pulsación suave de escala (efecto "respiración").
    /// Usado por las casillas de resurrección y el aura de carga lista del Nigromante.
    /// </summary>
    public class PulsingOverlay : MonoBehaviour
    {
        public float pulseSpeed      = 5f;
        public float pulseAmplitude  = 0.18f;
        /// <summary>Escala mínima relativa respecto a la escala inicial configurada.</summary>
        public float minScaleFactor  = 0.75f;

        private Vector3 _baseScale;
        private float _time;

        private void Start()
        {
            _baseScale = transform.localScale;
        }

        private void Update()
        {
            _time += Time.deltaTime * pulseSpeed;
            float wave = (Mathf.Sin(_time) * 0.5f + 0.5f); // 0..1
            float factor = Mathf.Lerp(minScaleFactor, 1f + pulseAmplitude, wave);
            transform.localScale = _baseScale * factor;
        }
    }

    public class ToastFade : MonoBehaviour
    {
        public float duration = 2.2f;
        private float _t;
        private TextMesh _tm;
        private Color _initial;
        private Vector3 _startPos;
        private void Start()
        {
            _tm = GetComponent<TextMesh>();
            if (_tm != null) _initial = _tm.color;
            _startPos = transform.position;
        }
        private void Update()
        {
            _t += Time.deltaTime;
            float p = _t / duration;
            transform.position = _startPos + Vector3.up * (p * 0.6f);
            if (_tm != null)
            {
                Color c = _initial;
                c.a = Mathf.Lerp(1f, 0f, p);
                _tm.color = c;
            }
            if (_t >= duration) Destroy(gameObject);
        }
    }

    /// <summary>
    /// Anillo de la Explosión de Calabaza: se expande y se desvanece sobre la
    /// casilla del capturador. Se autodestruye al terminar.
    /// </summary>
    public class PumpkinExplosionFx : MonoBehaviour
    {
        public float duration = 0.55f;
        public float maxScale = 2.4f;
        public Color startColor = new Color(1f, 0.55f, 0.1f, 0.95f);

        private float _t;
        private Vector3 _baseScale;
        private SpriteRenderer _sr;

        private void Start()
        {
            _baseScale = transform.localScale;
            _sr = GetComponent<SpriteRenderer>();
        }

        private void Update()
        {
            _t += Time.deltaTime;
            float p = Mathf.Clamp01(_t / duration);
            transform.localScale = _baseScale * Mathf.Lerp(1f, maxScale, p);
            if (_sr != null)
            {
                Color c = startColor;
                c.a = Mathf.Lerp(startColor.a, 0f, p);
                _sr.color = c;
            }
            if (_t >= duration) Destroy(gameObject);
        }
    }
}
