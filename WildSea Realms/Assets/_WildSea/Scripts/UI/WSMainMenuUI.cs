using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.UIElements;
using UnityEngine.Video;
using WildSea.Core;

namespace WildSea.UI
{
    /// <summary>
    /// Main Menu WILDSEA. UXML/USS en Resources/WS/MainMenu. Solo pide nombre igual en UXML.
    /// Uso: añade WSApp a la escena y pulsa Play. WSApp crea esto solo.
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class WSMainMenuUI : MonoBehaviour
    {
        public System.Action OnEnterPressed;

        UIDocument doc;
        VisualElement root, modalOverlay, howCard, optionsCard;
        Label toast, musicValue, sfxValue;
        Button optLang, optFull, optFlash;
        IVisualElementScheduledItem toastHide;
        int fitW = -1, fitH = -1;
        bool visible;
        VideoPlayer videoA, videoB;      // doble reproductor para fundido en el loop
        RenderTexture rtA, rtB;
        VisualElement videoLayer;       // capa extra reutilizada para el fundido
        bool videoActiveIsA = true;
        bool videoFading;
        float videoFadeT;
        bool videoFadeHold; // fundido congelado hasta que el entrante renderice
        float videoFadeWait;
        const float VideoFadeDur = 0.8f; // solape del fundido antes del corte
        // Tras la 1ª pasada completa (0..fin), el loop repite solo desde aquí,
        // que es cuando los puntos ya aparecieron. En frames del clip (24 fps).
        const long VideoLoopStartFrame = 48;
        const double VideoLoopStartTime = 48.0 / 24.0; // = 2.0 s
        const int VideoMaxRetries = 3; // reintentos seguidos antes de rendirse al fondo CSS
        int videoRetries;
        int videoLoopCount; // TEMP diag: nº de swaps completados
        double videoLastTime = -1; // TEMP diag: último time visto avanzar
        float videoLastAdvance;

        const string UxmlPath = "WS/MainMenu/MainMenu";
        const string MenuBgClipPath = "WS/MainMenu/menu_bg"; // MP4 directo, sin pasar a frames

        void Awake() => doc = GetComponent<UIDocument>();

        void OnEnable()
        {
            EnsureTree();
            // El panel reconstruye el árbol un frame después: reintenta hasta verlo
            int tries = 0;
            IVisualElementScheduledItem wait = null;
            wait = doc.rootVisualElement.schedule.Execute(() =>
            {
                var r = doc.rootVisualElement;
                if (r != null && r.childCount > 0) { wait?.Pause(); Build(); }
                else if (++tries > 120) { wait?.Pause(); Debug.LogError("[WildSea] MainMenu: UXML nunca cargó."); }
            }).Every(16);
        }

        void EnsureTree()
        {
            if (doc.visualTreeAsset != null) return;
            var tree = Resources.Load<VisualTreeAsset>(UxmlPath);
            if (tree != null) doc.visualTreeAsset = tree;
            else BuildFallback(); // sin UXML: construye por código con las mismas clases USS
        }

        void Build()
        {
            var r = doc.rootVisualElement;
            if (r == null || r.childCount == 0) return;
            // UIDocument recrea el árbol visual en cada OnEnable: si el root guardado
            // ya no es el árbol vivo, hay que re-resolver y re-cablear desde cero.
            var live = r.Q<VisualElement>("menu-root");
            if (root != null && live == root) return;
            // USS siempre: aunque el UXML ya trae <Style>, refuerza por si se instanció sin él
            var sheet = Resources.Load<StyleSheet>(UxmlPath);
            if (sheet != null && r.styleSheets.count == 0) r.styleSheets.Add(sheet);

            root = live;
            if (root == null) { BuildFallback(); return; }
            root.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
            toast = r.Q<Label>("toast");
            modalOverlay = r.Q<VisualElement>("modal-overlay");
            howCard = r.Q<VisualElement>("modal-how-card");
            optionsCard = r.Q<VisualElement>("modal-options-card");
            musicValue = r.Q<Label>("opt-music-value");
            sfxValue = r.Q<Label>("opt-sfx-value");
            optLang = r.Q<Button>("opt-lang");
            optFull = r.Q<Button>("opt-fullscreen");
            optFlash = r.Q<Button>("opt-flash");

            WireButton("btn-enter", () => OnEnterPressed?.Invoke(), WSfx.Confirm);
            WireButton("btn-how", ShowHow);
            WireButton("btn-options", ShowOptions);
            WireButton("btn-quit", Quit);
            WireButton("btn-how-close", HideModal);
            WireButton("btn-options-close", HideModal);
            if (modalOverlay != null)
                modalOverlay.RegisterCallback<ClickEvent>(e => { if (e.target == modalOverlay) HideModal(); });

            WireButton("opt-music-minus", () => { WSSave.Music -= 0.1f; RefreshOptions(); WSAudio.ApplyVolumes(); });
            WireButton("opt-music-plus", () => { WSSave.Music += 0.1f; RefreshOptions(); WSAudio.ApplyVolumes(); });
            WireButton("opt-sfx-minus", () => { WSSave.Sfx -= 0.1f; RefreshOptions(); WSAudio.ApplyVolumes(); });
            WireButton("opt-sfx-plus", () => { WSSave.Sfx += 0.1f; RefreshOptions(); WSAudio.ApplyVolumes(); });
            if (optLang != null) optLang.clicked += () => { WSAudio.Click(); WSSave.Lang = WSSave.Lang == "es" ? "en" : "es"; RefreshOptions(); };
            if (optFull != null) optFull.clicked += () => { WSAudio.Click(); WSSave.Fullscreen = !WSSave.Fullscreen; RefreshOptions(); };
            if (optFlash != null) optFlash.clicked += () => { WSAudio.Click(); WSSave.ReducedFlash = !WSSave.ReducedFlash; RefreshOptions(); ApplyFlash(); };

            int i = 0;
            foreach (var n in new[] { "btn-enter", "btn-how", "btn-options", "btn-quit" })
            {
                var b = r.Q<Button>(n);
                if (b != null) b.AddToClassList($"ws-btn--d{++i}");
            }
            StartBubbles(r);
            if (SetupVideoBackground(r)) HideBubbles(r); // el vídeo ya trae partículas
            ApplyFlash();
            RefreshOptions();
            WSFontFix.Apply(root);
            FitRoot();
            var r0 = doc.rootVisualElement;
            Debug.Log($"[WildSea] panel={doc.panelSettings != null} kids={r0?.childCount} root={(root != null)} size={r0?.layout.size}");
            root.schedule.Execute(() => root.AddToClassList("ws-root--ready")).StartingIn(50);
            root.schedule.Execute(ClearStagger).StartingIn(1200);
            root.schedule.Execute(DiagSprites).StartingIn(800); // TEMP: diagnosticar fondos
        }

        // TEMP: vuelca layout real + textura resuelta de los fondos con sprite.
        // Quitar cuando el titulo y el panel se vean bien.
        void DiagSprites()
        {
            foreach (var n in new[] { "title-logo", "menu-buttons", "btn-enter" })
            {
                var e = root?.Q<VisualElement>(n);
                if (e == null) { Debug.Log($"[WildSea][Diag] {n}: NO ENCONTRADO"); continue; }
                var bg = e.resolvedStyle.backgroundImage;
                string tex = bg.texture != null ? $"{bg.texture.width}x{bg.texture.height}" : "null";
                string spr = bg.sprite != null
                    ? $"rect={bg.sprite.rect} tex={bg.sprite.texture?.width}x{bg.sprite.texture?.height}"
                    : "null";
                Debug.Log($"[WildSea][Diag] {n}: layout={e.layout.size} bgTex={tex} bgSprite={spr}");
            }
        }

        /// <summary>
        /// Cablea un boton y le asigna su sonido. Todo boton del menu pasa por
        /// aca: si se olvida el sonido se ve en el diff (no hay AudioSource.Play
        /// suelto en ningun lado).
        /// </summary>
        void WireButton(string name, System.Action a, WSfx s = WSfx.Click)
        {
            var b = doc.rootVisualElement.Q<Button>(name);
            if (b == null) return;
            b.clicked += () => WSAudio.Play(s);
            if (a != null) b.clicked += () => a();
        }

        void ClearStagger()
        {
            var col = root?.Q<VisualElement>("menu-buttons");
            if (col == null) return;
            ClearStaggerRec(col);
        }

        void ClearStaggerRec(VisualElement e)
        {
            for (int d = 1; d <= 4; d++) e.RemoveFromClassList($"ws-btn--d{d}");
            foreach (var c in e.Children()) ClearStaggerRec(c);
        }

        void ShowHow()
        {
            if (modalOverlay == null) return;
            if (howCard != null) howCard.style.display = DisplayStyle.Flex;
            if (optionsCard != null) optionsCard.style.display = DisplayStyle.None;
            modalOverlay.style.display = DisplayStyle.Flex;
            modalOverlay.schedule.Execute(() => modalOverlay.AddToClassList("ws-modal-overlay--visible")).StartingIn(1);
        }

        void ShowOptions()
        {
            if (modalOverlay == null) return;
            RefreshOptions();
            if (howCard != null) howCard.style.display = DisplayStyle.None;
            if (optionsCard != null) optionsCard.style.display = DisplayStyle.Flex;
            modalOverlay.style.display = DisplayStyle.Flex;
            modalOverlay.schedule.Execute(() => modalOverlay.AddToClassList("ws-modal-overlay--visible")).StartingIn(1);
        }

        void HideModal()
        {
            if (modalOverlay == null) return;
            modalOverlay.RemoveFromClassList("ws-modal-overlay--visible");
            modalOverlay.schedule.Execute(() => modalOverlay.style.display = DisplayStyle.None).StartingIn(240);
        }

        void Quit()
        {
#if UNITY_EDITOR
            UnityEditor.EditorApplication.isPlaying = false;
#else
            Application.Quit();
#endif
        }

        void RefreshOptions()
        {
            if (musicValue != null) musicValue.text = $"{Mathf.RoundToInt(WSSave.Music * 100)}%";
            if (sfxValue != null) sfxValue.text = $"{Mathf.RoundToInt(WSSave.Sfx * 100)}%";
            if (optLang != null) optLang.text = WSSave.Lang.ToUpper();
            if (optFull != null) optFull.text = WSSave.Fullscreen ? "SÍ" : "NO";
            if (optFlash != null) optFlash.text = WSSave.ReducedFlash ? "SÍ" : "NO";
        }

        void ApplyFlash()
        {
            // Reducir destellos: congela burbujas apagándolas
            if (WSSave.ReducedFlash && doc != null)
                foreach (var n in new[] { "bubble-1", "bubble-2", "bubble-3", "bubble-4", "bubble-5", "bubble-6" })
                {
                    var b = doc.rootVisualElement.Q<VisualElement>(n);
                    if (b != null) b.style.display = DisplayStyle.None;
                }
        }

        void StartBubbles(VisualElement r)
        {
            if (WSSave.ReducedFlash) return;
            var cfg = new (string n, float d, float p)[] {
                ("bubble-1", 11f, 0f), ("bubble-2", 14f, -3.5f), ("bubble-3", 16f, -7f),
                ("bubble-4", 12f, -1.5f), ("bubble-5", 15f, -5f), ("bubble-6", 10f, -9f),
            };
            foreach (var (n, d, p) in cfg)
            {
                var b = r.Q<VisualElement>(n);
                if (b == null) continue;
                float dur = d; float[] el = { -p };
                b.schedule.Execute(() =>
                {
                    el[0] += 0.016f;
                    float raw = el[0] % dur; if (raw < 0) raw += dur;
                    float t = raw / dur;
                    b.style.translate = new Translate(new Length(0), new Length(-t * 1400f, LengthUnit.Pixel));
                    b.style.opacity = t < 0.12f ? t / 0.12f : t > 0.88f ? (1f - t) / 0.12f : 0.55f;
                }).Every(16);
            }
        }

        // Fondo de vídeo (MP4 directo, sin pasar a frames): VideoPlayer →
        // RenderTexture → background del UXML, en loop y sin audio.
        // El loop no es un corte seco: 0.8 s antes del final arranca el segundo
        // reproductor en el frame del loop (puntos ya visibles) en una capa
        // extra y funde opacidad (dissolve). Si el fundido no engancha,
        // loopPointReached + watchdog reinician el loop para no congelarse.
        // Sin clip en Resources: devuelve false y queda el fondo CSS.
        VideoPlayer ActivePlayer => videoActiveIsA ? videoA : videoB;
        VideoPlayer IncomingPlayer => videoActiveIsA ? videoB : videoA;
        RenderTexture ActiveRT => videoActiveIsA ? rtA : rtB;
        RenderTexture IncomingRT => videoActiveIsA ? rtB : rtA;

        bool SetupVideoBackground(VisualElement r)
        {
            var clip = Resources.Load<VideoClip>(MenuBgClipPath);
            if (clip == null) return false;
            var bg = r.Q<VisualElement>("menu-background");
            if (bg == null) return false;
            EnsureVideoPlayers(clip);
            // La capa vive en el árbol: se recrea si el UIDocument lo reconstruyó
            videoLayer = new VisualElement { name = "menu-background-video-x" };
            videoLayer.AddToClassList("ws-bg-video");
            videoLayer.pickingMode = PickingMode.Ignore;
            videoLayer.style.opacity = 0;
            bg.Insert(0, videoLayer);
            bg.style.backgroundImage = new StyleBackground(Background.FromRenderTexture(ActiveRT));
            CancelVideoFade();
            if (visible && !ActivePlayer.isPlaying) ActivePlayer.Play();
            return true;
        }

        void EnsureVideoPlayers(VideoClip clip)
        {
            if (rtA == null) { rtA = new RenderTexture(1920, 1080, 0, RenderTextureFormat.ARGB32); rtA.Create(); }
            if (rtB == null) { rtB = new RenderTexture(1920, 1080, 0, RenderTextureFormat.ARGB32); rtB.Create(); }
            videoA = EnsureVideoPlayer(videoA, "WS_VideoA", clip, rtA);
            videoB = EnsureVideoPlayer(videoB, "WS_VideoB", clip, rtB);
        }

        VideoPlayer EnsureVideoPlayer(VideoPlayer p, string tag, VideoClip clip, RenderTexture rt)
        {
            if (p != null) return p;
            var go = new GameObject(tag);
            go.transform.SetParent(transform, false);
            p = go.AddComponent<VideoPlayer>();
            p.source = VideoSource.VideoClip;
            p.clip = clip;
            p.renderMode = VideoRenderMode.RenderTexture;
            p.targetTexture = rt;
            p.aspectRatio = VideoAspectRatio.Stretch;
            p.isLooping = false; // el loop lo hace el fundido, no el reproductor
            p.skipOnDrop = true;
            p.waitForFirstFrame = true;
            p.playOnAwake = false;
            p.audioOutputMode = VideoAudioOutputMode.None;
            p.loopPointReached += OnVideoLoopPoint;
            p.errorReceived += OnVideoError;
            p.Prepare();
            return p;
        }

        void OnVideoError(VideoPlayer p, string msg)
        {
            Debug.LogError($"[WildSea] Fondo vídeo ({(p == videoA ? "A" : "B")}): {msg}");
            if (p != ActivePlayer || !visible || videoFading) return;
            RestartActiveAtLoop();
        }

        void OnVideoLoopPoint(VideoPlayer p)
        {
            // Red de seguridad: si el activo tocó el final, reengancha el loop
            // en vez de quedarse congelado en el último frame.
            if (p == ActivePlayer && visible && !videoFading)
            {
                Debug.LogWarning("[WildSea] Fondo vídeo: reinicio por loopPointReached.");
                RestartActiveAtLoop();
            }
        }

        void RestartActiveAtLoop() => RestartActiveAtFrame(VideoLoopStartFrame);

        void RestartActiveAtFrame(long frame)
        {
            var act = ActivePlayer;
            if (act == null) return;
            if (videoRetries >= VideoMaxRetries)
            {
                Debug.LogError("[WildSea] Fondo vídeo: demasiados reintentos, queda el fondo CSS.");
                var bgFail = root?.Q<VisualElement>("menu-background");
                if (bgFail != null) bgFail.style.backgroundImage = new StyleBackground();
                if (videoLayer != null) videoLayer.style.opacity = 0;
                videoFading = false;
                return;
            }
            videoRetries++;
            var bg = root?.Q<VisualElement>("menu-background");
            act.Stop();
            act.frame = frame;
            if (bg != null) bg.style.backgroundImage = new StyleBackground(Background.FromRenderTexture(ActiveRT));
            if (videoLayer != null) videoLayer.style.opacity = 0;
            videoFading = false;
            videoFadeT = 0f;
            videoFadeHold = false;
            videoFadeWait = 0f;
            videoLastTime = -1;
            videoLastAdvance = Time.time;
            if (visible) act.Play();
        }

        void UpdateVideoCrossfade()
        {
            if (videoA == null || !visible) return;
            var act = ActivePlayer;
            if (act == null || act.clip == null) return;
            double len = act.clip.length;
            if (len <= VideoFadeDur + 0.2) return;
            if (!act.isPlaying && !videoFading)
            {
                // Parada inesperada en CUALQUIER punto (no solo al final): reengancha
                // donde se quedó en vez de dejar la imagen congelada.
                // time > 0.01 evita pelear con el arranque inicial (t=0 preparando).
                // Con fundido en curso NO se entra aquí: el fundido sigue abajo
                // aunque el activo ya haya parado (no lo necesita para el swap).
                if (len > 0.5 && act.time > 0.01)
                {
                    long resume = act.time >= len - 0.05 ? VideoLoopStartFrame : act.frame;
                    Debug.LogWarning($"[WildSea] Fondo vídeo: watchdog reanuda en frame {resume}.");
                    RestartActiveAtFrame(resume);
                }
                return;
            }
            if (!videoFading)
            {
                // TEMP diag: el reproductor dice playing pero ¿avanza el tiempo?
                if (System.Math.Abs(act.time - videoLastTime) > 0.001)
                {
                    videoLastTime = act.time;
                    videoLastAdvance = Time.time;
                }
                else if (len > 0.5 && videoLastTime >= 0
                    && Time.time - videoLastAdvance > 2f)
                {
                    Debug.LogWarning($"[WildSea] Fondo vídeo: tiempo congelado en {act.time:F2}s, reiniciando loop.");
                    RestartActiveAtFrame(VideoLoopStartFrame);
                    videoLastTime = -1;
                    videoLastAdvance = Time.time;
                    return;
                }
                if (act.time >= len - VideoFadeDur)
                {
                    // El entrante arranca en el inicio del loop (puntos visibles),
                    // no en 0: la 1ª pasada completa ya se vio al iniciar.
                    var inc = IncomingPlayer;
                    if (videoLayer != null)
                    {
                        videoLayer.style.backgroundImage = new StyleBackground(Background.FromRenderTexture(IncomingRT));
                        videoLayer.style.opacity = 0;
                    }
                    inc.Stop();
                    inc.frame = VideoLoopStartFrame;
                    inc.Play();
                    Debug.Log($"[WildSea] Fondo vídeo: fundido #{videoLoopCount + 1} inicia (inc t={inc.time:F2}s frame={inc.frame})."); // TEMP diag
                    videoFading = true;
                    videoFadeT = 0f;
                    videoFadeHold = true; // el seek es async: no fundir hasta verlo
                    videoFadeWait = 0f;
                }
            }
            else
            {
                if (videoFadeHold)
                {
                    // El frame pedido tarda 1-3 frames en estar listo; fundir antes
                    // mezcla el frame viejo del RT (= tick). Capa invisible meanwhile.
                    var incHold = IncomingPlayer;
                    videoFadeWait += Time.deltaTime;
                    bool ready = incHold != null && incHold.isPlaying
                        && incHold.time >= VideoLoopStartTime - 0.1;
                    if (!ready && videoFadeWait < 1.0f)
                    {
                        if (videoLayer != null) videoLayer.style.opacity = 0;
                        return;
                    }
                    Debug.Log($"[WildSea] Fondo vídeo: entrante listo (t={incHold?.time:F2}s, porTimeout={videoFadeWait >= 1.0f})."); // TEMP diag
                    videoFadeHold = false;
                }
                videoFadeT += Time.deltaTime;
                float k = Mathf.Clamp01(videoFadeT / VideoFadeDur);
                if (videoLayer != null) videoLayer.style.opacity = k;
                if (k < 1f) return;
                // Fundido completo: el fondo toma el frame entrante (idéntico al
                // de la capa) y la capa se apaga. Intercambio sin corte visible.
                var bg = root?.Q<VisualElement>("menu-background");
                if (bg != null) bg.style.backgroundImage = new StyleBackground(Background.FromRenderTexture(IncomingRT));
                if (videoLayer != null) videoLayer.style.opacity = 0;
                act.Stop();
                videoActiveIsA = !videoActiveIsA;
                IncomingPlayer.Prepare(); // el que espera, listo para el próximo ciclo
                videoFading = false;
                videoRetries = 0; // ciclo completo OK: resetea los reintentos
                videoLoopCount++;
                videoLastTime = -1; // el nuevo activo arranca en otro punto
                Debug.Log($"[WildSea] Fondo vídeo: loop #{videoLoopCount} OK."); // TEMP diag
            }
        }

        void CancelVideoFade()
        {
            videoFading = false;
            videoFadeT = 0f;
            videoFadeHold = false;
            videoFadeWait = 0f;
            videoLastTime = -1;
            videoLastAdvance = Time.time;
            if (videoLayer != null) videoLayer.style.opacity = 0;
            var inc = IncomingPlayer;
            if (inc != null && inc.isPlaying) inc.Stop();
        }

        void HideBubbles(VisualElement r)
        {
            foreach (var n in new[] { "bubble-1", "bubble-2", "bubble-3", "bubble-4", "bubble-5", "bubble-6" })
            {
                var b = r.Q<VisualElement>(n);
                if (b != null) b.style.display = DisplayStyle.None;
            }
        }

        // La raíz del panel no siempre tiene altura fija (flex-grow no estira):
        // aquí le damos tamaño explícito = tamaño visible del panel en unidades.
        void FitRoot() => WSFit.Update(root, doc, ref fitW, ref fitH);

        void Update()
        {
            if (root != null && (Screen.width != fitW || Screen.height != fitH)) FitRoot();
            UpdateVideoCrossfade();
            if (!visible || Keyboard.current == null) return;
            if (Keyboard.current.enterKey.wasPressedThisFrame || Keyboard.current.numpadEnterKey.wasPressedThisFrame ||
                Keyboard.current.spaceKey.wasPressedThisFrame)
            {
                // Con un modal abierto, Enter no debe saltar al Hub
                bool modalOpen = modalOverlay != null && modalOverlay.style.display == DisplayStyle.Flex;
                if (!modalOpen && root != null && root.style.display != DisplayStyle.None)
                {
                    WSAudio.Confirm();
                    OnEnterPressed?.Invoke();
                }
            }
            if (Keyboard.current.escapeKey.wasPressedThisFrame) { WSAudio.Back(); HideModal(); }
        }

        // No se desactiva el GameObject: UIDocument.OnEnable recrea el árbol visual y
        // se perderían el cableado de botones y las burbujas. Se oculta con display:none.
        public void Show(bool v)
        {
            visible = v;
            gameObject.SetActive(true);
            if (root == null) return; // aún sin árbol: Build() aplicará visible al construirse
            root.style.display = v ? DisplayStyle.Flex : DisplayStyle.None;
            if (videoA != null)
            {
                if (v)
                {
                    videoLastTime = -1;
                    videoLastAdvance = Time.time;
                    if (!ActivePlayer.isPlaying) ActivePlayer.Play();
                }
                else
                {
                    if (videoA.isPlaying) videoA.Pause();
                    if (videoB != null && videoB.isPlaying) videoB.Pause();
                    CancelVideoFade();
                }
            }
            if (!v) return;
            fitW = -1; fitH = -1; FitRoot(); // re-forzar si el árbol se recreó al reactivar
            root.RemoveFromClassList("ws-root--ready");
            root.schedule.Execute(() => root.AddToClassList("ws-root--ready")).StartingIn(50);
        }

        void OnDisable()
        {
            // Pause en parado mete error en consola: solo pausar si reproduce.
            if (videoA != null && videoA.isPlaying) videoA.Pause();
            if (videoB != null && videoB.isPlaying) videoB.Pause();
        }

        void OnDestroy()
        {
            if (rtA != null)
            {
                if (rtA.IsCreated()) rtA.Release();
                Destroy(rtA);
                rtA = null;
            }
            if (rtB != null)
            {
                if (rtB.IsCreated()) rtB.Release();
                Destroy(rtB);
                rtB = null;
            }
        }

        // Fallback por código si falta el UXML (misma estética, cero dependencias)
        void BuildFallback()
        {
            var r = doc.rootVisualElement;
            r.Clear();
            var sheet = Resources.Load<StyleSheet>(UxmlPath);
            if (sheet != null) r.styleSheets.Add(sheet);
            root = new VisualElement { name = "menu-root" };
            root.AddToClassList("ws-root");
            root.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
            root.Add(new Label { name = "title-top", text = "WILDSEA" });
            var btn = new Button(() => OnEnterPressed?.Invoke()) { name = "btn-enter", text = "➤  ENTRAR" };
            btn.AddToClassList("ws-btn"); btn.AddToClassList("ws-btn--primary");
            root.Add(btn);
            toast = new Label { name = "toast", text = "" };
            root.Add(toast);
            r.Add(root);
            WSFontFix.Apply(root);
            FitRoot();
            root.schedule.Execute(() => root.AddToClassList("ws-root--ready")).StartingIn(50);
        }
    }
}
