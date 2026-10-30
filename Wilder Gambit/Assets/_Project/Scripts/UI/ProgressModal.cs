using System;
using System.Collections;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.AI;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Vista PROGRESO del menú: la barra del Atelier de 7 días (una recompensa por día
    /// perfecto y cofre por semana completa), las misiones diarias y semanales, los retos
    /// (desafío diario y entrenamiento táctico), los logros y el catálogo de fuentes de
    /// Gambits con su tope del día.
    /// Rellena contenedores vacíos del UXML: el UXML solo lleva el esqueleto.
    /// </summary>
    public class ProgressModal : MonoBehaviour
    {
        private VisualElement _root;
        private VisualElement _weekBar;
        private VisualElement _chest;
        private ChestStage _chestStage;
        private VisualElement _dailyList;
        private VisualElement _weeklyList;
        private VisualElement _achList;
        private VisualElement _sourcesList;

        private Label _gambits;
        private Label _rhythm;
        private Label _rhythmSub;
        private Label _weekStatus;
        private Label _weekReset;
        private Label _chestTitle;
        private Label _chestSub;
        private Label _dailyTimer;
        private Label _weeklyTimer;
        private Label _achProgress;
        private Label _challengeSub;
        private Label _trainingSub;

        private Button _claimChest;
        private Button _reroll;
        private Button _dailyChallenge;
        private Button _training;

        private Action _onClose;
        private Action _onTraining;
        private Action _onDailyChallenge;
        private Action<string> _onToast;

        private bool _subscribed;

        // ── Capa de carga (saldo de Surface) ────────────────────────────────
        /// <summary>
        /// Antigüedad máxima del saldo antes de volver a pedirlo al servidor. El saldo en memoria
        /// ya se actualiza con cada premio, así que aquí solo se decide cuándo molesta la espera.
        /// </summary>
        private const float BalanceFreshSeconds = 120f;
        /// <summary>Tope de espera con la capa puesta: Render puede tardar en despertar.</summary>
        private const float MaxLoadSeconds = 10f;

        private VisualElement _loading;
        private VisualElement _loadingIcon;
        private Label _loadingLabel;
        private VisualElement _loadingBarFill;
        private IVisualElementScheduledItem _loadingAnim;
        private Coroutine _syncRoutine;
        private string _loadingBase = "";
        private float _loadingT;
        private bool _opened;

        /// <summary>Se llama desde MainMenuController una sola vez, tras cargar el UXML.</summary>
        public void Initialize(VisualElement root, Action onClose, Action onTraining, Action onDailyChallenge, Action<string> onToast)
        {
            _root = root;
            _onClose = onClose;
            _onTraining = onTraining;
            _onDailyChallenge = onDailyChallenge;
            _onToast = onToast;

            // Los retos necesitan sus managers aunque la escena no los tenga puestos
            PuzzleManager.EnsureExists();
            DailyChallenge.EnsureExists();
            GambitProgress.Init();

            if (_root == null)
            {
                Debug.LogWarning("[ProgressModal] No se encontró la vista de progreso en el UXML.");
                return;
            }

            _weekBar       = _root.Q<VisualElement>("prog-week-bar");
            _chest         = _root.Q<VisualElement>("prog-chest");
            _dailyList     = _root.Q<VisualElement>("prog-daily-list");
            _weeklyList    = _root.Q<VisualElement>("prog-weekly-list");
            _achList       = _root.Q<VisualElement>("prog-achievements-list");
            _sourcesList   = _root.Q<VisualElement>("prog-sources-list");

            _gambits       = _root.Q<Label>("prog-gambits-label");
            _rhythm        = _root.Q<Label>("prog-rhythm-label");
            _rhythmSub     = _root.Q<Label>("prog-rhythm-sub");
            _weekStatus    = _root.Q<Label>("prog-week-status");
            _weekReset     = _root.Q<Label>("prog-week-reset");
            _chestTitle    = _root.Q<Label>("prog-chest-title");
            _chestSub      = _root.Q<Label>("prog-chest-sub");
            _dailyTimer    = _root.Q<Label>("prog-daily-timer");
            _weeklyTimer   = _root.Q<Label>("prog-weekly-timer");
            _achProgress   = _root.Q<Label>("prog-ach-progress");
            _challengeSub  = _root.Q<Label>("prog-challenge-sub");
            _trainingSub   = _root.Q<Label>("prog-training-sub");

            _claimChest    = _root.Q<Button>("btn-claim-chest");
            _reroll        = _root.Q<Button>("btn-reroll-daily");
            _dailyChallenge = _root.Q<Button>("btn-daily-challenge");
            _training      = _root.Q<Button>("btn-training");

            _claimChest?.RegisterCallback<ClickEvent>(_ => OnClaimChest());
            _reroll?.RegisterCallback<ClickEvent>(_ => OnReroll());
            _dailyChallenge?.RegisterCallback<ClickEvent>(_ => _onDailyChallenge?.Invoke());
            _training?.RegisterCallback<ClickEvent>(_ => _onTraining?.Invoke());

            _root.Q<Button>("btn-close-progress")?.RegisterCallback<ClickEvent>(_ => _onClose?.Invoke());
            _root.Q<Button>("btn-close-progress-foot")?.RegisterCallback<ClickEvent>(_ => _onClose?.Invoke());

            ApplyContainerSprites();

            // El escenario del cofre ocupa el lugar del icono fijo: pone la pose, la apertura
            // con los 8 clips de VFX y la carta de premio. Si los PNG no están, no hace nada.
            _chestStage = new ChestStage(_root, _root.Q<VisualElement>("prog-chest-stage"));

            BuildLoadingOverlay();

            // USS no soporta ':first-child'/':last-child': los filetes de los hijos se
            // aplican por clase desde aqui (los hijos del UXML ya estan puestos).
            foreach (var col in _root.Query<VisualElement>(className: "prog-col").ToList())
                if (col.parent != null && col.parent.IndexOf(col) == 0)
                    col.AddToClassList("prog-first");
            var challenges = _root.Query<VisualElement>(className: "prog-challenge").ToList();
            for (int i = 0; i < challenges.Count; i++)
            {
                if (i == challenges.Count - 1) challenges[i].AddToClassList("prog-challenge-last");
            }

            Debug.Log("[ProgressModal] Vista de progreso lista.");
        }

        /// <summary>
        /// Sustituye los contenedores planos del USS por sus sprites (Resources/UI/Progress).
        /// Si un sprite no existe todavía, el contenedor conserva el estilo USS.
        ///
        /// SOLO se aplican los sprites cuya proporción aguanta el estirado del contenedor.
        /// Un 9-slice estira el centro a la caja del elemento, así que las volutas y coronas
        /// se deforman cuando la proporción no coincide: card_large (2,98) dentro de una
        /// columna de misiones (1,59) salía aplastada a la mitad, y card_week (2,41) estirada
        /// un 56%. Por eso las tarjetas anchas y las filas van con el estilo plano del USS
        /// (fondo oscuro + filete dorado) y los marcos adornados se reservan para los
        /// elementos de proporción estable: la ventana, los chips, las pastillas de cobro,
        /// las barras y las filas de catálogo.
        /// </summary>
        private void ApplyContainerSprites()
        {
            // Marco de la ventana: 1024x548 encaja con el modal (~1,87)
            ProgressSprites.Apply(_root, "frame_window");

            // Contenedores chicos de proporción estable
            ProgressSprites.Apply(_root.Q("prog-chip-gambits"), "chip_gold");
            ProgressSprites.Apply(_root.Q("prog-chip-rhythm"), "chip_blue");

            // Marco de las tarjetas de misiones (daily/semanal). Se usa card_week
            // (proporcion 2,41, la menos ancha) y NO card_large (2,98): en una columna
            // angosta el ancho estira mas el centro. El 9-slice CONSERVA las esquinas;
            // unitySliceScale<1 adelgaza el filete para que no se vea gigante, y el
            // padding del USS despeja las volutas. Si se ve deformado, subir el slice
            // o bajar la escala.
            ProgressSprites.Apply(_root.Q("prog-card-daily"), "card_week");
            ProgressSprites.Apply(_root.Q("prog-card-weekly"), "card_week");
            // La tarjeta de RETOS lleva el mismo marco card_week en su contenedor
            // principal, para que todas las tarjetas de Progreso compartan el mismo
            // lenguaje visual y tamaño.
            ProgressSprites.Apply(_root.Q("prog-card-challenges"), "card_week");

            // Filas de Retos del Día: mismo sprite y MISMO slice en las dos (por igual),
            // el que trae la tabla (14,14,15,15). row_challenge (prop. 9,53) tiene el
            // centro LISO: al ser la fila real mucho más ancha solo se estira el centro y
            // el filete no se deforma. El fondo/borde plano del USS se quitan para no
            // duplicar con el sprite (ver .prog-challenge en MainMenu.uss).
            ProgressSprites.Apply(_root.Q("prog-challenge-daily"), "row_challenge");
            ProgressSprites.Apply(_root.Q("prog-challenge-training"), "row_challenge");
            // El boton de cambio NO lleva sprite (btn_ghost): va con el estilo USS
            // .prog-ghost, sin caja, para no competir con la filigrana de las misiones.
        }

        /// <summary>Estados de un botón de cobro (disponible / bloqueado / cobrado).</summary>
        private static void SkinClaim(Button button, string state)
        {
            if (button == null) return;
            ProgressSprites.ApplyFirst(button, $"btn_claim_{state}", "btn_claim");
        }

        /// <summary>Al abrir: se engancha a los cambios de progreso y repinta.</summary>
        public void OnOpened()
        {
            if (!_subscribed)
            {
                GambitProgress.OnChanged += Refresh;
                _subscribed = true;
            }

            _opened = true;

            // Se pinta ya con lo que hay guardado; si el saldo de la cuenta no está fresco,
            // se enseña la capa de carga mientras se le pregunta a Surface (Render tarda).
            Refresh();

            if (!NeedsBalanceSync())
            {
                SetLoading(false);
                return;
            }

            SetLoading(true, "Sincronizando tu progreso");
            if (_syncRoutine != null) StopCoroutine(_syncRoutine);
            _syncRoutine = StartCoroutine(SyncBalanceThenReveal());
        }

        public void OnClosed()
        {
            _opened = false;
            SetLoading(false);
            _chestStage?.Stop();

            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        // ── Saldo de la cuenta: capa de carga ────────────────────────────────

        /// <summary>
        /// La capa de carga se construye aquí y no en el UXML porque el panel entero se
        /// monta desde código. Tapa la vista para que no se lea un saldo a medias.
        /// </summary>
        private void BuildLoadingOverlay()
        {
            if (_root == null || _loading != null) return;

            _loading = new VisualElement();
            _loading.AddToClassList("prog-loading");
            _loading.AddToClassList("hidden");

            var card = new VisualElement();
            card.AddToClassList("prog-loading-card");

            _loadingIcon = Text("♟", "prog-loading-icon");
            card.Add(_loadingIcon);

            _loadingLabel = Text("", "prog-loading-text");
            card.Add(_loadingLabel);

            card.Add(Text("Tus Gambits viven en tu cuenta de Surface. En cuanto conteste el servidor, el progreso real.",
                          "prog-loading-sub"));

            var bar = new VisualElement();
            bar.AddToClassList("prog-loading-bar");
            _loadingBarFill = new VisualElement();
            _loadingBarFill.AddToClassList("prog-loading-bar-fill");
            bar.Add(_loadingBarFill);
            card.Add(bar);

            _loading.Add(card);
            _root.Add(_loading);
        }

        private void SetLoading(bool visible, string message = null)
        {
            if (_loading == null) return;

            if (!string.IsNullOrEmpty(message)) _loadingBase = message;

            _loading.EnableInClassList("hidden", !visible);
            if (visible) StartLoadingAnimation();
            else StopLoadingAnimation();
        }

        private void StartLoadingAnimation()
        {
            _loadingT = 0f;
            if (_loadingAnim == null && _loading != null)
                _loadingAnim = _loading.schedule.Execute(TickLoading).Every(40);
            _loadingAnim?.Resume();
        }

        private void StopLoadingAnimation() => _loadingAnim?.Pause();

        /// <summary>Puntos suspensivos, latido del icono y barra indeterminada de ida y vuelta.</summary>
        private void TickLoading()
        {
            if (_loading == null || _loading.ClassListContains("hidden")) return;

            _loadingT += 0.04f;
            int dots = ((int)(_loadingT * 2f)) % 4;

            if (_loadingLabel != null) _loadingLabel.text = _loadingBase + new string('.', dots);
            if (_loadingIcon != null) _loadingIcon.style.opacity = 0.45f + 0.55f * Mathf.PingPong(_loadingT * 0.8f, 1f);
            if (_loadingBarFill != null) _loadingBarFill.style.left = Length.Percent(Mathf.PingPong(_loadingT * 0.55f, 1f) * 68f);
        }

        /// <summary>¿Hace falta preguntar el saldo al servidor antes de dar la vista por buena?</summary>
        private bool NeedsBalanceSync()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc == null || !svc.IsLoggedIn) return false;   // sin cuenta no hay nada que esperar
            return !svc.HasRecentBalance(BalanceFreshSeconds);
        }

        /// <summary>Pide el saldo a Surface y retira la capa de carga pase lo que pase.</summary>
        private IEnumerator SyncBalanceThenReveal()
        {
            var svc = WilderGambit.Services.OceanPayService.Instance;
            if (svc == null)
            {
                _syncRoutine = null;
                SetLoading(false);
                yield break;
            }

            // La petición va en paralelo para poder cortar la espera por tiempo: si se esperase
            // al yield, el timeout de UnityWebRequest (25 s) manda sobre el tope de la vista.
            bool done = false;
            StartCoroutine(RefreshBalanceRequest(svc, () =>
            {
                done = true;
                PieceSkinManager.SyncFromOceanPay();
                if (_opened) Refresh();   // saldo ya real (aunque llegue tarde)
            }));

            float t0 = Time.unscaledTime;
            while (!done && Time.unscaledTime - t0 < MaxLoadSeconds) yield return null;

            if (!done) PieceSkinManager.SyncFromOceanPay();
            _syncRoutine = null;

            if (!_opened) yield break;   // se cerró el panel mientras cargaba

            SetLoading(false);
            Refresh();

            if (!done)
                _onToast?.Invoke("Sin conexión con tu cuenta · progreso local");
        }

        /// <summary>Pide el saldo al servidor (auto-login si aún no hay usuario cargado).</summary>
        private IEnumerator RefreshBalanceRequest(WilderGambit.Services.OceanPayService svc, Action onDone)
        {
            if (svc.CurrentUser == null)
                yield return svc.TryAutoLoginAsync(_ => onDone(), () => onDone());
            else
                yield return svc.RefreshBalancesAsync(svc.SavedToken, svc.CurrentUser, _ => onDone(), _ => onDone());
        }

        private void OnDestroy()
        {
            if (_subscribed)
            {
                GambitProgress.OnChanged -= Refresh;
                _subscribed = false;
            }
        }

        // ── Repintado ─────────────────────────────────────────────────────────

        /// <summary>Reconstruye toda la vista con el estado actual de la economía.</summary>
        public void Refresh()
        {
            if (_root == null) return;

            // El día pudo cambiar con la ventana abierta
            WeeklyProgress.SyncToday(DailyMissions.CompletedCount);

            RefreshHeader();
            RefreshWeekBar();
            RefreshChest();
            RefreshMissions();
            RefreshChallenges();
            RefreshAchievements();
            RefreshSources();
        }

        private void RefreshHeader()
        {
            if (_gambits != null) _gambits.text = GambitEconomy.Balance.ToString("N0");

            var config = GambitEconomyConfig.Instance;
            int today = GambitLedger.TotalToday;

            if (_rhythm != null) _rhythm.text = $"Hoy: {today:N0}";
            if (_rhythmSub != null)
            {
                if (today >= config.dailyHardCap) _rhythmSub.text = "TOPE DIARIO ALCANZADO";
                else if (today >= config.dailySoftCap) _rhythmSub.text = "RITMO AL 25%";
                else _rhythmSub.text = $"HASTA {config.dailySoftCap:N0} AL 100%";
            }
        }

        // ── Barra del Atelier (7 segmentos) ───────────────────────────────────

        private void RefreshWeekBar()
        {
            if (_weekBar == null) return;
            _weekBar.Clear();

            int segCount = WeeklyProgress.SegmentCount;
            for (int i = 0; i < segCount; i++)
            {
                var seg = BuildSegment(WeeklyProgress.GetSegment(i));
                // USS no soporta ':last-child': el filete va por clase en el ultimo segmento
                if (i == segCount - 1) seg.AddToClassList("prog-last");
                _weekBar.Add(seg);
            }

            int filled = WeeklyProgress.FilledCount;
            int toChest = WeeklyProgress.SegmentCount - filled;
            if (_weekStatus != null)
            {
                _weekStatus.text = filled >= WeeklyProgress.SegmentCount
                    ? $"¡SEMANA PERFECTA! {filled} / {WeeklyProgress.SegmentCount} días completos"
                    : $"{filled} / {WeeklyProgress.SegmentCount} días perfectos · faltan {toChest} para abrir el cofre";
            }
            if (_weekReset != null) _weekReset.text = $"Se reinicia en {WeeklyProgress.TimeToWeekResetText()}";
        }

        private VisualElement BuildSegment(WeekSegment seg)
        {
            var wrap = new VisualElement();
            wrap.AddToClassList("prog-seg");

            switch (seg.state)
            {
                case SegmentState.Complete: wrap.AddToClassList("prog-seg-complete"); break;
                case SegmentState.Today:    wrap.AddToClassList("prog-seg-today"); break;
                case SegmentState.Missed:   wrap.AddToClassList("prog-seg-missed"); break;
                default:                    wrap.AddToClassList("prog-seg-future"); break;
            }
            if (seg.paid) wrap.AddToClassList("prog-seg-paid");

            // sprite del contenedor según el estado del día.
            // seg_* mide 149x296 (proporcion 0,5), la misma que la celda del segmento
            // (~0,38): encaja sin deformarse, así que aquí sí se aplica.
            string segSprite = seg.state switch
            {
                SegmentState.Complete => "seg_done",
                SegmentState.Today => "seg_today",
                SegmentState.Missed => "seg_missed",
                _ => "seg_future",
            };
            ProgressSprites.Apply(wrap, segSprite);

            var head = new VisualElement();
            head.AddToClassList("prog-seg-head");
            head.Add(Text(seg.dayInitial, "prog-seg-day"));
            head.Add(Text(seg.dayNumber, "prog-seg-num"));
            wrap.Add(head);

            var track = new VisualElement();
            track.AddToClassList("prog-seg-track");
            ProgressSprites.Apply(track, "bar_track_v");
            var fill = new VisualElement();
            fill.AddToClassList("prog-seg-fill");
            ProgressSprites.Apply(fill, "bar_fill_v");
            fill.style.height = Length.Percent(Mathf.Round(seg.fill * 100f));
            track.Add(fill);
            wrap.Add(track);

            string status = seg.missionsDone >= DailyMissions.Slots ? "✓" : $"{seg.missionsDone}/3";
            wrap.Add(Text(status, "prog-seg-status"));
            wrap.Add(GambitIcon.Row($"{seg.reward:N0}{(seg.paid ? " ✓" : "")}", 14f, "prog-seg-reward"));

            string dayName = WeeklyProgress.DayName(seg.index);
            string rewardState = seg.paid ? "cobrado"
                : seg.missionsDone >= DailyMissions.Slots ? "pendiente de cobro"
                : $"{seg.missionsDone}/3 misiones";
            wrap.tooltip = $"{dayName} · {rewardState} · recompensa {seg.reward:N0} Gambits";
            return wrap;
        }

        private void RefreshChest()
        {
            if (_chest == null) return;

            bool ready = WeeklyProgress.CanClaimChest;
            bool claimed = WeeklyProgress.Data.chestClaimed;

            if (ready) _chest.AddToClassList("prog-chest-ready");
            else _chest.RemoveFromClassList("prog-chest-ready");
            if (_chestTitle != null) _chestTitle.text = $"{WeeklyProgress.ChestAmount:N0} Gambits";

            if (_chestSub != null)
            {
                int streak = WeeklyProgress.PerfectWeeks;
                string streakText = streak > 0
                    ? $"Racha: {streak} semana{(streak == 1 ? "" : "s")} perfecta{(streak == 1 ? "" : "s")} seguidas · +{WeeklyProgress.ChestStep:N0} por semana"
                    : $"Encadena semanas perfectas y el cofre sube +{WeeklyProgress.ChestStep:N0} cada vez.";
                _chestSub.text = claimed
                    ? "Cobrado esta semana. ¡A por la siguiente!"
                    : ready ? "¡Listo para reclamar!" : streakText;
            }

            _chestStage?.Refresh(ready, claimed, WeeklyProgress.ChestAmount);

            if (_claimChest == null) return;
            _claimChest.RemoveFromClassList("prog-claim-locked");
            _claimChest.RemoveFromClassList("prog-claim-done");
            _claimChest.SetEnabled(ready);

            if (ready)
            {
                _claimChest.text = $"COBRAR COFRE · {WeeklyProgress.ChestAmount:N0}";
                _claimChest.tooltip = "Cobra el cofre de esta semana perfecta.";
                SkinClaim(_claimChest, "ready");
            }
            else if (claimed)
            {
                _claimChest.text = "✓ COFRE COBRADO";
                _claimChest.tooltip = "Ya cobraste el cofre de esta semana.";
                _claimChest.AddToClassList("prog-claim-done");
                SkinClaim(_claimChest, "done");
            }
            else
            {
                int left = WeeklyProgress.SegmentCount - WeeklyProgress.FilledCount;
                _claimChest.text = "🔒 COBRAR COFRE";
                _claimChest.tooltip = $"Se abre al completar los 7 días perfectos (faltan {left}).";
                _claimChest.AddToClassList("prog-claim-locked");
                SkinClaim(_claimChest, "locked");
            }
        }

        private void OnClaimChest()
        {
            // Se cobra ANTES de animar: si el jugador cierra el modal a mitad de la apertura, los
            // Gambits ya están en la cuenta. La animación es presentación, no un requisito.
            var payout = WeeklyProgress.ClaimChest();
            if (payout.granted <= 0) return;

            if (_chestStage == null)
            {
                _onToast?.Invoke("🏆 Cofre del Atelier");
                Refresh();
                return;
            }

            // El aviso y el repintado de la fila llegan cuando termina la carta de premio.
            _chestStage.Play(payout.granted, () =>
            {
                _onToast?.Invoke("🏆 Cofre del Atelier");
                Refresh();
            });
        }

        /// <summary>
        /// Solo para las herramientas del editor: salta la capa de carga y lanza la apertura,
        /// para poder verla sin esperar a que conteste Surface ni rellenar una semana entera.
        /// No cobra nada: es presentación pura.
        /// </summary>
        public void DebugPlayChest(int amount)
        {
            if (_syncRoutine != null)
            {
                StopCoroutine(_syncRoutine);
                _syncRoutine = null;
            }

            SetLoading(false);
            _chestStage?.Play(amount);
        }

        /// <summary>
        /// Solo para probar el cofre a mano: salta la capa de carga y repinta, sin lanzar la
        /// apertura. La fila queda en 7/7 con el botón COBRAR COFRE habilitado para que el
        /// cobro y la animación se prueben pulsándolo como un jugador real.
        /// </summary>
        public void DebugReadyChest()
        {
            if (_syncRoutine != null)
            {
                StopCoroutine(_syncRoutine);
                _syncRoutine = null;
            }

            SetLoading(false);
            Refresh();
        }

        // ── Misiones ──────────────────────────────────────────────────────────

        private void RefreshMissions()
        {
            if (_dailyList != null)
            {
                _dailyList.Clear();
                for (int i = 0; i < DailyMissions.Slots; i++)
                {
                    var def = DailyMissions.GetAt(i);
                    if (def == null) continue;
                    var row = BuildMissionRow(
                        def,
                        DailyMissions.Progress(i),
                        DailyMissions.IsComplete(i),
                        DailyMissions.IsClaimed(i),
                        weekly: false,
                        index: i);
                    // USS no soporta ':last-child': filete por clase en la ultima fila
                    if (i == DailyMissions.Slots - 1) row.AddToClassList("prog-mission-last");
                    _dailyList.Add(row);
                }
            }

            if (_dailyTimer != null)
                _dailyTimer.text = $"{DailyMissions.CompletedCount}/{DailyMissions.Slots} hoy · reset en {DailyMissions.TimeToResetText()}";

            if (_reroll != null)
            {
                bool canReroll = DailyMissions.CanReroll && DailyMissions.CompletedCount < DailyMissions.Slots;
                _reroll.SetEnabled(canReroll);
                if (canReroll) _reroll.RemoveFromClassList("prog-ghost-disabled");
                else _reroll.AddToClassList("prog-ghost-disabled");
                _reroll.text = DailyMissions.CanReroll ? "CAMBIAR UNA MISIÓN (1 al día)" : "CAMBIO YA USADO HOY";
                // El sprite btn_ghost se retiró a propósito: su caja plana desentonaba
                // con la filigrana de las misiones. El estilo USS manda (.prog-ghost).
                ProgressSprites.Clear(_reroll);
            }

            if (_weeklyList != null)
            {
                _weeklyList.Clear();
                int weeklyCount = WeeklyProgress.WeeklyMissions.Length;
                for (int i = 0; i < weeklyCount; i++)
                {
                    var def = WeeklyProgress.WeeklyMissions[i];
                    var row = BuildMissionRow(
                        def,
                        WeeklyProgress.WeeklyProgressValue(i),
                        WeeklyProgress.IsWeeklyComplete(i),
                        WeeklyProgress.IsWeeklyClaimed(i),
                        weekly: true,
                        index: i);
                    // USS no soporta ':last-child': filete por clase en la ultima fila
                    if (i == weeklyCount - 1) row.AddToClassList("prog-mission-last");
                    _weeklyList.Add(row);
                }
            }

            if (_weeklyTimer != null)
                _weeklyTimer.text = $"Se reinician en {WeeklyProgress.TimeToWeekResetText()}";
        }

        private VisualElement BuildMissionRow(MissionDef def, int progress, bool complete, bool claimed, bool weekly, int index)
        {
            var row = new VisualElement();
            row.AddToClassList("prog-mission");
            if (complete) row.AddToClassList("prog-mission-done");

            // Marco 9-slice del contenedor. Con slice las ESQUINAS y la gema azul de la
            // izquierda NO se estiran (solo el centro): row_mission lleva slice-left=34 que
            // preserva la gema entera. El USS deja aire con padding-left para despejarla.
            if (claimed)
                ProgressSprites.ApplyFirst(row, "row_mission_done");
            else
                ProgressSprites.ApplyFirst(row, weekly ? "row_weekly" : "row_mission");

            var iconWrap = new VisualElement();
            iconWrap.AddToClassList("prog-mission-icon-wrap");
            iconWrap.Add(Text(def.icon, "prog-mission-icon"));
            row.Add(iconWrap);

            var texts = new VisualElement();
            texts.AddToClassList("prog-mission-texts");
            texts.Add(Text(def.title, "prog-mission-title"));
            texts.Add(Text(def.Description, "prog-mission-desc"));
            texts.Add(GambitIcon.Row($"Recompensa: {def.payout:N0}{(weekly ? "  ·  semanal" : "")}", 14f, "prog-mission-reward"));
            row.Add(texts);

            var right = new VisualElement();
            right.AddToClassList("prog-mission-right");

            var bar = new VisualElement();
            bar.AddToClassList("prog-bar");
            ProgressSprites.Apply(bar, "bar_track");
            var fill = new VisualElement();
            fill.AddToClassList("prog-bar-fill");
            ProgressSprites.Apply(fill, "bar_fill");
            fill.style.width = Length.Percent(def.target > 0 ? Mathf.Clamp01(progress / (float)def.target) * 100f : 0f);
            bar.Add(fill);
            right.Add(bar);
            row.Add(right);

            if (claimed)
            {
                var done = new Button { text = "✓ COBRADO" };
                done.AddToClassList("prog-claim");
                done.AddToClassList("prog-claim-done");
                done.SetEnabled(false);
                SkinClaim(done, "done");
                right.Add(done);
            }
            else if (complete)
            {
                var claim = new Button { text = $"COBRAR · {def.payout:N0}" };
                claim.AddToClassList("prog-claim");
                SkinClaim(claim, "ready");
                int slot = index;
                bool isWeekly = weekly;
                claim.RegisterCallback<ClickEvent>(_ => OnClaimMission(isWeekly, slot));
                right.Add(claim);
            }
            else
            {
                var pending = Text($"{progress}/{def.target}", "prog-source-today");
                right.Add(pending);
            }

            return row;
        }

        private void OnClaimMission(bool weekly, int index)
        {
            GambitPayout payout = weekly ? WeeklyProgress.ClaimWeekly(index) : DailyMissions.Claim(index);
            if (payout.granted > 0)
            {
                string label = weekly ? WeeklyProgress.WeeklyMissions[index].title : DailyMissions.GetAt(index)?.title ?? "Misión";
                _onToast?.Invoke($"📜 {label}");
            }
            Refresh();
        }

        private void OnReroll()
        {
            int slot = -1;
            for (int i = 0; i < DailyMissions.Slots; i++)
            {
                if (!DailyMissions.IsComplete(i)) { slot = i; break; }
            }

            if (slot < 0)
            {
                _onToast?.Invoke("Todas las misiones están completas hoy");
                return;
            }

            if (!DailyMissions.Reroll(slot))
            {
                _onToast?.Invoke("El cambio de misión ya se usó hoy");
                return;
            }

            _onToast?.Invoke("Nueva misión");
            Refresh();
        }

        // ── Retos ─────────────────────────────────────────────────────────────

        private void RefreshChallenges()
        {
            var dc = DailyChallenge.Instance;
            if (_challengeSub != null)
                _challengeSub.text = dc == null ? "No disponible hoy" : dc.StreakText;

            if (_dailyChallenge != null)
            {
                bool available = dc != null && dc.IsAvailable;
                _dailyChallenge.SetEnabled(available);
                _dailyChallenge.RemoveFromClassList("prog-claim-done");
                if (available)
                {
                    _dailyChallenge.text = "JUGAR DESAFÍO";
                    _dailyChallenge.tooltip = "Resuelve la posición de hoy y sube la racha de días.";
                    SkinClaim(_dailyChallenge, "ready");
                }
                else
                {
                    _dailyChallenge.text = "✓ HECHO HOY";
                    _dailyChallenge.tooltip = "Ya resolviste el desafío de hoy. Vuelve mañana.";
                    _dailyChallenge.AddToClassList("prog-claim-done");
                    SkinClaim(_dailyChallenge, "done");
                }
            }

            // El entrenamiento no depende del reto diario. Los primeros DailyPaidPuzzles puzzles
            // del día cobran (Gambits, rating y racha); el resto sigue disponible pero es práctica.
            int freeToday = PuzzleManager.PaidPuzzlesLeftToday;
            bool trainingPays = freeToday > 0;
            if (_training != null)
            {
                _training.text = trainingPays
                    ? $"ENTRENAR {PuzzleManager.TrainingSessionSize} PUZZLES"
                    : $"PRACTICAR {PuzzleManager.TrainingSessionSize} PUZZLES";
                _training.tooltip = trainingPays
                    ? $"Una sesión de {PuzzleManager.TrainingSessionSize} puzzles al día. Te quedan {freeToday} con premio ({PuzzleManager.MinPuzzlePayout}–{PuzzleManager.MaxPuzzlePayout} Gambits por puzzle resuelto); el resto es práctica."
                    : "Ya usaste los puzzles con premio de hoy: puedes entrenar todo lo que quieras, pero sin Gambits, sin rating y sin racha. Vuelve mañana.";
                SkinClaim(_training, "ready");
            }

            if (_trainingSub != null)
            {
                var pm = PuzzleManager.Instance;
                _trainingSub.text = pm == null
                    ? $"{PuzzleManager.MinPuzzlePayout}–{PuzzleManager.MaxPuzzlePayout} Gambits por puzzle"
                    : trainingPays
                        ? $"Tu rating: {pm.PlayerRating} · te quedan {freeToday}/{PuzzleManager.DailyPaidPuzzles} con premio · mejor racha: {pm.BestSolveStreak}"
                        : $"Tu rating: {pm.PlayerRating} · mejor racha: {pm.BestSolveStreak} · cupo de hoy gastado";
            }
        }

        // ── Logros ────────────────────────────────────────────────────────────

        private void RefreshAchievements()
        {
            if (_achProgress != null)
                _achProgress.text = $"{Achievements.UnlockedCount} / {Achievements.TotalCount} desbloqueados";

            if (_achList == null) return;
            _achList.Clear();

            int slot = 0;
            foreach (var def in Achievements.All)
            {
                bool unlocked = Achievements.IsUnlocked(def);
                int progress = Mathf.Clamp(Achievements.Progress(def), 0, def.target);

                var item = new VisualElement();
                item.AddToClassList("prog-ach");
                if (unlocked) item.AddToClassList("prog-ach-unlocked");
                if (slot % 2 == 1) item.AddToClassList("prog-ach-last"); // cierra cada fila de 2
                ProgressSprites.ApplyFirst(item, unlocked ? "card_ach_done" : "card_ach");
                slot++;

                item.Add(Text(def.icon, "prog-ach-icon"));

                var texts = new VisualElement();
                texts.AddToClassList("prog-ach-texts");
                texts.Add(Text(def.title, "prog-ach-title"));
                texts.Add(Text(def.desc, "prog-ach-desc"));
                item.Add(texts);

                string state = unlocked ? "✓" : (def.target > 1 ? $"{progress}/{def.target}" : "🔒");
                item.Add(Text(state, "prog-ach-state"));

                item.tooltip = $"{def.title} · {def.desc} · ♔ {def.payout:N0}" + (unlocked ? " (cobrado)" : "");
                _achList.Add(item);
            }
        }

        // ── Fuentes de Gambits ────────────────────────────────────────────────

        private void RefreshSources()
        {
            if (_sourcesList == null) return;
            _sourcesList.Clear();

            int srcCount = GambitSources.All.Length;
            for (int s = 0; s < srcCount; s++)
            {
                var info = GambitSources.All[s];
                bool room = GambitLedger.HasRoom(info.source, out _);
                int today = GambitLedger.SourceToday(info.source);
                int payments = GambitLedger.PaymentsToday(info.source);

                var row = new VisualElement();
                row.AddToClassList("prog-source");
                if (!room) row.AddToClassList("prog-source-exhausted");
                // USS no soporta ':last-child': filete por clase en la ultima fila
                if (s == srcCount - 1) row.AddToClassList("prog-source-last");
                ProgressSprites.ApplyFirst(row, room ? "row_source" : "row_source_empty");

                row.Add(Text(info.icon, "prog-source-icon"));

                var texts = new VisualElement();
                texts.AddToClassList("prog-source-texts");
                texts.Add(Text(info.label, "prog-source-label"));
                texts.Add(Text(info.hint, "prog-source-hint"));
                row.Add(texts);

                if (today > 0)
                {
                    string todayAmount = $"{today:N0}";
                    if (info.maxPayments > 0 && payments > 0)
                        todayAmount += $"  ({payments}/{info.maxPayments})";
                    row.Add(GambitIcon.Row(todayAmount, 14f, "prog-source-today"));
                }
                else row.Add(Text("—", "prog-source-today"));

                _sourcesList.Add(row);
            }
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Label Text(string value, string className)
        {
            var l = new Label(value ?? "");
            l.AddToClassList(className);
            return l;
        }
    }
}
