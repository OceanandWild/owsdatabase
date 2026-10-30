using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// MISIONES DE LA VELADA — el tablero completo de misiones de Halloween,
    /// abierto desde el pase (botón MISIONES del topbar o las fichas de resumen
    /// del cuerpo) como modal por encima de la velada.
    ///
    /// Dos pestañas:
    ///  · VÍA LUNA — las 3 misiones del día, del pool de 25, con progreso y cobro.
    ///  · VÍA SANGRE — las 10 exclusivas de la edición: 5 libres y 5 premium.
    ///    Las premium quedan cerradas hasta abrir la Vía Sangre con Dulces; el
    ///    mismo botón de la vía vive en el banner de esa pestaña.
    ///
    /// Fuera de la ventana de la velada el modal sigue abriéndose (para ver qué
    /// viene), pero los cobros esperan a que la velada esté activa. El progreso
    /// y los cobros los pone <see cref="HalloweenMissions"/>: aquí solo se pinta
    /// y se pide.
    /// </summary>
    public class HalloweenMissionsModal : MonoBehaviour
    {
        private VisualElement _root;
        private ScrollView _bodyScroll;
        private Button _tabLuna;
        private Button _tabSangre;
        private VisualElement _paneLuna;
        private VisualElement _paneSangre;
        private VisualElement _listLuna;
        private VisualElement _listSangreFree;
        private VisualElement _listSangrePaid;
        private Label _noteLuna;
        private Label _noteSangreFree;
        private Label _noteSangrePaid;
        private Label _heroNote;
        private Label _heroTimer;
        private Label _stateChip;
        private Label _xpLabel;
        private Label _dulcesLabel;
        private Label _footerNote;
        private VisualElement _sangreBanner;
        private Label _sangreBannerTitle;
        private Label _sangreBannerNote;
        private Button _btnSangre;
        private VisualElement _window;
        private VisualElement _crest;

        /// <summary>Orientación con la que se pintó el arte: en móvil vertical el
        /// marco pintado no entra en la ventana a sangre y vuelve el estilo USS.
        /// <c>null</c> = todavía sin decidir.</summary>
        private bool? _artPortrait;

        /// <summary>Estandarte dibujado: evita rehacerlo en cada repintado.</summary>
        private string _bannerArt;

        /// <summary>Orientación del último repintado (decide qué arte se aplica).</summary>
        private bool _portrait;

        private Action _onClose;
        private Action<string, string> _onToast;
        private bool _subscribed;
        private bool _showSangre;

        /// <summary>Firma del último repintado: evita rehacer las tarjetas por nada.</summary>
        private string _stamp;

        // ── Ciclo de vida ─────────────────────────────────────────────────

        /// <summary>Se llama una vez desde MainMenuController tras cargar el UXML.</summary>
        public void Initialize(VisualElement root, Action onClose, Action<string, string> onToast = null)
        {
            _root = root;
            _onClose = onClose;
            _onToast = onToast;
            if (_root == null) return;

            _bodyScroll = _root.Q<ScrollView>("hwm-body-scroll");
            _tabLuna = _root.Q<Button>("hwm-tab-luna");
            _tabSangre = _root.Q<Button>("hwm-tab-sangre");
            _paneLuna = _root.Q<VisualElement>("hwm-pane-luna");
            _paneSangre = _root.Q<VisualElement>("hwm-pane-sangre");
            _listLuna = _root.Q<VisualElement>("hwm-list-luna");
            _listSangreFree = _root.Q<VisualElement>("hwm-list-sangre-free");
            _listSangrePaid = _root.Q<VisualElement>("hwm-list-sangre-paid");
            _noteLuna = _root.Q<Label>("hwm-note-luna");
            _noteSangreFree = _root.Q<Label>("hwm-note-sangre-free");
            _noteSangrePaid = _root.Q<Label>("hwm-note-sangre-paid");
            _heroNote = _root.Q<Label>("hwm-hero-note");
            _heroTimer = _root.Q<Label>("hwm-hero-timer");
            _stateChip = _root.Q<Label>("hwm-state-chip");
            _xpLabel = _root.Q<Label>("hwm-xp-label");
            _dulcesLabel = _root.Q<Label>("hwm-dulces-label");
            _footerNote = _root.Q<Label>("hwm-footer-note");
            _sangreBanner = _root.Q<VisualElement>("hwm-sangre-banner");
            _sangreBannerTitle = _root.Q<Label>("hwm-sangre-banner-title");
            _sangreBannerNote = _root.Q<Label>("hwm-sangre-banner-note");
            _btnSangre = _root.Q<Button>("hwm-btn-sangre");
            _window = _root.Q<VisualElement>(className: "hwm-window");
            _crest = _root.Q<VisualElement>("hwm-crest");

            ApplyChromeArt();
            _window?.RegisterCallback<GeometryChangedEvent>(_ => OnWindowGeometry());

            _root.Q<Button>("btn-close-hw-missions")?.RegisterCallback<ClickEvent>(_ => Close());
            _root.Q<Button>("btn-close-hw-missions-foot")?.RegisterCallback<ClickEvent>(_ => Close());
            _tabLuna?.RegisterCallback<ClickEvent>(_ => ShowTab(false));
            _tabSangre?.RegisterCallback<ClickEvent>(_ => ShowTab(true));
            _btnSangre?.RegisterCallback<ClickEvent>(_ => OnSangreClicked());

            if (_listLuna == null || _listSangreFree == null || _listSangrePaid == null)
                Debug.LogWarning("[HalloweenMissionsModal] Faltan listas «hwm-list-*» en el UXML: las misiones no se pintarán.");
        }

        /// <summary>Elige la pestaña antes de abrir (la usan las fichas del pase).</summary>
        public void PrepareTab(bool sangre) => _showSangre = sangre;

        public void OnOpened()
        {
            if (!_subscribed)
            {
                GambitProgress.OnChanged += Refresh;
                _subscribed = true;
            }
            _stamp = null;
            ShowTab(_showSangre);
            Refresh();
        }

        public void OnClosed()
        {
            HalloweenSangreConfirm.Hide(_root);
            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        private void OnDestroy()
        {
            if (!_subscribed) return;
            GambitProgress.OnChanged -= Refresh;
            _subscribed = false;
        }

        private void Close()
        {
            WilderGambit.Audio.MusicManager.Instance?.PlayBackSound();
            _onClose?.Invoke();
        }

        // ── Arte pintado (ventana, emblema y estandarte) ──────────────────

        /// <summary>Marco de la ventana y emblema del hero. En móvil vertical se
        /// deja el estilo USS: el marco pintado no entra en la ventana a sangre.
        /// Si Unity todavía no importó los PNG, tampoco se toca nada.</summary>
        private void ApplyChromeArt()
        {
            if (_window == null) return;

            bool portrait = IsPortrait(_window);
            _artPortrait = portrait;

            if (portrait)
            {
                HalloweenMissionsSprites.Clear(_window);
                _window.RemoveFromClassList("hwm-framed");
                ClearBandArt();
                if (_crest != null) _crest.style.display = DisplayStyle.None;
                return;
            }

            if (HalloweenMissionsSprites.ApplyWindow(_window))
                _window.AddToClassList("hwm-framed");

            if (_crest != null)
            {
                _crest.style.display = HalloweenMissionsSprites.ApplyArt(
                    _crest, HalloweenMissionsSprites.Crest, 62f)
                    ? DisplayStyle.Flex
                    : DisplayStyle.None;
            }

            ApplyBandArt();
        }

        /// <summary>Bandas, pestañas, chips y filetes pintados (Tanda 2). Cada PNG
        /// reemplaza el estilo USS del elemento; si falta, el elemento se queda
        /// como está. En móvil vertical no se aplican: manda el estilo USS.</summary>
        private void ApplyBandArt()
        {
            if (_root == null) return;

            Skin(_root.Q<VisualElement>(className: "hwm-topbar"), HalloweenMissionsSprites.ApplyTopbar);
            Skin(_root.Q<VisualElement>(className: "hwm-hero"), HalloweenMissionsSprites.ApplyHero);
            Skin(_root.Q<VisualElement>(className: "hwm-footer"), HalloweenMissionsSprites.ApplyFooter);
            Skin(_root.Q<VisualElement>(className: "hwm-chip-xp"),
                element => HalloweenMissionsSprites.ApplyChip(element, false));
            Skin(_root.Q<VisualElement>(className: "hwm-chip-dulces"),
                element => HalloweenMissionsSprites.ApplyChip(element, true));
            Skin(_stateChip, HalloweenMissionsSprites.ApplyStateChip);

            foreach (var hint in _root.Query<VisualElement>(className: "hwm-hint").ToList())
                Skin(hint, HalloweenMissionsSprites.ApplyHint);

            foreach (var rule in _root.Query<VisualElement>(className: "hwm-section-line").ToList())
            {
                bool sangre = rule.ClassListContains("hwm-section-line-sangre");
                Skin(rule, element => HalloweenMissionsSprites.ApplyRule(element, sangre));
            }

            ApplyTabArt();
        }

        /// <summary>Las pestañas cambian de arte al cambiar de vía: apagada o
        /// encendida. Solo en horizontal (en vertical manda el USS).</summary>
        private void ApplyTabArt()
        {
            if (_artPortrait == true) return;
            Skin(_tabLuna, element => HalloweenMissionsSprites.ApplyTab(element, false, !_showSangre));
            Skin(_tabSangre, element => HalloweenMissionsSprites.ApplyTab(element, true, _showSangre));
        }

        /// <summary>Devuelve al estilo USS todo lo que tenga arte de la Tanda 2.</summary>
        private void ClearBandArt()
        {
            if (_root == null) return;
            foreach (var element in _root.Query<VisualElement>(className: "hwm-skinned").ToList())
            {
                HalloweenMissionsSprites.Clear(element);
                element.RemoveFromClassList("hwm-skinned");
                element.style.unitySliceLeft = StyleKeyword.Null;
                element.style.unitySliceRight = StyleKeyword.Null;
                element.style.unitySliceTop = StyleKeyword.Null;
                element.style.unitySliceBottom = StyleKeyword.Null;
                element.style.unitySliceScale = StyleKeyword.Null;
            }
        }

        private static void Skin(VisualElement element, Func<VisualElement, bool> apply)
        {
            if (element == null) return;
            if (apply(element)) element.AddToClassList("hwm-skinned");
        }

        /// <summary>El panel cambió de tamaño: si se giró la pantalla se rehace el
        /// arte y las tarjetas (con marco en horizontal, planas en vertical).</summary>
        private void OnWindowGeometry()
        {
            if (IsPortrait(_window) == _artPortrait) return;
            ApplyChromeArt();
            _stamp = null;
            Refresh();
        }

        /// <summary>¿El panel está en vertical? La clase la pone UiResponsive en la raíz.</summary>
        private static bool IsPortrait(VisualElement element)
        {
            for (var p = element; p != null; p = p.parent)
                if (p.ClassListContains(UiResponsive.PortraitClass)) return true;
            return false;
        }

        /// <summary>Estandarte de la Vía Sangre: pasa de carmesí a verde cuando la
        /// vía se abre. En vertical se queda con el estilo USS, como el resto.</summary>
        private void ApplyBannerArt()
        {
            if (_sangreBanner == null) return;

            if (_portrait)
            {
                if (_bannerArt == null) return;
                HalloweenMissionsSprites.Clear(_sangreBanner);
                _sangreBanner.RemoveFromClassList("hwm-banner-framed");
                _bannerArt = null;
                return;
            }

            string art = HalloweenLanes.SangreUnlocked
                ? HalloweenMissionsSprites.BannerOpen
                : HalloweenMissionsSprites.Banner;
            if (art == _bannerArt) return;

            if (HalloweenMissionsSprites.ApplyBanner(_sangreBanner, HalloweenLanes.SangreUnlocked))
            {
                _bannerArt = art;
                _sangreBanner.AddToClassList("hwm-banner-framed");
            }
        }

        // ── Pestañas ──────────────────────────────────────────────────────

        private void ShowTab(bool sangre)
        {
            _showSangre = sangre;

            _paneLuna?.EnableInClassList("hidden", sangre);
            _paneSangre?.EnableInClassList("hidden", !sangre);
            _tabLuna?.EnableInClassList("hwm-tab-active", !sangre);
            _tabSangre?.EnableInClassList("hwm-tab-active", sangre);
            ApplyTabArt();

            if (_bodyScroll != null) _bodyScroll.scrollOffset = Vector2.zero;
        }

        // ── Pintado ───────────────────────────────────────────────────────

        public void Refresh()
        {
            if (_root == null) return;

            var phase = HalloweenEvent.CurrentPhase;
            string stamp = Stamp(phase);
            if (stamp == _stamp) return;
            _stamp = stamp;

            _portrait = IsPortrait(_window);

            if (_xpLabel != null)
                _xpLabel.text = $"{HalloweenProgress.Xp:N0} / {HalloweenProgress.MaxXp:N0} XP";
            if (_dulcesLabel != null)
                _dulcesLabel.text = $"{HalloweenCurrency.Balance:N0}";
            if (_stateChip != null)
                _stateChip.text = phase == HalloweenEvent.Phase.Active ? "¡VELADA ACTIVA!"
                    : phase == HalloweenEvent.Phase.NotStarted ? "PRÓXIMAMENTE" : "TERMINADA";

            if (_heroNote != null)
                _heroNote.text = phase == HalloweenEvent.Phase.Active
                    ? "La velada está abierta: cada misión paga XP de la velada y Dulces"
                    : phase == HalloweenEvent.Phase.NotStarted
                        ? "PRÓXIMAMENTE · las misiones se encienden con la velada"
                        : "LAS PUERTAS SE CERRARON · las misiones descansan";
            if (_heroTimer != null) _heroTimer.text = HalloweenEvent.TimeTextNow.ToUpperInvariant();

            RefreshTabs(phase);
            RefreshLuna(phase);
            RefreshSangre(phase);
            RefreshSangreBanner(phase);

            if (_footerNote != null)
                _footerNote.text = phase == HalloweenEvent.Phase.Active
                    ? $"Luna: 3 misiones por jornada de un pool de {HalloweenMissions.LunaPoolCount}"
                      + $" · Sangre: {HalloweenMissions.SangreFreeSlots} libres + {HalloweenMissions.SangrePaidSlots} premium"
                      + " · todo se cobra al instante"
                    : "Las misiones de la velada solo se cobran mientras la velada está abierta.";
        }

        private void RefreshTabs(HalloweenEvent.Phase phase)
        {
            if (_tabLuna != null)
            {
                string count = phase == HalloweenEvent.Phase.NotStarted
                    ? $"{HalloweenMissions.Slots} AL DÍA"
                    : $"{HalloweenMissions.CompletedCount}/{HalloweenMissions.Slots}";
                _tabLuna.text = $"🌙 VÍA LUNA · {count}";
            }

            if (_tabSangre != null)
            {
                int done = HalloweenMissions.SangreCompletedCount(false) + HalloweenMissions.SangreCompletedCount(true);
                _tabSangre.text = $"🩸 VÍA SANGRE · {done}/{HalloweenMissions.SangreSlots}";
            }
        }

        private void RefreshLuna(HalloweenEvent.Phase phase)
        {
            if (_listLuna == null) return;
            _listLuna.Clear();

            int built = 0;
            for (int slot = 0; slot < HalloweenMissions.Slots; slot++)
            {
                var def = HalloweenMissions.GetAt(slot);
                if (def == null) continue;
                _listLuna.Add(BuildMissionCard(slot, def, sangre: false));
                built++;
            }

            if (built == 0)
                _listLuna.Add(EmptyState("🌙", "La Vía Luna sortea sus misiones al abrir la velada",
                    $"Cada jornada entran 3 del pool de {HalloweenMissions.LunaPoolCount}: "
                    + "partidas, victorias, precisión, capturas, puzzles y desafío diario."));

            if (_noteLuna != null)
                _noteLuna.text = phase == HalloweenEvent.Phase.Active
                    ? $"{HalloweenMissions.CompletedCount}/{HalloweenMissions.Slots} completadas"
                      + $" · {HalloweenMissions.PendingClaimsCount} por cobrar"
                      + $" · nueva tanda en {HalloweenMissions.TimeToResetText()}"
                    : phase == HalloweenEvent.Phase.NotStarted
                        ? $"3 por jornada desde un pool de {HalloweenMissions.LunaPoolCount} · se encienden el {HalloweenEvent.Start:dd/MM}"
                        : "La velada terminó: sin misiones nuevas";
        }

        private void RefreshSangre(HalloweenEvent.Phase phase)
        {
            if (_listSangreFree != null) _listSangreFree.Clear();
            if (_listSangrePaid != null) _listSangrePaid.Clear();

            for (int i = 0; i < HalloweenMissions.SangreFreeSlots; i++)
            {
                var def = HalloweenMissions.SangreGetAt(i);
                if (def == null) continue;
                _listSangreFree?.Add(BuildMissionCard(i, def, sangre: true));
            }

            for (int i = HalloweenMissions.SangreFreeSlots; i < HalloweenMissions.SangreSlots; i++)
            {
                var def = HalloweenMissions.SangreGetAt(i);
                if (def == null) continue;
                _listSangrePaid?.Add(BuildMissionCard(i, def, sangre: true));
            }

            if (_noteSangreFree != null)
            {
                int done = HalloweenMissions.SangreCompletedCount(false);
                _noteSangreFree.text =
                    $"{done}/{HalloweenMissions.SangreFreeSlots} completadas"
                    + $" · abiertas a todo el mundo · {HalloweenMissions.SangreFreeSlots} de un fondo de {HalloweenMissions.SangreFreePoolCount}";
            }

            if (_noteSangrePaid != null)
            {
                if (!HalloweenLanes.SangreUnlocked)
                {
                    _noteSangrePaid.text = "BLOQUEADAS · se abren al comprar la Vía Sangre";
                }
                else
                {
                    int done = HalloweenMissions.SangreCompletedCount(true);
                    _noteSangrePaid.text =
                        $"{done}/{HalloweenMissions.SangrePaidSlots} completadas"
                        + $" · {HalloweenMissions.SangrePaidSlots} de un fondo de {HalloweenMissions.SangrePaidPoolCount}";
                }
            }
        }

        private void RefreshSangreBanner(HalloweenEvent.Phase phase)
        {
            ApplyBannerArt();
            if (_sangreBanner == null || _btnSangre == null) return;

            if (HalloweenLanes.SangreUnlocked)
            {
                _sangreBanner.AddToClassList("hwm-banner-open");
                if (_sangreBannerTitle != null) _sangreBannerTitle.text = "✓ VÍA SANGRE ABIERTA";
                if (_sangreBannerNote != null)
                    _sangreBannerNote.text = "Las 10 exclusivas están disponibles hasta el final de la velada.";
                _btnSangre.text = "ABIERTA";
                _btnSangre.SetEnabled(false);
                return;
            }

            _sangreBanner.RemoveFromClassList("hwm-banner-open");
            if (_sangreBannerTitle != null) _sangreBannerTitle.text = "🔒 VÍA SANGRE";

            switch (phase)
            {
                case HalloweenEvent.Phase.Active:
                    if (_sangreBannerNote != null)
                        _sangreBannerNote.text =
                            $"Se abre con {HalloweenCurrency.Icon} {HalloweenLanes.SangreUnlockCost} {HalloweenCurrency.Label}"
                            + $" · tienes {HalloweenCurrency.Balance:N0} · incluye 5 misiones premium y el carril Sangre del pase";
                    _btnSangre.text = $"ABRIR · {HalloweenCurrency.Icon} {HalloweenLanes.SangreUnlockCost}";
                    _btnSangre.SetEnabled(true);
                    break;
                case HalloweenEvent.Phase.NotStarted:
                    if (_sangreBannerNote != null)
                        _sangreBannerNote.text =
                            $"Se abre con la velada, el {HalloweenEvent.Start:dd/MM} · {HalloweenCurrency.Icon} "
                            + $"{HalloweenLanes.SangreUnlockCost} · 5 misiones premium + carril Sangre del pase";
                    _btnSangre.text = "PRÓXIMAMENTE";
                    _btnSangre.SetEnabled(false);
                    break;
                default:
                    if (_sangreBannerNote != null)
                        _sangreBannerNote.text = "La velada terminó: la vía quedó cerrada.";
                    _btnSangre.text = "CERRADA";
                    _btnSangre.SetEnabled(false);
                    break;
            }
        }

        // ── Tarjetas ──────────────────────────────────────────────────────

        private VisualElement BuildMissionCard(int index, HalloweenMissions.HwMissionDef def, bool sangre)
        {
            bool claimed = sangre ? HalloweenMissions.SangreIsClaimed(index) : HalloweenMissions.IsClaimed(index);
            bool complete = sangre ? HalloweenMissions.SangreIsComplete(index) : HalloweenMissions.IsComplete(index);
            int progress = sangre ? HalloweenMissions.SangreProgress(index) : HalloweenMissions.Progress(index);
            bool locked = sangre && HalloweenMissions.SangreLocked(index);
            var phase = HalloweenEvent.CurrentPhase;

            var card = new VisualElement();
            card.AddToClassList("hwm-mission");
            card.AddToClassList(sangre ? "hwm-mission-sangre" : "hwm-mission-luna");
            bool ready = !claimed && complete && !locked && phase == HalloweenEvent.Phase.Active;
            if (def.premium) card.AddToClassList("hwm-mission-premium");
            if (claimed) card.AddToClassList("hwm-mission-claimed");
            else if (ready) card.AddToClassList("hwm-mission-ready");

            // Marco pintado: el riel del sprite reemplaza la barra de color y el
            // fondo (el estilo USS queda de respaldo si el PNG todavía no está).
            if (!_portrait && HalloweenMissionsSprites.ApplyCard(card,
                    HalloweenMissionsSprites.CardFor(sangre, def.premium, claimed, locked, ready)))
                card.AddToClassList("hwm-mission-framed");

            var icon = new Label(def.icon);
            icon.AddToClassList("hwm-mission-icon");
            card.Add(icon);

            var body = new VisualElement();
            body.AddToClassList("hwm-mission-body");

            var top = new VisualElement();
            top.AddToClassList("hwm-mission-top");

            var title = new Label(def.title);
            title.AddToClassList("hwm-mission-title");
            top.Add(title);

            var badge = new Label(def.LaneLabel);
            badge.AddToClassList("hwm-mission-badge");
            if (sangre) badge.AddToClassList(def.premium ? "hwm-badge-premium" : "hwm-badge-free");
            else badge.AddToClassList("hwm-badge-luna");
            top.Add(badge);
            body.Add(top);

            var desc = new Label(def.Description);
            desc.AddToClassList("hwm-mission-desc");
            body.Add(desc);

            var barRow = new VisualElement();
            barRow.AddToClassList("hwm-mission-bar-row");

            var bar = new VisualElement();
            bar.AddToClassList("hwm-mission-bar");
            var fill = new VisualElement();
            fill.AddToClassList("hwm-mission-fill");
            fill.style.width = Length.Percent(def.target > 0
                ? Mathf.Clamp01(progress / (float)def.target) * 100f
                : 0f);
            bar.Add(fill);
            barRow.Add(bar);

            var count = new Label($"{Mathf.Min(progress, def.target)}/{def.target}");
            count.AddToClassList("hwm-mission-count");
            barRow.Add(count);
            body.Add(barRow);

            card.Add(body);

            // Columna de acción: recompensa arriba y estado/botón abajo. Así el
            // cuerpo queda solo con título, descripción y barra, y todas las
            // tarjetas alinean su borde derecho.
            var action = new VisualElement();
            action.AddToClassList("hwm-mission-action");

            var reward = new Label(def.RewardText);
            reward.AddToClassList("hwm-mission-reward");
            action.Add(reward);

            if (claimed)
            {
                action.Add(Pill("✓ COBRADO", "hwm-pill-done"));
            }
            else if (locked)
            {
                action.Add(Pill($"🔒 {HalloweenLanes.SangreUnlockCost} {HalloweenCurrency.Icon}", "hwm-pill-locked"));
            }
            else if (phase == HalloweenEvent.Phase.NotStarted)
            {
                action.Add(Pill($"ABRE EL {HalloweenEvent.Start:dd/MM}", "hwm-pill-locked"));
            }
            else if (phase == HalloweenEvent.Phase.Ended)
            {
                action.Add(Pill("CERRADA", "hwm-pill-locked"));
            }
            else if (complete)
            {
                var btn = new Button(() => OnClaim(index, sangre)) { text = "COBRAR" };
                btn.AddToClassList("hwm-claim");
                if (!_portrait && HalloweenMissionsSprites.ApplyClaim(btn))
                    btn.AddToClassList("hwm-claim-framed");
                btn.RegisterCallback<ClickEvent>(evt => evt.StopPropagation());
                action.Add(btn);
            }
            else
            {
                action.Add(Pill(progress > 0 ? "EN CURSO" : "PENDIENTE", "hwm-pill-pending"));
            }

            card.Add(action);
            card.tooltip = $"{def.title} · {def.Description} · {def.RewardText}";
            return card;
        }

        private static Label Pill(string text, string stateClass)
        {
            var pill = new Label(text);
            pill.AddToClassList("hwm-pill");
            pill.AddToClassList(stateClass);
            pill.pickingMode = PickingMode.Ignore;
            return pill;
        }

        private VisualElement EmptyState(string icon, string title, string note)
        {
            var box = new VisualElement();
            box.AddToClassList("hwm-empty");

            var art = new VisualElement();
            art.AddToClassList("hwm-empty-art");
            art.pickingMode = PickingMode.Ignore;
            if (_portrait || !HalloweenMissionsSprites.ApplyArt(art, HalloweenMissionsSprites.EmptyMoon, 320f))
            {
                var iconLabel = new Label(icon);
                iconLabel.AddToClassList("hwm-empty-icon");
                box.Add(iconLabel);
            }
            else
            {
                box.Add(art);
            }

            var titleLabel = new Label(title);
            titleLabel.AddToClassList("hwm-empty-title");
            box.Add(titleLabel);

            var noteLabel = new Label(note);
            noteLabel.AddToClassList("hwm-empty-note");
            box.Add(noteLabel);

            return box;
        }

        // ── Cobros ────────────────────────────────────────────────────────

        private void OnClaim(int index, bool sangre)
        {
            var phase = HalloweenEvent.CurrentPhase;
            if (phase != HalloweenEvent.Phase.Active)
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                _onToast?.Invoke("Misiones de la velada",
                    phase == HalloweenEvent.Phase.NotStarted
                        ? $"Se encienden el {HalloweenEvent.Start:dd/MM} a las {HalloweenEvent.Start:HH:mm}"
                        : "La velada terminó: las misiones quedaron cerradas");
                return;
            }

            if (sangre && HalloweenMissions.SangreLocked(index))
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                _onToast?.Invoke("Vía Sangre cerrada",
                    $"Se abre con {HalloweenLanes.SangreUnlockCost} {HalloweenCurrency.Icon}: incluye las 5 misiones premium y el carril Sangre del pase");
                return;
            }

            var def = sangre ? HalloweenMissions.SangreGetAt(index) : HalloweenMissions.GetAt(index);
            bool ok = sangre ? HalloweenMissions.SangreClaim(index) : HalloweenMissions.Claim(index);
            if (!ok) return;

            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            _stamp = null;
            GambitProgress.NotifyChanged();   // repinta este modal y el pase de la velada
            _onToast?.Invoke($"Misión cobrada · {def?.title}",
                $"+{def?.xp ?? 0} XP de la velada · +{def?.dulces ?? 0} {HalloweenCurrency.Icon} {HalloweenCurrency.Label}");
        }

        private void OnSangreClicked()
        {
            var phase = HalloweenEvent.CurrentPhase;
            if (HalloweenLanes.SangreUnlocked) return;

            if (phase != HalloweenEvent.Phase.Active)
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                _onToast?.Invoke("Vía Sangre", phase == HalloweenEvent.Phase.NotStarted
                    ? $"Se abre con la velada · el {HalloweenEvent.Start:dd/MM}"
                    : "La velada terminó: la vía quedó cerrada");
                return;
            }

            WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
            HalloweenSangreConfirm.Show(_root, BuySangre);
        }

        /// <summary>Compra confirmada desde el overlay (ver HalloweenSangreConfirm).</summary>
        private void BuySangre()
        {
            if (HalloweenLanes.SangreUnlocked) return;

            if (!HalloweenLanes.TryBuySangre())
            {
                _onToast?.Invoke("Faltan Dulces",
                    $"Cuesta {HalloweenLanes.SangreUnlockCost} {HalloweenCurrency.Icon} y tienes {HalloweenCurrency.Balance:N0}"
                    + " · se ganan en las misiones del pase");
                return;
            }

            _stamp = null;
            GambitProgress.NotifyChanged();
            _onToast?.Invoke("Vía Sangre abierta",
                $"Las 5 misiones premium y el carril Sangre del pase quedaron disponibles"
                + $" · {HalloweenCurrency.Icon} {HalloweenCurrency.Balance:N0} restantes");
        }

        // ── Firma del repintado ───────────────────────────────────────────

        private static string Stamp(HalloweenEvent.Phase phase)
        {
            var sb = new System.Text.StringBuilder(phase.ToString());
            sb.Append('|').Append(HalloweenProgress.Xp)
              .Append('|').Append(HalloweenCurrency.Balance)
              .Append('|').Append(HalloweenLanes.SangreUnlocked ? 1 : 0);

            for (int i = 0; i < HalloweenMissions.Slots; i++)
            {
                var def = HalloweenMissions.GetAt(i);
                sb.Append('|').Append(def != null ? def.id : "-")
                  .Append(':').Append(HalloweenMissions.Progress(i))
                  .Append(':').Append(HalloweenMissions.IsClaimed(i) ? 1 : 0);
            }

            for (int i = 0; i < HalloweenMissions.SangreSlots; i++)
            {
                var def = HalloweenMissions.SangreGetAt(i);
                sb.Append('|').Append(def != null ? def.id : "-")
                  .Append(':').Append(HalloweenMissions.SangreProgress(i))
                  .Append(':').Append(HalloweenMissions.SangreIsClaimed(i) ? 1 : 0);
            }

            if (phase == HalloweenEvent.Phase.Active)
                sb.Append('|').Append(HalloweenMissions.TimeToResetText());
            return sb.ToString();
        }
    }
}
