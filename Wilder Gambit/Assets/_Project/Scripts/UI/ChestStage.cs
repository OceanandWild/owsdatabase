using System;
using System.Collections.Generic;
using WilderGambit.Audio;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// El cofre del Atelier tal como se ve en la fila de PROGRESO, junto al botón de cobro, y su
    /// **apertura completa**: las 8 capas de VFX, el cambio de pose y la carta de premio.
    ///
    /// Tres cosas que conviene tener presentes si se toca el guion:
    ///
    /// 1. **El cofre no tiene bisagra.** Las piezas del generador no son cuerpo y tapa sueltos:
    ///    son dos poses del mismo cofre (<c>chest_small</c> cerrado y <c>chest_base</c> abierto).
    ///    El cambio se hace dentro del destello de <c>shockwave</c> (ver <see cref="PoseSwapAt"/>),
    ///    así que no se nota el corte y no hay que animar ninguna rotación.
    /// 2. **Las 8 capas comparten encuadre.** El vídeo se entregó a 1280x720 y se instaló a
    ///    384x216 (1,778) sin recortar, precisamente para que se superpongan centradas en el cofre
    ///    sin ajustar cada una. La caja <see cref="LayerWidth"/> x <see cref="LayerHeight"/>
    ///    respeta esa proporción: si se cambia el ancho hay que cambiar el alto con él.
    /// 3. **La animación se conduce desde un solo tic.** Un elemento programado a 16 ms avanza el
    ///    reloj y de ahí salen todos los frames. No hay corrutinas ni Animator, así que el guion se
    ///    lee de arriba abajo en <see cref="Script"/> y se puede cambiar sin tocar nada más.
    /// 4. **El sonido sale de ese mismo tic.** Cada cue lleva su pieza de <see cref="ChestAudio"/> y
    ///    se dispara al encender la capa, así que imagen y sonido no pueden desincronizarse por
    ///    andar en dos relojes.
    /// </summary>
    public sealed class ChestStage
    {
        // ── Guion de la apertura, en segundos desde el cobro ──────────────────
        private struct Cue
        {
            public readonly string clip;
            public readonly float start;
            public readonly float duration;
            /// <summary>La capa va DELANTE del cofre.</summary>
            public readonly bool front;
            /// <summary>Fracción del clip por la que entra y por la que sale.</summary>
            public readonly float from;
            public readonly float to;
            /// <summary>Cuánto se levanta la capa, en px. La grieta cae sobre el frente del cofre.</summary>
            public readonly float lift;
            /// <summary>Pieza de <see cref="ChestAudio"/> que suena con este cue. Null = muda.</summary>
            public readonly string sfx;
            /// <summary>Volumen relativo de la pieza en la mezcla.</summary>
            public readonly float gain;

            public Cue(string clip, float start, float duration, bool front = false,
                       float from = 0f, float to = 1f, float lift = 0f,
                       string sfx = null, float gain = 1f)
            {
                this.clip = clip;
                this.start = start;
                this.duration = duration;
                this.front = front;
                this.from = from;
                this.to = to;
                this.lift = lift;
                this.sfx = sfx;
                this.gain = gain;
            }
        }

        private sealed class Layer
        {
            public Cue cue;
            public VisualElement element;
            public Sprite[] frames;
            public int index = -1;
            public bool shown;
            /// <summary>El sonido del cue ya se disparó en esta pasada.</summary>
            public bool played;
        }

        /// <summary>
        /// El cofre pasa de cerrado a abierto en este segundo. Tiene que caer sobre el fogonazo
        /// DELANTE del cofre: un anillo como <c>shockwave</c> no lo tapa porque deja el centro
        /// descubierto, y ahí está justamente el cofre.
        /// </summary>
        public const float PoseSwapAt = 0.70f;
        /// <summary>Duración de la apertura. Antes de esta marca no empieza la carta de premio.</summary>
        public const float OpeningSeconds = 2.20f;

        // Los volúmenes de cada cue siguen la mezcla ya calibrada: el fogonazo
        // manda y el resto acompaña. El margen global lo pone ChestAudio.Master.
        private static readonly Cue[] Script =
        {
            new Cue("seal_break", 0.22f, 0.88f, front: true, lift: 11f,
                    sfx: ChestAudio.Crack,  gain: 0.85f),   // la grieta, sobre el frente
            new Cue("halo",       0.30f, 1.15f,
                    sfx: ChestAudio.Charge, gain: 0.55f),   // el orbe que llena el centro
            new Cue("dust",       0.42f, 0.50f,
                    sfx: ChestAudio.Dust,   gain: 0.60f),
            new Cue("shockwave",  0.55f, 0.85f,
                    sfx: ChestAudio.Boom,   gain: 0.85f),
            // El fogonazo va DELANTE y entra por el 8% del clip, que es donde está el estallido:
            // es la capa que tapa el cambio de pose en PoseSwapAt.
            new Cue("flare",      0.50f, 0.85f, front: true, from: 0.08f, to: 0.48f,
                    sfx: ChestAudio.Burst,  gain: 1.00f),
            new Cue("rays",       0.70f, 1.20f,
                    sfx: ChestAudio.Rays,   gain: 0.70f),
            new Cue("embers",     0.85f, 1.25f, front: true,
                    sfx: ChestAudio.Embers, gain: 0.50f),
            new Cue("coins",      1.05f, 1.15f, front: true,
                    sfx: ChestAudio.Coins,  gain: 0.80f),
            // Segundo uso del mismo clip: la cola, que es una raya que barre y se apaga.
            new Cue("flare",      1.62f, 0.55f, front: true, from: 0.62f, to: 1f,
                    sfx: ChestAudio.Tail,   gain: 0.45f),
        };

        // Caja de una capa de VFX dentro del escenario. 196 x 110 = 1,78, la proporción del
        // encuadre de 384x216. Cabe entera en el escenario: el ScrollView del modal recorta,
        // así que las capas no pueden desbordar.
        private const float LayerLeft = 0f;
        private const float LayerTop = 4f;
        private const float LayerWidth = 196f;
        private const float LayerHeight = 110f;

        private const float CardWidth = 140f;
        private const float CardHeight = 173f;
        private const float CardIn = 0.45f;
        private const float CardHold = 1.35f;
        private const float CardOut = 0.40f;

        // Volúmenes de las dos piezas que no cuelgan de una capa de VFX (§3 del documento).
        private const float CardGain = 0.75f;
        private const float RewardGain = 0.90f;
        /// <summary>Cuándo entra el pago dentro de la carta: el golpe seco del clip está ahí.</summary>
        private const float RewardAt = 0.10f;

        private const long TickMs = 16;
        private const long PulseMs = 900;

        /// <summary>Último escenario construido. Lo usan los atajos de depuración.</summary>
        public static ChestStage Last { get; private set; }

        private readonly VisualElement _stage;
        private readonly VisualElement _fx;
        private readonly VisualElement _fxFront;
        private readonly VisualElement _art;
        private readonly List<Layer> _layers = new List<Layer>();

        private VisualElement _overlay;
        private VisualElement _card;
        private Label _amount;

        private IVisualElementScheduledItem _tick;
        private IVisualElementScheduledItem _pulse;

        private double _last;
        private float _t;
        private float _cardT = -1f;
        private bool _opening;
        private bool _openPose;
        private bool _pulseOn;
        private bool _replayable;
        private bool _rewardOn;
        private int _lastAmount;
        private Action _onDone;

        public ChestStage(VisualElement root, VisualElement stage)
        {
            _stage = stage;
            Last = this;
            if (_stage == null) return;

            _fx = _stage.Q<VisualElement>("prog-chest-fx");
            _fxFront = _stage.Q<VisualElement>("prog-chest-fx-front");
            _art = _stage.Q<VisualElement>("prog-chest-art");

            BuildLayers();
            BuildCard(root);
            SetPose(ChestSprites.PoseClosed);

            _stage.RegisterCallback<ClickEvent>(_ =>
            {
                if (_replayable && !_opening) Play(_lastAmount);
            });
        }

        // ── Construcción ─────────────────────────────────────────────────────

        private void BuildLayers()
        {
            if (_fx == null) return;

            foreach (Cue cue in Script)
            {
                VisualElement parent = cue.front ? _fxFront : _fx;
                if (parent == null) parent = _fx;

                var element = new VisualElement { pickingMode = PickingMode.Ignore };
                element.AddToClassList("prog-chest-fx-layer");
                element.style.left = LayerLeft;
                element.style.top = LayerTop - cue.lift;
                element.style.width = LayerWidth;
                element.style.height = LayerHeight;
                element.style.display = DisplayStyle.None;

                _layers.Add(new Layer
                {
                    cue = cue,
                    element = element,
                    frames = ChestSprites.Sequence(cue.clip),
                });
                parent.Add(element);
            }
        }

        private void BuildCard(VisualElement root)
        {
            // Sobre el modal entero y no sobre el ScrollView: el ScrollView recorta el desborde
            // y la carta tiene que poder salir de la fila.
            VisualElement host = root?.Q("progress-modal-view") ?? root;
            if (host == null) return;

            _overlay = new VisualElement { pickingMode = PickingMode.Ignore };
            _overlay.AddToClassList("prog-reward-overlay");
            _overlay.style.display = DisplayStyle.None;

            _card = Make("prog-reward-card");

            var back = Make("prog-reward-back");
            var frame = Make("prog-reward-frame");
            var emblem = Make("prog-reward-emblem");
            var seal = Make("prog-reward-seal");
            var kind = new Label("GAMBITS") { pickingMode = PickingMode.Ignore };
            kind.AddToClassList("prog-reward-kind");
            _amount = new Label { pickingMode = PickingMode.Ignore };
            _amount.AddToClassList("prog-reward-amount");

            _card.Add(back);
            _card.Add(frame);
            _card.Add(emblem);
            _card.Add(seal);
            _card.Add(kind);
            _card.Add(_amount);

            _overlay.Add(_card);
            host.Add(_overlay);

            // Sin capa de resplandor detrás: `card_reward_glow` es un rectángulo de luz MACIZO,
            // y UI Toolkit solo sabe componer por alfa (no hay modo aditivo), así que detrás de
            // la carta se vería su borde como una losa dorada. El brillo lo da la propia carta
            // al entrar, y las capas de VFX ya están en el escenario del cofre.
            SetBackground(back, ChestSprites.Get(ChestSprites.CardBack));
            SetBackground(emblem, ChestSprites.Emblem("gambits"));
            SetBackground(seal, ChestSprites.Get(ChestSprites.CardSeal));
            ApplySliced(frame, ChestSprites.BestFrame(), CardWidth);
        }

        private static VisualElement Make(string className)
        {
            var element = new VisualElement { pickingMode = PickingMode.Ignore };
            element.AddToClassList(className);
            return element;
        }

        private static void SetBackground(VisualElement element, Sprite sprite)
        {
            if (element == null || sprite == null) return;
            element.style.backgroundImage = new StyleBackground(sprite);
        }

        /// <summary>Fondo con el 9-slice real del sprite (el borde que midió el importador).</summary>
        private static void ApplySliced(VisualElement element, Sprite sprite, float cssWidth)
        {
            if (element == null || sprite == null) return;
            element.style.backgroundImage = new StyleBackground(sprite);

            Vector4 b = sprite.border;
            if (b == Vector4.zero) return;

            element.style.unitySliceLeft = Mathf.RoundToInt(b.x);
            element.style.unitySliceRight = Mathf.RoundToInt(b.z);
            element.style.unitySliceTop = Mathf.RoundToInt(b.w);
            element.style.unitySliceBottom = Mathf.RoundToInt(b.y);
            element.style.unitySliceScale = cssWidth / Mathf.Max(1f, sprite.rect.width);
        }

        // ── Estado de la fila ────────────────────────────────────────────────

        /// <summary>
        /// Pinta el estado del cofre. <paramref name="ready"/> = se puede cobrar (pose cerrada y
        /// latido), <paramref name="claimed"/> = ya cobrado (pose abierta), y
        /// <paramref name="amount"/> es la cifra que sale en la carta si se repite la apertura.
        /// </summary>
        public void Refresh(bool ready, bool claimed, int amount = 0)
        {
            if (_stage == null || _opening) return;

            if (amount > 0) _lastAmount = amount;

            // Pulsar el cofre repite la apertura en dos casos: ya cobrado (volver a verlo) o
            // todavía cerrado (ver lo que viene). Con el cofre LISTO para cobrar no: ahí el clic
            // es del botón, y abrirlo sin pagar confundiría.
            _replayable = claimed || !ready;
            _openPose = claimed;
            SetPose(claimed ? ChestSprites.PoseOpen : ChestSprites.PoseClosed);
            SetWaiting(ready && !claimed);

            _stage.EnableInClassList("prog-chest-stage-ready", ready && !claimed);
            _stage.EnableInClassList("prog-chest-stage-claimed", claimed);
            // Marca de "esto responde al clic", para que el USS sepa cuando pintar
            // hover y presion. Sale de _replayable (la misma fuente de verdad que
            // usa el handler del clic) y no de recalcular la condicion en CSS:
            // USS no soporta :not(), y duplicar la regla acá la desincronizaría
            // apenas cambiara el criterio de "reproducible".
            _stage.EnableInClassList("prog-chest-stage-clickable", _replayable);
        }

        private void SetPose(string name)
        {
            Sprite sprite = ChestSprites.Get(name);
            if (_art == null || sprite == null) return;
            _art.style.backgroundImage = new StyleBackground(sprite);
        }

        /// <summary>Latido suave del cofre cuando hay algo que cobrar. El vaivén lo hace el USS.</summary>
        private void SetPulse(bool on)
        {
            if (_art == null) return;

            if (on)
            {
                if (_pulse == null)
                {
                    _pulse = _art.schedule.Execute(() =>
                    {
                        _pulseOn = !_pulseOn;
                        float s = _pulseOn ? 1.03f : 0.985f;
                        _art.style.scale = new Scale(new Vector2(s, s));
                    }).Every(PulseMs);
                }
                _pulse.Resume();
            }
            else
            {
                _pulse?.Pause();
                _pulseOn = false;
                _art.style.scale = new Scale(Vector2.one);
            }
        }

        /// <summary>
        /// Estado de espera: el cofre está cerrado y hay algo que cobrar. Late en pantalla y suena
        /// su latido. Es el único sonido del set que no pertenece a la apertura, y por eso se
        /// enciende y se apaga con el estado de la fila y no con el guion.
        /// </summary>
        private void SetWaiting(bool on)
        {
            SetPulse(on);

            if (on) ChestAudio.StartIdle();
            else ChestAudio.StopIdle();
        }

        // ── Apertura y carta ────────────────────────────────────────────────

        /// <summary>
        /// Apertura del cofre y, al terminar, carta con el premio. <paramref name="amount"/> es lo
        /// que paga el cofre (los Gambits); con 0 o menos la carta sale sin cifra.
        /// </summary>
        public void Play(int amount, Action onDone = null)
        {
            if (_stage == null) return;

            _lastAmount = amount;
            _onDone = onDone;
            _opening = true;
            _openPose = false;
            _t = 0f;
            _cardT = -1f;
            _last = Time.unscaledTimeAsDouble;

            // Cortar antes de arrancar: si se repite la presentación, no debe quedar nada sonando.
            ChestAudio.StopAll();
            SetWaiting(false);
            _rewardOn = false;
            HideCard();
            SetPose(ChestSprites.PoseClosed);
            HideLayers();

            if (_tick == null) _tick = _stage.schedule.Execute(Tick).Every(TickMs);
            else _tick.Resume();
        }

        /// <summary>Corta la animación y deja el escenario en el estado que diga Refresh.</summary>
        public void Stop()
        {
            _tick?.Pause();
            _opening = false;
            _cardT = -1f;
            _rewardOn = false;
            _onDone = null;
            HideLayers();
            HideCard();
            SetWaiting(false);
            // Al cerrar el modal se corta también lo que esté a medio sonar.
            ChestAudio.StopAll();
        }

        private void Tick()
        {
            double now = Time.unscaledTimeAsDouble;
            float dt = (float)(now - _last);
            _last = now;
            if (dt < 0f) dt = 0f;
            if (dt > 0.20f) dt = 0.20f;      // si el editor se atasca, no saltar medio guion

            _t += dt;

            if (_opening)
            {
                if (!_openPose && _t >= PoseSwapAt)
                {
                    _openPose = true;
                    SetPose(ChestSprites.PoseOpen);
                }

                for (int i = 0; i < _layers.Count; i++) ApplyLayer(_layers[i]);

                if (_t >= OpeningSeconds)
                {
                    _opening = false;
                    HideLayers();
                    BeginCard();
                }
                return;
            }

            if (_cardT < 0f) return;

            _cardT += dt;
            UpdateCard();

            // El pago entra un poco después de la carta: el golpe seco del clip está ahí.
            if (!_rewardOn && _cardT >= RewardAt)
            {
                _rewardOn = true;
                ChestAudio.Play(ChestAudio.Reward, RewardGain);
            }

            if (_cardT >= CardIn + CardHold + CardOut)
            {
                _cardT = -1f;
                HideCard();
                _tick?.Pause();
                Action done = _onDone;
                _onDone = null;
                done?.Invoke();
            }
        }

        private void ApplyLayer(Layer layer)
        {
            if (layer.element == null) return;

            float p = (_t - layer.cue.start) / Mathf.Max(0.01f, layer.cue.duration);
            if (p < 0f || p > 1f)
            {
                if (layer.shown)
                {
                    layer.element.style.display = DisplayStyle.None;
                    layer.shown = false;
                }
                return;
            }

            // El sonido sale de ESTE mismo tic, no de un reloj aparte: así no se pueden
            // desincronizar aunque el editor se atasque. Se dispara antes de mirar los frames,
            // para que suene igual aunque falten sprites por importar.
            if (!layer.played)
            {
                layer.played = true;
                if (layer.cue.sfx != null) ChestAudio.Play(layer.cue.sfx, layer.cue.gain);
            }

            int count = layer.frames.Length;
            if (count == 0) return;

            if (!layer.shown)
            {
                layer.element.style.display = DisplayStyle.Flex;
                layer.shown = true;
            }

            float q = Mathf.Lerp(layer.cue.from, layer.cue.to, p);
            int index = Mathf.Clamp((int)(q * count), 0, count - 1);
            if (index == layer.index) return;

            layer.index = index;
            layer.element.style.backgroundImage = new StyleBackground(layer.frames[index]);
        }

        private void HideLayers()
        {
            foreach (Layer layer in _layers)
            {
                if (layer.element == null) continue;
                layer.element.style.display = DisplayStyle.None;
                layer.shown = false;
                layer.index = -1;
                layer.played = false;
            }
        }

        private void BeginCard()
        {
            if (_overlay == null)
            {
                Action done = _onDone;
                _onDone = null;
                _tick?.Pause();
                done?.Invoke();
                return;
            }

            if (_amount != null)
                _amount.text = _lastAmount > 0 ? $"+{_lastAmount:N0}" : "";

            ChestAudio.Play(ChestAudio.Card, CardGain);

            _cardT = 0f;
            _overlay.style.display = DisplayStyle.Flex;
            UpdateCard();
        }

        private void UpdateCard()
        {
            float scale;
            float alpha;

            if (_cardT < CardIn)
            {
                float k = Mathf.Clamp01(_cardT / CardIn);
                float eased = 1f - Mathf.Pow(1f - k, 3f);          // entra frenando
                scale = Mathf.Lerp(0.55f, 1.06f, eased);
                alpha = k;
            }
            else if (_cardT < CardIn + CardHold)
            {
                float k = Mathf.Clamp01((_cardT - CardIn) / 0.18f); // se asienta
                scale = Mathf.Lerp(1.06f, 1f, k);
                alpha = 1f;
            }
            else
            {
                float k = Mathf.Clamp01((_cardT - CardIn - CardHold) / CardOut);
                scale = Mathf.Lerp(1f, 0.98f, k);
                alpha = 1f - k;
            }

            if (_card == null) return;
            _card.style.scale = new Scale(new Vector2(scale, scale));
            _card.style.opacity = alpha;
        }

        private void HideCard()
        {
            if (_overlay != null) _overlay.style.display = DisplayStyle.None;
        }
    }
}
