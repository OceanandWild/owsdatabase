using System.Collections;
using UnityEngine;
using UnityEngine.UI;
using WildWeapon.UI;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Overlay "PVP ONLINE" del menu principal: conecta con el server,
    /// entra a la cola de emparejamiento y carga la Arena cuando llega el rival.
    /// La UI se arma por codigo para no depender de la escena; las pieles
    /// (<see cref="PvpOverlaySkin"/>) las inyecta el builder y, si faltan,
    /// el overlay cae al look plano de siempre.
    /// </summary>
    public class PvpQuickmatchPanel : MonoBehaviour
    {
        private static PvpQuickmatchPanel _current;

        public static void Open(MainMenuController menu)
        {
            if (_current != null) return;
            var go = new GameObject("[PvpQuickmatch]");
            DontDestroyOnLoad(go);
            _current = go.AddComponent<PvpQuickmatchPanel>();
            _current.Build(menu);
        }

        // Mismo lenguaje de color que el menu: acero frio + acento violeta del modo PVP.
        private static readonly Color Steel = new Color(0.80f, 0.84f, 0.92f);
        private static readonly Color Accent = new Color(0.72f, 0.45f, 1f);
        private static readonly Color Gold = new Color(1f, 0.82f, 0.35f);
        private static readonly Vector2 PanelSize = new Vector2(900f, 380f);

        private MainMenuController _menu;
        private PvpClient _client;
        private Text _status;
        private Text _sub;
        private Button _cancelButton;
        private Text _cancelLabel;
        private CanvasGroup _dim;
        private RectTransform _panelRt;
        private Image _radar;
        private Image _shine;

        private float _radarSpeed = 34f;
        private float _radarTargetSpeed = 34f;
        private float _radarAlpha = 0.10f;
        private float _radarTargetAlpha = 0.10f;
        private float _shineT = -1.4f;
        private bool _closing;

        void OnDestroy()
        {
            if (_client != null) _client.Message -= OnMessage;
            if (_current == this) _current = null;
        }

        // =================================================================
        // Flujo
        // =================================================================

        private void Build(MainMenuController menu)
        {
            _menu = menu;
            BuildUi();

            _client = PvpClient.Ensure();
            _client.Message += OnMessage;

            if (_client.IsConnected)
            {
                JoinQueue();
            }
            else
            {
                RadarMood(34f, 0.12f);
                SetStatus("CONECTANDO...", "Contactando al servidor de duelos...");
                _client.Connect();
                StartCoroutine(WaitConnection());
            }
        }

        private IEnumerator WaitConnection()
        {
            float t = 0f;
            while (t < 12f && !_client.IsConnected)
            {
                t += Time.unscaledDeltaTime;
                if (!string.IsNullOrEmpty(_client.LastError))
                {
                    RadarMood(12f, 0.08f);
                    SetStatus("SIN CONEXION", "No se pudo conectar al servidor PVP. Intenta de nuevo.");
                    SetCancelLabel("VOLVER");
                    yield break;
                }
                yield return null;
            }

            if (_closing) yield break;
            if (_client.IsConnected) JoinQueue();
            else
            {
                RadarMood(12f, 0.08f);
                SetStatus("SIN CONEXION", "No se pudo conectar al servidor PVP. Intenta de nuevo.");
            }
        }

        private void JoinQueue()
        {
            RadarMood(120f, 0.18f);
            SetStatus("BUSCANDO RIVAL...", "El duelo arranca apenas aparezca otro portador.");
            _client.Send(new PvpMsg
            {
                t = PvpMsgType.Join,
                name = GetPlayerName(),
                color = GameSession.GetColorIndex(0)
            });
        }

        private void OnMessage(PvpMsg m)
        {
            if (_closing) return;
            switch (m.t)
            {
                case PvpMsgType.Queued:
                    RadarMood(120f, 0.18f);
                    SetStatus("BUSCANDO RIVAL...",
                        m.n <= 1
                            ? "Sos el primero en la cola. El duelo arranca apenas llegue otro portador."
                            : $"Portadores en cola: {m.n}");
                    break;

                case PvpMsgType.Matched:
                    string oppName = m.opp != null && !string.IsNullOrEmpty(m.opp.name) ? m.opp.name : "RIVAL";
                    int oppColor = m.opp != null ? m.opp.color : 1;
                    GameSession.PvpOpps.Clear();
                    if (m.opps != null) GameSession.PvpOpps.AddRange(m.opps);
                    else if (m.opp != null) GameSession.PvpOpps.Add(m.opp);
                    RadarMood(300f, 0.30f);
                    SetStatus("RIVAL ENCONTRADO: " + oppName, "Preparando la arena...");
                    SetCancelLabel("");
                    StartCoroutine(StartMatchSoon(m.seat, oppName, oppColor, m.seed));
                    break;

                case PvpMsgType.Error:
                    RadarMood(20f, 0.10f);
                    SetStatus("AVISO", string.IsNullOrEmpty(m.msg) ? "Algo salio mal." : m.msg);
                    if (_client.IsConnected)
                    {
                        SetCancelLabel("");
                    }
                    break;
            }
        }

        private IEnumerator StartMatchSoon(int seat, string oppName, int oppColor, int seed)
        {
            yield return new WaitForSecondsRealtime(1.3f);
            var menu = _menu;
            Close(false);
            if (menu != null) menu.StartPvpMatch(seat, oppName, oppColor, seed);
        }

        public void Cancel()
        {
            Close(true);
        }

        private void Close(bool disconnect)
        {
            if (_closing) return;
            _closing = true;

            if (_client != null)
            {
                _client.Message -= OnMessage;
                if (disconnect)
                {
                    if (_client.IsConnected) _client.Send(new PvpMsg { t = PvpMsgType.Leave });
                    _client.LeaveAndDisconnect();
                }
            }
            if (_current == this) _current = null;
            Destroy(gameObject);
        }

        private static string GetPlayerName()
        {
            const string key = "ww_pvp_name";
            string name = PlayerPrefs.GetString(key, "");
            if (string.IsNullOrEmpty(name))
            {
                name = "CYBORG-" + Random.Range(100, 999);
                PlayerPrefs.SetString(key, name);
                PlayerPrefs.Save();
            }
            return name;
        }

        // =================================================================
        // Presentacion (radar + barrido de luz)
        // =================================================================

        /// <summary>Velocidad/opacidad objetivo del radar segun el estado de la cola.</summary>
        private void RadarMood(float speed, float alpha)
        {
            _radarTargetSpeed = speed;
            _radarTargetAlpha = alpha;
        }

        void Update()
        {
            float dt = Time.unscaledDeltaTime;

            _radarSpeed = Mathf.MoveTowards(_radarSpeed, _radarTargetSpeed, dt * 260f);
            _radarAlpha = Mathf.MoveTowards(_radarAlpha, _radarTargetAlpha, dt * 1.4f);
            if (_radar != null)
            {
                _radar.rectTransform.Rotate(0f, 0f, -_radarSpeed * dt);
                var rc = _radar.color;
                rc.a = _radarAlpha;
                _radar.color = rc;
            }

            if (_status != null)
            {
                var sc = _status.color;
                sc.a = 0.86f + 0.14f * Mathf.Sin(Time.unscaledTime * 2.6f);
                _status.color = sc;
            }

            if (_shine != null)
            {
                _shineT += dt;
                const float period = 4.4f;   // barrido + pausa
                const float travel = 1.15f;  // duracion del barrido
                float k = Mathf.Repeat(_shineT, period) / travel;
                var c = _shine.color;
                c.a = k <= 1f ? Mathf.Sin(k * Mathf.PI) * 0.10f : 0f;
                _shine.color = c;
                _shine.rectTransform.anchoredPosition = new Vector2(
                    Mathf.Lerp(-PanelSize.x * 0.62f, PanelSize.x * 0.62f, k), 0f);
            }
        }

        // =================================================================
        // UI (por codigo)
        // =================================================================

        private void BuildUi()
        {
            var font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            var skin = FindFirstObjectByType<PvpOverlaySkin>();

            var canvasGo = new GameObject("Canvas", typeof(RectTransform));
            canvasGo.transform.SetParent(transform, false);
            var canvas = canvasGo.AddComponent<Canvas>();
            canvas.renderMode = RenderMode.ScreenSpaceOverlay;
            canvas.sortingOrder = 90;
            var scaler = canvasGo.AddComponent<CanvasScaler>();
            scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920f, 1080f);
            scaler.matchWidthOrHeight = 1f;
            canvasGo.AddComponent<GraphicRaycaster>();

            var dim = NewImage(canvasGo.transform, "Dim", null, new Color(0f, 0.02f, 0.05f, 0f));
            Stretch(dim.rectTransform);
            _dim = dim.gameObject.AddComponent<CanvasGroup>();
            _dim.alpha = 0f;

            // ---- Placa (skin de Flow o panel plano) ----
            bool hasPanelSkin = skin != null && skin.panel != null;
            var panel = NewImage(canvasGo.transform, "Panel",
                hasPanelSkin ? skin.panel : null,
                hasPanelSkin ? Color.Lerp(Steel, Accent, 0.26f) : new Color(0.02f, 0.03f, 0.06f, 0.94f));
            _panelRt = panel.rectTransform;
            _panelRt.anchorMin = _panelRt.anchorMax = new Vector2(0.5f, 0.5f);
            _panelRt.anchoredPosition = Vector2.zero;
            _panelRt.sizeDelta = PanelSize;
            if (!hasPanelSkin)
            {
                var outline = panel.gameObject.AddComponent<Outline>();
                outline.effectColor = new Color(0.35f, 0.85f, 1f, 0.55f);
                outline.effectDistance = new Vector2(3f, -3f);
            }
            panel.gameObject.AddComponent<RectMask2D>(); // recorta el barrido de luz
            _panelRt.localScale = new Vector3(0.94f, 0.94f, 1f);

            // ---- Radar fantasma (busqueda de rival) ----
            if (skin != null && skin.radar != null)
            {
                _radar = NewImage(panel.transform, "Radar", skin.radar,
                    new Color(Steel.r, Steel.g, Steel.b, 0f));
                _radar.raycastTarget = false;
                var rrt = _radar.rectTransform;
                rrt.anchorMin = rrt.anchorMax = new Vector2(0.5f, 0.5f);
                rrt.anchoredPosition = new Vector2(0f, 6f);
                rrt.sizeDelta = new Vector2(300f, 300f);
            }

            // ---- Titulo + regla ----
            var title = NewText(panel.transform, "Title", font, "PVP ONLINE", 46, Gold);
            var titleRt = title.rectTransform;
            titleRt.anchorMin = new Vector2(0f, 1f);
            titleRt.anchorMax = new Vector2(1f, 1f);
            titleRt.pivot = new Vector2(0.5f, 1f);
            titleRt.anchoredPosition = new Vector2(0f, -26f);
            titleRt.sizeDelta = new Vector2(-40f, 58f);
            var titleShadow = title.gameObject.AddComponent<Shadow>();
            titleShadow.effectColor = new Color(0f, 0f, 0f, 0.85f);
            titleShadow.effectDistance = new Vector2(2f, -3f);

            bool hasRuleSkin = skin != null && skin.rule != null;
            var ruleColor = Color.Lerp(Steel, Accent, 0.55f);
            var rule = NewImage(panel.transform, "Rule",
                hasRuleSkin ? skin.rule : null,
                hasRuleSkin ? new Color(ruleColor.r, ruleColor.g, ruleColor.b, 0.85f)
                            : new Color(Steel.r, Steel.g, Steel.b, 0.22f));
            rule.raycastTarget = false;
            var ruleRt = rule.rectTransform;
            ruleRt.anchorMin = ruleRt.anchorMax = new Vector2(0.5f, 1f);
            ruleRt.pivot = new Vector2(0.5f, 1f);
            ruleRt.anchoredPosition = new Vector2(0f, -94f);
            ruleRt.sizeDelta = hasRuleSkin ? new Vector2(340f, 16f) : new Vector2(320f, 2f);

            // ---- Estado + bajada ----
            _status = NewText(panel.transform, "Status", font, "", 42, Color.white);
            var statusRt = _status.rectTransform;
            statusRt.anchorMin = new Vector2(0f, 1f);
            statusRt.anchorMax = new Vector2(1f, 1f);
            statusRt.pivot = new Vector2(0.5f, 1f);
            statusRt.anchoredPosition = new Vector2(0f, -120f);
            statusRt.sizeDelta = new Vector2(-56f, 56f);
            _status.horizontalOverflow = HorizontalWrapMode.Wrap;
            _status.resizeTextForBestFit = true;
            _status.resizeTextMinSize = 26;
            _status.resizeTextMaxSize = 42;
            var statusShadow = _status.gameObject.AddComponent<Shadow>();
            statusShadow.effectColor = new Color(0f, 0f, 0f, 0.65f);
            statusShadow.effectDistance = new Vector2(2f, -2f);

            _sub = NewText(panel.transform, "Sub", font, "", 23, new Color(1f, 1f, 1f, 0.68f));
            var subRt = _sub.rectTransform;
            subRt.anchorMin = new Vector2(0f, 1f);
            subRt.anchorMax = new Vector2(1f, 1f);
            subRt.pivot = new Vector2(0.5f, 1f);
            subRt.anchoredPosition = new Vector2(0f, -184f);
            subRt.sizeDelta = new Vector2(-120f, 84f);
            _sub.horizontalOverflow = HorizontalWrapMode.Wrap;

            // ---- Boton de cancelar ----
            bool hasButtonSkin = skin != null && skin.button != null;
            var buttonTint = Color.Lerp(Steel, Accent, 0.42f);
            var btnImg = NewImage(panel.transform, "Cancel",
                hasButtonSkin ? skin.button : null,
                hasButtonSkin ? new Color(buttonTint.r, buttonTint.g, buttonTint.b, 0.98f)
                              : new Color(0.05f, 0.08f, 0.12f, 0.92f));
            var btnRt = btnImg.rectTransform;
            btnRt.anchorMin = btnRt.anchorMax = new Vector2(0.5f, 0f);
            btnRt.pivot = new Vector2(0.5f, 0f);
            btnRt.anchoredPosition = new Vector2(0f, 26f);
            btnRt.sizeDelta = new Vector2(320f, 64f);
            if (!hasButtonSkin)
            {
                var btnOutline = btnImg.gameObject.AddComponent<Outline>();
                btnOutline.effectColor = new Color(1f, 0.5f, 0.3f, 0.55f);
                btnOutline.effectDistance = new Vector2(2f, -2f);
            }
            _cancelButton = btnImg.gameObject.AddComponent<Button>();
            _cancelButton.transition = Selectable.Transition.ColorTint;
            var colors = _cancelButton.colors;
            colors.normalColor = Color.white;
            colors.highlightedColor = new Color(1.18f, 1.18f, 1.22f);
            colors.pressedColor = new Color(0.82f, 0.82f, 0.88f);
            colors.disabledColor = new Color(0.55f, 0.55f, 0.6f);
            _cancelButton.colors = colors;
            _cancelButton.onClick.AddListener(Cancel);

            var fx = btnImg.gameObject.AddComponent<MenuButtonFx>();
            fx.hoverScale = 1.05f;
            fx.normalColor = new Color(1f, 1f, 1f, 0.96f);
            fx.hoverColor = Gold;

            _cancelLabel = NewText(btnImg.transform, "Label", font, "CANCELAR", 28, Color.white);
            Stretch(_cancelLabel.rectTransform);
            var labelShadow = _cancelLabel.gameObject.AddComponent<Shadow>();
            labelShadow.effectColor = new Color(0f, 0f, 0f, 0.7f);
            labelShadow.effectDistance = new Vector2(1.5f, -2f);
            fx.label = _cancelLabel;

            // ---- Barrido de brillo (recortado por el mask de la placa) ----
            if (skin != null && skin.shine != null)
            {
                _shine = NewImage(panel.transform, "Shine", skin.shine, new Color(1f, 1f, 1f, 0f));
                _shine.raycastTarget = false;
                var srt = _shine.rectTransform;
                srt.anchorMin = srt.anchorMax = new Vector2(0.5f, 0.5f);
                srt.anchoredPosition = new Vector2(-PanelSize.x * 0.62f, 0f);
                srt.sizeDelta = new Vector2(120f, PanelSize.y * 1.5f);
                srt.localRotation = Quaternion.Euler(0f, 0f, -18f);
            }

            StartCoroutine(Intro());
        }

        /// <summary>Entrada del modal: fundido del fondo + pop de la placa.</summary>
        private IEnumerator Intro()
        {
            const float duration = 0.34f;
            float t = 0f;
            while (t < 1f)
            {
                t = Mathf.Min(1f, t + Time.unscaledDeltaTime / duration);
                float e = 1f - Mathf.Pow(1f - t, 3f);
                if (_dim != null) _dim.alpha = 0.8f * e;
                if (_panelRt != null)
                {
                    float s = Mathf.Lerp(0.94f, 1f, e);
                    _panelRt.localScale = new Vector3(s, s, 1f);
                }
                yield return null;
            }
        }

        private void SetStatus(string status, string sub)
        {
            if (_status != null) _status.text = status;
            if (_sub != null) _sub.text = sub;
        }

        private void SetCancelLabel(string text)
        {
            if (_cancelLabel != null) _cancelLabel.text = text;
            if (_cancelButton != null) _cancelButton.gameObject.SetActive(!string.IsNullOrEmpty(text));
        }

        private static Image NewImage(Transform parent, string name, Sprite sprite, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Image));
            go.transform.SetParent(parent, false);
            var img = go.GetComponent<Image>();
            img.sprite = sprite;
            img.color = color;
            img.raycastTarget = true;
            return img;
        }

        private static Text NewText(Transform parent, string name, Font font, string value, int size, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Text));
            go.transform.SetParent(parent, false);
            var t = go.GetComponent<Text>();
            t.font = font;
            t.text = value;
            t.fontSize = size;
            t.fontStyle = FontStyle.Bold;
            t.alignment = TextAnchor.MiddleCenter;
            t.color = color;
            t.raycastTarget = false;
            return t;
        }

        private static void Stretch(RectTransform rt)
        {
            rt.anchorMin = Vector2.zero;
            rt.anchorMax = Vector2.one;
            rt.offsetMin = Vector2.zero;
            rt.offsetMax = Vector2.zero;
        }
    }
}
