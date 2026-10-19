using System.Collections;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Lobby multijugador local: se arma el plantel (nombre, color, control y equipo)
    /// antes de elegir la arena. La lista usa scroll (hasta <see cref="MaxPlayers"/>
    /// jugadores) y cada fila se construye por codigo con la grilla de
    /// <see cref="LobbyLayout"/>: el encabezado de columnas y las filas comparten los
    /// mismos numeros, asi quedan alineados. Esc / Start vuelve al menu principal.
    /// </summary>
    public class MultiplayerLobbyController : MonoBehaviour
    {
        public const int MaxPlayers = 15;

        /// <summary>Controles ofrecidos, en el orden que guarda <see cref="GameSession.PlayerSlot.controlIndex"/>.</summary>
        public static readonly string[] ControlNames = { "TECLADO", "PAD 1", "PAD 2", "PAD 3", "PAD 4" };
        /// <summary>Equipos ofrecidos, en el orden que guarda <see cref="GameSession.PlayerSlot.team"/>.</summary>
        public static readonly string[] TeamNames = { "EQUIPO A", "EQUIPO B", "EQUIPO C", "EQUIPO D" };

        [Header("Lista")]
        public RectTransform listContent;
        public ScrollRect listScroll;
        [Tooltip("Placa 9-slice de las filas (Art/VFX/ui_panel).")]
        public Sprite rowPlate;
        [Tooltip("Circulo suave para el color del jugador (Art/VFX/soft_circle).")]
        public Sprite orbSprite;

        [Header("Textos")]
        public Text subLabel;
        public Text footHint;
        public Text countLabel;

        [Header("Botones")]
        public Button addButton;
        public Button removeButton;
        public Button continueButton;
        public Button backButton;

        [Header("Fundido")]
        public CanvasGroup fader;
        public float fadeTime = 0.45f;

        [Header("Paleta")]
        public Color[] palette = GameSession.Palette;

        // Tints de las piezas internas (mismo lenguaje que el menu: acero frio + acento).
        private static readonly Color RowTint = new Color(0.07f, 0.09f, 0.13f, 0.92f);
        private static readonly Color FieldTint = new Color(0.02f, 0.03f, 0.05f, 0.90f);
        private static readonly Color StepTint = new Color(0.10f, 0.13f, 0.19f, 0.96f);
        private static readonly Color LabelDim = new Color(1f, 1f, 1f, 0.58f);
        private static readonly Color ReadyText = new Color(0.62f, 0.85f, 1f, 0.85f);
        private static readonly Color WarnText = new Color(1f, 0.72f, 0.30f, 0.90f);

        private Font _font;
        private bool _loading;

        void Start()
        {
            Time.timeScale = 1f;
            if (_font == null) _font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");

            if (GameSession.MultiPlayers.Count == 0)
            {
                // Plantel por defecto: dos jugadores (los colores 0 y 1 de la paleta).
                GameSession.MultiPlayers.Add(new GameSession.PlayerSlot { name = "Jugador 1", colorIndex = 0, controlIndex = 0, team = 0 });
                GameSession.MultiPlayers.Add(new GameSession.PlayerSlot { name = "Jugador 2", colorIndex = 1, controlIndex = 1, team = 1 });
            }

            if (addButton != null) addButton.onClick.AddListener(AddPlayer);
            if (removeButton != null) removeButton.onClick.AddListener(RemoveLast);
            if (continueButton != null) continueButton.onClick.AddListener(Continue);
            if (backButton != null) backButton.onClick.AddListener(Back);

            Rebuild();
            if (fader != null) StartCoroutine(Fade(1f, 0f, null));
        }

        void Update()
        {
            if (_loading) return;
            var kb = Keyboard.current;
            var pad = Gamepad.current;
            if ((kb != null && (kb.escapeKey.wasPressedThisFrame || kb.backspaceKey.wasPressedThisFrame)) ||
                (pad != null && pad.selectButton.wasPressedThisFrame))
            {
                Back();
            }
        }

        // =================================================================
        // Lista
        // =================================================================

        private void Rebuild()
        {
            if (listContent != null)
            {
                for (int i = listContent.childCount - 1; i >= 0; i--)
                {
                    var child = listContent.GetChild(i).gameObject;
                    child.SetActive(false);       // fuera del layout antes de destruirse
                    Destroy(child);
                }

                for (int i = 0; i < GameSession.MultiPlayers.Count; i++) BuildRow(i);
                LayoutRebuilder.ForceRebuildLayoutImmediate(listContent);
            }

            RefreshStatus();
        }

        private void BuildRow(int index)
        {
            var slot = GameSession.MultiPlayers[index];
            var color = ColorOf(slot.colorIndex);

            var row = NewRect(listContent, "Row" + (index + 1).ToString("00"), 0f, 0f, 0f, LobbyLayout.RowH);
            var rowRt = (RectTransform)row.transform;
            rowRt.sizeDelta = new Vector2(0f, LobbyLayout.RowH);   // el ancho lo define el layout
            var layout = row.gameObject.AddComponent<LayoutElement>();
            layout.minHeight = layout.preferredHeight = LobbyLayout.RowH;
            layout.flexibleHeight = 0f;

            // Placa de la fila
            var plate = NewImage(row.transform, "Bg", rowPlate, RowTint);
            Stretch(plate.rectTransform);
            if (rowPlate != null) { plate.type = Image.Type.Sliced; plate.pixelsPerUnitMultiplier = 3f; }

            // Barra de acento con el color del jugador
            var bar = NewImage(row.transform, "Accent", rowPlate, color);
            Rect(bar.rectTransform, LobbyLayout.BarX, LobbyLayout.BarH * 0f, LobbyLayout.BarW, LobbyLayout.BarH);
            if (rowPlate != null) { bar.type = Image.Type.Sliced; bar.pixelsPerUnitMultiplier = 8f; }

            // Orbe de color: click para pasar al siguiente color de la paleta
            var colorRt = NewRect(row.transform, "Color", LobbyLayout.ColorX - LobbyLayout.ColorButtonSize * 0.5f,
                0f, LobbyLayout.ColorButtonSize, LobbyLayout.ColorButtonSize);
            var colorBtn = colorRt.gameObject.AddComponent<Button>();
            colorBtn.transition = Selectable.Transition.ColorTint;
            colorBtn.colors = Highlighted();

            var glow = NewImage(colorRt, "Glow", orbSprite, new Color(color.r, color.g, color.b, 0.30f));
            Centered(glow.rectTransform, LobbyLayout.ColorGlowSize, LobbyLayout.ColorGlowSize);
            var orb = NewImage(colorRt, "Orb", orbSprite, color);
            Centered(orb.rectTransform, LobbyLayout.ColorSize, LobbyLayout.ColorSize);
            orb.raycastTarget = true;      // es el blanco del click (glow y barra no lo son)
            colorBtn.targetGraphic = orb;

            int idx = index;
            colorBtn.onClick.AddListener(() => CycleColor(idx, orb, glow, bar));

            // Nombre (campo editable)
            var nameRt = NewRect(row.transform, "Name", LobbyLayout.NameX, 0f, LobbyLayout.NameW, LobbyLayout.FieldH);
            var nameBg = NewImage(nameRt, "Bg", rowPlate, FieldTint);
            Stretch(nameBg.rectTransform);
            nameBg.raycastTarget = true;
            if (rowPlate != null) { nameBg.type = Image.Type.Sliced; nameBg.pixelsPerUnitMultiplier = 8f; }
            var nameOutline = nameBg.gameObject.AddComponent<Outline>();
            nameOutline.effectColor = new Color(0.35f, 0.80f, 1f, 0.20f);
            nameOutline.effectDistance = new Vector2(2f, -2f);

            var field = nameRt.gameObject.AddComponent<InputField>();
            field.targetGraphic = nameBg;
            field.lineType = InputField.LineType.SingleLine;
            field.characterLimit = 14;
            field.customCaretColor = true;
            field.caretColor = new Color(0.5f, 0.9f, 1f);
            field.selectionColor = new Color(0.30f, 0.85f, 1f, 0.35f);
            field.colors = Highlighted();

            var nameTxt = NewText(nameRt, "Text", slot.name, 19, new Color(0.92f, 0.95f, 1f));
            Rect(nameTxt.rectTransform, 14f, 0f, LobbyLayout.NameW - 28f, 30f);
            nameTxt.alignment = TextAnchor.MiddleLeft;
            nameTxt.supportRichText = false;
            field.textComponent = nameTxt;
            field.text = slot.name;
            field.onEndEdit.AddListener(v =>
            {
                if (idx < 0 || idx >= GameSession.MultiPlayers.Count) return;
                var s = GameSession.MultiPlayers[idx];
                s.name = string.IsNullOrWhiteSpace(v) ? s.name : v.Trim();
                field.text = s.name;
            });

            // Control y equipo: campos que ciclan con el click (sin desplegables que tapen la lista)
            var controlRt = NewRect(row.transform, "Control", LobbyLayout.ControlX, 0f, LobbyLayout.ControlW, LobbyLayout.FieldH);
            var controlValue = NewText(controlRt, "Value", ControlText(slot.controlIndex), 18, Color.white);
            Stretch(controlValue.rectTransform);
            controlValue.rectTransform.offsetMin = new Vector2(34f, 0f);
            controlValue.rectTransform.offsetMax = new Vector2(-34f, 0f);
            Stepper(controlRt, controlValue, () =>
            {
                slot.controlIndex = (slot.controlIndex + 1) % ControlNames.Length;
                controlValue.text = ControlText(slot.controlIndex);
            });

            var teamRt = NewRect(row.transform, "Team", LobbyLayout.TeamX, 0f, LobbyLayout.TeamW, LobbyLayout.FieldH);
            var teamValue = NewText(teamRt, "Value", TeamText(slot.team), 18, Color.white);
            Stretch(teamValue.rectTransform);
            teamValue.rectTransform.offsetMin = new Vector2(34f, 0f);
            teamValue.rectTransform.offsetMax = new Vector2(-34f, 0f);
            Stepper(teamRt, teamValue, () =>
            {
                slot.team = (slot.team + 1) % TeamNames.Length;
                teamValue.text = TeamText(slot.team);
            });

            // Numero de asiento, teñido con el color del jugador
            var seat = NewText(row.transform, "Seat", "J" + (index + 1), 17, color);
            Rect(seat.rectTransform, LobbyLayout.SeatX, 0f, LobbyLayout.SeatW, 26f);
            seat.alignment = TextAnchor.MiddleCenter;
        }

        /// <summary>Campo con flechas: cada click pasa al valor siguiente.</summary>
        private Button Stepper(RectTransform fieldRt, Text value, UnityEngine.Events.UnityAction cycle)
        {
            var bg = NewImage(fieldRt, "Bg", rowPlate, StepTint);
            bg.transform.SetAsFirstSibling();   // detras del valor y las flechas
            Stretch(bg.rectTransform);
            bg.raycastTarget = true;
            if (rowPlate != null) { bg.type = Image.Type.Sliced; bg.pixelsPerUnitMultiplier = 8f; }
            var outline = bg.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(1f, 1f, 1f, 0.10f);
            outline.effectDistance = new Vector2(2f, -2f);

            var btn = fieldRt.gameObject.AddComponent<Button>();
            btn.targetGraphic = bg;
            btn.colors = Highlighted();
            btn.onClick.AddListener(cycle);

            var left = NewText(fieldRt, "Left", "<", 20, LabelDim);
            Rect(left.rectTransform, 6f, 0f, 26f, 30f);
            left.alignment = TextAnchor.MiddleCenter;

            var right = NewText(fieldRt, "Right", ">", 20, LabelDim);
            Rect(right.rectTransform, fieldRt.sizeDelta.x - 32f, 0f, 26f, 30f);
            right.alignment = TextAnchor.MiddleCenter;

            value.raycastTarget = false;
            return btn;
        }

        // =================================================================
        // Acciones
        // =================================================================

        public void AddPlayer()
        {
            if (GameSession.MultiPlayers.Count >= MaxPlayers) return;
            int idx = GameSession.MultiPlayers.Count;
            GameSession.MultiPlayers.Add(new GameSession.PlayerSlot
            {
                name = "Jugador " + (idx + 1),
                colorIndex = idx % palette.Length,
                controlIndex = Mathf.Min(idx, ControlNames.Length - 1),
                team = idx % TeamNames.Length,
            });

            Rebuild();
            ScrollToNewest();
        }

        public void RemoveLast()
        {
            if (GameSession.MultiPlayers.Count <= 1) return;
            GameSession.MultiPlayers.RemoveAt(GameSession.MultiPlayers.Count - 1);
            Rebuild();
        }

        private void CycleColor(int idx, Image orb, Image glow, Image bar)
        {
            if (idx < 0 || idx >= GameSession.MultiPlayers.Count) return;
            var slot = GameSession.MultiPlayers[idx];
            slot.colorIndex = (slot.colorIndex + 1) % palette.Length;
            var color = ColorOf(slot.colorIndex);
            orb.color = color;
            glow.color = new Color(color.r, color.g, color.b, 0.30f);
            bar.color = color;
        }

        /// <summary>Rellena la fila desde afuera (lo usan las pruebas del editor).</summary>
        public void UpdateSlot(int index, string name, int colorIndex, int controlIndex, int team)
        {
            if (index < 0 || index >= GameSession.MultiPlayers.Count) return;
            var s = GameSession.MultiPlayers[index];
            s.name = name;
            s.colorIndex = colorIndex;
            s.controlIndex = controlIndex;
            s.team = team;
        }

        public void Continue()
        {
            if (_loading || GameSession.MultiPlayers.Count < 2) return;
            _loading = true;
            GameSession.Mode = GameMode.Multi;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MapSelectScene)));
        }

        public void Back()
        {
            if (_loading) return;
            _loading = true;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MenuScene)));
        }

        // =================================================================
        // Estado de los textos y de los botones
        // =================================================================

        private void RefreshStatus()
        {
            int n = GameSession.MultiPlayers.Count;

            if (subLabel != null) subLabel.text = "LOCAL · " + n + " / " + MaxPlayers + " JUGADORES";
            if (countLabel != null) countLabel.text = CountText(n);

            bool ready = n >= 2;
            if (footHint != null)
            {
                footHint.text = ready ? "LISTO PARA ARRANCAR" : "AGREGA OTRO JUGADOR PARA ARRANCAR";
                footHint.color = ready ? ReadyText : WarnText;
            }

            SetButton(addButton, n < MaxPlayers);
            SetButton(removeButton, n > 1);
            SetButton(continueButton, ready);
        }

        private static string CountText(int n)
        {
            int teams = 0;
            for (int t = 0; t < TeamNames.Length; t++)
            {
                foreach (var s in GameSession.MultiPlayers)
                    if (s.team == t) { teams++; break; }
            }
            return n + (n == 1 ? " JUGADOR" : " JUGADORES") + " · " + teams + (teams == 1 ? " EQUIPO" : " EQUIPOS");
        }

        /// <summary>Apaga el boton entero (placa + label) con un CanvasGroup, sin pelear con MenuButtonFx.</summary>
        private static void SetButton(Button b, bool on)
        {
            if (b == null) return;
            b.interactable = on;
            var group = b.GetComponent<CanvasGroup>();
            if (group == null) group = b.gameObject.AddComponent<CanvasGroup>();
            group.alpha = on ? 1f : 0.42f;
        }

        private static string ControlText(int index)
        {
            return ControlNames[Mathf.Clamp(index, 0, ControlNames.Length - 1)];
        }

        private static string TeamText(int index)
        {
            return TeamNames[Mathf.Clamp(index, 0, TeamNames.Length - 1)];
        }

        private Color ColorOf(int colorIndex)
        {
            if (palette == null || palette.Length == 0) return Color.white;
            return palette[Mathf.Clamp(colorIndex, 0, palette.Length - 1)];
        }

        private void ScrollToNewest()
        {
            if (listScroll == null || listContent == null) return;
            Canvas.ForceUpdateCanvases();
            var viewport = listScroll.viewport;
            if (viewport != null && listContent.rect.height > viewport.rect.height)
                listScroll.verticalNormalizedPosition = 0f;
        }

        private IEnumerator Fade(float from, float to, System.Action done)
        {
            if (fader != null)
            {
                fader.blocksRaycasts = true;
                float t = 0f;
                while (t < fadeTime)
                {
                    t += Time.unscaledDeltaTime;
                    fader.alpha = Mathf.Lerp(from, to, t / fadeTime);
                    yield return null;
                }
                fader.alpha = to;
                fader.blocksRaycasts = to > 0.5f;
            }
            done?.Invoke();
        }

        // =================================================================
        // Utilidades de UI por codigo
        // =================================================================

        private static readonly ColorBlock HighlightBlock = new ColorBlock
        {
            normalColor = Color.white,
            highlightedColor = new Color(1.22f, 1.26f, 1.34f, 1f),
            pressedColor = new Color(0.82f, 0.84f, 0.90f, 1f),
            selectedColor = new Color(1.22f, 1.26f, 1.34f, 1f),
            disabledColor = new Color(0.50f, 0.50f, 0.55f, 0.70f),
            colorMultiplier = 1f,
            fadeDuration = 0.1f,
        };

        private static ColorBlock Highlighted()
        {
            var b = HighlightBlock;
            b.colorMultiplier = 1f;
            return b;
        }

        /// <summary>hijo con rect anclado al borde izquierdo del padre (para columnas).</summary>
        private static RectTransform NewRect(Transform parent, string name, float x, float y, float w, float h)
        {
            var go = new GameObject(name, typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0f, 0.5f);
            rt.pivot = new Vector2(0f, 0.5f);
            rt.anchoredPosition = new Vector2(x, y);
            rt.sizeDelta = new Vector2(w, h);
            return rt;
        }

        private static void Rect(RectTransform rt, float x, float y, float w, float h)
        {
            rt.anchorMin = rt.anchorMax = new Vector2(0f, 0.5f);
            rt.pivot = new Vector2(0f, 0.5f);
            rt.anchoredPosition = new Vector2(x, y);
            rt.sizeDelta = new Vector2(w, h);
        }

        private static void Centered(RectTransform rt, float w, float h)
        {
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = Vector2.zero;
            rt.sizeDelta = new Vector2(w, h);
        }

        private static void Stretch(RectTransform rt)
        {
            rt.anchorMin = Vector2.zero;
            rt.anchorMax = Vector2.one;
            rt.offsetMin = Vector2.zero;
            rt.offsetMax = Vector2.zero;
        }

        private Image NewImage(Transform parent, string name, Sprite sprite, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Image));
            go.transform.SetParent(parent, false);
            var img = go.GetComponent<Image>();
            img.sprite = sprite;
            img.color = color;
            img.raycastTarget = false;
            return img;
        }

        private Text NewText(Transform parent, string name, string value, int size, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Text));
            go.transform.SetParent(parent, false);
            var t = go.GetComponent<Text>();
            if (_font == null) _font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            t.font = _font;
            t.text = value;
            t.fontSize = size;
            t.fontStyle = FontStyle.Bold;
            t.alignment = TextAnchor.MiddleCenter;
            t.color = color;
            t.raycastTarget = false;
            t.horizontalOverflow = HorizontalWrapMode.Overflow;
            t.verticalOverflow = VerticalWrapMode.Overflow;
            return t;
        }
    }
}
