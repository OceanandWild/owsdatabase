using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.UIElements;
using WildSea.Core;
using WildSea.Data;

namespace WildSea.UI
{
    /// <summary>
    /// Hub minimalista: 4 cards que ocupan toda la pantalla, cada una con su fondo
    /// y decoración, y el botón Volver abajo. Sin header, sin panel de detalle: el
    /// lore y los modos de cada Universo viven dentro de su propia card.
    /// Las cards se generan desde UniverseCatalog, así que agregar un Universo
    /// al catálogo las agrega en pantalla sin tocar este script.
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class WSUniverseHubUI : MonoBehaviour
    {
        public System.Action OnBackPressed;

        UIDocument doc;
        VisualElement root, hubTint, cardsRow;
        Label toast;
        IVisualElementScheduledItem toastHide;
        UniverseDef selected;
        int fitW = -1, fitH = -1;
        bool visible;
        public System.Action<string, string> OnPlayRequested;

        const string UxmlPath = "WS/Hub/Hub";

        void Awake() => doc = GetComponent<UIDocument>();

        void OnEnable()
        {
            if (doc.visualTreeAsset == null)
            {
                var tree = Resources.Load<VisualTreeAsset>(UxmlPath);
                if (tree != null) doc.visualTreeAsset = tree;
            }
            int tries = 0;
            IVisualElementScheduledItem wait = null;
            wait = doc.rootVisualElement.schedule.Execute(() =>
            {
                var r = doc.rootVisualElement;
                if (r != null && r.childCount > 0) { wait?.Pause(); Build(); }
                else if (++tries > 120) { wait?.Pause(); Debug.LogError("[WildSea] Hub: UXML nunca cargó."); }
            }).Every(16);
        }

        void Build()
        {
            var r = doc.rootVisualElement;
            if (r == null || r.childCount == 0) return;
            // UIDocument recrea el árbol visual en cada OnEnable: si el root guardado
            // ya no es el árbol vivo, hay que re-resolver y re-cablear desde cero.
            var live = r.Q<VisualElement>("hub-root");
            if (root != null && live == root) return;

            var sheet = Resources.Load<StyleSheet>(UxmlPath);
            if (sheet != null && r.styleSheets.count == 0) r.styleSheets.Add(sheet);

            root = live;
            if (root == null) return;
            root.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
            FitRoot();

            hubTint = r.Q<VisualElement>("hub-tint");
            cardsRow = r.Q<VisualElement>("hub-cards");
            toast = r.Q<Label>("hub-toast");

            var back = r.Q<Button>("btn-back");
            if (back != null) back.clicked += () => { WSAudio.Back(); OnBackPressed?.Invoke(); };

            BuildCards();
            Select(UniverseCatalog.GetById(WSSave.SelectedUniverseId));
            WSFontFix.Apply(root);
            root.schedule.Execute(() => root.AddToClassList("hub-root--ready")).StartingIn(50);
        }

        /// <summary>
        /// Monta una card por Universo. El orden de Add() es el orden de pintado:
        /// primero las capas decorativas (fondo, tinte, grano, marco, glow) y
        /// encima el contenido, que es lo único que recibe input.
        /// </summary>
        void BuildCards()
        {
            if (cardsRow == null) return;
            cardsRow.Clear();
            int i = 0;
            foreach (var u in UniverseCatalog.GetAll())
            {
                var card = BuildCard(u, Mathf.Min(++i, 4));
                if (card != null) cardsRow.Add(card);
            }
            MarkSelected();
            WSFontFix.Apply(cardsRow);
        }

        VisualElement BuildCard(UniverseDef u, int delayStep)
        {
            if (u == null) return null;

            var card = new VisualElement { name = $"card-{u.id}" };
            card.AddToClassList("uni-card");
            card.AddToClassList($"uni-card--{u.id}");  // USS: fondo propio del Universo
            card.AddToClassList($"uni-card--d{delayStep}");
            if (!u.unlockedInV1) card.AddToClassList("uni-card--locked");

            // Fondo: la imagen llega por la clase uni-card--{id} en Hub.uss.
            card.Add(Layer("uni-card-bg"));
            card.Add(Layer("uni-card-tint"));
            card.Add(Layer("uni-card-grain"));

            var glow = Layer("uni-card-glow");
            glow.style.borderTopColor = new StyleColor(u.accentColor);
            glow.style.borderBottomColor = new StyleColor(u.accentColor);
            glow.style.borderLeftColor = new StyleColor(u.accentColor);
            glow.style.borderRightColor = new StyleColor(u.accentColor);
            card.Add(glow);

            var body = new VisualElement { name = "body" };
            body.AddToClassList("uni-card-body");

            var icon = Text(u.iconGlyph, "icon", "uni-icon");
            body.Add(icon);

            body.Add(Text(u.isTeased ? "???" : u.displayName, "name", "uni-name"));
            body.Add(Layer("uni-rule"));
            body.Add(Text(u.tagline, "tagline", "uni-tag"));

            // El card de ???? no muestra modos: no tiene.
            var badges = ModesLine(u);
            if (!string.IsNullOrEmpty(badges)) body.Add(Text(badges, "badges", "uni-badges"));

            var state = Text(StateLine(u), "state", "uni-state");
            state.AddToClassList(u.unlockedInV1 ? "uni-state--active"
                              : u.isTeased ? "uni-state--soon"
                              : "uni-state--locked");
            body.Add(state);

            card.Add(body);

            var captured = u;
            card.RegisterCallback<ClickEvent>(_ => OnCardClicked(captured, card));
            card.RegisterCallback<PointerEnterEvent>(_ =>
            {
                WSAudio.Hover();
                if (captured.unlockedInV1 && hubTint != null)
                    hubTint.style.backgroundColor = new StyleColor(Tint(captured.bottomColor));
            });
            return card;
        }

        static VisualElement Layer(string ussClass)
        {
            var e = new VisualElement();
            e.AddToClassList(ussClass);
            e.pickingMode = PickingMode.Ignore;
            return e;
        }

        static Label Text(string content, string name, string ussClass)
        {
            var l = new Label(content) { name = name };
            l.AddToClassList(ussClass);
            l.pickingMode = PickingMode.Ignore;
            return l;
        }

        /// <summary>Todos los modos del Universo, no solo los dos primeros.</summary>
        static string ModesLine(UniverseDef u)
        {
            if (u.modes == null || u.modes.Length == 0) return string.Empty;
            var parts = new List<string>(u.modes.Length);
            foreach (var m in u.modes)
                if (m != null) parts.Add($"{m.iconGlyph} {m.displayName}");
            return string.Join("   ", parts);
        }

        static string StateLine(UniverseDef u)
            => u.unlockedInV1 ? "● ACTIVO" : u.isTeased ? "PRÓXIMAMENTE" : "🔒 BLOQUEADO";

        void OnCardClicked(UniverseDef u, VisualElement card)
        {
            if (!u.unlockedInV1)
            {
                WSAudio.Denied();
                Shake(card);
                ShowToast(u.isTeased ? "✦ Próximamente" : "🔒 Desbloquea en v2");
                return;
            }
            WSAudio.Confirm();
            Select(u);
            if (OnPlayRequested != null)
            {
                string mode = (WSSave.SelectedModeId == "galaxia" && HasMode(u, "galaxia")) ? "galaxia" : (u.modes != null && u.modes.Length > 0 ? u.modes[0].id : "estrella");
                OnPlayRequested.Invoke(u.id, mode);
            }
        }

        void Select(UniverseDef u)
        {
            selected = u;
            WSSave.SelectedUniverseId = u.id;
            if (hubTint != null) hubTint.style.backgroundColor = new StyleColor(Tint(u.bottomColor));
            MarkSelected();
        }

        void MarkSelected()
        {
            if (cardsRow == null) return;
            foreach (var c in cardsRow.Children())
                c.RemoveFromClassList("uni-card--selected");
            if (selected != null)
                cardsRow.Q<VisualElement>($"card-{selected.id}")?.AddToClassList("uni-card--selected");
        }

        // La raíz del panel no siempre tiene altura fija (overflow:hidden recortaba):
        // tamaño explícito = tamaño visible del panel en unidades.
        void FitRoot() => WSFit.Update(root, doc, ref fitW, ref fitH);

        void Update()
        {
            if (!visible) return;
            if (Screen.width != fitW || Screen.height != fitH) FitRoot();
            if (Keyboard.current != null && Keyboard.current.escapeKey.wasPressedThisFrame)
            {
                WSAudio.Back();
                OnBackPressed?.Invoke();
            }
            if (Keyboard.current != null && (Keyboard.current.enterKey.wasPressedThisFrame || Keyboard.current.numpadEnterKey.wasPressedThisFrame || Keyboard.current.spaceKey.wasPressedThisFrame))
            {
                if (selected != null && selected.unlockedInV1)
                {
                    string mode = (WSSave.SelectedModeId == "galaxia" && HasMode(selected, "galaxia")) ? "galaxia" : (selected.modes != null && selected.modes.Length > 0 ? selected.modes[0].id : "estrella");
                    WSAudio.Confirm();
                    OnPlayRequested?.Invoke(selected.id, mode);
                }
            }
        }

        static bool HasMode(UniverseDef u, string id)
        {
            if (u.modes == null) return false;
            foreach (var m in u.modes) if (m != null && m.id == id) return true;
            return false;
        }

        // No se desactiva el GameObject: UIDocument.OnEnable recrea el árbol visual y
        // se perderían el cableado y las cards. Se oculta con display:none.
        public void Show(bool v)
        {
            visible = v;
            gameObject.SetActive(true);
            if (root == null) return; // aún sin árbol: Build() aplicará visible al construirse
            root.style.display = v ? DisplayStyle.Flex : DisplayStyle.None;
            if (!v) return;
            fitW = -1; fitH = -1; FitRoot(); // re-forzar si el árbol se recreó al reactivar
            root.RemoveFromClassList("hub-root--ready");
            root.schedule.Execute(() => root.AddToClassList("hub-root--ready")).StartingIn(50);
            Select(UniverseCatalog.GetById(WSSave.SelectedUniverseId));
        }

        void ShowToast(string msg)
        {
            if (toast == null) return;
            toast.text = msg;
            toastHide?.Pause();
            toast.AddToClassList("hub-toast--visible");
            toastHide = toast.schedule.Execute(() => toast.RemoveFromClassList("hub-toast--visible")).StartingIn(1800);
        }

        static void Shake(VisualElement e)
        {
            if (e == null) return;
            int i = 0;
            IVisualElementScheduledItem s = null;
            s = e.schedule.Execute(() =>
            {
                if (++i >= 8) { e.style.translate = new Translate(0, 0); s?.Pause(); return; }
                float t = (float)i / 8;
                e.style.translate = new Translate(new Length(Mathf.Sin(t * Mathf.PI * 3f) * 10f * (1f - t), LengthUnit.Pixel), new Length(0, LengthUnit.Pixel));
            }).Every(35);
        }

        static Color Darken(Color c, float f) => new Color(c.r * f + 0.02f, c.g * f + 0.05f, c.b * f + 0.10f, 1f);

        /// <summary>
        /// Tinte del Universo activo sobre el fondo del Hub. Va con alfa para
        /// que la imagen de WS_bg_hub_deep se vea por debajo en vez de taparse.
        /// </summary>
        static Color Tint(Color c)
        {
            var d = Darken(c, 0.5f);
            d.a = 0.38f;
            return d;
        }
    }
}
