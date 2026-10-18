using System.Collections;
using System.Text;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Selector de arena: se llega desde el menu principal despues de elegir modo.
    /// Las tarjetas (4 chicas, 4 medianas, 4 grandes) salen del <see cref="MapCatalog"/>;
    /// al elegir una se completa la ficha y "JUGAR" carga la Arena con ese mapa.
    /// Esc / Start vuelve al menu.
    /// </summary>
    public class MapSelectController : MonoBehaviour
    {
        [Header("Datos")]
        public MapCatalog catalog;

        [Header("Tarjetas")]
        public MapSelectCard[] cards;

        [Header("Cabecera")]
        public Text headerTitle;
        public Text headerMode;

        [Header("Ficha del mapa")]
        public CanvasGroup info;
        public Image infoPreview;
        public Text infoTitle;
        public Text infoSubtitle;
        public Text infoMeta;
        public Text infoHazards;
        public Text infoDecor;

        [Header("Acciones")]
        public Button playButton;
        public Text playLabel;

        [Header("Fundido")]
        public CanvasGroup fader;
        public float fadeTime = 0.45f;

        public int SelectedIndex { get; private set; } = -1;
        public MapSelectCard[] Cards => cards;

        private bool _loading;
        private static readonly StringBuilder Sb = new StringBuilder();

        private static readonly string[] HazardNames =
        {
            "DERRUMBE", "ZONA", "ONDA", "ARCO", "VENDAVAL", "LLUVIA DORADA", "FUEGO", "FRIO",
        };

        void Start()
        {
            Time.timeScale = 1f;

            if (catalog != null && catalog.Count > 0)
            {
                if (headerTitle != null) headerTitle.text = "ELEGI TU ARENA";
                if (headerMode != null) headerMode.text = ModeText(GameSession.Mode);

                BindCards();

                int index = GameSession.SelectedMap;
                if (index < 0 || index >= catalog.Count) index = PreferredIndex();
                Select(index);
            }
            else
            {
                Debug.LogWarning("[WildWeapon] El selector de mapas no tiene catalogo (corre el builder).");
                if (infoDecor != null) infoDecor.text = "Falta el catalogo de arenas: reconstrui el juego desde el editor.";
            }

            if (playButton != null) playButton.interactable = catalog != null && catalog.Count > 0;
            if (fader != null) StartCoroutine(Fade(1f, 0f, null));
        }

        private void BindCards()
        {
            if (cards == null) return;
            for (int i = 0; i < cards.Length; i++)
            {
                var card = cards[i];
                if (card == null) continue;
                card.owner = this;
                card.index = i;
                card.Bind(catalog.Get(i));
            }
        }

        /// <summary>Mapa por defecto del modo (el jugador puede cambiarlo en la grilla).</summary>
        private int PreferredIndex()
        {
            var size = GameSession.Mode == GameMode.Bots ? MapSizeClass.Mediano : MapSizeClass.Chico;
            return catalog.FirstOf(size);
        }

        public static string ModeText(GameMode mode)
        {
            switch (mode)
            {
                case GameMode.Bots: return "SUPERVIVENCIA";
                case GameMode.Pvp: return "PVP ONLINE";
                default: return "DUELO 1 VS 1";
            }
        }

        /// <summary>Click en una tarjeta: la primera vez elige, la segunda juega.</summary>
        public void Pick(int index)
        {
            if (_loading) return;
            if (index == SelectedIndex) { Play(); return; }
            Select(index);
        }

        public void Highlight(int index)
        {
            if (catalog == null || index < 0 || index >= catalog.Count) return;
            FillInfo(catalog.Get(index));
        }

        public void Select(int index)
        {
            if (catalog == null || catalog.Count == 0) return;
            SelectedIndex = Mathf.Clamp(index, 0, catalog.Count - 1);
            GameSession.SelectedMap = SelectedIndex;
            FillInfo(catalog.Get(SelectedIndex));
        }

        private void FillInfo(MapDef def)
        {
            if (def == null) return;

            if (infoTitle != null) infoTitle.text = def.displayName.ToUpperInvariant();
            if (infoSubtitle != null) infoSubtitle.text = def.subtitle;
            if (info != null) info.alpha = 1f;
            if (infoPreview != null)
            {
                infoPreview.sprite = def.previewSprite != null ? def.previewSprite : def.floorSprite;
                infoPreview.color = Color.white;
                infoPreview.enabled = infoPreview.sprite != null;
            }

            int platforms = DeckCount(def);
            int hazards = def.hazards != null ? def.hazards.Length : 0;
            if (infoMeta != null)
            {
                infoMeta.text = string.Format("{0}  ·  {1:0.#}x{2:0.#}  ·  {3} PLATAFORMA{4}  ·  {5} PELIGRO{6}",
                    MapSelectCard.SizeText(def.sizeClass), def.arenaSize.x, def.arenaSize.y,
                    platforms, platforms == 1 ? "" : "S", hazards, hazards == 1 ? "" : "S");
            }

            if (infoHazards != null) infoHazards.text = HazardList(def);
            if (infoDecor != null) infoDecor.text = string.IsNullOrEmpty(def.decorNote) ? "DECORACION DEL TEMA" : def.decorNote.ToUpperInvariant();

            if (playButton != null) playButton.interactable = true;
            if (playLabel != null) playLabel.text = "JUGAR " + def.displayName.ToUpperInvariant();
        }

        /// <summary>Decks que vera la partida: fuera de Supervivencia los pares espejados cuentan doble.</summary>
        private static int DeckCount(MapDef def)
        {
            if (def.platforms == null) return 0;
            bool mirror = def.mirroredForDuel && GameSession.Mode != GameMode.Bots;
            int n = 0;
            foreach (var pl in def.platforms) n += mirror && pl.mirrored ? 2 : 1;
            return n;
        }

        private static string HazardList(MapDef def)
        {
            Sb.Length = 0;
            Sb.Append("PELIGROS: ");
            if (def.hazards == null || def.hazards.Length == 0) { Sb.Append("NINGUNO"); return Sb.ToString(); }
            for (int i = 0; i < def.hazards.Length; i++)
            {
                if (i > 0) Sb.Append("  ·  ");
                int k = (int)def.hazards[i].kind;
                Sb.Append(k >= 0 && k < HazardNames.Length ? HazardNames[k] : def.hazards[i].kind.ToString().ToUpperInvariant());
            }
            return Sb.ToString();
        }

        /// <summary>Lanza la partida con el mapa elegido.</summary>
        public void Play()
        {
            if (_loading || catalog == null || catalog.Count == 0) return;
            if (SelectedIndex < 0) return;
            _loading = true;
            GameSession.SelectedMap = SelectedIndex;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.ArenaScene)));
        }

        /// <summary>Vuelve al menu principal sin fundido de arena.</summary>
        public void Back()
        {
            if (_loading) return;
            _loading = true;
            StartCoroutine(Fade(0f, 1f, () => SceneManager.LoadScene(GameSession.MenuScene)));
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
                return;
            }

            if ((kb != null && (kb.enterKey.wasPressedThisFrame || kb.numpadEnterKey.wasPressedThisFrame || kb.spaceKey.wasPressedThisFrame)) ||
                (pad != null && pad.buttonSouth.wasPressedThisFrame))
            {
                Play();
            }
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
    }
}
