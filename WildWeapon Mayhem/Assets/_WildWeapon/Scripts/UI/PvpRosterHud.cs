using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;
using WildWeapon.Pvp;

namespace WildWeapon.UI
{
    /// <summary>
    /// Tablero compacto de la sala PVP. Va **pegado a la esquina superior izquierda**
    /// para no tapar la franja de abajo: esa franja queda libre para el panel de
    /// habilidades del arma equipada.
    ///
    /// - Con equipos: una fila por equipo con la letra, el marcador de ronda y un
    ///   disco por combatiente (vivo = color del personaje, muerto = apagado, el
    ///   local con anillo blanco).
    /// - En todos contra todos: tabla corta por bajas (hasta 8 filas, mas la del
    ///   local si no entra).
    ///
    /// Se construye en runtime sobre el canvas del HUD: no toca la escena.
    /// </summary>
    public class PvpRosterHud : MonoBehaviour
    {
        // Medidas del tablero (canvas de referencia 1920x1080).
        private const float BoardW = 268f;
        private const float RowH = 20f;
        private const float HeaderH = 13f;
        private const int PadX = 9;
        private const int PadY = 7;
        private const float DiscSize = 20f;      // disco del combatiente
        private const float DiscGap = 4f;
        private const int MaxFfaRows = 8;         // filas de la tabla (mas la del local)

        private static readonly Color Ink = new Color(0.05f, 0.07f, 0.10f, 1f);
        private static readonly Color TextMain = new Color(1f, 1f, 1f, 0.92f);
        private static readonly Color TextDim = new Color(1f, 1f, 1f, 0.42f);
        private static readonly Color Dead = new Color(0.34f, 0.38f, 0.46f, 0.80f);
        private static readonly Color PanelFill = new Color(0.05f, 0.07f, 0.10f, 0.80f);

        private class TeamRow
        {
            public int team;
            public Text score;
            public List<Image> discs = new List<Image>();
            public List<PlayerHealth> members = new List<PlayerHealth>();
            public List<Color> accents = new List<Color>();
        }

        private class FfaRow
        {
            public int seat;
            public PlayerHealth health;
            public Color accent;
            public Text name;
            public Text kills;
            public Image disc;
        }

        private PvpMatchManager _mgr;
        private Font _font;
        private RectTransform _root;
        private RectTransform _content;
        private Text _caption;
        private Text _hint;

        private readonly List<TeamRow> _teams = new List<TeamRow>();
        private readonly List<FfaRow> _ffa = new List<FfaRow>();
        private int _signature = int.MinValue;

        // Sprites generados en runtime (una sola vez por sesion de play).
        private static Sprite _frameSprite, _circleSprite, _roundedSprite;

        // =================================================================
        // Alta
        // =================================================================

        public static PvpRosterHud Create(Transform canvas, Font font, PvpMatchManager mgr)
        {
            var go = new GameObject("PvpRosterHud", typeof(RectTransform));
            go.transform.SetParent(canvas, false);
            var hud = go.AddComponent<PvpRosterHud>();
            hud.Build(mgr, font);
            return hud;
        }

        private void Build(PvpMatchManager mgr, Font font)
        {
            _mgr = mgr;
            _font = font != null ? font : Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");

            _root = (RectTransform)transform;
            // Esquina superior izquierda: la franja de abajo queda libre.
            _root.anchorMin = _root.anchorMax = new Vector2(0f, 1f);
            _root.pivot = new Vector2(0f, 1f);
            _root.anchoredPosition = new Vector2(14f, -14f);
            _root.sizeDelta = new Vector2(BoardW, 120f);

            var layout = gameObject.AddComponent<VerticalLayoutGroup>();
            layout.padding = new RectOffset(PadX, PadX, PadY, PadY);
            layout.spacing = 3f;
            layout.childAlignment = TextAnchor.UpperLeft;
            layout.childControlWidth = true;
            layout.childControlHeight = true;
            layout.childForceExpandWidth = false;
            layout.childForceExpandHeight = false;

            var fitter = gameObject.AddComponent<ContentSizeFitter>();
            fitter.horizontalFit = ContentSizeFitter.FitMode.Unconstrained;   // ancho fijo
            fitter.verticalFit = ContentSizeFitter.FitMode.PreferredSize;     // alto segun contenido

            var frame = NewImage(_root, "Frame", FrameSprite(), PanelFill);
            frame.type = Image.Type.Sliced;
            Stretch(frame.rectTransform, 0f);
            frame.gameObject.AddComponent<LayoutElement>().ignoreLayout = true;

            // Encabezado: modo de la partida a la izquierda, regla a la derecha.
            var header = NewRect(_root, "Header");
            header.gameObject.AddComponent<LayoutElement>().preferredHeight = HeaderH;
            var hlay = header.gameObject.AddComponent<HorizontalLayoutGroup>();
            hlay.childControlWidth = true;
            hlay.childControlHeight = true;
            hlay.childForceExpandWidth = true;
            hlay.childForceExpandHeight = false;

            _caption = NewText(header, "Caption", "", 10, TextMain);
            _caption.fontStyle = FontStyle.Bold;
            FlexWidth(_caption.gameObject, 1f);
            _hint = NewText(header, "Hint", "", 9, TextDim);
            _hint.alignment = TextAnchor.MiddleRight;
            FlexWidth(_hint.gameObject, 1f);

            _content = NewRect(_root, "Content");
            var clay = _content.gameObject.AddComponent<VerticalLayoutGroup>();
            clay.spacing = 2f;
            clay.childAlignment = TextAnchor.UpperLeft;
            clay.childControlWidth = true;
            clay.childControlHeight = true;
            clay.childForceExpandWidth = true;      // las filas ocupan todo el ancho
            clay.childForceExpandHeight = false;
        }

        /// <summary>Tamano fijo de un hijo dentro de un layout (los sprites no sirven: miden en unidades).</summary>
        private static LayoutElement SetSize(GameObject go, float w, float h)
        {
            var el = go.GetComponent<LayoutElement>();
            if (el == null) el = go.AddComponent<LayoutElement>();
            el.preferredWidth = w;
            el.minWidth = w;
            el.preferredHeight = h;
            el.minHeight = h;
            el.flexibleWidth = 0f;
            el.flexibleHeight = 0f;
            return el;
        }

        /// <summary>El hijo reparte el espacio sobrante del layout (texto que se estira).</summary>
        private static LayoutElement FlexWidth(GameObject go, float flex)
        {
            var el = go.GetComponent<LayoutElement>();
            if (el == null) el = go.AddComponent<LayoutElement>();
            el.flexibleWidth = flex;
            el.flexibleHeight = 0f;
            el.minHeight = 0f;
            return el;
        }

        private void OnDestroy() { _mgr = null; }

        /// <summary>
        /// Distancia en pixeles desde el borde superior del canvas hasta el borde
        /// inferior del tablero. El HUD lo usa para colgar el pie de controles
        /// justo debajo (asi la franja de abajo queda libre para las habilidades).
        /// </summary>
        public float BottomFromTop => 14f + (_root != null ? _root.rect.height : 0f);

        // =================================================================
        // Refresco
        // =================================================================

        /// <summary>Llamado por MatchHud cada frame mientras corre el PVP.</summary>
        public void Refresh()
        {
            if (_mgr == null || _root == null) return;

            bool visible = _mgr.Roster.Count > 0;
            if (_root.gameObject.activeSelf != visible) _root.gameObject.SetActive(visible);
            if (!visible) return;

            int signature = Signature();
            if (signature != _signature)
            {
                _signature = signature;
                Rebuild();
            }

            foreach (var row in _teams) UpdateTeam(row);
            foreach (var row in _ffa) UpdateFfa(row);
        }

        /// <summary>Identifica el contenido que obliga a reconstruir (plantel, modo, orden por bajas).</summary>
        private int Signature()
        {
            int hash = _mgr.RosterVersion * 397 ^ (GameSession.PvpTeams ? 1 : 7);
            if (!GameSession.PvpTeams && _mgr.Kills != null)
                for (int i = 0; i < _mgr.Kills.Length; i++) hash = hash * 31 + _mgr.Kills[i];
            return hash;
        }

        private void Rebuild()
        {
            for (int i = _content.childCount - 1; i >= 0; i--)
            {
                var child = _content.GetChild(i).gameObject;
                child.SetActive(false);
                Destroy(child);
            }
            _teams.Clear();
            _ffa.Clear();

            bool teams = GameSession.PvpTeams;
            if (_caption != null)
            {
                _caption.text = teams ? "EQUIPOS" : "TODOS CONTRA TODOS";
                _caption.color = teams ? TextMain : new Color(1f, 0.80f, 0.45f);
            }
            if (_hint != null)
                _hint.text = teams ? "SIN FUEGO AMIGO" : "ORDEN POR BAJAS";

            if (_mgr.Roster.Count == 0) return;

            if (teams)
            {
                for (int t = 0; t < 4; t++)
                {
                    var members = new List<PvpCombatant>();
                    foreach (var c in _mgr.Roster)
                        if (c.team == t) members.Add(c);
                    if (members.Count == 0) continue;
                    BuildTeamRow(t, members);
                }
            }
            else
            {
                // Todos contra todos: tabla corta por bajas. Si el local no entra,
                // su fila se agrega al final (siempre hay que verlo).
                var sorted = new List<PvpCombatant>(_mgr.Roster);
                sorted.Sort(CompareFfa);
                int shown = Mathf.Min(MaxFfaRows, sorted.Count);
                for (int i = 0; i < shown; i++) BuildFfaRow(sorted[i], i + 1);

                int localIndex = sorted.FindIndex(c => c.isLocal);
                if (localIndex >= 0 && localIndex >= shown) BuildFfaRow(sorted[localIndex], localIndex + 1);
            }
        }

        private int CompareFfa(PvpCombatant a, PvpCombatant b)
        {
            int ka = _mgr.KillsFor(a.seat);
            int kb = _mgr.KillsFor(b.seat);
            if (ka != kb) return kb.CompareTo(ka);

            bool da = a.health != null && a.health.IsDead;
            bool db = b.health != null && b.health.IsDead;
            if (da != db) return da ? 1 : -1;

            return a.seat.CompareTo(b.seat);
        }

        // =================================================================
        // Filas
        // =================================================================

        /// <summary>Fila de equipo: letra, marcador de ronda y un disco por combatiente.</summary>
        private void BuildTeamRow(int team, List<PvpCombatant> members)
        {
            var row = NewRect(_content, "Team" + team);
            var element = row.gameObject.AddComponent<LayoutElement>();
            element.preferredHeight = RowH;
            element.minHeight = RowH;

            var lay = row.gameObject.AddComponent<HorizontalLayoutGroup>();
            lay.spacing = 5f;
            lay.childAlignment = TextAnchor.MiddleLeft;
            lay.childControlWidth = true;
            lay.childControlHeight = true;
            lay.childForceExpandWidth = false;
            lay.childForceExpandHeight = false;

            // Distintivo del equipo: cuadrado con la letra.
            var badge = NewImage(row, "Badge", RoundedSprite(), TeamColor(team));
            badge.rectTransform.sizeDelta = new Vector2(15f, 15f);
            SetSize(badge.gameObject, 15f, 15f);
            var letter = NewText(badge.rectTransform, "L", TeamLetter(team), 9, Ink);
            Stretch(letter.rectTransform);
            letter.alignment = TextAnchor.MiddleCenter;
            letter.fontStyle = FontStyle.Bold;

            // Marcador de ronda del equipo.
            var score = NewText(row, "Score", "0", 12, TextMain);
            score.fontStyle = FontStyle.Bold;
            score.rectTransform.sizeDelta = new Vector2(20f, RowH);
            SetSize(score.gameObject, 20f, RowH);
            score.alignment = TextAnchor.MiddleLeft;

            var entry = new TeamRow { team = team, score = score };
            foreach (var c in members)
            {
                var disc = BuildPortrait(row, c, DiscSize);
                entry.discs.Add(disc);
                entry.members.Add(c.health);
                entry.accents.Add(c.Accent);
            }

            _teams.Add(entry);
        }

        /// <summary>Fila de la tabla de todos contra todos: puesto, nombre, bajas y disco.</summary>
        private void BuildFfaRow(PvpCombatant data, int rank)
        {
            var row = NewRect(_content, "Row" + data.seat);
            var element = row.gameObject.AddComponent<LayoutElement>();
            element.preferredHeight = RowH;
            element.minHeight = RowH;

            var lay = row.gameObject.AddComponent<HorizontalLayoutGroup>();
            lay.spacing = 5f;
            lay.childAlignment = TextAnchor.MiddleLeft;
            lay.childControlWidth = true;
            lay.childControlHeight = true;
            lay.childForceExpandWidth = false;
            lay.childForceExpandHeight = false;

            var badge = NewImage(row, "Rank", CircleSprite(), RankColor(rank));
            badge.rectTransform.sizeDelta = new Vector2(14f, 14f);
            SetSize(badge.gameObject, 14f, 14f);
            var num = NewText(badge.rectTransform, "N", rank.ToString(), 8, Ink);
            Stretch(num.rectTransform);
            num.alignment = TextAnchor.MiddleCenter;
            num.fontStyle = FontStyle.Bold;

            var name = NewText(row, "Name", ShortName(data.name), 11, TextMain);
            name.rectTransform.sizeDelta = new Vector2(146f, RowH);
            SetSize(name.gameObject, 146f, RowH);
            name.alignment = TextAnchor.MiddleLeft;
            name.horizontalOverflow = HorizontalWrapMode.Overflow;

            var kills = NewText(row, "Kills", "", 11, data.Accent);
            kills.fontStyle = FontStyle.Bold;
            kills.rectTransform.sizeDelta = new Vector2(34f, RowH);
            SetSize(kills.gameObject, 34f, RowH);
            kills.alignment = TextAnchor.MiddleRight;

            var disc = BuildPortrait(row, data, DiscSize);

            _ffa.Add(new FfaRow
            {
                seat = data.seat,
                health = data.health,
                accent = data.Accent,
                name = name,
                kills = kills,
                disc = disc,
            });
        }

        /// <summary>
        /// Disco del combatiente: aro del color con que juega, fondo oscuro y la
        /// cabeza real del personaje. El local lleva un aro blanco por fuera.
        /// Devuelve el disco de color (el que se apaga cuando el combatiente cae).
        /// </summary>
        private Image BuildPortrait(Transform parent, PvpCombatant data, float size)
        {
            // El local se distingue con un aro blanco por fuera del disco.
            Transform holder = parent;
            float holderSize = size;
            if (data.isLocal)
            {
                var ring = NewImage(parent, "Local" + data.seat, CircleSprite(), new Color(1f, 1f, 1f, 0.92f));
                holderSize = size + 4f;
                ring.rectTransform.sizeDelta = new Vector2(holderSize, holderSize);
                SetSize(ring.gameObject, holderSize, holderSize);
                holder = ring.transform;
            }

            var disc = NewImage(holder, "Disc" + data.seat, CircleSprite(), data.Accent);
            if (data.isLocal)
            {
                disc.rectTransform.anchorMin = disc.rectTransform.anchorMax = new Vector2(0.5f, 0.5f);
                disc.rectTransform.pivot = new Vector2(0.5f, 0.5f);
                disc.rectTransform.anchoredPosition = Vector2.zero;
                disc.rectTransform.sizeDelta = new Vector2(size, size);
            }
            else
            {
                disc.rectTransform.sizeDelta = new Vector2(size, size);
                SetSize(disc.gameObject, size, size);
            }

            var face = NewImage(disc.rectTransform, "Face", CircleSprite(), Ink);
            Stretch(face.rectTransform, 2f);
            var mask = face.gameObject.AddComponent<Mask>();
            mask.showMaskGraphic = true;

            Sprite head, paint;
            HeadSprites(data.visual, out head, out paint);
            if (head != null)
            {
                var headImg = NewImage(face.rectTransform, "Head", head, Color.white);
                headImg.preserveAspect = true;
                Center(headImg.rectTransform, new Vector2(0f, -1f), new Vector2(size, size));

                if (paint != null)
                {
                    var paintImg = NewImage(face.rectTransform, "Paint", paint, data.Accent);
                    paintImg.preserveAspect = true;
                    Center(paintImg.rectTransform, new Vector2(0f, -1f), new Vector2(size, size));
                }
            }
            else
            {
                var initial = NewText(face.rectTransform, "Initial", InitialOf(data.name), 9, data.Accent);
                Stretch(initial.rectTransform);
                initial.alignment = TextAnchor.MiddleCenter;
            }

            return disc;
        }

        // =================================================================
        // Estado por frame
        // =================================================================

        private void UpdateTeam(TeamRow row)
        {
            if (row == null) return;

            int wins = 0;
            for (int i = 0; i < row.members.Count; i++)
            {
                var member = row.members[i];
                bool dead = member != null && member.IsDead;
                if (i < row.discs.Count && row.discs[i] != null)
                    row.discs[i].color = dead ? Dead : (i < row.accents.Count ? row.accents[i] : TextMain);
            }

            foreach (var c in _mgr.Roster)
                if (c.team == row.team) wins += _mgr.ScoreFor(c.seat);

            if (row.score != null) row.score.text = wins.ToString();
        }

        private void UpdateFfa(FfaRow row)
        {
            if (row == null) return;
            bool dead = row.health != null && row.health.IsDead;

            if (row.disc != null) row.disc.color = dead ? Dead : row.accent;
            if (row.name != null)
            {
                row.name.color = dead ? TextDim : TextMain;
                row.name.fontStyle = row.seat == LocalSeat() ? FontStyle.Bold : FontStyle.Normal;
            }
            if (row.kills != null)
            {
                row.kills.text = _mgr.KillsFor(row.seat).ToString();
                row.kills.color = dead ? TextDim : row.accent;
            }
        }

        private int LocalSeat()
        {
            for (int i = 0; i < _mgr.Roster.Count; i++)
                if (_mgr.Roster[i].isLocal) return _mgr.Roster[i].seat;
            return -1;
        }

        // =================================================================
        // Datos del personaje
        // =================================================================

        /// <summary>Saca del rig las dos capas de la cabeza (base y pintura tintable).</summary>
        private static void HeadSprites(CharacterVisual visual, out Sprite head, out Sprite paint)
        {
            head = null;
            paint = null;
            if (visual == null || visual.parts == null) return;

            foreach (var part in visual.parts)
            {
                if (part.renderer == null || part.renderer.sprite == null) continue;
                var t = part.renderer.transform;
                if (t.parent == null) continue;
                bool isHead = t.parent.name == "Head" ||
                              (t.parent.parent != null && t.parent.parent.name == "Head");
                if (!isHead) continue;

                if (part.paint) paint = part.renderer.sprite;
                else head = part.renderer.sprite;
            }
        }

        private static string ShortName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "PORTADOR";
            return name.Length <= 14 ? name : name.Substring(0, 13) + "…";
        }

        private static string InitialOf(string name)
            => string.IsNullOrEmpty(name) ? "?" : name.Substring(0, 1).ToUpperInvariant();

        private static string TeamLetter(int team) => ((char)('A' + Mathf.Clamp(team, 0, 3))).ToString();

        private static Color TeamColor(int team) =>
            GameSession.Palette[Mathf.Clamp(team, 0, 3)];

        private static Color RankColor(int rank)
        {
            if (rank == 1) return new Color(1f, 0.82f, 0.25f);
            if (rank == 2) return new Color(0.82f, 0.86f, 0.92f);
            if (rank == 3) return new Color(0.85f, 0.55f, 0.28f);
            return new Color(0.35f, 0.40f, 0.50f);
        }

        // =================================================================
        // Helpers de UI
        // =================================================================

        private RectTransform NewRect(Transform parent, string name)
        {
            var go = new GameObject(name, typeof(RectTransform));
            go.transform.SetParent(parent, false);
            return (RectTransform)go.transform;
        }

        private Image NewImage(Transform parent, string name, Sprite sprite, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var img = go.AddComponent<Image>();
            img.sprite = sprite;
            img.color = color;
            img.raycastTarget = false;
            return img;
        }

        private Text NewText(Transform parent, string name, string value, int size, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var text = go.AddComponent<Text>();
            text.font = _font;
            text.text = value;
            text.fontSize = size;
            text.color = color;
            text.alignment = TextAnchor.MiddleLeft;
            text.raycastTarget = false;
            text.horizontalOverflow = HorizontalWrapMode.Overflow;
            text.verticalOverflow = VerticalWrapMode.Overflow;
            return text;
        }

        private static void Center(RectTransform rt, Vector2 offset, Vector2 size)
        {
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = offset;
            rt.sizeDelta = size;
        }

        private static void Stretch(RectTransform rt, float inset = 0f)
        {
            rt.anchorMin = Vector2.zero;
            rt.anchorMax = Vector2.one;
            rt.pivot = new Vector2(0.5f, 0.5f);
            rt.offsetMin = new Vector2(inset, inset);
            rt.offsetMax = new Vector2(-inset, -inset);
        }

        // =================================================================
        // Sprites procedurales (sin assets extra)
        // =================================================================

        private static Sprite FrameSprite()
        {
            if (_frameSprite == null)
                _frameSprite = SpriteFrom(RoundedTexture(72, 20f), new Vector4(22f, 22f, 22f, 22f), "PvpFrame");
            return _frameSprite;
        }

        private static Sprite RoundedSprite()
        {
            if (_roundedSprite == null)
                _roundedSprite = SpriteFrom(RoundedTexture(40, 8f), new Vector4(8f, 8f, 8f, 8f), "PvpRounded");
            return _roundedSprite;
        }

        private static Sprite CircleSprite()
        {
            if (_circleSprite == null)
                _circleSprite = SpriteFrom(CircleTexture(96), Vector4.zero, "PvpCircle");
            return _circleSprite;
        }

        private static Sprite SpriteFrom(Texture2D tex, Vector4 border, string name)
        {
            tex.name = name;
            var sprite = Sprite.Create(tex, new Rect(0f, 0f, tex.width, tex.height),
                new Vector2(0.5f, 0.5f), 100f, 0, SpriteMeshType.FullRect, border);
            sprite.name = name;
            return sprite;
        }

        /// <summary>Rectangulo redondeado blanco con borde mas claro (se tinta por Image.color).</summary>
        private static Texture2D RoundedTexture(int size, float radius)
        {
            var tex = new Texture2D(size, size, TextureFormat.RGBA32, false);
            tex.wrapMode = TextureWrapMode.Clamp;
            tex.filterMode = FilterMode.Bilinear;

            var pixels = new Color32[size * size];
            float half = size * 0.5f;
            float inner = half - radius;

            for (int y = 0; y < size; y++)
            {
                for (int x = 0; x < size; x++)
                {
                    float dx = Mathf.Abs(x + 0.5f - half) - inner;
                    float dy = Mathf.Abs(y + 0.5f - half) - inner;
                    float outside = Mathf.Sqrt(Mathf.Max(dx, 0f) * Mathf.Max(dx, 0f) +
                                               Mathf.Max(dy, 0f) * Mathf.Max(dy, 0f));
                    float distance = outside + Mathf.Min(Mathf.Max(dx, dy), 0f) - radius;

                    float alpha = Mathf.Clamp01(0.5f - distance);
                    // El filo exterior queda mas claro: se lee como un bisel.
                    float shade = Mathf.Lerp(0.66f, 1f, Mathf.Clamp01(-distance / 2f));
                    var c = (byte)(shade * 255f);
                    pixels[y * size + x] = new Color32(c, c, c, (byte)(alpha * 255f));
                }
            }

            tex.SetPixels32(pixels);
            tex.Apply();
            return tex;
        }

        private static Texture2D CircleTexture(int size)
        {
            var tex = new Texture2D(size, size, TextureFormat.RGBA32, false);
            tex.wrapMode = TextureWrapMode.Clamp;
            tex.filterMode = FilterMode.Bilinear;

            var pixels = new Color32[size * size];
            float half = size * 0.5f;
            float radius = half - 2f;

            for (int y = 0; y < size; y++)
            {
                for (int x = 0; x < size; x++)
                {
                    float dx = x + 0.5f - half;
                    float dy = y + 0.5f - half;
                    float distance = Mathf.Sqrt(dx * dx + dy * dy) - radius;
                    float alpha = Mathf.Clamp01(0.5f - distance);
                    pixels[y * size + x] = new Color32(255, 255, 255, (byte)(alpha * 255f));
                }
            }

            tex.SetPixels32(pixels);
            tex.Apply();
            return tex;
        }
    }
}