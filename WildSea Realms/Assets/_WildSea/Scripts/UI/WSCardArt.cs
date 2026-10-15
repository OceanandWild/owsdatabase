using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;
using WildSea.Game;

namespace WildSea.UI
{
    /// <summary>
    /// Resuelve el arte de una carta por su id y cachea el sprite.
    ///
    /// Los PNG viven en Assets/Resources/WS/Card/ con el nombre WS_card_{id}.png,
    /// donde {id} es CardDef.id tal cual (con guiones). Ej: WS_card_proxima-centauri.png.
    ///
    /// Si falta el PNG (cartas nuevas todavia sin pintar, o el id cambio y el archivo
    /// no se renombro) devuelve null y la UI cae al fallback de texto: el juego
    /// sigue siendo jugable sin arte.
    /// </summary>
    public static class WSCardArt
    {
        const string Dir = "WS/Card/";
        const string Prefix = "WS_card_";

        // Tamano nativo del arte de carta. La UI saca el alto a partir del ancho con
        // esta proporcion: 560x1030 es la de todo el set.
        public const int CardW = 560, CardH = 1030;

        static readonly Dictionary<string, Sprite> cache = new();
        static readonly HashSet<string> missing = new();
        static Sprite backSprite;
        static bool backSpriteLoaded;

        public static Sprite Get(CardDef c)
        {
            if (c == null) return null;
            return Get(c.id);
        }

        public static Sprite Get(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            if (cache.TryGetValue(id, out var sp)) return sp;
            if (missing.Contains(id)) return null;

            sp = Resources.Load<Sprite>(Dir + Prefix + id);
            if (sp == null) missing.Add(id);
            else cache[id] = sp;
            return sp;
        }

        public static bool HasArt(CardDef c) => Get(c) != null;

        /// <summary>
        /// Colors de categoria (WILDSEA-MODO-CLASICO.md seccion 12). Se usan para
        /// el borde de las cartas y para el chip de la escalera, para que el jugador
        /// lea el peldano sin acordarse del nombre.
        /// </summary>
        public static Color CategoryColor(BodyCategory c)
        {
            switch (c)
            {
                case BodyCategory.Object:   return Hex("7C8FA6"); // acero frio
                case BodyCategory.Asteroid: return Hex("9999B3"); // gris roca
                case BodyCategory.Moon:     return Hex("B9A6E8"); // violeta palido
                case BodyCategory.Planet:   return Hex("E86A4C"); // terracota
                case BodyCategory.Star:     return Hex("FFD75A"); // oro
                case BodyCategory.Nebula:   return Hex("FFD75A"); // comparte oro
                case BodyCategory.Galaxy:   return Hex("C08BFF"); // sin cartas todavia
                default:                    return Color.white;
            }
        }

        public static Color Hex(string hex)
        {
            return ColorUtility.TryParseHtmlString("#" + hex, out var c) ? c : Color.magenta;
        }

        /// <summary>
        /// Tile de carta: el sprite si existe, o un rectangulo con el nombre si no.
        /// El arte ya trae marco, numero de peldan, categoria y subcategoria, asi que
        /// cuando hay sprite NO se le agrega texto encima: solo los indicadores que
        /// el arte no puede saber (si sirve al objetivo, si esta seleccionada).
        ///
        /// El mismo tile se usa en la mano, en la mesa y en el zoom: el zoom es esta
        /// misma funcion con mas ancho, no una segunda version de la carta.
        /// </summary>
        public static VisualElement BuildTile(CardDef c, int width)
        {
            // El userData deja que un evento de puntero sepa QUE carta tiene debajo con
            // solo subir por los padres. Es lo que alimenta el zoom de la partida.
            var tile = new VisualElement { name = $"card-{c.id}", userData = c };
            tile.style.width = width;
            tile.style.height = Mathf.RoundToInt(width * 1030f / 560f);
            tile.style.alignItems = Align.Center;
            tile.style.justifyContent = Justify.Center;
            tile.style.backgroundColor = new Color(0.07f, 0.10f, 0.19f, 1f);
            Border(tile, CategoryColor(c.category), 2);

            var sp = Get(c);
            if (sp != null)
            {
                var img = new VisualElement();
                img.style.width = Length.Percent(100);
                img.style.height = Length.Percent(100);
                img.style.backgroundImage = new StyleBackground(sp);
                img.style.backgroundSize = new BackgroundSize(BackgroundSizeType.Contain);
                img.style.backgroundPositionX = new BackgroundPosition(BackgroundPositionKeyword.Center);
                img.style.backgroundPositionY = new BackgroundPosition(BackgroundPositionKeyword.Center);
                img.style.backgroundRepeat = new BackgroundRepeat(Repeat.NoRepeat, Repeat.NoRepeat);
                img.pickingMode = PickingMode.Ignore;
                tile.Add(img);
            }
            else
            {
                // Fallback: sin arte la carta sigue siendo legible e identificable.
                var col = CategoryColor(c.category);
                var glyph = new Label(CellName(c.category));
                glyph.style.fontSize = Mathf.Max(11, width / 6);
                glyph.style.color = col;
                glyph.style.unityFontStyleAndWeight = FontStyle.Bold;
                glyph.style.unityTextAlign = TextAnchor.MiddleCenter;
                glyph.style.marginTop = 6;
                glyph.pickingMode = PickingMode.Ignore;
                tile.Add(glyph);

                var nm = new Label(c.name);
                nm.style.fontSize = Mathf.Max(9, width / 8);
                nm.style.color = new Color(0.85f, 0.90f, 1f, 1f);
                nm.style.unityTextAlign = TextAnchor.MiddleCenter;
                nm.style.whiteSpace = WhiteSpace.Normal;
                nm.style.marginLeft = 4; nm.style.marginRight = 4;
                nm.pickingMode = PickingMode.Ignore;
                tile.Add(nm);
            }
            return tile;
        }

        /// <summary>
        /// Reverso compartido para las cartas del rival. Se dibuja con UI Toolkit
        /// para que no dependa de un asset ni tenga datos de la carta ocultos.
        /// </summary>
        public static VisualElement BuildBackTile(int width)
        {
            var tile = new VisualElement { name = "card-back" };
            tile.style.width = width;
            tile.style.height = Mathf.RoundToInt(width * (float)CardH / CardW);
            tile.style.alignItems = Align.Center;
            tile.style.justifyContent = Justify.Center;
            tile.style.backgroundColor = Hex("09152B");
            tile.style.overflow = Overflow.Hidden;
            Border(tile, Hex("55D9EE"), 2);

            if (!backSpriteLoaded)
            {
                backSprite = Resources.Load<Sprite>(Dir + "WS_card_back");
                backSpriteLoaded = true;
            }

            if (backSprite != null)
            {
                tile.style.backgroundImage = new StyleBackground(backSprite);
                tile.style.backgroundSize = new BackgroundSize(BackgroundSizeType.Cover);
                tile.style.backgroundPositionX = new BackgroundPosition(BackgroundPositionKeyword.Center);
                tile.style.backgroundPositionY = new BackgroundPosition(BackgroundPositionKeyword.Center);
                tile.style.backgroundRepeat = new BackgroundRepeat(Repeat.NoRepeat, Repeat.NoRepeat);
                return tile;
            }

            var frame = new VisualElement { name = "card-back-frame" };
            frame.style.position = Position.Relative;
            frame.style.width = Length.Percent(88);
            frame.style.height = Length.Percent(96);
            frame.style.flexDirection = FlexDirection.Column;
            frame.style.alignItems = Align.Center;
            frame.style.justifyContent = Justify.Center;
            frame.style.borderTopWidth = 1;
            frame.style.borderBottomWidth = 1;
            frame.style.borderLeftWidth = 1;
            frame.style.borderRightWidth = 1;
            frame.style.borderTopColor = new StyleColor(Hex("236B8B"));
            frame.style.borderBottomColor = new StyleColor(Hex("236B8B"));
            frame.style.borderLeftColor = new StyleColor(Hex("236B8B"));
            frame.style.borderRightColor = new StyleColor(Hex("236B8B"));
            frame.style.borderTopLeftRadius = 5;
            frame.style.borderTopRightRadius = 5;
            frame.style.borderBottomLeftRadius = 5;
            frame.style.borderBottomRightRadius = 5;
            tile.Add(frame);

            // Órbitas cruzadas y el sello central dan una silueta reconocible
            // incluso cuando la carta se ve pequeña en la mesa.
            var orbitWide = new VisualElement { name = "card-back-orbit-wide" };
            orbitWide.style.position = Position.Absolute;
            orbitWide.style.left = Length.Percent(8);
            orbitWide.style.right = Length.Percent(8);
            orbitWide.style.top = Length.Percent(34);
            orbitWide.style.bottom = Length.Percent(34);
            Border(orbitWide, Hex("257FA0"), 1);
            orbitWide.style.borderTopLeftRadius = 100;
            orbitWide.style.borderTopRightRadius = 100;
            orbitWide.style.borderBottomLeftRadius = 100;
            orbitWide.style.borderBottomRightRadius = 100;
            orbitWide.style.rotate = new Rotate(28);
            frame.Add(orbitWide);

            var orbitTall = new VisualElement { name = "card-back-orbit-tall" };
            orbitTall.style.position = Position.Absolute;
            orbitTall.style.left = Length.Percent(22);
            orbitTall.style.right = Length.Percent(22);
            orbitTall.style.top = Length.Percent(24);
            orbitTall.style.bottom = Length.Percent(24);
            Border(orbitTall, Hex("1B5F7C"), 1);
            orbitTall.style.borderTopLeftRadius = 100;
            orbitTall.style.borderTopRightRadius = 100;
            orbitTall.style.borderBottomLeftRadius = 100;
            orbitTall.style.borderBottomRightRadius = 100;
            orbitTall.style.rotate = new Rotate(-28);
            frame.Add(orbitTall);

            var topMark = BackMark("✦", Mathf.Max(10, width * 0.14f), Hex("55D9EE"));
            topMark.style.marginTop = 4;
            frame.Add(topMark);

            var center = new VisualElement { name = "card-back-center" };
            center.style.flexGrow = 1;
            center.style.width = Length.Percent(100);
            center.style.alignItems = Align.Center;
            center.style.justifyContent = Justify.Center;
            frame.Add(center);

            float sealSize = width * 0.40f;
            var seal = new VisualElement { name = "card-back-seal" };
            seal.style.width = sealSize;
            seal.style.height = sealSize;
            seal.style.alignItems = Align.Center;
            seal.style.justifyContent = Justify.Center;
            seal.style.backgroundColor = Hex("102844");
            seal.style.rotate = new Rotate(45);
            Border(seal, Hex("E8C86D"), 2);
            center.Add(seal);

            var star = BackMark("✦", Mathf.Max(18, width * 0.27f), Hex("FFE28A"));
            star.style.rotate = new Rotate(-45);
            seal.Add(star);

            var bottomMark = BackMark("✧", Mathf.Max(10, width * 0.14f), Hex("55D9EE"));
            bottomMark.style.marginBottom = 4;
            frame.Add(bottomMark);

            return tile;
        }

        static Label BackMark(string glyph, float size, Color color)
        {
            var mark = new Label(glyph);
            mark.style.fontSize = size;
            mark.style.color = color;
            mark.style.unityFontStyleAndWeight = FontStyle.Bold;
            mark.style.unityTextAlign = TextAnchor.MiddleCenter;
            mark.pickingMode = PickingMode.Ignore;
            return mark;
        }

        /// <summary>Glifo del peldan, para los botones de fusion.</summary>
        public static string CellName(BodyCategory c)        {
            switch (c)
            {
                case BodyCategory.Object:   return "OBJ";
                case BodyCategory.Asteroid: return "AST";
                case BodyCategory.Moon:     return "LUN";
                case BodyCategory.Planet:   return "PLN";
                case BodyCategory.Star:     return "EST";
                case BodyCategory.Nebula:   return "NUB";
                case BodyCategory.Galaxy:   return "GAL";
                default:                    return "?";
            }
        }

        static void Border(VisualElement e, Color c, float w)
        {
            e.style.borderTopWidth = w; e.style.borderBottomWidth = w;
            e.style.borderLeftWidth = w; e.style.borderRightWidth = w;
            e.style.borderTopColor = new StyleColor(c);
            e.style.borderBottomColor = new StyleColor(c);
            e.style.borderLeftColor = new StyleColor(c);
            e.style.borderRightColor = new StyleColor(c);
            e.style.borderTopLeftRadius = 6; e.style.borderTopRightRadius = 6;
            e.style.borderBottomLeftRadius = 6; e.style.borderBottomRightRadius = 6;
        }
    }
}
