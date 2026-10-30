using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Arte del <b>modal de Misiones de la Velada</b>
    /// (<c>Resources/UI/Halloween/Missions</c>).
    ///   · <c>hwm_window</c>        — marco de la ventana: arco con velas y esquinas de encaje
    ///   · <c>hwm_card_luna</c>     — tarjeta de la Vía Luna (riel azul, luna creciente)
    ///   · <c>hwm_card_sangre</c>   — tarjeta libre de Sangre (riel ámbar, gota)
    ///   · <c>hwm_card_premium</c>  — tarjeta premium (riel carmesí, corona de espinas)
    ///   · <c>hwm_card_ready</c>    — tarjeta lista para cobrar (placa encendida)
    ///   · <c>hwm_card_claimed</c>  — tarjeta cobrada (riel gris, sello verde)
    ///   · <c>hwm_card_locked</c>   — tarjeta cerrada (cadena y candado)
    ///   · <c>hwm_banner</c> / <c>hwm_banner_open</c> — estandarte de la Vía Sangre
    ///   · <c>hwm_claim</c>         — placa del botón COBRAR
    ///   · <c>hwm_empty_moon</c>    — ilustración del estado vacío
    ///   · <c>hwm_crest</c>         — emblema de la velada (torre, luna y gota)
    ///   · <c>hwm_topbar</c> / <c>hwm_hero</c> / <c>hwm_footer</c> — bandas del modal
    ///   · <c>hwm_hint_strip</c>    — tira de ayuda al pie de cada pestaña
    ///   · <c>hwm_tab_luna</c> / <c>hwm_tab_luna_on</c> — pestaña Luna, apagada y encendida
    ///   · <c>hwm_tab_sangre</c> / <c>hwm_tab_sangre_on</c> — pestaña Sangre
    ///   · <c>hwm_chip_xp</c> / <c>hwm_chip_dulces</c> / <c>hwm_state_chip</c> — chips del topbar
    ///   · <c>hwm_rule_luna</c> / <c>hwm_rule_sangre</c> — filetes divisores del cuerpo
    ///
    /// Cada familia tiene su 9-slice: el ornato (el riel del carril, las esquinas
    /// y los filetes) queda fijo y el centro se estira. La escala del slice
    /// acompaña el tamaño real del elemento —el arte va a ~2× del uso—, así el
    /// riel no se deforma cuando la tarjeta crece con textos largos o la ventana
    /// cambia de alto. Si el PNG no está importado, el elemento conserva el
    /// estilo USS: nada se rompe mientras falte el arte.
    /// </summary>
    public static class HalloweenMissionsSprites
    {
        public const string Folder = "UI/Halloween/Missions";

        public const string Window = "hwm_window";
        public const string CardLuna = "hwm_card_luna";
        public const string CardSangre = "hwm_card_sangre";
        public const string CardPremium = "hwm_card_premium";
        public const string CardReady = "hwm_card_ready";
        public const string CardClaimed = "hwm_card_claimed";
        public const string CardLocked = "hwm_card_locked";
        public const string Banner = "hwm_banner";
        public const string BannerOpen = "hwm_banner_open";
        public const string Claim = "hwm_claim";
        public const string EmptyMoon = "hwm_empty_moon";
        public const string Crest = "hwm_crest";

        // Tanda 2: bandas, pestañas, chips y filetes del modal.
        public const string Topbar = "hwm_topbar";
        public const string Hero = "hwm_hero";
        public const string Footer = "hwm_footer";
        public const string HintStrip = "hwm_hint_strip";
        public const string TabLuna = "hwm_tab_luna";
        public const string TabLunaOn = "hwm_tab_luna_on";
        public const string TabSangre = "hwm_tab_sangre";
        public const string TabSangreOn = "hwm_tab_sangre_on";
        public const string ChipXp = "hwm_chip_xp";
        public const string ChipDulces = "hwm_chip_dulces";
        public const string StateChip = "hwm_state_chip";
        public const string RuleLuna = "hwm_rule_luna";
        public const string RuleSangre = "hwm_rule_sangre";

        /// <summary>Esquinas fijas de una familia, en píxeles del sprite, y la
        /// escala a la que se dibuja el arte (0.557 ≈ 1× cuando la tarjeta mide
        /// 1140×96 sobre un sprite de 2048×172).</summary>
        private readonly struct Frame
        {
            public readonly int Left;
            public readonly int Right;
            public readonly int Top;
            public readonly int Bottom;
            public readonly float Scale;

            /// <summary>Alto en pantalla con el que se recalcula la escala
            /// (0 = usar <see cref="Scale"/>). El arte de la Tanda 2 viene en un
            /// canvas propio por slot: la escala sale del alto real del elemento,
            /// así el ornato se dibuja a la escala correcta aunque cada PNG tenga
            /// un aspecto distinto.</summary>
            public readonly float TargetHeight;

            public Frame(int left, int right, int top, int bottom, float scale, float targetHeight = 0f)
            {
                Left = left;
                Right = right;
                Top = top;
                Bottom = bottom;
                Scale = scale;
                TargetHeight = targetHeight;
            }
        }

        private static readonly Frame WindowFrame = new Frame(330, 330, 260, 260, 0.69f);
        private static readonly Frame CardFrame = new Frame(280, 150, 20, 20, 0.557f);
        private static readonly Frame BannerFrame = new Frame(210, 170, 18, 18, 0.54f);
        private static readonly Frame ButtonFrame = new Frame(62, 62, 12, 12, 0.5f);

        // Tanda 2: esquinas fijas en px del arte y alto en pantalla del elemento.
        private static readonly Frame TopbarFrame = new Frame(230, 230, 34, 34, 0f, 52f);
        private static readonly Frame HeroFrame = new Frame(300, 300, 60, 60, 0f, 88f);
        private static readonly Frame FooterFrame = new Frame(200, 200, 26, 26, 0f, 28f);
        private static readonly Frame HintFrame = new Frame(190, 170, 30, 30, 0f, 50f);
        private static readonly Frame TabLunaFrame = new Frame(210, 210, 90, 90, 0f, 34f);
        private static readonly Frame TabLunaOnFrame = new Frame(210, 210, 117, 117, 0f, 34f);
        private static readonly Frame TabSangreFrame = new Frame(240, 240, 97, 97, 0f, 34f);
        private static readonly Frame TabSangreOnFrame = new Frame(230, 230, 100, 100, 0f, 34f);
        private static readonly Frame ChipXpFrame = new Frame(190, 190, 88, 88, 0f, 32f);
        private static readonly Frame ChipDulcesFrame = new Frame(230, 230, 100, 100, 0f, 32f);
        private static readonly Frame StateChipFrame = new Frame(230, 190, 62, 62, 0f, 28f);
        private static readonly Frame RuleLunaFrame = new Frame(180, 190, 20, 20, 0f, 15f);
        private static readonly Frame RuleSangreFrame = new Frame(190, 200, 24, 24, 0f, 15f);

        private static readonly Dictionary<string, Sprite> Cache = new Dictionary<string, Sprite>();

        /// <summary>Sprite por nombre base, o <c>null</c> si el PNG no está importado.</summary>
        public static Sprite Get(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (Cache.TryGetValue(name, out var cached)) return cached;

            // 1) Sprite único directo (lo deja así ProgressSpriteImport).
            Sprite sprite = Resources.Load<Sprite>($"{Folder}/{name}");

            // 2) Textura multi-sprite: quedarse con el recorte de mayor área.
            if (sprite == null)
            {
                Sprite[] all = Resources.LoadAll<Sprite>($"{Folder}/{name}");
                if (all != null && all.Length > 0)
                {
                    float bestArea = 0f;
                    foreach (var s in all)
                    {
                        if (s == null) continue;
                        float area = s.rect.width * s.rect.height;
                        if (area > bestArea) { bestArea = area; sprite = s; }
                    }
                }
            }

            // 3) Textura cruda: envolverla en Sprite (red de seguridad).
            if (sprite == null)
            {
                var tex = Resources.Load<Texture2D>($"{Folder}/{name}");
                if (tex != null)
                {
                    sprite = Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height),
                        new Vector2(0.5f, 0.5f), 100f);
                    sprite.name = name;
                }
            }

            Cache[name] = sprite; // se cachea también el fallo para no golpear Resources en bucle
            return sprite;
        }

        public static bool Exists(string name) => Get(name) != null;

        /// <summary>Aplica el marco de una familia con 9-slice de esquinas fijas.</summary>
        private static bool Apply(VisualElement element, string name, Frame family)
        {
            var sprite = Get(name);
            if (element == null || sprite == null) return false;

            Rect rect = sprite.rect;
            int sw = Mathf.Max(1, Mathf.RoundToInt(rect.width));
            int sh = Mathf.Max(1, Mathf.RoundToInt(rect.height));

            element.style.backgroundImage = new StyleBackground(sprite);
            element.style.unitySliceLeft = Mathf.Clamp(family.Left, 1, sw / 2);
            element.style.unitySliceRight = Mathf.Clamp(family.Right, 1, sw / 2);
            element.style.unitySliceTop = Mathf.Clamp(family.Top, 1, sh / 2);
            element.style.unitySliceBottom = Mathf.Clamp(family.Bottom, 1, sh / 2);
            element.style.unitySliceScale = family.TargetHeight > 0f
                ? family.TargetHeight / sh
                : family.Scale;
            return true;
        }

        /// <summary>Marco de la ventana del modal (arco, velas y esquinas).</summary>
        public static bool ApplyWindow(VisualElement element) => Apply(element, Window, WindowFrame);

        /// <summary>Tarjeta de misión según el estado (ver <see cref="CardFor"/>).</summary>
        public static bool ApplyCard(VisualElement element, string card) => Apply(element, card, CardFrame);

        /// <summary>Estandarte de la Vía Sangre: cerrado (carmesí) o abierto (verde).</summary>
        public static bool ApplyBanner(VisualElement element, bool open) =>
            Apply(element, open ? BannerOpen : Banner, BannerFrame);

        /// <summary>Placa del botón COBRAR.</summary>
        public static bool ApplyClaim(VisualElement element) => Apply(element, Claim, ButtonFrame);

        // ── Tanda 2: bandas, pestañas, chips y filetes ────────────────────

        /// <summary>Rail de arriba del modal, con la cresta de la velada.</summary>
        public static bool ApplyTopbar(VisualElement element) => Apply(element, Topbar, TopbarFrame);

        /// <summary>Banda del hero: estado de la velada y pestañas.</summary>
        public static bool ApplyHero(VisualElement element) => Apply(element, Hero, HeroFrame);

        /// <summary>Banda del pie.</summary>
        public static bool ApplyFooter(VisualElement element) => Apply(element, Footer, FooterFrame);

        /// <summary>Tira de ayuda al final de cada pestaña.</summary>
        public static bool ApplyHint(VisualElement element) => Apply(element, HintStrip, HintFrame);

        /// <summary>Pestaña: apagada o encendida según la vía y si está activa.</summary>
        public static bool ApplyTab(VisualElement element, bool sangre, bool active) =>
            Apply(element, TabFor(sangre, active), TabFrameFor(sangre, active));

        /// <summary>Chip de progreso: XP de la velada o Dulces.</summary>
        public static bool ApplyChip(VisualElement element, bool dulces) =>
            Apply(element, dulces ? ChipDulces : ChipXp, dulces ? ChipDulcesFrame : ChipXpFrame);

        /// <summary>Chip de estado de la velada (activa, próxima o terminada).</summary>
        public static bool ApplyStateChip(VisualElement element) => Apply(element, StateChip, StateChipFrame);

        /// <summary>Filete divisor del cuerpo: Vía Luna o Vía Sangre.</summary>
        public static bool ApplyRule(VisualElement element, bool sangre) =>
            Apply(element, sangre ? RuleSangre : RuleLuna, sangre ? RuleSangreFrame : RuleLunaFrame);

        private static string TabFor(bool sangre, bool active) =>
            sangre ? (active ? TabSangreOn : TabSangre) : (active ? TabLunaOn : TabLuna);

        private static Frame TabFrameFor(bool sangre, bool active) =>
            sangre ? (active ? TabSangreOnFrame : TabSangreFrame) : (active ? TabLunaOnFrame : TabLunaFrame);

        /// <summary>Arte suelto sin 9-slice: ancho pedido y alto según el aspecto
        /// del sprite (emblema del hero y estado vacío).</summary>
        public static bool ApplyArt(VisualElement element, string name, float width)
        {
            var sprite = Get(name);
            if (element == null || sprite == null) return false;

            Rect rect = sprite.rect;
            float w = Mathf.Max(1f, width);
            element.style.backgroundImage = new StyleBackground(sprite);
            element.style.width = w;
            element.style.height = Mathf.Max(1f, w * (rect.height / Mathf.Max(1f, rect.width)));
            return true;
        }

        /// <summary>Vuelve al estilo USS (quita el arte aplicado).</summary>
        public static void Clear(VisualElement element)
        {
            if (element == null) return;
            element.style.backgroundImage = new StyleBackground(StyleKeyword.None);
        }

        /// <summary>Sprite de tarjeta según el estado real de la misión: lo cobrado
        /// y lo cerrado mandan sobre el resto, y lo listo manda sobre el carril.</summary>
        public static string CardFor(bool sangre, bool premium, bool claimed, bool locked, bool ready)
        {
            if (claimed) return CardClaimed;
            if (locked) return CardLocked;
            if (ready) return CardReady;
            if (!sangre) return CardLuna;
            return premium ? CardPremium : CardSangre;
        }
    }
}
