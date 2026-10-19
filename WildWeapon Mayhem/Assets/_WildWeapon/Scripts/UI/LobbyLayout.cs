namespace WildWeapon.UI
{
    /// <summary>
    /// Grilla del lobby multijugador local, en unidades de la resolucion de referencia
    /// (1920x1080). La comparten el generador de escena
    /// (<c>WildWeaponBuilder.BuildLobbyScene</c>) y <see cref="MultiplayerLobbyController"/>:
    /// el encabezado de columnas y las filas salen de los mismos numeros, asi no se
    /// desalinean al retocar la maqueta.
    /// </summary>
    public static class LobbyLayout
    {
        // ---- Tablero: placa ww_lobby_panel (1024x512 = 2:1 exacto) ----
        // 1400x650 (2.15:1): apenas 7% mas bajo que el arte, imperceptible en un
        // marco tan fino, y es lo que le deja aire a la placa del titulo en 21:9.
        public const float BoardW = 1400f;
        public const float BoardH = 650f;
        public const float BoardY = -39f;
        /// <summary>Marco pintado de la placa: margen que hay que respetar adentro.</summary>
        public const float BoardInsetX = 96f;
        public const float BoardInsetY = 78f;

        public const float InnerW = BoardW - 2f * BoardInsetX;          // 1208
        public const float InnerTop = BoardH * 0.5f - BoardInsetY;      // 247 sobre el centro del tablero
        public const float InnerBottom = -BoardH * 0.5f + BoardInsetY;  // -247

        // ---- Encabezado de columnas ----
        public const float HeaderH = 44f;
        public const float HeaderGap = 12f;
        public const float HeaderY = InnerTop - HeaderH * 0.5f;         // 225
        public const float RuleY = InnerTop - HeaderH - 4f;             // 199
        public const float RuleH = 2f;

        // ---- Lista con scroll ----
        public const float ScrollbarW = 12f;
        public const float ScrollbarGap = 8f;
        public const float ListW = InnerW - ScrollbarW - ScrollbarGap;      // 1188
        public const float ListX = -InnerW * 0.5f + ListW * 0.5f;           // -10
        public const float ScrollbarX = InnerW * 0.5f - ScrollbarW * 0.5f;  // 598
        public const float ListTop = InnerTop - HeaderH - HeaderGap;        // 191
        public const float ListBottom = InnerBottom;                        // -247
        public const float ListH = ListTop - ListBottom;                    // 438 (5 filas y media)
        public const float ListY = (ListTop + ListBottom) * 0.5f;           // -28

        // ---- Placa del titulo (ww_lobby_title_banner, 1024x170 = 6.02:1) ----
        // No se ancla al borde superior sino a la columna bajada+tablero: en 21:9
        // (el caso mas apretado) el borde de arriba esta en 466 y la placa termina
        // en 454. Tampoco choca con los chips: viven pegados a las esquinas.
        public const float BannerW = 760f;
        public const float BannerH = 126.17f;   // BannerW * 170/1024: no se deforma
        public const float BannerY = 391f;
        public const float TitleSize = 42f;
        public const float SubY = 307f;         // bajada entre la placa y el tablero

        // ---- Fila (las columnas se miden desde el borde izquierdo de la fila) ----
        public const float RowH = 72f;
        public const float RowGap = 8f;
        public const float BarX = 14f;          // barra de acento (solo si falta la tarjeta)
        public const float BarW = 5f;
        public const float BarH = 34f;

        // Tarjeta del jugador (ww_lobby_player_card, 512x128 = 4:1 exacto, no se
        // deforma), apenas adentro del marco de la fila. El medallon pintado en el
        // arte esta en (66,65) sobre 512x128: el orbe va justo encima.
        public const float CardX = 10f;
        public const float CardW = 260f;
        public const float CardH = 65f;
        public const float CardColorX = CardX + 33.5f;   // centro del medallon
        public const float CardSeatX = 146f;             // "J1".."J15", centrado en el panel
        public const float CardSeatW = 44f;
        public const float ColorButtonSize = 60f;
        public const float ColorSize = 44f;
        public const float ColorGlowSize = 62f;

        public const float FieldH = 48f;        // alto de los campos de la fila
        public const float NameX = 284f;
        public const float NameW = 336f;
        public const float ControlX = 636f;
        public const float ControlW = 288f;
        public const float TeamX = 940f;
        public const float TeamW = 240f;
    }
}
