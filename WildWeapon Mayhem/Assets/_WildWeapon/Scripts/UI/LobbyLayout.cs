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
        // ---- Tablero: placa ww_lobby_panel (1024x512 = 2:1 exacto, no se deforma) ----
        public const float BoardW = 1400f;
        public const float BoardH = 700f;
        public const float BoardY = -14f;
        /// <summary>Marco pintado de la placa: margen que hay que respetar adentro.</summary>
        public const float BoardInsetX = 96f;
        public const float BoardInsetY = 84f;

        public const float InnerW = BoardW - 2f * BoardInsetX;          // 1208
        public const float InnerTop = BoardH * 0.5f - BoardInsetY;      // 266 sobre el centro del tablero
        public const float InnerBottom = -BoardH * 0.5f + BoardInsetY;  // -266

        // ---- Encabezado de columnas ----
        public const float HeaderH = 44f;
        public const float HeaderGap = 12f;
        public const float HeaderY = InnerTop - HeaderH * 0.5f;         // 244
        public const float RuleY = InnerTop - HeaderH - 4f;             // 218
        public const float RuleH = 2f;

        // ---- Lista con scroll ----
        public const float ScrollbarW = 12f;
        public const float ScrollbarGap = 8f;
        public const float ListW = InnerW - ScrollbarW - ScrollbarGap;      // 1188
        public const float ListX = -InnerW * 0.5f + ListW * 0.5f;           // -10
        public const float ScrollbarX = InnerW * 0.5f - ScrollbarW * 0.5f;  // 598
        public const float ListTop = InnerTop - HeaderH - HeaderGap;        // 210
        public const float ListBottom = InnerBottom;                        // -266
        public const float ListH = ListTop - ListBottom;                    // 476 (6 filas exactas)
        public const float ListY = (ListTop + ListBottom) * 0.5f;           // -28

        // ---- Fila (las columnas se miden desde el borde izquierdo de la fila) ----
        public const float RowH = 72f;
        public const float RowGap = 8f;
        public const float BarX = 14f;          // barra de acento del color del jugador
        public const float BarW = 5f;
        public const float BarH = 34f;
        public const float ColorX = 62f;        // centro del orbe de color
        public const float ColorButtonSize = 60f;
        public const float ColorSize = 46f;
        public const float ColorGlowSize = 84f;
        public const float FieldH = 48f;        // alto de los campos de la fila
        public const float NameX = 104f;
        public const float NameW = 470f;
        public const float ControlX = 590f;
        public const float ControlW = 320f;
        public const float TeamX = 926f;
        public const float TeamW = 200f;
        public const float SeatX = 1138f;       // etiqueta "J1".."J15"
        public const float SeatW = 44f;
    }
}
