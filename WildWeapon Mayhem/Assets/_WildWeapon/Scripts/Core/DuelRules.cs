namespace WildWeapon
{
    /// <summary>
    /// Numeros linea base del documento de diseno (secciones 2 y 3).
    /// Escala: 100 px = 1 unidad. Todo es parametro de iteracion F0/F1.
    /// </summary>
    public static class DuelRules
    {
        public const float Hp = 100f;
        public const int RoundsToWin = 2;              // best-of-3

        public const float OverdriveAt = 75f;          // segundos
        public const float OverdriveDamageMultiplier = 1.5f;

        public const float MoveSpeed = 3.2f;           // 320 px/s
        public const float DashSpeed = 5.2f;           // 520 px/s
        public const float DashTime = 0.18f;
        public const float DashIFrameTime = 0.15f;
        public const float DashCooldown = 5f;

        public const float KnockbackSpeed = 1.2f;      // 120 px/s, cosmetico
        public const float SwapCooldown = 0.5f;

        public const float HitStopDuration = 0.06f;
        public const float HitStopTimeScale = 0.05f;
    }
}
