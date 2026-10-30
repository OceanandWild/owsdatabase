using System;
using UnityEngine;
using WilderGambit.Services;

namespace WilderGambit.Core
{
    /// <summary>Resultado de un cobro: lo pedido, lo concedido y por qué se recortó.</summary>
    public struct GambitPayout
    {
        public GambitSource source;
        public int requested;
        public int granted;
        public bool limited;
        public string limitReason;
        public int balanceAfter;

        public bool Any => granted > 0;
    }

    /// <summary>
    /// Punto único por el que entra TODO Gambit del juego. Aplica topes diarios
    /// (por fuente y global), abona el saldo local al instante (lo lee la Tienda) y
    /// lo sincroniza con Surface cuando hay sesión. Avisa por OnEarned para que la
    /// UI muestre el toast.
    /// </summary>
    public static class GambitEconomy
    {
        /// <summary>(pago, saldo resultante) tras cada cobro concedido.</summary>
        public static event Action<GambitPayout> OnEarned;

        /// <summary>Cambios de progreso que la UI debe repintar (misiones, barra, logros).</summary>
        public static event Action OnProgressChanged;

        public static int Balance => PieceSkinManager.GetLocalGambits();
        public static int TodayTotal => GambitLedger.TotalToday;

        /// <summary>Gambits que faltan para el tope blando del día (para mostrar "ritmo" en la UI).</summary>
        public static int RemainingSoftBudget
        {
            get
            {
                int cap = GambitEconomyConfig.Instance.dailySoftCap;
                return Mathf.Max(0, cap - GambitLedger.TotalToday);
            }
        }

        /// <summary>
        /// Cobra una cantidad. Devuelve el pago efectivo (granted puede ser 0 si hay tope).
        /// <paramref name="ignorePaymentLimit"/> salta el tope de Nº de pagos (solo para las
        /// herramientas de depuración: el tope de importe del día se respeta siempre).
        /// <paramref name="bypassCaps"/> salta todos los topes diarios (global y de fuente)
        /// y no registra el pago en el libro del día: es para recompensas ya ganadas
        /// (pase de temporada), que no son farming y no deben recortarse ni apretar
        /// los topes de juego.
        /// </summary>
        public static GambitPayout Earn(int amount, GambitSource source, string meta = null, string note = null,
            bool ignorePaymentLimit = false, bool bypassCaps = false)
        {
            var payout = new GambitPayout { source = source, requested = Mathf.Max(0, amount), balanceAfter = Balance };
            if (amount <= 0) return payout;

            var config = GambitEconomyConfig.Instance;

            // 1. Tope global del día (blando con overflow, duro absoluto)
            int today = GambitLedger.TotalToday;
            int granted = amount;

            if (!bypassCaps)
            {
                if (today >= config.dailyHardCap)
                {
                    payout.limited = true;
                    payout.limitReason = "tope diario total alcanzado";
                    payout.granted = 0;
                    Debug.Log($"[GambitEconomy] {amount}G bloqueados: {payout.limitReason} ({today}/{config.dailyHardCap}).");
                    return payout;
                }

                int hardRoom = config.dailyHardCap - today;
                if (granted > hardRoom)
                {
                    granted = hardRoom;
                    payout.limited = true;
                    payout.limitReason = "tope diario total";
                }

                if (today >= config.dailySoftCap)
                {
                    int softened = Mathf.Max(1, Mathf.RoundToInt(granted * config.overflowFactor));
                    if (softened < granted)
                    {
                        granted = softened;
                        payout.limited = true;
                        payout.limitReason = "ritmo diario superado";
                    }
                }
            }

            // 2. Tope propio de la fuente: primero el número de pagos del día, luego el importe.
            // Sin esto, repetir la misma fuente saltaba el «hasta N pagos al día» de su ficha.
            var info = GambitSources.Get(source);
            if (!bypassCaps)
            {
                if (!ignorePaymentLimit && info.maxPayments > 0)
                {
                    int pagos = GambitLedger.PaymentsToday(source);
                    if (pagos >= info.maxPayments)
                    {
                        payout.limited = true;
                        payout.limitReason = $"límite diario de {info.label.ToLowerInvariant()} ({pagos}/{info.maxPayments} pagos)";
                        payout.granted = 0;
                        Debug.Log($"[GambitEconomy] {amount}G bloqueados: {payout.limitReason}.");
                        return payout;
                    }
                }

                if (info.dailyCap > 0)
                {
                    int room = info.dailyCap - GambitLedger.SourceToday(source);
                    if (room <= 0)
                    {
                        payout.limited = true;
                        payout.limitReason = $"tope de {info.label.ToLowerInvariant()}";
                        payout.granted = 0;
                        return payout;
                    }
                    if (granted > room)
                    {
                        granted = room;
                        payout.limited = true;
                        payout.limitReason = $"tope de {info.label.ToLowerInvariant()}";
                    }
                }
            }

            // 3. Abonar
            payout.granted = granted;
            payout.balanceAfter = Balance + granted;

            PieceSkinManager.SetLocalGambits(payout.balanceAfter);
            if (!bypassCaps) GambitLedger.RegisterPayment(source, granted);

            SyncWithOceanPay(granted, GambitSources.Reason(source, meta));

            Debug.Log($"[GambitEconomy] +{granted}G de {info.label}{(string.IsNullOrEmpty(note) ? "" : $" ({note})")} → saldo {payout.balanceAfter} · hoy {GambitLedger.TotalToday}");

            OnEarned?.Invoke(payout);
            OnProgressChanged?.Invoke();
            return payout;
        }

        /// <summary>¿Esta fuente puede pagar algo ahora mismo?</summary>
        public static bool CanEarn(GambitSource source, out string reason)
        {
            return GambitLedger.HasRoom(source, out reason);
        }

        /// <summary>Recalcula y avisa a la UI (tras comprar, cambiar de día, etc.).</summary>
        public static void NotifyChanged() => OnProgressChanged?.Invoke();

        private static void SyncWithOceanPay(int amount, string reason)
        {
            var svc = OceanPayService.Instance;
            if (svc == null || !svc.IsLoggedIn || !svc.isActiveAndEnabled) return;

            svc.StartCoroutine(svc.EarnGambitsAsync(
                amount,
                reason,
                null,
                err => Debug.LogWarning($"[GambitEconomy] Gambits locales sin sincronizar con Surface: {err}")));
        }
    }
}
