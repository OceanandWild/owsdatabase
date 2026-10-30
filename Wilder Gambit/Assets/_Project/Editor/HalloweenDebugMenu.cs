using UnityEditor;
using UnityEngine;
using WilderGambit.Core;
using WilderGambit.UI;

namespace WilderGambit.EditorTools
{
    /// <summary>
    /// QA de la velada de Halloween desde «Wilder Gambit › Halloween».
    /// Todo escribe PlayerPrefs: sirve en el Editor (fuera de Play) y durante
    /// una partida, y no dispara eventos de UI — los valores se leen al abrir
    /// el pase. «Fase» pisa las fechas reales para probar los tres estados
    /// (PRÓXIMAMENTE / ACTIVO / TERMINADO) sin tocar el reloj del sistema.
    /// </summary>
    public static class HalloweenDebugMenu
    {
        private const string Root = "Wilder Gambit/Halloween/";
        private const string PhaseRoot = Root + "Fase/";

        // ── Fase (override de fechas reales) ──────────────────────────────

        [MenuItem(PhaseRoot + "0 · Fechas reales (auto)")]
        private static void PhaseAuto() => HalloweenEvent.DebugPhaseOption = 0;

        [MenuItem(PhaseRoot + "0 · Fechas reales (auto)", true)]
        private static bool PhaseAutoValidate()
        {
            Menu.SetChecked(PhaseRoot + "0 · Fechas reales (auto)", HalloweenEvent.DebugPhaseOption == 0);
            return true;
        }

        [MenuItem(PhaseRoot + "1 · Forzar PRÓXIMAMENTE")]
        private static void PhaseSoon() => HalloweenEvent.DebugPhaseOption = 1;

        [MenuItem(PhaseRoot + "1 · Forzar PRÓXIMAMENTE", true)]
        private static bool PhaseSoonValidate()
        {
            Menu.SetChecked(PhaseRoot + "1 · Forzar PRÓXIMAMENTE", HalloweenEvent.DebugPhaseOption == 1);
            return true;
        }

        [MenuItem(PhaseRoot + "2 · Forzar ACTIVO")]
        private static void PhaseActive() => HalloweenEvent.DebugPhaseOption = 2;

        [MenuItem(PhaseRoot + "2 · Forzar ACTIVO", true)]
        private static bool PhaseActiveValidate()
        {
            Menu.SetChecked(PhaseRoot + "2 · Forzar ACTIVO", HalloweenEvent.DebugPhaseOption == 2);
            return true;
        }

        [MenuItem(PhaseRoot + "3 · Forzar TERMINADO")]
        private static void PhaseEnded() => HalloweenEvent.DebugPhaseOption = 3;

        [MenuItem(PhaseRoot + "3 · Forzar TERMINADO", true)]
        private static bool PhaseEndedValidate()
        {
            Menu.SetChecked(PhaseRoot + "3 · Forzar TERMINADO", HalloweenEvent.DebugPhaseOption == 3);
            return true;
        }

        // ── Sello «SE VA PRONTO!» ─────────────────────────────────────────

        [MenuItem(Root + "Forzar el sello «SE VA PRONTO!» (QA)", false, 19)]
        private static void ToggleSeal() =>
            HalloweenEvent.DebugForceFinalStretch = !HalloweenEvent.DebugForceFinalStretch;

        [MenuItem(Root + "Forzar el sello «SE VA PRONTO!» (QA)", true)]
        private static bool ToggleSealValidate()
        {
            Menu.SetChecked(Root + "Forzar el sello «SE VA PRONTO!» (QA)", HalloweenEvent.DebugForceFinalStretch);
            return true;
        }

        // ── Atajos de progreso ────────────────────────────────────────────

        [MenuItem(Root + "Dar +240 XP de la velada (4 niveles)", false, 20)]
        private static void AddXp()
        {
            HalloweenProgress.DebugAddXp(240);
            Debug.Log($"[Halloween QA] +240 XP · total {HalloweenProgress.Xp}/{HalloweenProgress.MaxXp} · nivel {HalloweenProgress.CurrentLevel}");
        }

        [MenuItem(Root + "Dar +40 Dulces", false, 21)]
        private static void AddDulces()
        {
            HalloweenCurrency.DebugAdd(40);
            Debug.Log($"[Halloween QA] +40 {HalloweenCurrency.Label} · saldo {HalloweenCurrency.Balance}");
        }

        [MenuItem(Root + "Completar las misiones de hoy (sin cobrar)", false, 22)]
        private static void CompleteMissions()
        {
            HalloweenMissions.DebugCompleteToday();
            Debug.Log($"[Halloween QA] Misiones diarias completadas: {HalloweenMissions.CompletedCount}/{HalloweenMissions.Slots} · pendientes de cobro {HalloweenMissions.PendingClaimsCount}");
        }

        [MenuItem(Root + "Completar las misiones de Sangre (sin cobrar)", false, 23)]
        private static void CompleteSangreMissions()
        {
            HalloweenMissions.DebugCompleteSangre();
            Debug.Log($"[Halloween QA] Exclusivas de Sangre completadas: "
                      + $"{HalloweenMissions.SangreCompletedCount(false)}/{HalloweenMissions.SangreFreeSlots} libres · "
                      + $"{HalloweenMissions.SangreCompletedCount(true)}/{HalloweenMissions.SangrePaidSlots} premium · "
                      + $"{HalloweenMissions.SangrePendingClaimsCount} pendientes");
        }

        [MenuItem(Root + "Abrir la Vía Sangre (gratis)", false, 24)]
        private static void UnlockSangre()
        {
            HalloweenPassModal.DebugUnlockSangre();
            Debug.Log("[Halloween QA] Vía Sangre abierta sin gastar Dulces.");
        }

        [MenuItem(Root + "Cerrar la Vía Sangre (volver a probar el candado)", false, 25)]
        private static void LockSangre()
        {
            HalloweenLanes.DebugLockSangre();
            Debug.Log("[Halloween QA] Vía Sangre cerrada: las 5 premium vuelven a estar bloqueadas.");
        }

        [MenuItem(Root + "Tienda: dar +500 Dulces (packs, skins y variantes)", false, 26)]
        private static void AddDulcesShop()
        {
            HalloweenCurrency.DebugAdd(500);
            Debug.Log($"[Halloween QA] +500 {HalloweenCurrency.Label} · saldo {HalloweenCurrency.Balance}");
        }

        [MenuItem(Root + "Tienda: revocar las compras de la velada (skins y variantes)", false, 27)]
        private static void RevokeShopPurchases()
        {
            if (!EditorUtility.DisplayDialog(
                    "Revocar compras de la velada",
                    "Las 4 skins y las 3 variantes vuelven a estar a la venta.\n" +
                    "Los Dulces, el pase y la Vía Sangre no se tocan.",
                    "Revocar", "Cancelar"))
                return;

            foreach (HalloweenShop.SkinOffer skin in HalloweenShop.SkinOffers)
                PieceSkinManager.DebugRevokeOwnership(skin.skinId);
            PieceLoadoutManager.DebugRevokeShopVariants();
            Debug.Log("[Halloween QA] Skins y variantes de la velada devueltas a la tienda para recomprarlas.");
        }

        [MenuItem(Root + "Revocar la Reina Vampira (probar la Vía Sangre desde cero)", false, 28)]
        private static void RevokeVampire()
        {
            if (!EditorUtility.DisplayDialog(
                    "Revocar la Reina Vampira",
                    "La variante vuelve a estar bloqueada en la Vía Sangre.\n" +
                    "Si estaba equipada, la Dama vuelve a la clásica.",
                    "Revocar", "Cancelar"))
                return;

            PieceLoadoutManager.DebugRevokeVampire();
            Debug.Log("[Halloween QA] Reina Vampira revocada: vuelve a cobrarse en la Vía Sangre.");
        }

        [MenuItem(Root + "Ver estado en la consola", false, 40)]
        private static void LogStatus()
        {
            Debug.Log(
                "[Halloween QA] Estado de la velada\n" +
                $"  · Fase: {HalloweenEvent.CurrentPhase} (override {HalloweenEvent.DebugPhaseOption}) · {HalloweenEvent.TimeTextNow}\n" +
                $"  · XP: {HalloweenProgress.Xp}/{HalloweenProgress.MaxXp} · nivel {HalloweenProgress.CurrentLevel}/{HalloweenProgress.TierCount}\n" +
                $"  · {HalloweenCurrency.Label}: {HalloweenCurrency.Balance}\n" +
                $"  · Vía Sangre: {(HalloweenLanes.SangreUnlocked ? "abierta" : $"cerrada ({HalloweenLanes.SangreUnlockCost} Dulces)")}\n" +
                $"  · Misiones diarias: {HalloweenMissions.CompletedCount}/{HalloweenMissions.Slots} completadas · {HalloweenMissions.PendingClaimsCount} pendientes\n" +
                $"  · Misiones de Sangre: {HalloweenMissions.SangreCompletedCount(false)}/{HalloweenMissions.SangreFreeSlots} libres · " +
                $"{HalloweenMissions.SangreCompletedCount(true)}/{HalloweenMissions.SangrePaidSlots} premium · " +
                $"{HalloweenMissions.SangrePendingClaimsCount} pendientes · {HalloweenMissions.SangreClaimedCount} cobradas\n" +
                $"  · Cobros Luna: {HalloweenPassModal.ClaimedCount(false)}/{HalloweenProgress.TierCount} · Sangre: {HalloweenPassModal.ClaimedCount(true)}/{HalloweenProgress.TierCount}");
        }

        [MenuItem(Root + "Tienda: ver estado en la consola", false, 42)]
        private static void LogShopStatus()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("[Halloween QA] Tienda de la velada");
            sb.AppendLine(HalloweenShop.LevelsOnSale
                ? "  · Niveles: a la venta (velada activa)"
                : "  · Niveles: cerrados (fuera de la velada activa)");
            sb.AppendLine($"  · Nivel {HalloweenProgress.CurrentLevel}/{HalloweenProgress.TierCount} · XP {HalloweenProgress.Xp}/{HalloweenProgress.MaxXp} · faltan {HalloweenShop.MissingLevels} niveles");
            sb.AppendLine(HalloweenShop.PassComplete
                ? "  · Pase completo: no queda nada que comprar"
                : $"  · Completar todo el pase: {HalloweenShop.CompletePassPrice} {HalloweenCurrency.Icon} ({HalloweenShop.CompletePassPerLevel} {HalloweenCurrency.Icon} por nivel)");
            sb.AppendLine($"  · Monedero: {HalloweenCurrency.Balance} {HalloweenCurrency.Icon} · {GambitEconomy.Balance} Gambits");

            foreach (HalloweenShop.SkinOffer skin in HalloweenShop.SkinOffers)
            {
                int index = PieceSkinManager.GetIndexById(skin.skinId);
                string state = index < 0 ? "sin ficha en PieceSkinManager"
                             : PieceSkinManager.IsEquipped(index) ? "EN USO"
                             : PieceSkinManager.IsOwnedById(skin.skinId) ? "en el inventario"
                             : $"en venta por {skin.price} {HalloweenCurrency.Icon}";
                sb.AppendLine($"  · Skin {skin.skinId}: {state}");
            }

            foreach (HalloweenShop.VariantOffer variant in HalloweenShop.VariantOffers)
            {
                string state = HalloweenShop.IsVariantEquipped(variant.id) ? "EN USO"
                             : HalloweenShop.IsVariantOwned(variant.id) ? "en el inventario"
                             : $"en venta por {variant.price} {HalloweenCurrency.Icon}";
                sb.AppendLine($"  · Variante {variant.name} ({variant.id}): {state}");
            }

            Debug.Log(sb.ToString());
        }

        [MenuItem(Root + "Reset total de la velada", false, 41)]
        private static void ResetAll()
        {
            if (!EditorUtility.DisplayDialog(
                    "Reset de la velada",
                    "Borra XP, Dulces, cobros, Vía Sangre y misiones de Halloween.\n" +
                    "No toca la temporada T1 ni sus cobros.",
                    "Borrar", "Cancelar"))
                return;

            HalloweenProgress.DebugReset();
            HalloweenCurrency.DebugReset();
            HalloweenMissions.DebugReset();
            HalloweenPassModal.DebugReset();
            Debug.Log("[Halloween QA] Velada reiniciada por completo.");
        }
    }
}
