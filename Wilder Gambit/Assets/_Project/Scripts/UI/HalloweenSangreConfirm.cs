using System;
using System.Collections.Generic;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Confirmación de compra de la Vía Sangre. No vive en un UXML: se monta
    /// como overlay sobre el modal que la invoca (el tablero de misiones o el
    /// pase de la velada), así los dos entry points comparten el mismo resumen
    /// de recompensas y el mismo botón de compra.
    ///
    /// El overlay se agrega al root fullscreen del modal, tapa el resto de la
    /// UI y se elimina solo al cancelar o confirmar. Si falta saldo, el botón
    /// de compra queda deshabilitado y el precio muestra cuánto falta: el
    /// jugador igual puede ver todas las recompensas antes de decidir.
    /// </summary>
    public static class HalloweenSangreConfirm
    {
        private const string OverlayName = "hwc-overlay";

        public static void Show(VisualElement host, Action onConfirmed)
        {
            if (host == null || onConfirmed == null) return;
            Hide(host);

            var overlay = new VisualElement { name = OverlayName };
            overlay.AddToClassList("hwc-overlay");
            overlay.pickingMode = PickingMode.Position;

            var panel = new VisualElement();
            panel.AddToClassList("hwc-panel");
            overlay.Add(panel);

            var kicker = new Label("VÍA SANGRE · CONFIRMACIÓN");
            kicker.AddToClassList("hwc-kicker");
            panel.Add(kicker);

            var title = new Label("Abrir la Vía Sangre");
            title.AddToClassList("hwc-title");
            panel.Add(title);

            var sub = new Label(
                "Un solo pago por edición: desbloquea las 5 misiones premium y el carril Sangre del pase. "
                + "Los niveles que ya ganaste te esperan.");
            sub.AddToClassList("hwc-sub");
            panel.Add(sub);

            var scroll = new ScrollView(ScrollViewMode.Vertical);
            scroll.AddToClassList("hwc-scroll");
            scroll.horizontalScrollerVisibility = ScrollerVisibility.Hidden;
            panel.Add(scroll);

            // ── Las 5 misiones premium: título y pago de cada una ──────────
            int xp = 0;
            int dulces = 0;
            var rows = new List<HwRewardRow>();
            for (int i = HalloweenMissions.SangreFreeSlots; i < HalloweenMissions.SangreSlots; i++)
            {
                var def = HalloweenMissions.SangreGetAt(i);
                if (def == null) continue;
                xp += def.xp;
                dulces += def.dulces;
                rows.Add(new HwRewardRow(def.icon, def.title, def.RewardText));
            }

            AddSectionHead(scroll, "MISIONES PREMIUM",
                $"{rows.Count} · +{xp} XP · +{dulces} {HalloweenCurrency.Icon}");
            for (int i = 0; i < rows.Count; i++)
                scroll.Add(BuildRow(rows[i].icon, rows[i].name, rows[i].pay));

            // ── Carril Sangre del pase: totales + piezas que reparte ───────
            HalloweenPassModal.GetSangreLaneSummary(
                out int laneDulces, out int laneGambits, out List<string> highlights);

            AddSectionHead(scroll, "CARRIL SANGRE DEL PASE",
                $"{HalloweenProgress.TierCount} niveles"
                + (laneDulces > 0 ? $" · +{laneDulces} {HalloweenCurrency.Icon}" : "")
                + $" · +{laneGambits:N0} Gambits");

            if (highlights.Count > 0)
            {
                var chips = new VisualElement();
                chips.AddToClassList("hwc-chips");
                for (int i = 0; i < highlights.Count; i++)
                {
                    var chip = new Label(highlights[i]);
                    chip.AddToClassList("hwc-chip");
                    chips.Add(chip);
                }
                scroll.Add(chips);
            }

            var laneNote = new Label(
                "Se cobran al alcanzar cada nivel; los niveles ya alcanzados quedan disponibles al abrir.");
            laneNote.AddToClassList("hwc-note");
            scroll.Add(laneNote);

            // ── Coste y saldo resultante ───────────────────────────────────
            int cost = HalloweenLanes.SangreUnlockCost;
            int balance = HalloweenCurrency.Balance;
            bool canAfford = balance >= cost;

            var price = new VisualElement();
            price.AddToClassList("hwc-price");

            var priceTexts = new VisualElement();
            priceTexts.AddToClassList("hwc-price-texts");

            var priceLabel = new Label("COSTE DE APERTURA");
            priceLabel.AddToClassList("hwc-price-label");
            priceTexts.Add(priceLabel);

            var priceNote = new Label(canAfford
                ? $"Tienes {balance:N0} · te quedan {balance - cost:N0}"
                : $"Tienes {balance:N0} · te faltan {cost - balance:N0}");
            priceNote.AddToClassList("hwc-balance");
            if (!canAfford) priceNote.AddToClassList("hwc-balance-low");
            priceTexts.Add(priceNote);

            price.Add(priceTexts);

            var priceValue = new Label($"{cost} {HalloweenCurrency.Icon}");
            priceValue.AddToClassList("hwc-price-value");
            price.Add(priceValue);
            panel.Add(price);

            // ── Acciones ───────────────────────────────────────────────────
            var actions = new VisualElement();
            actions.AddToClassList("hwc-actions");

            var cancel = new Button { text = "CANCELAR" };
            cancel.AddToClassList("hwc-btn");
            cancel.AddToClassList("hwc-cancel");
            cancel.RegisterCallback<ClickEvent>(_ =>
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                overlay.RemoveFromHierarchy();
            });
            actions.Add(cancel);

            var buy = new Button
            {
                text = canAfford
                    ? $"ABRIR · {cost} {HalloweenCurrency.Icon}"
                    : $"FALTAN {cost - balance:N0} {HalloweenCurrency.Icon}",
            };
            buy.AddToClassList("hwc-btn");
            buy.AddToClassList("hwc-buy");
            buy.SetEnabled(canAfford);
            buy.RegisterCallback<ClickEvent>(_ =>
            {
                WilderGambit.Audio.MusicManager.Instance?.PlayClickSound();
                overlay.RemoveFromHierarchy();
                onConfirmed();
            });
            actions.Add(buy);
            panel.Add(actions);

            host.Add(overlay);
            overlay.BringToFront();
        }

        /// <summary>Quita el overlay si quedó abierto (al cerrar el modal padre).</summary>
        public static void Hide(VisualElement host)
        {
            host?.Q<VisualElement>(OverlayName)?.RemoveFromHierarchy();
        }

        // ── Bloques ───────────────────────────────────────────────────────

        private static void AddSectionHead(VisualElement parent, string title, string total)
        {
            var head = new VisualElement();
            head.AddToClassList("hwc-section-head");

            var titleLabel = new Label(title);
            titleLabel.AddToClassList("hwc-section-title");
            head.Add(titleLabel);

            var totalLabel = new Label(total);
            totalLabel.AddToClassList("hwc-section-total");
            head.Add(totalLabel);

            parent.Add(head);
        }

        private static VisualElement BuildRow(string icon, string name, string pay)
        {
            var row = new VisualElement();
            row.AddToClassList("hwc-row");

            var iconLabel = new Label(icon);
            iconLabel.AddToClassList("hwc-row-icon");
            row.Add(iconLabel);

            var nameLabel = new Label(name);
            nameLabel.AddToClassList("hwc-row-name");
            row.Add(nameLabel);

            var payLabel = new Label(pay);
            payLabel.AddToClassList("hwc-row-pay");
            row.Add(payLabel);

            return row;
        }

        private readonly struct HwRewardRow
        {
            public readonly string icon;
            public readonly string name;
            public readonly string pay;

            public HwRewardRow(string icon, string name, string pay)
            {
                this.icon = icon;
                this.name = name;
                this.pay = pay;
            }
        }
    }
}
