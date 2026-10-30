using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Tienda de la Velada: el destino de los Dulces sobrantes de la edición.
    /// Vende tres cosas —niveles del mini-pase, las skins esculpidas del lote
    /// <c>hwp_*</c> y las variantes de la velada— y todo se paga con
    /// <see cref="HalloweenCurrency"/>.
    ///
    /// Reglas de la casa:
    ///  · la tienda VENDE, el inventario EQUIPA (nunca pone nada en uso);
    ///  · los niveles solo se compran con la velada activa (el XP se cobra
    ///    igual: <see cref="HalloweenProgress.AddXpForced"/>);
    ///  · cada cobro se verifica antes de dar por hecho el gasto: si algo no
    ///    queda en posesión del jugador, se devuelven los Dulces.
    ///
    /// Este archivo es el único lugar donde viven precios y catálogo: ajustar
    /// la economía de la edición es tocar una línea.
    /// </summary>
    public static class HalloweenShop
    {
        // ══ Niveles del pase ══════════════════════════════════════════════

        /// <summary>Un nivel del mini-pase (60 XP) en suelto: el precio más caro por nivel.</summary>
        public const int LevelPrice = 14;
        /// <summary>Niveles que entrega el tramo medio y lo que cuesta.</summary>
        public const int LevelMidCount = 5;
        public const int LevelMidPrice = 65;   // 13 por nivel
        /// <summary>Niveles que entrega la decena y lo que cuesta.</summary>
        public const int LevelTenCount = 10;
        public const int LevelTenPrice = 120;  // 12 por nivel
        /// <summary>
        /// Precio de «completar todo el pase», por nivel faltante: carísimo a
        /// propósito (≈780 Dulces desde cero, más que todo lo que reparte la
        /// edición). Es la salida de emergencia de quien llegó tarde.
        /// </summary>
        public const int CompletePassPerLevel = 26;

        /// <summary>Niveles que le faltan al pase para estar entero (0 = completo).</summary>
        public static int MissingLevels
        {
            get
            {
                int missing = HalloweenProgress.TierCount - HalloweenProgress.CurrentLevel;
                return Mathf.Clamp(missing, 0, HalloweenProgress.TierCount);
            }
        }

        /// <summary>¿El pase ya está al tope de XP?</summary>
        public static bool PassComplete => HalloweenProgress.Xp >= HalloweenProgress.MaxXp;

        /// <summary>¿Se pueden comprar niveles ahora? Solo con la velada activa.</summary>
        public static bool LevelsOnSale => HalloweenEvent.IsActiveNow;

        /// <summary>Precio de «completar todo el pase» con los niveles faltantes de ahora.</summary>
        public static int CompletePassPrice => MissingLevels * CompletePassPerLevel;

        /// <summary>Precio del tramo de 1 / 5 / 10 niveles, recortado a lo que falta.</summary>
        public static int BulkPrice(int levels, int fullPrice)
        {
            if (levels <= 0) return 0;
            int deliver = Mathf.Min(levels, MissingLevels);
            if (deliver <= 0) return 0;
            int perLevel = Mathf.Max(1, Mathf.RoundToInt(fullPrice / (float)levels));
            return deliver * perLevel;
        }

        /// <summary>Niveles que entregaría el tramo de 1 / 5 / 10 con lo que falta ahora.</summary>
        public static int BulkLevels(int levels) => Mathf.Clamp(Mathf.Min(levels, MissingLevels), 0, levels);

        // ══ Skins esculpidas ══════════════════════════════════════════════

        public struct SkinOffer
        {
            public string skinId;
            public string flavor;
            public int price;
        }

        /// <summary>
        /// Las seis pieles esculpidas de la velada. Todas tienen arte propio
        /// (<c>hwp_*</c>): la skin reemplaza el sprite de la pieza en partida.
        /// Las cuatro primeras son del lote original; las dos últimas, «La Corte»
        /// del Pase de la Velada 21-30 (Torre Relicario y Reina Maleficio), se
        /// venden aquí con Dulces en vez de entregarse en la Vía Sangre.
        /// Las skins que sí reparte el pase no aparecen en esta tabla.
        /// </summary>
        public static readonly SkinOffer[] SkinOffers =
        {
            new SkinOffer { skinId = "skin_pawn_spider", flavor = "Peón araña tejido en sombra.",        price = 55 },
            new SkinOffer { skinId = "skin_rook_crypt",  flavor = "Torre cripta sellada con lápidas.",    price = 70 },
            new SkinOffer { skinId = "skin_knight_bat",  flavor = "Caballo murciélago de la noche larga.", price = 75 },
            new SkinOffer { skinId = "skin_rook_grave",  flavor = "Torre tumba de la hora muerta.",      price = 85 },
            new SkinOffer { skinId = "skin_rook_reliquary", flavor = "Torre relicario de hueso, plata vieja y cera roja.", price = 125 },
            new SkinOffer { skinId = "skin_queen_hex",      flavor = "Dama de espino negro y fuego de bruja violeta.",     price = 165 },
        };

        public static int SkinPrice(string skinId)
        {
            for (int i = 0; i < SkinOffers.Length; i++)
                if (SkinOffers[i].skinId == skinId) return SkinOffers[i].price;
            return -1;
        }

        // ══ Variantes ═════════════════════════════════════════════════════

        public struct VariantOffer
        {
            public string id;
            public string name;
            public string icon;
            public string tag;
            public string flavor;
            public int price;
        }

        /// <summary>
        /// Variantes de la edición. Peón Calabaza y Caballo Fantasma traen su
        /// habilidad y se equipan por bando desde el inventario.
        /// </summary>
        public static readonly VariantOffer[] VariantOffers =
        {
            new VariantOffer
            {
                id = HalloweenArt.PumpkinPawnId, name = "Peón Calabaza", icon = "🎃", tag = "PEÓN",
                flavor = "Peón tallado en calabaza de la velada.", price = 110,
            },
            new VariantOffer
            {
                id = HalloweenArt.GhostKnightId, name = "Caballo Fantasma", icon = "👻", tag = "CABALLO",
                flavor = "Jinete de niebla que aparece y se desvanece.", price = 125,
            },
        };

        public static int VariantPrice(string variantId)
        {
            for (int i = 0; i < VariantOffers.Length; i++)
                if (VariantOffers[i].id == variantId) return VariantOffers[i].price;
            return -1;
        }

        public static bool IsVariantOwned(string variantId)
        {
            switch (variantId)
            {
                case HalloweenArt.PumpkinPawnId: return PieceLoadoutManager.IsPumpkinPawnOwned();
                case HalloweenArt.GhostKnightId: return PieceLoadoutManager.IsGhostKnightOwned();
                default: return false;
            }
        }

        private static bool OwnVariant(string variantId)
        {
            switch (variantId)
            {
                case HalloweenArt.PumpkinPawnId: PieceLoadoutManager.OwnPumpkinPawn(); return PieceLoadoutManager.IsPumpkinPawnOwned();
                case HalloweenArt.GhostKnightId: PieceLoadoutManager.OwnGhostKnight(); return PieceLoadoutManager.IsGhostKnightOwned();
                default: return false;
            }
        }

        /// <summary>Desbloquea una variante sin cobrar Dulces (recompensa del pase).</summary>
        public static bool GrantVariant(string variantId) => OwnVariant(variantId);

        /// <summary>¿La variante está equipada en alguno de los bandos?</summary>
        public static bool IsVariantEquipped(string variantId)
        {
            switch (variantId)
            {
                case HalloweenArt.PumpkinPawnId:
                    return PieceLoadoutManager.UsesPumpkinPawn(TeamColor.White)
                        || PieceLoadoutManager.UsesPumpkinPawn(TeamColor.Black);
                case HalloweenArt.GhostKnightId:
                    return PieceLoadoutManager.UsesGhostKnight(TeamColor.White)
                        || PieceLoadoutManager.UsesGhostKnight(TeamColor.Black);
                default:
                    return false;
            }
        }

        // ══ Compras ═══════════════════════════════════════════════════════

        /// <summary>
        /// Compra el tramo de niveles pedido (1 / 5 / 10) con la velada activa.
        /// El precio se calcula sobre lo que falta: nunca cobra de más.
        /// </summary>
        public static bool BuyLevels(int levels, int fullPrice, out string detail)
        {
            detail = null;

            if (!LevelsOnSale)
            {
                detail = HalloweenEvent.IsNotStartedNow
                    ? $"Los niveles se compran con la velada abierta · arranca el {HalloweenEvent.Start:dd/MM}"
                    : "La velada terminó: el pase ya no vende niveles";
                return false;
            }

            if (PassComplete)
            {
                detail = "El pase ya está completo";
                return false;
            }

            int deliver = BulkLevels(levels);
            int price = BulkPrice(levels, fullPrice);
            if (deliver <= 0 || price <= 0)
            {
                detail = "No queda nada por comprar";
                return false;
            }

            if (!HalloweenCurrency.Spend(price))
            {
                detail = $"Faltan Dulces: {price:N0} {HalloweenCurrency.Icon} y tienes {HalloweenCurrency.Balance:N0}";
                return false;
            }

            HalloweenProgress.AddXpForced(deliver * HalloweenProgress.XpPerTier);
            NotifyProgressChanged();
            detail = $"+{deliver * HalloweenProgress.XpPerTier:N0} XP de la velada por {price:N0} {HalloweenCurrency.Icon}";
            return true;
        }

        /// <summary>Compra «completar todo el pase»: XP hasta el tope a precio de lujo.</summary>
        public static bool BuyCompletePass(out string detail)
        {
            detail = null;

            if (!LevelsOnSale)
            {
                detail = HalloweenEvent.IsNotStartedNow
                    ? $"El pase se completa con la velada abierta · arranca el {HalloweenEvent.Start:dd/MM}"
                    : "La velada terminó: el pase ya no se completa";
                return false;
            }

            if (PassComplete)
            {
                detail = "El pase ya está completo";
                return false;
            }

            int missing = MissingLevels;
            int price = CompletePassPrice;
            if (missing <= 0 || price <= 0)
            {
                detail = "No queda nada por completar";
                return false;
            }

            if (!HalloweenCurrency.Spend(price))
            {
                detail = $"Faltan Dulces: cuesta {price:N0} {HalloweenCurrency.Icon} y tienes {HalloweenCurrency.Balance:N0}"
                       + $" · es el atajo de lujo, a {CompletePassPerLevel} {HalloweenCurrency.Icon} por nivel";
                return false;
            }

            int xp = HalloweenProgress.MaxXp - HalloweenProgress.Xp;
            HalloweenProgress.AddXpForced(xp);
            NotifyProgressChanged();
            detail = $"Pase completo · +{xp:N0} XP por {price:N0} {HalloweenCurrency.Icon}";
            return true;
        }

        /// <summary>Compra una skin esculpida (quien compra no equipa: eso es el inventario).</summary>
        public static bool BuySkin(string skinId, out string detail)
        {
            detail = null;
            int price = SkinPrice(skinId);
            if (price < 0)
            {
                detail = "Esa pieza no está en la tienda de la velada";
                return false;
            }

            int index = PieceSkinManager.GetIndexById(skinId);
            if (index < 0)
            {
                detail = "La skin no está en el catálogo";
                return false;
            }

            if (PieceSkinManager.IsOwned(index))
            {
                detail = "Ya es tuya: equípala en el inventario";
                return true;
            }

            if (!HalloweenCurrency.Spend(price))
            {
                detail = $"Faltan Dulces: {price:N0} {HalloweenCurrency.Icon} y tienes {HalloweenCurrency.Balance:N0}";
                return false;
            }

            PieceSkinManager.OwnSkin(index);
            if (!PieceSkinManager.IsOwned(index))
            {
                HalloweenCurrency.Earn(price, "devolución tienda de la velada");
                detail = "La skin no se pudo desbloquear · no se descontaron los Dulces";
                return false;
            }

            detail = $"{PieceSkinManager.GetSkinName(index)} · esculpida desbloqueada";
            return true;
        }

        /// <summary>Compra una variante (solo propiedad: se equipa en el inventario).</summary>
        public static bool BuyVariant(string variantId, out string detail)
        {
            detail = null;
            int price = VariantPrice(variantId);
            if (price < 0)
            {
                detail = "Esa variante no está en la tienda de la velada";
                return false;
            }

            if (IsVariantOwned(variantId))
            {
                detail = "Ya es tuya: equípala en el inventario";
                return true;
            }

            if (!HalloweenCurrency.Spend(price))
            {
                detail = $"Faltan Dulces: {price:N0} {HalloweenCurrency.Icon} y tienes {HalloweenCurrency.Balance:N0}";
                return false;
            }

            if (!OwnVariant(variantId))
            {
                HalloweenCurrency.Earn(price, "devolución tienda de la velada");
                detail = "La variante no se pudo desbloquear · no se descontaron los Dulces";
                return false;
            }

            GambitProgress.SyncVariantsOwned();
            detail = $"{VariantName(variantId)} · variante desbloqueada";
            return true;
        }

        public static string VariantName(string variantId)
        {
            for (int i = 0; i < VariantOffers.Length; i++)
                if (VariantOffers[i].id == variantId) return VariantOffers[i].name;
            return variantId;
        }

        /// <summary>Tras mover el XP del pase, la UI se repinta por la vía de siempre.</summary>
        private static void NotifyProgressChanged() => GambitProgress.NotifyChanged();
    }
}
