using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>Divisa de una línea del carrito. Surface cobra una sola por checkout.</summary>
    public enum ShopCurrency
    {
        Gambits,
        Tides
    }

    /// <summary>Artículo elegido para el carrito: precio, arte, propiedad y entrega.</summary>
    public sealed class ShopCartItem
    {
        public string productId;
        public string displayName;
        public string description;
        public string kindLabel;
        public int price;
        public ShopCurrency currency;
        public Texture2D thumbnail;
        public Sprite sprite;
        public string fallbackIcon;
        public Func<bool> isOwned;
        public Action grant;
    }

    /// <summary>Pestaña que sabe convertir su selección actual en una línea del carrito.</summary>
    public interface IShopCartSource
    {
        bool TryAddSelectedToCart();
        void RefreshCartButton();
    }

    /// <summary>
    /// Carrito de la tienda. Guarda la selección en memoria, valida duplicados y
    /// divisa única (Surface solo cobra una divisa por checkout) y expone el total.
    /// Los artículos se entregan recién cuando Surface confirma el cobro.
    /// </summary>
    public sealed class ShopCart
    {
        private readonly List<ShopCartItem> _items = new List<ShopCartItem>();

        /// <summary>La lista cambió (agregar, quitar, vaciar o depurar propiedad).</summary>
        public event Action Changed;
        /// <summary>Se agregó un artículo (para el aviso de la tienda).</summary>
        public event Action<ShopCartItem> ItemAdded;
        /// <summary>No se pudo agregar: ya está, es gratis, no tiene precio o cambia la divisa.</summary>
        public event Action<string> AddRejected;

        public IReadOnlyList<ShopCartItem> Items { get { return _items; } }
        public int Count { get { return _items.Count; } }
        public bool IsEmpty { get { return _items.Count == 0; } }

        public ShopCurrency Currency
        {
            get { return _items.Count > 0 ? _items[0].currency : ShopCurrency.Gambits; }
        }

        public int Total
        {
            get
            {
                int total = 0;
                for (int i = 0; i < _items.Count; i++) total += _items[i].price;
                return total;
            }
        }

        public string CheckoutProductName
        {
            get
            {
                if (_items.Count == 0) return "Carrito del Atelier";
                if (_items.Count == 1) return _items[0].displayName;
                return "Carrito del Atelier · " + _items.Count + " artículos";
            }
        }

        public string CheckoutDescription
        {
            get
            {
                if (_items.Count == 0) return "Carrito del Atelier";
                var names = new List<string>(_items.Count);
                for (int i = 0; i < _items.Count; i++) names.Add(_items[i].displayName);
                string plural = _items.Count == 1 ? "artículo" : "artículos";
                string text = _items.Count + " " + plural + ": " + string.Join(" · ", names);
                // Surface recorta la descripción a 240 caracteres: se manda ya
                // acotada para que el ticket no muestre un corte a mitad de palabra.
                const int maxLength = 240;
                return text.Length <= maxLength
                    ? text
                    : text.Substring(0, maxLength - 1) + "…";
            }
        }

        public bool Contains(string productId)
        {
            if (string.IsNullOrEmpty(productId)) return false;
            for (int i = 0; i < _items.Count; i++)
                if (string.Equals(_items[i].productId, productId, StringComparison.Ordinal))
                    return true;
            return false;
        }

        public bool Add(ShopCartItem item)
        {
            if (item == null)
            {
                Reject("El artículo no tiene datos válidos.");
                return false;
            }
            if (string.IsNullOrEmpty(item.productId))
            {
                Reject("El artículo no tiene identificador de compra.");
                return false;
            }
            if (item.price <= 0)
            {
                Reject("«" + item.displayName + "» es gratis: se consigue directo desde su ficha.");
                return false;
            }
            if (Contains(item.productId))
            {
                Reject("«" + item.displayName + "» ya está en el carrito.");
                return false;
            }
            if (_items.Count > 0 && _items[0].currency != item.currency)
            {
                string current = CurrencyLabel(_items[0].currency);
                string incoming = CurrencyLabel(item.currency);
                Reject("El carrito está en " + current +
                       ". Completá esa compra o vacía el carrito para añadir artículos en " + incoming + ".");
                return false;
            }

            _items.Add(item);
            ItemAdded?.Invoke(item);
            Changed?.Invoke();
            return true;
        }

        public bool Remove(string productId)
        {
            for (int i = 0; i < _items.Count; i++)
            {
                if (!string.Equals(_items[i].productId, productId, StringComparison.Ordinal)) continue;
                _items.RemoveAt(i);
                Changed?.Invoke();
                return true;
            }
            return false;
        }

        public void Clear()
        {
            if (_items.Count == 0) return;
            _items.Clear();
            Changed?.Invoke();
        }

        /// <summary>
        /// Saca los artículos que ya entraron al inventario por otra vía (compra
        /// directa, recompensa o reclamo) para no cobrarlos dos veces.
        /// </summary>
        public int PruneOwned()
        {
            int removed = 0;
            for (int i = _items.Count - 1; i >= 0; i--)
            {
                bool owned = false;
                try { owned = _items[i].isOwned != null && _items[i].isOwned(); }
                catch { owned = false; }
                if (!owned) continue;
                _items.RemoveAt(i);
                removed++;
            }
            if (removed > 0) Changed?.Invoke();
            return removed;
        }

        public string CurrencyLabel() { return CurrencyLabel(Currency); }

        public static string CurrencyLabel(ShopCurrency currency)
        {
            return currency == ShopCurrency.Tides ? "Tides" : "Gambits";
        }

        private void Reject(string reason)
        {
            AddRejected?.Invoke(reason);
        }

        /// <summary>
        /// Pinta el botón secundario del panel de detalle: visible solo si el
        /// artículo se puede comprar y alterna entre añadir y «en el carrito».
        /// </summary>
        public static void RefreshDetailButton(Button button, ShopCart cart, string productId, bool purchasable)
        {
            if (button == null) return;
            if (!purchasable)
            {
                button.style.display = DisplayStyle.None;
                return;
            }

            button.style.display = DisplayStyle.Flex;
            bool inCart = cart != null && cart.Contains(productId);
            button.SetEnabled(!inCart);
            button.text = inCart ? "✓  EN EL CARRITO" : "+  AÑADIR AL CARRITO";
        }
    }
}
