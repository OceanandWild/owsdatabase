using System;
using System.Collections.Generic;
using OWS.Surface;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Services;

namespace WilderGambit.UI
{
    /// <summary>
    /// Overlay del carrito del Atelier: lista los artículos con su miniatura,
    /// permite quitarlos, muestra el total y abre un único checkout de Surface.
    /// La entrega local ocurre recién cuando Surface confirma el cobro.
    /// </summary>
    public sealed class ShopCartUI
    {
        private readonly ShopCart _cart;
        private readonly Action _onPaid;
        private readonly Action _onCartChanged;

        private readonly VisualElement _overlay;
        private readonly VisualElement _list;
        private readonly ScrollView _scroll;
        private readonly VisualElement _empty;
        private readonly VisualElement _totalHost;
        private readonly Button _payButton;
        private readonly Button _clearButton;
        private readonly VisualElement _status;
        private readonly Label _statusLabel;
        private readonly Label _badge;
        private readonly Button _cartButton;
        private readonly Label _toast;

        private IVisualElementScheduledItem _toastHide;
        private bool _paying;

        public ShopCartUI(VisualElement shopRoot, ShopCart cart, Action onPaid, Action onCartChanged)
        {
            _cart = cart;
            _onPaid = onPaid;
            _onCartChanged = onCartChanged;

            if (shopRoot == null || cart == null) return;

            _overlay = shopRoot.Q<VisualElement>("shop-cart-overlay");
            _list = shopRoot.Q<VisualElement>("shop-cart-list");
            _scroll = shopRoot.Q<ScrollView>("shop-cart-scroll");
            _empty = shopRoot.Q<VisualElement>("shop-cart-empty");
            _totalHost = shopRoot.Q<VisualElement>("shop-cart-total");
            _payButton = shopRoot.Q<Button>("btn-cart-pay");
            _clearButton = shopRoot.Q<Button>("btn-cart-clear");
            _status = shopRoot.Q<VisualElement>("shop-cart-status");
            _statusLabel = shopRoot.Q<Label>("shop-cart-status-label");
            _badge = shopRoot.Q<Label>("shop-cart-count");
            _cartButton = shopRoot.Q<Button>("btn-shop-cart");
            _toast = shopRoot.Q<Label>("shop-toast");

            _cartButton?.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                Open();
            });

            var closeButton = shopRoot.Q<Button>("btn-cart-close");
            closeButton?.RegisterCallback<ClickEvent>(_ => Close());

            var browseButton = shopRoot.Q<Button>("btn-cart-browse");
            browseButton?.RegisterCallback<ClickEvent>(_ => Close());

            _payButton?.RegisterCallback<ClickEvent>(_ => Pay());
            _clearButton?.RegisterCallback<ClickEvent>(_ => OnClearClicked());

            _cart.Changed += Rebuild;
            Rebuild();
        }

        /// <summary>Abre la lista de compra y depura lo que ya entró al inventario.</summary>
        public void Open()
        {
            if (_overlay == null || _cart == null) return;

            HideStatus();
            _overlay.RemoveFromClassList("hidden");

            int pruned = _cart.PruneOwned();
            if (pruned > 0)
            {
                ShowToast(pruned == 1
                    ? "Quitamos un artículo que ya estaba en tu inventario."
                    : "Quitamos " + pruned + " artículos que ya estaban en tu inventario.");
            }

            Rebuild();
        }

        public void Close()
        {
            _overlay?.AddToClassList("hidden");
            HideStatus();
        }

        /// <summary>Repinta el estado de pago (por ejemplo, después de iniciar sesión).</summary>
        public void Refresh()
        {
            Rebuild();
        }

        public void HideToast()
        {
            _toastHide?.Pause();
            _toast?.AddToClassList("hidden");
        }

        public void ShowToast(string message, bool error = false)
        {
            if (_toast == null || string.IsNullOrEmpty(message)) return;

            _toast.text = message;
            _toast.RemoveFromClassList("hidden");
            _toast.EnableInClassList("shop-toast-error", error);

            _toastHide?.Pause();
            _toastHide = _toast.schedule.Execute(() =>
            {
                if (_toast != null) _toast.AddToClassList("hidden");
            }).StartingIn(2800);
        }

        private void OnClearClicked()
        {
            if (_paying || _cart == null || _cart.IsEmpty) return;
            _cart.Clear();
            HideStatus();
        }

        private void Rebuild()
        {
            if (_cart == null) return;

            int count = _cart.Count;
            bool empty = count == 0;

            if (_badge != null)
            {
                _badge.text = count.ToString();
                _badge.EnableInClassList("hidden", empty);
            }
            if (_cartButton != null)
                _cartButton.EnableInClassList("has-items", !empty);

            if (_scroll != null)
                _scroll.style.display = empty ? DisplayStyle.None : DisplayStyle.Flex;
            if (_empty != null)
                _empty.style.display = empty ? DisplayStyle.Flex : DisplayStyle.None;

            if (_list != null)
            {
                _list.Clear();
                if (!empty)
                {
                    for (int i = 0; i < _cart.Items.Count; i++)
                        _list.Add(BuildRow(_cart.Items[i]));
                }
            }

            BuildTotal();

            bool hasSession = SurfaceCheckoutBridge.HasSession;
            if (_payButton != null)
            {
                _payButton.SetEnabled(!empty && !_paying && hasSession);
                if (_paying)
                    _payButton.text = "PROCESANDO…";
                else if (empty)
                    _payButton.text = "CARRITO VACÍO";
                else if (!hasSession)
                    _payButton.text = "INICIÁ SESIÓN PARA PAGAR";
                else
                    _payButton.text = "PAGAR — " + _cart.Total.ToString("N0") + " " +
                                      _cart.CurrencyLabel().ToUpperInvariant();
            }

            if (_clearButton != null)
                _clearButton.SetEnabled(!empty && !_paying);

            _onCartChanged?.Invoke();
        }

        private VisualElement BuildRow(ShopCartItem item)
        {
            var row = new VisualElement();
            row.AddToClassList("shop-cart-row");

            var thumb = new VisualElement();
            thumb.AddToClassList("shop-cart-thumb");
            if (item.thumbnail != null)
            {
                var image = new Image { image = item.thumbnail, scaleMode = ScaleMode.ScaleToFit };
                image.AddToClassList("shop-cart-thumb-img");
                thumb.Add(image);
            }
            else if (item.sprite != null)
            {
                var image = new Image { sprite = item.sprite, scaleMode = ScaleMode.ScaleToFit };
                image.AddToClassList("shop-cart-thumb-img");
                thumb.Add(image);
            }
            else
            {
                var icon = new Label(string.IsNullOrEmpty(item.fallbackIcon) ? "◈" : item.fallbackIcon);
                icon.AddToClassList("shop-cart-thumb-icon");
                thumb.Add(icon);
            }
            row.Add(thumb);

            var info = new VisualElement();
            info.AddToClassList("shop-cart-info");

            var name = new Label(item.displayName);
            name.AddToClassList("shop-cart-name");
            info.Add(name);

            string kind = string.IsNullOrEmpty(item.kindLabel) ? "ARTÍCULO" : item.kindLabel;
            var kindLabel = new Label(kind + "  ·  " + ShopCart.CurrencyLabel(item.currency).ToUpperInvariant());
            kindLabel.AddToClassList("shop-cart-kind");
            info.Add(kindLabel);

            row.Add(info);

            if (item.currency == ShopCurrency.Tides)
            {
                var price = new Label("💧 " + item.price.ToString("N0") + " Tides");
                price.AddToClassList("shop-cart-price");
                price.AddToClassList("shop-cart-price-tides");
                row.Add(price);
            }
            else
            {
                var price = GambitIcon.Price(item.price, 14f, "shop-cart-price");
                price.AddToClassList("shop-cart-price-row");
                row.Add(price);
            }

            var remove = new Button { text = "✕" };
            remove.AddToClassList("shop-cart-remove");
            remove.tooltip = "Quitar del carrito";
            string productId = item.productId;
            remove.RegisterCallback<ClickEvent>(evt =>
            {
                evt.StopPropagation();
                if (_paying || _cart == null) return;
                _cart.Remove(productId);
                HideStatus();
            });
            row.Add(remove);

            return row;
        }

        private void BuildTotal()
        {
            if (_totalHost == null) return;
            _totalHost.Clear();

            if (_cart.IsEmpty)
            {
                var zero = new Label("0 Gambits");
                zero.AddToClassList("shop-cart-total-text");
                _totalHost.Add(zero);
                return;
            }

            if (_cart.Currency == ShopCurrency.Tides)
            {
                var tides = new Label("💧 " + _cart.Total.ToString("N0") + " Tides");
                tides.AddToClassList("shop-cart-total-text");
                _totalHost.Add(tides);
                return;
            }

            var row = GambitIcon.Price(_cart.Total, 18f, "shop-cart-total-text");
            row.AddToClassList("shop-cart-total-row");
            _totalHost.Add(row);
        }

        private void Pay()
        {
            if (_paying || _cart == null || _cart.IsEmpty) return;
            if (!SurfaceCheckoutBridge.HasSession)
            {
                ShowStatus("Iniciá sesión en Surface para poder pagar.", true);
                return;
            }

            int pruned = _cart.PruneOwned();
            if (pruned > 0)
            {
                ShowToast(pruned == 1
                    ? "Quitamos un artículo que ya tenías."
                    : "Quitamos " + pruned + " artículos que ya tenías.");
            }
            if (_cart.IsEmpty)
            {
                ShowStatus("Los artículos del carrito ya están en tu inventario.");
                return;
            }

            int total = _cart.Total;
            if (total <= 0)
            {
                ShowStatus("El carrito no tiene un total válido.");
                return;
            }

            ShopCurrency currency = _cart.Currency;
            string productName = _cart.CheckoutProductName;
            string description = _cart.CheckoutDescription;
            var items = new List<ShopCartItem>(_cart.Items);
            string productId = "wilder-gambit-cart-" + DateTime.UtcNow.Ticks;

            _paying = true;
            HideStatus();
            Rebuild();

            Action<SurfacePurchaseResult> done = result =>
            {
                _paying = false;

                if (result == null || !result.success)
                {
                    Rebuild();
                    string message = result != null && !string.IsNullOrEmpty(result.message)
                        ? result.message
                        : "No se pudo completar la compra.";
                    ShowStatus(message, true);
                    if (result != null && result.cancelled)
                        ShowToast("Compra cancelada. Tu carrito sigue intacto.");
                    return;
                }

                _cart.Clear();

                int granted = 0;
                for (int i = 0; i < items.Count; i++)
                {
                    try
                    {
                        if (items[i].grant == null) continue;
                        items[i].grant();
                        granted++;
                    }
                    catch (Exception exception)
                    {
                        Debug.LogException(exception);
                    }
                }

                _onPaid?.Invoke();
                Close();
                ShowToast(granted == 1
                    ? "Compra completada. Tu artículo ya está en el inventario."
                    : "Compra completada. " + granted + " artículos ya están en tu inventario.");
            };

            if (currency == ShopCurrency.Tides)
                SurfaceCheckoutBridge.BuyTides(productId, productName, description, total, done);
            else
                SurfaceCheckoutBridge.BuyGambits(productId, productName, description, total, done);
        }

        private void ShowStatus(string message, bool error = false)
        {
            if (_status == null || _statusLabel == null) return;
            if (string.IsNullOrEmpty(message))
            {
                HideStatus();
                return;
            }

            _status.RemoveFromClassList("hidden");
            _status.EnableInClassList("shop-cart-status-error", error);
            _statusLabel.text = message;
        }

        private void HideStatus()
        {
            _status?.AddToClassList("hidden");
            _status?.EnableInClassList("shop-cart-status-error", false);
            if (_statusLabel != null) _statusLabel.text = "";
        }
    }
}
