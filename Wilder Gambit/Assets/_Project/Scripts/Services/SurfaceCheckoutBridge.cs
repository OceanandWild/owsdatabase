using System;
using System.Collections;
using OWS.Surface;
using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.Services
{
    /// <summary>
    /// Une la tienda de Wilder Gambit con el checkout global de Surface.
    ///
    /// Todas las compras que gastan Gambits o Tides pasan por acá: el módulo
    /// muestra el ticket, valida saldo y topes, y el servidor debita. Después
    /// del cobro el artículo se entrega localmente (propiedad en PlayerPrefs)
    /// y el saldo en memoria se actualiza con el que devolvió Surface.
    ///
    /// El Pase de Halloween no usa este puente: se paga con Dulces y tiene su
    /// propio flujo. El Pase de Temporada sí entra, con su endpoint de siempre.
    /// </summary>
    public static class SurfaceCheckoutBridge
    {
        public const string Origin = "Wilder Gambit";
        public const string TokenPrefKey = "OceanPayToken";
        public const string TidesPrefKey = "PlayerTides";

        private const string PanelSettingsResource = "SurfaceUI/SurfaceCheckoutPanelSettings";

        /// <summary>Token de la sesión Surface, venga del servicio o de PlayerPrefs.</summary>
        public static string Token
        {
            get
            {
                var svc = OceanPayService.Instance;
                if (svc != null && !string.IsNullOrEmpty(svc.SavedToken)) return svc.SavedToken;
                return PlayerPrefs.GetString(TokenPrefKey, "");
            }
        }

        public static bool HasSession => !string.IsNullOrEmpty(Token);

        /// <summary>Compra un artículo con Gambits.</summary>
        public static void BuyGambits(string productId, string productName, string description, int price,
            Action<SurfacePurchaseResult> onDone)
        {
            Buy(new SurfacePurchaseRequest
            {
                productId = productId,
                productName = productName,
                description = description,
                price = price,
                currency = "gambits",
                origin = Origin
            }, onDone);
        }

        /// <summary>Compra un artículo con Tides.</summary>
        public static void BuyTides(string productId, string productName, string description, int price,
            Action<SurfacePurchaseResult> onDone)
        {
            Buy(new SurfacePurchaseRequest
            {
                productId = productId,
                productName = productName,
                description = description,
                price = price,
                currency = "tides",
                origin = Origin
            }, onDone);
        }

        /// <summary>Abre el checkout y devuelve el resultado real del cobro.</summary>
        public static void Buy(SurfacePurchaseRequest request, Action<SurfacePurchaseResult> onDone)
        {
            if (request == null)
            {
                onDone?.Invoke(Failure("La compra no tiene un producto válido.", "INVALID_PRODUCT"));
                return;
            }

            SurfaceCheckoutUI ui = EnsureInstance();
            if (ui == null)
            {
                onDone?.Invoke(Failure("El checkout de Surface no está disponible en esta escena.", "UI_NOT_READY"));
                return;
            }

            ui.SessionToken = Token;
            ui.OpenCheckout(request, result =>
            {
                ApplyBalance(result);
                onDone?.Invoke(result);
            });
        }

        /// <summary>
        /// Pase de Temporada: el checkout muestra la revisión y los topes, pero
        /// el cobro lo resuelve el endpoint del pase (que además entrega la
        /// ventaja en el servidor). Así nunca se cobra dos veces.
        /// </summary>
        public static void BuySeasonPass(int price, string productName, string description,
            Action<SurfacePurchaseResult> onDone)
        {
            SurfaceCheckoutUI ui = EnsureInstance();
            if (ui == null)
            {
                onDone?.Invoke(Failure("El checkout de Surface no está disponible en esta escena.", "UI_NOT_READY"));
                return;
            }

            var request = new SurfacePurchaseRequest
            {
                productId = "wilder-gambit-season-pass",
                productName = productName,
                description = description,
                price = price,
                currency = "tides",
                origin = Origin
            };

            ui.SessionToken = Token;
            ui.SubmitHandler = (req, done) => SeasonPassRoutine(req, done);
            ui.OpenCheckout(request, result =>
            {
                // El handler es por compra: no debe quedar pegado para la siguiente.
                ui.SubmitHandler = null;
                ApplyBalance(result);
                onDone?.Invoke(result);
            });
        }

        private static IEnumerator SeasonPassRoutine(SurfacePurchaseRequest request,
            Action<SurfacePurchaseResult> done)
        {
            var svc = OceanPayService.Instance;
            if (svc == null || !svc.IsLoggedIn)
            {
                done(Failure("Iniciá sesión en Surface para pagar con Tides.", "NO_SESSION"));
                yield break;
            }

            OceanPayUser.SeasonPassPurchaseResponse resp = null;
            string error = null;
            yield return svc.BuySeasonPassAsync(r => resp = r, e => error = e);

            if (resp == null || !resp.success)
            {
                done(Failure(string.IsNullOrEmpty(error) ? "No se pudo completar el pago." : error,
                    "SEASON_PASS_FAILED"));
                yield break;
            }

            int spent = resp.alreadyOwned ? 0 : Mathf.Max(0, resp.spent);
            long newBalance = Mathf.RoundToInt(resp.tides);
            done(new SurfacePurchaseResult
            {
                success = true,
                cancelled = false,
                message = "Compra completada",
                code = resp.alreadyOwned ? "ALREADY_OWNED" : "OK",
                transactionId = 0,
                productName = request.productName,
                price = spent,
                currency = "TIDES",
                previousBalance = newBalance + spent,
                newBalance = newBalance,
                purchasedAt = DateTime.UtcNow.ToString("o"),
                origin = request.origin
            });
        }

        /// <summary>
        /// Refleja en la sesión local el saldo que devolvió Surface. Se llama
        /// solo después de un cobro exitoso: acá no se descuenta nada.
        /// </summary>
        public static void ApplyBalance(SurfacePurchaseResult result)
        {
            if (result == null || !result.success) return;

            if (string.Equals(result.currency, "TIDES", StringComparison.OrdinalIgnoreCase))
            {
                int tides = (int)Mathf.Max(0, result.newBalance);
                var svc = OceanPayService.Instance;
                if (svc != null && svc.CurrentUser != null) svc.CurrentUser.tides = tides;
                PlayerPrefs.SetInt(TidesPrefKey, tides);
                PlayerPrefs.Save();
                return;
            }

            PieceSkinManager.SetLocalGambits((int)Mathf.Max(0, result.newBalance));
        }

        /// <summary>
        /// Devuelve el checkout de la escena o lo crea con la configuración de
        /// Resources. El objeto es DontDestroyOnLoad, así que sobrevive a los
        /// cambios de escena y se reutiliza en toda la sesión.
        /// </summary>
        public static SurfaceCheckoutUI EnsureInstance()
        {
            if (SurfaceCheckoutUI.Instance != null) return SurfaceCheckoutUI.Instance;

            SurfaceCheckoutUI existing = UnityEngine.Object.FindAnyObjectByType<SurfaceCheckoutUI>(
                FindObjectsInactive.Include);
            if (existing != null) return existing;

            PanelSettings panelSettings = Resources.Load<PanelSettings>(PanelSettingsResource);

            // Si el proyecto todavía no tiene el PanelSettings en Resources, se
            // reutiliza el panel de cualquier UIDocument de la escena. Es un
            // último recurso para no dejar la compra sin UI.
            if (panelSettings == null)
            {
                UIDocument anyDocument = UnityEngine.Object.FindAnyObjectByType<UIDocument>(
                    FindObjectsInactive.Include);
                if (anyDocument != null) panelSettings = anyDocument.panelSettings;
            }

            var go = new GameObject("SurfaceCheckout");
            var document = go.AddComponent<UIDocument>();
            if (panelSettings != null) document.panelSettings = panelSettings;
            document.sortingOrder = 500;

            return go.AddComponent<SurfaceCheckoutUI>();
        }

        private static SurfacePurchaseResult Failure(string message, string code)
        {
            return new SurfacePurchaseResult
            {
                success = false,
                cancelled = false,
                message = message,
                code = code
            };
        }
    }
}
