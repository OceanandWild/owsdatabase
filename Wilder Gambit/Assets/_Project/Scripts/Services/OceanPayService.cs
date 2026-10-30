using System;
using System.Collections;
using UnityEngine;

namespace WilderGambit.Services
{
    /// <summary>
    /// Cliente HTTP singleton para la API de Surface.
    /// Las peticiones pasan por <see cref="OwsApiFailover"/>: si el servidor
    /// principal (owsdatabase) no responde, se reintentan solas contra el
    /// espejo (owsdatabase2).
    /// Persiste el JWT en PlayerPrefs["OceanPayToken"].
    /// </summary>
    public class OceanPayService : MonoBehaviour
    {
        public static OceanPayService Instance { get; private set; }

        private const string TokenKey  = "OceanPayToken";
        private const string UserIdKey = "OceanPayUserId";
        private const string UserNameKey = "OceanPayUsername";

        public bool  IsLoggedIn  => !string.IsNullOrEmpty(SavedToken);
        public string SavedToken => PlayerPrefs.GetString(TokenKey, "");
        public string SavedUsername => PlayerPrefs.GetString(UserNameKey, "");

        // Ultimo usuario cargado en memoria
        public OceanPayUser CurrentUser { get; private set; }

        /// <summary>Momento (Time.realtimeSinceStartup) del último saldo leído del servidor.</summary>
        public float LastBalanceSyncAt { get; private set; } = -9999f;

        /// <summary>
        /// ¿Hay saldo de servidor lo bastante reciente como para no volver a preguntar?
        /// Render puede tardar en despertar, así que la UI solo enseña la pantalla de carga
        /// cuando el dato de verdad toca pedirlo.
        /// </summary>
        public bool HasRecentBalance(float maxAgeSeconds)
            => CurrentUser != null && Time.realtimeSinceStartup - LastBalanceSyncAt <= maxAgeSeconds;

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private void SaveSession(string token, int userId, string username)
        {
            PlayerPrefs.SetString(TokenKey,   token);
            PlayerPrefs.SetInt(UserIdKey,     userId);
            PlayerPrefs.SetString(UserNameKey, username);
            PlayerPrefs.Save();
        }

        public void ClearSession()
        {
            PlayerPrefs.DeleteKey(TokenKey);
            PlayerPrefs.DeleteKey(UserIdKey);
            PlayerPrefs.DeleteKey(UserNameKey);
            PlayerPrefs.Save();
            CurrentUser = null;
        }

        /// <summary>
        /// Mensaje para la UI: si el servidor contestó (usuario inexistente,
        /// contraseña incorrecta, etc.) se muestra su mensaje; si no hubo
        /// respuesta (red caída tras probar principal y espejo), el de red.
        /// </summary>
        private static string DescribeFailure(OwsApiCall call)
        {
            string serverMsg = call.ProtocolError ? call.ServerMessage : null;
            return serverMsg ?? ("Error de conexión: " + call.ErrorText);
        }

        // ── Login ─────────────────────────────────────────────────────────────

        public IEnumerator LoginAsync(string username, string password,
            Action<OceanPayUser> onSuccess, Action<string> onError)
        {
            string json = $"{{\"username\":\"{EscapeJson(username)}\",\"password\":\"{EscapeJson(password)}\"}}";
            var call = OwsApiFailover.Post("/ocean-pay/login", json);
            yield return call;

            if (!call.Success)
            {
                onError?.Invoke(DescribeFailure(call));
                yield break;
            }

            var resp = JsonUtility.FromJson<OceanPayUser.LoginResponse>(call.text);
            if (resp == null || !resp.success)
            {
                onError?.Invoke(resp?.error ?? "Error desconocido");
                yield break;
            }

            SaveSession(resp.token, resp.user?.id ?? 0, resp.user?.username ?? username);
            var user = OceanPayUser.FromLoginJson(resp);
            CurrentUser = user;

            // Extraer saldos iniciales del login si están presentes
            string loginRaw = call.text;
            float initialTides = ExtractBalanceFromJson(loginRaw, "tides");
            float initialGambits = ExtractBalanceFromJson(loginRaw, "gambits");
            if (user != null)
            {
                user.tides = initialTides;
                user.gambits = initialGambits;
            }

            // Cargar saldos completos
            yield return StartCoroutine(RefreshBalancesAsync(resp.token, user, null, null));
            onSuccess?.Invoke(CurrentUser ?? user);
        }

        // ── Register ─────────────────────────────────────────────────────────

        public IEnumerator RegisterAsync(string username, string password,
            Action<OceanPayUser> onSuccess, Action<string> onError)
        {
            string json = $"{{\"username\":\"{EscapeJson(username)}\",\"password\":\"{EscapeJson(password)}\"}}";
            var call = OwsApiFailover.Post("/ocean-pay/register", json);
            yield return call;

            if (!call.Success)
            {
                onError?.Invoke(DescribeFailure(call));
                yield break;
            }

            var resp = JsonUtility.FromJson<OceanPayUser.RegisterResponse>(call.text);
            if (resp == null || !resp.success)
            {
                onError?.Invoke(resp?.error ?? "Error al registrar");
                yield break;
            }

            SaveSession(resp.token, resp.user?.id ?? 0, resp.user?.username ?? username);
            var user = new OceanPayUser
            {
                id = resp.user?.id ?? 0,
                username = resp.user?.username ?? username,
                tides    = 0f,
                gambits  = 0f
            };
            CurrentUser = user;
            onSuccess?.Invoke(CurrentUser);
        }

        // ── Refresh balances (Tides + Gambits) ────────────────────────────────

        public IEnumerator RefreshBalancesAsync(string token, OceanPayUser user,
            Action<OceanPayUser> onSuccess, Action<string> onError)
        {
            if (string.IsNullOrEmpty(token)) { onError?.Invoke("Sin sesión"); yield break; }

            float tides   = 0f;
            float gambits = 0f;
            bool  tidesOk = false, gambitsOk = false;
            string tidesErr = null, gambitsErr = null;

            var meCall = OwsApiFailover.Get("/ocean-pay/me", token);
            yield return meCall;

            if (meCall.Success)
            {
                string text = meCall.text;
                var me = JsonUtility.FromJson<OceanPayUser.MeResponse>(text);
                tides   = me != null && me.tides > 0 ? me.tides : ExtractBalanceFromJson(text, "tides");
                gambits = me != null && me.gambits > 0 ? me.gambits : ExtractBalanceFromJson(text, "gambits");
                tidesOk = gambitsOk = true;
            }
            else
            {
                // Fallback: endpoint individual de gambits
                var gCall = OwsApiFailover.Get("/ocean-pay/gambits/balance", token);
                yield return gCall;
                if (gCall.Success)
                {
                    try
                    {
                        var br = JsonUtility.FromJson<OceanPayUser.BalanceResponse>(gCall.text);
                        gambits   = br?.gambits ?? 0f;
                        gambitsOk = true;
                    }
                    catch (Exception e)
                    {
                        Debug.LogWarning("[OceanPayService] Error parseando balance: " + e.Message);
                    }
                }
                else
                {
                    gambitsErr = "No se pudo cargar Gambits";
                }
                tidesErr = "No se pudo cargar Tides";
            }

            if (user != null)
            {
                if (tidesOk)   user.tides   = tides;
                if (gambitsOk) user.gambits  = gambits;
            }
            if (CurrentUser != null)
            {
                if (tidesOk)   CurrentUser.tides   = tides;
                if (gambitsOk) CurrentUser.gambits  = gambits;
            }

            if (tidesOk || gambitsOk)
            {
                LastBalanceSyncAt = Time.realtimeSinceStartup;
                onSuccess?.Invoke(CurrentUser ?? user);
            }
            else
            {
                onError?.Invoke(tidesErr ?? gambitsErr ?? "Error cargando saldos");
            }
        }

        // ── Earn Gambits ────────────────────────────────────────────────────

        public IEnumerator EarnGambitsAsync(float amount, string reason,
            Action<float> onSuccess, Action<string> onError)
        {
            var token = SavedToken;
            if (string.IsNullOrEmpty(token)) { onError?.Invoke("Sin sesión"); yield break; }

            string json = $"{{\"amount\":{amount},\"reason\":\"{EscapeJson(reason)}\"}}";
            var call = OwsApiFailover.Post("/ocean-pay/gambits/earn", json, token);
            yield return call;

            if (!call.Success)
            {
                onError?.Invoke(DescribeFailure(call));
                yield break;
            }

            var resp = JsonUtility.FromJson<OceanPayUser.EarnResponse>(call.text);
            if (resp == null || !resp.success)
            {
                onError?.Invoke(resp?.error ?? "Error al otorgar Gambits");
                yield break;
            }

            if (CurrentUser != null) CurrentUser.gambits = resp.gambits;
            onSuccess?.Invoke(resp.gambits);
        }

        // ── Season Pass (Gambito Real) ─────────────────────────────────────

        /// <summary>
        /// Estado del pase en el servidor: propiedad, precio vigente en Tides y
        /// saldo real de la cuenta. El precio lo manda el servidor.
        /// </summary>
        public IEnumerator GetSeasonPassStatusAsync(
            Action<OceanPayUser.SeasonPassStatusResponse> onSuccess, Action<string> onError)
        {
            var token = SavedToken;
            if (string.IsNullOrEmpty(token)) { onError?.Invoke("Sin sesión"); yield break; }

            var call = OwsApiFailover.Get("/ocean-pay/wilder-gambit/season-pass", token);
            yield return call;

            var resp = ParseJsonOrNull<OceanPayUser.SeasonPassStatusResponse>(call.text);
            if (call.Success)
            {
                if (resp == null || !resp.success) { onError?.Invoke(resp?.error ?? "Error desconocido"); yield break; }
                if (CurrentUser != null) CurrentUser.tides = resp.tides;
                onSuccess?.Invoke(resp);
                yield break;
            }

            onError?.Invoke(resp?.error ?? ("Error de conexión: " + call.ErrorText));
        }

        /// <summary>
        /// Compra el Gambito Real: el servidor descuenta los Tides de la cuenta
        /// Surface y devuelve el nuevo saldo. Sin sesión no hay compra.
        /// </summary>
        public IEnumerator BuySeasonPassAsync(
            Action<OceanPayUser.SeasonPassPurchaseResponse> onSuccess, Action<string> onError)
        {
            var token = SavedToken;
            if (string.IsNullOrEmpty(token)) { onError?.Invoke("Inicia sesión con Surface para comprar."); yield break; }

            var call = OwsApiFailover.Post("/ocean-pay/wilder-gambit/season-pass/purchase", "{}", token);
            yield return call;

            var resp = ParseJsonOrNull<OceanPayUser.SeasonPassPurchaseResponse>(call.text);
            if (call.Success)
            {
                if (resp == null || !resp.success) { onError?.Invoke(resp?.error ?? "Error desconocido"); yield break; }
                if (CurrentUser != null) CurrentUser.tides = resp.tides;
                onSuccess?.Invoke(resp);
                yield break;
            }

            // 400 (saldo insuficiente) llega con cuerpo legible: se aprovecha
            // para devolver el saldo real y el importe requerido.
            if (resp != null && (resp.success || resp.required > 0))
            {
                if (CurrentUser != null) CurrentUser.tides = resp.tides;
                onError?.Invoke(resp.error ?? "No se pudo completar el pago");
                yield break;
            }

            onError?.Invoke(resp?.error ?? ("Error de conexión: " + call.ErrorText));
        }

        private static T ParseJsonOrNull<T>(string json) where T : class
        {
            if (string.IsNullOrEmpty(json)) return null;
            try { return JsonUtility.FromJson<T>(json); }
            catch (Exception e)
            {
                Debug.LogWarning("[OceanPayService] Respuesta ilegible: " + e.Message);
                return null;
            }
        }

        // ── Auto-login with saved token ───────────────────────────────────────

        public IEnumerator TryAutoLoginAsync(Action<OceanPayUser> onSuccess, Action onFail)
        {
            var token = SavedToken;
            if (string.IsNullOrEmpty(token)) { onFail?.Invoke(); yield break; }

            var call = OwsApiFailover.Get("/ocean-pay/me", token);
            yield return call;

            if (!call.Success)
            {
                // Token rechazado por el servidor (401) o cuenta inexistente (404):
                // la sesión ya no sirve. Un problema de red/portal caído NO borra
                // la sesión: el token sigue siendo válido y se reintentará luego.
                bool sessionRejected = call.ProtocolError &&
                                       (call.responseCode == 401 || call.responseCode == 404);
                if (sessionRejected) ClearSession();
                onFail?.Invoke();
                yield break;
            }

            try
            {
                string text = call.text;
                var me = JsonUtility.FromJson<OceanPayUser.MeResponse>(text);
                if (me == null || me.id == 0)
                {
                    ClearSession();
                    onFail?.Invoke();
                    yield break;
                }

                float tidesVal = me.tides > 0 ? me.tides : ExtractBalanceFromJson(text, "tides");
                float gambitsVal = me.gambits > 0 ? me.gambits : ExtractBalanceFromJson(text, "gambits");

                CurrentUser = new OceanPayUser
                {
                    id       = me.id,
                    username = me.username ?? SavedUsername,
                    tides    = tidesVal,
                    gambits  = gambitsVal
                };
                SaveSession(token, me.id, me.username ?? SavedUsername);
                LastBalanceSyncAt = Time.realtimeSinceStartup;
                onSuccess?.Invoke(CurrentUser);
            }
            catch
            {
                ClearSession();
                onFail?.Invoke();
            }
        }

        // ── Utilities ─────────────────────────────────────────────────────────

        private static float ExtractBalanceFromJson(string json, string currencyKey)
        {
            if (string.IsNullOrEmpty(json)) return 0f;
            var match = System.Text.RegularExpressions.Regex.Match(
                json,
                $"\"{currencyKey}\"\\s*:\\s*([0-9]+(?:\\.[0-9]+)?)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
            );
            if (match.Success && float.TryParse(match.Groups[1].Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out float val))
            {
                return val;
            }
            return 0f;
        }

        private static string EscapeJson(string s) =>
            (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
}
