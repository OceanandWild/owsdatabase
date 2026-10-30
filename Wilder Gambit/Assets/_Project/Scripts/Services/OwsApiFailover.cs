using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace WilderGambit.Services
{
    /// <summary>
    /// Failover de API entre el servidor principal y su espejo (réplica en C#
    /// de web/OWS/ows-api-failover.js del monorepo):
    ///
    ///     Principal : https://owsdatabase.onrender.com
    ///     Espejo    : https://owsdatabase2.onrender.com
    ///
    /// Si el principal no responde (error de red, timeout o HTTP 502/503/504,
    /// típico de Render suspendido), la petición se reintenta sola contra el
    /// espejo. La última base que respondió se recuerda y se usa primero, y
    /// una sonda de salud cada 45 s devuelve el tráfico al principal en cuanto
    /// se recupera.
    /// </summary>
    public static class OwsApiFailover
    {
        public const string Primary = "https://owsdatabase.onrender.com";

        public static readonly string[] Mirrors =
        {
            "https://owsdatabase2.onrender.com"
        };

        public static readonly string[] KnownBases = BuildKnownBases();

        /// <summary>Ruta de salud compartida por el monorepo para el sondeo.</summary>
        public const string HealthPath = "/ecoconsole/health";
        public const float ProbeEverySeconds = 45f;
        public const int ProbeTimeoutSeconds = 8;

        private const string LastGoodKey = "OwsApiLastGoodBase";

        // Orden de intento en memoria: la base sana primero, luego el resto.
        private static readonly List<string> order = BuildInitialOrder();

        /// <summary>Base que se intenta primero en cada petición.</summary>
        public static string ClientBase => order[0];

        /// <summary>¿La URL apunta al principal o a algún espejo conocido?</summary>
        public static bool IsKnownBase(string url) => BaseOf(url) != null;

        /// <summary>Reescribe una URL conocida para que apunte a la base sana actual.</summary>
        public static string PreferredUrl(string url)
        {
            string found = BaseOf(url);
            if (found == null) return url;
            return ClientBase + url.Substring(found.Length);
        }

        /// <summary>GET con failover. Se usa como corrutina (ver <see cref="OwsApiCall"/>).</summary>
        public static OwsApiCall Get(string path, string token = null, int timeoutSeconds = 25)
            => new OwsApiCall("GET", path, null, token, timeoutSeconds);

        /// <summary>POST JSON con failover. Se usa como corrutina (ver <see cref="OwsApiCall"/>).</summary>
        public static OwsApiCall Post(string path, string jsonBody = "{}", string token = null, int timeoutSeconds = 25)
            => new OwsApiCall("POST", path, jsonBody, token, timeoutSeconds);

        // ── Interno ──────────────────────────────────────────────────────────

        private static string[] BuildKnownBases()
        {
            var all = new List<string> { Primary };
            all.AddRange(Mirrors);
            return all.ToArray();
        }

        private static List<string> BuildInitialOrder()
        {
            var list = new List<string>(KnownBases);
            string lastGood = PlayerPrefs.GetString(LastGoodKey, "");
            if (!string.IsNullOrEmpty(lastGood) && list.Remove(lastGood))
                list.Insert(0, lastGood);
            return list;
        }

        private static string BaseOf(string url)
        {
            if (string.IsNullOrEmpty(url)) return null;
            foreach (string baseUrl in KnownBases)
            {
                if (url == baseUrl || url.StartsWith(baseUrl + "/", StringComparison.Ordinal))
                    return baseUrl;
            }
            return null;
        }

        internal static string[] AttemptOrder() => order.ToArray();

        /// <summary>Marca una base como sana: pasa al frente y se recuerda.</summary>
        internal static void MarkGood(string baseUrl) => SetActive(baseUrl, true);

        internal static void SetActive(string baseUrl, bool persist)
        {
            if (string.IsNullOrEmpty(baseUrl) || !order.Contains(baseUrl)) return;

            string previous = order[0];
            order.Remove(baseUrl);
            order.Insert(0, baseUrl);

            if (persist)
            {
                // Solo se toca el disco si de verdad cambió lo recordado:
                // MarkGood se llama en cada petición exitosa.
                string saved = PlayerPrefs.GetString(LastGoodKey, "");
                if (previous != baseUrl || saved != baseUrl)
                {
                    PlayerPrefs.SetString(LastGoodKey, baseUrl);
                    PlayerPrefs.Save();
                }
            }

            if (previous != baseUrl)
            {
                Debug.Log("[OWS/API] Base activa: " + baseUrl +
                    (baseUrl == Primary ? " (principal)" : " (espejo de respaldo)"));
            }
        }

        internal static UnityWebRequest CreateRequest(string method, string url,
            string jsonBody, string token, int timeoutSeconds)
        {
            var req = new UnityWebRequest(url, method);
            if (method == UnityWebRequest.kHttpVerbPOST)
                req.uploadHandler = new UploadHandlerRaw(Encoding.UTF8.GetBytes(jsonBody ?? "{}"));
            req.downloadHandler = new DownloadHandlerBuffer();
            if (method == UnityWebRequest.kHttpVerbPOST)
                req.SetRequestHeader("Content-Type", "application/json");
            if (!string.IsNullOrEmpty(token))
                req.SetRequestHeader("Authorization", "Bearer " + token);
            req.timeout = timeoutSeconds;
            return req;
        }

        /// <summary>
        /// Con el dominio recargado apagado los estáticos viven entre sesiones de
        /// Play: se rearma el orden guardado para no arrastrar estado viejo.
        /// </summary>
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.SubsystemRegistration)]
        private static void ResetStatics()
        {
            order.Clear();
            order.AddRange(BuildInitialOrder());
        }
    }

    /// <summary>
    /// Petición HTTP con failover incluido. Se consume como una corrutina:
    ///
    ///     var call = OwsApiFailover.Get("/ocean-pay/me", token);
    ///     yield return call;
    ///     if (call.Success) { ... usará call.text ... }
    ///
    /// Al terminar expone la respuesta de la base que contestó (o, si ninguna
    /// lo hizo, el último error) en <see cref="result"/>, <see cref="text"/>,
    /// <see cref="responseCode"/>, <see cref="error"/> y <see cref="baseUrl"/>.
    /// </summary>
    public sealed class OwsApiCall : IEnumerator
    {
        private readonly string method;
        private readonly string path;
        private readonly string jsonBody;
        private readonly string token;
        private readonly int timeoutSeconds;

        private IEnumerator routine;

        public UnityWebRequest.Result result { get; private set; } = UnityWebRequest.Result.ConnectionError;
        public long responseCode { get; private set; }
        public string text { get; private set; } = "";
        public string error { get; private set; } = "";
        public string baseUrl { get; private set; } = "";

        public bool Success => result == UnityWebRequest.Result.Success;

        /// <summary>El servidor respondió con un error HTTP (4xx/5xx).</summary>
        public bool ProtocolError => result == UnityWebRequest.Result.ProtocolError;

        /// <summary>
        /// Mensaje que mandó el servidor ({ "error": "..." }) cuando la respuesta
        /// HTTP falló; null si no hay cuerpo legible.
        /// </summary>
        public string ServerMessage
        {
            get
            {
                if (string.IsNullOrEmpty(text)) return null;
                try
                {
                    var payload = JsonUtility.FromJson<OwsErrorPayload>(text);
                    return payload != null && !string.IsNullOrEmpty(payload.error) ? payload.error : null;
                }
                catch
                {
                    return null;
                }
            }
        }

        [Serializable]
        private sealed class OwsErrorPayload
        {
            public string error;
        }

        /// <summary>Mensaje legible para la UI cuando la llamada falla.</summary>
        public string ErrorText => string.IsNullOrEmpty(error) ? ("HTTP " + responseCode) : error;

        internal OwsApiCall(string method, string path, string jsonBody, string token, int timeoutSeconds)
        {
            this.method = method;
            this.path = path;
            this.jsonBody = jsonBody;
            this.token = token;
            this.timeoutSeconds = timeoutSeconds;
        }

        object IEnumerator.Current => routine?.Current;

        bool IEnumerator.MoveNext()
        {
            if (routine == null) routine = Run();
            return routine.MoveNext();
        }

        void IEnumerator.Reset() => throw new NotSupportedException();

        private IEnumerator Run()
        {
            string[] bases = OwsApiFailover.AttemptOrder();

            // Último intento (pase lo que pase) y última respuesta HTTP real:
            // si alguna base contestó, esa respuesta manda al final (misma
            // semántica que fetch + failover en web).
            UnityWebRequest.Result attemptResult = UnityWebRequest.Result.ConnectionError;
            long attemptCode = 0;
            string attemptText = "", attemptError = "", attemptBase = "";

            bool hasResponse = false;
            UnityWebRequest.Result responseResult = UnityWebRequest.Result.ConnectionError;
            long responseCodeValue = 0;
            string responseText = "", responseError = "", responseBase = "";

            for (int i = 0; i < bases.Length; i++)
            {
                string candidate = bases[i];

                using var req = OwsApiFailover.CreateRequest(
                    method, candidate + path, jsonBody, token, timeoutSeconds);
                yield return req.SendWebRequest();

                string body = req.downloadHandler != null ? req.downloadHandler.text : "";
                string err = string.IsNullOrEmpty(req.error)
                    ? (req.responseCode > 0 ? "HTTP " + req.responseCode : "")
                    : req.error;

                attemptResult = req.result;
                attemptCode = req.responseCode;
                attemptText = body;
                attemptError = err;
                attemptBase = candidate;

                if (req.result == UnityWebRequest.Result.ProtocolError)
                {
                    hasResponse = true;
                    responseResult = req.result;
                    responseCodeValue = req.responseCode;
                    responseText = body;
                    responseError = err;
                    responseBase = candidate;
                }

                if (req.result == UnityWebRequest.Result.Success)
                {
                    Apply(req.result, req.responseCode, body, err, candidate);
                    OwsApiFailover.MarkGood(candidate);
                    yield break;
                }

                if (!IsGatewayDown(req.result, req.responseCode))
                {
                    // La base contestó (p. ej. 400/401): es una respuesta
                    // legítima, no un problema de disponibilidad.
                    Apply(req.result, req.responseCode, body, err, candidate);
                    OwsApiFailover.MarkGood(candidate);
                    yield break;
                }

                if (i + 1 < bases.Length)
                {
                    Debug.LogWarning($"[OWS/API] {candidate} no respondió ({err}). Reintentando con {bases[i + 1]}...");
                }
            }

            if (hasResponse)
                Apply(responseResult, responseCodeValue, responseText, responseError, responseBase);
            else
                Apply(attemptResult, attemptCode, attemptText, attemptError, attemptBase);
        }

        private void Apply(UnityWebRequest.Result r, long code, string body, string err, string baseUsed)
        {
            result = r;
            responseCode = code;
            text = body ?? "";
            error = err ?? "";
            baseUrl = baseUsed;
        }

        private static bool IsGatewayDown(UnityWebRequest.Result r, long code)
        {
            if (r == UnityWebRequest.Result.ConnectionError) return true;
            if (r == UnityWebRequest.Result.DataProcessingError) return true;
            if (r == UnityWebRequest.Result.ProtocolError)
                return code == 502 || code == 503 || code == 504;
            return false;
        }
    }

    /// <summary>
    /// Sonda de salud del principal. Al arrancar comprueba (sin bloquear a
    /// nadie) si responde; si está caído, activa el espejo para que las
    /// primeras peticiones reales no esperen un timeout, y mientras el espejo
    /// esté activo reintenta cada 45 s para volver solo al principal.
    /// Se crea sola: no depende de ninguna escena.
    /// </summary>
    internal sealed class OwsApiFailoverProbe : MonoBehaviour
    {
        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.AfterSceneLoad)]
        private static void Bootstrap()
        {
            if (FindAnyObjectByType<OwsApiFailoverProbe>() != null) return;

            var go = new GameObject("OwsApiFailover");
            DontDestroyOnLoad(go);
            go.AddComponent<OwsApiFailoverProbe>();
        }

        private void Start() => StartCoroutine(Loop());

        private static IEnumerator Loop()
        {
            // Sonda inicial: si el principal está caído, la primera petición
            // real del juego sale directo por el espejo.
            yield return ProbePrimary();

            while (true)
            {
                yield return new WaitForSecondsRealtime(OwsApiFailover.ProbeEverySeconds);
                if (OwsApiFailover.ClientBase != OwsApiFailover.Primary)
                    yield return ProbePrimary();
            }
        }

        private static IEnumerator ProbePrimary()
        {
            using var req = UnityWebRequest.Get(OwsApiFailover.Primary + OwsApiFailover.HealthPath);
            req.timeout = OwsApiFailover.ProbeTimeoutSeconds;
            yield return req.SendWebRequest();

            if (req.result == UnityWebRequest.Result.Success)
            {
                OwsApiFailover.SetActive(OwsApiFailover.Primary, true);
                yield break;
            }

            // Principal caído: pasar al espejo. Sin persistir, porque la sonda
            // seguirá intentando volver al principal.
            if (OwsApiFailover.ClientBase == OwsApiFailover.Primary)
                OwsApiFailover.SetActive(OwsApiFailover.Mirrors[0], false);
        }
    }
}
