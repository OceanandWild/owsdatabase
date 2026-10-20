using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Cliente WebSocket del PVP online (server.js -> wss://owsdatabase.onrender.com/wildweapon/pvp,
    /// con espejo wss://owsdatabase2.onrender.com/wildweapon/pvp si el principal no responde).
    /// Singleton persistente entre escenas: el menu lo usa para la cola de emparejamiento
    /// y la Arena para el duelo. Los mensajes entrantes se parsean en el hilo principal.
    ///
    /// Render apaga la instancia gratuita cuando pasa un rato sin trafico. El primer
    /// request de la manana despierta el servicio y puede tardar 30-90 s: por eso la
    /// conexion ya no se rinde a los pocos segundos. Primero golpea el endpoint HTTP
    /// /wildweapon/pvp/info (que fuerza el arranque) y despues abre el WebSocket,
    /// informando la fase por <see cref="Phase"/> para que la UI muestre el "Cargando...".
    /// </summary>
    public class PvpClient : MonoBehaviour
    {
        public static PvpClient Instance { get; private set; }

        /// <summary>Servidor de produccion (Render).</summary>
        public const string ProductionUrl = "wss://owsdatabase.onrender.com/wildweapon/pvp";
        /// <summary>Servidor espejo: se usa automaticamente si el principal no se puede conectar.</summary>
        public const string FallbackUrl = "wss://owsdatabase2.onrender.com/wildweapon/pvp";

        /// <summary>
        /// Cuanto se insiste antes de declarar el servidor caido. Un cold start de Render
        /// puede tardar 30-90 s; 120 s deja margen para despertar y abrir el socket.
        /// </summary>
        public const float ConnectWindowSeconds = 120f;
        /// <summary>Tope de cada handshake WebSocket antes de probar el siguiente servidor.</summary>
        private const float SocketAttemptSeconds = 18f;
        /// <summary>Tope de cada sondeo HTTP de despertar.</summary>
        private const int WarmupTimeoutSeconds = 15;
        /// <summary>Pausa entre rondas de reintento.</summary>
        private const float RetryDelaySeconds = 2.5f;

        /// <summary>Fase visible de la conexion (la UI la usa para el cartel de carga).</summary>
        public enum ConnectionPhase { Offline, WarmingUp, Connecting, Retrying, Online }

#if UNITY_EDITOR
        /// <summary>
        /// Override solo para el editor: primer intento de conexion contra un stub local.
        /// Si no responde, la sesion sigue con produccion y el espejo. En builds se ignora.
        /// </summary>
        private const string DevOverridePrefKey = "ww_pvp_url_dev";
        /// <summary>Clave vieja que dejaba la conexion clavada en localhost; se borra al arrancar.</summary>
        private const string LegacyOverridePrefKey = "ww_pvp_url";

        [RuntimeInitializeOnLoadMethod(RuntimeInitializeLoadType.BeforeSceneLoad)]
        private static void DropLegacyOverride()
        {
            if (!PlayerPrefs.HasKey(LegacyOverridePrefKey)) return;
            PlayerPrefs.DeleteKey(LegacyOverridePrefKey);
            PlayerPrefs.Save();
            Debug.Log("[WW-PVP] se elimino el override legado 'ww_pvp_url'. " +
                      "Para pruebas locales usar 'ww_pvp_url_dev'.");
        }
#endif

        /// <summary>URL primaria del PVP (informativa). La conexion prueba produccion y espejo.</summary>
        public static string Url
        {
            get
            {
#if UNITY_EDITOR
                string dev = PlayerPrefs.GetString(DevOverridePrefKey, "");
                if (!string.IsNullOrEmpty(dev)) return dev;
#endif
                return ProductionUrl;
            }
        }

        /// <summary>Ultima URL que logro conectar (en memoria): se intenta primero en la proxima conexion.</summary>
        private static string _lastGoodUrl;

        public bool IsConnected => _connected;
        public string LastError { get; private set; } = "";

        /// <summary>Fase actual del intento de conexion (se lee desde el hilo principal).</summary>
        public ConnectionPhase Phase { get; private set; } = ConnectionPhase.Offline;
        /// <summary>Texto corto de lo que esta pasando, listo para mostrar.</summary>
        public string PhaseDetail { get; private set; } = "";
        /// <summary>Cuantos sondeos/handshakes se intentaron en la ventana actual.</summary>
        public int Attempts { get; private set; }
        /// <summary>Hay una ventana de conexion activa (despertando o reintentando).</summary>
        public bool IsConnecting => _connectRoutine != null;
        /// <summary>
        /// Conexion ya estable y confirmada: recien despues de un instante de socket sano.
        /// La UI espera esta senal para no mandar acciones sobre una conexion que se cae.
        /// </summary>
        public bool IsOnline => _connected && Phase == ConnectionPhase.Online;
        /// <summary>La ventana termino sin exito: la UI puede ofrecer reintentar.</summary>
        public bool HasFailed => !IsConnected && !IsConnecting && !string.IsNullOrEmpty(LastError);
        /// <summary>Segundos desde que arranco la ventana de conexion.</summary>
        public float ConnectSeconds => IsConnecting ? Time.realtimeSinceStartup - _connectStart : 0f;
        /// <summary>Segundos desde el ultimo cambio de fase.</summary>
        public float PhaseSeconds => Time.realtimeSinceStartup - _phaseStart;

        /// <summary>Mensajes del server; se invoca en el hilo principal (Update).</summary>
        public event Action<PvpMsg> Message;

        private volatile bool _connected;
        private volatile ClientWebSocket _socket;
        private volatile string _sessionError;
        private volatile bool _receivedAny;
        private CancellationTokenSource _cts;
        private Task _worker;

        private Coroutine _connectRoutine;
        private float _connectStart;
        private float _phaseStart;
        private int _sessionGen;
        private string _attemptError = "";
        private bool _warmupAwake;

        private readonly ConcurrentQueue<string> _inbox = new ConcurrentQueue<string>();
        private readonly ConcurrentQueue<string> _outbox = new ConcurrentQueue<string>();

        /// <summary>Crea (si hace falta) el singleton persistente.</summary>
        public static PvpClient Ensure()
        {
            if (Instance == null)
            {
                var go = new GameObject("[PvpClient]");
                DontDestroyOnLoad(go);
                Instance = go.AddComponent<PvpClient>();
            }
            return Instance;
        }

        void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }

        void OnDestroy()
        {
            if (Instance == this) Instance = null;
            Disconnect();
        }

        void Update()
        {
            while (_inbox.TryDequeue(out var json))
            {
                PvpMsg msg = null;
                try { msg = JsonUtility.FromJson<PvpMsg>(json); }
                catch (Exception e) { Debug.LogWarning("[WW-PVP] mensaje invalido: " + e.Message); }
                if (msg == null || string.IsNullOrEmpty(msg.t)) continue;

                try { Message?.Invoke(msg); }
                catch (Exception e) { Debug.LogException(e); }
            }
        }

        // =================================================================
        // API publica
        // =================================================================

        /// <summary>
        /// Arranca una ventana de conexion con reintentos. Si ya hay una en curso no
        /// hace nada; si el servidor esta dormido, la ventana lo despierta y sigue
        /// informando el progreso por <see cref="Phase"/> / <see cref="PhaseDetail"/>.
        /// </summary>
        public void Connect()
        {
            if (_connected || _connectRoutine != null) return;

            LastError = "";
            Attempts = 0;
            _attemptError = "";
            _connectStart = Time.realtimeSinceStartup;
            _cts = new CancellationTokenSource();
            _connectRoutine = StartCoroutine(ConnectRoutine(++_sessionGen, _cts.Token));
        }

        /// <summary>
        /// Servidores a probar, en orden: override de editor (pruebas), la ultima URL que anduvo,
        /// el servidor de produccion y el espejo. El override nunca reemplaza a produccion:
        /// si el stub local esta apagado, se sigue con los servidores reales.
        /// </summary>
        private static string[] BuildCandidateUrls(string preferred = null)
        {
            var urls = new List<string>(5);

#if UNITY_EDITOR
            string dev = PlayerPrefs.GetString(DevOverridePrefKey, "");
            if (!string.IsNullOrEmpty(dev)) urls.Add(dev);
#endif

            if (!string.IsNullOrEmpty(preferred) && !urls.Contains(preferred)) urls.Add(preferred);
            if (!string.IsNullOrEmpty(_lastGoodUrl) && !urls.Contains(_lastGoodUrl)) urls.Add(_lastGoodUrl);
            if (!urls.Contains(ProductionUrl)) urls.Add(ProductionUrl);
            if (!urls.Contains(FallbackUrl)) urls.Add(FallbackUrl);
            return urls.ToArray();
        }

        public void Disconnect()
        {
            _sessionGen++;                 // invalida la sesion en curso
            if (_connectRoutine != null)
            {
                if (isActiveAndEnabled) StopCoroutine(_connectRoutine);
                _connectRoutine = null;
            }
            try { _cts?.Cancel(); } catch (Exception) { }
            AbortSocket();
            _cts = null;
            _worker = null;
            _connected = false;
            _socket = null;
            _attemptError = "";
            Attempts = 0;
            SetPhase(ConnectionPhase.Offline, "Desconectado.");
            while (_inbox.TryDequeue(out _)) { }
            while (_outbox.TryDequeue(out _)) { }
        }

        /// <summary>Vuelve al menu: avisa al server y cierra el socket con una pequena demora para que salga el 'leave'.</summary>
        public void LeaveAndDisconnect()
        {
            if (_connected) Send(new PvpMsg { t = PvpMsgType.Leave });
            if (isActiveAndEnabled) StartCoroutine(DisconnectSoonRoutine(0.3f));
            else Disconnect();
        }

        private IEnumerator DisconnectSoonRoutine(float delay)
        {
            yield return new WaitForSecondsRealtime(delay);
            Disconnect();
        }

        public void Send(PvpMsg msg)
        {
            try { Send(JsonUtility.ToJson(msg)); }
            catch (Exception e) { Debug.LogWarning("[WW-PVP] no se pudo serializar: " + e.Message); }
        }

        public void Send(string json)
        {
            if (string.IsNullOrEmpty(json) || !_connected) return;
            _outbox.Enqueue(json);
        }

        // =================================================================
        // Ventana de conexion (despertar + reintentos)
        // =================================================================

        private IEnumerator ConnectRoutine(int gen, CancellationToken ct)
        {
            try
            {
                SetPhase(ConnectionPhase.WarmingUp, "Despertando el servidor de duelos...");

                // ---- 1. Despertar Render por HTTP (el WS solo no siempre lo logra) ----
                float deadline = _connectStart + ConnectWindowSeconds;
                string warmTarget = PreferredCandidate();
                string awakeUrl = null;
                bool awake = !NeedsWarmup(warmTarget);

                while (!awake && !ct.IsCancellationRequested && Time.realtimeSinceStartup < deadline)
                {
                    Attempts++;
                    yield return WarmUp(warmTarget, ct);
                    awake = _warmupAwake;
                    if (awake) { awakeUrl = warmTarget; break; }

                    SetPhase(ConnectionPhase.Retrying, "El servidor esta arrancando...");
                    yield return WaitUnscaled(RetryDelaySeconds, ct);
                    warmTarget = AlternateCandidate(warmTarget);
                }

                // ---- 2. WebSocket, con reintentos hasta la ventana total ----
                while (!ct.IsCancellationRequested && !_connected && Time.realtimeSinceStartup < deadline)
                {
                    SetPhase(ConnectionPhase.Connecting, "Abriendo el canal de duelos...");
                    string[] urls = BuildCandidateUrls(awakeUrl);   // PlayerPrefs solo se lee en el hilo principal
                    _attemptError = "";
                    Attempts++;

                    Task session = Task.Run(() => RunSession(gen, urls, ct));
                    _worker = session;

                    while (!session.IsCompleted && !_connected && !ct.IsCancellationRequested &&
                           Time.realtimeSinceStartup < deadline)
                        yield return null;

                    // Un socket que se cae apenas abre (p. ej. instancia a medio arrancar)
                    // no cuenta como conexion: se exige que se mantenga un instante.
                    if (_connected)
                    {
                        float held = 0f;
                        while (held < 1.2f && _connected && !session.IsCompleted &&
                               !ct.IsCancellationRequested && Time.realtimeSinceStartup < deadline)
                        {
                            held += Time.unscaledDeltaTime;
                            yield return null;
                        }
                        if (_connected && !session.IsCompleted) break;
                    }

                    if (!session.IsCompleted)
                    {
                        // Se agoto la ventana con un handshake colgado: cortarlo y salir.
                        AbortSocket();
                        float grace = 0f;
                        while (!session.IsCompleted && grace < 2f)
                        {
                            grace += Time.unscaledDeltaTime;
                            yield return null;
                        }
                        break;
                    }

                    if (ct.IsCancellationRequested) break;

                    SetPhase(ConnectionPhase.Retrying, "El servidor no responde. Reintentando...");
                    yield return WaitUnscaled(RetryDelaySeconds, ct);
                }

                if (_connected)
                {
                    SetPhase(ConnectionPhase.Online, "Conectado al servidor de duelos.");
                }
                else if (!ct.IsCancellationRequested)
                {
                    LastError = string.IsNullOrEmpty(_attemptError)
                        ? "No se pudo conectar con el servidor PVP."
                        : _attemptError;
                    SetPhase(ConnectionPhase.Offline, "Sin conexion.");
                }
            }
            finally
            {
                if (gen == _sessionGen) _connectRoutine = null;
            }
        }

        private void SetPhase(ConnectionPhase phase, string detail)
        {
            Phase = phase;
            PhaseDetail = detail ?? "";
            _phaseStart = Time.realtimeSinceStartup;
        }

        /// <summary>
        /// Sondeo HTTP de despertar. Render responde 502/503 mientras la instancia
        /// arranca; cualquier respuesta 2xx-4xx ya significa que Express esta arriba.
        /// </summary>
        private IEnumerator WarmUp(string wsUrl, CancellationToken ct)
        {
            _warmupAwake = false;
            string url = InfoUrlFor(wsUrl);
            if (string.IsNullOrEmpty(url))
            {
                _warmupAwake = true;   // sin endpoint HTTP: se intenta el socket directo
                yield break;
            }

            using (UnityWebRequest req = UnityWebRequest.Get(url))
            {
                req.timeout = WarmupTimeoutSeconds;
                req.SetRequestHeader("Cache-Control", "no-cache");
                UnityWebRequestAsyncOperation op = req.SendWebRequest();

                while (!op.isDone && !ct.IsCancellationRequested) yield return null;
                if (!op.isDone) { req.Abort(); yield break; }

                long code = req.responseCode;
                _warmupAwake = req.result == UnityWebRequest.Result.Success ||
                               (code >= 200 && code < 500);

                if (_warmupAwake)
                    SetPhase(ConnectionPhase.Connecting, "Servidor despierto. Abriendo el canal de duelos...");
                else if (code == 502 || code == 503 || code == 504)
                    SetPhase(ConnectionPhase.Retrying, "Render esta despertando la instancia...");
                else
                    SetPhase(ConnectionPhase.Retrying, "Esperando al servidor...");
            }
        }

        private static string PreferredCandidate()
        {
#if UNITY_EDITOR
            string dev = PlayerPrefs.GetString(DevOverridePrefKey, "");
            if (!string.IsNullOrEmpty(dev)) return dev;
#endif
            return string.IsNullOrEmpty(_lastGoodUrl) ? ProductionUrl : _lastGoodUrl;
        }

        private static string AlternateCandidate(string current)
        {
            if (!string.IsNullOrEmpty(current) &&
                current.IndexOf("owsdatabase2", StringComparison.OrdinalIgnoreCase) >= 0)
                return ProductionUrl;
            return FallbackUrl;
        }

        /// <summary>Solo los hosts de Render se despiertan por HTTP; el stub local va directo al WS.</summary>
        private static bool NeedsWarmup(string url)
        {
            return !string.IsNullOrEmpty(url) &&
                   url.IndexOf("onrender.com", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>wss://host/wildweapon/pvp -> https://host/wildweapon/pvp/info</summary>
        private static string InfoUrlFor(string wsUrl)
        {
            if (!Uri.TryCreate(wsUrl, UriKind.Absolute, out Uri uri)) return null;
            if (uri.Scheme != "ws" && uri.Scheme != "wss") return null;

            var builder = new UriBuilder(uri)
            {
                Scheme = uri.Scheme == "wss" ? "https" : "http",
                Path = uri.AbsolutePath.TrimEnd('/') + "/info",
                Query = "",
            };
            return builder.Uri.ToString();
        }

        private IEnumerator WaitUnscaled(float seconds, CancellationToken ct)
        {
            float t = 0f;
            while (t < seconds && !ct.IsCancellationRequested)
            {
                t += Time.unscaledDeltaTime;
                yield return null;
            }
        }

        private void AbortSocket()
        {
            var socket = _socket;
            if (socket == null) return;
            try { socket.Abort(); } catch (Exception) { }
        }

        // =================================================================
        // Hilos: sesion, envio y recepcion
        // =================================================================

        private async Task RunSession(int gen, string[] urls, CancellationToken ct)
        {
            string lastError = null;

            for (int i = 0; i < urls.Length && !ct.IsCancellationRequested; i++)
            {
                string url = urls[i];
                bool hadData = false;
                string sessionError = null;

                using (var socket = new ClientWebSocket())
                {
                    _sessionError = null;
                    _receivedAny = false;
                    try
                    {
                        using (var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                        {
                            attemptCts.CancelAfter(TimeSpan.FromSeconds(SocketAttemptSeconds));
                            await socket.ConnectAsync(new Uri(url), attemptCts.Token).ConfigureAwait(false);
                        }

                        if (ct.IsCancellationRequested || gen != _sessionGen) return;

                        _socket = socket;
                        _connected = true;
                        _lastGoodUrl = url;
                        Debug.Log("[WW-PVP] conectado a " + url);

                        var receive = ReceiveLoop(socket, ct);
                        var send = SendLoop(socket, ct);
                        await Task.WhenAny(receive, send).ConfigureAwait(false);

                        hadData = _receivedAny;
                        sessionError = _sessionError;
                        if (!hadData && !ct.IsCancellationRequested)
                        {
                            lastError = sessionError ?? "La conexion se cerro sin respuesta.";
                            Debug.LogWarning("[WW-PVP] " + url + " acepto la conexion pero no respondio; probando el siguiente servidor...");
                        }
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                    {
                        lastError = "El servidor tardo demasiado en responder.";
                        Debug.LogWarning("[WW-PVP] tiempo de espera agotado (" + url + "); se reintenta.");
                    }
                    catch (OperationCanceledException) { /* cierre normal */ }
                    catch (Exception e)
                    {
                        lastError = e.Message;
                        Debug.LogWarning("[WW-PVP] conexion fallida (" + url + "): " + e.Message);
                    }
                    finally
                    {
                        if (gen == _sessionGen)
                        {
                            _connected = false;
                            _socket = null;
                            _sessionError = null;
                        }
                    }
                }

                // Sesion que llego a intercambiar mensajes: termino de forma normal
                // (leave, fin de partida, etc.). Se conserva el motivo si lo hubo.
                if (hadData || ct.IsCancellationRequested)
                {
                    if (!ct.IsCancellationRequested && !string.IsNullOrEmpty(sessionError) && gen == _sessionGen)
                        LastError = sessionError;
                    return;
                }
                // Servidor caido sin responder: se prueba el proximo candidato.
            }

            if (!ct.IsCancellationRequested && gen == _sessionGen)
                _attemptError = lastError ?? _attemptError;
        }

        private async Task SendLoop(ClientWebSocket socket, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                while (_outbox.TryDequeue(out var json))
                {
                    var bytes = Encoding.UTF8.GetBytes(json);
                    try
                    {
                        await socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
                    }
                    catch (Exception) { return; }
                }
                try { await Task.Delay(5, ct).ConfigureAwait(false); }
                catch (Exception) { return; }
            }
        }

        private async Task ReceiveLoop(ClientWebSocket socket, CancellationToken ct)
        {
            var buffer = new byte[8192];
            var sb = new StringBuilder();
            while (!ct.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result;
                try
                {
                    do
                    {
                        result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), ct).ConfigureAwait(false);
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            _sessionError = "El servidor cerro la conexion.";
                            return;
                        }
                        sb.Append(Encoding.UTF8.GetString(buffer, 0, result.Count));
                    }
                    while (!result.EndOfMessage);
                }
                catch (OperationCanceledException) { return; }
                catch (Exception e)
                {
                    _sessionError = e.Message;
                    return;
                }

                _inbox.Enqueue(sb.ToString());
                _receivedAny = true;
                sb.Clear();
            }
        }
    }
}
