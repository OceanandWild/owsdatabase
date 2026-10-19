using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;

namespace WildWeapon.Pvp
{
    /// <summary>
    /// Cliente WebSocket del PVP online (server.js -> wss://owsdatabase.onrender.com/wildweapon/pvp,
    /// con espejo wss://owsdatabase2.onrender.com/wildweapon/pvp si el principal no responde).
    /// Singleton persistente entre escenas: el menu lo usa para la cola de emparejamiento
    /// y la Arena para el duelo. Los mensajes entrantes se parsean en el hilo principal.
    /// </summary>
    public class PvpClient : MonoBehaviour
    {
        public static PvpClient Instance { get; private set; }

        /// <summary>Servidor de produccion (Render).</summary>
        public const string ProductionUrl = "wss://owsdatabase.onrender.com/wildweapon/pvp";
        /// <summary>Servidor espejo: se usa automaticamente si el principal no se puede conectar.</summary>
        public const string FallbackUrl = "wss://owsdatabase2.onrender.com/wildweapon/pvp";

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

        /// <summary>Mensajes del server; se invoca en el hilo principal (Update).</summary>
        public event Action<PvpMsg> Message;

        private volatile bool _connected;
        private volatile ClientWebSocket _socket;
        private volatile string _sessionError;
        private volatile bool _receivedAny;
        private CancellationTokenSource _cts;
        private Task _worker;

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

        public void Connect()
        {
            if (_connected || _worker != null) return;
            LastError = "";
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            var urls = BuildCandidateUrls();   // PlayerPrefs solo se lee en el hilo principal
            _worker = Task.Run(() => RunSession(urls, ct));
        }

        /// <summary>
        /// Servidores a probar, en orden: override de editor (pruebas), la ultima URL que anduvo,
        /// el servidor de produccion y el espejo. El override nunca reemplaza a produccion:
        /// si el stub local esta apagado, se sigue con los servidores reales.
        /// </summary>
        private static string[] BuildCandidateUrls()
        {
            var urls = new List<string>(4);

#if UNITY_EDITOR
            string dev = PlayerPrefs.GetString(DevOverridePrefKey, "");
            if (!string.IsNullOrEmpty(dev)) urls.Add(dev);
#endif

            if (!string.IsNullOrEmpty(_lastGoodUrl) && !urls.Contains(_lastGoodUrl)) urls.Add(_lastGoodUrl);
            if (!urls.Contains(ProductionUrl)) urls.Add(ProductionUrl);
            if (!urls.Contains(FallbackUrl)) urls.Add(FallbackUrl);
            return urls.ToArray();
        }

        public void Disconnect()
        {
            try { _cts?.Cancel(); } catch (Exception) { }
            var socket = _socket;
            if (socket != null)
            {
                try { socket.Abort(); } catch (Exception) { }
            }
            _cts = null;
            _worker = null;
            _connected = false;
            _socket = null;
            while (_inbox.TryDequeue(out _)) { }
            while (_outbox.TryDequeue(out _)) { }
        }

        /// <summary>Vuelve al menu: avisa al server y cierra el socket con una pequeña demora para que salga el 'leave'.</summary>
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
        // Hilos: sesion, envio y recepcion
        // =================================================================

        private async Task RunSession(string[] urls, CancellationToken ct)
        {
            string lastError = null;

            for (int i = 0; i < urls.Length && !ct.IsCancellationRequested; i++)
            {
                string url = urls[i];
                var socket = new ClientWebSocket();
                bool hadData = false;
                string sessionError = null;

                _sessionError = null;
                _receivedAny = false;
                try
                {
                    await socket.ConnectAsync(new Uri(url), ct).ConfigureAwait(false);
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
                catch (OperationCanceledException) { /* cierre normal */ }
                catch (Exception e)
                {
                    lastError = e.Message;
                    Debug.LogWarning("[WW-PVP] conexion fallida (" + url + "): " + e.Message);
                }
                finally
                {
                    _connected = false;
                    _socket = null;
                    _sessionError = null;
                    try { socket.Dispose(); } catch (Exception) { }
                }

                // Sesion que llego a intercambiar mensajes: termino de forma normal
                // (leave, fin de partida, etc.). Se conserva el motivo si lo hubo.
                if (hadData || ct.IsCancellationRequested)
                {
                    if (!ct.IsCancellationRequested && !string.IsNullOrEmpty(sessionError))
                        LastError = sessionError;
                    return;
                }
                // Servidor caido sin responder: se prueba el proximo candidato.
            }

            if (!ct.IsCancellationRequested) LastError = lastError ?? LastError;
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
