using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using Debug = UnityEngine.Debug;

namespace WilderGambit.Engine
{
    public struct StockfishAnalysis
    {
        public string BestMove;
        public float Centipawns; // Evaluation from perspective of the side to move (positive = advantage)
        public bool IsMate;
        public int MateInMoves;
        public int Depth;
    }

    public class StockfishEngine : MonoBehaviour
    {
        public static StockfishEngine Instance { get; private set; }

        private Process _process;
        private StreamWriter _input;
        private StreamReader _output;
        private readonly object _lock = new object();
        private bool _isInitialized = false;

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }
            Instance = this;
            DontDestroyOnLoad(gameObject);

            InitializeEngine();
        }

        private void InitializeEngine()
        {
            try
            {
                string binaryPath = Path.Combine(Application.streamingAssetsPath, "Stockfish", "stockfish.exe");
                if (!File.Exists(binaryPath))
                {
                    Debug.LogError($"[StockfishEngine] No se encontró el ejecutable de Stockfish en: {binaryPath}");
                    return;
                }

                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = binaryPath,
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8
                };

                _process = new Process { StartInfo = psi };
                _process.Start();

                _input = _process.StandardInput;
                _output = _process.StandardOutput;

                // Send UCI handshake and configure maximum potential
                SendCommand("uci");
                int threads = Mathf.Clamp(Environment.ProcessorCount - 1, 1, 8);
                SendCommand($"setoption name Threads value {threads}");
                SendCommand("setoption name Hash value 128");
                SendCommand("setoption name UCI_AnalyseMode value true");
                SendCommand("setoption name Skill Level value 20");
                SendCommand("setoption name UCI_LimitStrength value false");
                SendCommand("isready");

                // Wait briefly for readyok
                string line;
                while ((line = _output.ReadLine()) != null)
                {
                    if (line.Trim() == "readyok") break;
                }

                _isInitialized = true;
                Debug.Log($"[StockfishEngine] Stockfish 18 iniciado correctamente con potencial máximo (Threads: {threads}, Hash: 128MB, Skill: 20).");
            }
            catch (Exception ex)
            {
                Debug.LogError($"[StockfishEngine] Error al iniciar Stockfish: {ex.Message}");
            }
        }

        public void SendCommand(string command)
        {
            if (_input == null) return;
            lock (_lock)
            {
                _input.WriteLine(command);
                _input.Flush();
            }
        }

        public async Task<StockfishAnalysis> AnalyzePositionAsync(string fen, int moveTimeMs = 300, int maxDepth = 18)
        {
            if (!_isInitialized)
            {
                return new StockfishAnalysis { BestMove = "", Centipawns = 0 };
            }

            return await Task.Run(() =>
            {
                lock (_lock)
                {
                    StockfishAnalysis result = new StockfishAnalysis();
                    try
                    {
                        // Ensure engine is ready and standard output is clean
                        SendCommand("isready");
                        string syncLine;
                        while ((syncLine = _output.ReadLine()) != null)
                        {
                            if (syncLine.Trim() == "readyok") break;
                        }

                        SendCommand($"position fen {fen}");
                        SendCommand($"go movetime {moveTimeMs} depth {maxDepth}");

                        string line;
                        while ((line = _output.ReadLine()) != null)
                        {
                            line = line.Trim();
                            if (line.StartsWith("info ") && line.Contains("score "))
                            {
                                ParseInfoLine(line, ref result);
                            }
                            else if (line.StartsWith("bestmove "))
                            {
                                string[] parts = line.Split(' ');
                                if (parts.Length > 1 && parts[1] != "(none)")
                                {
                                    result.BestMove = parts[1];
                                }
                                break;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.LogError($"[StockfishEngine] Error durante análisis: {ex.Message}");
                    }
                    return result;
                }
            });
        }

        private void ParseInfoLine(string line, ref StockfishAnalysis analysis)
        {
            string[] tokens = line.Split(' ');
            for (int i = 0; i < tokens.Length; i++)
            {
                if (tokens[i] == "depth" && i + 1 < tokens.Length)
                {
                    int.TryParse(tokens[i + 1], out analysis.Depth);
                }
                else if (tokens[i] == "score" && i + 2 < tokens.Length)
                {
                    string scoreType = tokens[i + 1];
                    if (scoreType == "cp")
                    {
                        if (float.TryParse(tokens[i + 2], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out float cp))
                        {
                            analysis.Centipawns = cp / 100f; // Convert centipawns to pawns
                            analysis.IsMate = false;
                        }
                    }
                    else if (scoreType == "mate")
                    {
                        if (int.TryParse(tokens[i + 2], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int mate))
                        {
                            analysis.IsMate = true;
                            analysis.MateInMoves = mate;
                            analysis.Centipawns = mate > 0 ? 1000f : -1000f;
                        }
                    }
                }
            }
        }

        private void OnDestroy()
        {
            ShutdownEngine();
        }

        private void OnApplicationQuit()
        {
            ShutdownEngine();
        }

        private void ShutdownEngine()
        {
            try
            {
                if (_process != null && !_process.HasExited)
                {
                    SendCommand("quit");
                    _process.Kill();
                    _process.Dispose();
                    _process = null;
                }
            }
            catch { }
        }
    }
}
