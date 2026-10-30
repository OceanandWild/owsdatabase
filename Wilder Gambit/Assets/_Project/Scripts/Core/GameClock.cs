using System;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Time control configurations for chess games.
    /// </summary>
    public enum TimeControl
    {
        None,       // No time limit
        Bullet,     // 1 minute
        Blitz,      // 3 minutes + 2 second increment
        Rapid,      // 10 minutes
        Classical   // 30 minutes
    }

    /// <summary>
    /// Reloj de partida: cuenta atrás de ambos bandos con incremento opcional.
    ///
    /// Se descuenta del bando que tiene el turno mientras la partida corre. Lo llama
    /// GameManager: arranca al empezar, cambia de bando en cada EndTurn, se congela en
    /// pausa y dispara OnTimeExpired cuando alguien se queda sin tiempo.
    ///
    /// Vive en un GameObject propio que se crea con EnsureExists() (igual que
    /// PuzzleManager, DailyChallenge o ChessAI) para no depender de que alguien lo haya
    /// puesto a mano en la escena: sin él, los modos con reloj no arrancaban nunca.
    /// </summary>
    public class GameClock : MonoBehaviour
    {
        public static GameClock Instance { get; private set; }

        [Header("Time Control")]
        [SerializeField] private TimeControl timeControl = TimeControl.None;

        private float _whiteTime;
        private float _blackTime;
        private float _increment;
        private bool _isRunning;
        private bool _isPaused;
        private TeamColor _activeTeam = TeamColor.White;

        public float WhiteTime => _whiteTime;
        public float BlackTime => _blackTime;

        /// <summary>Bando que tiene el reloj corriendo ahora mismo.</summary>
        public TeamColor ActiveTeam => _activeTeam;

        /// <summary>Modo de tiempo con el que se arrancó (None = sin reloj).</summary>
        public TimeControl Control => timeControl;

        /// <summary>Segundos que se suman a cada bando al completar su jugada.</summary>
        public float Increment => _increment;

        /// <summary>Hay reloj y está descontando (no pausado, sin tiempo agotado).</summary>
        public bool IsActive => _isRunning && !_isPaused && timeControl != TimeControl.None;

        public event Action<TeamColor> OnTimeExpired;

        /// <summary>Crea el reloj si la escena no lo tiene (patrón del resto de managers).</summary>
        public static void EnsureExists()
        {
            if (Instance != null) return;
            var go = new GameObject("GameClock");
            go.AddComponent<GameClock>();
        }

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
        }

        /// <summary>
        /// Configura y arranca el reloj. None detiene la cuenta atrás y deja el reloj
        /// apagado (así una partida sin tiempo no hereda el estado de la anterior).
        /// </summary>
        public void StartClock(TimeControl control)
        {
            timeControl = control;

            switch (control)
            {
                case TimeControl.Bullet:
                    _whiteTime = 60f; _blackTime = 60f; _increment = 0f; break;
                case TimeControl.Blitz:
                    _whiteTime = 180f; _blackTime = 180f; _increment = 2f; break;
                case TimeControl.Rapid:
                    _whiteTime = 600f; _blackTime = 600f; _increment = 0f; break;
                case TimeControl.Classical:
                    _whiteTime = 1800f; _blackTime = 1800f; _increment = 0f; break;
                default:
                    _whiteTime = 0f; _blackTime = 0f; _increment = 0f; break;
            }

            _isRunning = (control != TimeControl.None);
            _isPaused = false;
            _activeTeam = TeamColor.White;
        }

        /// <summary>
        /// Pasa el reloj al bando contrario tras cada jugada: suma el incremento al que
        /// acaba de mover y arranca a descontar el nuevo.
        /// </summary>
        public void SwitchClock()
        {
            if (!_isRunning) return;

            // Add increment to the player who just moved
            if (_activeTeam == TeamColor.White)
                _whiteTime += _increment;
            else
                _blackTime += _increment;

            _activeTeam = (_activeTeam == TeamColor.White) ? TeamColor.Black : TeamColor.White;
        }

        /// <summary>
        /// Alinea el reloj con el turno real sin sumar incremento. Se usa al deshacer,
        /// donde la jugada ya se cobró y solo hay que devolver el turno a la vista.
        /// </summary>
        public void SyncTurn(TeamColor team)
        {
            _activeTeam = team;
        }

        /// <summary>Congela la cuenta atrás sin perder el tiempo restante (ESC / pausa).</summary>
        public void Pause()
        {
            if (!_isRunning) return;
            _isPaused = true;
        }

        /// <summary>Reanuda la cuenta atrás donde se quedó.</summary>
        public void Resume()
        {
            _isPaused = false;
        }

        private void Update()
        {
            if (!_isRunning || _isPaused || timeControl == TimeControl.None) return;

            if (_activeTeam == TeamColor.White)
            {
                _whiteTime -= Time.deltaTime;
                if (_whiteTime <= 0f)
                {
                    _whiteTime = 0f;
                    _isRunning = false;
                    OnTimeExpired?.Invoke(TeamColor.White);
                }
            }
            else
            {
                _blackTime -= Time.deltaTime;
                if (_blackTime <= 0f)
                {
                    _blackTime = 0f;
                    _isRunning = false;
                    OnTimeExpired?.Invoke(TeamColor.Black);
                }
            }
        }

        /// <summary>Formats seconds as "M:SS" or "H:MM:SS".</summary>
        public static string FormatTime(float seconds)
        {
            seconds = Mathf.Max(0f, seconds);
            int totalSeconds = Mathf.CeilToInt(seconds);
            int hours = totalSeconds / 3600;
            int mins = (totalSeconds % 3600) / 60;
            int secs = totalSeconds % 60;

            if (hours > 0)
                return $"{hours}:{mins:D2}:{secs:D2}";
            return $"{mins}:{secs:D2}";
        }

        /// <summary>Detiene la cuenta atrás (fin de partida, vuelta al menú, pausa de sesión).</summary>
        public void Stop() => _isRunning = false;

        /// <summary>Igual que Stop: el reloj queda apagado hasta el próximo StartClock.</summary>
        public void Reset() => _isRunning = false;
    }
}