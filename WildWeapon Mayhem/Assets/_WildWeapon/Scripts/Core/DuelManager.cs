using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;

namespace WildWeapon
{
    /// <summary>
    /// Director del duelo local F0: best-of-3, HP, Overdrive a los 75 s,
    /// hitstop y revancha. Sim a 60 Hz fijo (doc seccion 9).
    /// En PVP online (pvpDriven) las rondas las arbitra el server: aca solo
    /// se ejecutan los anuncios que llegan por red.
    /// </summary>
    public class DuelManager : MonoBehaviour
    {
        public static DuelManager Instance { get; private set; }

        public enum Phase { Intro, Fight, RoundEnd, MatchEnd }

        public List<PlayerController> players = new List<PlayerController>();
        public Transform[] spawns = new Transform[2];

        /// <summary>PVP online: el arranque y el avance de rondas vienen del server.</summary>
        public bool pvpDriven;

        /// <summary>PVP: se pide revancha (R) y lo maneja PvpMatchManager.</summary>
        public event Action PvpRematchRequested;

        public Phase CurrentPhase { get; private set; } = Phase.Intro;
        public int RoundNumber { get; private set; } = 1;
        public int[] Scores { get; private set; } = new int[2];
        public float RoundTime { get; private set; }
        public bool Overdrive { get; private set; }
        public string StatusText { get; private set; } = "";
        public float DamageMultiplier => Overdrive ? DuelRules.OverdriveDamageMultiplier : 1f;
        public PlayerController[] Players => players.ToArray();

        private float _introTimer;
        private float _endTimer;
        private float _clearStatusIn;
        private bool _waitingForRound;

        void Awake()
        {
            Instance = this;
            Time.fixedDeltaTime = 1f / 60f;   // sim 60 Hz (doc seccion 9)
        }

        void OnDestroy()
        {
            if (Instance == this) Instance = null;
        }

        void Start()
        {
            if (pvpDriven)
            {
                // PVP: la ronda 1 arranca cuando el server empareja y ambos confirman.
                _waitingForRound = true;
                SetPlayersCanAct(false);
                return;
            }
            StartMatch();
        }

        void Update()
        {
            switch (CurrentPhase)
            {
                case Phase.Intro:
                    if (_waitingForRound) break;   // PVP: esperando round_start del server
                    _introTimer -= Time.deltaTime;
                    if (_introTimer <= 0f)
                    {
                        CurrentPhase = Phase.Fight;
                        StatusText = "";
                        SetPlayersCanAct(true);
                    }
                    break;

                case Phase.Fight:
                    RoundTime += Time.deltaTime;
                    if (!Overdrive && RoundTime >= DuelRules.OverdriveAt)
                    {
                        Overdrive = true;
                        StatusText = "!OVERDRIVE!";
                        _clearStatusIn = 1.6f;
                    }
                    break;

                case Phase.RoundEnd:
                    if (pvpDriven) break;   // PVP: la ronda siguiente la anuncia el server
                    _endTimer -= Time.deltaTime;
                    if (_endTimer <= 0f)
                    {
                        int winner = MatchWinner();
                        if (winner >= 0)
                        {
                            CurrentPhase = Phase.MatchEnd;
                            StatusText = $"GANA J{winner + 1} LA PARTIDA";
                        }
                        else
                        {
                            RoundNumber++;
                            BeginRound();
                        }
                    }
                    break;

                case Phase.MatchEnd:
                    if (RematchPressed())
                    {
                        if (pvpDriven) PvpRematchRequested?.Invoke();
                        else StartMatch();
                    }
                    break;
            }

            if (_clearStatusIn > 0f)
            {
                _clearStatusIn -= Time.deltaTime;
                if (_clearStatusIn <= 0f) StatusText = "";
            }
        }

        public void StartMatch()
        {
            Scores = new int[Mathf.Max(2, players.Count)];
            for (int i = 0; i < Scores.Length; i++) Scores[i] = 0;
            RoundNumber = 1;
            BeginRound();
        }

        /// <summary>PVP: arranca una ronda con el numero y marcador que arbitro el server.</summary>
        public void PvpRoundStart(int round, int[] scores)
        {
            if (scores != null && scores.Length >= 2)
            {
                Scores[0] = scores[0];
                Scores[1] = scores[1];
            }
            RoundNumber = Mathf.Max(1, round);
            // La ronda 1 lleva la cuenta regresiva 3-2-1-GO; las siguientes, intro corto.
            BeginRound(RoundNumber == 1 ? 3.0f : 1.1f);
        }

        /// <summary>PVP: resultado de ronda anunciado por el server.</summary>
        public void PvpRoundEnd(int winner, int[] scores, bool isFinal)
        {
            if (scores != null && scores.Length >= 2)
            {
                Scores[0] = scores[0];
                Scores[1] = scores[1];
            }
            SetPlayersCanAct(false);
            _clearStatusIn = 0f;
            CurrentPhase = isFinal ? Phase.MatchEnd : Phase.RoundEnd;
            StatusText = isFinal
                ? $"GANA J{winner + 1} LA PARTIDA"
                : $"RONDA {RoundNumber}: GANA J{winner + 1}";
        }

        /// <summary>PVP: el rival se desconecto o abandono.</summary>
        public void PvpOpponentLeft(string reason)
        {
            SetPlayersCanAct(false);
            _clearStatusIn = 0f;
            CurrentPhase = Phase.MatchEnd;
            StatusText = string.Equals(reason, "leave", StringComparison.OrdinalIgnoreCase)
                ? "EL RIVAL SE RETIRO"
                : "RIVAL DESCONECTADO";
        }

        /// <summary>PVP: mensaje de estado externo (sincronizacion/conexion).</summary>
        public void SetStatus(string text)
        {
            StatusText = text;
        }

        private void BeginRound() => BeginRound(1.1f);

        private void BeginRound(float introSeconds)
        {
            _waitingForRound = false;
            Overdrive = false;
            RoundTime = 0f;
            _clearStatusIn = 0f;
            StatusText = $"RONDA {RoundNumber}";
            _introTimer = introSeconds;
            CurrentPhase = Phase.Intro;

            ResetPlayers();
            SetPlayersCanAct(false);
        }

        private void ResetPlayers()
        {
            if (players == null || spawns == null) return;
            for (int i = 0; i < players.Count && i < spawns.Length; i++)
            {
                if (players[i] == null || spawns[i] == null) continue;

                Vector2 pos = spawns[i].position;
                Vector2 toCenter = Vector2.zero - pos;
                Vector2 look = toCenter.sqrMagnitude > 0.0001f ? toCenter.normalized : Vector2.right;
                players[i].ResetForRound(pos, look);
                var caster = players[i].Abilities;
                if (caster != null) caster.ResetForRound();
            }
        }

        private void SetPlayersCanAct(bool value)
        {
            if (players == null) return;
            foreach (var p in players)
                if (p != null) p.CanAct = value;
        }

        public void NotifyDeath(PlayerHealth dead)
        {
            if (pvpDriven) return;   // PVP: la muerte la arbitra el server (mensaje died)
            if (CurrentPhase != Phase.Fight) return;

            int deadIndex = -1;
            for (int i = 0; i < players.Count; i++)
                if (players[i] != null && players[i].Health == dead) { deadIndex = i; break; }
            if (deadIndex < 0) return;

            int alive = 0;
            int lastAlive = -1;
            for (int i = 0; i < players.Count; i++)
            {
                if (players[i] != null && players[i].Health != null && !players[i].Health.IsDead)
                {
                    alive++;
                    lastAlive = i;
                }
            }

            _clearStatusIn = 0f;
            SetPlayersCanAct(false);

            if (alive <= 1 && lastAlive >= 0)
            {
                if (lastAlive < Scores.Length) Scores[lastAlive]++;
                CurrentPhase = Phase.MatchEnd;
                StatusText = $"GANA J{lastAlive + 1} LA PARTIDA";
            }
            else
            {
                CurrentPhase = Phase.RoundEnd;
                _endTimer = 2.2f;
                StatusText = $"J{deadIndex + 1} ELIMINADO ({alive} restantes)";
            }
        }

        public void RequestHitStop(float duration)
        {
            GameFeel.HitStop(duration);
        }

        private int MatchWinner()
        {
            if (Scores[0] >= DuelRules.RoundsToWin) return 0;
            if (Scores[1] >= DuelRules.RoundsToWin) return 1;
            return -1;
        }

        private static bool RematchPressed()
        {
            var kb = Keyboard.current;
            if (kb != null && kb.rKey.wasPressedThisFrame) return true;
            var pad = Gamepad.current;
            if (pad != null && pad.startButton.wasPressedThisFrame) return true;
            return false;
        }
    }
}
