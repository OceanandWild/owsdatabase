using UnityEngine;
using UnityEngine.InputSystem;

namespace WildWeapon
{
    /// <summary>
    /// Director del duelo local F0: best-of-3, HP, Overdrive a los 75 s,
    /// hitstop y revancha. Sim a 60 Hz fijo (doc seccion 9).
    /// </summary>
    public class DuelManager : MonoBehaviour
    {
        public static DuelManager Instance { get; private set; }

        public enum Phase { Intro, Fight, RoundEnd, MatchEnd }

        public PlayerController[] players = new PlayerController[2];
        public Transform[] spawns = new Transform[2];

        public Phase CurrentPhase { get; private set; } = Phase.Intro;
        public int RoundNumber { get; private set; } = 1;
        public int[] Scores { get; private set; } = new int[2];
        public float RoundTime { get; private set; }
        public bool Overdrive { get; private set; }
        public string StatusText { get; private set; } = "";
        public float DamageMultiplier => Overdrive ? DuelRules.OverdriveDamageMultiplier : 1f;
        public PlayerController[] Players => players;

        private float _introTimer;
        private float _endTimer;
        private float _hitStopTimer;
        private float _clearStatusIn;

        void Awake()
        {
            Instance = this;
            Time.fixedDeltaTime = 1f / 60f;   // sim 60 Hz (doc seccion 9)
        }

        void Start()
        {
            StartMatch();
        }

        void Update()
        {
            if (_hitStopTimer > 0f)
            {
                _hitStopTimer -= Time.unscaledDeltaTime;
                if (_hitStopTimer <= 0f) Time.timeScale = 1f;
            }

            switch (CurrentPhase)
            {
                case Phase.Intro:
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
                    if (RematchPressed()) StartMatch();
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
            Scores[0] = 0;
            Scores[1] = 0;
            RoundNumber = 1;
            BeginRound();
        }

        private void BeginRound()
        {
            Overdrive = false;
            RoundTime = 0f;
            _clearStatusIn = 0f;
            StatusText = $"RONDA {RoundNumber}";
            _introTimer = 1.1f;
            CurrentPhase = Phase.Intro;

            ResetPlayers();
            SetPlayersCanAct(false);
        }

        private void ResetPlayers()
        {
            if (players == null || spawns == null) return;
            for (int i = 0; i < players.Length && i < spawns.Length; i++)
            {
                if (players[i] == null || spawns[i] == null) continue;

                Vector2 pos = spawns[i].position;
                Vector2 toCenter = Vector2.zero - pos;
                Vector2 look = toCenter.sqrMagnitude > 0.0001f ? toCenter.normalized : Vector2.right;
                players[i].ResetForRound(pos, look);
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
            if (CurrentPhase != Phase.Fight) return;

            int loserIndex = -1;
            for (int i = 0; i < players.Length; i++)
                if (players[i] != null && players[i].Health == dead) { loserIndex = i; break; }
            if (loserIndex < 0) return;

            int winnerIndex = 1 - loserIndex;
            Scores[winnerIndex]++;
            CurrentPhase = Phase.RoundEnd;
            _endTimer = 2.2f;
            _clearStatusIn = 0f;
            StatusText = $"RONDA {RoundNumber}: GANA J{winnerIndex + 1}";
            SetPlayersCanAct(false);
        }

        public void RequestHitStop(float duration)
        {
            if (duration <= 0f) return;
            Time.timeScale = DuelRules.HitStopTimeScale;
            _hitStopTimer = Mathf.Max(_hitStopTimer, duration);
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
