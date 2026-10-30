using System;
using System.Collections;
using UnityEngine;

namespace WilderGambit.Services
{
    /// <summary>
    /// Skeleton multiplayer service for online matchmaking.
    /// Uses HTTP polling initially; upgrade to WebSocket for real-time play.
    /// Las peticiones pasan por <see cref="OwsApiFailover"/>: si el servidor
    /// principal (owsdatabase) no responde, se reintentan solas contra el
    /// espejo (owsdatabase2).
    /// </summary>
    public class MultiplayerService : MonoBehaviour
    {
        public static MultiplayerService Instance { get; private set; }

        public enum MatchState
        {
            Idle,
            Searching,
            Found,
            InGame,
            Error
        }

        public MatchState CurrentState { get; private set; } = MatchState.Idle;
        public string OpponentName { get; private set; } = "";
        public string MatchId { get; private set; } = "";

        public event Action<MatchState> OnStateChanged;
        public event Action<string> OnError;

        private Coroutine _pollingCoroutine;

        private void Awake()
        {
            if (Instance != null && Instance != this) { Destroy(gameObject); return; }
            Instance = this;
            DontDestroyOnLoad(gameObject);
        }

        /// <summary>Starts searching for a match.</summary>
        public void StartMatchmaking()
        {
            if (CurrentState == MatchState.Searching) return;

            SetState(MatchState.Searching);
            _pollingCoroutine = StartCoroutine(MatchmakingPoll());
        }

        /// <summary>Cancels the current matchmaking search.</summary>
        public void CancelMatchmaking()
        {
            if (_pollingCoroutine != null)
            {
                StopCoroutine(_pollingCoroutine);
                _pollingCoroutine = null;
            }
            SetState(MatchState.Idle);
        }

        /// <summary>Sends a move to the opponent.</summary>
        public void SendMove(string uciMove)
        {
            if (CurrentState != MatchState.InGame) return;
            StartCoroutine(SendMoveCoroutine(uciMove));
        }

        /// <summary>Forfeits the current game.</summary>
        public void Forfeit()
        {
            StartCoroutine(ForfeitCoroutine());
            SetState(MatchState.Idle);
        }

        private IEnumerator MatchmakingPoll()
        {
            while (CurrentState == MatchState.Searching)
            {
                var token = OceanPayService.Instance?.SavedToken;
                if (string.IsNullOrEmpty(token))
                {
                    SetState(MatchState.Error);
                    OnError?.Invoke("No hay sesión activa.");
                    yield break;
                }

                var call = OwsApiFailover.Post("/multiplayer/search", "{}", token, 10);
                yield return call;

                if (call.Success)
                {
                    // TODO: Parse match found response
                    // if (matchFound) { SetState(MatchState.Found); MatchId = ...; }
                    Debug.Log("[Multiplayer] Poll response: " + call.text);
                }
                else
                {
                    Debug.LogWarning("[Multiplayer] Sin respuesta de matchmaking: " + call.ErrorText);
                }

                yield return new WaitForSecondsRealtime(3f);
            }
        }

        private IEnumerator SendMoveCoroutine(string uciMove)
        {
            var token = OceanPayService.Instance?.SavedToken;
            if (string.IsNullOrEmpty(token)) yield break;

            string json = $"{{\"match_id\":\"{MatchId}\",\"move\":\"{uciMove}\"}}";
            var call = OwsApiFailover.Post("/multiplayer/move", json, token, 10);
            yield return call;

            if (!call.Success)
            {
                OnError?.Invoke("Error enviando movimiento: " + call.ErrorText);
            }
        }

        private IEnumerator ForfeitCoroutine()
        {
            var token = OceanPayService.Instance?.SavedToken;
            if (string.IsNullOrEmpty(token)) yield break;

            string json = $"{{\"match_id\":\"{MatchId}\"}}";
            yield return OwsApiFailover.Post("/multiplayer/forfeit", json, token, 10);
        }

        private void SetState(MatchState state)
        {
            CurrentState = state;
            OnStateChanged?.Invoke(state);
        }
    }
}
