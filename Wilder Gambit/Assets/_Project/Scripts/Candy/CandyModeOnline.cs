using System;
using UnityEngine;
using WilderGambit.Core;
using WilderGambit.Services;

namespace WilderGambit.Candy
{
    [Serializable]
    public class CandySearchRequest
    {
        public string player_id;
        public string player_name;
        public string loadout_json;
    }

    [Serializable]
    public class CandySearchResponse
    {
        public string state;
        public string match_id;
        public int side;
        public string opponent_name;
        public string white_loadout;
        public string black_loadout;
        public int seed;
        public long started_at;
        public long server_time;
        public string status;
        public string turn;
        public int seq;
        public CandyAction[] actions;
        public string result;
        public string winner;
        public bool opponent_connected;
        public string error;
    }

    [Serializable]
    public class CandyStateResponse
    {
        public string state;
        public string match_id;
        public int side;
        public string opponent_name;
        public string status;
        public string turn;
        public int seq;
        public CandyAction[] actions;
        public long started_at;
        public long server_time;
        public string result;
        public string winner;
        public bool opponent_connected;
        public string error;
    }

    [Serializable]
    public class CandyActionRequest
    {
        public string match_id;
        public string player_id;
        public CandyAction action;
    }

    [Serializable]
    public class CandyActionResponse
    {
        public bool success;
        public int seq;
        public string turn;
        public string status;
        public long server_time;
        public string error;
    }

    [Serializable]
    public class CandyPlayerRequest
    {
        public string match_id;
        public string player_id;
    }

    [Serializable]
    public class CandyPlayerOnlyRequest
    {
        public string player_id;
    }

    [Serializable]
    public class CandyFinishRequest
    {
        public string match_id;
        public string player_id;
        public string reason;
        public string winner;
    }

    /// <summary>
    /// Puente HTTP del modo online. Las peticiones pasan por el failover de OWS:
    /// si owsdatabase no contesta, se reintentan solas contra owsdatabase2, y
    /// el servidor se despierta con la primera petición.
    /// </summary>
    public static class CandyApi
    {
        public const string SearchPath = "/multiplayer/candy/search";
        public const string CancelPath = "/multiplayer/candy/cancel";
        public const string StatePath = "/multiplayer/candy/state";
        public const string ActionPath = "/multiplayer/candy/action";
        public const string LeavePath = "/multiplayer/candy/leave";
        public const string FinishPath = "/multiplayer/candy/finish";

        private const string PlayerIdKey = "WG_CandyMode_PlayerId";

        public static string PlayerId
        {
            get
            {
                string id = PlayerPrefs.GetString(PlayerIdKey, "");
                if (string.IsNullOrEmpty(id))
                {
                    id = Guid.NewGuid().ToString("N").Substring(0, 16);
                    PlayerPrefs.SetString(PlayerIdKey, id);
                    PlayerPrefs.Save();
                }
                return id;
            }
        }

        public static string PlayerName
        {
            get
            {
                string name = OceanPayService.Instance != null
                    ? OceanPayService.Instance.SavedUsername
                    : "";
                if (!string.IsNullOrEmpty(name)) return name.Trim();

                string id = PlayerId;
                string suffix = id.Length >= 4 ? id.Substring(id.Length - 4) : id;
                return "Invitado-" + suffix;
            }
        }

        public static string SearchBody(CandyLoadout loadout)
        {
            return JsonUtility.ToJson(new CandySearchRequest
            {
                player_id = PlayerId,
                player_name = PlayerName,
                loadout_json = (loadout ?? CandyLoadout.Default()).ToJson()
            });
        }

        public static string CancelBody()
        {
            return JsonUtility.ToJson(new CandyPlayerOnlyRequest { player_id = PlayerId });
        }

        public static string LeaveBody(string matchId)
        {
            return JsonUtility.ToJson(new CandyPlayerRequest
            {
                match_id = matchId,
                player_id = PlayerId
            });
        }

        public static string ActionBody(string matchId, CandyAction action)
        {
            return JsonUtility.ToJson(new CandyActionRequest
            {
                match_id = matchId,
                player_id = PlayerId,
                action = action
            });
        }

        public static string FinishBody(string matchId, string reason, string winner)
        {
            return JsonUtility.ToJson(new CandyFinishRequest
            {
                match_id = matchId,
                player_id = PlayerId,
                reason = reason,
                winner = winner
            });
        }

        public static string StateUrl(string matchId, int since)
        {
            return StatePath
                + "?match_id=" + Uri.EscapeDataString(matchId ?? "")
                + "&player_id=" + Uri.EscapeDataString(PlayerId)
                + "&since=" + Mathf.Max(0, since);
        }

        public static CandySearchResponse ParseSearch(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try { return JsonUtility.FromJson<CandySearchResponse>(json); }
            catch { return null; }
        }

        public static CandyStateResponse ParseState(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try { return JsonUtility.FromJson<CandyStateResponse>(json); }
            catch { return null; }
        }

        public static CandyActionResponse ParseAction(string json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try { return JsonUtility.FromJson<CandyActionResponse>(json); }
            catch { return null; }
        }

        public static bool IsWhiteSide(int side) => side == 0;

        public static TeamColor SideFromTurn(string turn)
        {
            return string.Equals(turn, "black", StringComparison.OrdinalIgnoreCase)
                ? TeamColor.Black
                : TeamColor.White;
        }

        public static bool TryParseWinner(string winner, out TeamColor? side)
        {
            side = null;
            if (string.Equals(winner, "white", StringComparison.OrdinalIgnoreCase))
            {
                side = TeamColor.White;
                return true;
            }
            if (string.Equals(winner, "black", StringComparison.OrdinalIgnoreCase))
            {
                side = TeamColor.Black;
                return true;
            }
            return false;
        }
    }
}
