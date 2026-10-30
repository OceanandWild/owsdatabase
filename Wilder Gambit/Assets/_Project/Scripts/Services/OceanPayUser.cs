using System;

namespace WilderGambit.Services
{
    [Serializable]
    public class OceanPayUser
    {
        public int    id;
        public string username;
        public float  tides;
        public float  gambits;

        public static OceanPayUser FromLoginJson(LoginResponse resp)
        {
            if (resp?.user == null) return null;
            return new OceanPayUser
            {
                id       = resp.user.id,
                username = resp.user.username ?? "",
                tides    = 0f,
                gambits  = 0f
            };
        }

        [Serializable] public class LoginResponse   { public bool success; public string token; public string error; public UserPayload user; }
        [Serializable] public class RegisterResponse { public bool success; public string token; public string error; public UserPayload user; }
        [Serializable] public class UserPayload     { public int id; public string username; public float aquabux; public float wildcredits; }
        [Serializable] public class MeResponse      { public bool success; public string error; public int id; public string username; public float tides; public float gambits; }
        [Serializable] public class BalanceResponse { public float tides; public float gambits; public string error; }
        [Serializable] public class EarnResponse    { public bool success; public float gambits; public float earned; public string reason; public string error; }

        /// <summary>GET /ocean-pay/wilder-gambit/season-pass — estado del pase en el servidor.</summary>
        [Serializable]
        public class SeasonPassStatusResponse
        {
            public bool success;
            public bool owned;
            public int season;
            public int priceTides;
            public float tides;
            public string username;
            public string error;
        }

        /// <summary>POST /ocean-pay/wilder-gambit/season-pass/purchase — cobro real de Tides.</summary>
        [Serializable]
        public class SeasonPassPurchaseResponse
        {
            public bool success;
            public bool owned;
            public bool alreadyOwned;
            public int spent;
            public int season;
            public int priceTides;
            public float tides;
            public int required;
            public string error;
        }
    }
}
