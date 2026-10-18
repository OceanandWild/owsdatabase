using System;

namespace WildWeapon.Pvp
{
    /// <summary>Datos del rival que manda el server al emparejar.</summary>
    [Serializable]
    public class PvpOpp
    {
        public string name;
        public int color;
    }

    /// <summary>
    /// Mensaje del protocolo PVP (server.js -> /wildweapon/pvp).
    /// JsonUtility no soporta polimorfismo, asi que es un unico tipo plano:
    /// solo se leen los campos que correspondan al tipo 't'.
    /// </summary>
    [Serializable]
    public class PvpMsg
    {
        public string t;

        // Emparejamiento
        public int seat;
        public string room;
        public int seed;
        public PvpOpp opp;
        public string name;
        public int color;

        // Flujo de rondas
        public int round;
        public int winner;
        public bool final;
        public int[] scores;

        // Estado del jugador remoto
        public float x;
        public float y;
        public float ax = 1f;
        public float ay;
        public float sp;
        public float hp;
        /// <summary>Altura (Z) simulada del pawn: plataformas y saltos viajan en el state.</summary>
        public float z;

        // Eventos
        public int w;
        public int k;
        public float dmg;
        public float dx;
        public float dy;

        // Varios
        public int n;
        public string msg;
        public string reason;
    }

    /// <summary>Tipos de mensaje del protocolo (t).</summary>
    public static class PvpMsgType
    {
        public const string Join = "join";
        public const string Leave = "leave";
        public const string Ready = "ready";
        public const string Queued = "queued";
        public const string Matched = "matched";
        public const string RoundStart = "round_start";
        public const string RoundEnd = "round_end";
        public const string State = "state";
        public const string Attack = "atk";
        public const string Cast = "cast";
        public const string Swap = "swap";
        public const string Hit = "hit";
        public const string Died = "died";
        public const string Rematch = "rematch";
        public const string RematchWait = "rematch_wait";
        public const string OppLeft = "opp_left";
        public const string Error = "error";
    }
}
