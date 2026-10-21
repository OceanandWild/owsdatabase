using System;

namespace WildWeapon.Pvp
{
    /// <summary>Datos del rival que manda el server al emparejar.</summary>
    [Serializable]
    public class PvpOpp
    {
        public string name;
        public int color;
        public int seat;
        /// <summary>Equipo del rival (0-3) tal como quedo en la sala.</summary>
        public int team;
        /// <summary>El rival lo conduce la IA del anfitrion (no es una persona).</summary>
        public bool bot;
    }

    /// <summary>Un asiento de la sala (persona o bot) tal como lo manda el server.</summary>
    [Serializable]
    public class PvpLobbyPlayer
    {
        public int seat;
        public string name;
        public int color;
        public int team;
        public int control;
        public bool bot;
        public bool host;
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

        // Sala / lobby
        public string room;
        public string code;
        public int cap;
        public bool host;
        public bool started;
        public int total;
        public int waiters;
        public int pos;
        public PvpLobbyPlayer[] players;

        // Emparejamiento
        public int seat;
        public int seed;
        public PvpOpp opp;
        public PvpOpp[] opps;
        public string name;
        public int color;
        /// <summary>Equipo propio y control (viajan al emparejar y en el roster).</summary>
        public int team;
        public int control;
        /// <summary>
        /// Sala: 1 = equipos activos (mismo equipo no se dana), 0 = todos contra
        /// todos. Arranca en 1 para que un server viejo que no manda el campo
        /// mantenga el comportamiento de equipos.
        /// </summary>
        public int teams = 1;
        /// <summary>Asiento que recibe un golpe (hit) o los bots que se fueron (bots_left).</summary>
        public int target = -1;
        /// <summary>Asiento que se lleva la baja (lo manda el dueno del pawn al morir).</summary>
        public int killer = -1;
        public int[] seats;

        // Flujo de rondas
        public int round;
        public int winner;
        public bool final;
        public int[] scores;
        /// <summary>Bajas por asiento (tablero PVP), indexado por seat.</summary>
        public int[] kills;

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
        public const string Kills = "kills";
        public const string Died = "died";
        public const string Rematch = "rematch";
        public const string RematchWait = "rematch_wait";
        public const string OppLeft = "opp_left";
        public const string BotsLeft = "bots_left";
        public const string Error = "error";

        // Lobby por codigo (MultiplayerLobbyController)
        public const string LobbyNew = "lobby_new";
        public const string LobbyJoin = "lobby_join";
        public const string LobbySet = "lobby_set";
        public const string LobbyBots = "lobby_bots";
        public const string LobbyTeams = "lobby_teams";
        public const string LobbyStart = "lobby_start";
        public const string LobbyState = "lobby_state";
        public const string LobbyFull = "lobby_full";
        public const string LobbyClosed = "lobby_closed";
        public const string LobbyError = "lobby_error";
    }
}
