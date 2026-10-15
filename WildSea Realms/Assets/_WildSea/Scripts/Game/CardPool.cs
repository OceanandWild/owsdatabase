using System.Collections.Generic;

namespace WildSea.Game
{
    /// <summary>
    /// Catalogo de cartas del Universo Espacio.
    ///
    /// Clasificacion por cuerpo fisico (no por rol mecanico como en el modo viejo):
    ///   - Titán y Europa son LUNAS de Saturno y Júpiter. Antes figuraban como "Star"
    ///     porque en el modo viejo "Star" significaba "dispara al completar". Acá la
    ///     categoria es fisica, asi que Titán fusiona con Ganimedes y no con Betelgeuse.
    ///   - La Singularidad es un agujero negro: categoria Estrella.
    ///   - Los objetos hechos por el hombre (sondas, estaciones, motores) son el escalon
    ///     mas bajo, categoria Objeto.
    ///
    /// Lunas y satelites no llevan subcategoria. Los planetas del Sistema Solar
    /// comparten esa subcategoria; Ceres, Pluton, Eris, Haumea y Makemake llevan
    /// "Planeta Enano". Vesta y Palas se quedan sin subcategoria.
    /// </summary>
    public static class CardPool
    {
        public const string SUB_SOLAR_SYSTEM = "Sistema Solar";
        public const string SUB_DWARF_PLANET = "Planeta Enano";

        /// El peso por categoria de una coleccion.
        ///
        /// Reparto actual (9 de promedio por categoria, dentro del rango sano):
        ///   Objeto 11 · Asteroide 11 · Luna 9 · Planeta 10 · Estrella 8 · Nube 9 · Galaxia 7
        ///
        /// Sube "sol" si querés que el Sistema Solar dure menos: es 1 de las 8
        /// plantillas de Estrella, asi que sale en 1 de cada 56 robos y es lo unico
        /// que hace que ese objetivo tarde ~47 turnos. Agrandar la bolsa no lo
        /// arregla; cambiar su peso, si.
        /// </summary>
        static readonly (string id, int n)[] DeckWeights =
        {
            // Objeto: sondas, estaciones, motores. Es el pie de la escalera.
            ("cubesat",3), ("radiotelescopio",2), ("estacion-orbital",2), ("plasma-solar",2),
            ("sonda-voyager",1), ("motor-plasma",1),
            // Asteroide: 5 planetas enanos + 2 asteroides grandes.
            ("ceres",3), ("pluton",1), ("eris",1), ("haumea",1), ("makemake",1),
            ("vesta",2), ("palas",2),
            // Luna: satelites, sin subcategoria.
            ("luna",3), ("ganimedes",2), ("titan",2), ("europa",2),
            // Planeta: 8 del Sistema Solar. "sol" pesa 1 (ver nota arriba).
            ("sol",1),
            ("venus",1), ("marte",1), ("tierra",1), ("mercurio",1),
            ("jupiter",2), ("saturno",2), ("urano",1), ("neptuno",1),
            // Estrella: el Sol mas 6 estrellas sin subcategoria.
            ("enana-roja",2), ("proxima-centauri",1), ("betelgeuse",1),
            ("rigel",1), ("sirius",1), ("aldebaran",1),
            // Nube: Orion pesa 2 y las otras 7 una cada una: 9 Nubes en total. El
            // minimo son 3, porque cada fusion Estrella->Nube gasta una del mazo,
            // y con menos de 3 la regla Nube->Galaxia no podia dispararse nunca.
            ("nebulosa-orion",2),
            ("roseta",1), ("trifida",1), ("aguila",1), ("cola-de-caballo",1),
            ("america-del-norte",1), ("bruja",1), ("carina",1),
            // Galaxia: tope de la escalera, no sube.
            ("via-lactea",1), ("andromeda",1), ("sombrero",1), ("remolino",1),
            ("triangulo",1), ("molinete",1), ("centaurus-a",1),
        };

        static List<CardDef> _templates;
        public static IReadOnlyList<CardDef> Templates => _templates ??= BuildTemplates();

        static CardDef ById(string id)
        {
            foreach (var c in Templates)
                if (c.id == id) return c;
            throw new System.Exception("Carta desconocida: " + id);
        }

        /// <summary>
        /// Mazo inicial: ya no existe como lista fija.
        ///
        /// Antes eran 5 asteroides (Ceres x3, Vesta, Palas) y el jugador arrancaba en
        /// el SEGUNDO peldan de la escalera: con "Cinturon de Asteroides x3" ya venia
        /// gana en el primer clic. Ahora MatchController saca 5 Objetos de la pila
        /// real (MatchController.TakeObjects), asi que arrancan en el pie de verdad y
        /// forman parte de la misma coleccion.
        /// </summary>

        /// <summary>
        /// Mazo de UN jugador: su coleccion de cartas del Universo Espacio.
        ///
        /// Antes esto se llamaba BuildSharedPile y era una bolsa COMUN a la que los
        /// dos jugadores sacaban cartas que se borraban para siempre. Ahora cada
        /// jugador tiene la suya y MatchController la re-baraja cuando se acaba, asi
        /// que ninguna carta se pierde nunca.
        ///
        /// El reparto por categoria esta medido: por debajo de 6 cartas por categoria
        /// el ciclo se cierra tan rapido que el ruido domina (el objetivo "Cinturon x3"
        /// se va de 12 a 23 turnos). Arriba de 6, agrandar la bolsa no mueve casi nada
        /// la duracion, porque lo que la fija es la TASA (1/7 de los robos por
        /// categoria), no la cantidad. Este reparto promedia 9.
        /// </summary>
        public static List<CardDef> BuildPlayerDeck()
        {
            var l = new List<CardDef>();
            foreach (var (id, n) in DeckWeights)
                for (int i = 0; i < n; i++) l.Add(ById(id));
            Shuffle(l);
            return l;
        }

        public static void Shuffle(List<CardDef> list)
        {
            for (int i = list.Count - 1; i > 0; i--)
            {
                int j = UnityEngine.Random.Range(0, i + 1);
                (list[i], list[j]) = (list[j], list[i]);
            }
        }

        static List<CardDef> BuildTemplates()
        {
            var l = new List<CardDef>();

            // ── Objeto (6) ──────────────────────────────────────────────
            // Escalon mas bajo: sondas, estaciones, motores. Sin subcategoria,
            // asi que jamas sirven para un objetivo: son protectores puros.
            l.Add(new CardDef("cubesat", "CubeSat", BodyCategory.Object, null,
                "Satelite minimo estandarizado."));
            l.Add(new CardDef("radiotelescopio", "Radiotelescopio", BodyCategory.Object, null,
                "Plato enorme, recoge mucho."));
            l.Add(new CardDef("estacion-orbital", "Estacion Orbital", BodyCategory.Object, null,
                "Anillo central y dos alas solares."));
            l.Add(new CardDef("plasma-solar", "Plasma Solar", BodyCategory.Object, null,
                "Viento solar."));
            l.Add(new CardDef("sonda-voyager", "Sonda Voyager", BodyCategory.Object, null,
                "La sonda mas iconica de la flota."));
            l.Add(new CardDef("motor-plasma", "Motor de Plasma", BodyCategory.Object, null,
                "Propulsion compactada."));

            // ── Asteroide (7) ───────────────────────────────────────────
            // Ceres, Pluton, Eris, Haumea y Makemake son los cinco planetas enanos
            // del sistema solar. Vesta y Palas son asteroides grandes, NO enanos,
            // asi que quedan sin subcategoria.
            l.Add(new CardDef("ceres", "Ceres", BodyCategory.Asteroid, SUB_DWARF_PLANET,
                "El único planeta enano del cinturón."));
            l.Add(new CardDef("pluton", "Plutón", BodyCategory.Asteroid, SUB_DWARF_PLANET,
                "Casquete de hielo con forma de corazón."));
            l.Add(new CardDef("eris", "Eris", BodyCategory.Asteroid, SUB_DWARF_PLANET,
                "La superficie más reflectiva del sistema solar."));
            l.Add(new CardDef("haumea", "Haumea", BodyCategory.Asteroid, SUB_DWARF_PLANET,
                "Gira en tres horas y es ovalada."));
            l.Add(new CardDef("makemake", "Makemake", BodyCategory.Asteroid, SUB_DWARF_PLANET,
                "Rojizo y casi sin marcas en su superficie."));
            l.Add(new CardDef("vesta", "Vesta", BodyCategory.Asteroid, null,
                "Asteroide del cinturón principal."));
            l.Add(new CardDef("palas", "Palas", BodyCategory.Asteroid, null,
                "El segundo asteroide más grande."));

            // ── Luna (4) ────────────────────────────────────────────────
            // Sin subcategoria por logica real: son satelites, no cuerpos
            // que pertenezcan a un sistema con nombre propio.
            l.Add(new CardDef("luna", "Luna", BodyCategory.Moon, null,
                "El unico satelite que vio un humano."));
            l.Add(new CardDef("ganimedes", "Ganimedes", BodyCategory.Moon, null,
                "El satelite mas grande del sistema solar."));
            l.Add(new CardDef("titan", "Titan", BodyCategory.Moon, null,
                "Luna de Saturno con atmosfera densa."));
            l.Add(new CardDef("europa", "Europa", BodyCategory.Moon, null,
                "Luna de Jupiter con hielo bajo el oceano."));

            // ── Planeta (8) ─────────────────────────────────────────────
            // Los 8 planetas del Sistema Solar, del mas cercano al mas lejano.
            l.Add(new CardDef("venus", "Venus", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "Planeta rocoso y denso."));
            l.Add(new CardDef("marte", "Marte", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "El planeta rojo."));
            l.Add(new CardDef("tierra", "Tierra", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "El único mundo con vida conocida."));
            l.Add(new CardDef("mercurio", "Mercurio", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "El planeta más pequeño y cercano al Sol."));
            l.Add(new CardDef("jupiter", "Jupiter", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "El gigante gaseoso."));
            l.Add(new CardDef("saturno", "Saturno", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "El gigante de anillos."));
            l.Add(new CardDef("urano", "Urano", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "Gigante helado que rueda de lado."));
            l.Add(new CardDef("neptuno", "Neptuno", BodyCategory.Planet, SUB_SOLAR_SYSTEM,
                "El planeta de los vientos más fuertes."));

            // ── Estrella (8) ───────────────────────────────────────────
            // Todas son estrellas de verdad: una categoria "Estrella" que cuelgue
            // de un agujero negro o de un nucleo galactivo no es una estrella.
            // La Singularidad y el Quasar se fueron; los reemplazan Rigel,
            // Sirius y Aldebaran, que son tres tipos visualmente distintos.
            // El Sol es el unico con subcategoria: es la estrella de un sistema
            // con nombre propio, y sin el el objetivo del Sistema Solar era
            // inalcanzable (IsReachable lo filtraba y nunca se sorteaba).
            l.Add(new CardDef("sol", "Sol", BodyCategory.Star, SUB_SOLAR_SYSTEM,
                "La estrella del sistema solar."));
            l.Add(new CardDef("enana-roja", "Enana Roja", BodyCategory.Star, null,
                "Estrella pequeña y apagada."));
            l.Add(new CardDef("proxima-centauri", "Proxima Centauri", BodyCategory.Star, null,
                "La estrella mas cercana al Sol."));
            l.Add(new CardDef("betelgeuse", "Betelgeuse", BodyCategory.Star, null,
                "Supergigante roja."));
            l.Add(new CardDef("rigel", "Rigel", BodyCategory.Star, null,
                "Supergigante azul."));
            l.Add(new CardDef("sirius", "Sirius", BodyCategory.Star, null,
                "La estrella mas brillante del cielo."));
            l.Add(new CardDef("aldebaran", "Aldebaran", BodyCategory.Star, null,
                "El ojo del toro."));
            // ── Nube de gas (1) ──────────────────────────────────────
            // Una nube no es una estrella: es gas y polvo donde se forman. Por eso
            // tiene su PROPIA categoria y no cuelga de Estrella.
            // Hoy NO hay ningun objetivo que la pida, asi que jugarla nunca suma:
            // es un protector. Su unico valor es como escalon de fusion hacia
            // Galaxia (3 nubes -> 1 galaxia).
            l.Add(new CardDef("nebulosa-orion", "Nebulosa de Orion", BodyCategory.Nebula, null,
                "Region de formacion estelar."));

            // Las 7 siguientes son todas REGIONES DE FORMACION ESTELAR reales y
            // observadas: por eso van en esta categoria y no con las planetarias.
            // Faltan >= 3 copias de Nube en el mazo grande, porque tener 3 Nubes en
            // mano exige gastar 3 fusionando Estrella->Nube: con 2 era fisicamente
            // imposible y la regla Nube->Galaxia jamas se disparaba.
            l.Add(new CardDef("roseta", "Roseta", BodyCategory.Nebula, null,
                "Una flor de gas y estrellas novas."));
            l.Add(new CardDef("trifida", "Trífida", BodyCategory.Nebula, null,
                "Tres cuñas partidas por el polvo."));
            l.Add(new CardDef("aguila", "Águila", BodyCategory.Nebula, null,
                "Columnas de polvo dentro del gas."));
            l.Add(new CardDef("cola-de-caballo", "Cola de Caballo", BodyCategory.Nebula, null,
                "El polvo dibuja la cabeza de un caballo."));
            l.Add(new CardDef("america-del-norte", "América del Norte", BodyCategory.Nebula, null,
                "El gas tiene forma de continente."));
            l.Add(new CardDef("bruja", "Bruja", BodyCategory.Nebula, null,
                "Rigel ilumina su perfil de polvo."));
            l.Add(new CardDef("carina", "Carina", BodyCategory.Nebula, null,
                "Donde nacen las estrellas más masivas."));

            // ── Galaxia (7) ───────────────────────────────────────────
            // Tope de la escalera: no sube. Sin subcategoria, asi que hoy
            // ningun objetivo las pide: son protectoras. Su valor real es
            // (a) cerrar el ciclo 3 Nubes -> 1 Galaxia, que antes era un
            // callejon sin salida porque el pool no tenia ninguna Galaxia, y
            // (b) sostener el techo del modo clasico: son las cartas que solo
            // se consiguen encadenando 9 peldanos de fusion.
            // Las siete son galaxias reales y todas tienen imagen observada.
            l.Add(new CardDef("via-lactea", "Vía Láctea", BodyCategory.Galaxy, null,
                "La galaxia que contiene el sistema solar."));
            l.Add(new CardDef("andromeda", "Andrómeda", BodyCategory.Galaxy, null,
                "La galaxia espiral más cercana."));
            l.Add(new CardDef("sombrero", "Sombrero", BodyCategory.Galaxy, null,
                "Su banda de polvo parece un ala."));
            l.Add(new CardDef("remolino", "Remolino", BodyCategory.Galaxy, null,
                "Su vecina le esculpe los brazos."));
            l.Add(new CardDef("triangulo", "Triángulo", BodyCategory.Galaxy, null,
                "Diminuta y con regiones estelares gigantes."));
            l.Add(new CardDef("molinete", "Molinete", BodyCategory.Galaxy, null,
                "Más ancha que la Vía Láctea."));
            l.Add(new CardDef("centaurus-a", "Centaurus A", BodyCategory.Galaxy, null,
                "El anillo de polvo de una fusión."));

            return l;
        }
    }
}
