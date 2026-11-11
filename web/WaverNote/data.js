/* ============================================================
   WaverNote · catálogo ficticio del prototipo
   Todo el contenido (álbumes, artistas y pistas) es inventado
   para esta demo. La música se genera en vivo en audio-engine.js.
   ============================================================ */

const WN_ALBUMS = [
  {
    id: "mareas",
    title: "Mareas de Medianoche",
    artist: "Auralis",
    year: 2026,
    genre: "Ambient · Downtempo",
    description:
      "Cuatro piezas para bajarle el volumen al mundo. Pads tibios, bajos que respiran y el rumor del agua siempre al fondo.",
    palette: ["#0f6b78", "#06121f", "#6be8d2"],
    art: "ridge",
    tags: ["nocturno", "calma", "enfoque", "agua", "lento"],
    sonic: {
      bpm: 84,
      root: 57,
      key: "La menor",
      mood: "Calma nocturna",
      chords: [
        [0, 3, 7, 10],
        [-4, 0, 3, 7],
        [-2, 2, 5, 9],
        [0, 4, 7, 11],
      ],
      drums: true,
      clap: false,
      piano: false,
    },
  },
  {
    id: "coral",
    title: "Coral & Neón",
    artist: "Luma Tide",
    year: 2025,
    genre: "Synthwave · Chill",
    description:
      "Carretera, horizonte y sintetizadores cálidos. Un álbum para mirar cómo la ciudad se vuelve neón al caer la tarde.",
    palette: ["#ff6f5e", "#1a0e2b", "#8f7dff"],
    art: "rings",
    tags: ["atardecer", "neon", "carretera", "pop"],
    sonic: {
      bpm: 104,
      root: 50,
      key: "Re menor",
      mood: "Neón costero",
      chords: [
        [0, 3, 7, 10],
        [-4, 0, 3, 7],
        [-2, 2, 5, 9],
        [0, 4, 7, 11],
      ],
      drums: true,
      clap: true,
      piano: false,
    },
  },
  {
    id: "sal",
    title: "Bosque de Sal",
    artist: "Kaia Nera",
    year: 2024,
    genre: "Neo-soul · Trip hop",
    description:
      "Ritmos que arrastran los pies y una voz que parece venir de otra habitación. Orgánico, terroso y con luz de tarde.",
    palette: ["#3f7255", "#0a130f", "#d8b26b"],
    art: "dunes",
    tags: ["atardecer", "organico", "lluvia", "calma"],
    sonic: {
      bpm: 92,
      root: 53,
      key: "Fa mayor",
      mood: "Verde profundo",
      chords: [
        [0, 4, 7, 11],
        [-3, 0, 4, 7],
        [-5, -1, 2, 7],
        [0, 4, 7, 14],
      ],
      drums: true,
      clap: true,
      piano: false,
    },
  },
  {
    id: "islas",
    title: "Islas Flotantes",
    artist: "Noa Fern",
    year: 2026,
    genre: "Indie · Dream pop",
    description:
      "Guitarras que flotan, coros que se disuelven y la sensación de estar arriba de todo, sin apuro por volver.",
    palette: ["#7ba7ff", "#121731", "#d7a8ff"],
    art: "orb",
    tags: ["pop", "deriva", "agua", "enfoque"],
    sonic: {
      bpm: 96,
      root: 60,
      key: "Do mayor",
      mood: "Deriva pop",
      chords: [
        [0, 4, 7, 11],
        [-2, 2, 5, 9],
        [-4, 0, 3, 7],
        [0, 4, 7, 11],
      ],
      drums: true,
      clap: false,
      piano: false,
    },
  },
  {
    id: "bajo",
    title: "Ciudad Sumergida",
    artist: "Bajo Cero",
    year: 2023,
    genre: "Lo-fi · Jazz",
    description:
      "Beats polvorientos, vinilo y luces de calle reflejadas en el asfalto. La banda sonora de volver a casa tarde.",
    palette: ["#c98545", "#121018", "#ffd27a"],
    art: "grid",
    tags: ["nocturno", "enfoque", "lluvia", "ciudad", "lofi"],
    sonic: {
      bpm: 78,
      root: 55,
      key: "Sol menor",
      mood: "Ciudad dormida",
      chords: [
        [0, 3, 7, 10],
        [-2, 2, 5, 9],
        [-4, 0, 4, 7],
        [0, 3, 7, 14],
      ],
      drums: true,
      clap: true,
      piano: true,
    },
  },
  {
    id: "viento",
    title: "Viento de Vidrio",
    artist: "Sable Norte",
    year: 2025,
    genre: "Cinemático · Piano",
    description:
      "Piano, cuerdas y espacio. Música para paisajes anchos: costas de invierno, ventanas empañadas y amaneceres lentos.",
    palette: ["#93b3c7", "#080f18", "#e8f4ff"],
    art: "bloom",
    tags: ["calma", "cinematico", "invierno", "enfoque"],
    sonic: {
      bpm: 68,
      root: 52,
      key: "Mi menor",
      mood: "Cristal y viento",
      chords: [
        [0, 3, 7, 10],
        [-2, 2, 5, 9],
        [0, 4, 7, 11],
        [-4, 0, 3, 7],
      ],
      drums: false,
      clap: false,
      piano: true,
    },
  },
];

const WN_TRACKS = [
  // Mareas de Medianoche
  { id: "mareas-1", albumId: "mareas", title: "Marea baja", duration: 214, plays: "2.4M" },
  { id: "mareas-2", albumId: "mareas", title: "Faros dormidos", duration: 252, plays: "1.1M" },
  { id: "mareas-3", albumId: "mareas", title: "Sal en el aire", duration: 182, plays: "864K" },
  { id: "mareas-4", albumId: "mareas", title: "Medianoche azul", duration: 308, plays: "3.8M" },

  // Coral & Neón
  { id: "coral-1", albumId: "coral", title: "Coral neón", duration: 204, plays: "4.1M" },
  { id: "coral-2", albumId: "coral", title: "Autopista costera", duration: 242, plays: "2.7M" },
  { id: "coral-3", albumId: "coral", title: "Reflejo líquido", duration: 218, plays: "1.9M" },
  { id: "coral-4", albumId: "coral", title: "Última ola", duration: 266, plays: "5.2M" },

  // Bosque de Sal
  { id: "sal-1", albumId: "sal", title: "Raíces de sal", duration: 228, plays: "980K" },
  { id: "sal-2", albumId: "sal", title: "Musgo y oro", duration: 255, plays: "1.4M" },
  { id: "sal-3", albumId: "sal", title: "Nadie en el claro", duration: 192, plays: "742K" },
  { id: "sal-4", albumId: "sal", title: "Verdad verde", duration: 284, plays: "1.2M" },

  // Islas Flotantes
  { id: "islas-1", albumId: "islas", title: "Gravedad suave", duration: 199, plays: "3.1M" },
  { id: "islas-2", albumId: "islas", title: "Islas flotantes", duration: 273, plays: "4.6M" },
  { id: "islas-3", albumId: "islas", title: "Pluma de agua", duration: 185, plays: "1.7M" },
  { id: "islas-4", albumId: "islas", title: "Aquí arriba", duration: 240, plays: "2.2M" },

  // Ciudad Sumergida
  { id: "bajo-1", albumId: "bajo", title: "Azotea 3AM", duration: 178, plays: "2.9M" },
  { id: "bajo-2", albumId: "bajo", title: "Metro fantasma", duration: 222, plays: "1.5M" },
  { id: "bajo-3", albumId: "bajo", title: "Té de jazmín", duration: 201, plays: "1.8M" },
  { id: "bajo-4", albumId: "bajo", title: "Luces en el asfalto", duration: 250, plays: "2.1M" },

  // Viento de Vidrio
  { id: "viento-1", albumId: "viento", title: "Cristal", duration: 166, plays: "1.3M" },
  { id: "viento-2", albumId: "viento", title: "Viento de vidrio", duration: 298, plays: "2.6M" },
  { id: "viento-3", albumId: "viento", title: "Nieve en la costa", duration: 236, plays: "944K" },
  { id: "viento-4", albumId: "viento", title: "Amanecer en la deriva", duration: 324, plays: "1.6M" },
];

const WN_PLAYLISTS = [
  {
    id: "marea-lenta",
    name: "Marea lenta",
    description: "Para bajar el ritmo después de un día largo. Poco a poco, como el agua.",
    palette: ["#0f6b78", "#081420", "#8ce8d8"],
    art: "ridge",
    tags: ["calma", "nocturno"],
    tracks: ["mareas-2", "islas-3", "viento-2", "sal-3", "mareas-4", "viento-3"],
  },
  {
    id: "concentracion",
    name: "Concentración · Olas",
    description: "Texturas suaves y ritmo estable para trabajar sin que la música pida atención.",
    palette: ["#3c6f7a", "#0a141c", "#b8f3e7"],
    art: "orb",
    tags: ["enfoque", "calma"],
    tracks: ["bajo-1", "mareas-1", "bajo-3", "viento-1", "mareas-3", "viento-4", "bajo-2"],
  },
  {
    id: "atardecer-muelle",
    name: "Atardecer en el muelle",
    description: "Luz cálida, brisa y ganas de quedarse un rato más mirando el horizonte.",
    palette: ["#d5744d", "#1e1020", "#ffc98a"],
    art: "rings",
    tags: ["atardecer", "pop"],
    tracks: ["coral-4", "sal-2", "islas-2", "coral-2", "sal-4"],
  },
  {
    id: "ruta-nocturna",
    name: "Ruta nocturna",
    description: "Para conducir con la ciudad dormida y las ventanillas apenas abiertas.",
    palette: ["#5d7cff", "#0a0f22", "#ff9b8a"],
    art: "grid",
    tags: ["nocturno", "neon", "ciudad"],
    tracks: ["bajo-4", "coral-1", "islas-1", "bajo-2", "coral-3", "sal-1"],
  },
];

/* Sesión curada de la portada */
const WN_HOME_SESSION = [
  "mareas-4",
  "coral-4",
  "islas-2",
  "bajo-1",
  "viento-2",
  "mareas-2",
  "coral-2",
  "bajo-4",
];

const WN_FEATURED_ALBUM = "mareas";
const WN_FEATURED_TRACK = "mareas-4";

const WN_DEFAULT_LIKED = ["mareas-2", "coral-1", "islas-2", "viento-1"];

const WN_MOODS = [
  { label: "Nocturno", query: "nocturno" },
  { label: "Enfoque", query: "enfoque" },
  { label: "Atardecer", query: "atardecer" },
  { label: "Agua", query: "agua" },
  { label: "Neón", query: "neon" },
  { label: "Lluvia", query: "lluvia" },
];
