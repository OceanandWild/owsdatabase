# WaverNote

Biblioteca musical personal: subís tus propios archivos y los escuchás desde cualquier navegador con tu cuenta Surface. Sin catálogos de ejemplo ni audio generado, la biblioteca arranca vacía.

El frontend es HTML, CSS y JavaScript sin frameworks ni paso de compilación. El backend vive en el `server.js` de OWS y se apoya en PostgreSQL + Cloudinary.

## Cómo abrirlo

Podés abrir `index.html` directamente o servirlo en local:

```bash
npx http-server . -p 5500
```

Y entrar a `http://localhost:5500`. La app apunta a `https://owsdatabase.onrender.com`.

Para usar otro backend:

- `?api=https://mi-servidor` en la URL, o
- `localStorage.wavernote_api_base = "https://mi-servidor"`.

## Cuenta

El acceso usa la misma cuenta que Surface / Ocean Pay:

- `POST /surface/login`
- `POST /surface/register`
- `GET /surface/me`

El token queda en `ocean_pay_token` y el usuario en `ocean_pay_user`, así que la sesión se comparte con el resto del ecosistema OWS en el mismo navegador.

## Qué incluye

- **Inicio:** saludo, última subida y un estado inicial que invita a cargar música.
- **Buscar:** por título, artista, álbum o género dentro de tu biblioteca.
- **Tendencias:** una canción por categoría —la más escuchada, el artista del momento, la reina de la noche y más— con el motivo y un ícono de fuego en la portada.
- **Recomendaciones:** mezcla diaria con motivos, secciones por artista, novedades, canciones sin escuchar y “Vuelve a escuchar”.
- **Biblioteca:** canciones, álbumes, playlists y favoritos.
- **Detalle de álbum y playlist:** listado de pistas, reproducción, aleatorio y cola.
- **Reproductor persistente:** play/pausa, anterior/siguiente, progreso, volumen, aleatorio y repetición.
- **Cola:** panel de “Ahora suena” con visualizador sobre el audio real.
- **Subida:** modo manual con archivo, metadatos y miniatura; modo automático que escanea tu carpeta Música, lee etiquetas y portadas, y te muestra qué quiere agregar.
- **Responsive:** barra lateral en escritorio, navegación inferior en móvil y paneles deslizables.

## Tendencias

La sección **Tendencias** muestra patrones personales de escucha. No es un ranking largo: cada categoría elige **una sola canción**, la que mejor representa ese patrón, y explica por qué está ahí. En la portada de cada elegida aparece un ícono de fuego.

Categorías:

| Categoría | Qué premia |
| --- | --- |
| La más escuchada | La canción con más reproducciones acumuladas |
| Artista del momento | El artista con más reproducciones; muestra su canción más escuchada |
| El álbum que no soltás | El álbum con más reproducciones |
| El género que domina | El género con más reproducciones |
| En llamas esta semana | La canción más repetida en los últimos 7 días |
| La reina de la noche | La más escuchada entre las 22:00 y las 06:00 |
| La favorita del finde | La más escuchada sábados y domingos |
| La de un solo día | La mayor cantidad de reproducciones de una canción en un mismo día |
| Racha encendida | La seguidilla más larga de una misma canción (con menos de 20 minutos entre plays) |
| La consentida | La canción marcada con corazón que más escuchaste |
| La revelación | La canción subida en los últimos 30 días que más escuchaste |

Las categorías de artista, álbum, género y tiempo necesitan al menos dos reproducciones para encenderse; la racha pide tres. Si no hay datos suficientes, la página lo explica en lugar de inventar tendencias.

## Recomendaciones

La sección **Recomendaciones** arma sola una selección para el día con lo que hay en tu biblioteca. Cambia a diario y se vuelve más precisa a medida que escuchás y agregás música.

Cómo puntúa cada canción:

- **Afinidad de artista:** los artistas que más reproducciones acumulan pesan más.
- **Favoritos:** las canciones marcadas con corazón suman.
- **Reproducciones:** lo que ya escuchaste vuelve a aparecer, con menos peso que una novedad.
- **Novedad:** lo agregado en los últimos días recibe un empujón.
- **Pendientes:** las canciones sin ninguna reproducción tienen prioridad en la sección de descubrimiento.
- **Variación diaria:** un desempate estable por día y usuario cambia el orden sin volverse aleatorio entre recargas.

Secciones fijas:

| Sección | Qué muestra |
| --- | --- |
| Mezcla del día | Hasta 8 canciones con el motivo de cada elección |
| Porque escuchaste a… | Tu artista con más reproducciones, o el de más presencia si todavía no hay historial |
| Recién agregadas | Lo último que sumaste a la biblioteca |
| Todavía no las escuchaste | Canciones que siguen esperando su primera reproducción |
| Vuelve a escuchar | Las menos escuchadas entre las que ya llevan al menos un día en la biblioteca |

“Vuelve a escuchar” aparece solo cuando hay candidatas; si no las hay, la página explica qué falta. En bibliotecas grandes las secciones no repiten canciones de la mezcla; en bibliotecas chicas se permite el solapamiento para que la página no quede vacía.

### Dónde se guardan las reproducciones

El conteo se guarda por usuario en `localStorage`, bajo `wavernote.plays.v2.<userId>`, con `{ count, firstPlayedAt, lastPlayedAt, events }`. `events` es una lista de marcas de tiempo (epoch en milisegundos) con las últimas 80 reproducciones de esa canción: permite calcular tendencias por semana, horario, día y racha sin tocar el historial agregado. Se suma una reproducción cuando el audio arranca de verdad, no al pausar o reanudar. Al cargar la biblioteca se descartan los registros de canciones que ya no existen. No requiere backend: viaja con el navegador, igual que el historial reciente.

## Subir música

Al abrir la subida podés elegir entre dos modos:

- **Manual:** elegís uno o varios archivos, escribís título, artista, álbum y género, y agregás una miniatura. Los metadatos que completás se aplican a lo que subas.
- **Automático:** la app pide permiso para escanear la carpeta Música y lee los archivos de audio que encuentre. Detecta título, artista, álbum, género, duración y portada embebida, y después te muestra la lista para que marques cuáles querés agregar a tu biblioteca. Las canciones que ya tenés aparecen marcadas y no se seleccionan.

El permiso se pide siempre al entrar en modo automático, aunque el sistema indique que no hace falta o ya lo hayas dado antes. Si el dispositivo muestra su propio aviso de «Permitir», se responde una sola vez y no vuelve a aparecer.

- Formatos: MP3, WAV, OGG, M4A, AAC, FLAC, OPUS y WEBM.
- Límite: 50 MB por archivo.
- En manual, el título sale del nombre del archivo si lo dejás vacío. Si el nombre tiene la forma `Artista - Título`, se separa solo.
- En automático, las etiquetas del archivo tienen prioridad sobre el nombre; si no hay etiquetas, se usa el nombre.
- El audio se guarda en Cloudinary (`resource_type: "video"`, que incluye audio) y los metadatos, favoritos y playlists en PostgreSQL, siempre asociados a tu usuario.

## API

| Método | Ruta | Descripción |
| --- | --- | --- |
| `GET` | `/wavernote/health` | Estado del servicio |
| `GET` | `/wavernote/library` | Canciones, playlists y favoritos del usuario |
| `POST` | `/wavernote/tracks` | Subir audio (`multipart/form-data`: `audio`, `cover`, `artist`, `album`, `genre`, `duration`) |
| `PATCH` | `/wavernote/tracks/:id` | Editar título, artista, álbum o género |
| `DELETE` | `/wavernote/tracks/:id` | Eliminar canción y sus archivos |
| `POST` | `/wavernote/tracks/:id/like` | Marcar favorito |
| `DELETE` | `/wavernote/tracks/:id/like` | Quitar favorito |
| `POST` | `/wavernote/playlists` | Crear playlist |
| `PATCH` | `/wavernote/playlists/:id` | Editar playlist |
| `DELETE` | `/wavernote/playlists/:id` | Eliminar playlist |
| `POST` | `/wavernote/playlists/:id/tracks` | Agregar canción (`trackId`) |
| `DELETE` | `/wavernote/playlists/:id/tracks/:trackId` | Quitar canción |

Todas las rutas de `/wavernote` salvo `health` requieren `Authorization: Bearer <token>`.

## Atajos de teclado

| Tecla | Acción |
| --- | --- |
| `Espacio` | Reproducir / pausar |
| `←` / `→` | Retroceder / avanzar 5 segundos |
| `L` | Favorito de la canción actual |
| `M` | Silenciar / activar sonido |
| `U` | Abrir la subida |
| `/` o `Ctrl/Cmd + K` | Ir a buscar |
| `Esc` | Cerrar modales, panel o salir de la búsqueda |

## Estructura

```
index.html        Estructura, acceso y sprite de iconos
styles.css        Base visual, layout y componentes generales
library.css       Listas, detalles, búsqueda y biblioteca
player.css        Reproductor, panel lateral y responsive
recommend.css     Mezcla del día, tarjetas y “Vuelve a escuchar”
trends.css        Tendencias, tarjetas con fuego y franja del inicio
app.css           Acceso, formularios, modales y subidas
audio-engine.js   Motor de audio real con <audio> + Web Audio
core.js           Sesión Surface, API, estado y navegación
metadata.js       Lectura de etiquetas y portadas de archivos locales
recommend.js      Motor de recomendaciones diario
trends.js         Motor de tendencias por categoría
views.js          Render de las pantallas
player.js         Transporte, cola, Media Session y visualizador
app.js            Eventos, subidas, playlists y arranque
```

El volumen, el historial reciente y las reproducciones de cada usuario se guardan en `localStorage`; la biblioteca real vive en el servidor.
