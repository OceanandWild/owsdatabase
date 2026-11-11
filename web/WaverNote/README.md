# WaverNote

Prototipo de reproductor de música con estética oceánica, construido con HTML, CSS y JavaScript sin dependencias ni paso de compilación.

## Cómo abrirlo

Abrí `index.html` en un navegador moderno (Chrome, Edge o Firefox). No hace falta instalar nada.

También podés servirlo localmente:

```bash
npx http-server . -p 5500
```

Y entrar a `http://localhost:5500`.

## Qué incluye

- **Descubrir:** portada con álbum del día, sesión sugerida, álbumes y playlists.
- **Buscar:** por canción, álbum, artista o mood, con resaltado de coincidencias.
- **Biblioteca:** me gusta, escuchado recientemente, álbumes y playlists.
- **Detalle de álbum y playlist:** listado de pistas, reproducción y aleatorio.
- **Reproductor persistente:** play/pausa, anterior/siguiente, barra de progreso, volumen, silencio, aleatorio y repetición.
- **Cola:** panel de “Ahora suena” con visualizador y pistas a continuación.
- **Responsive:** barra lateral en escritorio, navegación inferior en móvil y panel deslizable.

## Audio

Las pistas son ficticias y se sintetizan en vivo con la Web Audio API: pads, bajos, arpegios y percusión generados por código. No hay archivos de audio ni se descarga música. Si el navegador no permite iniciar el audio, el reproductor sigue avanzando en modo visual.

El estado local (me gusta, volumen y escuchado recientemente) se guarda en `localStorage`.

## Atajos de teclado

| Tecla | Acción |
| --- | --- |
| `Espacio` | Reproducir / pausar |
| `←` / `→` | Retroceder / avanzar 5 segundos |
| `L` | Me gusta de la pista actual |
| `M` | Silenciar / activar sonido |
| `/` | Ir a buscar |
| `Esc` | Cerrar el panel o salir de la búsqueda |

## Estructura

```
index.html        Estructura y sprite de iconos
styles.css        Base visual, layout y componentes generales
library.css       Listas, detalles, búsqueda y biblioteca
player.css        Reproductor, panel lateral y responsive
data.js           Catálogo ficticio de álbumes, pistas y playlists
audio-engine.js   Síntesis y reproducción con Web Audio API
core.js           Utilidades, estado y navegación
views.js          Render de las pantallas
player.js         Transporte, cola y visualizador
app.js            Eventos y arranque
```

WaverNote es un prototipo de producto: el catálogo, los artistas y las portadas son inventados.
