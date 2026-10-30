# Arte de Halloween — Paneles del topbar (NIVEL · XP · DULCES)

Estado: **INTEGRADO** (arte generado, procesado e instalado el 2026-10-16).

Reemplazan los contenedores de los 3 paneles del topbar del Pase de Halloween
(`NIVEL` · `XP DE LA VELADA` · `DULCES DE LA VELADA`). El chip de estado
(`PRÓXIMAMENTE` / `¡ACTIVO!` / `TERMINADO`) **no** lleva sprite: sigue siendo
una píldora USS. El medallón del icono (círculo izquierdo) y los textos se
pintan encima de la placa, que es un marco vacío con el interior limpio.

| Panel | Acento | PNG integrado |
|---|---|---|
| `NIVEL 0 · 0/30 niveles` | dorado hueso (castillo, luna) | `chip_nivel.png` |
| `0 / 1.800 XP · XP DE LA VELADA` | violeta arcano (estrellas) | `chip_xp.png` |
| `0 · DULCES DE LA VELADA` | carmesí caramelo (confite, goterones) | `chip_dulces.png` |

## Piezas finales

Canvas **uniforme para las tres: 374×180 px** (2× del tamaño de uso). Las
generaciones salieron con proporción real ≈2,08:1, así que se normalizó a ese
canvas en lugar de forzar 420×148 (habría estirado ~33% lo ancho). PNG con
alfa real.

| Slot | Archivo | Tamaño | Destino |
|---|---|---|---|
| chip_nivel | `chip_nivel.png` | 374×180 | `Assets/Resources/UI/Halloween/` |
| chip_xp | `chip_xp.png` | 374×180 | idem |
| chip_dulces | `chip_dulces.png` | 374×180 | idem |

Generaciones de origen: 3 JPG de 1376×768 con fondo negro puro
(`Chips - Halloween/` en Descargas).

Procesado (reproducible con `Wilder Gambit/Tools/build_halloween_chips.py`):
flood-fill del negro exterior desde los bordes (semilla estricta + crecimiento
acotado sobre el halo del JPEG), defringe de 1 px + desenfoque leve, recorte al
marco y resize LANCZOS al canvas uniforme. El script deja además un preview a
tamaño real junto a los PNG.

## Integración (hecha)

1. **Importación**: `ProgressSpriteImport` cubre ahora
   `Assets/Resources/UI/Halloween/` (Sprite, Single, Full Rect, sin compresión)
   con menú `Wilder Gambit > Reimportar sprites de HALLOWEEN`.
2. **Cableado en el topbar** (dos capas, mismo camino que el banner):
   - `MainMenu.uxml`: los tres chips llevan nombre propio (`hw-chip-nivel`,
     `hw-chip-xp`, `hw-chip-dulces`).
   - `MainMenu.uss`: quita borde, radio y fondo de esos chips, deja
     `min-height: 78px` y conecta las URLs `project://database/...` de respaldo.
   - `HalloweenSprites.cs` (patrón `ProgressSprites`): aplica la placa con
     **9-slice de esquinas fijas** — slice 88×46 px del sprite, escala 0.5 — así
     la filigrana no se deforma cuando el chip crece con cifras más largas
     («1.800 / 1.800 XP»). Se aplica al inicializar el menú, junto al banner y
     el título de la velada.
3. **Orden y reparto**: los chips mantienen el orden NIVEL → XP → DULCES y se
   reparten a lo ancho con `space-between`; el chip de estado cierra la fila.

Para reencuadrar el ornato: `SliceX` / `SliceY` / `SliceScale` en
`HalloweenSprites.cs`, o regenerar con `CANVAS_H` del script de procesado. El
chip de estado no se toca.

---

## Prompts usados (registro)

Los tres prompts que se usaron para generar el arte, con el canvas pedido
(420×148; la herramienta entregó su propio encuadre, normalizado luego a
374×180).

### 1. `chip_nivel.png` — panel NIVEL (acento dorado hueso)

```
Fantasy game UI stat panel frame, wide rounded-rectangle plate, 420 by 148,
ornate halloween gothic border in pale bone-gold, intricate filigree
scrollwork in all four corners with tiny crescent-moon and candle-flame
motifs, double rim with a bright highlight line and a dark bronze shadow
line, deep eggplant-purple interior with a smooth vertical gradient,
completely empty clean interior, luxurious spooky metalwork, gothic
halloween chess fantasy aesthetic, interior colors #130B21 to #1C1030,
frame colors #E8C46A #B08A2E #6B4E1F, flat frontal 2D illustration, single
centered object, uniform flat pure black background for easy background
removal, no shadow, no perspective, no 3D, no text, no letters, no numbers,
no logo, no watermark, high detail ornamental metalwork
```

### 2. `chip_xp.png` — panel XP (acento violeta arcano)

```
Fantasy game UI stat panel frame, wide rounded-rectangle plate, 420 by 148,
ornate arcane border in cold silver-violet, intricate filigree scrollwork in
all four corners with tiny five-pointed stars and a small crescent moon
motif, double rim with a bright highlight line and a dark shadow line, deep
eggplant-purple interior with a smooth vertical gradient, completely empty
clean interior, mystical and luminous, gothic halloween chess fantasy
aesthetic, interior colors #130B21 to #1C1030, frame colors #C9B4FF #7E5CBF
#42306E, flat frontal 2D illustration, single centered object, uniform flat
pure black background for easy background removal, no shadow, no
perspective, no 3D, no text, no letters, no numbers, no logo, no watermark,
high detail ornamental metalwork
```

### 3. `chip_dulces.png` — panel DULCES (acento carmesí caramelo)

```
Fantasy game UI stat panel frame, wide rounded-rectangle plate, 420 by 148,
ornate halloween border in crimson and caramel, intricate filigree
scrollwork in all four corners with tiny candy-corn and dripping-caramel
motifs and thin thorn vines, double rim with a bright highlight line and a
dark shadow line, deep eggplant-purple interior with a smooth vertical
gradient, completely empty clean interior, sweetly sinister metalwork,
gothic halloween chess fantasy aesthetic, interior colors #130B21 to
#201024, frame colors #E07A4F #A3362A #5F1D16, flat frontal 2D illustration,
single centered object, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

## Negative prompt (si la herramienta lo soporta)

```
text, letters, numbers, watermark, signature, background scenery, floor,
cast shadow, perspective, 3D, blurry, lowres, duplicated frames, multiple
objects, cropped, oversaturated
```

## Herramientas compatibles

- **DALL·E / GPT Image / Firefly / Midjourney / Stable Diffusion**: el prompt
  es autocontenido (no requiere imagen de referencia). Generar las 3 variantes
  seguidas para que compartan estilo; si la herramienta mantiene contexto
  entre imágenes, pedir «same frame as before, swap accent color and motifs».
- Si alguna vez se regeneran: dejarlas como JPG en una carpeta y correr
  `python Wilder Gambit/Tools/build_halloween_chips.py` ajustando `SRC`
  (el script recorta, limpia el fondo y normaliza el canvas por su cuenta).

---

# Piezas de la velada (skins + variante)

Estado: **INTEGRADO** (generado, procesado e instalado el 2026-10-16).

Los cinco reskins se generaron con la fórmula común de reescultura: bloque de
**bloqueo de forma** (la referencia es solo silueta: superpuestas, ambas
imágenes coincidirían perfectamente; no se agregan ni quitan partes — solo
cambia el material), bloque de **tema/material** con paleta hex y glow en
superficie (sin partículas flotantes: el juego añade su animación encima), y
cola técnica (frontal 2D, fondo blanco puro, sin sombra/perspectiva/texto).
Los prompts completos se entregaron en el chat de trabajo.

| Objeto | Id | Material / paleta | Animación | Rareza | Salida |
|---|---|---|---|---|---|
| Peón de Brasa | `skin_pawn_halloween` | piedra + vetas de brasa `#FF8538` | Embers | POCO COMÚN | `Resources/Skins/skin_pawn_halloween.png` |
| Torre de Musgo | `skin_rook_halloween` | piedra con musgo y grietas encendidas (0.48, 0.72, 0.34) | Embers | RARA | `Resources/Skins/skin_rook_halloween.png` |
| Reina Agrietada | `skin_queen_halloween` | roca erosionada + luz lunar (0.78, 0.55, 0.95) | Spectral | ÉPICA | `Resources/Skins/skin_queen_halloween.png` |
| Rey Esqueleto | `skin_king_halloween` | hueso antiguo (0.88, 0.85, 0.70) + fulgor espectral | Spectral | RARA | `Resources/Skins/skin_king_halloween.png` |
| Reina Vampira | `vampira` | obsidiana `#1A1018`–`#2A1420` + rubí `#8E0F26`/`#FF3B54` | — (variante) | — | `StreamingAssets/Pieces/White/VampireQueen.png` |

Canvas: **917×512** las skins (encuadre de la familia, reproducido de la skin
de referencia de cada tipo); **1065×810** la variante (encuadre de la Dama
Jinete). Fuente: `Variantes y Skins - Halloween/` en Descargas (JPG con fondo
blanco). Procesado reproducible con
`python Wilder Gambit/Tools/build_halloween_sprites.py` (flood-fill del blanco
+ defringe + desmezcla del halo + normalización), con previews en
`_procesados/` junto a los JPG de origen.

---

# Tableros y fondo del menú — estado de integración

Estado (2026-10-16): los **dos tableros y el fondo del menú quedaron
integrados** con el arte generado a partir de estos prompts (originales
archivados en `_art-source/Halloween/`).

| Objeto | Id | Archivo | Estado |
|---|---|---|---|
| Tablero Luna Llena | `halloween_moon` | `Assets/StreamingAssets/Board/bg_halloween_moon.jpeg` | INTEGRADO |
| Tablero Luna de Sangre | `halloween_blood` | `Assets/StreamingAssets/Board/bg_halloween_blood.jpeg` | INTEGRADO |
| Tablero Luna Llena — objeto v2 | `halloween_moon` | `Assets/StreamingAssets/Board/bg_halloween_moon_board.png` | INTEGRADO |
| Tablero Luna de Sangre — objeto v2 | `halloween_blood` | `Assets/StreamingAssets/Board/bg_halloween_blood_board.png` | INTEGRADO |
| Fondo Noche de Brujas | `halloween_night` | `Assets/StreamingAssets/Backdrop/backdrop_halloween_night.jpg` | INTEGRADO |

Sin cambios de código: los managers levantan el archivo por nombre (`.jpg`,
`.jpeg` o `.png`). El tablero se dibuja **detrás de las piezas** cubriendo la
pantalla; el fondo del menú va con `cover` + parallax.

**Nota (misma noche, línea v2):** además de esa capa ambiente, los tableros se
generaron como **objeto 8×8 aislado sobre negro** (prompts v2, más abajo) para
recortar y colocar en la partida. Ya están recortados con alfa, medidos y
normalizados — ver «Procesado de la generación v2» — y **colocados** en la
partida y en las tarjetas (ver «Colocación en partida (hecho)»).

**Lección del 16/10 (primera generación):** pedir «chess board background»
con la luna sobre un horizonte devolvió tableros de ajedrez literales y/o
escenas tipo fondo (cielo y horizonte). El tablero del juego es **solo la
capa de suelo/ambiente**: marco completo, sin cielo, sin horizonte, sin
tablero dibujado. Los prompts de abajo ya lo evitan (ni la palabra "chess").

**Actualización (misma noche):** la línea **v2** cambia el enfoque — el
tablero se genera como **objeto 8×8 sobre negro** para recortar (ver más
abajo); esa es la que rige ahora.

## Prompts v1 — tableros (capa ambiente; usados para los instalados)

Generar los dos en la misma sesión (el segundo hereda cámara y composición
del primero).

### 1. Luna Llena — `bg_halloween_moon.jpeg`

```
Dark fantasy game environment art, ambient ground layer only, wide 16:9
landscape that fills the entire frame edge to edge, high view looking
down with a very slight angle onto ancient worn stone flagstones at
midnight, smooth weathered slabs with thin moss in the joints, a few
dried autumn leaves caught in the cracks, cold silver-blue moonlight
raking across the floor from beyond the frame, long soft shadows of
bare twisted branches cast over the stones from the corners, a pale
dew film glinting faintly, soft ground mist pooling in the lowest
joints, empty quiet surface with nothing in the center, gothic
halloween fantasy aesthetic, palette: moonlight silver #CCD1E6, deep
indigo #1A1A38, dark slate #23233F, faint bone-gold candle glow at the
far edges #E8C46A, painterly semi-realistic illustration, cinematic
soft lighting, dark and low-contrast so small game pieces read clearly
on top, high detail toward the edges, soft vignette, 1376x768, do not
draw any playfield, chessboard, grid or checker pattern, no pieces, no
equipment, no sky, no horizon, no clouds, no moon drawn in a sky, no
distant landscape, no text, no letters, no numbers, no watermark, no
signature, no logo, no UI, no frame, no border, no people
```

### 2. Luna de Sangre — `bg_halloween_blood.jpeg`

```
Dark fantasy game environment art, ambient ground layer only, wide 16:9
landscape that fills the entire frame edge to edge, the same stone
terrace under a blood moon night, high view looking down with a very
slight angle onto ancient worn stone flagstones, smooth weathered
slabs cracked and stained with ash, dried blood-red leaves caught in
the cracks, embers glowing faintly deep in the joints, crimson mist
pooling low, deep red moonlight raking across the floor from beyond
the frame, long soft shadows of bare twisted branches cast over the
stones from the corners, empty quiet surface with nothing in the
center, sinister halloween fantasy aesthetic, palette: blood moon
#C74D47, deep crimson-black #290D12, wine red #8E0F26, faint ember
#FF3B54, painterly semi-realistic illustration, cinematic soft
lighting, dark and low-contrast so small game pieces read clearly on
top, high detail toward the edges, soft vignette, 1376x768, do not
draw any playfield, chessboard, grid or checker pattern, no pieces, no
equipment, no sky, no horizon, no clouds, no moon drawn in a sky, no
distant landscape, no text, no letters, no numbers, no watermark, no
signature, no logo, no UI, no frame, no border, no people
```

**Variante «luna visible sin volver al look de fondo»:** agregar «a still
shallow puddle between the stones reflecting a perfect round full moon
(blood moon), seen from above» y quitar «no moon drawn in a sky».

**Fallback si igual inventa horizonte:** pedir «top-down material study of
ancient stone floor tiles under cold moonlight, full-frame, no sky».

### Negative prompt (tableros)

```
chessboard, checkerboard, chess pieces, game board, playfield, game grid,
sky, horizon, clouds, distant landscape, mountains, buildings, people,
characters, text, letters, numbers, logo, watermark, signature, UI, HUD,
frame, border, cartoon, chibi, flat vector, oversaturated, blurry, lowres,
fisheye
```

## Prompts v2 — tablero como objeto sobre negro (para recorte)

Pedido del 16/10: «solo los tableros, sin fondos, solo fondo negro para
remover después». El tablero se genera como **pieza aislada**: la plataforma
completa dentro del encuadre, con margen negro en los cuatro lados, para
recortarla después con alfa (mismo camino que los chips: flood-fill del negro
+ defringe). Generar las dos en la misma sesión, como la v1.

Revisión (16/10): la primera pasada salió con volumen (plataforma 3D con
espesor y relieve, look maqueta) → estos prompts fuerzan **2D cenital
plano**: vista directa desde arriba, sin espesor ni perspectiva.

Revisión 2 (16/10): salió plano pero **sin grilla** («No es un tablero de
ajedrez») → ahora se pide **tablero cuadrado 8×8** con casillas alternadas de
piedra. Se quitaron de prompts y negativos las prohibiciones de «checkerboard
/ grid»: eran justo las que bloqueaban el patrón de ajedrez.

### 1. Luna Llena — objeto (2D cenital, 8×8)

```
Flat 2D halloween game art of a single isolated square stone chessboard,
seen directly from above (orthographic top-down view, 90 degrees), an
ancient 8x8 chessboard with exactly 8 columns and 8 rows of square tiles in
a perfect checkerboard pattern, alternating pale moonlit flagstones and deep
shadowed indigo flagstones, weathered cracked stone with thin moss in the
joints, a few dried autumn leaves caught in the cracks, an ornate carved
stone border painted flat around the whole board with small crescent-moon
motifs and a faint bone-gold candle glow at the corners, cold silver-blue
moonlight raking low across the surface, long soft shadows of bare twisted
branches cast over the tiles, thin low mist pooling in the joints, gothic
halloween fantasy aesthetic, palette: moonlight silver #CCD1E6, deep indigo
#1A1A38, dark slate #23233F, faint bone-gold #E8C46A, painterly
semi-realistic 2D illustration, flat painted look, completely flat: no
visible thickness, no side faces, no raised edges, no perspective, no
vanishing point, cinematic soft lighting, dark and low-contrast so small
game pieces read clearly on top, high detail, the entire board fully visible
and centered, complete clean silhouette against a uniform flat pure black
background with a margin of black on all four sides for easy background
removal, single centered object, no sky, no horizon, no clouds, no moon in a
sky, no distant landscape, no surrounding terrain, no trees, no buildings,
no fog banks, no floating debris, no cast shadow on the black background, no
chess pieces, no equipment, no text, no letters, no numbers, no coordinate
labels, no watermark, no signature, no logo, no UI, no decorative frame
around the image, no people
```

### 2. Luna de Sangre — objeto (2D cenital, 8×8)

```
Flat 2D halloween game art of a single isolated square stone chessboard
under a blood moon night, seen directly from above (orthographic top-down
view, 90 degrees), an ancient 8x8 chessboard with exactly 8 columns and 8
rows of square tiles in a perfect checkerboard pattern, alternating pale
ash-grey flagstones and dark blood-stained crimson-black flagstones,
weathered cracked stone with embers glowing faintly deep in the joints and
crimson mist pooling low, dried blood-red leaves caught in the cracks, an
ornate carved stone border painted flat around the whole board with small
thorn and crescent motifs and a faint ember glow at the corners, deep red
moonlight raking low across the surface, long soft shadows of bare twisted
branches cast over the tiles, sinister halloween fantasy aesthetic, palette:
blood moon #C74D47, deep crimson-black #290D12, wine red #8E0F26, faint
ember #FF3B54, painterly semi-realistic 2D illustration, flat painted look,
completely flat: no visible thickness, no side faces, no raised edges, no
perspective, no vanishing point, cinematic soft lighting, dark and
low-contrast so small game pieces read clearly on top, high detail, the
entire board fully visible and centered, complete clean silhouette against a
uniform flat pure black background with a margin of black on all four sides
for easy background removal, single centered object, no sky, no horizon, no
clouds, no moon in a sky, no distant landscape, no surrounding terrain, no
trees, no buildings, no fog banks, no floating debris, no cast shadow on the
black background, no chess pieces, no equipment, no text, no letters, no
numbers, no coordinate labels, no watermark, no signature, no logo, no UI,
no decorative frame around the image, no people
```

### Negative prompt (objeto)

```
3D, 3D render, isometric, miniature, diorama, perspective, vanishing point,
visible thickness, side faces, raised edges, side walls, drop shadow, chess
pieces, sky, horizon, clouds, distant landscape, mountains, trees, buildings,
surrounding terrain, background scenery, characters, people, text, letters,
numbers, coordinate labels, logo, watermark, signature, UI, HUD, decorative
frame around the image, cartoon, chibi, flat vector, oversaturated, blurry,
lowres, fisheye
```

Variantes rápidas: luna reflejada (agregar «a still shallow puddle between
the stones reflecting a perfect round full moon, seen from above» y quitar
«no moon in a sky»); borde más decorado (agregar «tiny carved
jack-o'-lanterns and small lit candles resting on the rim corners»).

Fallback si igual sale con volumen: cambiar la primera línea por «Top-down
flat material study of ancient stone game tiles, orthographic view, no 3D».

### Procesado de la generación v2 (hecho)

Recibidas la noche del 16/10 (dos JPG de 1376×768 con fondo negro puro,
`Tableros de halloween/` en Descargas). Reproducible con
`python Wilder Gambit/Tools/build_halloween_boards.py`:

1. Flood-fill del negro + defringe (mismo criterio que los chips) y recorte al
   objeto: **Luna Llena 693×694** · **Luna de Sangre 730×729**.
2. Medición de la grilla 8×8 pintada (regla graduada + perfiles de luminancia;
   overlays `cand_*` / `medicion_*` en la carpeta de origen) y recomposición a
   canvas cuadrado con la grilla **centrada al 83 % del lienzo** — constante
   única para ambos tableros, con ~1 % de margen exterior:

| Tablero | PNG con alfa | Lienzo | Grilla pintada |
|---|---|---|---|
| Luna Llena | `halloween_moon_board_v2.png` | 706×706 | 585 px (83 %) |
| Luna de Sangre | `halloween_blood_board_v2.png` | 748×748 | 620 px (83 %) |

3. Originales archivados en `_art-source/Halloween/`; PNG en
   `_art-source/Halloween/procesados/` con copia en la carpeta de origen.
   Preview lado a lado: `preview_tableros_v2.png`.

Ese 83 % es lo que después permite alinear el arte pintado a las casillas del
juego con un solo número. La colocación en la partida ya está hecha (ver la
sección siguiente).

### Colocación en partida (hecho)

Integrada el 17/10 sobre la capa ambiente v1 (que se mantiene detrás, con
`cover`: el borde del objeto no cubre 16:9 por sí solo). Los PNG v2 viven en
`Assets/StreamingAssets/Board/bg_halloween_{moon,blood}_board.png` y
`BoardView` los dibuja como **objeto alineado a las 8×8** cuando el tema
elegido es Luna Llena / Luna de Sangre:

- **Capas de dibujo:** ambiente v1 (orden −2) → objeto v2 (orden −1) →
  casillas (0, ahora transparentes: el patrón visible es el arte) → sombras,
  piezas e indicadores (1+). Colliders e indicadores de casilla no cambian.
- **Escala:** la grilla pintada (83 % del lienzo) mide exactamente
  `8 × tileSize`; `BoardBackgroundManager.BoardArtInnerFraction` es la
  constante compartida con `Tools/build_halloween_boards.py`.
- **Cámara:** el encuadre abre lo justo para que entre el borde ornamental
  completo (~10 % extra por lado); el fondo ambiente se re-escala solo.
- **Tarjetas:** pase de Halloween, pase de temporada, tienda e inventario
  muestran el objeto (`LoadThumbnailForIndex` lo prefiere; la tienda lo
  escala completo para no recortar el marco).
- **Exclusividad:** los dos tableros son exclusivos del Pase de Halloween:
  la tienda no los lista (no se pueden comprar) y el inventario los agrupa en
  su sección de evento hasta reclamar la recompensa.

## Prompt vigente — Fondo Noche de Brujas (menú)

Este asset sí es un fondo: cielo, luna y paisaje son correctos. Generación
integrada el 2026-10-16 (`backdrop_halloween_night.jpg`, 2752×1536, original
en `_art-source/Halloween/`).

```
Dark fantasy Halloween night landscape, video game main menu backdrop,
wide cinematic 16:9, a witch's cottage hidden deep in a haunted forest
clearing, painterly gothic illustration, crooked thatched cottage with
a lopsided chimney, warm amber light glowing from its crooked windows,
carved jack-o'-lanterns with flickering candle flames lining a winding
dirt path, old crooked wooden fence, twisted leafless oaks framing
both sides of the frame, hanging ivy and cobwebs, mossy stone ruins,
a large full moon wrapped in torn clouds high in the sky, distant bat
silhouettes, drifting will-o'-wisps and fireflies, thin low mist over
dark grass, cauldron smoke rising beside the cottage, palette: deep
eggplant night #130B21 to #2A1B4A, moon silver #CCD1E6, pumpkin ember
#E07A4F and #A3362A, arcane violet accents #7E3CA8 and #BA80FF, moss
green hints, atmospheric depth, soft vignette, calm darker areas
toward the lower-left column and bottom where UI panels sit, no
people, no figures, no chess pieces, no chessboard, no grid, no text,
no letters, no numbers, no watermark, no signature, no logo, no UI
elements, no frame, no border
```
