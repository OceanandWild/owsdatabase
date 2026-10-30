# Arte de Progreso (Assets/Resources/UI/Progress) — ESTADO: COMPLETO

La sección de Progreso del juego (misiones, barra semanal, logros, cofre y fuentes
de Gambits) tiene **todo su arte entregado e instalado**. No queda ningún sprite
pendiente de generar ni de verificar: cada contenedor que `ProgressModal` pide
resuelve contra un PNG real en `Assets/Resources/UI/Progress/`, y el resto de los
elementos se apoya en el estilo USS cuando no lleva marco.

Verificación hecha sobre la tabla de `ProgressSprites.cs` (los `fracX/fracY` y
tamaños de referencia de cada slot) cruzada con los `ProgressSprites.Apply(...)`
de `ProgressModal.cs`:

| Slot | PNG | Tamaño final |
|---|---|---|
| frame_window | frame_window.png | 1024×548 |
| card_week | card_week.png | 1588×660 |
| card_large | card_large.png | 1191×400 |
| card_chest | card_chest.png | 967×172 |
| card_chest_ready | card_chest_ready.png | 748×172 |
| card_ach | card_ach.png | 482×108 |
| card_ach_done | card_ach_done.png | 608×108 |
| row_mission / _done | row_mission.png · row_mission_done.png | 478×136 · 346×136 |
| row_challenge | row_challenge.png | 1182×124 |
| row_source / row_source_empty | row_source.png · row_source_empty.png | 1123×108 · 476×108 |
| seg_future / today / done / missed | seg_*.png | ~149–153×296 |
| chip_gold / chip_blue | chip_*.png | 288×104 · 275×104 |
| btn_claim_ready / locked / done / btn_claim | btn_claim_*.png · btn_claim.png | 168–174×68 · 189×68 |
| btn_ghost / btn_ghost_locked | btn_ghost*.png | 331×64 · 349×64 |
| btn_menu_progress | btn_menu_progress.png | 595×120 |
| toast | toast.png | 404×104 |
| bar_track / bar_fill / _v | bar_*.png | 140×12 · 104×12 · 44×240 · 44×227 |
| badge_pending | badge_pending.png | 44×44 |

Convención de los archivos: fondo eliminado (PNG con alfa), alto = 2× el alto de
referencia del contenedor y ancho según el aspect natural del marco, para que el
9-slice de `ProgressSprites.Apply` escale el ornamento a su tamaño real. Unity los
importa solo como Sprite (Single, Full Rect, sin compresión) vía
`ProgressSpriteImport.cs`.

Los slots `row_weekly` / `row_weekly_done` resuelven contra
`row_weekly.png` / `row_weekly_done.png`, que son el mismo marco que
`row_mission` / `row_mission_done` (copia exacta, con su propio `.meta`):
las filas semanales piden esos nombres en `ProgressModal.BuildMissionRow`
y así ningún `Apply`/`ApplyFirst` queda sin sprite. No requiere arte nuevo.

## Verificación 1.0.2 (09/10/2026)

La última tanda pendiente
(`C:\Users\Equipo\Downloads\Wilder Gambit - Progress Section Remaining Assets`,
9 JPG con fondo negro puro) se procesó así: flood-fill del negro exterior
desde los bordes (tolerancia RGB < 28, el interior azul-noche `#0D1424…#222A3F`
queda intacto tras el filete dorado), defringe de 1 px, recorte al marco y
redimensión LANCZOS al tamaño final de la tabla. Los 9 PNG resultantes tienen
alfa real (5–36 % transparente según el calado) y conservan sus medidas, así
que el 9-slice de `ProgressSprites` no cambia. Con `row_weekly*` como alias,
la tabla queda 33/33: **no hay más assets de Progreso por verificar**,
todos los contenedores del modal resuelven y la sección está cerrada para
la build 1.0.2 (carpeta `Builds`, disponible en `web/OWS`).

---

## Referencia: prompts originales de la última tanda

Se conservan como historial por si hay que regenerar algùn marco. Todos son
**marcos/paneles vacíos** (el texto lo escribe la UI): interior azul-noche liso,
adorno concentrado en el borde y las esquinas. Pipeline de entrega: recibir la
imagen, quitarle el fondo, ajustar el tamaño y dejarla en
`Assets/Resources/UI/Progress/`.

### 1. `card_week.png`

Fantasy game UI panel frame, wide horizontal card, 2048 by 593, ornate
baroque golden border with intricate filigree scrollwork in all four
corners, double gold rim with a bright highlight line and a dark bronze
shadow line, deep midnight-navy interior with a smooth vertical gradient,
completely empty clean interior, luxurious elegant metalwork, gothic-royal
chess fantasy aesthetic, midnight-navy interior colors #0D1424 to #222A3F,
ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

### 2. `card_large.png`

Fantasy game UI panel frame, medium horizontal card, 2048 by 359, ornate
golden border with subtle filigree accents in the corners, single thick
gold rim with a bright highlight line, deep midnight-navy interior with a
smooth vertical gradient, completely empty clean interior, gothic-royal
chess fantasy aesthetic, midnight-navy interior colors #0D1424 to #222A3F,
ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

### 3. `card_chest.png`

Fantasy game UI strip frame, thin horizontal bar, 2048 by 160, slim ornate
golden border with small corner flourishes, deep midnight-navy interior
with a smooth vertical gradient, completely empty clean interior, elegant
metal trim, gothic-royal chess fantasy aesthetic, midnight-navy interior
colors #0D1424 to #222A3F, ornate gold frame colors #F7D47C #CEAB57 #8A6D33,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective,
no 3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork

### 4. `card_chest_ready.png`

Fantasy game UI strip frame, thin horizontal bar, 2048 by 160, ornate
bright golden border glowing warmly with small sparkles and tiny corner
flourishes, deep midnight-navy interior lit by a soft warm amber glow,
completely empty clean interior, precious and inviting, gothic-royal chess
fantasy aesthetic, midnight-navy interior colors #0D1424 to #222A3F,
ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

### 5. `card_ach.png`

Fantasy game UI small card frame, compact rounded rectangle, 1080 by 108,
slim ornate golden border with tiny corner flourishes, deep midnight-navy
interior with a smooth vertical gradient, completely empty clean interior,
gothic-royal chess fantasy aesthetic, midnight-navy interior colors #0D1424
to #222A3F, ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal
2D illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

### 6. `card_ach_done.png`

Fantasy game UI small card frame, compact rounded rectangle, 1080 by 108,
ornate jade-teal and gold border with tiny laurel corner flourishes, deep
dark teal-navy interior with a smooth vertical gradient, completely empty
clean interior, rewarding and prestigious, gothic-royal chess fantasy
aesthetic, teal and gold frame colors #96E8C4 #56A880 #265442 with gold
#CEAB57 accents, flat frontal 2D illustration, single centered object,
uniform flat pure black background for easy background removal, no shadow,
no perspective, no 3D, no text, no letters, no numbers, no logo, no
watermark, high detail ornamental metalwork

### 7. `row_challenge.png`

Fantasy game UI row frame, thin horizontal strip, 2048 by 116, slim gold
border with small elegant corner curls, deep midnight-navy interior with a
smooth vertical gradient, completely empty clean interior, gothic-royal
chess fantasy aesthetic, midnight-navy interior colors #0D1424 to #222A3F,
ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

### 8. `row_source.png`

Fantasy game UI row frame, thin horizontal strip, 2048 by 101, slim ornate
gold border with small corner flourishes, deep midnight-navy interior with
a smooth vertical gradient, completely empty clean interior, gothic-royal
chess fantasy aesthetic, midnight-navy interior colors #0D1424 to #222A3F,
ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

### 9. `btn_claim.png`

Fantasy game UI button bezel, pill stadium shape, 236 by 68, thick ornate
gold rim with a bright highlight line and a dark bronze shadow, deep
midnight-navy center, empty center with no text, luxurious and tactile,
gothic-royal chess fantasy aesthetic, midnight-navy interior colors #0D1424
to #222A3F, ornate gold frame colors #F7D47C #CEAB57 #8A6D33, flat frontal
2D illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork

---

## Ajeno al proyecto: icono del Admin Panel

El proxy de iconos del panel busca `owsrecover/Wilder Gambit/build/icon.png`
y hoy no existe (404). No es arte del juego ni bloquea la sección de
Progreso; si en algún momento se quiere cerrar, 256×256:

Fantasy chess game emblem, golden king chess piece silhouette inside an
ornate circular crest, midnight-navy background, gothic-royal chess fantasy
aesthetic, flat iconic illustration, single centered object, uniform flat
pure black background for easy background removal, no shadow, no
perspective, no 3D, no text, no letters, no logo, no watermark, 256 by 256
