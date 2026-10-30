# Invasión de los Gummy Bears — plan y arte

> Estado: **arte inicial producido, sin integración**. La Torre Golosa y el
> banner están en disco y documentados; todavía no hay catálogo, tienda ni
> pantalla de evento que los use. Nada de esto toca la velada de Halloween
> 21-30 ni el pase de temporada.

---

## 0. Resumen

- **Lore:** la **Torre Golosa** es la culpable del caos. Su obsesión por los
  dulces la llevó a convertir el reino en una despensa y, de paso, a despertar a
  los Gummy Bears. Es la causante habitual: cuando algo se derrite, se pega o se
  llena de osos de goma, la torre está cerca.
- **Piezas producidas:** la **Torre Golosa** en sus dos caras (`hwp_rook_candy`
  y `hwp_rook_candy_black`) y el **banner** de la invasión, con los Gummy Bears
  al fondo y el Peón Golosina y la Torre Golosa al frente sobre un tablero de
  golosinas.
- **Estado:** la Torre Golosa y el Peón Golosina quedan **reservados**. La torre no
  entra en el catálogo (`FallbackSkins`), ni en `ArtSkinPaths`, ni en la tienda,
  ni en el pase hasta definir cómo se entrega. El banner ya está importado en
  `Resources/UI/GummyBears` y listo para la pantalla del evento.

## 1. Piezas

### 1.1 Torre Golosa — `hwp_rook_candy` (reservada)

- **Pieza:** Torre. **Rareza propuesta:** Épica (a definir con la entrega).
- **Concepto:** la torre clásica construida como un castillo de golosinas.
  Ladrillos de pan de jengibre con junta de glaseado, franjas de caramelo en los
  cantos del fuste, banda de glaseado rosa chorreando bajo las almenas,
  remolinos de piruleta planos en cada almena, gotas de goma en el collar y base
  de mazapán con azúcar cristalizada.
- **Materiales:** pan de jengibre, glaseado real, caramelo, piruleta, goma,
  mazapán.
- **Paleta:** caramelo `#D49F6A`, crema `#FDEDC7`, rosa `#FC89B0`, menta
  `#9AD6AA`, contorno `#441D04`.
- **Reglas de silueta:** mismas tres almenas, mismos dos collares, misma base
  ancha y plana. Ningún dulce sobresale del contorno: los remolinos van
  **pintados dentro** de las almenas y las gotas dentro del collar.
- **Versión negra (`hwp_rook_candy_black`):** regaliz negro y chocolate amargo.
  Ladrillo de regaliz, junta de chocolate, glaseado violeta, piruletas de mora y
  gotas lila. Misma geometría, mismo encuadre.

### 1.2 Peón Golosina — `hwp_pawn_candy` (reservado)

Ya producido para la Parte 2 de la velada y retirado del reparto. Es la primera
pieza en salir en la invasión y el compañero de la torre en el banner. Ficha
completa en `PLAN-PASE-VELADA-21-30.md` §4.2.

## 2. Especificaciones del arte

| Archivo | Tamaño | Alto útil | Formato |
|---|---|---|---|
| `hwp_rook_candy.png` | 543×900 | 900 px | RGBA, alfa |
| `hwp_rook_candy_black.png` | 544×900 | 900 px | RGBA, alfa |

- Ubicación: `Assets/Resources/Pieces/Halloween/` (lote `hwp_*`, compartido con
  el resto del arte full-art; `HalloweenArt.LoadSprite` ya lo resuelve).
- `.meta` de sprite: `textureType: 8`, `alphaIsTransparency: 1`,
  `spriteMeshType: 0`, `maxTextureSize: 2048`, rect exacto, GUID único.
- QA de par (`Tools/check_skin_pair.py hwp_rook_candy`): **IoU 0.997**,
  luminancia a 78 px **152.3 / 36.1** (delta 116.3). El par se distingue de un
  vistazo sobre casilla clara y oscura.

## 3. Banner de la invasión

- **Archivo listo para usar:** `Assets/Resources/UI/GummyBears/gummy_bears_banner.jpg`
  (1376×768, 16:9, importado como sprite). Fuente en
  `_art-source/GummyBears/gummy_bears_banner.jpg`; crudo de Flow en
  `gummy_bears_banner_chase_raw.jpg`. La versión con brazos y piernas quedó en
  `gummy_bears_banner_chase_limbs.jpg`, y la composición original en
  `gummy_bears_banner_standoff.jpg`.
- **Composición (huida sin extremidades):** cámara a ras del tablero; el Peón
  Golosina y la Torre Golosa avanzan flotando hacia la derecha en vista de tres
  cuartos, inclinados y con estelas de polvo, **sin piernas, sin pies, sin
  brazos y sin manos unidas al cuerpo**. A cada lado de cada pieza flotan dos
  discos blancos lisos —cuatro en total—, con el mismo contorno oscuro grueso:
  sin dedos, pulgar, puño, costura ni muñeca. Gotas de sudor celeste salen de sus
  cuerpos. A la izquierda y al fondo, la horda de osos de goma en rojo, verde,
  naranja, amarillo y violeta los persigue con las patas alzadas. El piso es un
  tablero de chocolate y galleta con juntas de glaseado y rieles de caramelo; el
  horizonte tiene piruletas, montañas de jengibre y nubes de algodón bajo un
  atardecer rosa y dorado. Las piezas conservan sus formas, proporciones,
  materiales y contorno grueso, con sus bases anchas intactas y sin caras ni
  ojos. Esta licencia es solo del banner: los sprites del juego no cambian.
- **Referencias usadas en Flow:** `TorreGolosa.png` (642×1064, derivada de
  `hwp_rook_candy.png`) y `PeonGolosin.png` (900×1200, derivada de
  `hwp_pawn_candy.png`).
- **Prompt de Flow (16:9, una línea):**
  > Wide cinematic video game event banner artwork, 16:9, comedic candy kingdom
  > chase: the two chess pieces from the reference images flee toward the right
  > side of the frame in a three quarter side view, tilted forward in panic,
  > floating and gliding over the candy board with absolutely no legs no feet no
  > arms no limbs and no hands attached to their bodies, keeping the exact same
  > silhouettes, wide candy bases, shapes, proportions, colors, candy materials
  > and thick dark outline as the references; beside each piece float two
  > detached plain flat pure white circular discs, simple featureless blank
  > white coins with the same thick dark outline as the piece, hovering in the
  > air without any arm or support connecting them, no fingers no thumb no
  > knuckles no crease no fold no seam no cuff no wristband no glove detail, only
  > four smooth white circles total; big cartoon light blue sweat droplets fly
  > off their bodies; behind them, flooding the left side and the whole
  > background, a dense horde of hundreds of glossy translucent gummy bears in
  > red, green, orange, yellow and purple chases them with raised paws, soft
  > depth of field; the short candy pawn with its jawbreaker head and the taller
  > candy rook candy castle with dripping pink icing and lollipop battlements,
  > both with no faces and no eyes; they float above a giant candy chessboard
  > floor of chocolate and vanilla wafer squares with white icing grout and
  > candy cane rails; candy world horizon with lollipop trees, gingerbread hills
  > and cotton candy clouds under a warm pink and golden sunset sky; dynamic
  > motion, motion streaks and dust puffs behind them, dramatic rim light,
  > glowing candy highlights, high detail, no text no letters no numbers no logos
- **Archivos del banner:**

  | Archivo | Qué es |
  |---|---|
  | `Assets/Resources/UI/GummyBears/gummy_bears_banner.jpg` | Banner activo de la huida sin extremidades (1376×768, mismo `.meta` y GUID). |
  | `_art-source/GummyBears/gummy_bears_banner.jpg` | Fuente del banner activo (1376×768). |
  | `_art-source/GummyBears/gummy_bears_banner_chase_raw.jpg` | Crudo de Flow del banner sin extremidades (1376×768, JPG q95 desde el WebP de Flow). |
  | `_art-source/GummyBears/gummy_bears_banner_chase_limbs.jpg` | Versión anterior con brazos y piernas, conservada como referencia (1376×768). |
  | `_art-source/GummyBears/gummy_bears_banner_standoff.jpg` | Composición anterior: piezas plantadas y osos en filas (1376×768). |
  | `_art-source/GummyBears/gummy_bears_banner_alt.jpg` | Variante anterior con el tablero completo a la vista. |

## 4. Pendientes

- [ ] Decidir la entrega de la Torre Golosa: skin de evento, recompensa de
  apertura o pieza de la tienda de golosinas. Hoy no está cableada.
- [ ] Definir la ficha de catálogo (id, nombre, descripción, rareza, precio de
  referencia e icono) cuando se cierre el evento.
- [ ] Producir el resto del set de la invasión (damas, alfiles, caballos y rey
  de golosina) si el evento repite el formato full-art.
- [ ] Tablero y fondo propios del evento: el banner ya marca la dirección
  (chocolate + galleta, rieles de caramelo, horizonte de piruletas).
- [ ] QA en juego: equipar la torre en blancas y negras, comprobar el sprite a
  78 px, el `_black` propio y que no arrastre tinte ni aura.

## 5. Archivos

| Archivo | Qué es |
|---|---|
| `Assets/Resources/Pieces/Halloween/hwp_rook_candy.png` | Torre Golosa blanca (543×900). |
| `Assets/Resources/Pieces/Halloween/hwp_rook_candy_black.png` | Torre Golosa negra (544×900). |
| `Assets/Resources/Pieces/Halloween/hwp_pawn_candy.png` | Peón Golosina (reservado). |
| `Assets/Resources/UI/GummyBears/gummy_bears_banner.jpg` | Banner 16:9 de la huida sin extremidades, listo para `Resources.Load<Sprite>("UI/GummyBears/gummy_bears_banner")` (1376×768). |
| `_art-source/GummyBears/gummy_bears_banner.jpg` | Banner activo 16:9 (fuente, 1376×768). |
| `_art-source/GummyBears/gummy_bears_banner_chase_raw.jpg` | Crudo de Flow del banner sin extremidades (1376×768). |
| `_art-source/GummyBears/gummy_bears_banner_chase_limbs.jpg` | Versión anterior con brazos y piernas (1376×768). |
| `_art-source/GummyBears/gummy_bears_banner_standoff.jpg` | Composición original: piezas plantadas y osos en filas (1376×768). |
| `_art-source/GummyBears/gummy_bears_banner_alt.jpg` | Variante anterior con el tablero completo a la vista. |
| `_art-source/GummyBears/hwp_rook_candy_raw.jpg` | Crudo de Flow (blanca). |
| `_art-source/GummyBears/hwp_rook_candy_black_raw.jpg` | Crudo de Flow (negra). |
| `Assets/_Project/Scripts/Core/HalloweenArt.cs` | Constantes `RookCandyArt` y `PawnCandyArt`, marcadas como reservadas. |
| `Tools/check_skin_pair.py` | QA del par blanco/negro, ya incluye `hwp_rook_candy`. |
