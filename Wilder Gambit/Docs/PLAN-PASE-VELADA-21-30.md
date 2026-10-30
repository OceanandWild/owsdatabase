# PLAN — Pase de la Velada 21-30: lote definitivo

> **Objetivo:** reemplazar los tramos **21-30** del Pase de la Velada (Halloween 2026)
> por un lote definitivo de **skins, tableros y fondos**. Sin variantes ni animaciones
> nuevas. Los sprites se generan después con `ows-unity-flow`, usando la pieza clásica
> como referencia de silueta: **igual en todo, solo cambia la piel**.
>
> **Alcance:** contenido + integración. La generación de arte queda para la fase
> siguiente; este documento fija qué se hace, con qué ids y cómo se monta.

---

## 0. Resumen ejecutivo

- **18 archivos de arte:** 12 skins (6 blancas + 6 negras) + 4 de tablero
  (2 ambientes + 2 objetos 8×8) + 2 fondos. Diez conceptos únicos.
- **20 tramos** (10 Luna + 10 Sangre): **7 arte + 13 economía/reroll**.
- **Vía Luna = «La Cosecha»** (gratis): Alfil Farol, Caballo Espantapájaros,
  fondo Noche de la Cosecha y tablero Cementerio Olvidado.
- **Vía Sangre = «La Corte»** (premium): Rey Carmesí, tablero Cripta de los Cuervos
  y fondo Salón del Banquete. Torre Relicario y Reina Maleficio bajan a la **tienda de
  la velada**, donde se pagan con Dulces.
- **Peón Golosina: fuera de circulación.** Se retira del pase porque su concepto
  chocaría con la próxima velada de los Gummy Bears. El PNG blanco y su `_black`
  se conservan como asset para ese evento: no aparece en tiendas, inventario ni
  recompensas.
- Las cinco skins que se distribuyen son **full-art**: reemplazan el sprite en
  partida (`ArtSkinPaths`), no son solo tinte + aura. Cada una lleva su **`_black`
  propio** (misma geometría, material negro); si un `_black` falta, `BoardView`
  cae al horneado en runtime. El par del Peón Golosina sigue el mismo estándar de
  arte, pero no se cablea al catálogo.
- La economía de la Vía Luna queda **idéntica** a la documentada (126 Dulces y 2.000
  Gambits). La Vía Sangre cambia el tramo provisional (9 recompensas de arte + 900
  Gambits) por 2 arte + economía: 52 Dulces y 1.600 Gambits en 21-30, porque los dos
  tramos que daban la Torre y la Reina pasan a financiar su compra en la tienda.
- Los tramos 21-30 son **Parte 2**: todavía no se publicaron, así que **no hace falta
  migración** de cobros. Ver §8.3.

---

## 1. Contexto y decisión

El Pase de la Velada creció de 20 a 30 niveles y los tramos 21-30 quedaron marcados
como **provisionales** en `HalloweenPassModal.cs` y en `Docs/PLAN-HALLOWEEN.md` §5.
Hoy reutilizan skins de la tienda, animaciones ya existentes y un fondo regular
(`caravan_dunes`), lo que rompe la progresión de la segunda mitad.

Este plan los sustituye por un lote cerrado y coherente. **No es el Pase de
Temporada T1** (`SeasonPassModal`): sus 21-30 ya son definitivos y no se tocan.

Restricciones confirmadas:

- Solo **skins, tableros y fondos**.
- **No** se crean variantes de pieza ni animaciones.
- Las skins usan la **pieza clásica** (`Assets/StreamingAssets/Pieces/White/<Pieza>.png`)
  como referencia: misma geometría, proporción, pose y base; solo cambia el material.
- Sin sombreros, armas, capas ni props que sobresalgan de la silueta.

---

## 2. Pilares de diseño

1. **Completar el set.** Los niveles 1-20 ya dieron Peón, Torre, Dama y Rey. Los
   tramos 21-30 cierran **Caballo** y **Alfil** y dan una segunda pasada a las piezas
   reales.
2. **Dos materiales, dos vías.**
   - **Luna:** cosecha y pueblo — hierro, ámbar, caramelo, arpillera, paja, piedra
     cubierta de musgo.
   - **Sangre:** corte y banquete — hueso, plata, espino negro, terciopelo, rubí,
     mármol negro.
3. **Silueta intocable.** La nueva piel no cambia el contorno. Si un detalle no se
   lee a 78 px (tamaño de casilla), no vale.
4. **Full-art, no tinte.** Las cinco skins distribuidas entran en `ArtSkinPaths` y
   reemplazan el sprite; el tinte queda en blanco para no ensuciar el arte. La del
   Peón Golosina se reserva para los Gummy Bears y no se cablea a este pase.
5. **Una pieza, una lectura.** Cada skin debe reconocerse por silueta + paleta, no
   por detalles pequeños que desaparecen en el tablero.

---

## 3. Tabla de recompensas

### 3.1 Vía Luna (gratis) — «La Cosecha»

| Nivel | Recompensa | Tipo | Detalle |
|---:|---|---|---|
| 21 | Dulces ×20 | Economía | Puente hacia la tienda de la velada. |
| 22 | **Alfil Farol** (`skin_bishop_lantern`) | Skin · Alfil · Rara | Hierro forjado + vitral ámbar. |
| 23 | Gambits ×350 | Economía | — |
| 24 | **Noche de la Cosecha** (`backdrop_halloween_harvest`) | Fondo | Calabazas, espantapájaros y luna de cosecha. |
| 25 | Dulces ×24 | Economía | — |
| 26 | Dulces ×10 | Economía | Cubre el hueco del Peón Golosina, reservado para los Gummy Bears. |
| 27 | Gambits ×450 | Economía | — |
| 28 | Dulces ×18 | Economía | Se reparte el resto para conservar los 72 Dulces de la vía. |
| 29 | **Cementerio Olvidado** (`halloween_graveyard`) | Tablero | Piedra con musgo, hierro y velas. |
| 30 | **Caballo Espantapájaros** (`skin_knight_scarecrow`) | Skin · Caballo · Épica | Arpillera, paja y botón. Capstone de la vía. |

**Totales Luna 21-30:** 72 Dulces · 800 Gambits · 2 skins · 1 tablero · 1 fondo.
Se mantienen los totales de la vía (126 Dulces y 2.000 Gambits con los niveles 1-20).

### 3.2 Vía Sangre (premium) — «La Corte»

| Nivel | Recompensa | Tipo | Detalle |
|---:|---|---|---|
| 21 | Dulces ×10 | Economía | Financia la Torre Relicario en la tienda. |
| 22 | Dulces ×8 | Economía | — |
| 23 | Dulces ×12 | Economía | Financia la Reina Maleficio en la tienda. |
| 24 | Gambits ×700 | Economía | — |
| 25 | **Cripta de los Cuervos** (`halloween_crypt`) | Tablero | Mármol negro, hueso y rubí. |
| 26 | Dulces ×10 | Economía | — |
| 27 | **Salón del Banquete** (`backdrop_halloween_banquet`) | Fondo | Mesa larga, candelabros y terciopelo. |
| 28 | Gambits ×900 | Economía | — |
| 29 | Dulces ×12 | Economía | — |
| 30 | **Rey Carmesí** (`skin_king_crimson`) | Skin · Rey · Mítica | Obsidiana, plata y rubí. Capstone de la vía. |

**Totales Sangre 21-30:** 52 Dulces · 1.600 Gambits · 1 skin · 1 tablero · 1 fondo.
Los 130 Dulces de los niveles 1-20 no se tocan.

**Lectura de la economía:** la vía queda en **182 Dulces** (130 + 52). Los tramos 21 y
23, que antes daban la Torre Relicario y la Reina Maleficio, pasan a pagar Dulces para
comprarlas en la tienda (125 y 165): el jugador elige si completa la Corte. Los Gambits
de 21-30 bajan de 4.200 a 1.600 porque el tramo ahora reparte Dulces; el total de la vía
queda en 3.890. Luna sigue siendo la vía de moneda (72 Dulces y 800 Gambits en 21-30);
Sangre es la vía de arte y Gambits altos.

> **Si se quiere mantener el sink estricto** (no devolver nunca los 150): bajar los
> cinco tramos de Dulces a ×4 (total 20, vía 150). No tocar los 130 de 1-20 ni la tabla
> de `Docs/PLAN-HALLOWEEN.md` §5 en ese caso; con 182 hay que actualizarla.

---

## 4. Skins (6 producidas; 5 distribuidas)

Las seis se entregan **con lado negro propio**: `hwp_<nombre>.png` y
`hwp_<nombre>_black.png`, mismo encuadre y misma silueta. El `_black` no es un tinte
plano: cambia el material (hierro negro, regaliz, arpillera quemada, obsidiana…) para
que los bandos se distingan de un vistazo. Si un `_black` faltara, `BoardView` cae al
horneado en runtime, así que el arte negro se puede entregar en un segundo lote sin
romper nada. El **Peón Golosina** no se distribuye en esta velada: su par queda
archivado para la invasión de los Gummy Bears.

### 4.1 Alfil Farol — `skin_bishop_lantern`

- **Pieza:** Alfil. **Rareza:** Rara. **Vía:** Luna 22.
- **Concepto:** la silueta clásica del alfil se convierte en un farol de hierro
  forjado. La mitra es una jaula de nervios metálicos con vitral ámbar; la ranura
  diagonal es la boca del farol; la bola superior es el anillo de suspensión; la base
  es un portavelas con cera derretida y hollín.
- **Materiales:** hierro forjado, vidrio ámbar, cera de abeja, hollín.
- **Paleta:** hierro `#2A2724`, ámbar `#F0A63C`, cera `#E8D9B8`, brillo `#FFD27A`.
- **Reglas de silueta:** misma mitra, misma ranura, misma base. Sin asa, sin cadena,
  sin llama que sobresalga del contorno.
- **Lectura en tablero:** el ámbar interno debe verse incluso a 78 px; el hierro
  oscuro mantiene la silueta.
- **Versión negra (`hwp_bishop_lantern_black`):** hierro negro, vitral verde frío y
  cera gris; mismo farol, misma llama, misma base.

### 4.2 Peón Golosina — `skin_pawn_candy` (reservado)

- **Pieza:** Peón. **Rareza:** Poco común. **Disponibilidad: retirada.** El arte
  queda guardado para la invasión de los Gummy Bears: no entra en el catálogo, la
  tienda ni el pase de esta velada.
- **Concepto:** el peón clásico tallado en caramelo. Cabeza de jawbreaker con espiral,
  cuello con banda de maíz dulce (crema → ámbar → dorado), cuerpo de caramelo
  brillante y base de azúcar cristalizada.
- **Materiales:** maíz dulce, caramelo, azúcar, glaseado.
- **Paleta:** crema `#F6E7C8`, naranja `#E8892E`, amarillo `#F2C14E`, brillo `#FFF3D0`.
- **Reglas de silueta:** mismo peón, misma base, mismo cuello. Sin envoltorio que
  sobresalga; sin mordiscos que rompan el contorno.
- **Lectura en tablero:** el degradado vertical debe leerse como caramelo, no como
  piedra; los brillos son clave.
- **Versión negra (`hwp_pawn_candy_black`):** regaliz y mora — violeta profundo,
  negro y brillo lila; misma espiral y misma base de azúcar.

### 4.3 Caballo Espantapájaros — `skin_knight_scarecrow`

- **Pieza:** Caballo. **Rareza:** Épica. **Vía:** Luna 30 (capstone).
- **Concepto:** la cabeza y el cuello del caballo clásico se cubren de arpillera
  cosida, con melena y flequillo de paja que siguen las mismas curvas. El ojo es un
  botón negro; el hocico lleva un cabestro de cuerda; la base es madera con clavos y
  mechones de paja.
- **Materiales:** arpillera, paja, cuerda, madera vieja, botón de hierro.
- **Paleta:** arpillera `#B89A6A`, paja `#D9B45A`, madera `#5A4632`, costura `#3A2E22`.
- **Reglas de silueta:** misma cabeza, mismas orejas, mismo cuello, misma base. Sin
  sombrero, sin alas, sin brazos. La melena de paja no debe abrir el contorno.
- **Lectura en tablero:** las costuras y el botón deben leerse a tamaño de casilla;
  la paja va en mechones grandes, no en pelos finos.
- **Versión negra (`hwp_knight_scarecrow_black`):** arpillera carbonizada, paja
  quemada, cuerda ennegrecida y madera oscura; mismo botón y mismas costuras.

### 4.4 Torre Relicario — `skin_rook_reliquary`

- **Pieza:** Torre. **Rareza:** Épica. **Vía:** tienda de la velada · 125 Dulces.
- **Concepto:** la torre clásica como relicario de hueso: mampostería de marfil
  unida con filigrana de plata, nichos con calaveras y huesos, sellos de cera roja
  escurriendo, almenas remachadas en plata y un brillo rubí en las juntas.
- **Materiales:** hueso, plata vieja, cera roja, rubí.
- **Paleta:** hueso `#D8CDB4`, plata `#A8A8A2`, cera `#8E1F24`, rubí `#C0202A`.
- **Reglas de silueta:** misma torre, mismas almenas, misma base. Sin púas extra
  fuera de las almenas; los nichos van dentro del fuste.
- **Lectura en tablero:** la plata y la cera deben separar la torre de la piedra del
  tablero; el rubí es un acento, no una luz.
- **Versión negra (`hwp_rook_reliquary_black`):** obsidiana, oro viejo y rubí; los
  nichos pasan a hueso ahumado.

### 4.5 Reina Maleficio — `skin_queen_hex`

- **Pieza:** Dama. **Rareza:** Legendaria. **Vía:** tienda de la velada · 165 Dulces.
- **Concepto:** la corona clásica de la dama como regalia de bruja: espino negro
  retorcido en las cinco puntas, cada orbe una perla de fuego de bruja violeta,
  telarañas finas dentro del negativo de la corona, media luna de plata en la base y
  un manto de terciopelo oscuro en el pedestal.
- **Materiales:** espino negro, fuego de bruja, plata, terciopelo.
- **Paleta:** espino `#2A1E2E`, violeta `#8A4FD8`, plata `#B8B8C0`, terciopelo `#3A1638`.
- **Reglas de silueta:** misma corona, mismas cinco puntas, misma base. Sin sombrero
  de bruja, sin cara, sin ala que sobresalga.
- **Lectura en tablero:** el fuego violeta en las puntas es la firma; las telarañas
  deben quedar dentro del contorno.
- **Versión negra (`hwp_queen_hex_black`):** espino negro, fuego esmeralda y oro
  viejo; la media luna pasa a plata oscura.

### 4.6 Rey Carmesí — `skin_king_crimson`

- **Pieza:** Rey. **Rareza:** Mítica. **Vía:** Sangre 30 (capstone).
- **Concepto:** la corona clásica del rey como relicario de monarca vampiro:
  obsidiana y marfil con vetas de plata, rubí en la cruz, grabados de alas de
  murciélago en los hombros de la corona, terciopelo carmesí en la base y un brillo
  rojo interno.
- **Materiales:** obsidiana, marfil, plata, rubí, terciopelo.
- **Paleta:** obsidiana `#141018`, marfil `#E4D8C0`, plata `#B0B0B8`, rubí `#B01828`, terciopelo `#4A0E18`.
- **Reglas de silueta:** misma cruz, mismos lóbulos, misma base. Sin capa, sin alas
  fuera del contorno; los grabados van en la superficie.
- **Lectura en tablero:** el rubí de la cruz y el borde de plata deben leerse a
  distancia; el resto es textura.
- **Versión negra (`hwp_king_crimson_black`):** obsidiana ahumada, plata bruñida y
  rubí; se recorta el marfil para que el bando negro lea más oscuro que el blanco.

---

## 5. Tableros (2)

### 5.1 Cementerio Olvidado — `halloween_graveyard`

- **Vía:** Luna 29. **Tipo:** tablero de evento (exclusivo del pase).
- **Ambiente:** `bg_halloween_graveyard.jpeg` — 1376×768, cementerio nocturno con
  lápidas torcidas, reja de hierro, árboles secos, calabazas encendidas, niebla
  azul-gris y luna llena.
- **Objeto 8×8:** `bg_halloween_graveyard_board.png` — 1024×1024, grilla 0.83,
  losas de piedra cubiertas de musgo, grietas, hojas caídas, filigrana de hierro en
  las esquinas, cera y velas votivas, runas verdes tenues.
- **Paleta:** pizarra `#3E4A52`, musgo `#4F6B3A`, hueso `#D8CDB4`, ámbar `#E8A34A`,
  hierro `#1E2226`.
- **Composición:** grilla centrada y legible; borde ornamentado pero no más ancho
  que el de Luna Llena; sin piezas, sin texto.
- **Diferencia con los tableros existentes:** Luna Llena es piedra azul con sombras
  de ramas; Luna de Sangre es piedra roja; Cementerio Olvidado es piedra vieja con
  musgo, reja y velas (verde/ámbar, no azul/rojo).

### 5.2 Cripta de los Cuervos — `halloween_crypt`

- **Vía:** Sangre 25. **Tipo:** tablero de evento (exclusivo del pase).
- **Ambiente:** `bg_halloween_crypt.jpeg` — 1376×768, cripta iluminada por velas,
  bóvedas de nervios, sarcófagos, cuervos, cortinas de terciopelo rojo y candelabros.
- **Objeto 8×8:** `bg_halloween_crypt_board.png` — 1024×1024, grilla 0.83, mármol
  negro con incrustaciones de hueso, calaveras de cuervo en las esquinas, filigrana
  de plata, juntas con brillo rubí y cera roja.
- **Paleta:** borgoña `#4A1218`, hueso `#D9C9A8`, oro `#B08A3E`, negro `#0E0B0C`,
  rubí `#C0202A`.
- **Composición:** grilla centrada; borde estrecho de filigrana de oro con calaveras
  de cuervo pequeñas en las esquinas; sin piezas, sin texto.
- **Diferencia con los tableros existentes:** es interior, mármol negro + hueso +
  oro; no compite con la piedra roja exterior de Luna de Sangre.

> **Stretch opcional:** un tercer tablero **Salón del Banquete**
> (`halloween_banquet`) para el nivel 29 de Sangre, con piso de mármol blanco y negro
> vetado en oro, pétalos y velas. Reemplazaría a los 1.500 Gambits. Solo si sobra
> tiempo de arte.

---

## 6. Fondos (2)

### 6.1 Noche de la Cosecha — `backdrop_halloween_harvest`

- **Vía:** Luna 24. **Tipo:** fondo de evento (exclusivo del pase).
- **Composición:** campo de calabazas bajo una luna de cosecha enorme; espantapájaros
  con sombrero de paja, fardos de heno, farolillos de papel, luciérnagas, árboles
  retorcidos y una granja lejana con ventanas cálidas. Cielo índigo con nubes
  violáceas.
- **Paleta:** índigo `#1B1630`, calabaza `#D96A1E`, ámbar `#F2B24A`, musgo `#3E5A34`,
  luna `#E8E4D8`.
- **Formato:** 2752×1536 JPG (16:9), calidad 90.
- **Lectura de UI:** dejar el tercio inferior/izquierdo relativamente despejado para
  que el menú respire; evitar alto contraste detrás del logo.

### 6.2 Salón del Banquete — `backdrop_halloween_banquet`

- **Vía:** Sangre 27. **Tipo:** fondo de evento (exclusivo del pase).
- **Composición:** salón de banquete vampírico con mesa larga, candelabros, cortinas
  de terciopelo rojo, lámparas de cristal, ventanales arqueados con luna, vajilla
  dorada, pétalos de rosa y sillas vacías. Sin personas.
- **Paleta:** borgoña `#3A0E14`, oro `#C9A24A`, hueso `#E4D8C0`, negro `#0B090A`,
  luna `#AFC4D8`.
- **Formato:** 2752×1536 JPG (16:9), calidad 90.
- **Lectura de UI:** mesa y candelabros en el tercio inferior; ventanales y cortinas
  arriba; centro-izquierda despejado para el texto del menú.

---

## 7. Pipeline de arte (`ows-unity-flow`)

### 7.1 Referencia

Para cada skin, subir a Flow la pieza clásica:

```
Assets/StreamingAssets/Pieces/White/Bishop.png
Assets/StreamingAssets/Pieces/White/Pawn.png
Assets/StreamingAssets/Pieces/White/Knight.png
Assets/StreamingAssets/Pieces/White/Rook.png
Assets/StreamingAssets/Pieces/White/Queen.png
Assets/StreamingAssets/Pieces/White/King.png
```

La referencia manda la geometría. El prompt solo describe el material. Si Flow
propone una pose distinta, se descarta aunque el material sea bonito.

### 7.2 Fórmula de prompt (inglés, una línea)

```
Game asset, maintain exact geometry, anatomy and structure of the original white
chess <piece>, keep the clean vector-like silhouette, thick dark outline, soft inner
bevel and flat shading of the classic piece, transform only its surface into
<material/concept>, <palette>, no extra props outside the silhouette, flat pure white
background with a clear margin, no shadow, no gradient, orthographic front view,
no text no letters no numbers, single piece, high detail
```

### 7.3 Prompts base

**Alfil Farol**
```
Game asset, maintain exact geometry, anatomy and structure of the original white chess bishop, keep the clean vector-like silhouette, thick dark outline, soft inner bevel and flat shading of the classic piece, transform only its surface into a hand-forged wrought-iron lantern with warm amber glass panels, the mitre becomes an iron cage holding a candle flame, melted beeswax and soot at the base, aged silver-ivory iron, subtle warm emissive glow, no extra handle or chain outside the silhouette, flat pure white background with a clear margin, no shadow, no gradient, orthographic front view, no text no letters no numbers, single piece, high detail
```

**Peón Golosina**
```
Game asset, maintain exact geometry, anatomy and structure of the original white chess pawn, keep the clean vector-like silhouette, thick dark outline, soft inner bevel and flat shading of the classic piece, transform only its surface into glossy candy corn and caramel, cream-to-amber-to-golden banded glaze, sugar crystals, a jawbreaker spiral on the ball head, thin caramel seam at the collar, no wrapper extending beyond the silhouette, flat pure white background with a clear margin, no shadow, no gradient, orthographic front view, no text no letters no numbers, single piece, high detail
```

**Caballo Espantapájaros**
```
Game asset, maintain exact geometry, anatomy and structure of the original white chess knight, keep the clean vector-like silhouette, thick dark outline, soft inner bevel and flat shading of the classic piece, transform only its surface into a weathered scarecrow horse effigy, stitched burlap panels, golden straw mane and forelock following the same curves, rope halter, black button eye, wooden base with nails and straw tufts, no hat and no extra props outside the silhouette, flat pure white background with a clear margin, no shadow, no gradient, orthographic front view, no text no letters no numbers, single piece, high detail
```

**Torre Relicario**
```
Game asset, maintain exact geometry, anatomy and structure of the original white chess rook, keep the clean vector-like silhouette, thick dark outline, soft inner bevel and flat shading of the classic piece, transform only its surface into an ornate bone reliquary tower, ivory bone masonry bound with aged silver filigree, small relic niches with skulls and bones, red wax seals dripping down, silver-capped crenellations, faint ruby glow in the seams, no extra spikes beyond the crenellations, flat pure white background with a clear margin, no shadow, no gradient, orthographic front view, no text no letters no numbers, single piece, high detail
```

**Reina Maleficio**
```
Game asset, maintain exact geometry, anatomy and structure of the original white chess queen, keep the clean vector-like silhouette, thick dark outline, soft inner bevel and flat shading of the classic piece, transform only its surface into a witch-queen crown of twisted blackthorn branches, five points ending in glowing violet witchfire pearls, delicate cobwebs inside the negative spaces, aged silver crescent motif on the base, dark velvet and pale ash wood accents, no hat, no face and no extra brim outside the silhouette, flat pure white background with a clear margin, no shadow, no gradient, orthographic front view, no text no letters no numbers, single piece, high detail
```

**Rey Carmesí**
```
Game asset, maintain exact geometry, anatomy and structure of the original white chess king, keep the clean vector-like silhouette, thick dark outline, soft inner bevel and flat shading of the classic piece, transform only its surface into a vampire monarch's reliquary crown, ancient ivory and obsidian with silver veins, a blood-red ruby in the cross, engraved bat-wing motifs on the crown shoulders, crimson velvet at the base, faint red inner glow, no cape and no wings extending beyond the silhouette, flat pure white background with a clear margin, no shadow, no gradient, orthographic front view, no text no letters no numbers, single piece, high detail
```

### 7.3.b Prompts del lado negro

Se generan **desde el arte blanco ya aprobado** (img2img / referencia), no desde la
pieza clásica: así la geometría no se mueve. El prompt solo cambia el material.

```
Keep the exact silhouette, pose, proportions and framing of the reference chess
<piece> artwork; repaint only its material as <black material>, <black palette>,
keep the thick dark outline and flat shading, no extra props, flat pure white
background with a clear margin, no shadow, no gradient, orthographic front view,
no text no letters no numbers, single piece, high detail
```

| Skin | `<black material>` | `<black palette>` |
|---|---|---|
| Alfil Farol | blackened wrought iron lantern, cold green glass, grey wax | `#141416` · `#3E7A5A` · `#9AA8A0` |
| Peón Golosina | black licorice and blackberry candy, lilac sugar glaze | `#1A1220` · `#4A2A5E` · `#B08AD0` |
| Caballo Espantapájaros | charred burlap, burnt straw, blackened rope | `#241C14` · `#6A4A1E` · `#8A6A2E` |
| Torre Relicario | obsidian masonry, aged gold filigree, smoked bone niches | `#0E0B0C` · `#B08A3E` · `#8A7A62` |
| Reina Maleficio | blackthorn, emerald witchfire, dark silver | `#1A1420` · `#2FA86A` · `#6E6E78` |
| Rey Carmesí | smoked obsidian, burnished silver, deep ruby | `#0C0A0C` · `#A8A8B0` · `#8E1020` |

**Tablero Cementerio Olvidado**
```
Top-down orthographic game board asset, a square 8x8 chessboard made of mossy cracked stone slabs, wrought-iron corner filigree and side rails, fallen autumn leaves, candle wax and tiny votive candles, faint green runes, fog and moonlight, dark fantasy Halloween graveyard palette of slate blue, moss green, bone and amber, the 8x8 grid centered and clearly readable, ornate border, no pieces, no text no letters no numbers, pure black background outside the board with a clear margin, high detail
```

**Tablero Cripta de los Cuervos**
```
Top-down orthographic game board asset, a square 8x8 chessboard made of black marble and bone inlay, raven skull corner motifs, silver filigree, ruby-red glowing seams, dripping red wax, dark velvet and gold accents, vampire crypt palette of burgundy, bone, gold and black, the 8x8 grid centered and clearly readable, ornate border, no pieces, no text no letters no numbers, pure black background outside the board with a clear margin, high detail
```

**Fondo Noche de la Cosecha**
```
Painterly dark fantasy Halloween environment, a pumpkin patch under a huge harvest moon, a weathered scarecrow with a straw hat, hay bales, glowing paper lanterns, fireflies, twisted dead trees, a distant farmhouse with warm windows, purple-blue night sky with clouds, cinematic wide composition, 16:9, clear lower-left area for UI, no text no letters no numbers, no UI, high detail
```

**Fondo Salón del Banquete**
```
Painterly dark fantasy Halloween environment, a vampire banquet hall with a long table, candelabras, red velvet drapes, crystal chandeliers, tall arched windows with moonlight, gold tableware, rose petals, empty chairs, cinematic wide composition, 16:9, clear center-left area for UI, no people, no text no letters no numbers, no UI, high detail
```

### 7.4 Generación y descarga

- Generar de a una pieza; Flow devuelve 2 variantes. Orden: las 6 blancas, aprobar
  silueta, y recién entonces las 6 negras desde su blanca.
- Elegir por `aria-label` del tile + inspección de silueta, no por orden de aparición.
- Descargar por `fetch` + blob desde la página (las URLs firmadas rechazan curl).
- Guardar crudos en `%TEMP%\ows-flow\raw\` o en la carpeta de descargas de las
  browser tools; copiar antes de procesar.
- Nombrar el crudo con el slot (`bishop_lantern_w1`, `bishop_lantern_b1`…) para no
  confundir blanca y negra al procesar.

### 7.5 Procesado

**Skins (12 PNG: 6 blancas + 6 negras):**

```powershell
magick raw.jpg -fuzz 8% -transparent white -trim +repage keyed.png
# normalizar al marco de la familia hwp_*: canvas 717x900, contenido centrado
python Tools/build_halloween_sprites.py   # ampliar SKIN_JOBS con los 12 trabajos
```

- Marco de referencia: `hwp_knight_skeleton.png` (717×900) o la skin de referencia
  del mismo tipo (`skin_pawn_golden`, `skin_knight_storm`, etc.).
- Salida: `Assets/Resources/Pieces/Halloween/hwp_<name>.png` y
  `hwp_<name>_black.png`.
- **No** hace falta copia en `Resources/Skins`: `GetSkinThumbnail` ya resuelve
  `ArtSkinPaths` → `HalloweenArt`.
- La negra se genera desde la blanca aprobada y se procesa con el **mismo** marco y
  el **mismo** offset: si la blanca quedó centrada en el canvas, la negra debe caer
  pixel a pixel encima.

**Tableros (2 ambientes + 2 objetos):**

```powershell
# ambiente 16:9 -> 1376x768 JPG (calidad 92)   +   fondos -> 2752x1536 JPG (calidad 90)
python Tools/build_halloween_scenery.py

# objeto 8x8 -> 1024x1024 PNG, grilla 0.83
python Tools/build_halloween_boards.py --only graveyard,crypt
```

- Salida: `Assets/StreamingAssets/Board/bg_halloween_<slot>.jpeg` y
  `bg_halloween_<slot>_board.png`.
- El pipeline de tableros detecta la grilla por contraste de paridad y luego
  engancha cada junta interior al perfil de bordes: no hace falta medir a mano.
  Verificar con el overlay verde de `verificacion_<slot>.png` que la grilla mida
  0.83 del lienzo.

**Fondos (2 JPG):**

```powershell
# incluido en build_halloween_scenery.py
```

- Salida: `Assets/StreamingAssets/Backdrop/backdrop_halloween_<name>.jpg`.

### 7.6 Verificación de silueta

Para cada skin, además del alpha y el tamaño:

1. Superponer el arte nuevo al 50 % sobre la pieza clásica (`magick composite`).
2. Revisar que el contorno externo, la base, la altura y el centro coincidan.
3. Si el contorno se desvía más de unos pocos píxeles, regenerar o recortar.
4. Ver la pieza a 78 px sobre una casilla clara y una oscura; si no se lee, simplificar
   el material (más contraste, menos detalle).
5. Superponer `_black` sobre la blanca: el contorno debe coincidir al píxel. Si se
   movió, se corrige por offset en el pipeline, no regenerando.
6. Comparar blanca y negra a 78 px: tienen que distinguirse por valor (no solo por
   matiz); si no, oscurecer más la negra.

---

## 8. Integración en Unity

### 8.1 Catálogos y recompensas

| Archivo | Cambio |
|---|---|
| `Assets/_Project/Scripts/Core/PieceSkinManager.cs` | Agregar 5 `FallbackSkin` y 5 entradas a `ArtSkinPaths` (`skin_*` → `hwp_*`); el Peón Golosina no se cablea y su arte queda reservado. Agregar `PassExclusiveSkinIds` con las 4 skins del pase 1-20 + las 3 del pase 21-30, y `IsPassExclusiveSkin(int)`. `IsHalloweenShopExclusive` pasa a exigir arte propio **y** no ser del pase. |
| `Assets/_Project/Scripts/Core/HalloweenShop.cs` | Agregar las ofertas de Torre Relicario (125 Dulces) y Reina Maleficio (165 Dulces). |
| `Assets/_Project/Scripts/UI/HalloweenShopModal.cs` | Visor de vista previa en la pestaña SKINS: las dos caras del arte (la negra solo si existe `_black`), tipo, rareza y precio. Solo pinta: no compra ni equipa. |
| `Assets/_Project/Scripts/UI/HalloweenPassModal.cs` | Reemplazar `LunaRewards[20..29]` y `SangreRewards[20..29]` por las tablas de §3. Quitar los comentarios de «PROVISIONAL». |
| `Assets/_Project/Scripts/Core/BoardBackgroundManager.cs` | Agregar 2 `FallbackTheme` al final, 2 precios de referencia y los ids a `PassExclusiveIds`. |
| `Assets/_Project/Scripts/Core/BackdropManager.cs` | Agregar 2 `BackdropTheme` al final, 2 precios de referencia y los ids a `EventExclusiveIds`. `Select` dispara `Changed` para que el menú repinte el fondo al equiparlo. |
| `Assets/_Project/Scripts/UI/ShopBackdropSelector.cs` | Listar los fondos de evento **ya desbloqueados** (los del pase) para poder equiparlos; los que faltan siguen fuera del catálogo. |
| `Assets/_Project/Scripts/Core/HalloweenArt.cs` | Constantes de los 6 nombres `hwp_*` nuevos (opcional, para legibilidad). El `_black` no necesita constante: `PiecePath(name, true)` agrega el sufijo. `ArtExists(resourcePath)` comprueba un PNG sin cargarlo ni avisar (lo usa el visor para saber si hay lado negro). |
| `Assets/_Project/Scripts/UI/ShopSkinSelector.cs` | Excluir también `IsPassExclusiveSkin` del Atelier (hoy las skins del pase se colarían). |
| `Assets/_Project/Scripts/UI/InventoryModal.cs` | Mostrar las skins del pase en una sección «PASE DE LA VELADA» (o saltar las bloqueadas) para que no caigan en «se compran con Gambits». |

### 8.2 Assets

```
Assets/Resources/Pieces/Halloween/
  hwp_bishop_lantern.png
  hwp_bishop_lantern_black.png
  hwp_pawn_candy.png
  hwp_pawn_candy_black.png
  hwp_knight_scarecrow.png
  hwp_knight_scarecrow_black.png
  hwp_rook_reliquary.png
  hwp_rook_reliquary_black.png
  hwp_queen_hex.png
  hwp_queen_hex_black.png
  hwp_king_crimson.png
  hwp_king_crimson_black.png

Assets/StreamingAssets/Board/
  bg_halloween_graveyard.jpeg
  bg_halloween_graveyard_board.png
  bg_halloween_crypt.jpeg
  bg_halloween_crypt_board.png

Assets/StreamingAssets/Backdrop/
  backdrop_halloween_harvest.jpg
  backdrop_halloween_banquet.jpg
```

- Los `.meta` de `hwp_*` siguen el import de `hwp_knight_skeleton.png` (textura con
  alpha, mipmaps, filtro trilineal).
- Los tableros y fondos viven en `StreamingAssets` (igual que los de Halloween
  actuales); no hace falta copia en `Resources`.
- Si se copia un `.meta` existente, **cambiar el GUID** para no colisionar; lo más
  simple es dejar que Unity genere el `.meta` y ajustar el import.

### 8.3 Sin migración: 21-30 es Parte 2

Los tramos 21-30 **no se publicaron**: pertenecen a la Parte 2 de la velada. La tabla
se cambia antes de abrir esa parte y no hay cobros que rescatar, así que **no hace
falta** flag de migración ni entrega retroactiva.

Condiciones para que esto siga siendo cierto:

1. La Parte 2 no sale a producción hasta que las 18 piezas estén importadas y la QA
   de §9 esté cerrada.
2. Si alguna build de prueba llegó a 21+, sus perfiles son de QA: se resetean con el
   menú de debug, no se migran.
3. Si por error la tabla vieja llegara a producción, aplicar el plan B de §11
   (entrega única por `WG_Halloween_2130_Rework_2026`) antes de tocar la tabla.

---

## 9. QA

- [ ] Las 20 tarjetas 21-30 muestran nombre, arte, tag y rareza correctos en las dos vías.
- [ ] Cobrar cada tramo deja el objeto en propiedad y persiste tras reiniciar.
- [ ] Ningún tramo se puede cobrar dos veces.
- [ ] Cada skin se equipa en blancas y negras; reemplaza el sprite, respeta escala y
      sombra, no arrastra tinte ni aura.
- [ ] Las 5 `_black` en uso cargan desde su PNG (no desde el horneado): comprobar
      en el log que no aparece el warning de arte negro faltante. El par del Peón
      Golosina se conserva como asset, sin entrar en juego.
- [ ] Blanca y negra de la misma skin se distinguen a 78 px sobre casilla clara y
      oscura.
- [ ] Las 5 skins disponibles no aparecen en el Atelier ni en Tus Piezas; sí en el
      inventario cuando se poseen.
- [ ] El Peón Golosina no se lista en tiendas, inventario ni pase, y no se puede
      comprar ni reclamar; sus PNG siguen en `Resources/Pieces/Halloween` para los
      Gummy Bears.
- [ ] Torre Relicario y Reina Maleficio se compran con Dulces en la tienda de la velada,
      llegan al inventario y no aparecen en el Atelier.
- [ ] Las skins del pase no se venden en la tienda de la velada ni se pueden comprar con
      Gambits: el inventario las agrupa en «PASE DE LA VELADA».
- [ ] El visor de la tienda cambia de escultura con los chips, enseña las dos caras en
      las ofertas con `_black` propio y no compra ni equipa nada.
- [ ] Los tableros nuevos se desbloquean, se seleccionan y cargan ambiente + objeto
      8×8 en partida; la grilla coincide.
- [ ] Los fondos nuevos se desbloquean, aparecen en FONDOS de la tienda y se
      equipan al menú; el texto sigue legible.
- [ ] Los tableros/fondos del pase no aparecen en la tienda regular.
- [ ] Promoción: un peón corona con el arte de su nuevo tipo y no conserva el
      tinte/aura del peón; si la dama tiene skin, se aplica al instante.
- [ ] Layout móvil vertical: nombres largos caben sin desbordar la tarjeta y el visor no
      desborda su panel.
- [ ] Build: StreamingAssets y Resources incluidos; consola sin errores ni warnings
      de arte faltante.
- [ ] Perfil nuevo ve la tabla 21-30 definitiva y no hay claves de cobro viejas en
      el guardado de QA.

### 9.1 Comprobaciones automáticas ya pasadas

- **Compilación:** `Assembly-CSharp` con 0 errores y las 15 advertencias previas
  (`CS0649` de campos serializados), usando el compilador del SDK que trae Unity
  6000.6.6f1.
- **Assets:** los 12 PNG existen y sus 12 `.meta` son `textureType: 8` (sprite),
  `alphaIsTransparency: 1`, `spriteMeshType: 0`, con el rect del sprite igual al tamaño
  real de cada PNG y GUID único (sin colisión entre los 1.346 `.meta` del proyecto).
- **Parejas:** IoU de alfa y luminancia a 78 px de las seis (tabla de §10.1).
- **Tableros:** superposición de la grilla al 0.83 sobre los dos PNG 1024×1024; las
  líneas caen en las juntas pintadas.
- **UI:** `MainMenu.uxml` parsea como XML, `MainMenu.uss` tiene las llaves balanceadas
  y los 19 nombres que consulta la tienda existen en el UXML.
- **Visor:** `LoadSprite` recibe el nombre del lote (`hwp_*`, con sufijo `_black`), no la
  ruta con carpeta; `ArtExists` sí recibe la ruta de `Resources/Pieces` que devuelve
  `PiecePath`. Mezclar ambas APIs dejaba las dos caras en blanco.
- **Fondos:** `ShopBackdropSelector` lista un fondo de evento solo cuando está
  desbloqueado; `BackdropManager.Select` dispara `Changed` y el menú repinta el fondo
  sin recargar la escena.
- **Variantes:** `_variantArtSprites` se llena solo en los puntos de entrada de
  variante; el cargador genérico ya no mezcla el arte de las skins. El conjunto
  significa lo que dice y el guardián no depende de que la pieza se haya repintado
  antes.

---

## 10. Producción y prioridades

| Prioridad | Piezas | Archivos | Por qué |
|---|---|---:|---|
| **P0** | Alfil Farol, Caballo Espantapájaros, Rey Carmesí + sus negras; Cementerio Olvidado, Cripta de los Cuervos, Noche de la Cosecha, Salón del Banquete | 12 | Cierran el set (Alfil/Caballo), dan los dos tableros y los dos fondos, y el capstone premium. |
| **P1** | Torre Relicario y Reina Maleficio + sus negras | 4 | Completan la «Corte» premium. |
| **Reservado** | Peón Golosina + su negra | 2 | Producido; se guarda para la invasión de los Gummy Bears, fuera de esta velada. |

**Calendario sugerido (Parte 2, sin fecha fija):**

1. **Día 1:** P0 blancas (3) y aprobación de silueta contra la pieza clásica.
2. **Día 2:** P0 negras (3), superposición 1:1 con su blanca.
3. **Día 3:** tableros (2 ambientes + 2 objetos) y fondos (2).
4. **Día 4:** P1 (2 blancas + 2 negras) + procesado completo. El par del Peón
   Golosina ya está producido y se archiva para los Gummy Bears.
5. **Día 5:** integración en Unity + import + build.
6. **Día 6:** QA de cobros, equipamiento, lados, tableros y fondos.
7. **Buffer:** 1-2 días antes de abrir la Parte 2.

Si Flow rate-limita o el tiempo no alcanza: ship P0 (12 archivos) y deja P1 para un
parche de contenido. La Parte 2 funciona igual con esas 7 piezas; las otras 2 skins se
agregan después sin tocar la UI. Como el `_black` cae al horneado si falta, también se
puede abrir con las blancas y soltar las negras en caliente.

### 10.1 Estado del arte (P0 + P1 + reserva)

Producido y aprobado en Flow; PNG con alfa en `Assets/Resources/Pieces/Halloween/`.
El par del Peón Golosina está terminado, pero no se distribuye en esta velada: queda
archivado para la invasión de los Gummy Bears.

| Skin | Blanca | Negro | IoU silueta | Lum. 78 px (B/N) |
|---|---|---|---|---|
| Alfil Farol | `hwp_bishop_lantern` 438×900 | `hwp_bishop_lantern_black` 393×900 | 0.81 | 69 / 54 |
| Peón Golosina **(reservado)** | `hwp_pawn_candy` 546×900 | `hwp_pawn_candy_black` 544×900 | 0.99 | 128 / 55 |
| Caballo Espantapájaros | `hwp_knight_scarecrow` 511×900 | `hwp_knight_scarecrow_black` 509×900 | 0.95 | 118 / 52 |
| Torre Relicario | `hwp_rook_reliquary` 562×900 | `hwp_rook_reliquary_black` 564×900 | 1.00 | 117 / 49 |
| Reina Maleficio | `hwp_queen_hex` 689×900 | `hwp_queen_hex_black` 688×900 | 0.99 | 161 / 63 |
| Rey Carmesí | `hwp_king_crimson` 750×900 | `hwp_king_crimson_black` 752×900 | 1.00 | 122 / 54 |

- El Alfil negro conserva la silueta pero redibuja las costillas del farol: se acepta por
  lectura a 78 px (ámbar vs verde frío), aunque es el par más flojo del lote.
- El Rey se generó dos veces: en 3:4 la corona ancha se salía del marco y el recorte
  dejaba sombra pegada al borde; en 1:1 entra completa con margen. La Reina negra siguió
  el mismo camino para que su corona ancha no tocara el borde.
- **Desviación de la Reina blanca:** el primer intento (espino negro, lum 62) quedaba
  demasiado oscuro frente a su negra (lum 50, delta 12) y los bandos no se distinguían.
  Se rehízo en madera de fresno pálida con perlas violeta (lum 160). También se quitaron
  las telarañas del negativo de la corona: cerraban los huecos en V y el key se tragaba
  fondo blanco opaco dentro del alfa.
- Pipeline: `Tools/build_pase_velada_sprites.py` (fondo a blanco → key desde todo el
  borde → alfa → 900 px de alto) y `Tools/check_skin_pair.py` (IoU + luminancia a 78 px).

### 10.2 Estado del arte (P0) — tableros y fondos

Producido en Flow y procesado; verificado con overlay de grilla y mock de partida a
78 px de casilla.

| Pieza | Archivos | Tamaño | Peso |
|---|---|---|---|
| Cementerio Olvidado | `bg_halloween_graveyard.jpeg` · `bg_halloween_graveyard_board.png` | 1376×768 · 1024×1024 | 301 KB · 2,0 MB |
| Cripta de los Cuervos | `bg_halloween_crypt.jpeg` · `bg_halloween_crypt_board.png` | 1376×768 · 1024×1024 | 284 KB · 1,8 MB |
| Noche de la Cosecha | `backdrop_halloween_harvest.jpg` | 2752×1536 | 653 KB |
| Salón del Banquete | `backdrop_halloween_banquet.jpg` | 2752×1536 | 734 KB |

- **Grilla 0.83 exacta.** El detector va en dos pasos: contraste de paridad para el
  orden de magnitud y enganche de las 7 juntas interiores al perfil de bordes con
  ajuste lineal. El primer paso solo dejaba las líneas centrales 5-8 px fuera.
- **Bordes estrechos.** El primer Cementerio y la primera Cripta salieron con marcos
  de 12,5 % y 19,5 % por lado; a 0.83 eso obligaba a recortar 19 y 62 px por lado
  (media calavera en la Cripta). Se regeneraron pidiendo un borde de media casilla:
  quedaron en 8,0 % y 8,3 %, así que entran completos sin deformar.
- **Sin compresión de marco.** El pipeline conserva un modo `squeeze` (comprime solo
  el borde, grilla intacta) por si un tablero futuro no entra; estos dos no lo usan.
- **Ambiente y objeto son capas distintas:** el JPEG va en `Board/` como fondo y el
  PNG con alfa se dibuja encima; `BoardArtInnerFraction` alinea la grilla con las
  casillas. El mock confirma que las piezas caen centradas.
- **El canto roto del Cementerio es del arte**, no del key: la laja tiene piedra
  partida en el borde superior. Se aceptó por tema; la Cripta tiene marco cerrado.
- Pipeline: `Tools/build_halloween_boards.py` y `Tools/build_halloween_scenery.py`.
  Crudos archivados en `_art-source/Halloween/` (`halloween_*_raw.jpg` de escenarios
  y `halloween_*_board_v3_original.jpg` de tableros).

---

## 11. Alternativas y descartes

- **Reusar `hwp_knight_skeleton`, `hwp_bishop_vampire`, `hwp_king_vampire`,
  `hwp_queen_witch`:** descartado como skins del pase porque ya son variantes del modo
  Candy; reusarlas mezcla identidades y no aporta arte nuevo. Sirven como **plan B**
  si Flow falla y hay que ship ya.
- **Más skins de piedra agrietada:** descartado; los niveles 1-20 ya tienen cuatro
  esculturas de piedra. La segunda mitad debe cambiar de material.
- **Variantes y animaciones nuevas:** excluidas por pedido.
- **Tercer tablero / cuarto fondo:** stretch; no es parte del núcleo.
- **Cambiar la economía de Luna:** no; se conservan los 126 Dulces y 2.000 Gambits.
- **Sangre sin Dulces (4.200 Gambits):** descartado; la vía premium reparte 52 Dulces
  y 1.600 Gambits para que el cierre se sienta recompensado y para financiar las dos
  piezas de la Corte que se compran en la tienda. La variante sink estricto (20 Dulces)
  queda en §3.2.
- **Hornear el lado negro en runtime:** descartado como entrega final; se generan los
  6 `_black` (el del Peón Golosina queda reservado para los Gummy Bears). El horneado
  queda solo como red de seguridad si un PNG falta.
- **Migración de cobros:** innecesaria; 21-30 no se publicó (Parte 2). Ver §8.3.

---

## 12. Decisiones

Cerradas:

1. **Full-art.** Las cinco skins distribuidas reemplazan el sprite en partida vía
   `ArtSkinPaths`; no son tinte + thumbnail. El Peón Golosina queda fuera del catálogo
   y su arte se reserva para los Gummy Bears.
2. **Sangre reparte Dulces.** 52 Dulces y 1.600 Gambits en 21-30 (vía: 182 Dulces y
   3.890 Gambits). Los tramos de la Torre y la Reina se convierten en Dulces para
   comprarlas en la tienda. La variante sink estricto queda documentada en §3.2.
3. **`_black` propios.** Se generan 6 PNG negros desde su blanca aprobada; el del Peón
   Golosina se archiva para el evento de los Gummy Bears y el horneado en runtime queda
   solo como respaldo.
4. **Sin migración.** 21-30 pertenece a la Parte 2 y no se publicó; no hay cobros que
   rescatar.
5. **La Corte baja a la tienda.** Torre Relicario (125 Dulces) y Reina Maleficio
   (165 Dulces) se venden en la tienda de la velada; la pestaña SKINS estrena un visor
   con las dos caras como única mejora extra del escaparate: la blanca siempre y la
   negra cuando la pieza ya trae su `_black` propio.

Pendiente:

6. **Nombres e ids de §4.** Son los que quedan persistidos en PlayerPrefs: una vez
   que la Parte 2 salga, cambiarlos obliga a migrar el inventario.
