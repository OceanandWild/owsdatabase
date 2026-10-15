# WILDSEA REALMS — Prompts de sprites de UI (Partida / Modo Clásico)

Documento de referencia para el arte de `WSGameUI`. Cada entrada dice **qué pieza es**,
**dónde se usa**, **a qué tamaño se dibuja**, **qué restrictions tiene** y **el prompt**
para generarla.

> **Estado actual.** La UI de la partida ya funciona **completa sin estos sprites**: todo
> el chrome que hoy falta está hecho con USS (bordes anidados, radios, rombos rotados
> 45°) + el arte que el proyecto ya tenía (`WS_bg_space_nebula`, `WS_panel_glass`,
> `WS_panel_tall`, `WS_card_nameplate`, `WS_btn_universal`, `WS_card_back`).
> Cuando estas piezas existan, se Connectean por `Resources.Load("WS/GameUI/<nombre>")`
> y **borran** su contraparte USS. No hay que tocar nada más: el código ya avisa por
> consola si un sprite no está y sigue con el plan B.

## Reglas de la casa (aplican a todos los prompts)

Ver `WILDSEA-ART-SPRITES.md` y el set ya existente. En resumen:

- **Fondo TRANSPARENTE.** Nada de fondo negro, blanco ni degradado de "estudio". El
  sprite va recortado sobre el que se le pone debajo.
- **Sin texto en el sprite.** Las etiquetas ("VS", "PUNTOS", "TU MAZO", los números)
  las pone la UI en runtime: si van quemadas en la imagen no se pueden traducir ni
  cambiar de tamaño.
- **1×**, resolución exacta de la columna "Lienzo", sin subir de escala.
- **Borde transparente de 2 px.** UI Toolkit no tiene recorte de 9 slices en background,
  así que el sprite se estira a la caja: nada de contenido vital pegado al borde.
- **Oro del proyecto:** `#E8C86D` sombra, `#FFD75A` luz. **Azul del proyecto:**
  `#55D9EE` acento frío, `#236B8B` acento oscuro. Fondo de la escena: `#06142B`.
- **Estilo:** filigrana de metal noble sobre vacío, no illustration, no 3D render con
  luz de estudio. Debe leerse a **48 px de alto** (el tamaño real en pantalla).

---

## 1 · Escudo VS del centro del tapete

**Se usa en:** `BuildCrest()` — el rombo dorado con "VS" entre las dos mitades de la mesa.
**Reemplaza a:** los cuatro rombos concéntricos + las cuatro puntas de USS.
**Lienzo:** 512 × 512 · se dibuja a ~132 px en 1080p.

```
Ornate heraldic crest badge, isolated on transparent background, centered.
A vertically oriented kite/shield silhouette with a small notch at top and bottom,
built from three concentric gold beveled frames. The outer frame ends in four sharp
diamond finials at its cardinal points. Two symmetrical acanthus scroll flourishes
curl outward from the left and right sides. Deep navy enamel core, matte, no text,
no emblem inside. Aged polished gold metal, subtle cyan rim light on the upper left
edge. Flat vector illustration, crisp edges, no drop shadow, no glow, no background.
```

**Al integrarlo:** el centro del sprite **queda hueco** (donde va el `Label` "VS") y el
anillo exterior tiene que caber en un cuadrado: nada sobresale del 50 % del lienzo en
ningún eje.

---

## 2 · Marco del tapete (filigrana de esquina)

**Se usa en:** `BuildArena()`, capa `arena-glass`.
**Reemplaza a:** `WS_panel_glass.png` al 34 % + el filete USS de 2 px.
**Lienzo:** 2048 × 1152 · se dibuja a ~1600 × 620 en 1080p (se estira).

> ⚠️ Se estira mucho en horizontal (de 16:9 a ~2.6:1). **El diseño tiene que tolerar
> estirado**: que la filigrana viva solo en las esquinas y el resto sean rieles
> horizontales simples. Si en vez de esto se hace un marco con ornamentación repartida,
> estirado lo va a deformar.

```
Wide ornamental frame, isolated on transparent background, full canvas.
Only the four corners carry detail: symmetrical gold acanthus scroll filigree
growing inward from each corner, plus a small eight-pointed star nestled in each
corner's curl. The four edges are plain: a single thin double gold rule, the outer
line brighter, the inner line dimmer, running straight from corner to corner.
Everything between the corners is fully transparent — no fill, no tint, no gradient.
Flat vector illustration, crisp, aged polished gold, no drop shadow, no glow, no text.
```

**Al integrarlo:** entra con `unityBackgroundImageTintColor` en 0.30–0.40 sobre la
nebulosa. Si el sprite trae relleno translúcido, ese relleno se multiplica y enturbia.

---

## 3 · Riel lateral (marco alto)

**Se usa en:** `BuildRail()`, envuelve las tres piezas de cada riel.
**Reemplaza a:** el doble filete USS + el velo de color plano.
**Lienzo:** 512 × 2048 · se dibuja a ~132 × 600 en 1080p (se estira ~3× en vertical).

> ⚠️ Mismo aviso: se estira mucho. Solo esquinas con filigrana + rieles simples.

```
Tall narrow ornamental panel frame, isolated on transparent background, full canvas.
Detail only in the four corners: gold filigree scrolls curling inward, each corner
finished with a tiny four-pointed sparkle. The two long vertical edges are plain thin
double gold rules. The interior is completely transparent, no fill, no vignette.
Flat vector illustration, crisp, aged polished gold, no shadow, no glow, no text.
```

---

## 4 · Medallón de puntos

**Se usa en:** `BuildMedallion()` — el disco con el avance sobre el objetivo.
**Reemplaza a:** los dos círculos USS + la joya y el colgante.
**Lienzo:** 512 × 512 · se dibuja a ~92 px en 1080p.

> El sprite se usa en una caja **circular**: el círculo del sprite tiene que ser
> centrado y del mismo diámetro que el lienzo, o el borde se ve descentrado.

```
Ornate circular medallion, isolated on transparent background, centered, filling
the canvas edge to edge as a true circle. A ring of small gold beads around the
outer rim, then a smooth polished gold band, then a thin inset circle. Twelve tiny
notches divide the band like a dial. A single small gold diamond jewel set at twelve
o'clock on the outer rim and a small teardrop pendant at six o'clock. The disc face
itself is deep navy enamel, matte, completely empty — no number, no text.
Flat vector illustration, crisp, aged polished gold, no shadow, no glow.
```

---

## 5 · Pila de mazo (tres reversos escalonados)

**Se usa en:** `FillRailPile()` — las dos pilas de cada riel (mazo y cartas en juego).
**Reemplaza a:** tres llamadas a `WSCardArt.BuildBackTile()` superpuestas.
**Lienzo:** 512 × 960 · se dibuja a ~88 × 165 en 1080p.

```
Three playing cards seen as a neat stack, isolated on transparent background,
the stack offset diagonally: each card behind peeks out a few pixels to the lower
right. The top card shows its full face design: dark navy field, thin cyan border,
a large eight-pointed gold star in the centre, small gold corner filigree. The two
cards behind are the same design at lower opacity, reading as depth. Clean crisp
edges, flat vector illustration, no drop shadow, no background, no text.
```

> **Ojo:** si este sprite entra, la opacidad por capa que hoy hace `FillRailPile()`
> se aplica al sprite entero y se pierde el escalonado de opacidades. Conviene entonces
> dibujar la pila YA con el escalonado horneado y dejar `dim` como un único valor.

---

## 6 · Placa de la barra de ayuda

**Se usa en:** `BuildBottomBar()`, capa `hint-plate`.
**Reemplaza a:** `WS_card_nameplate.png` al 55 %.
**Lienzo:** 2048 × 192 · se dibuja a ~600 × 38 en 1080p (se estira).

```
Wide horizontal ornamental nameplate bar, isolated on transparent background,
full canvas. Thin gold double rule along the top and bottom edges that stop short
before the corners and close into a small elongated hexagon in the very centre.
Delicate gold scroll filigree in the left and right ends. The whole central band is
completely transparent — no fill, no gradient, no tint. The plate must stay legible
when an opaque text label is drawn across its centre.
Flat vector illustration, crisp, aged polished gold, no shadow, no glow, no text.
```

> La banda central **tiene** que quedar vacía: es donde va el texto de ayuda, que cambia
> con el objetivo y con el estado del turno.

---

## 7 · Botón "Terminar turno"

**Se usa en:** `BuildBottomBar()`.
**Reemplaza a:** `WS_btn_universal.png` teñido de oro.
**Lienzo:** 1024 × 256 · se dibuja a ~190 × 38 en 1080p (se estira ~1.5×).

```
Gold pill button plate, isolated on transparent background, full canvas. A rounded
pill outline in bright gold, a slightly thinner inner outline inset a few pixels, and
a very subtle dark navy fill inside so the button reads as a solid surface when it is
tinted. Small eight-pointed stars at the left and right ends of the pill, just inside
the outline. Entirely empty in the middle — no text, no icon. The outer 3 % of the
canvas on every side must be fully transparent.
Flat vector illustration, crisp edges, polished gold, no shadow, no glow.
```

> El botón se **tiñe entero** (`unityBackgroundImageTintColor`) para diferenciar el
> estado activo del apagado. Un sprite con degradado propio se va a ver raro teñido:
> mejor que el relleno sea casi liso.

---

## 8 · Punto de chip del header (opcional)

**Se usa en:** `Chip()` — los tres chips de arriba.
**Reemplaza a:** el rombo `◆` / `●` / `▣` de texto.
**Lienzo:** 128 × 128 (se dibuja a ~9 px).

```
Tiny gold four-pointed sparkle diamond with a bright core and four short tapered
rays, isolated on transparent background, centered, occupying about 60 % of the
canvas. Simple, sharp, readable at very small size. Flat vector, no glow, no shadow.
```

> Los chips son de ancho **variable** (el objetivo puede ser largo), así que este
> sprite va como pieza suelta pegada al texto, no como fondo del chip.

---

## Receta para integrar un sprite nuevo

1. Generar el PNG con fondo transparente, al tamaño exacto del lienzo de la tabla.
2. Recortarlo a alfa dura (no dejar halo blanco ni semitransparencia residual).
3. **Recomprimir sin perder el canal alfa.** Un PNG de 1024 con filigrana fina no
   puede ir a JPEG ni a palettes: DXT5 comprime el alfa a 1 bit y el filigrana se
   rompe en el borde. Dejar RGBA32 o DXT5 con `alphaIsTransparency`.
4. Guardarlo en `Assets/Resources/WS/GameUI/<nombre>.png`. **Resources, no `_WildSea/Art`**:
   `WSGameUI` lo carga por código con `Resources.Load` en runtime.
5. `WSArtPostprocessor` ya cubre esa carpeta: sin mipmaps para el chrome (el borde
   centellea al escalar), `FullRect` siempre, `Clamp` salvo tiles.
6. Si el nombre empieza con `WS_bg_`, entra con mipmaps y aniso 4: es una foto escalada
   con `Cover`, no una pieza de UI.
7. Cambiar la llamada a `Art("<nombre>")` en el punto correspondiente. Si el sprite no
   aparece, `Art()` avisa una vez por consola y la UI se queda con el plan B en USS —
   **nunca** se rompe la partida por un asset faltante.

## Comprobación

`Assets/_WildSea/Scripts/UI/WSGameUI.cs` compila contra la UI actual. Al pegar los
sprites nuevos, los caminos a reemplazar son:

| Sprite | Punto de código | Qué se borra |
|---|---|---|
| Escudo VS | `BuildCrest()` | `crest.halo/ring/ring2/core`, `CrestTip()` |
| Marco del tapete | `BuildArena()` | capa `arena-glass`, `edge` |
| Riel lateral | `BuildRail()` | `frame` + `frameIn` |
| Medallón | `BuildMedallion()` | `ring`, `MedalPip()`, los bordes circulares |
| Pila de mazo | `FillRailPile()` | las 3 llamadas a `BuildBackTile` |
| Placa de ayuda | `BuildBottomBar()` | `hintPlate` (hoy `WS_frame_hint_plate`) |
| Botón | `BuildBottomBar()` | `endArt` (hoy `WS_btn_plate`) |
