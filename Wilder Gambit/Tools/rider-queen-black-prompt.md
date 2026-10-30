# RiderQueen Negra — Prompt de generación (IA)

> **ESTADO: INTEGRADO (2026-10-09).** Imagen generada por IA con este prompt sobre el JPG
> recibido (`BlackRiderQueen.jpg`, fondo blanco). Se recortó el fondo con flood-fill desde
> los bordes (Python/PIL) y se normalizó a 1065x810 px (463 KB), igual que la pieza blanca.
> Entregada en:
> - `Assets/Resources/Pieces/Black/RiderQueen.png`
> - `Assets/StreamingAssets/Pieces/Black/RiderQueen.png`
> El build headless posterior (exit 0) verificó que el PNG entra en
> `Wilder Gambit_Data/StreamingAssets/Pieces/Black/`. El fallback a reina negra clásica en
> `BoardView.GetRiderQueenSprite` queda como red de seguridad. Pendiente opcional: la animación
> `Resources/RiderQueenIdle/` sigue siendo de la versión blanca (material de tienda/video).

> **Ticket de arte**: falta `Assets/Resources/Pieces/Black/RiderQueen.png` (y su copia en
> `Assets/StreamingAssets/Pieces/Black/`). El código la pide en
> `BoardView.LoadPieceSpritesIfMissing()` y en `SeasonPassModal.LoadVariantArt()`.
> Mientras no exista, `GetRiderQueenSprite(TeamColor.Black)` hace fallback a la reina
> negra clásica (comportamiento actual, no es un error).

## Referencia visual

`Assets/Resources/Pieces/White/RiderQueen.png` — 1065x810 px. Es una reina de hielo
estilo cartoon: corona ancha con cinco esferas brillantes, espada de cristal empuñada
con guante claro, base ovalada, contorno negro grueso, sombreado cel suave.

## Prompt (copiar y pegar)

Adjuntar la imagen de referencia blanca y usar:

```
Using the attached reference image as the exact character reference. Keep the same
pose, composition, silhouette and cartoon outline style: a wide crown with five
glowing orbs on top, a crystalline sword held in the right hand wearing a light
gauntlet, and a smooth oval base, thick dark outline, soft cel shading.

Recolor it as a black-team chess piece: replace every ice-blue and white tone with a
dark obsidian / charcoal palette (body from #2b2f3a to #14161d), and give the crown
orbs and the sword edge a violet-blue and cold cyan glow so the piece stays readable
on dark squares.

Do NOT change the geometry: same crown shape, same number and position of orbs, same
sword angle, same glove, same base, same proportions. Clean fully transparent
background (alpha channel), no cast shadow, no floor reflection, no text, no
watermark, single object centered, uniform thin black outline, 2D game-art asset
style, crisp anti-aliased edges, high detail, approx. 1065x810 px.
```

## Negative prompt (si la herramienta lo soporta)

```
ice-blue body, white body, pale palette, background, scenery, floor, shadow,
text, letters, watermark, signature, blurry, lowres, extra pieces, duplicates,
multiple objects, cropped, oversaturated
```

## Notas de integración

1. Guardar el PNG generado como `RiderQueen.png` (nombre exacto, con esa capitalización).
2. Copiarlo a:
   - `Wilder Gambit/Assets/Resources/Pieces/Black/RiderQueen.png`
   - `Wilder Gambit/Assets/StreamingAssets/Pieces/Black/RiderQueen.png` (fuente que usa el build)
3. No hace falta recortar ni centrar a mano: `BoardView.CreateTrimmedSprite` recorta el
   padding transparente y ajusta el pivote automáticamente, igual que con las demás piezas.
4. Rebuild del juego (editor cerrado) para que salga en el build.

## Herramientas compatibles

- **Midjourney**: subir la blanca como `--cref <url>` y repetir el prompt; `--iw 2` para
  máxima fidelidad de pose.
- **DALL·E / GPT Image / Firefly**: subir como imagen de referencia y pegar el prompt.
- **Stable Diffusion / ComfyUI**: usar IP-Adapter o img2img con la blanca como referencia
  de layout y el prompt de recolor.
