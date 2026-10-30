# Tema de UI — Obsidiana y Latón

Capa visual del Wilder Gambit (UI Toolkit). Reemplaza el "chrome" plano hecho a
mano con placas de latón sobre obsidiana, sin tocar el layout ni el cableado de
los controladores.

- **Hoja de tema:** `Assets/_Project/UI/WgTheme.uss` (se carga al final).
- **Kit de arte:** `Assets/Resources/UI/Wg/` (10 PNG).
- **Fuentes del arte:** `_art-source/UI-Kit/` (crudos de Flow + previews).
- **Herramientas:** `Tools/make-ui-plate.ps1`, `Tools/build-ui-kit.ps1`,
  `Tools/check-uss.ps1`, `Tools/verify-ui.ps1`.
- **Importación:** `Assets/_Project/Editor/WgUiArtImport.cs` (sprites, alpha, 9-slice).
- **Chequeo headless:** `Assets/_Project/Editor/WgUiCheck.cs` (menú
  *Wilder Gambit › Reimportar sprites del TEMA UI* y `-executeMethod WilderGambit.Editor.WgUiCheck.Run`).

## Paleta

| Token | Hex | Uso |
|---|---|---|
| ink-0 | `#05070e` | fondo profundo, backdrops |
| ink-1 | `#0b1220` | cuerpo de panel |
| ink-2 | `#101a2c` | superficie elevada |
| ink-3 | `#16233a` | hover |
| brass | `#c9a84a` | filo, iconos, líneas |
| brass-hi | `#e8c46a` | highlight, texto activo |
| text | `#f3eedf` | texto principal |
| muted | `#9fb0c8` | texto secundario |
| emerald | `#37c08a` | positivo / piezas |
| crimson | `#c0524f` | peligro / salir |
| violet | `#8e7be0` | Velada / Cacería |

## Kit de placas

Todas las placas se generaron con Google Flow (Nano Banana 2.1, skill
`ows-unity-flow`) y después pasaron por `make-ui-plate.ps1`, que recorta las
cuatro esquinas reales y estira solo los tramos rectos: así el 9-slice no
deforma la filigrana. El `-unity-slice-*` de la hoja y el `spriteBorder` del
importador dicen lo mismo; `check-uss.ps1` falla si se desalinean.

| PNG | Tamaño | Borde 9-slice (L/B/R/T) | Se usa en |
|---|---|---|---|
| `wg_window.png` | 1400×880 | 150/150/150/150 | `.shop2-window` (tienda, inventario, progreso, pases, misiones) |
| `wg_panel.png` | 1200×760 | 130/130/130/130 | `.modal-dialog`, `.settings-modal-dialog`, `.candy-modal` |
| `wg_card.png` | 480×640 | 72/72/72/72 | `.bg-card`, `.diff-card`, `.btn-inventory`, `.candy-side`, `.candy-score-card` |
| `wg_btn.png` | 620×180 | 110/40/110/40 | `.btn-primary`, `.cta-start` |
| `wg_btn_dark.png` | 620×180 | 110/40/110/40 | `.btn-pieces`, `.btn-modal-close`, `.candy-btn-primary` |
| `wg_tile.png` | 560×140 | 30/30/30/30 | `.menu-tile`, `.btn-secondary`, `.btn-danger`, `.candy-topbar` |
| `wg_chip.png` | 320×96 | 26/18/26/18 | `.menu-wallet`, `.shop2-chip`, `.shop2-tab`, `.candy-chip`, `.candy-hand-card`, `.candy-btn` |
| `wg_banner.png` | 1000×220 | — (estirada) | `.modal-title` |
| `wg_divider.png` | 900×48 | — (scale-to-fit) | `.section-divider` |
| `wg_medal.png` | 240×240 | — (scale-to-fit) | `.diff-avatar-wrap`, `.separator-diamond` |

`wg_scroll.png` (pomo de scrollbar) queda generado pero **sin usar**: los rieles
se resuelven por color en la sección 9 de la hoja.

## Placas de los atajos y marcos de los pases

Segunda tanda de Flow (Nano Banana 2.1), esta vez **sin 9-slice**: las cinco
fichas de atajo tienen un tamaño fijo, así que cada placa se generó ya con la
proporción exacta de su hueco y se dibuja con `stretch-to-fill` sobre una
textura a 2x. Se evita el corte de esquinas y el bisel no se deforma.

| PNG | Tamaño | Se usa en |
|---|---|---|
| `wg_tile_candy.png` | 338×160 | `.plate-candy` — CACERÍA DE DULCES (cobre y miel) |
| `wg_tile_shop.png` | 338×160 | `.plate-shop` — TIENDA (bronce viejo) |
| `wg_tile_settings.png` | 338×160 | `.plate-settings` — AJUSTES (acero pizarra) |
| `wg_tile_progress.png` | 524×160 | `.plate-progress` — PROGRESO (oliva y oro viejo) |
| `wg_tile_quit.png` | 524×160 | `.plate-quit` — SALIR (sangre de buey y hierro) |
| `wg_pass_season.png` | 600×354 | `.menu-pass-frame-season` — marco completo del Pase de Temporada (300×177) |
| `wg_pass_halloween.png` | 600×410 | `.menu-pass-frame-halloween` — marco completo del Pase de Halloween (300×205) |

- Carpeta: `Assets/Resources/UI/Menu/` (texturas `textureType 0`, sin mipmaps,
  `alphaIsTransparency`).
- La placa trae el marco pintado en el PNG: la ficha va con `border-width: 0` y
  `background-color: transparent` para no recortar la filigrana ni teñir los
  cantos con el color de fondo del botón.
- El tint sigue el mismo truco que el resto del tema: 92 % en reposo, 100 % en
  hover y 78 % al pulsar.
- Los marcos de los pases abrazan el **botón entero** (lámina + rótulo), no solo
  la ilustración. Por eso cada pase tiene su PNG con la proporción exacta de su
  tarjeta: 600×354 para temporada (300×177) y 600×410 para Halloween (300×205).
  Se construyeron por franjas: la banda superior e inferior se escalan a lo
  ancho y solo se estira el tramo recto central, de modo que la corona y las
  esquinas no se deforman.
- El marco va como última capa de la entrada, con `position: absolute` a los
  cuatro bordes y tinte 235 → 255 al pasar el cursor. La tarjeta pierde borde y
  radio (`border-width: 0`, `overflow: visible`) para no recortar la filigrana.
- El contenido se retira 10 px de cada borde y los rótulos se achican (224×20 y
  202×40) para entrar en el hueco que dejan los remates inferiores.

## Feedback de hover

USS no tiene filtros: no se puede aclarar una imagen al hacer hover. El truco
del tema es que el estado de reposo va con `-unity-background-image-tint-color`
al ~80 % y el hover al 100 %, así la placa "se enciende". Los estados de
`:hover`/`:active`/`:disabled` y los `scale`/`translate` que ya existían se
mantienen.

## Regenerar una placa

```powershell
# 1) Generar (0 puntos). Prompt en inglés, fondo blanco plano, sin texto.
node scripts/flow-gen.js gen --name wg_panel --size 1200x700 --outdir "<proj>\_art-source\UI-Kit" `
  --prompt "Fantasy game UI dialog panel, medium wide rectangular window plate, ... flat pure white background ..."

# 2) Rehacer 9-slice (ajustar -Width/-Height/-CornerX/-CornerY)
powershell -ExecutionPolicy Bypass -File Tools/make-ui-plate.ps1 `
  -In "_art-source\UI-Kit\wg_panel_keyed.png" -Out "Assets\Resources\UI\Wg\wg_panel.png" `
  -Width 1200 -Height 760 -Corner 130

# 3) Verificar sin abrir Unity
powershell -ExecutionPolicy Bypass -File Tools/check-uss.ps1 -Verbose
```

Si cambia el tamaño canónico de una placa hay que actualizar **tres** lugares:
`Tools/build-ui-kit.ps1`, `WgUiArtImport.cs` (borde del sprite) y
`WgTheme.uss` (`-unity-slice-*`). `check-uss.ps1` detecta la desalineación.

## Estado y pendientes

Cubierto por esta capa: menú principal, selector de dificultad, ajustes, tienda,
inventario, progreso, pase de temporada, pases y misiones de la Velada, modo
Cacería de Dulces (incluido su tablero y sus modales), y el HUD de pausa (que
mantiene su paleta de pergamino: solo se le agregó marco y se le unificó el
tratamiento de botones).

Pendiente (segunda pasada), todo en **uGUI**, no en UI Toolkit:

- `GameOverModal.cs` (resultado de partida) — Canvas/Image con el arte de
  `Resources/UI/Victory`.
- `PromotionModal.cs`, `TributoModal.cs`, `UiFeedback.cs`, `CinematicPlayer.cs`.
- HUD del tablero (`BoardView.cs`) y las animaciones del reloj.

Para una pasada por esos hay que decidir si se migran a UI Toolkit o se les
cambia el arte de uGUI; el kit actual (medalla, banners, divisores) ya sirve
para ambos casos.
