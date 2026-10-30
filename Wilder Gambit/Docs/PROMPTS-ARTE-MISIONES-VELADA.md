# Arte del Modal de Misiones de la Velada — paquete de prompts

Estado: **Tandas 1 y 2 integradas** (25 PNG cableados al modal). Tandas 3–4
pendientes de generar e integrar.

Decoración del modal *MISIONES DE LA VELADA* (`VIEW 10`, prefijo `hwm-` en
`MainMenu.uxml` / `MainMenu.uss`). Hoy el modal vive solo de estilo USS: bordes
de 1 px, gradientes planos y emojis como iconos. Este paquete reemplaza los
contenedores por **marcos vacíos** (el texto lo sigue escribiendo la UI) y los
emojis por **iconos de medallón**, con la misma receta que ya usaron Progreso,
el Cofre y los chips del Pase de Halloween.

## Reglas de la casa (no negociables)

1. Los PNG finales van a `Assets/Resources/UI/Halloween/Missions/`
   (la carpeta cuelga de `Resources/UI/Halloween/`, así que
   `ProgressSpriteImport` ya la cubre con `Wilder Gambit > Reimportar sprites
   de HALLOWEEN`).
2. **Marcos vacíos**: adorno en el borde y las esquinas, interior limpio. El
   texto, las cifras y las barras los pinta la UI encima.
3. **Fondo negro puro** en la generación: es lo que permite el recorte con
   alfa (flood-fill del negro exterior + defringe, mismo camino que
   `Tools/build_halloween_chips.py`).
4. **Sin texto**: ni letras ni números ni signos en el arte.
5. Si un spritesheet no divide exacto por su grilla, primero normalizar canvas
   (`-extent`) y después recortar por grilla + normalizar cada frame centrado
   (pipeline ImageMagick de la regla 6 del workspace).

## Paleta de referencia (tomada del USS del modal)

| Uso | Hex |
|---|---|
| Interior ventana / tarjeta | `#0A0518` · `#180D2A` |
| Topbar / hero / pie | `#12082A` · `#0D0620` |
| Vía Luna (violeta arcano) | `#B98CF0` · `#E0C6FF` · `#7E5CBF` |
| Vía Luna (azul luna) | `#8FA8DD` · `#B9C8EA` |
| Sangre libre (óxido/ámbar) | `#D68254` · `#E0A17C` · `#8E4A2A` |
| Sangre premium (carmesí) | `#B03A5E` · `#FF9FB6` · `#5F1D16` |
| Recompensa / cobrado | `#C9A84A` · `#72C480` · `#9FD6A8` |
| Texto | `#F6EEFF` · `#A293C4` |

## Bloque de estilo común (va al final de TODOS los marcos)

```
gothic halloween chess fantasy aesthetic, flat frontal 2D illustration,
single centered object, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

Con ese bloque ya pegado, cada prompt de abajo queda autocontenido: sirve igual
en DALL·E, GPT Image, Firefly, Midjourney o Stable Diffusion.

## Negative prompt (si la herramienta lo soporta)

```
text, letters, numbers, roman numerals, watermark, signature, logo, UI
mockup, screenshot, background scenery, floor, cast shadow, perspective,
3D render, isometric, blurry, lowres, multiple objects, cropped, extra
objects, chess pieces, grid, checkerboard pattern, photo, oversaturated
```

---

## Tanda 1 — los 12 que más cambian el modal

| # | Slot | Archivo | Canvas final | Dónde vive |
|---|---|---|---|---|
| 1 | Ventana | `hwm_window.png` | 1770×1230 | `shop2-window hwm-window` (9-slice) |
| 2 | Tarjeta Luna | `hwm_card_luna.png` | 2048×172 | `.hwm-mission-luna` |
| 3 | Tarjeta Sangre libre | `hwm_card_sangre.png` | 2048×172 | `.hwm-mission-sangre` |
| 4 | Tarjeta Sangre premium | `hwm_card_premium.png` | 2048×172 | `.hwm-mission-premium` |
| 5 | Tarjeta lista | `hwm_card_ready.png` | 2048×172 | `.hwm-mission-ready` |
| 6 | Tarjeta cobrada | `hwm_card_claimed.png` | 2048×172 | `.hwm-mission-claimed` |
| 7 | Tarjeta bloqueada | `hwm_card_locked.png` | 2048×172 | premium sin vía |
| 8 | Banner Sangre | `hwm_banner.png` | 2048×128 | `.hwm-banner` |
| 9 | Banner Sangre abierta | `hwm_banner_open.png` | 2048×128 | `.hwm-banner-open` |
| 10 | Botón COBRAR | `hwm_claim.png` | 208×64 | `.hwm-claim` |
| 11 | Estado vacío | `hwm_empty_moon.png` | 768×768 | `.hwm-empty` |
| 12 | Emblema | `hwm_crest.png` | 320×320 | hero / ventana |

> **Estado: aplicada.** Los 12 PNG llegaron en `Tanda 1 - Modales`, se
> recortaron con `Tools/build_halloween_missions.py` (fondo por bandas de
> luminancia y croma, cierre morfológico para sellar las fugas finas y
> defringe de 1–2 px) y viven en `Assets/Resources/UI/Halloween/Missions/`.
> Los originales crudos quedaron en `_art-source/Halloween/Missions/`.
>
> | Sprite | Origen | Canvas real | Dónde se aplica |
> |---|---|---|---|
> | `hwm_window` | `Fantasy_game_UI_window_frame` | 1670×1230 | `.hwm-window` + clase `hwm-framed` |
> | `hwm_card_luna` | `Fantasy_game_UI_frame_border` | 2048×172 | tarjeta de la Vía Luna |
> | `hwm_card_sangre` | `Gothic_halloween_game_UI_frame` | 2048×172 | Sangre libre |
> | `hwm_card_premium` | `Fantasy_game_UI_row_frame` | 2048×172 | Sangre premium |
> | `hwm_card_ready` | `Fantasy_game_UI_frame_glowing` | 2048×172 | lista para cobrar |
> | `hwm_card_claimed` | `Fantasy_game_UI_frame_design` | 2048×172 | ya cobrada |
> | `hwm_card_locked` | `Locked_fantasy_game_UI_card` | 2048×172 | premium sin Vía Sangre |
> | `hwm_banner` | `Fantasy_game_UI_banner_plate_2` | 2048×128 | `.hwm-banner` |
> | `hwm_banner_open` | `Fantasy_game_UI_banner_plate` | 2048×128 | `.hwm-banner-open` |
> | `hwm_claim` | `Fantasy_game_UI_button_plate` | 186×64 | `.hwm-claim` |
> | `hwm_empty_moon` | `Halloween_chessboard_and_candles` | 1092×768 | arte del estado vacío |
> | `hwm_crest` | `Chess_tower_and_crescent_moon` | 302×320 | `hwm-crest` del hero |
>
> El cableado: `Scripts/UI/HalloweenMissionsSprites.cs` (slices por familia),
> `HalloweenMissionsModal.cs` (`ApplyChromeArt`, `ApplyBannerArt`, sprite de
> tarjeta por estado y placa del COBRAR) y el bloque «Arte de la ventana» de
> `MainMenu.uss` (bandas con velo, `hwm-crest`, `hwm-empty-art`). En móvil
> vertical el arte se saltea y vuelve el estilo USS; si un PNG falta, cada
> elemento conserva su estilo de siempre.

### 1. `hwm_window.png` — marco de la ventana

```
Fantasy game UI window frame, large panel plate with an aspect ratio close
to 3:2, ornate gothic halloween border in bone-gold and arcane violet, a
pointed-arch pediment at the top center with a small carved crescent moon
flanked by two lit candles, intricate filigree scrollwork in all four
corners with tiny bat and cobweb motifs, thorn vines creeping up the side
rims, double rim with a bright highlight line and a dark bronze shadow
line, a few carved blood droplets along the bottom rim, deep eggplant
interior colors #0A0518 to #180D2A with a smooth vertical gradient,
completely empty clean interior, luxurious spooky metalwork, gothic
halloween chess fantasy aesthetic, flat frontal 2D illustration, single
centered object, uniform flat pure black background for easy background
removal, no shadow, no perspective, no 3D, no text, no letters, no
numbers, no logo, no watermark, high detail ornamental metalwork
```

### 2. `hwm_card_luna.png` — tarjeta de misión (Vía Luna)

```
Fantasy game UI row frame, wide horizontal card, 2048 by 172, slim gothic
halloween border with a thicker rail on the left edge, the left rail in
moonlight blue #8FA8DD and arcane violet #B98CF0 with a small carved
crescent moon near its top, thin double rim with a bright highlight line
and a dark shadow line, small filigree curls in the right corners, a tiny
five-pointed star at the right end, deep eggplant interior colors #0A0518
to #180D2A with a smooth vertical gradient, completely empty clean
interior, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 3. `hwm_card_sangre.png` — tarjeta de Sangre libre

```
Fantasy game UI row frame, wide horizontal card, 2048 by 172, slim gothic
halloween border with a thicker rail on the left edge, the left rail in
rust-amber #D68254 fading to dark #8E4A2A with a small carved blood drop
near its top, thin double rim with a bright highlight line and a dark
shadow line, tiny thorn curls in the right corners, deep eggplant
interior colors #140A1E to #1C0F22 with a smooth vertical gradient,
completely empty clean interior, gothic halloween chess fantasy aesthetic,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective,
no 3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

### 4. `hwm_card_premium.png` — tarjeta de Sangre premium

```
Fantasy game UI row frame, wide horizontal card, 2048 by 172, ornate gothic
halloween border with a thicker rail on the left edge, the left rail in
deep crimson #B03A5E with thin thorn vines and a small rose-crown motif
near its top, thin double rim with a bright rose highlight line and a dark
shadow line, small carved blood drops in the right corners, faint bone-gold
#C9A84A accents, deep wine-black interior colors #16070F to #200C18 with a
smooth vertical gradient, completely empty clean interior, precious and
sinister, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 5. `hwm_card_ready.png` — la misma tarjeta, lista para cobrar

```
Fantasy game UI row frame, wide horizontal card, 2048 by 172, slim gothic
halloween border with a thicker rail on the left edge, the left rail in
moonlight blue #8FA8DD and arcane violet #B98CF0 with a small carved
crescent moon near its top, thin double rim with a bright highlight line
and a dark shadow line, small filigree curls in the right corners, a tiny
five-pointed star at the right end, now glowing and inviting: the rim lit
in bright arcane violet #E0C6FF over #B98CF0, a warm golden candle glow
spilling into the interior, tiny golden sparkles and a small crescent moon
at the right end, thin double rim with a very bright highlight line,
interior colors #2A1548 to #3A2260 with a smooth vertical gradient,
completely empty clean interior, gothic halloween chess fantasy aesthetic,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective, no
3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

### 6. `hwm_card_claimed.png` — la misma tarjeta, ya cobrada

```
Fantasy game UI row frame, wide horizontal card, 2048 by 172, slim gothic
halloween border with a thicker rail on the left edge, the left rail in
moonlight blue #8FA8DD and arcane violet #B98CF0 with a small carved
crescent moon near its top, thin double rim with a bright highlight line
and a dark shadow line, small filigree curls in the right corners, a tiny
five-pointed star at the right end, now dimmed and settled: muted
desaturated violet rim, a small jade-green #72C480 embossed wax seal with a
tiny crescent moon stamped in the right corner, interior darker #100A1E to
#180D2A with a smooth vertical gradient, completely empty clean interior,
spent and peaceful, gothic halloween chess fantasy aesthetic, flat frontal
2D illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork
```

### 7. `hwm_card_locked.png` — la misma tarjeta, bloqueada

```
Fantasy game UI row frame, wide horizontal card, 2048 by 172, slim gothic
halloween border with a thicker rail on the left edge, the left rail in
moonlight blue #8FA8DD and arcane violet #B98CF0 with a small carved
crescent moon near its top, thin double rim with a bright highlight line
and a dark shadow line, small filigree curls in the right corners, a tiny
five-pointed star at the right end, now cold and closed: slim grey-violet
rim #6E6486, a small carved padlock with a short hanging chain crossing
the left rail, thin double rim with a faint highlight line, a single dead
thorn, interior very dark #0E0820 to #140A22 with a smooth vertical
gradient, completely empty clean interior, gothic halloween chess fantasy
aesthetic, flat frontal 2D illustration, single centered object, uniform
flat pure black background for easy background removal, no shadow, no
perspective, no 3D, no text, no letters, no numbers, no logo, no
watermark, high detail ornamental metalwork
```

### 8. `hwm_banner.png` — banner de la Vía Sangre (cerrada)

```
Fantasy game UI banner plate, wide horizontal frame, 2048 by 128, ornate
gothic halloween border in rust-amber #D68254 and deep crimson #B03A5E, a
thicker rail on the left edge in crimson, a carved blood drip hanging from
the top rim at the center, thin hanging chains with small rings at both
ends, thorn vines along the rims, double rim with a bright highlight line
and a dark shadow line, deep wine interior colors #16070F to #200C14 with a
smooth vertical gradient, completely empty clean interior, ominous and
ritual, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 9. `hwm_banner_open.png` — el mismo banner, abierto

```
Fantasy game UI banner plate, wide horizontal frame, 2048 by 128, ornate
gothic halloween border in rust-amber #D68254 and deep crimson #B03A5E, a
thicker rail on the left edge in crimson, now opened: the chains broken and
pushed aside, the thorn vines blooming with tiny pale flowers, the rim in
jade green #72C480 with bone-gold #E8C46A accents, a small embossed green
wax seal with a crescent moon in the right corner, thin double rim with a
bright highlight line, deep green-black interior colors #0C1810 to #101E16
with a smooth vertical gradient, completely empty clean interior, relieved
and rewarding, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental
metalwork
```

### 10. `hwm_claim.png` — botón COBRAR

```
Fantasy game UI button plate, small horizontal rounded button, 208 by 64,
ornate halloween rim in bright arcane violet #B98CF0 with a bone-gold
#E8C46A inner line, a tiny carved crescent moon inside the left end, thin
double rim with a very bright highlight line, interior lit with a warm
golden violet gradient #3A2260 to #B98CF0, completely empty clean interior,
inviting and ready to be pressed, gothic halloween chess fantasy aesthetic,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective,
no 3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

### 11. `hwm_empty_moon.png` — arte del estado vacío

Este sí es una ilustración (no un marco): la silueta completa sobre negro.

```
Flat 2D halloween game illustration of a single isolated scene: a large
crescent moon low over an ancient stone chessboard half swallowed by ground
mist, two melting candles in small bone holders burning at the left and
right, one toppled dark knight and one dark pawn silhouette resting on the
stones, cobwebs strung between the candle holders, a few dried autumn
leaves, cold silver-blue moonlight rimming every edge, palette: moonlight
silver #CCD1E6, deep indigo #1A1A38, dark slate #23233F, arcane violet
#B98CF0, faint bone-gold candle glow #E8C46A, painterly semi-realistic 2D
illustration, calm and quiet, the entire scene fully visible and centered,
complete clean silhouette against a uniform flat pure black background with
a margin of black on all four sides for easy background removal, single
centered object, no cast shadow on the black background, no sky, no
horizon, no distant landscape, no people, no text, no letters, no numbers,
no watermark, no signature, no logo, no UI, no frame around the image
```

### 12. `hwm_crest.png` — emblema del modal

```
Flat 2D heraldic game emblem, single centered emblem, 320 by 320, an
antique rook chess tower standing behind a carved crescent moon, a blood
drop set in the middle of a small shield, a thin crown resting on the top,
bone-gold #E8C46A and arcane violet #B98CF0 metal with deep crimson #B03A5E
drip accents at the base, small thorn vines climbing the shield, thin
double rim with a bright highlight line, deep eggplant interior #0A0518,
completely empty clean surface, gothic halloween chess fantasy aesthetic,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective,
no 3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

---

## Tanda 2 — estructura y pestañas

| # | Slot | Archivo | Canvas final | Dónde vive |
|---|---|---|---|---|
| 13 | Banda topbar | `hwm_topbar.png` | 2048×148 | `.hwm-topbar` |
| 14 | Banda hero | `hwm_hero.png` | 2048×168 | `.hwm-hero` |
| 15 | Banda pie | `hwm_footer.png` | 2048×112 | `.hwm-footer` |
| 16 | Pestaña Luna | `hwm_tab_luna.png` | 260×68 | `.hwm-tab` (inactiva) |
| 17 | Pestaña Luna activa | `hwm_tab_luna_on.png` | 260×68 | `.hwm-tab-active` |
| 18 | Pestaña Sangre | `hwm_tab_sangre.png` | 260×68 | `.hwm-tab-sangre` |
| 19 | Pestaña Sangre activa | `hwm_tab_sangre_on.png` | 260×68 | `.hwm-tab-sangre.hwm-tab-active` |
| 20 | Chip XP | `hwm_chip_xp.png` | 260×68 | `.hwm-chip-xp` |
| 21 | Chip Dulces | `hwm_chip_dulces.png` | 260×68 | `.hwm-chip-dulces` |
| 22 | Chip de estado | `hwm_state_chip.png` | 300×52 | `hwm-state-chip` |
| 23 | Divisor Luna | `hwm_rule_luna.png` | 2048×20 | `.hwm-section-line` |
| 24 | Divisor Sangre | `hwm_rule_sangre.png` | 2048×20 | `.hwm-section-line-sangre` |
| 25 | Franja de nota | `hwm_hint_strip.png` | 2048×88 | `.hwm-hint` |

> **Estado: aplicada.** Los 13 PNG llegaron en `Tanda 2` y se procesaron con
> `Tools/build_halloween_missions_tanda2.py`: mismo corte de fondo que la
> Tanda 1, más recorte de la zona central que el 9-slice estira (los adornos
> con borde duro se convertirían en mancha), aplanado del filete con perfil
> mediano en las píldoras e inpaint de la luna que cuelga del pie. Los
> originales crudos quedaron en `_art-source/Halloween/Missions/`.
>
> | Sprite | Origen | Canvas real | Alto pantalla | Dónde se aplica |
> |---|---|---|---|---|
> | `hwm_topbar` | `Fantasy_game_UI_band_frame_2` | 1306×328 | 52 | `.hwm-topbar` |
> | `hwm_hero` | `Fantasy_game_UI_band_frame` | 1350×257 | 88 | `.hwm-hero` |
> | `hwm_footer` | `Gothic_fantasy_UI_frame_banner` | 1312×130 | 28 | `.hwm-footer` |
> | `hwm_hint_strip` | `Fantasy_game_UI_frame_strip` | 1338×212 | 50 | `.hwm-hint` |
> | `hwm_tab_luna` | `Fantasy_game_UI_button_plate_2` | 1224×297 | 34 | pestaña Vía Luna apagada |
> | `hwm_tab_luna_on` | `Glowing_fantasy_game_UI_button` | 1111×405 | 34 | pestaña Vía Luna activa |
> | `hwm_tab_sangre` | `Gothic_fantasy_game_UI_button` | 1309×318 | 34 | pestaña Vía Sangre apagada |
> | `hwm_tab_sangre_on` | `Fantasy_game_UI_button_plate` | 1165×361 | 34 | pestaña Vía Sangre activa |
> | `hwm_chip_xp` | `Fantasy_game_UI_stat_chip` | 1110×286 | 32 | `.hwm-chip-xp` |
> | `hwm_chip_dulces` | `Fantasy_game_UI_stat_frame` | 1148×372 | 32 | `.hwm-chip-dulces` |
> | `hwm_state_chip` | `Fantasy_game_UI_badge_frame` | 1274×237 | 28 | `.hw-state-chip` |
> | `hwm_rule_luna` | `Gothic_Halloween_ornamental_divider` | 1319×103 | 15 | `.hwm-section-line` |
> | `hwm_rule_sangre` | `Gothic_ornamental_divider_line` | 1276×128 | 15 | `.hwm-section-line-sangre` |
>
> **Aspecto natural:** a diferencia de la tabla de arriba (canvas orientativo
> de generación), cada PNG conservó el aspecto propio de su arte: los JPG
> llegaron con encuadres distintos y forzarlos al target plano deformaba el
> ornato. La escala de dibujo sale del alto real en pantalla
> (`Frame.TargetHeight` de `HalloweenMissionsSprites.cs`), así el 9-slice se
> pinta a la escala correcta de uso sin importar el canvas de origen.
>
> El cableado: constantes y wrappers en `Scripts/UI/HalloweenMissionsSprites.cs`
> (`ApplyTopbar`, `ApplyHero`, `ApplyFooter`, `ApplyHint`, `ApplyTab`,
> `ApplyChip`, `ApplyStateChip`, `ApplyRule`), los ganchos de
> `HalloweenMissionsModal.cs` (`ApplyBandArt` y `ApplyTabArt` desde
> `ApplyChromeArt`/`ShowTab`, con `ClearBandArt` al volver a vertical) y el
> bloque `.hwm-skinned` de `MainMenu.uss` (quita fondo, borde y radio cuando
> el PNG está importado; si falta, cada elemento conserva su estilo USS).

### 13. `hwm_topbar.png`

```
Fantasy game UI band frame, thin horizontal strip bar, 2048 by 148, ornate
gothic halloween top rail in bone-gold #E8C46A and violet #B98CF0, slim
double rim with a bright highlight line and a dark bronze shadow line, tiny
crescent-moon and star flourishes at both ends, a small downward finial in
the center of the bottom edge, deep eggplant interior colors #0A0518 to
#12082A with a smooth vertical gradient, completely empty clean interior,
gothic halloween chess fantasy aesthetic, flat frontal 2D illustration,
single centered object, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 14. `hwm_hero.png`

```
Fantasy game UI band frame, thin horizontal strip bar, 2048 by 168, ornate
arcane halloween band in cold silver-violet #8FA8DD and #B98CF0, slim double
rim with a bright highlight line, a five-pointed star and a crescent moon at
each end, a tiny hanging cobweb in one corner, deep eggplant interior colors
#0A0518 to #0D0620 with a smooth vertical gradient, completely empty clean
interior, mystical and calm, gothic halloween chess fantasy aesthetic, flat
frontal 2D illustration, single centered object, uniform flat pure black
background for easy background removal, no shadow, no perspective, no 3D,
no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

### 15. `hwm_footer.png`

```
Fantasy game UI band frame, very thin horizontal strip bar, 2048 by 112,
slim gothic halloween foot rail in bone-gold #E8C46A and violet #B98CF0
with a dark bronze shadow line, small corner curls and a single tiny carved
crescent moon at the center of the top edge, deep eggplant interior colors
#0A0518 to #12082A with a smooth vertical gradient, completely empty clean
interior, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 16–17. `hwm_tab_luna.png` / `hwm_tab_luna_on.png`

```
Fantasy game UI button plate, small horizontal rounded pill, 260 by 68, slim
arcane halloween rim in moonlight blue #8FA8DD and arcane violet #B98CF0
with a tiny carved crescent moon at the left end, thin double rim with a
bright highlight line, deep eggplant-black interior #0A0518, completely
empty clean interior, muted and unlit, gothic halloween chess fantasy
aesthetic, flat frontal 2D illustration, single centered object, uniform
flat pure black background for easy background removal, no shadow, no
perspective, no 3D, no text, no letters, no numbers, no logo, no watermark,
high detail ornamental metalwork
```

Variante encendida (prompt completo, copiar y pegar tal cual):

```
Fantasy game UI button plate, small horizontal rounded pill, 260 by 68, slim
arcane halloween rim in moonlight blue #8FA8DD and arcane violet #B98CF0
with a tiny carved crescent moon at the left end, the rim lit bright, the
carved crescent moon in pale bone-gold, thin double rim with a very bright
highlight line, interior a luminous arcane violet gradient #B98CF0 to #7E5CBF
with faint star sparkles, completely empty clean interior, glowing and
selected, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 18–19. `hwm_tab_sangre.png` / `hwm_tab_sangre_on.png`

```
Fantasy game UI button plate, small horizontal rounded pill, 260 by 68, slim
gothic halloween rim in rust-amber #D68254 and deep crimson #B03A5E with a
tiny carved blood drop at the left end, small thorn accents at both ends,
thin double rim with a bright highlight line, deep eggplant-black interior
#0A0518, completely empty clean interior, muted and unlit, gothic halloween
chess fantasy aesthetic, flat frontal 2D illustration, single centered
object, uniform flat pure black background for easy background removal, no
shadow, no perspective, no 3D, no text, no letters, no numbers, no logo, no
watermark, high detail ornamental metalwork
```

Variante encendida (prompt completo, copiar y pegar tal cual):

```
Fantasy game UI button plate, small horizontal rounded pill, 260 by 68, slim
gothic halloween rim in rust-amber #D68254 and deep crimson #B03A5E with a
tiny carved blood drop at the left end, small thorn accents at both ends,
the rim lit bright, the carved blood drop in bright rose #FF9FB6, thin
double rim with a very bright highlight line, interior a luminous crimson
gradient #B03A5E to #8C2F4C with faint ember specks, completely empty clean
interior, glowing and selected, gothic halloween chess fantasy aesthetic,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective, no
3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

### 20–21. `hwm_chip_xp.png` / `hwm_chip_dulces.png`

```
Fantasy game UI stat chip frame, small horizontal rounded pill, 260 by 68,
slim arcane halloween rim in cold silver-violet #8FA8DD with a tiny carved
five-pointed star at the left end, thin double rim with a bright highlight
line, deep eggplant interior #0A0518 to #140A24 with a smooth vertical
gradient, completely empty clean interior, gothic halloween chess fantasy
aesthetic, flat frontal 2D illustration, single centered object, uniform
flat pure black background for easy background removal, no shadow, no
perspective, no 3D, no text, no letters, no numbers, no logo, no watermark,
high detail ornamental metalwork
```

Chip de Dulces (prompt completo, copiar y pegar tal cual):

```
Fantasy game UI stat chip frame, small horizontal rounded pill, 260 by 68,
slim sweetly sinister halloween rim in crimson and caramel #E07A4F #A3362A
with tiny candy-corn and dripping-caramel motifs and a thin thorn vine, thin
double rim with a bright highlight line, deep eggplant interior colors #0A0518
to #201024 with a smooth vertical gradient, completely empty clean interior,
gothic halloween chess fantasy aesthetic, flat frontal 2D illustration,
single centered object, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 22. `hwm_state_chip.png`

```
Fantasy game UI badge frame, small horizontal rounded pill, 300 by 52, slim
bone-gold halloween rim with a tiny carved lantern at the left end, thin
double rim with a bright highlight line, deep eggplant interior #0A0518 to
#12082A with a smooth vertical gradient, completely empty clean interior,
gothic halloween chess fantasy aesthetic, flat frontal 2D illustration,
single centered object, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 23–24. `hwm_rule_luna.png` / `hwm_rule_sangre.png`

```
Thin horizontal ornamental divider, 2048 by 20, a very slender gothic
halloween rule line, a small carved crescent moon with a tiny five-pointed
star at the left end and a single small star at the right end, the line in
moonlight blue #8FA8DD and arcane violet #B98CF0 with a bright highlight
line along the top and a dark shadow line below, the line tapering and
fading out at both ends, decorated ends only, flat frontal 2D illustration,
uniform flat pure black background for easy background removal, no shadow,
no perspective, no 3D, no text, no letters, no numbers, no logo, no
watermark, high detail ornamental metalwork
```

Divisor de Sangre (prompt completo, copiar y pegar tal cual):

```
Thin horizontal ornamental divider, 2048 by 20, a very slender gothic
halloween rule line, a small carved dagger at the left end and a hanging
blood drop at the right end, the line in rust-amber #D68254 and deep crimson
#B03A5E with a bright highlight line along the top and a dark shadow line
below, the line tapering and fading out at both ends, decorated ends only,
flat frontal 2D illustration, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 25. `hwm_hint_strip.png`

```
Fantasy game UI strip frame, thin horizontal bar, 2048 by 88, slim arcane
gothic halloween rim in dim violet #7E5CBF, a small carved closed book with
a crescent moon on its cover at the left end, thin double rim with a faint
highlight line, deep eggplant interior colors #0A0518 to #12082A with a
smooth vertical gradient, completely empty clean interior, quiet and
scholarly, flat frontal 2D illustration, single centered object, uniform
flat pure black background for easy background removal, no shadow, no
perspective, no 3D, no text, no letters, no numbers, no logo, no watermark,
high detail ornamental metalwork
```

---

## Tanda 3 — acciones, barras y adornos

| # | Slot | Archivo | Canvas final | Dónde vive |
|---|---|---|---|---|
| 26 | Botón COBRAR hover | `hwm_claim_hover.png` | 208×64 | `.hwm-claim:hover` |
| 27 | Píldora base | `hwm_pill.png` | 208×60 | `.hwm-pill` (pendiente) |
| 28 | Píldora bloqueada | `hwm_pill_locked.png` | 208×60 | `.hwm-pill-locked` |
| 29 | Píldora cobrada | `hwm_pill_done.png` | 208×60 | `.hwm-pill-done` |
| 30 | Botón Vía Sangre | `hwm_btn_sangre.png` | 280×64 | `.hwm-banner-btn` |
| 31 | Botón Vía Sangre hover | `hwm_btn_sangre_hover.png` | 280×64 | `.hwm-banner-btn:hover` |
| 32 | Riel de barra | `hwm_bar_track.png` | 2048×16 | `.hwm-mission-bar` |
| 33 | Relleno Luna | `hwm_bar_fill_luna.png` | 2048×16 | `.hwm-mission-fill` |
| 34 | Relleno Sangre | `hwm_bar_fill_sangre.png` | 2048×16 | `.hwm-mission-sangre .hwm-mission-fill` |
| 35 | Esquina Luna | `hwm_corner_luna.png` | 256×256 | ventana / hero |
| 36 | Esquina Sangre | `hwm_corner_sangre.png` | 256×256 | banner / ventana |
| 37 | Separador vertical | `hwm_vrule.png` | 24×256 | hero (textos ↔ pestañas) |
| 38 | Riel de scroll | `hwm_scroll_track.png` | 16×512 | `hwm-body-scroll` |
| 39 | Pulgar de scroll | `hwm_scroll_thumb.png` | 16×256 | `hwm-body-scroll` |
| 40 | Icono pestaña Luna | `icon_tab_moon.png` | 128×128 | pestaña VÍA LUNA |
| 41 | Icono pestaña Sangre | `icon_tab_blood.png` | 128×128 | pestaña VÍA SANGRE |

### 26. `hwm_claim_hover.png`

```
Fantasy game UI button plate, small horizontal rounded button, 208 by 64,
ornate halloween rim in bright arcane violet #B98CF0 with a bone-gold #E8C46A
inner line, a tiny carved crescent moon inside the left end, thin double rim
with a very bright highlight line, now at its brightest: rim almost
white-pale #E0C6FF over #B98CF0, the crescent moon lit bone-gold, interior
flooded with a warm golden violet glow #4A2E7A to #D9B6FF, tiny golden
sparkles at the corners, completely empty clean interior, inviting and ready
to be pressed, gothic halloween chess fantasy aesthetic, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 27–29. Píldoras de estado

Base (pendiente):

```
Fantasy game UI pill frame, small horizontal rounded pill, 208 by 60, slim
dim silver-violet halloween rim, thin double rim with a faint highlight
line, near-black violet interior colors #0A0518 to #180D2A with a smooth
vertical gradient, completely empty clean interior, quiet and neutral, flat
frontal 2D illustration, single centered object, uniform flat pure black
background for easy background removal, no shadow, no perspective, no 3D,
no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

Bloqueada:

```
Fantasy game UI pill frame, small horizontal rounded pill, 208 by 60, cold
grey-violet halloween rim #6E6486, a small carved padlock with a short
hanging chain at the left end and a single dead thorn at the right end,
thin double rim with a faint highlight line, very dark interior colors
#0A0518 to #140A22, completely empty clean interior, closed and cold, flat
frontal 2D illustration, single centered object, uniform flat pure black
background for easy background removal, no shadow, no perspective, no 3D,
no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

Cobrada:

```
Fantasy game UI pill frame, small horizontal rounded pill, 208 by 60, slim
jade-green halloween rim #72C480 with a thin bone-gold inner line, a small
embossed wax seal with a tiny crescent moon at the left end and a laurel
curl at the right end, thin double rim with a bright highlight line, deep
green-black interior colors #0A1610 to #101E16, completely empty clean
interior, settled and rewarding, flat frontal 2D illustration, single
centered object, uniform flat pure black background for easy background
removal, no shadow, no perspective, no 3D, no text, no letters, no numbers,
no logo, no watermark, high detail ornamental metalwork
```

### 30–31. `hwm_btn_sangre.png` / `hwm_btn_sangre_hover.png`

```
Fantasy game UI button plate, small horizontal rounded button, 280 by 64,
gothic halloween rim in deep crimson #B03A5E with a rust-amber #D68254
double line, a tiny carved blood drop at the left end, thin rim with a
bright highlight line, interior a glowing crimson gradient #8C2F4C to
#B03A5E, completely empty clean interior, ominous and inviting, gothic
halloween chess fantasy aesthetic, flat frontal 2D illustration, single
centered object, uniform flat pure black background for easy background
removal, no shadow, no perspective, no 3D, no text, no letters, no numbers,
no logo, no watermark, high detail ornamental metalwork
```

Hover (prompt completo, copiar y pegar tal cual):

```
Fantasy game UI button plate, small horizontal rounded button, 280 by 64,
gothic halloween rim in deep crimson #B03A5E with a rust-amber #D68254
double line, a tiny carved blood drop at the left end lit bright rose, thin
rim with a bright highlight line, interior a hotter crimson gradient #A3362A
to #FF6F8E, the blood drop lit bright rose, small ember specks at the
corners, rim glowing, completely empty clean interior, ominous and inviting,
gothic halloween chess fantasy aesthetic, flat frontal 2D illustration,
single centered object, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark, high detail ornamental metalwork
```

### 32–34. Barra de progreso

Riel:

```
Fantasy game UI progress bar track, very slim horizontal groove, 2048 by
16, a dark recessed trough with a thin bone-gold rim along the top and
bottom edges and small carved notches at both ends, deep eggplant interior
#0A0518 with a smooth vertical gradient, completely empty clean interior,
flat frontal 2D illustration, single centered object, uniform flat pure
black background for easy background removal, no shadow, no perspective, no
3D, no text, no letters, no numbers, no logo, no watermark, high detail
ornamental metalwork
```

Relleno Luna:

```
Fantasy game UI progress bar fill, very slim horizontal bar, 2048 by 16,
glowing arcane violet liquid #B98CF0 to #8C5CD6 with a very bright
highlight line along the top edge, a soft moonlit glow, tiny star sparkles
suspended inside the liquid, rounded capped ends, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark
```

Relleno Sangre (prompt completo, copiar y pegar tal cual):

```
Fantasy game UI progress bar fill, very slim horizontal bar, 2048 by 16,
glowing amber-crimson liquid #D68254 to #B03A5E with tiny ember specks
suspended inside and a thin wax-like drip at the capped ends, a very bright
highlight line along the top edge, rounded capped ends, flat frontal 2D
illustration, single centered object, uniform flat pure black background
for easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark
```

### 35–36. Esquinas ornamentales

```
Flat 2D corner ornament for a game UI panel, single L-shaped corner piece
drawn for the top-left corner, 256 by 256, gothic halloween filigree in
bone-gold #E8C46A and moonlight blue #8FA8DD, a small crow perched on the
ornament with a cobweb clinging to it and a thin crescent moon behind, thin
double rim with a bright highlight line, the two inner edges completely
straight and clean, soft arcane glow, flat frontal 2D illustration, single
centered object, uniform flat pure black background for easy background
removal, no shadow, no perspective, no 3D, no text, no letters, no numbers,
no logo, no watermark, high detail ornamental metalwork
```

Esquina de Sangre (prompt completo, copiar y pegar tal cual):

```
Flat 2D corner ornament for a game UI panel, single L-shaped corner piece
drawn for the top-left corner, 256 by 256, gothic halloween filigree in
rust-amber #D68254 and deep crimson #B03A5E, a small candle with melting
wax dripping over the corner and a thorn vine wrapped around it, thin
double rim with a bright highlight line, the two inner edges completely
straight and clean, soft arcane glow, flat frontal 2D illustration, single
centered object, uniform flat pure black background for easy background
removal, no shadow, no perspective, no 3D, no text, no letters, no
numbers, no logo, no watermark, high detail ornamental metalwork
```

### 37. `hwm_vrule.png`

```
Thin vertical ornamental divider, 24 by 256, a very slender gothic halloween
line with a small melted candle at the top and a single drop of wax running
down the line, tiny triangles and notches carved along it, bone-gold
#E8C46A and arcane violet #B98CF0 with a bright highlight line and a dark
shadow line, fading out at the bottom end, flat frontal 2D illustration,
uniform flat pure black background for easy background removal, no shadow,
no perspective, no 3D, no text, no letters, no numbers, no logo, no
watermark, high detail ornamental metalwork
```

### 38–39. Scroll

Riel:

```
Fantasy game UI scroll track, very thin vertical groove, 16 by 512, a dark
recessed channel with faint carved notches at both ends, deep eggplant
interior #0A0518, completely empty clean surface, flat frontal 2D
illustration, single centered object, uniform flat pure black background for
easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark
```

Pulgar:

```
Fantasy game UI scroll grip, thin vertical rounded bar, 16 by 256, arcane
violet metal #B98CF0 with a bright highlight line along one side and a tiny
carved crescent moon in the middle, small carved notches at both ends, flat
frontal 2D illustration, single centered object, uniform flat pure black
background for easy background removal, no shadow, no perspective, no 3D,
no text, no letters, no numbers, no logo, no watermark
```

### 40–41. Iconos de pestaña

```
Flat 2D game UI icon, single centered emblem, 128 by 128, a small carved
crescent moon with a sleeping face made of stone, bone-gold #E8C46A and
moonlight blue #8FA8DD, thin rim of light, simple and readable at small
size, flat frontal 2D illustration, uniform flat pure black background for
easy background removal, no shadow, no perspective, no 3D, no text, no
letters, no numbers, no logo, no watermark
```

Icono de Sangre (prompt completo, copiar y pegar tal cual):

```
Flat 2D game UI icon, single centered emblem, 128 by 128, a sculpted blood
drop with a tiny crown floating above it, deep crimson #B03A5E and bright
rose #FF9FB6, thin rim of light, simple and readable at small size, flat
frontal 2D illustration, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark
```

---

## Tanda 4 — iconos de misión (reemplazan los emojis)

Los 26 emojis del catálogo (`HalloweenMissions.LunaPool` + `SangreFreePool` +
`SangrePaidPool`) se cambian por emblemas de medallón. Se generan en **tres
hojas de 6×2 celdas de 256 px** (`1536×512`) para que la sesión comparta
estilo, y cada hoja se recorta por grilla (pipeline ImageMagick de la regla 6).

| Hoja | Archivo | Celdas |
|---|---|---|
| A (Luna 1) | `hwm_icons_luna_a.png` | peón, vela, trofeo, medalla de oro, pieza de puzzle, telaraña, espadas cruzadas, escudo, galera, diana, escuadra, microscopio |
| B (Luna 2) | `hwm_icons_luna_b.png` | cerebro, corona, rayo, torbellino, reloj de pie, daga, gota de sangre, dama oscura, bola de cristal, llama, calavera, torre de ajedrez |
| C (Sangre) | `hwm_icons_sangre.png` | grimorio, luna nueva, corona partida sangrante, cáliz de vino rojo, guadaña, murciélago, vela chorreando, calavera coronada, candado con cadena, reloj de arena rojo, araña en su tela, frasco de veneno |

### Hoja A — `hwm_icons_luna_a.png`

```
Flat 2D game icon spritesheet, a neat grid of 6 columns and 2 rows of
separate round medallion icons evenly spaced on pure black, each icon 256
by 256, every icon a single small object engraved on a dark circular
medallion with a thin bone-gold rim: a chess pawn, a lit candle, a trophy
cup, a gold medal with ribbon, a jigsaw puzzle piece, a cobweb, crossed
swords, a shield, a top hat, a target with an arrow, a drafting set square,
a microscope, materials in bone-gold #E8C46A, moonlight blue #8FA8DD and
arcane violet #B98CF0, silkscreen-like flat shading, each medallion fully
inside its own cell with even black margin around it, gothic halloween
chess fantasy aesthetic, flat frontal 2D illustration, uniform flat pure
black background for easy background removal, no shadow, no perspective, no
3D, no text, no letters, no numbers, no logo, no watermark
```

### Hoja B — `hwm_icons_luna_b.png`

Prompt completo (copiar y pegar tal cual):

```
Flat 2D game icon spritesheet, a neat grid of 6 columns and 2 rows of
separate round medallion icons evenly spaced on pure black, each icon 256
by 256, every icon a single small object engraved on a dark circular
medallion with a thin bone-gold rim: a brain, a crown, a lightning bolt, a
whirlwind, a tall mantel clock, a dagger, a blood drop, a dark queen chess
piece, a crystal ball, a flame, a skull, a rook chess tower, materials in
bone-gold #E8C46A, moonlight blue #8FA8DD and arcane violet #B98CF0,
silkscreen-like flat shading, each medallion fully inside its own cell with
even black margin around it, gothic halloween chess fantasy aesthetic, flat
frontal 2D illustration, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark
```

### Hoja C — `hwm_icons_sangre.png`

Prompt completo (copiar y pegar tal cual):

```
Flat 2D game icon spritesheet, a neat grid of 6 columns and 2 rows of
separate round medallion icons evenly spaced on pure black, each icon 256
by 256, every icon a single small object engraved on a dark circular
medallion with a thin bone-gold rim: a closed grimoire with a crescent
moon on its cover, a dark new moon disc, a broken crown with dripping blood,
a silver chalice with red wine, a reaper scythe, a bat, a dripping candle,
a crowned skull, a chained padlock, an hourglass with red sand, a spider on
its web, a poison vial, materials in rust-amber #D68254, deep crimson
#B03A5E and bone-gold #E8C46A with bright rose #FF9FB6 highlights,
silkscreen-like flat shading, each medallion fully inside its own cell with
even black margin around it, gothic halloween chess fantasy aesthetic, flat
frontal 2D illustration, uniform flat pure black background for easy
background removal, no shadow, no perspective, no 3D, no text, no letters,
no numbers, no logo, no watermark
```

**Fallback si la grilla sale desalineada** (pasa seguido con 12 objetos):
generar un icono por imagen con

```
Flat 2D game icon, single centered emblem, 256 by 256, a dark circular
medallion with a thin bone-gold rim, engraved on it: <OBJETO>, materials in
bone-gold #E8C46A and moonlight blue #8FA8DD, silkscreen-like flat shading,
gothic halloween chess fantasy aesthetic, flat frontal 2D illustration,
uniform flat pure black background for easy background removal, no shadow,
no perspective, no 3D, no text, no letters, no numbers, no logo, no
watermark
```

y nombrar cada PNG por su métrica (`hwm_icon_captures.png`,
`hwm_icon_win_streak5.png`, …), que es más simple de mapear que la hoja.

---

## Procesado (lo que viene después de generar)

1. Guardar las generaciones crudas (JPG con fondo negro puro) en
   `_art-source/Halloween/Missions/`.
2. Flood-fill del negro exterior desde los bordes (mismo criterio que
   `Tools/build_halloween_chips.py`) + defringe de 1 px + recorte al objeto.
3. Normalizar al canvas de la tabla con LANCZOS y guardar en
   `Assets/Resources/UI/Halloween/Missions/` (PNG con alfa real).
4. Hojas de iconos: aplicar la regla 6 — `-extent` para que el canvas divida
   exacto por 6×2, `-crop 6x2@ +repage +adjoin` y cada frame a 256×256
   centrado (`-trim +repage -gravity center -extent 256x256`).
5. En Unity: `Wilder Gambit > Reimportar sprites de HALLOWEEN` deja todo como
   Sprite / Single / Full Rect / sin compresión. Los marcos necesitan además
   su `spriteBorder` (9-slice).

## Integración sugerida (cuando el arte esté)

- Nuevo `HalloweenMissionsSprites.cs` con el mismo patrón que
  `HalloweenSprites` (carga por nombre + caché + `Apply` con 9-slice) y su
  propia constante de slice por familia de marco (ventana, tarjeta, banner,
  píldora).
- En `HalloweenMissionsModal`, el icono de la tarjeta hoy es
  `new Label(def.icon)` con emoji: pasa a `Image`/`VisualElement` con el
  sprite de la métrica, y el emoji queda como respaldo si el PNG no existe.
- Las tarjetas se aplican en `BuildMissionCard` según la clase que ya decide
  el estado (`hwm-mission-luna` / `-sangre` / `-premium` / `-ready` /
  `-claimed`), así que no hace falta tocar la lógica de estados.
- El `hwm-*` del resto del modal puede esperar: con la ventana, las tarjetas,
  el banner, el botón de cobro y los iconos ya cambia el 90 % de la lectura.
