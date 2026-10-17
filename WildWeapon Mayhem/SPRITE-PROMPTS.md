# WildWeapon Mayhem — Prompts de Sprites (v1)

> Objetivo: sacar el juego del greybox — portador, Katana, arenas, pickups y VFX.
> Cada bloque sigue el formato de `ICON_PROMPT.md` (Art direction / Technical / Negative). Los prompts van en **inglés** (los generadores rinden mejor así); el resto del documento en español.

---

## 0. Reglas de uso (leer antes)

1. **Un asset por generación.** Las grillas multi-frame salen irregulares: normalizar SIEMPRE con el pipeline ImageMagick del workspace (regla 6): `-extent` → `-crop CxR@ +repage +adjoin` → `-trim +repage -gravity center -extent`.
2. **Pivote y escala fijos.** Personaje: celda 256×256, pivote centro. Armas/VFX: celda 256×256, pivote centro. El personaje de la hoja base mira hacia **arriba (N)** y el juego rota el sprite; alternativa recomendada si el generador mezcla direcciones: **generar por dirección (S, N, E) y el oeste con flip horizontal**.
3. **Fondo plano puro**: blanco o transparente en imágenes; **chroma verde #00FF00 en videos** (los frames se extraen por key). **Sin sombras horneadas** — las luces y sombras las pone el motor.
4. **Crudo vs importado:** crudo a `_art-source/`; lo normalizado se importa a `Assets/_WildWeapon/Art/`.
5. **Nombres:** `ww_<asset>_<anim>_<dir>_##.png` (ej: `ww_portador_run_S_00.png`). Las armas mantienen la convención existente: `katana_00..23.png`.
6. **Intensidad de glow:** contenida. Los sets existentes (Chain Scythe rojo, Tiger naranja, Zeus azul) marcan el techo — lo nuevo no debe brillar más que ellos.
7. **Animaciones = video.** Los assets animados se generan como **video corto** (4 / 6 / 8 s según la tabla final) y de ahí se extraen los frames (ffmpeg → ImageMagick). Reglas de video: cámara **fija cenital estrictamente perpendicular**, fondo **chroma verde plano (#00FF00)** sin gradientes, sujeto centrado y **fijo en el centro del cuadro** (sin desplazamiento), sin cortes, diseño consistente (**sin morphing ni flicker**). Loops: primer y último frame idénticos. Los estáticos (pisos, props, muros, katana en mano, render) siguen siendo imágenes.

**Paleta maestra (ancla de todo):**
- Cian neón `#00F3FF` · magenta eléctrico `#BC13FE` · navy/negro `#050510`
- Metales oscuros con rim light · **Katana = acero gris SIN glow** (arma común); el color neón se reserva para armas de tier superior
- Alto contraste, siluetas legibles a tamaño chico, bloom contenido.

**Resumen de assets de esta tanda:** portador (idle/run/dash/hit/KO), Katana (tajo + en mano + render), 3 pisos de arena + props + muros + hazards, 2 orbes, 4 VFX, 6 partículas ambientales.

---

## 1. Portador (reemplaza el cuadrado blanco)

### 1.1 Video base — idle y run (por dirección)
> Generar **una vez por animación y por dirección** (S, N, E; oeste = flip). Duración: **4 s** cada uno, loop perfecto. La carrera es "en el lugar": el personaje **nunca se mueve del centro del cuadro**.

```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Action: [ELEGIR: "gentle breathing idle, weight shifting subtly" / "full sprint cycle IN PLACE, 2 complete strides"].

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only); weapon held forward but NOT visible (layered separately in the game).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the existing dark-metal arsenal. Character design stays perfectly consistent across the whole video (no morphing, no flicker).

Camera & background:
- LOCKED top-down camera: no movement, no zoom, no roll, no parallax. Subject centered and fixed at the center of the frame.
- Isolated on a FLAT PURE chroma green background (#00FF00), no gradient, no lighting variation, no props, no shadows.

Technical:
- Duration: 4 seconds, smooth high framerate. Seamless loop: first and last frame identical.

Negative constraints:
- No camera movement or shake, no cuts or transitions, no zoom, no text, no watermark, no lens flare, no motion blur, no other characters, no background objects, no 3/4 or oblique view.
```

### 1.2 Otras animaciones (mismo video base, cambiando solo Action + duración)
- **Dash — 4 s, one-shot:** "explosive dash burst: sharp forward lunge lean with a brief slide, then settle to ready stance; stays centered".
- **Hit — 4 s, one-shot:** "short hit reaction: sharp recoil with head snap backward, then recover to stance".
- **KO — 6 s, one-shot:** "collapse: balance breaks, falls sideways onto the ground, settles; last 2 seconds completely still".
- **Win — 4 s, one-shot:** "brief victory: fist raised with a sharp nod, then hold the pose".

### 1.3 Nota de skins (para producción)
El cuerpo en grises fríos es a propósito: el recolor por tinte (HSV) cubre las skins base del doc (sección 7). El acento cian queda fijo en v0; las variantes de acento llegan con las skins épicas.

---

## 2. Katana (arma inicial)

> **Arma común:** VFX grisáceo y básico. La intensidad de VFX escala con la rareza — la Katana no lleva glow de color (eso se reserva a tiers superiores).

### 2.1 Video del tajo M1 — 4 s, one-shot
> El VFX grisáceo y básico de arma común. De acá salen los 24 frames (6×4, 256 px).

```
Top-down weapon slash VFX animation for "Katana", the STARTER/common weapon of a 2D arena PVP game.
Design intent: a common weapon reads clean and honest — minimal, desaturated VFX, no neon glow.

Action & art direction:
- A single iaido crescent cut in plain steel grey/off-white, sweeping left→right across the frame ONCE, slow and readable (~2 seconds).
- Thin matte arc, soft grey motion smear, a few grey dust particles; NO colored glow, NO bloom.
- Nothing visible during the first and last second of the video.

Camera & background:
- LOCKED perpendicular top-down camera, no movement of any kind. Effect centered.
- Flat pure chroma green background (#00FF00), no gradient, no other elements.

Technical:
- Duration: 4 seconds, smooth high framerate.

Negative constraints:
- No colored energy, no cyan/magenta/neon, no character, no hand, no sword body, no camera movement, no text, no watermark, no motion blur.
```

### 2.2 Katana "en mano" (cenital, para el pivote de apuntado)
```
Single top-down sprite of a simple steel katana, seen from directly above, blade pointing UP.

Art direction:
- Plain steel blade (light grey, brushed texture), dark grey handle with simple black cord wrap.
- No energy edge, no glow, no colored accents: a clean common weapon that reads instantly.
- Subtle rim light only.

Technical output requirements:
- 1 sprite, 128x128 PNG. Pivot at the handle base (touching character center); delivery: transparent or flat white background.
- Blade tip at the top edge of the cell.

Negative constraints:
- No hands, no character, no perspective, no text, no watermark.
```

### 2.3 Render de presentación (ficha, tienda, selección de arma)
Mismo formato que los renders existentes (Chain Scythe, Zeus Axe, Tiger Gloves). **Este prompt es la plantilla base para CUALQUIER arma nueva**: cambiar nombre, tema y color.
```
Presentation render of a futuristic katana for a premium 2D action game card art.

Art direction:
- Plain forged steel katana: light grey blade, dark grey fittings — NO glowing core, NO neon (common weapon).
- Dramatic diagonal composition, centered, sword only. Restrained rim light, no bloom.
- Style match: same family as the existing arsenal renders (dark metal + light motion smear behind).
- Pure white background, no environment.

Technical output requirements:
- 1024x1024 PNG master, single weapon centered, generous margins.

Negative constraints:
- No text, no watermark, no hands/characters, no mockups, no UI frames.
```

---

## 3. Arenas

### 3.1 Pisos seamless (512×512, tileable — 1 por tema)
**Chatarra Nebula:**
```
Seamless top-down floor texture for a sci-fi junkyard district arena in a 2D PVP game.
Dark steel deck plates with rivets, subtle scrap debris, thin magenta (#BC13FE) and cyan (#00F3FF)
neon strips along some seams, worn paint, muted contrast so characters read clearly.
PERFECTLY TILEABLE: all four edges must match seamlessly. Strict orthographic top view.
No text, no watermark, no characters, no props, no strong highlights.
```
**Fosa Leviatán:**
```
Seamless top-down floor texture: dark abyssal rock and bio-coral crust, deep teal glow cracks,
faint bioluminescent specks, wet dark stone. Muted, readable under characters.
PERFECTLY TILEABLE (edges match). Strict orthographic top view. No text, no watermark, no characters.
```
**Bóveda Dorada:**
```
Seamless top-down floor texture: polished marble with gold inlay lines, warm vault lighting,
subtle engraved coin motifs, light wear. Elegant, muted, readable under characters.
PERFECTLY TILEABLE (edges match). Strict orthographic top view. No text, no watermark, no characters.
```

### 3.2 Coberturas y props (un objeto por generación, centrado, fondo plano)
```
Single game prop for a top-down 2D PVP arena, seen from directly above, centered, flat pure white background.
[VARIANTE]:
- Chatarra Nebula: heavy scrap-metal cover block (crate), welded plates, small cyan light, worn edges.
- Chatarra Nebula: central rotating pillar: tall column seen from above as a large circular armored drum.
- Fosa Leviatán: carved stone pedestal ring on a raised circular platform, teal glow runes.
- Bóveda Dorada: golden pedestal with velvet top and faint coin engravings, warm glow.
Style: dark metal/gothic sci-fi matching the game's weapons, painted AAA, subtle rim light.
Technical: 512x512 PNG, transparent or flat white background, object centered, no cast shadows.
Negative: no perspective view, no text, no watermark, no scene.
```

### 3.3 Muros (set común, tintable)
```
Top-down wall segment set for a 2D PVP arena: dark armored metal barriers with beveled top edges,
horizontal piece, vertical piece, corner piece, end caps. Neutral dark grey (tintable in engine),
subtle rim light. Strict orthographic top view. 256x256 cell each, flat white background.
No text, no watermark, no perspective, no characters.
```

### 3.4 Hazards (video, telegrafiado y legible)
```
Locked top-down game VFX animation, effect centered, flat pure chroma green background (#00FF00),
no camera movement, smooth high framerate, seamless loop (first = last frame).
[VARIANTE]:
- Nebula — 6 s loop: falling debris telegraph — a growing dark shadow circle, impact flash, dust settles, resets.
- Leviatán — 4 s loop: electrified border pulse — teal lightning crawling along a straight horizontal strip.
- Bóveda — 6 s loop: shower of golden MayhemCoins falling from the top of the frame with warm sparkle.
Style: high readability, muted glow. No text, no watermark, no characters, no gradient background.
```

---

## 4. Pickups y VFX genéricos

### 4.1 Orbes (video, 4 s loop)
```
Top-down pickup orb game animation, 4 seconds, seamless loop, centered, locked camera,
flat pure chroma green background (#00FF00).
[VARIANTE]:
- ADRENALINA: cyan energy sphere with electric arcs inside, calm hover bob and pulse.
- MAYHEMCOIN: gold coin with a stylized "W", slow spin with soft warm sparkle.
Style: premium arcade, readable at small size. No text, no watermark, no perspective, no motion blur.
```

### 4.2 VFX de impacto (video, one-shot, 4 s cada uno)
```
Locked top-down game VFX animation, 4 seconds, effect centered, flat pure chroma green background (#00FF00),
no camera movement, smooth high framerate. The effect happens in the middle of the video, nothing at start/end.
[VARIANTE]:
- DASH TRAIL: teardrop motion streak, white core fading to cyan.
- HIT IMPACT: radial white burst with small sparks, NEUTRAL color (tintable in engine).
- KO BURST: white flash ring expanding with dark shards flying out.
No text, no watermark, no characters, no perspective, no motion blur.
```

---

## 5. Ambiente (video, 8 s loop por tema)

```
Locked top-down ambient particle animation for a 2D PVP arena, 8 seconds, seamless loop,
flat pure chroma green background (#00FF00), no camera movement.
[VARIANTE por tema]:
- Nebula: drifting dark dust motes with a cyan glint.
- Leviatán: bioluminescent teal dots with soft glow halos.
- Bóveda: warm gold sparkles, slow twinkle.
No text, no watermark, no perspective, no motion blur.
```

---

## 6. Checklist de producción

| Asset | Formato | Duración | Destino |
|---|---|---|---|
| Portador idle / run | video → hoja | 4 s loop | `Art/Characters/` |
| Portador dash / hit / win | video → hoja | 4 s one-shot | `Art/Characters/` |
| Portador KO | video → hoja | 6 s one-shot | `Art/Characters/` |
| Katana tajo M1 | video → hoja 6×4 (24) | 4 s one-shot | `Art/Weapons/Katana/` |
| Katana en mano | imagen | — | `Art/Weapons/Katana/` |
| Katana render | imagen | — | `_art-source/` (ficha/tienda) |
| Pisos de arena (×3) | imagen tileable | — | `Art/Arenas/<tema>/` |
| Props y muros | imagen | — | `Art/Arenas/<tema>/` |
| Hazards (×3) | video → hoja | 4–6 s loop | `Art/VFX/` |
| Orbes | video → hoja | 4 s loop | `Art/Pickups/` |
| Dash trail / impacto / KO burst | video → hoja | 4 s one-shot | `Art/VFX/` |
| Partículas ambientales | video → hoja | 8 s loop | `Art/VFX/` |

**Orden sugerido de producción:** 1) Portador idle+run → 2) Katana (tajo + en mano) → 3) Piso Bóveda Dorada + props → 4) orbes y VFX → 5) los otros 2 pisos + hazards + ambiente.

> Cuando haya videos/arte nuevo: los videos se convierten a frames (ffmpeg), se normalizan con el pipeline (ImageMagick) y se integran al builder de F0 (`F0SceneBuilder`) para reemplazar los rectángulos por sprites reales.
