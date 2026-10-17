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
8. **Referencia primero (portador).** Antes de animar, generar la **imagen maestra** (§1.0) y usarla como **referencia** en todos los videos del portador (image-to-video). Así el diseño queda on-model entre animaciones y direcciones.

**Paleta maestra (ancla de todo):**
- Cian neón `#00F3FF` · magenta eléctrico `#BC13FE` · navy/negro `#050510`
- Metales oscuros con rim light · **Katana = acero gris SIN glow** (arma común); el color neón se reserva para armas de tier superior
- Alto contraste, siluetas legibles a tamaño chico, bloom contenido.

**Resumen de assets de esta tanda:** portador (idle/run/dash/hit/KO), Katana (tajo + en mano + render), 3 pisos de arena + props + muros + hazards, 2 orbes, 4 VFX, 6 partículas ambientales.

---

## 1. Portador (reemplaza el cuadrado blanco)

> Se genera **una vez por animación y por dirección** (S/N/E; oeste = flip horizontal de E). Cada prompt va completo: copiar y pegar directo.
> **Flujo:** primero la **imagen maestra (§1.0)**; después los videos, usando esa imagen como **referencia**.

### 1.0 Imagen maestra de referencia — estática (bloquea el diseño)
> Esta imagen define al personaje: es la **referencia** de los videos §1.1–§1.6 y de las skins futuras. El maestro de abajo mira hacia **arriba (N)**; para S y E se generan variantes con la misma cámara (bloque al final de esta sección), y cada una es la referencia de los videos de su dirección.

```
Single character reference illustration for a 2D arena PVP game: a futuristic duelist,
seen from directly above in a strict top-down orthographic view (bird's-eye), character faces UP
(away from the camera), standing in a neutral ready combat stance.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only). No weapon in hands (weapons are layered in the game engine).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the game's dark-metal arsenal (gothic sci-fi, worn edges).
- This image LOCKS the character design: proportions, armor shapes, colors and camera must match it exactly in all animations.

Technical:
- Centered, filling most of the frame, on a FLAT PURE chroma green background (#00FF00), no gradient, no props, no shadows.
- Square 1024x1024.

Negative constraints:
- No 3/4 or oblique view, no perspective, no face, no weapon, no text, no watermark, no scene background, no other characters.
```

**Variantes por dirección** (misma cámara y encuadre — solo cambia hacia dónde mira; generar cada variante con el **maestro N como referencia** y agregando esta línea al prompt: `Same character, same armor, same camera position and framing as the reference image — only the facing direction changes.`):
- **S — mira hacia abajo:** cambiar `character faces UP` → `character faces DOWN` y `(away from the camera)` → `(toward the camera)`; en Art direction, reemplazar `No face visible (crown of helmet only)` → `No human face: closed opaque visor (no exposed skin)`. Se ve el frente: pecho y visor.
- **E — mira a la derecha:** reemplazar la línea de orientación por `character faces RIGHT (east) — side profile`.
- **O (izquierda):** NO se genera — flip horizontal de los frames de E en el pipeline (regla 6).

Los videos (§1.1–§1.6) de cada dirección usan **su** maestro como `attached reference image`; en los prompts de video, cambiar además `character faces UP in every frame` por la dirección correspondiente.

### 1.0b Ilustración de presentación (opcional — ficha / tienda)
```
Full-body character illustration (premium key art) of a futuristic duelist for a 2D arena PVP game.
Three-quarter view showing the armor design clearly: dark tactical armor (#050510) with cold grey body panels
and cyan (#00F3FF) energy accents; no face visible (crown of helmet only); no weapon.
Style: painted AAA key art matching the game's dark-metal arsenal (gothic sci-fi, worn edges), subtle cyan rim light.
Composition: centered hero pose, clean; moody navy backdrop (#050510) with a faint cyan glow.
Negative: no text, no watermark, no other characters, no scene props, no logo.
```

### 1.1 Idle — 4 s, loop
```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Use the attached reference image as the exact character design and camera: same proportions, same armor shapes, same colors, same top-down view. Keep the design identical across every frame — no redesign.
Action: gentle breathing idle — the chest rises and falls subtly, weight shifts side to side, arms steady; calm and ready.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only); weapon held forward but NOT visible (layered separately in the game).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the existing dark-metal arsenal. Character design stays perfectly consistent across the whole video (no morphing, no flicker).

Camera & background:
- LOCKED top-down camera: no movement, no zoom, no roll, no parallax. Subject centered and fixed at the center of the frame.
- Isolated on a FLAT PURE chroma green background (#00FF00), no gradient, no lighting variation, no props, no shadows.

Technical:
- Duration: 4 seconds, smooth high framerate. Seamless loop: first and last frame identical; the first frame must match the reference image.

Negative constraints:
- No camera movement or shake, no cuts or transitions, no zoom, no text, no watermark, no lens flare, no motion blur, no other characters, no background objects, no 3/4 or oblique view.
```

### 1.2 Run — 4 s, loop
```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Use the attached reference image as the exact character design and camera: same proportions, same armor shapes, same colors, same top-down view. Keep the design identical across every frame — no redesign.
Action: full sprint cycle IN PLACE — 2 complete strides, arms pumping; the character stays fixed at the center of the frame (no forward translation).

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

### 1.3 Dash — 4 s, one-shot
```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Use the attached reference image as the exact character design and camera: same proportions, same armor shapes, same colors, same top-down view. Keep the design identical across every frame — no redesign.
Action: explosive dash burst — sharp forward lunge lean with a brief slide, then settle back to the ready stance; the character stays centered, motion is conveyed only by the body.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only); weapon held forward but NOT visible (layered separately in the game).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the existing dark-metal arsenal. Character design stays perfectly consistent across the whole video (no morphing, no flicker).

Camera & background:
- LOCKED top-down camera: no movement, no zoom, no roll, no parallax. Subject centered and fixed at the center of the frame.
- Isolated on a FLAT PURE chroma green background (#00FF00), no gradient, no lighting variation, no props, no shadows.

Technical:
- Duration: 4 seconds, smooth high framerate. One-shot: starts and ends in the ready stance.

Negative constraints:
- No camera movement or shake, no cuts or transitions, no zoom, no text, no watermark, no lens flare, no motion blur, no other characters, no background objects, no 3/4 or oblique view.
```

### 1.4 Hit — 4 s, one-shot
```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Use the attached reference image as the exact character design and camera: same proportions, same armor shapes, same colors, same top-down view. Keep the design identical across every frame — no redesign.
Action: short hit reaction — sharp recoil with a head snap backward and a quick stagger, then recover to the ready stance.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only); weapon held forward but NOT visible (layered separately in the game).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the existing dark-metal arsenal. Character design stays perfectly consistent across the whole video (no morphing, no flicker).

Camera & background:
- LOCKED top-down camera: no movement, no zoom, no roll, no parallax. Subject centered and fixed at the center of the frame.
- Isolated on a FLAT PURE chroma green background (#00FF00), no gradient, no lighting variation, no props, no shadows.

Technical:
- Duration: 4 seconds, smooth high framerate. One-shot: starts and ends in the ready stance.

Negative constraints:
- No camera movement or shake, no cuts or transitions, no zoom, no text, no watermark, no lens flare, no motion blur, no other characters, no background objects, no 3/4 or oblique view.
```

### 1.5 KO — 6 s, one-shot
```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Use the attached reference image as the exact character design and camera: same proportions, same armor shapes, same colors, same top-down view. Keep the design identical across every frame — no redesign.
Action: collapse — the balance breaks, the character falls sideways onto the ground and settles; the last 2 seconds are completely still.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only); weapon held forward but NOT visible (layered separately in the game).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the existing dark-metal arsenal. Character design stays perfectly consistent across the whole video (no morphing, no flicker).

Camera & background:
- LOCKED top-down camera: no movement, no zoom, no roll, no parallax. Subject centered and fixed at the center of the frame.
- Isolated on a FLAT PURE chroma green background (#00FF00), no gradient, no lighting variation, no props, no shadows.

Technical:
- Duration: 6 seconds, smooth high framerate. One-shot: ends with the character lying completely still.

Negative constraints:
- No camera movement or shake, no cuts or transitions, no zoom, no text, no watermark, no lens flare, no motion blur, no other characters, no background objects, no 3/4 or oblique view.
```

### 1.6 Win — 4 s, one-shot
```
Top-down (bird's-eye) game animation of a futuristic duelist for a 2D arena PVP game,
seen from directly above with a LOCKED perpendicular camera, character faces UP in every frame.
Use the attached reference image as the exact character design and camera: same proportions, same armor shapes, same colors, same top-down view. Keep the design identical across every frame — no redesign.
Action: brief victory — the fist rises with a sharp nod, then holds the pose.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510) with cold grey body (neutral for skin recoloring) and cyan (#00F3FF) energy accents.
- No face visible (crown of helmet only); weapon held forward but NOT visible (layered separately in the game).
- Even top light, subtle cyan rim light, NO projected floor shadow.
- Painted AAA game look matching the existing dark-metal arsenal. Character design stays perfectly consistent across the whole video (no morphing, no flicker).

Camera & background:
- LOCKED top-down camera: no movement, no zoom, no roll, no parallax. Subject centered and fixed at the center of the frame.
- Isolated on a FLAT PURE chroma green background (#00FF00), no gradient, no lighting variation, no props, no shadows.

Technical:
- Duration: 4 seconds, smooth high framerate. One-shot: holds the final pose.

Negative constraints:
- No camera movement or shake, no cuts or transitions, no zoom, no text, no watermark, no lens flare, no motion blur, no other characters, no background objects, no 3/4 or oblique view.
```

### 1.7 Nota de skins (para producción)
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

### 3.2 Coberturas y props (uno por generación, centrado, fondo plano)
**Chatarra Nebula — bloque de chatarra (512×512)**
```
Single game prop for a top-down 2D PVP arena, seen from directly above, centered, flat pure white background.
Subject: heavy scrap-metal cover block (crate), welded plates, small cyan light, worn edges.
Style: dark metal/gothic sci-fi matching the game's weapons, painted AAA, subtle rim light.
Technical: 512x512 PNG, transparent or flat white background, object centered, no cast shadows.
Negative: no perspective view, no text, no watermark, no scene.
```

**Chatarra Nebula — pilar central (512×512)**
```
Single game prop for a top-down 2D PVP arena, seen from directly above, centered, flat pure white background.
Subject: central rotating pillar — tall column seen from above as a large circular armored drum, radial metal ribs, thin cyan light seams.
Style: dark metal/gothic sci-fi matching the game's weapons, painted AAA, subtle rim light.
Technical: 512x512 PNG, transparent or flat white background, object centered, no cast shadows.
Negative: no perspective view, no text, no watermark, no scene.
```

**Fosa Leviatán — pedestal tallado (512×512)**
```
Single game prop for a top-down 2D PVP arena, seen from directly above, centered, flat pure white background.
Subject: carved stone pedestal ring on a raised circular platform, teal glow runes.
Style: dark metal/gothic sci-fi matching the game's weapons, painted AAA, subtle rim light.
Technical: 512x512 PNG, transparent or flat white background, object centered, no cast shadows.
Negative: no perspective view, no text, no watermark, no scene.
```

**Bóveda Dorada — pedestal dorado (512×512)**
```
Single game prop for a top-down 2D PVP arena, seen from directly above, centered, flat pure white background.
Subject: golden pedestal with velvet top and faint coin engravings, warm glow.
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

### 3.4 Hazards (video — uno por tema)
**Nebula — 6 s, loop**
```
Locked top-down game VFX animation of an arena hazard, effect centered,
flat pure chroma green background (#00FF00), no camera movement, smooth high framerate.
Action: a falling-debris telegraph — a dark shadow circle grows on the ground, an impact flash hits and dust settles, then the shadow clears and the cycle resets.
Duration: 6 seconds. Seamless loop: first and last frame identical.
Style: high readability, muted glow. No text, no watermark, no characters, no gradient background, no camera movement.
```

**Leviatán — 4 s, loop**
```
Locked top-down game VFX animation of an arena hazard, effect centered,
flat pure chroma green background (#00FF00), no camera movement, smooth high framerate.
Action: an electrified border pulse — teal lightning crawls along a straight horizontal strip, crackling and fading, looping seamlessly.
Duration: 4 seconds. Seamless loop: first and last frame identical.
Style: high readability, muted glow. No text, no watermark, no characters, no gradient background, no camera movement.
```

**Bóveda — 6 s, loop**
```
Locked top-down game VFX animation of an arena hazard, effect centered,
flat pure chroma green background (#00FF00), no camera movement, smooth high framerate.
Action: a shower of golden MayhemCoins falling from the top of the frame with warm sparkles, landing and settling briefly, then the cycle resets.
Duration: 6 seconds. Seamless loop: first and last frame identical.
Style: high readability, muted glow. No text, no watermark, no characters, no gradient background, no camera movement.
```

---

## 4. Pickups y VFX genéricos

### 4.1 Orbes (video — uno por variante)
**Adrenalina — 4 s, loop**
```
Top-down pickup orb game animation, centered, locked camera,
flat pure chroma green background (#00FF00), smooth high framerate.
Action: a cyan energy sphere with electric arcs inside — calm hover bob and pulse.
Duration: 4 seconds. Seamless loop: first and last frame identical.
Style: premium arcade, readable at small size. No text, no watermark, no perspective, no motion blur.
```

**MayhemCoin — 4 s, loop**
```
Top-down pickup orb game animation, centered, locked camera,
flat pure chroma green background (#00FF00), smooth high framerate.
Action: a gold coin with a stylized "W" — slow spin with soft warm sparkle.
Duration: 4 seconds. Seamless loop: first and last frame identical.
Style: premium arcade, readable at small size. No text, no watermark, no perspective, no motion blur.
```

### 4.2 VFX de impacto (video — uno por efecto)
**Dash trail — 4 s, one-shot**
```
Locked top-down game VFX animation, 4 seconds, effect centered, flat pure chroma green background (#00FF00),
no camera movement, smooth high framerate. The effect happens in the middle of the video, nothing at start/end.
Action: a teardrop motion streak — white core fading to cyan.
No text, no watermark, no characters, no perspective, no motion blur.
```

**Hit impact — 4 s, one-shot**
```
Locked top-down game VFX animation, 4 seconds, effect centered, flat pure chroma green background (#00FF00),
no camera movement, smooth high framerate. The effect happens in the middle of the video, nothing at start/end.
Action: a radial white burst with small sparks, NEUTRAL color (tintable in the engine).
No text, no watermark, no characters, no perspective, no motion blur.
```

**KO burst — 4 s, one-shot**
```
Locked top-down game VFX animation, 4 seconds, effect centered, flat pure chroma green background (#00FF00),
no camera movement, smooth high framerate. The effect happens in the middle of the video, nothing at start/end.
Action: a white flash ring expanding with dark shards flying out.
No text, no watermark, no characters, no perspective, no motion blur.
```

---

## 5. Ambiente (video — uno por tema)

**Nebula — 8 s, loop**
```
Locked top-down ambient particle animation for a 2D PVP arena, seamless loop,
flat pure chroma green background (#00FF00), no camera movement, smooth high framerate.
Action: drifting dark dust motes with a cyan glint.
Duration: 8 seconds. Seamless loop: first and last frame identical.
No text, no watermark, no perspective, no motion blur.
```

**Leviatán — 8 s, loop**
```
Locked top-down ambient particle animation for a 2D PVP arena, seamless loop,
flat pure chroma green background (#00FF00), no camera movement, smooth high framerate.
Action: bioluminescent teal dots with soft glow halos drifting slowly.
Duration: 8 seconds. Seamless loop: first and last frame identical.
No text, no watermark, no perspective, no motion blur.
```

**Bóveda — 8 s, loop**
```
Locked top-down ambient particle animation for a 2D PVP arena, seamless loop,
flat pure chroma green background (#00FF00), no camera movement, smooth high framerate.
Action: warm gold sparkles with a slow twinkle.
Duration: 8 seconds. Seamless loop: first and last frame identical.
No text, no watermark, no perspective, no motion blur.
```

---

## 6. Checklist de producción

| Asset | Formato | Duración | Destino |
|---|---|---|---|
| Portador — imagen maestra (§1.0) | imagen | — | `_art-source/` (referencia de animación) |
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
