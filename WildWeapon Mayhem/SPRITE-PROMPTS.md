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
> **Flujo:** primero la **imagen maestra (§1.0)**; después los videos, usando esa imagen como **referencia**. Cada video usa el maestro de **su misma dirección**.
> **Plan v1 (recomendado):** idle, run, dash y hit en las 3 direcciones (N/S/E); KO y win en una sola dirección (N) — se reproducen tal cual.

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


---

## 7. Logo del título y estallido del menú (regenerados)

> Assets del arte del menú reworkeado (oct 2026). Transparencia real, sin fondo horneado.
> Nota: el texto exacto del prompt usado no quedó registrado; abajo va qué es cada pieza y cómo se monta.

| Asset | Tamaño | Destino | Notas |
|---|---|---|---|
| `ww_logo.png` | 1024×1024 (alfa, bbox ~1005×941) | `Assets/_WildWeapon/Art/Sprites/` | Logo del título (katana + hacha cruzadas sobre el estallido). Reemplaza al anterior en el mismo path. |
| `ww_logo_burst.png` | 1024×1024 → canvas 1152×1152 | `Assets/_WildWeapon/Art/Sprites/` | Anillo de impacto cómic con centro hueco. **Normalizar antes de importar:** `magick ww_logo_burst.png -background none -gravity center -extent 1152x1152 ww_logo_burst.png` (deja ~80 px de margen para que al girar no se corte ninguna punta). |

**Montaje en el builder** (`WildWeaponBuilder.BuildMenuLogo`):

- `Logo/Glow` — halo suave que late por detrás (soft circle naranja).
- `Logo/Burst` — el estallido; gira 360° por ciclo de idle y entra con rebote en la intro.
- `Logo/LogoImage` — el logo; lleva un `Mask` (alpha) para que el brillo quede recortado a la silueta.
- `Logo/LogoImage/Shine` — barra de brillo diagonal que barre el logo: una vez al aterrizar (intro) y dos veces por vuelta de idle.

Clips del menú: `Menu_Intro` (~1.65 s, caída + rebote + barrido) y `Menu_Idle` (12 s en loop, respiración + giro del estallido + 2 barridos).

---

## 8. Tarjetas de modo del menú (skin + emblemas, oct 2026)

> Rework visual de la fila de tarjetas (`01 DUELO · 02 PVP · 03 SUPERVIVENCIA · 04 SALIR`): paneles biselados con glow y emblema fantasma por modo. Generado con Aura (imagen cuadrada/landscape + transparencia), normalizado con ImageMagick y cableado en el builder.

| Asset | Tamaño final | Destino | Notas |
|---|---|---|---|
| `ww_menu_card_skin.png` | 1024×461 (20:9) | `Assets/_WildWeapon/Art/Sprites/` | Panel oscuro biselado con borde fino y líneas de luz arriba/abajo. Se generó con glow cian y se **desaturó a gris** para tintarlo por acento en runtime. |
| `ww_icon_duel.png` | 512×512 | idem | Katanas cruzadas. |
| `ww_icon_pvp.png` | 512×512 | idem | Globo terráqueo con órbita y nodos de jugador. |
| `ww_icon_survival.png` | 512×512 | idem | Calavera frontal en emblema. |
| `ww_icon_exit.png` | 512×512 | idem | Puerta entreabierta con flecha de salida. |

**Prompts (esencia, en inglés):** panel "flat straight-on ultra-wide card, dark navy glass, chamfered corners, thin steel border, cyan rim light, subtle diagonal weave, transparent background"; íconos "bold minimal flat vector glyph, light grey/white with subtle bevel, centered, transparent background" (la misma cola de estilo para los cuatro). Los nombres se pasan **sin `.png`** a `generate_images`.

**Normalización (ImageMagick):**

```powershell
# Skin: neutralizar glow (gris) + trim + encuadre exacto 20:9 (como la tarjeta 320x144)
magick ww_menu_card_skin.png -modulate 100,0,100 -fuzz 8% -trim +repage -resize 1024x461! ww_menu_card_skin.png
# Iconos: trim + reencuadre centrado en 512 (llenan ~78% del marco)
magick ww_icon_*.png -fuzz 8% -trim +repage -resize 400x400 -background none -gravity center -extent 512x512 ww_icon_*.png
```

**Montaje en el builder** (`WildWeaponBuilder.ModeCard`):

- `Frame` — el skin (Image simple, estirado a la tarjeta); reemplaza al panel sólido. Si el sprite falta, cae al `Panel` viejo.
- `Mark` — el emblema del modo, fantasma detrás de los textos (120-ish px), raycast off.
- En `MenuModeCard`: el skin es gris neutro y `frame.color` se tintea con el acento del modo (reposo mezclado al 28%, resaltado acento pleno); el emblema sube de alfa 0.14 a 0.40 y escala 0.96→1.07 al resaltar.
- `ArtSpec` nuevos en la lista `Art` (skin 1024, íconos 512, PPU 512 estándar del set).
- Menú dev para iterar escenas sin el diálogo modal: **WildWeapon > Dev > Reconstruir escenas (silencioso)** (`WildWeaponDevMenu.cs`, llama a `BuildAllSilent`).

---

## 9. Franja de info del menú (skin + chips, oct 2026)

> Segundo pase del rework del menú: la franja que muestra el detalle del modo (`Título + bajada + 3 fichas`) deja los paneles planos y pasa a placa biselada con skin propia, y las fichas ganan un chip biselado. Los emblemas de §8 se reutilizan como marca fantasma detrás de las fichas (cambia con el modo activo).

A diferencia de §8 (Aura), esta tanda se generó con **Google Flow (Nano Banana 2.1)**, que rinde bien el estilo "consola de acero" y no consumió puntos; las piezas llegan como JPG sobre fondo blanco plano y se recortan con ImageMagick (key + trim), como los props de §3.2.

| Asset | Tamaño final | Destino | Notas |
|---|---|---|---|
| `ww_menu_info_skin.png` | 1024×120 (8.53:1) | `Assets/_WildWeapon/Art/Sprites/` | Placa ultra-ancha biselada: cuerpo de vidrio gris con tejido diagonal sutil y brillo, borde fino claro, líneas de acento arriba/abajo, esquinas chamferadas. **Desaturada a gris** para el tint por acento en runtime. |
| `ww_menu_chip_skin.png` | 512×94 (5.45:1) | idem | Chip compacto a juego (mismo lenguaje): chamfer chico, borde claro, highlight superior. También en gris neutro. |

Ambas calzan exactas al hueco de UI (franja 1180×138 y chip 186×34) para evitar estirados raros sin 9-slice.

**Prompts (esencia, en inglés):** "ONE single ultra-wide [information banner plate / small chip plate], flat straight-on orthographic view, axis-aligned, aspect ~8:1 [~5.5:1], deep navy glass with subtle diagonal weave and faint sheen, crisp chamfered corners, thin light steel border, faint accent lines on top/bottom edges, premium tactical game HUD style, on a completely flat pure white background with clear margins, no shadow, no text, no icons". Misma cola de estilo en ambas para que la familia se lea igual.

**Normalización (ImageMagick):**

```powershell
# Key del fondo blanco + trim de la placa (las piezas salen como JPG sin alpha)
magick ww_info_raw.jpg -fuzz 8% -transparent white -trim +repage ww_info_keyed.png
# Encuadre exacto al hueco (1024x120 = 8.53:1) y gris neutro para tint por acento
magick ww_info_keyed.png -background none -resize 1024x120! ww_menu_info_skin.png
magick ww_menu_info_skin.png -modulate 100,0,100 ww_menu_info_skin.png
# Chip (hueco 186x34 = 5.45:1), mismo tratamiento
magick ww_chip_raw.jpg -fuzz 8% -transparent white -trim +repage -background none -resize 512x94! ww_menu_chip_skin.png
magick ww_menu_chip_skin.png -modulate 100,0,100 ww_menu_chip_skin.png
```

**Montaje en el builder** (`WildWeaponBuilder.ModeInfoStrip`):

- `Bg` — el skin de la franja estirado al rect (1180×138); si el sprite falta, cae al `Panel` viejo.
- Chips — cada ficha usa el chip skin como fondo (186×34); el label queda encima; fallback a `Panel` translúcido.
- `MenuModeInfo` — `frame` y `bg` de cada chip se tintean por modo (`Lerp(FrameTint, acento, 0.30)` y `Lerp(ChipTint, acento, 0.5)`), y la marca fantasma detrás de las fichas cambia de emblema según el modo (alfa 0.16).
- `ArtSpec` nuevos en la lista `Art` (info 1024, chip 512, PPU 512 estándar del set).
- Verificación: reconstrucción con **WildWeapon > Dev > Reconstruir escenas (silencioso)** + captura en play (la franja queda en gris acero con tinte frío en DUELO; los chips salen casi neutros).

---

## 10. Modal PVP del menú (placa + botón + regla + radar, oct 2026)

> Tercer pase del rework del menú: el overlay de emparejamiento (`PvpQuickmatchPanel`, hasta ahora un panel plano con `Outline`) pasa a placa con skin propia y deja de ser una caja gris. Como la UI del overlay se arma por código, las piezas se inyectan con el componente **`PvpOverlaySkin`** que el builder cuelga de `MenuCanvas` en `MainMenu`; si alguna pieza falta, el overlay cae al look plano anterior.

Generado con **Google Flow (Nano Banana 2.1, 0 puntos)**, mismo lenguaje "consola de acero" que §9. Ojo con el recorte: este lote tiene interiores claros (el vidrio del radar y el acero de la regla), así que el key se hace por **floodfill desde las 4 esquinas** en vez de `-transparent white` liso, para no agujerear el centro.

| Asset | Tamaño final | Destino | Notas |
|---|---|---|---|
| `ww_pvp_panel_skin.png` | 900×380 (2.37:1) | `Assets/_WildWeapon/Art/Sprites/` | Placa del modal: vidrio navy con tejido diagonal, esquinas chamferadas, borde acero fino y ticks en las esquinas. Gris neutro para tint. |
| `ww_pvp_button_skin.png` | 320×64 (5:1) | idem | Botón de cancelar: bisel con highlight superior y tapas laterales. Gris neutro. |
| `ww_pvp_rule.png` | 340×16 (21:1) | idem | Regla divisoria bajo el título, con rombo central y puntas anguladas. Gris neutro. |
| `ww_pvp_radar.png` | 256×256 | idem | Scope circular de búsqueda (anillos, sweep, blips, bisel con marcas). Gris neutro: el acento lo pone el código. |

**Prompts (esencia, en inglés):** misma cola de estilo que §9 — "ONE single … flat straight-on orthographic view, axis-aligned, aspect ratio about X to 1, deep navy glass body with subtle diagonal weave, crisp chamfered corners, thin light steel border, premium tactical game HUD style matching a family of dark metal UI plates, isolated on a completely flat uniform pure white background with clear margins, no shadow, no text, no icons". Variantes: botón "compact wide button plate, gentle raised bevel, soft top highlight, tiny accent ticks at the ends"; regla "extremely long and thin horizontal divider ornament, narrow steel line, small diamond shape in the exact center, tiny angled end tips"; radar "circular radar scope dial, three thin concentric rings, soft wedge-shaped scan sweep, small square blips, thin outer bezel with tick marks".

**Normalización (ImageMagick):**

```powershell
# Key por floodfill desde las 4 esquinas (preserva el vidrio claro del radar y el acero de la regla)
magick ww_pvp_panel_raw.jpg -alpha set -fuzz 9% -fill none -floodfill +0+0 white -floodfill +1375+0 white -floodfill +0+767 white -floodfill +1375+767 white -trim +repage panel_keyed.png
# Encuadre EXACTO al hueco de UI + gris neutro para el tint por acento (mismo tratamiento en las 4)
magick panel_keyed.png  -background none -resize 900x380! -modulate 100,0,100 ww_pvp_panel_skin.png
magick button_keyed.png -background none -resize 320x64!  -modulate 100,0,100 ww_pvp_button_skin.png
magick rule_keyed.png   -background none -resize 340x16!  -modulate 100,0,100 ww_pvp_rule.png
magick radar_keyed.png  -background none -resize 256x256! -modulate 100,0,100 ww_pvp_radar.png
```

**Montaje (overlay por código + `PvpOverlaySkin`):**

- `PvpOverlaySkin` — componente nuevo (`Scripts/UI/`) con `panel`, `button`, `rule`, `radar` (vía `Spr(...)`) y `shine` (`EnsureShine()`, la veta de §7); el builder lo completa en `BuildMenuScene`.
- `PvpQuickmatchPanel` busca el skin con `FindFirstObjectByType<PvpOverlaySkin>()` y arma el modal: placa con `RectMask2D` (recorta el barrido de luz), radar fantasma girando por detrás del contenido (34°/s conectando → 120 buscando → 300 al encontrar rival; alfa 0.10→0.18→0.30), regla bajo el título, estado con best-fit + pulso suave, bajada y botón con `MenuButtonFx` (hover heredado del menú).
- Tints por acento: placa `Lerp(Steel, violeta, 0.26)`, regla 0.55, botón 0.42 — mismo criterio que §8/§9 (acero frío + acento del modo).
- `ArtSpec` nuevos en la lista `Art` (panel 1024; button/rule/radar 512; PPU 512 estándar del set). Crudos en `_art-source/Menu/`.
- Verificación: reconstrucción con **WildWeapon > Dev > Reconstruir escenas (silencioso)** sin "Falta arte", `.meta` con `spritePixelsToUnits: 512` + `alphaIsTransparency: 1`, GUIDs presentes en `MainMenu.unity` (1 por pieza) y capturas en play de "CONECTANDO…" y "SIN CONEXION".

---

## 10. HUD de partida 1v1 (rework oct 2026)

> Tercer pase del rework de UI: el HUD **OnGUI** de F0 (`HudDebug`) se reemplaza por un **canvas uGUI** con placas biseladas propias. Misma familia visual que el menú (§8/§9) pero con piezas dedicadas para las placas de jugador, el marcador de ronda y la barra de vida. Tanda generada con **Google Flow (Nano Banana 2.1, 0 puntos)**; las piezas llegan como JPG sobre fondo blanco plano y se recortan con ImageMagick (key + trim), igual que §9.

**Nueva jerarquía** (la arma `WildWeaponBuilder.BuildMatchHud`, canvas `MatchHudCanvas` dentro de `Mode_Duelo`, sortingOrder 50 — debajo de la cuenta regresiva PvP que va en 60):

- `RoundBanner` — placa 384×64 arriba al centro: "RONDA n" (izq) + reloj mm:ss (der).
- `OverdriveBanner` — misma placa, teñida roja y pulsante: "¡OVERDRIVE! DAÑO ×1.5".
- `PanelJ1` / `PanelJ2` — placas 420×118 (una por lado, espejadas): tag "J1 · VOS/· RIVAL", marcas de ronda (pips), canal de vida 396×24 y chips de arma 186×34 (`ww_menu_chip_skin`).
- `Status` — placa 640×120 para los anuncios ("RONDA n", "GANA Jx…"), con entrada de fundido + desliz; el texto se auto-ajusta (best fit 22–40).
- `Footer` — controles, texto plano.

`MatchHud` (runtime) actualiza todo: el acento de cada placa sale del **color del personaje** (`visual.paintColor`), la vida baja al toque y vuelve suave (con destello blanco al recibir daño), la marca de ronda nueva entra con un pop y el anuncio central se tinta con el color del ganador.

| Asset | Tamaño final | Destino | Notas |
|---|---|---|---|
| `ww_hud_panel_skin` | 1024×288 (3.56:1) | `Assets/_WildWeapon/Art/Sprites/` | Placa de jugador (hueco 420×118): vidrio gris biselado + borde fino claro. Desaturada a gris para el tinte por personaje. |
| `ww_hud_round_plate` | 1024×171 (6:1) | idem | Placa del marcador (hueco 384×64) con divisor fino al medio (ronda / reloj). También se usa para el banner de Overdrive (teñida). |
| `ww_hud_status_plate` | 1024×192 (5.33:1) | idem | Placa de anuncios (hueco 640×120), más alta, con marco interno sutil. |
| `ww_hud_hp_track` | 1024×62 (16.5:1) | idem | Canal de vida vacío (hueco 396×24): interior hundido + labio claro. |
| `ww_hud_hp_fill` | 1024×48 (21.3:1) | idem | Relleno sólido claro (ancho variable = Hp01): se tintea de rojo→verde en runtime. |
| `ww_hud_pip` | 256×256 | idem | Marca de ronda ganada (rombo biselado, 20×20 en pantalla). |

**Prompts (inglés, un solo renglón, cola de estilo compartida):** *"ONE single [pieza] for a 2D fighting game HUD, flat straight-on orthographic view, perfectly axis-aligned, aspect ratio about [X:1], [descripción], crisp chamfered corners, thin light steel border, muted neutral grey, premium tactical game HUD style, dark-steel gothic sci-fi, no text, no letters, no numbers, no icons, no watermark, no shadow, on a completely flat pure white background with clear margins."* — descripciones: panel = "ultra-wide beveled steel nameplate, dark navy-grey glass body with a subtle diagonal weave and faint sheen, a slim brighter highlight line along the top edge"; round plate = "ultra-wide beveled steel plate with a faint thin vertical divider line in the exact center"; status = "beveled announcement banner plate with a faint inner frame line near the edge"; track = "extremely long and thin shallow recessed channel, dark inset interior, a slim light steel rim with beveled highlight along the top edge, completely empty inside"; fill = "extremely long and thin solid light grey metal bar with a lighter highlight along the top edge and a slightly darker bottom edge, perfectly uniform along its length"; pip = "small round-win marker badge: a bold chamfered diamond emblem with a subtle inner bevel and a thin darker outline".

**Normalización (ImageMagick):**

```powershell
# Key del fondo blanco + trim (las piezas salen como JPG sin alpha)
magick ww_hud_panel_skin_raw.jpg -fuzz 8% -transparent white -trim +repage keyed.png
magick identify keyed.png
# Encuadre EXACTO al hueco + gris neutro para el tinte por personaje
magick keyed.png -background none -resize 1024x288! ww_hud_panel_skin.png
magick ww_hud_panel_skin.png -modulate 100,0,100 ww_hud_panel_skin.png
# Preview sobre fondo oscuro para revisar halo/encuadre
magick -size 1024x288 xc:'#191f2b' ww_hud_panel_skin.png -composite preview.png
```

**Montaje en el builder** (`WildWeaponBuilder.BuildMatchHud` / `HudPlayerPanel`):

- `ArtSpec` nuevos en la lista `Art` (panel/round/status/track/fill 1024, pip 256; PPU 512 estándar del set).
- Si falta un skin, el código cae a paneles/colores planos (mismo patrón que el menú).
- Verificación: **WildWeapon > Dev > Reconstruir escenas (silencioso)** + play de la escena Arena (modo DUELO por defecto) con captura; probar daño (`DuelManager.Instance.Players[0].Health.TakeDamage(...)`) para ver la barra bajar.

**Notas de tanda (Flow):** el filtro de política de Flow bloqueó tres prompts por falsos positivos de vocabulario ("health-bar trough", "solid bar strip", "badge/marker"). Se resolvieron reformulando: el canal de vida quedó como "horizontal gauge rail" y la marca de ronda como "a square rotated exactly 45 degrees to form a diamond". Verificado en play (capturas, oct 2026): HUD completo en duelo, drenaje de vida con tinte rojo, pip de J2 al ganar ronda, anuncio "RONDA n: GANA Jx" con placa, banner ¡OVERDRIVE! pulsante y pie de controles.

---

## 11. Arenas: 12 mapas + plataformas + props compartidos (rework oct 2026)

> Cuarto pase de contenido: el juego pasa de **1 arena** a **12** (4 chicas 16×9, 4 medianas 20×11, 4 grandes 24×13). Tanda generada con **Google Flow (Nano Banana 2.1, 0 puntos)**.
>
> **Alcance aprobado ("arte de arena + props compartidos")**: 1 fondo por mapa (piso + decoración horneada, un solo sprite estirado al área) + set de plataformas (chica/mediana/grande, 9-slice) + 5 props compartidos nuevos = **19 piezas**. Las **plataformas y los peligros son código**, no arte: los dibuja `MapGenerator` (`MapPlatform`) y `ArenaHazard`, y su sombra/anillo salen procedurales (`EnsurePlatShadow` / `EnsureRing`).

**Cómo funciona cada pieza en el juego**

- **Fondo** → `MapDef.floorSprite` con `floorSingle = true`: un único sprite estirado a `arenaSize`. Trae el piso y la decoración horneada; el motor agrega encima los obstáculos (con collider), la decoración suelta, las plataformas y los peligros. Por eso el **centro del cuadro debe quedar relativamente limpio y oscuro** y **no** llevar personajes, criaturas, textos ni sombras proyectadas.
- **Plataformas** → `ww_plat_chica/mediana/grande` son **9-slice** (borde configurado en el `ArtSpec`: 96/110/130 px a PPU 320): se estiran a la huella del deck sin deformar las puntas. La lógica es *one-way* (`HeightBody` + `PlatformSurface`): se camina por debajo sin collider, se sube saltando desde abajo, se aterriza arriba y **no** se baja a través del deck (hay que caminar hasta el borde).
- **Props** → obstáculos compartidos entre temas (`MapProp` con `tint` por mapa). Los que declaran `height` (cajas, barriles, contenedores, chatarra, tubería, escombro) tienen **techo pisable**: se puede saltar encima y dejan de bloquear a esa altura.

**Tabla de los 12 mapas** (el id manda el nombre del asset y del fondo):

| # | id | Nombre / bajada | Tamaño | Acento | Decoración horneada del fondo | Peligros (código) |
|---|---|---|---|---|---|---|
| 1 | `duela` | Duela de Chatarra · DUELO SOBRE TABLAS ROTAS | chica 16×9 | naranja óxido `#FF8C33` | tablones hundidos, sierras oxidadas, pilas de chatarra, clavos | Prensa (DERRUMBE) |
| 2 | `neon` | Balcón de Neón · LUZ QUE CORTA | chica | magenta `#FF59D9` | pavimento mojado, balcones de hotel, carteles de neón, cables | Cartel de neón (ARCO) |
| 3 | `camara` | Cámara Fría · NO TE CONGELES | chica | hielo `#8CD9FF` | cámara de congelados, ganchos, cajas apiladas, escarcha | Escarcha (FRIO) |
| 4 | `eco` | Pozo del Eco · EL POZO RESPONDE | chica | verde agua `#4DFFD9` | pozo seco, piedra tallada, musgo, ecos en el agua | Eco del pozo (ONDA) |
| 5 | `leviatan` | Fosa Leviatán · ALGO GRANDE MURIÓ ACÁ | mediana 20×11 | verde ácido `#B3D95A` | costillas gigantes, charcos de ácido, huesos, arena oscura | Charco de ácido (ZONA) · Costillas (DERRUMBE) |
| 6 | `boveda` | Bóveda Dorada · LLUVIA DE MAYHEMCOINS | mediana | dorado `#FFCC40` | bóveda de banco, lingotes, cajas fuertes, puerta blindada | Lluvia dorada (MONEDAS) · Puerta blindada (DERRUMBE) |
| 7 | `nebula` | Chatarra Nebulosa · VIENTO Y CABLE PELADO | mediana | azul acero `#99BFFF` | desguace orbital, turbinas, paneles flotando, cables | Turbina (VENDAVAL) · Cable pelado (ARCO) |
| 8 | `vivero` | Vivero Mutante · LAS ESPORAS NO PERDONAN | mediana | verde `#80FF80` | invernadero, enredaderas, macetas gigantes, esporas | Nube de esporas (ZONA) · Raíces vivas (ZONA) |
| 9 | `templo` | Templo Hundido · EL AGUA SUBE Y BAJA | grande 24×13 | cian `#59E6F2` | templo inundado, columnas caídas, estatuas sumergidas | Inundación (ZONA) · Columna (DERRUMBE) · Marea (ONDA) |
| 10 | `domo` | Domo de Hielo · FRENAR ES MORIR | grande | hielo | domo polar, grietas, ventisca, témpanos | Ventisca (FRIO) · Témpano (DERRUMBE) · Ráfaga (VENDAVAL) |
| 11 | `mercado` | Mercado del Caos · OFERTAS QUE EXPLOTAN | grande | naranja `#FF9933` | mercado nocturno, puestos, toneles de aceite, monedas | Tonel de aceite (FUEGO) · Lluvia de monedas (MONEDAS) · Puesto que se cae (DERRUMBE) |
| 12 | `nucleo` | Núcleo Overdrive · TOCÁ EL NÚCLEO Y CORRÉ | grande | violeta `#B873FF` | reactor, cables, plasma, fosas de escoria | Pulso de plasma (ONDA) · Cables del núcleo (ARCO) · Fosa de escoria (FUEGO) |

**Prompts (inglés, un solo renglón).** Cola de estilo compartida para los **fondos**: *"ONE single top-down arena floor for a 2D arena fighting game, perfectly flat straight-down orthographic view, aspect ratio about [16:9 / 20:11 / 24:13], [tema], [piso + decoración horneada], the middle of the arena stays fairly clean and dark so characters read against it, corners and edges sinking into deep shadow, high contrast painterly comic style, dark moody palette, [acento] accents, no characters, no creatures, no letters, no numbers, no text, no watermark, no logo, no UI, no frame or border around the image, no cast shadows of characters, no vignette overlay."* — temas:

- `duela`: *"a wrecked scrapyard wood-plank floor: broken timber boards nailed over rusted metal sheets, scattered saw blades, bolts and small piles of scrap, oil stains"*
- `neon`: *"a rain-slicked neon alley pavement: wet dark asphalt with puddle reflections, glowing pink and cyan sign light spilling from above, thin cables and a fire escape ladder along the lower edge"*
- `camara`: *"a refrigerated cold-storage room floor: frost-covered concrete tiles, hanging meat hooks in the corners, stacked pale crates, icy mist creeping from the edges"*
- `eco`: *"a dried-up stone well floor: carved stone tiles forming a circle, moss in the cracks, faint glowing turquoise runes, wet stone"*
- `leviatan`: *"a beast graveyard floor: colossal fossil ribs arching across the ground, dark sand, acid pools glowing acid green, scattered bones"*
- `boveda`: *"a bank vault floor: polished golden granite tiles with inlaid steel lines, scattered gold ingots and coins, heavy safe boxes along the edges"*
- `nebula`: *"an orbital scrap-dealer floor: riveted steel plates with bolts, turbine vents cut into the deck, scattered hull panels and a floor cable running across"*
- `vivero`: *"an overgrown greenhouse floor: cracked ceramic tiles with weeds pushing through, giant flower pots, creeping vines, glowing spores drifting"*
- `templo`: *"a flooded ancient temple floor: wet carved stone slabs, shallow dark water with reflections, fallen columns lying across the ground, sunken stone faces"*
- `domo`: *"a polar ice dome floor: thick cracked ice with frosty fractures, snow drifts, frozen machinery half buried, cold blue glow from the cracks"*
- `mercado`: *"a night market street floor: cobblestone with wooden planks, oil barrels, overturned market stalls, scattered coins, embers"*
- `nucleo`: *"a reactor core chamber floor: dark industrial grating over a violet reactor glow, thick cables running across, scorch marks, molten slag pits at the edges"*

Cola de las **plataformas** (9-slice): *"ONE single flat elevated platform slab piece for a top-down 2D arena, perfectly flat straight-down orthographic view, aspect ratio about 3.2:1, a long rectangular [material] deck plate: perfectly straight horizontal top and bottom edges with a thin bright rim highlight along the top edge, a uniform repeating surface texture across the whole middle band so it can be stretched horizontally without distortion, identical decorative cap detail at both the left and right end, a thin dark outline around the whole silhouette, dark moody palette, [acento] accent light, no text, no letters, no numbers, no watermark, isolated on a completely flat pure white background with clear margins."* — materiales: `chica` = *"thin riveted steel catwalk plate"*; `mediana` = *"beveled steel and concrete deck plate"*; `grande` = *"thick industrial platform plate with bolted edge trims"*.

Cola de los **props** (mismo patrón que §3): *"ONE single [prop] for a top-down 2D arena fighting game, flat straight-down orthographic view, aspect ratio about 1:1, [descripción], thick dark outline, painterly comic style, dark moody palette, no text, no watermark, no ground shadow, isolated on a completely flat pure white background with clear margins."*

| Asset | Tamaño final | Props / descripción |
|---|---|---|
| `ww_prop_chatarra` | 512 px | pila de chapa retorcida, engranajes y tubos rotos |
| `ww_prop_tuberia` | 512 px | tramo de caño industrial con bridas y una válvula |
| `ww_prop_contenedor` | 512 px | contenedor metálico chico con puertas y remaches |
| `ww_prop_totem` | 512 px | tótem de chapa con carteles apilados y una antena |
| `ww_prop_escombro` | 512 px | montículo de escombros con ladrillos y varillas |

**Normalización (ImageMagick)**

```powershell
# Fondos: llenan el cuadro, no se keyean (van sin alpha real, se estiran al área de arena)
magick raw.png -resize 2048x -strip ww_map_duela_bg.png

# Plataformas: key del blanco + trim + encuadre exacto del 9-slice (el borde lo pone el ArtSpec)
magick ww_plat_mediana_raw.jpg -fuzz 8% -transparent white -trim +repage -background none -resize 1024x320! ww_plat_mediana.png

# Props: key + trim + lado máximo
magick ww_prop_tuberia_raw.jpg -fuzz 8% -transparent white -trim +repage -background none -resize 512x512 ww_prop_tuberia.png
```

**Tanda generada (18-oct-2026, Flow / Nano Banana 2.1, 16:9 y 1:1, x2 por prompt)**

Las 19 piezas salieron en un solo proyecto de Flow; se generaron **2 variantes por prompt** y se eligió una de cada par revisando un contact sheet (`magick montage`) por tamaño. Elección final:

| Pieza | Variante | Pieza | Variante |
|---|---|---|---|
| duela | `a` | nebula | `a` |
| neon | `b` | vivero | `a` |
| camara | `b` | templo | `a` |
| eco | `a` | domo | `a` |
| leviatan | `a` | mercado | `a` |
| boveda | `b` | nucleo | `a` |
| plat_chica | `b` (chapa de catwalk) | plat_mediana | `a` (paneles acero+hormigón) |
| plat_grande | `a` (diamantada con remaches) | | |
| chatarra | `b` | totem | `b` |
| tuberia | `b` | escombro | `a` |
| contenedor | `b` | | |

Notas de la tanda: el tile de resultado en Flow trae `flow-grid-tile-container[aria-label]` con una descripción automática del contenido (ej. *"Steel catwalk platform slab"*, *"Metal shipping container prop"*), que es la forma confiable de asignar cada imagen nueva a su prompt cuando hay varias generaciones en vuelo (los pares de plataformas se distinguen por ese label). Los crudos quedaron en `_art-source/Maps/`; los 20 PNG en `Assets/_WildWeapon/Art/Sprites/` y el builder los levanta por nombre (`ww_map_<id>_bg`, `ww_plat_chica/mediana/grande`, `ww_prop_chatarra/tuberia/contenedor/totem/escombro`).

Crudos en `_art-source/Maps/`; importados a `Assets/_WildWeapon/Art/Sprites/` (PPU 512 estándar, plataformas PPU 320 con borde 9-slice).

**Montaje en el builder** (`WildWeaponBuilder`): `BuildMapDefs()` crea/actualiza los **12 `MapDef`** (`Data/Maps/Map_<id>.asset`) desde la tabla `MapThemes()` y arma el **`MapCatalog`** (`Data/Maps/MapCatalog.asset`); `BuildMapSelectScene(catalog)` genera la escena **MapSelect** (3 filas × 4 tarjetas + ficha del mapa + JUGAR/VOLVER) y el `MainMenu` manda Duelo/Supervivencia ahí (`GameSession.SelectedMap` → `GameBootstrap` resuelve el `MapDef` del catálogo; en PVP online el mapa sale de la semilla del server, `seed % count`, para que los dos clientes jueguen la misma arena).

**Verificación**: **WildWeapon > Dev > Reconstruir escenas (silencioso)** sin "Falta arte", play desde MainMenu → modo → selector (12 tarjetas con acento y vista previa) → JUGAR → la arena elegida; saltar sobre una plataforma (sube, aterriza arriba, no la atraviesa al bajar) y pisar un peligro en piso vs. parado arriba de un deck (arriba no llega: `maxHeight`).

---

## 12. Plataformas por mapa: 12 slabs propios + layouts 3/5/9 (rework oct 2026)

> Quinto pase de contenido: se retiran las 3 plataformas compartidas de §11 (`ww_plat_chica/mediana/grande`) y **cada mapa estrena su propio sprite de plataforma** (`ww_plat_<id>`, 1024×320, 9-slice). Además se redefinieron los layouts por tamaño (**chico = 3 decks, mediano = 5, grande = 9**) y se vaciaron **temporalmente** los peligros, la decoración y los obstáculos: vuelven más adelante, ahora la arena es piso + plataformas. Tanda generada con **Google Flow (Nano Banana 2.1, 0 puntos)**, x1 por prompt (16:9).

**Las 12 piezas** (material del slab / acento):

| id | Material | Acento |
|---|---|---|
| `duela` | tablones de madera sobre marco de acero oxidado | óxido |
| `neon` | hormigón mojado + acero con franja de neón | magenta/cian |
| `camara` | acero helado esmerilado | hielo |
| `eco` | piedra tallada con musgo y runas | turquesa |
| `leviatan` | hueso fósil | verde ácido |
| `boveda` | mármol dorado con molduras de bronce | dorado |
| `nebula` | acero orbital remachado | azul acero |
| `vivero` | cerámica agrietada con enredaderas | verde |
| `templo` | piedra de templo tallada y húmeda | cian |
| `domo` | hielo agrietado | hielo |
| `mercado` | tablones de puesto sobre cajones | naranja |
| `nucleo` | rejilla industrial sobre brillo de reactor | violeta |

**Prompt base** (inglés, un renglón; mismos remates que la cola de §11, cambia el material):

*"ONE single flat elevated platform slab piece for a top-down 2D arena game, perfectly flat straight-down orthographic view, aspect ratio about 3.2:1, a long rectangular **[material]**, perfectly straight horizontal top and bottom edges with a thin bright rim highlight along the top edge, a uniform repeating **[texture]** across the whole middle band so it can be stretched horizontally without distortion, identical decorative **[cap]** detail at both the left and right end, a thin dark outline around the whole silhouette, dark moody palette, **[accent]** accent light, no text, no letters, no numbers, no watermark, isolated on a completely flat pure white background with clear margins."*

Ejemplos de material: `wooden planks over rusted steel frame`, `frosted icy steel`, `carved mossy stone with turquoise runes`, `fossil bone`, `golden marble with brass trim`, `riveted orbital steel`, `cracked ice`, `industrial grating over violet reactor glow`.

**Normalización (ImageMagick)**

```powershell
# Slab por mapa: key del blanco + trim + encuadre exacto del 9-slice (borde 110 px por ArtSpec)
magick plat_<id>_raw.jpg -fuzz 8% -transparent white -trim +repage -background none -resize 1024x320! ww_plat_<id>.png
```

**Montaje en el juego**

- `MapDef.platformSprite`: **un solo** sprite por mapa; todos los decks de la arena usan ese arte. El enum `MapPlatformSize` quedó **descriptivo** (etiqueta del deck: Baja/Media/Alta), ya no elige arte.
- `MapGenerator.Platform()` usa `sprite.border` (9-slice → `SpriteDrawMode.Sliced`) y estira a la huella de `MapPlatform.size`; sombra procedural igual que antes.
- Layouts por tamaño (`MapThemes()`): **chico 3** decks (1 central + 1 par espejado), **mediano 5** (1 + 2 pares), **grande 9** (1 + 4 pares). El central va `mirrored = false` (no se duplica sobre sí mismo); los pares se espejan a 180° en duelo/PVP (`mirroredForDuel`).
- Alturas 0.55/0.95/1.35 (Baja/Media/Alta): el salto llega a ~1.6, así que la Alta se sube desde otro deck y las demás se suben del piso.
- `ww_plat_chica/mediana/grande` quedaron obsoletas: `CleanupLegacy()` las borra (PNG + meta) al reconstruir escenas.
- Sin peligros/decoración/obstáculos por ahora: `MapThemes()` ya no declara esas listas, los contadores quedan en 0 y `Fill()` es null-safe (`Obstacles()/Decor()` devuelven vacío, `def.hazards` queda `[]`). La ficha del selector muestra la **cuenta real de decks** (3/5/9 en duelo; sin espejo en Supervivencia).
- Crudos de esta tanda en `_art-source/Maps/plat_<id>_raw.jpg` (junto a los crudos previos `plat_chica_a/mediana_b/grande_a`, que quedan como archivo).

**Verificación (18-oct-2026)**: `Reconstruir escenas (silencioso)` sin "Falta arte"; render de los 12 mapas en modo espejo (960×540) con las cuentas exactas **3/5/9** y el arte propio de cada mapa; duelo jugado desde el menú (Duela de Chatarra) con sus 3 decks y sombras; ficha del selector: "CHICA · 16x9 · 3 PLATAFORMAS · 0 PELIGROS".
## 13. Fondos de entorno de los 12 mapas (rework oct 2026)

> Sexto pase de contenido: se reemplazan los fondos de placeholder por **entornos cenitales con volumen** generados con Google Flow (Nano Banana 2.1, 0 puntos, 16:9, x2). La arena de juego ocupa ~70% del encuadre, centrada; el resto es entorno del lugar (el lugar se lee alrededor). El arte es agnóstico al tamaño de arena: al estirarse al encuadre, la composición se mantiene. Tanda generada en el proyecto Flow `flow.google.com/project/982ec143-0ff6-44b8-9390-72bf05e6eca3`.

**Estilo elegido**: "entorno cenital con volumen" (vista picada ~35°, sin personajes, sin texto). Área de pelea ~70% centrada y limpia; el entorno del lugar cubre el resto del encuadre. Muros pasan a ser solo collider (sin sprite visible).

**Integración en código**:
- `MapDef.backdropArenaFraction`: fracción del encuadre que ocupa la arena (0.45–0.95). Cada mapa tiene su valor afinado.
- `MapGenerator` (Awake): cámara primero → `ortho = max(half.y/f, half.x/(f*aspect))`; fondo "Entorno" estirado a `view × 1.02` (cubre todo el encuadre sin bordes); muros solo collider.
- `WildWeaponBuilder.MapThemes()`: `MapTheme.backdropFraction` + `wallSprite = null` en `Fill()`.
- Script de control: `_art-source/_tools/map-layout-preview.ps1` arma el encuadre real (fondo + decks + rect de arena) sin entrar a Play; salida en `%TEMP%\opencode\ww_map_preview\`.
- Crudos archivados: `_art-source/Maps/<id>_env_<id8>_raw.jpg` (duela usa `duela_env_b_raw.jpg`, elegida por el usuario).

**Los 12 fondos** (id / fracción / variante elegida de Flow):

| id | backdropFraction | Variante Flow (id8) |
|---|---|---|
| `duela` | 0.68 | a38f682b |
| `neon` | 0.66 | 7ca8bf84 |
| `camara` | 0.64 | b3df493b |
| `eco` | 0.71 | 76647fc1 |
| `leviatan` | 0.68 | 784a61fc |
| `boveda` | 0.68 | 7a76ebdd |
| `nebula` | 0.67 | 7662d0bd |
| `vivero` | 0.66 | 10a47305 |
| `templo` | 0.68 | 8cedeb12 |
| `domo` | 0.70 | d4172315 |
| `mercado` | 0.67 | 58e8b6d5 |
| `nucleo` | 0.67 | f3ff009e |

Prompts completos y temas por mapa: ver el proyecto Flow (28 candidatas descartadas en `%TEMP%\opencode\ww_env_raw\env_<id8>.jpg`). Para cambiar un fondo: `magick <src> -resize 2048x -strip "Assets\_WildWeapon\Art\Sprites\ww_map_<id>_bg.png"`.

**Normalización (ImageMagick)**:
```powershell
# Fondo por mapa: 2048x1143, estirado al encuadre por MapGenerator
magick <id>_env_<id8>_raw.jpg -resize 2048x1143! -strip ww_map_<id>_bg.png
```

**Verificación**: fondos instalados en `Assets/_WildWeapon/Art/Sprites/ww_map_<id>_bg.png` (2048×1143, mismos nombres ⇒ mismos GUIDs). Escenas reconstruidas con los fondos nuevos (menú dev "WildWeapon/Dev/Reconstruir escenas (silencioso)" corrió OK). Crudos archivados en `_art-source/Maps/`.

## 14. Etapa 2: arenas ampliadas (x2) — oct 2026

> Tamaños confirmados por el usuario: **Chico 32×18, Mediano 40×22, Grande 48×26** (antes 16×9 / 20×11 / 24×13). Implementado en `WildWeaponBuilder.ArenaSize()` y reubicación de decks (centros ×2, huellas sin cambios) en `Fill()`. El arte es agnóstico al tamaño: el fondo se estira al encuadre y la composición se mantiene. Los spawns (`p1Spawn`/`p2Spawn`) se recalculan desde `arena * 0.5`. Pendiente: eliminación del modo 1v1 y rework multijugador (fuera de esta etapa).

---

## 15. Lobby multijugador local: reordenamiento del layout (oct 2026)

> Primer pase del rework del lobby. La escena venía a mano: una placa estirada a pantalla completa, el título flotando y tres botones planos gigantes que se pisaban con el marco. Ahora la arma el generador (`WildWeaponBuilder.BuildLobbyScene`, entra en `BuildAllSilent` y en `EditorBuildSettings`) y la grilla vive en un solo lugar: `WildWeapon.UI.LobbyLayout`, que comparten el generador (encabezado de columnas) y `MultiplayerLobbyController` (filas del runtime). Los números no se pueden desalinear al retocar la maqueta.

**Qué cambió**

- **Placa del tablero**: `ww_lobby_panel` (1024×512, 2:1 exacto) sin deformar en 1400×700, centrada en y −14 (antes: la placa vieja estirada a pantalla completa).
- **Línea de estado**: la bajada del título se parte en dos mitades — a la izquierda `LOCAL · n / 15 JUGADORES` (dinámico), a la derecha el estado (`LISTO PARA ARRANCAR` / `AGREGA OTRO JUGADOR PARA ARRANCAR`, en cian o ámbar). El plantel (`n JUGADORES · m EQUIPOS`) va pegado al chip de arriba a la derecha. Así el pie solo tiene botones y **entra en pantallas anchas** (en 21:9 el canvas queda en ~932 unidades de alto: todo el lobby vive dentro de ±452).
- **Lista con scroll**: pozo propio + `ScrollRect` + `VerticalLayoutGroup` + `ContentSizeFitter`; la barra (12 de ancho, `Permanent`) es 9-slice del panel generado. El viewport mide 1188×476 = 6 filas exactas de 72 + gaps de 8. Hasta 15 jugadores (`MultiplayerLobbyController.MaxPlayers`).
- **Filas por código** (una por jugador): barra de acento del color, orbe de color clickeable (cicla la paleta), campo de nombre, **control** y **equipo** como campos `« VALOR »` que ciclan con click, y la etiqueta de asiento `J1..J15` teñida.
- **Dropdowns afuera**: los `Dropdown` viejos no tenían template, así que las opciones nunca se veían. Los steppers conservan los mismos índices (`controlIndex`, `team`) que ya consume `GameBootstrap`.
- **Botonera**: `− QUITAR` (rojo), `+ AGREGAR` (verde) | `VOLVER` (acero) | `CONTINUAR` (cian, deshabilitado con menos de 2 jugadores). Todos 320×80 (4:1, igual que el arte) con el hover de `MenuButtonFx`; el que no corresponde se apaga con un `CanvasGroup` (0.42) para no pelear con el FX. `Esc`/`Backspace`/`Start` vuelven al menú.

**Geometría (`LobbyLayout`, unidades de la resolución de referencia 1920×1080)**

| Pieza | Números |
|---|---|
| Tablero | 1400×700 en y −14 · marco interior 96/84 → interior 1208×532 |
| Encabezado | alto 44 en y 244 (regla de 2 px en 218), columnas centradas sobre las de la fila |
| Lista | viewport 1188×476 centrado en x −10, y −28 · barra 12 de ancho en x 598 |
| Fila | alto 72, gap 8 · barra x 14 (5×34) · orbe centro 62 (caja 60, orbe 46, halo 84) · nombre x 104 (470) · control x 590 (320) · equipo x 926 (200) · asiento x 1138 (44) |
| Pie | botones en y −412 · divisor de 2×54 entre los pares |

**Montaje**

- `LobbyLayout.cs` (nuevo, `Scripts/UI/`): constantes compartidas.
- `MultiplayerLobbyController.cs`: filas, steppers, estado de los botones, fundido. Los textos de estado y el fader se cablean desde el generador.
- `WildWeaponBuilder.BuildLobbyScene()` + `LobbyButton()`/`LobbyList()`/`LobbyHeader()`; el arte generado (`_soft`, `_panel`, `_vignette`) se asegura solo, así el menú **WildWeapon > Dev > Reconstruir lobby (silencioso)** itera la maqueta sin rehacer el juego entero.
- Verificación: reconstrucción + captura en play (2 y 15 jugadores: la barra queda en 0.40, `+ AGREGAR` se apaga a los 15 y `CONTINUAR` prende con 2).

**Sprites pendientes (para el próximo lote)**

| Asset | Tamaño sugerido | Estado |
|---|---|---|
| `ww_lobby_button_remove` / `_continue` / `_back` | 256×64 (4:1) | **Instalados** (los cuatro ya están en `Art/Sprites` y en el `ArtSpec`): las placas son grises neutras casi idénticas, así que cada botón se distingue por el tinte de acento (`Lerp(blanco, acento, 0.18)`) + el `Outline`. Si en el próximo lote llega una versión con rasgos propios (símbolo o bisel distinto por acción), se reemplaza el archivo con el mismo nombre y el generador la toma solo. |
| `ww_lobby_title_banner` | 1024×170 (6:1) | **Instalada** (ver §16): es la placa del título, en 760×126 sobre la columna del tablero. |
| `ww_lobby_player_card` | 512×128 (4:1) | **Instalada** (ver §16): cada fila arranca con la tarjeta a escala 4:1 (260×65), sin deformar: el orbe del color cae en el medallón pintado y el asiento en el panel de la derecha. |
| `ww_lobby_row_plate` (9-slice) | 1024×128 | Opcional: hoy la fila usa `ui_panel` generado + tinte navy. Útil para que la fila tenga bisel propio; **debe ser 9-slice** (estirar `ww_lobby_player_card` deforma el círculo pintado: por eso va a tamaño fijo, ver §16). |
| `ww_lobby_scroll_track` / `_handle` | 128×… | Opcional: hoy son 9-slice del panel generado (riel oscuro + manija acero). |
| Emblemas de columna (color/nombre/control/equipo/asiento) | 64×64 | Opcional: hoy el encabezado es solo texto (16 px, acero claro). |

> Regla para el lote: **gris neutro** (`-modulate 100,0,100`) y encuadre exacto al hueco, igual que §8–§10 — el acento y el color de cada jugador los pone el código.

## 16. Lobby: placa del título y tarjeta de jugador (oct 2026)

> Segundo pase: entra el arte de §15 (banner + tarjeta) y la cabecera se reflota para que el título tenga placa propia. No se tocó la estructura, solo alturas y columnas.

**Qué cambió**

- **Placa del título**: `ww_lobby_title_banner` en 760×126,17 (6,02:1, sin deformar) centrada en y 391, con el título encima a 42 px. La cabecera cuelga de la bajada y el tablero, **no** del borde superior: en 21:9 el canvas queda en ~932 de alto, así que el borde de arriba está en 466 y la placa termina en 454 (12 de aire). Los chips viven pegados a las esquinas (x ±34), o sea que se cruzan con la placa en vertical pero nunca en horizontal: no hay colisión en ningún aspecto entre 4:3 y 21:9.
- **Tablero 1400×650** (antes 700): 7% más bajo que el arte 2:1 — imperceptible en un marco tan fino y es lo que le da el aire a la placa. El ancho no se toca, así que las columnas de la fila siguen midiendo lo mismo. Marco interior 96/78 → interior 1208×494; la lista queda 1188×438 y muestra 5 filas y media (el resto, scroll).
- **Tarjeta de jugador**: cada fila arranca con `ww_lobby_player_card` a **tamaño fijo 260×65** (4:1, escala 0,508). El arte trae el medallón pintado, medido sobre el PNG: disco interior en (66, 65,2) con radio 38,4 px → a esa escala el centro cae a 33,5 del borde de la tarjeta, así que **el orbe del color va en x 43,5** (caja de click 60, orbe 44, halo 62) y se apoya justo dentro del anillo. El panel de la derecha (x 150–473 del arte) hospeda el asiento `J1..J15` a 22 px, aclarado un 30% hacia blanco + sombra: sobre el gris oscuro del panel, el color puro no se leía.
- **Columnas nuevas de la fila**: nombre x 284 (336), control x 636 (288), equipo x 940 (240); el encabezado del tablero pasa a `JUGADOR · NOMBRE · CONTROL · EQUIPO` (el `N°` suelto desapareció: el asiento ahora está en la tarjeta). El encabezado y las filas siguen saliendo del mismo `LobbyLayout`.
- La **barra de acento** (x 14, 5×34) solo se dibuja como respaldo si falta el sprite de la tarjeta; con tarjeta, el color lo llevan el medallón y el asiento.

**Geometría (`LobbyLayout`, unidades de la resolución de referencia 1920×1080)**

| Pieza | Números |
|---|---|
| Placa del título | 760×126,17 en y 391 · título 42 px (495 de ancho de texto) |
| Bajada | y 307 (borde de arriba del tablero en 286) |
| Tablero | 1400×650 en y −39 · marco interior 96/78 → interior 1208×494 |
| Encabezado | alto 44 en y 225 (regla de 2 px en 199) |
| Lista | viewport 1188×438 centrado en x −10, y −28 · barra 12 de ancho en x 598 |
| Fila | alto 72, gap 8 · tarjeta x 10 (260×65) · orbe centro 43,5 · asiento x 146 (44) · nombre x 284 (336) · control x 636 (288) · equipo x 940 (240) |
| Pie | botones 320×80 en y −412 · divisor de 2×54 entre los pares |

**Verificación**

- Reconstrucción con **WildWeapon > Dev > Reconstruir lobby (silencioso)** y captura en play con 2 y 15 jugadores: la placa del título entra completa con el título centrado, las filas alinean con el encabezado, el orbe cae dentro del medallón (medido: orbe 44×44 con centro en x 43,5 sobre una tarjeta en x 10), a los 15 jugadores `+ AGREGAR` se apaga y la lista scrollea al último (contenido 1192 en un viewport de 438).
- Recordatorio del flujo: el arte se registra en el `ArtSpec` del generador (PPU 512, CompressedHQ, alpha, Bilinear) y se cablea por nombre; **reconstruir la escena después de recompilar** (si el menú de dev corre antes de que termine el recompilado, la escena sale con los números viejos).

**Pendientes para el próximo lote (opcionales)**

| Asset | Tamaño sugerido | Para qué |
|---|---|---|
| `ww_lobby_row_plate` (9-slice) | 1024×128 | Bisel propio de la fila (hoy `ui_panel` + tinte navy). |
| `ww_lobby_scroll_track` / `_handle` | 128 de ancho | Riel y manija de la barra (hoy 9-slice del panel). |
| Emblemas de columna | 64×64 | Chips chicos para `JUGADOR · NOMBRE · CONTROL · EQUIPO` (hoy texto 16 px). |
| Insignia de equipo (A–D) | 64×64 | Al lado del stepper de equipo, con el color del equipo. |
| Iconos de control (teclado / pads) | 64×64 | Reemplazar el texto `TECLADO` / `PAD n` del stepper. |


## 17. Lobby online por código de sala + bots en la arena (oct 2026)

> Tercer pase: la maqueta local se reemplaza por una sala real sobre `server.js` (`/wildweapon/pvp`). La tarjeta 1 del menú pasa a ser la puerta de entrada al lobby online.

**Qué cambió**

- **Menú**: la tarjeta 1 dice `SALA CON CODIGO` / `MULTIJUGADOR ONLINE` y la franja de info la describe (sala por código, hasta 15, bots de relleno). La tarjeta 2 (quickmatch) queda `PVP ONLINE` / `DUELO RAPIDO 1 VS 1`. El generador es la fuente: las etiquetas también se corrigieron en `MainMenu.unity`.
- **Servidor (`server.js`)**: familia `lobby_*` dentro de la sección WW-PVP. Código de 5 dígitos (al entrar se aceptan 4–6), 15 asientos, bots del anfitrión (cuentan para el límite), **lista de espera** cuando la sala está llena (`lobby_full`) con reingreso automático apenas se libera un asiento, aviso a la sala del número de espera, promoción de anfitrión al salir el dueño (los bots se van con él) y salas de lobby con TTL de 3 h (el barrido de 10 min solo toca partidas en curso).
- **Lobby (`MultiplayerLobbyController`)**: dos pasos sobre el mismo tablero. El modal de entrada (`ww_lobby_panel` + `ww_lobby_button_add`) pide el código; el modal de sala llena late el orbe y ofrece `CANCELAR ESPERA`. Las filas salen del roster del server y solo el asiento propio edita nombre/color/equipo (`lobby_set`); los bots se muestran `IA` en dorado y el anfitrión lleva contorno dorado. `+ BOT` / `- BOT` solo para el anfitrión; `ARRANCAR` con 2+ asientos, `ESPERANDO` para el resto. El nombre se recuerda en `PlayerPrefs` (`ww_pvp_name`).
- **Arena (`PvpMatchManager` + `PvpBotBrain`)**: N asientos. El anfitrión simula los bots (sin espejo de red) y les da cerebro propio (persecución, viento de ataque, recuperación, salto y separación); los demás clientes los dibujan como remotos. Los `hit` llevan `target` para rutear el daño al asiento correcto. La primera ronda espera el `ready` de todos y **los bots nacen listos**; si cae el último humano con bots vivos, la ronda la gana la IA (`winner -1`).
- **Robustez**: los estados del lobby se aplican como máximo uno por frame (el server puede mandar varios seguidos; reconstruir la lista por mensaje congelaba el editor).

**Protocolo**

| Mensaje | Campos |
|---|---|
| `lobby_new` | `name`, `color` → responde `lobby_state` con `code` |
| `lobby_join` | `room` (4–6 dígitos), `name`, `color`; sala llena → `lobby_full` (`pos`, `n`) |
| `lobby_set` | `name`, `color`, `team`, `control` (solo el asiento propio; −1 = sin cambio) |
| `lobby_bots` | `n` (solo anfitrión; target 0–14) |
| `lobby_start` | solo anfitrión, 2+ asientos → `matched` (`seat`, `seed`, `team`, `host`, `opps[]` con `bot`) |
| `lobby_state` | `code`, `seat`, `host`, `started`, `n`, `total`, `waiters`, `players[]` |
| `lobby_closed` / `lobby_error` | motivo / texto para el modal |

**Verificación**

- Protocolo local (server con stub de `pg`): **20/20** — crear, entrar por código, bots hasta 15, aviso de sala llena, ingreso automático al liberar, edición de asiento, permisos de arranque, `matched` completo, rechazo de sala arrancada, código inexistente, promoción de anfitrión, `ready` con bots, cierre sin humanos (`winner -1`) y revancha con voto de bots.
- Play (Aura): sala de 1 humano + 14 bots desde un cliente Node → el jugador entra, queda en `SALA LLENA` → el anfitrión libera un bot → ingresa solo en el asiento 15 → `VOLVER` sale de la sala. Después: sala propia + 3 bots + `ARRANCAR` → arena con 4 combatientes, `round_start` en el server y los bots persiguiendo al jugador (capturas 00:00 → 00:06).

**Pendientes / límites conocidos**

- El HUD de la arena sigue siendo 1v1 (`J1 · VOS` vs el primer rival) y el marcador guarda 2 valores: con 15 asientos solo se ve el primero. El equipo de la arena es 0/1 (el equipo A–D del lobby es cosmético) para que la ronda no quede trabada.
- Los bots no votan revancha por su cuenta: votan con el anfitrión.
- Sprites opcionales del lote anterior (riel/manija del scroll, placas de fila, emblemas de columna, insignias de equipo A–D, iconos de teclado/pad) siguen pendientes.
