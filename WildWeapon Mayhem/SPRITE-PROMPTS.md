# WildWeapon Mayhem — Prompts de Sprites (v1)

> Objetivo: sacar el juego del greybox — portador, Katana, arenas, pickups y VFX.
> Cada bloque sigue el formato de `ICON_PROMPT.md` (Art direction / Technical / Negative). Los prompts van en **inglés** (los generadores rinden mejor así); el resto del documento en español.

---

## 0. Reglas de uso (leer antes)

1. **Un asset por generación.** Las grillas multi-frame salen irregulares: normalizar SIEMPRE con el pipeline ImageMagick del workspace (regla 6): `-extent` → `-crop CxR@ +repage +adjoin` → `-trim +repage -gravity center -extent`.
2. **Pivote y escala fijos.** Personaje: celda 256×256, pivote centro. Armas/VFX: celda 256×256, pivote centro. El personaje de la hoja base mira hacia **arriba (N)** y el juego rota el sprite; alternativa recomendada si el generador mezcla direcciones: **generar por dirección (S, N, E) y el oeste con flip horizontal**.
3. **Fondo plano puro** (blanco o transparente): el pipeline lo recorta. **Sin sombras horneadas** — las luces y sombras las pone el motor.
4. **Crudo vs importado:** crudo a `_art-source/`; lo normalizado se importa a `Assets/_WildWeapon/Art/`.
5. **Nombres:** `ww_<asset>_<anim>_<dir>_##.png` (ej: `ww_portador_run_S_00.png`). Las armas mantienen la convención existente: `katana_00..23.png`.
6. **Intensidad de glow:** contenida. Los sets existentes (Chain Scythe rojo, Tiger naranja, Zeus azul) marcan el techo — lo nuevo no debe brillar más que ellos.

**Paleta maestra (ancla de todo):**
- Cian neón `#00F3FF` · magenta eléctrico `#BC13FE` · navy/negro `#050510`
- Metales oscuros con rim light · **Katana = acero gris SIN glow** (arma común); el color neón se reserva para armas de tier superior
- Alto contraste, siluetas legibles a tamaño chico, bloom contenido.

**Resumen de assets de esta tanda:** portador (idle/run/dash/hit/KO), Katana (tajo + en mano + render), 3 pisos de arena + props + muros + hazards, 2 orbes, 4 VFX, 6 partículas ambientales.

---

## 1. Portador (reemplaza el cuadrado blanco)

### 1.1 Hoja base v0 — idle (variante A: 4 frames) y run (variante B: 6 frames)
Generar **una vez por animación y por dirección** (S, N, E; oeste = flip). Van dos variantes del mismo prompt base:

```
Top-down (bird's-eye) orthographic sprite of a futuristic duelist for a 2D arena PVP game,
seen from directly above (head crown, shoulders and arms visible, foreshortened),
character faces UP in every frame.

Art direction:
- Compact readable silhouette; dark tactical armor (#050510 base) with metal joints.
- NEUTRAL design for skin recoloring: body in cold greys, ONLY energy accents in cyan (#00F3FF).
- Combat stance, weapon held forward (weapon sprite is layered separately, out of frame).
- Consistent top light, subtle cyan rim light. No projected floor shadows.
- Style: painted AAA game sprite, clean; matches the game's dark weapons with energy glow.

Technical output requirements:
- VARIANT A: 4 frames in one horizontal row (idle breathing loop: 2 up, 2 down).
- VARIANT B: 6 frames in one horizontal row (run cycle: contact, pass, up, contact, pass, up).
- Same cell size, character centered, uniform spacing. Cell 256x256. Flat pure white background.
- Pivot: body center (navel), identical across all frames.

Negative constraints:
- NO 3/4 view, NO oblique birds-eye, NO perspective: strictly perpendicular top view.
- Face not visible (only crown/helmet), no text, no watermark, no scene background, no baked shadows, no weapon effects.
```

### 1.2 Otras animaciones (misma plantilla que 1.1, cambiando solo la acción)
- **Dash (3 frames):** cuerpo inclinado en la dirección, estela corta cian detrás, sin arma.
- **Hit (2 frames):** retroceso seco, cabeza atrás, chispas mínimas.
- **KO (6 frames):** desplome hacia el costado, casco suelto al final (queda como pieza de piso).
- **Win (4 frames):** puño al aire, pose breve (para el cierre de ronda).

### 1.3 Nota de skins (para producción)
El cuerpo en grises fríos es a propósito: el recolor por tinte (HSV) cubre las skins base del doc (sección 7). El acento cian queda fijo en v0; las variantes de acento llegan con las skins épicas.

---

## 2. Katana (arma inicial)

> **Arma común:** VFX grisáceo y básico. La intensidad de VFX escala con la rareza — la Katana no lleva glow de color (eso se reserva a tiers superiores).

### 2.1 Hoja de tajo M1 — 24 frames, grilla 6×4, celda 256×256 (igual que los sets existentes)
```
Top-down weapon slash VFX sprite sheet for "Katana", the STARTER/common weapon of a 2D arena PVP game.
Design intent: a common weapon must read clean and honest — minimal, desaturated VFX, no neon glow.

Art direction:
- Iaido crescent cut in plain steel grey/off-white: a thin matte blade arc, sweeping left→right across the cell.
- NO colored glow, NO neon edge, NO bloom: just a soft grey motion smear and a few grey dust particles.
- The arc grows, peaks mid-sequence and fades quickly; the effect sits at HALF the visual intensity of the colored sets (they are the ceiling).
- Flat pure white background. No character, no hand, no sword body: only the cutting effect.

Technical output requirements:
- Exactly 24 frames, 6 columns x 4 rows grid, cell 256x256, uniform spacing.
- Arc is continuous and readable as one motion when played at ~60 fps.

Negative constraints:
- No colored energy, no cyan/magenta/neon, no text, no watermark, no environment, no character, no camera shake marks, no double cuts.
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
- Style match: same family as the existing arsenal renders (dark metal + glowing core + light motion smear behind).
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

### 3.4 Hazards (telegrafiado, legible)
```
Situational top-down VFX sprite sheet, 6 frames, cell 256x256, flat white background:
[VARIANTE]:
- Nebula: falling debris telegraph — growing dark shadow circle with a faint magenta rim, then impact flash.
- Leviatán: electrified border pulse — teal lightning crawling along a straight edge strip.
- Bóveda: shower of golden MayhemCoins — 5-6 coins falling with warm sparkle, adding up frames 1..6.
Style: high readability, muted glow. No text, no watermark, no characters, no perspective.
```

---

## 4. Pickups y VFX genéricos

### 4.1 Orbes
```
Top-down pickup orb sprite sheet, 4 frames (hover bob + pulse), cell 128x128, flat white background.
- ADRENALINA: cyan energy sphere with electric arcs inside, calm pulse.
- MAYHEMCOIN: gold coin with a stylized "W", soft warm glow, slow spin.
Style: premium arcade, readable at small size. No text, no watermark, no perspective.
```

### 4.2 Dash / impacto / KO
```
Top-down VFX sprite sheet, flat pure white background:
- DASH TRAIL: 3 frames, teardrop motion streak, white core fading to cyan, cell 128x128.
- HIT IMPACT: 6 frames, radial white burst with small sparks, NEUTRAL color (tintable in engine), cell 128x128.
- KO BURST: 8 frames, white flash ring expanding with dark shards flying out, cell 256x256.
No text, no watermark, no characters, no perspective, no environment.
```

---

## 5. Ambiente (vida barata por tema)

```
Tiny ambient particle sprite sheet, 4 variants in one row, cell 32x32, flat white background:
- Nebula: drifting dark dust motes with a cyan glint.
- Leviatán: bioluminescent teal dots, soft glow halo.
- Bóveda: gold sparkles, warm twinkle.
One sheet per theme. No text, no watermark, no perspective.
```

---

## 6. Checklist de producción

| Asset | Grilla | Celda | Destino |
|---|---|---|---|
| Portador idle/run (por dirección) | 1×4 / 1×6 | 256 | `Art/Characters/` |
| Portador dash / hit / KO | 1×3 / 1×2 / 1×6 | 256 | `Art/Characters/` |
| Katana tajo M1 | 6×4 (24) | 256 | `Art/Weapons/Katana/` |
| Katana en mano | 1×1 | 128 | `Art/Weapons/Katana/` |
| Katana render | 1×1 | 1024 | `_art-source/` (ficha/tienda) |
| Pisos de arena (×3) | tileable | 512 | `Art/Arenas/<tema>/` |
| Props y muros | 1×1 | 512 / 256 | `Art/Arenas/<tema>/` |
| Hazards | 1×6 | 256 | `Art/VFX/` |
| Orbes | 1×4 | 128 | `Art/Pickups/` |
| Dash / impacto / KO | varias | 128–256 | `Art/VFX/` |
| Partículas ambientales | 1×4 | 32 | `Art/VFX/` |

**Orden sugerido de producción:** 1) Portador idle+run → 2) Katana (tajo + en mano) → 3) Piso Bóveda Dorada + props → 4) orbes y VFX → 5) los otros 2 pisos + hazards + ambiente.

> Cuando haya arte nuevo, se normaliza con el pipeline y se integra al builder de F0 (`F0SceneBuilder`) para reemplazar los rectángulos por sprites reales.
