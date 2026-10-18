# WildWeapon Mayhem — Habilidades de la Katana (Q/E/R)

> Plan técnico + arte. Alineado con `WILDWEAPON-MAYHEM-DISENO.md` (§2.4 ataques, §3 arsenal, §8 arte, §11 roadmap F1).
> Estado del juego: el rig esqueletal, el combate melee y los VFX por arma ya existen; falta el **sistema de habilidades** y su contenido.
> Arte: hoy se genera con **Aura (tryaura.dev)** vía MCP — los créditos son reales, coordinar lotes.

---

## 1. Las 3 habilidades (según doc maestro §3)

| Tecla | Nombre | Rol | Mecánica | Números propuestos |
|---|---|---|---|---|
| **Q** | **Corte Circular** | Control / apertura | Gira y corta en 360° a su alrededor. Aplica **stun 0.4 s**. Radio corto (≈1.2 u). | dmg 20 · cd **6 s** · cast 0.5 s (windup 0.15 · active 0.1 · recovery 0.25) |
| **E** | **Dash-Tajo** | Movilidad / engage | Dash ofensivo de ~2.5 u que **atraviesa enemigos** cortando. **i-frames** durante el dash (0.15 s). | dmg 26 · cd **7 s** · cast 0.7 s (windup 0.12 · active 0.18 · recovery 0.4) |
| **R** | **Corte en 8 Direcciones** | Definitiva | **Consume Adrenalina 100**. Lanza 8 cortes radiales desde el portador (beams que salen en cruz + diagonales). | dmg 48 · sin cd (la carga es la Adrenalina) · cast 0.8 s (windup 0.25 posture, character kneels/charges) |

**Reglas transversales (doc §2.4) — aplican a las tres:**
- **Castigo de canalización:** golpeado durante el windup → daño recibido ×1.25.
- **Root parcial:** durante Q/E/R el portador se mueve al **40%**.
- **Adrenalina (R):** +8 por golpe dado · +5 por daño recibido · +25 por orbe · reset entre rondas. (Medidor compartido por el portador.)
- Cooldowns **independientes por arma**: podés castear Q con Katana → swap → E con la otra.
- Katana es **común** (doc §8): VFX grisáceos con acento mínimo, **sin glow**. **DECIDIDO:** el cyan del set actual se mantiene pero **fusionado con gris** (energía gris/blanco con tinte cyan suave en el trazo, sin bloom).

### 1.1 Flujo de uso pensado (por qué estas 3 juntas)

- **Q** abre: stun 0.4 s es la ventana de "confirm".
- **E** convierte: entrar con i-frames castiga al que disparó Q del otro lado o reposiciona sin riesgo.
- **R** castiga posicionamiento: 8 direcciones = no hay esquina segura lejos del borde; premia estar centrado.
- **Cadena con swap (la salsa del doc):** Q (stun) → swap → habilidad del arma 2 en el stun. La Katana es el **setup** del kit.

---

## 2. Sistema técnico requerido (código)

### 2.1 Lo que ya existe (reuso directo)

| Pieza | Archivo | Qué aporta |
|---|---|---|
| Arma melee data-driven | `Scripts/Combat/WeaponDef.cs` + `MeleeWeapon.cs` | Daño/alcance/cadencia, swing con coroutine, trail, VFX de swing/hit, hitstop + shake |
| VFX de tajo genérico | `Scripts/Combat/SlashVfx.cs` | Sprite de arco que crece/desvanece — sirve para Q y E casi tal cual (`life`, `startScale`, `endScale`) |
| Auto-destroy VFX | `Scripts/Combat/VfxAutoDestroy.cs` | Limpieza de prefabs de partículas |
| Rig + animador por triggers | `Core/CharacterVisual.cs` + `Character.controller` | `Speed / Attack / Hit / Dead` ya funcionan para todos (jugador, bots, preview del menú) |
| Input centralizado | `Player/PlayerController.cs` | Lee Input System directo (KB mouse / KB twin / gamepad) con flags `_dashQueued`, `_swapQueued` |
| Reglas | `Core/DuelRules.cs` | Constantes (HP, dash, swap, hitstop) — acá van los números de habilidad o en AbilityDef |

### 2.2 A construir

1. **`AbilityDef.cs`** (nuevo, ScriptableObject, patrón del doc §9):
   - `abilityName`, `kind` (CircularSlash / DashSlash / RadialBurst)
   - `damage`, `cooldown`, `castDuration`, `windupFraction`
   - `radius` o `dashDistance`, `stunSeconds`, `iFrames`, `adrenalineCost`
   - `swingVfx`, `hitVfx`, `castVfx` (opcional), `color`
   - Menú: `CreateAssetMenu "WildWeapon/Ability Def"`. Assets en `_WildWeapon/Data/Abilities/`.
2. **`WeaponDef`**: agregar 3 referencias `AbilityDef q, e, r`.
3. **`AbilityRunner.cs`** (nuevo, por portador — o extender `WeaponLoadout`):
   - Lee la habilidad del arma **activa**; mantiene cooldowns **por arma/por habilidad** (`float[3]` en MeleeWeapon o runner con struct por slot).
   - Máquina de estados del cast: `Windup → Active → Recovery`, tolerante a hitstop (usar `Time.deltaTime`).
   - Durante windup: flag `IsCasting` → `PlayerHealth.TakeDamage` multiplica por 1.25; `PlayerController` limita movimiento al 40%.
   - **Active** ejecuta el efecto:
     - Q: overlap circular (radio) → daño + stun + VFX anillo.
     - E: dash con i-frames (reusar patrón `_dashTimer`/`IsInvulnerable`) + daño a enemigos atravesados (no re-hit del mismo target).
     - R: chequea y consume 100 de Adrenalina; spawnea 8 proyectiles radiales (mismo prefab rotado 0/45/90/135...); cada uno con su hitbox corto.
4. **`AdrenalineMeter`** (nuevo o dentro de `PlayerHealth`/`DuelManager`): +8 hit / +5 daño recibido / +25 orbe, cap 100, reset por ronda. El HUD lo muestra (fuera de alcance de este plan, pero el hook tiene que existir).
5. **`StunState`** simple: `PlayerController.CanAct=false` + `EnemyBot` (misma bandera) durante `stunSeconds`. Feedback: VFX "stars/ticks" chico sobre el stuneado (reuso `soft_circle`).
6. **`PlayerController`**: leer **Q/E/R** (KB: Q/E/R; gamepad: LT/?? propuesta abajo) con flags `_qQueued/_eQueued/_rQueued`; mover a 40% durante cast; bloquear dash durante cast.
7. **`EnemyBot`**: hooks para stun (los bots ya comparten `CharacterVisual` y estructura de melee vía defs; el stun simple los congelados con tint/particles basta para F1).
8. **`WildWeaponBuilder.cs`**: 
   - `BuildCharacterController()` → agregar parámetros `AbilityQ/AbilityE/AbilityR` (triggers) + estados `Cast_Q/Cast_E/Cast_R` (AnyState→estado con `Dead` off, exit a Idle por exitTime, igual que Attack).
   - `Weapon(...)` → asignar los 3 `AbilityDef` a la Katana; crear los assets de habilidad.
   - VFX: `BuildSlashVfx`/`BuildHitVfx` existentes + nuevos builders (`BuildStunRingVfx`, `BuildBurstVfx`).

### 2.3 Inputs propuestos (sin romper los esquemas actuales)

| Acción | KB Mouse | KB Twin | Gamepad |
|---|---|---|---|
| Q | Q | U | LT |
| E | E | I | LB |
| R | R | O | Y (buttonNorth) |

*(Hoy: dash = Shift/Space · swap = X/rueda · ataque = M1/comma/RT. **DECIDIDO 2026-10-17:** esta propuesta queda firme; verificar ergonomía en playtest.)*

---

## 3. VFX requeridos (arte nuevo)

**Convención:** PNG 1024×1024, transparente, cartoon con contorno negro grueso y energía "rayada/rasgada" (mismo lenguaje visual que `ww_slash.png`). Canvas PPU 512, import copiando el set. Nombres `ww_vfx_katana_*`.

| # | Asset | Uso | Descripción de generación (Aura, inglés) |
|---|---|---|---|
| 1 | **`ww_vfx_katana_stunring.png`** | Q — el slash circular 360° + telegraph del stun | "Cartoon game VFX: full circular slash ring, fast 360-degree sword slash around the character, thin bright cutting edge with a few separated arc segments, hand-drawn ragged energy, bold thick black outlines, gray-white blade energy with a soft cyan tint fused into the edge, isolated on transparent background, centered, 1024x1024" |
| 2 | **`ww_vfx_katana_crescent.png`** | E — la estela/ola del dash-tajo | "Cartoon game VFX: horizontal crescent slash arc, thin and fast, motion-stretched tip, ragged hand-drawn energy, bold thick black outlines, gray-white with a soft cyan tint fused into the edge, isolated on transparent background, centered, wide crescent filling most of the frame, 1024x1024" |
| 3 | **`ww_vfx_katana_burst.png`** | R — anillo de detonación al soltar los 8 cortes | "Cartoon game VFX: radial explosion ring with 8 thin sword-slash beams radiating outward in a star pattern, blade energy, bold thick black outlines, gray-white with a soft cyan tint fused into the blades, isolated on transparent background, centered, 1024x1024" |
| 4 | **`ww_vfx_katana_beam.png`** | R — el proyectil individual (se rota ×8 por código, **no** generar 8 variantes) | "Cartoon game VFX: single long sword-beam projectile, narrow sharp blade of energy pointing right, motion streak, ragged hand-drawn, bold thick black outlines, gray-white with a soft cyan tint, isolated on transparent background, 1024x512 (ancho)" |

**Paleta DECIDIDA (2026-10-17):** gris/blanco como base (arma común, doc §8) **fusionado con el cyan existente** de la Katana — el acento cyan va en el filo/borde del efecto, nunca como glow. Coherente con el trail y `VFX_Katana_Hit` actuales.

**Reusables (no requieren arte nuevo):**
- Trail del dash E: `TrailRenderer` + `VFX_Trail.mat` (ya existe por arma).
- Partículas de impacto de las 3: `VFX_Katana_Hit` (ya existe, cyan a decidir → gris).
- Postura/telegraph del R en el suelo: `soft_circle.png` (ya existe, generado por el builder).
- Stun sobre el enemigo: `soft_circle` + tint.

**Presupuesto Aura:** 4 imágenes (1 lote de 4, `background_transparency: transparent`). Sin videos para VFX (son sprites estáticos animados por código/prefab, como `SlashVfx`).

---

## 4. Animaciones del personaje (rig)

El rig es **esqueletal por keyframes de huesos** (Hips/Torso/Head/brazos/piernas) — no spritesheets. Eso abarata todo: las animaciones de habilidad son clips nuevos con el mismo sistema `Cv` del builder.

### 4.1 Clips nuevos (3)

| Clip | Duración | Keyframes de huesos (base del Char_Attack existente) |
|---|---|---|
| **`Char_AbilityQ.anim`** | 0.5 s (30 frames a 60) | **Windup 0.15 s:** torso gira en contra (-25°), arma baja. **Active:** giro completo del torso/armas (RotZ 0→360 repartido en 4 keys, brazos abiertos en cruz). **Recovery 0.25 s:** reincorpora a idle. Hips con pequeña subida. |
| **`Char_AbilityE.anim`** | 0.7 s | **Windup 0.12 s:** comprime (hips -0.05, piernas dobladas). **Active 0.18 s:** estirada máxima hacia el frente (hips +0.1 en X, torso inclinado adelante 30°, brazo frontal extendido 150°). **Recovery 0.4 s:** recupera postura. Espejo 1:1 con la ventana de i-frames. |
| **`Char_AbilityR.anim`** | 0.8 s | **Windup 0.25 s (posture):** rodilla al suelo (hips baja 0.35, pierna trasera rotada), arma envainada a un costado, torso abajo (lectura de "carga"). **Active:** explosión — sube de golpe (hips +0.15), torso 0→-360 en 0.2 s (giro múltiple), brazos en cruz. **Recovery 0.35 s:** aterriza a idle. |

### 4.2 Cambios en el animador (`Character.controller`)

- Parámetros nuevos: `AbilityQ`, `AbilityE`, `AbilityR` (Trigger).
- Estados `Cast_Q`, `Cast_E`, `Cast_R` con transiciones AnyState→estado (mismo patrón exacto que `Attack`: `hasExitTime=false`, condición `Dead=false` + trigger, exit a Idle por `exitTime≈0.95`).
- Duplicar el patrón para bots (comparten el controller — gratis).

### 4.3 Ejecución (pipeline del proyecto)

- **Opción recomendada (barata):** editar `BuildCharacterController()` con los nuevos `RigClip(...)` — mismo flujo que `Char_Attack` (ya validado; 30-50 líneas de keyframes por clip).
- **Opción Aura (si se quiere más expresividad):** video corto con el personaje actuando el gesto (las 3 animaciones en clips separados de 4 s), extraer frames → keyframes → mismo rig. Más costoso y con riesgo de deriva on-model; only si el keyframe manual no alcanza.
- **Flujo por trigger**: `AbilityRunner` llama `visual.PlayCast(kind)` → `SetTrigger` correspondiente. El recovery del clip (exitTime) define cuándo vuelve a Idle.

### 4.4 La deuda del doc §8 (spritesheets del portador)

El doc pide a futuro: sprite del portador **4 direcciones + flip · frame 256 px · 8 anims** (v0 simple → F1+ completo). El rig esqueletal actual **ya cubre** idle/run/attack/hit/death con rotación de huesos y es más barato de iterar. Recomiendo: **mantener el rig** y registrar explícitamente el cambio de dirección en el doc maestro (los spritesheets 4-dir quedan solo si se quiere un look "pixel/2D clásico" más adelante). No bloquea nada de este plan.

---

## 5. Fases sugeridas

### Fase A — Sistema + animaciones (sin arte nuevo) — ✅ COMPLETADA 2026-10-17
1. ✅ `AbilityDef.cs` + assets para Katana (Q/E/R) con números de §1 (`Data/Abilities/katana_q_circular`, `katana_e_dash`, `katana_r_ocho`).
2. ✅ `AbilityCaster.cs` + hooks en `WeaponLoadout`/`PlayerController`/`PlayerHealth` (castigo 1.25, root 40%, i-frames de E, stun).
3. ✅ Stun en `EnemyBot` + Adrenalina (0-100: +8 golpe dado / +5 recibido, reset por ronda).
4. ✅ 3 clips `Char_AbilityQ/E/R` + estados `Cast_Q/E/R` en el controller + triggers `AbilityQ/E/R`.
5. ✅ VFX placeholder: `VFX_Katana_Slash`/`Hit` cableados en los 3 `AbilityDef`.
- **Criterio de salida:** probar en Play: Q stunea, E dashea con i-frames, R sale con Adrenalina llena (las 3 con feedback placeholder).

### Fase B — VFX reales (Aura, 1 lote de 4)
6. Generar los 4 assets de §3 → import → prefabs (`BuildStunRingVfx`, `BuildBurstVfx`, reel de beams).
7. Cablear en los `AbilityDef` + prueba en Arena con bots.

### Fase C — Pulido
8. SFX (reusar set de 4 variantes por arma de `_art-source/`).
9. HUD: cooldowns por arma + barra de Adrenalina.
10. Playtest de tuning: verificar que la Katana sea "starter justa" (doc §3: sin ventaja de stats).

---

## 6. Decisiones tomadas (2026-10-17)

1. **Paleta VFX:** ✅ Cyan **fusionado con gris** — base gris/blanca (arma común, doc §8), acento cyan en el filo/borde, sin glow.
2. **Inputs Q/E/R:** ✅ Aprobados tal como están en §2.3 (KB: Q/E/R · Twin: U/I/O · Gamepad: LT/LB/Y).
3. **Números:** ✅ Validados **con un ajuste: Dash-Tajo cd 7 s** (Q 6 s · R vía Adrenalina). Resto igual: 20/26/48.
4. **Alcance R:** ✅ A criterio de implementación (se prioriza proyectiles radiales por simplicidad de reuso; si el feel no convence, se ajusta en playtest).
5. **Animaciones:** ✅ **Keyframes** como camino principal (gratis, sin riesgo on-model). **Plan B:** si el rig por keyframes genera demasiados errores o no alcanza el nivel expresivo, se pasa a **videos de Aura** (3 clips, con el pipeline SPRITE-PROMPTS de video + extracción de frames).

---

## 7. Presupuesto de generación (Aura)

| Item | Cantidad | Método |
|---|---|---|
| VFX sprites | **4** | `generate_images` (1 lote transparente) |
| Animaciones | 0 (keyframes) | Rig por código — o 3 videos si se aprueba §4.3 opción Aura |
| Iteraciones | ~1–2 por asset | `edit_images` si el encuadre sale desviado |

**Total estimado: 4–8 créditos de imagen** (sin videos). Avisar antes de disparar el lote.

---

*Referencias: `WILDWEAPON-MAYHEM-DISENO.md` §2.4, §3, §8, §11 · `WildWeaponBuilder.cs` (BuildCharacterController, Weapon, VFX builders) · `MeleeWeapon.cs`, `SlashVfx.cs`, `PlayerController.cs` · `SPRITE-PROMPTS.md` (convenciones).*
