# CONCEPTO — Animaciones de juego (gatillables) para la tienda

> Documento de **concepto**. Cada animación se dispara por un **evento de partida**
> (fork, jaque, mate, captura…) y se vende/eqipa por **ranura de gatillo**, como una skin.
> Catálogo pensado para la pestaña `03 ANIMACIONES` de la tienda.

## Punto de partida (gancho en el código)

| Gatillo real | Dónde está hoy |
|---|---|
| Fork del caballo | `GameManager.IsMoveAFork` (~544), `UpdateKnightForkState` (~415), `BoardView.TriggerKnightForkTransformation`, `KnightForkAnimator` (frames Idle + Attack) |
| Jaque | `BoardView.kingCheckFrames` (frames de rey en jaque, ~808) |
| Jaque mate / tablas | `GameManager` (~632 stalemate), claves `checkmate_white/black` en `LocalizationManager` |
| Captura | `CaptureParticles` (prefabs de polvo/chispa + flash rojo para piezas pesadas) |
| Jugada brillante / gran jugada | `Engine/MoveEvaluator.cs` (~82: clasifica "Brillante", "Gran Jugada"…) |
| Efectos idle de skin | enum `SkinAnimation` (Fire, Ice, Spectral, Embers, Necrotic, Solar, Abyssal…) aplicados en `BoardView` (~1256) |

**Idea de sistema:** un bus de eventos único → cada gatillo tiene 1 ranura equipable →
la animación equipada (o la gratuita por defecto) se reproduce.

```
AnimationTrigger { Fork, Check, Checkmate, Stalemate, Capture, Promotion,
                   Castling, Brilliant, WinStreak, SkinIdle, ... }
FXEventBus.Raise(trigger, pos)  →  FxPlayer.Play(trigger, pos)  →  clip + sfx + partículas
```

---

## CATÁLOGO DE ANIMACIONES (12 conceptos)

### 1. «Cometa Ígnea» — gatillo: **FORK** *(rework de lo existente)*
- El caballo salta dejando una **estela de fuego**; al aterrizar, **onda de choque**
  circular + brasas que caen sobre las dos piezas horquilladas; el aura idle se intensifica.
- Reemplaza/evoluciona el `KnightForkAnimator` actual (que ya tiene frames de ataque).
- 1,2 s · ÉPICA · 99 Tides (`anim_fork_cometa`, frames en `Resources/ForkComet/`).

### 2. «Sello de Sangre» — gatillo: **JAQUE**
- Anillo rojo pulsante bajo el Rey + filigrana tipográfica **"JAQUE"** que entra con
  stagger (reutiliza el sistema `PlayStagger` del menú) + pulso de la corona decorativa.
- 0,9 s · COMÚN (gratuita por defecto) / variantes de color a la venta.
- Hoy existe el frame `kingCheckFrames`; esto lo eleva a FX completo.

### 3. «Corona de Cenizas» — gatillo: **JAQUE MATE (victoria)**
- Cámara lenta (`timeScale` breve), el Rey **se agrieta y se desmorona en brasas** que
  ascienden (misma paleta del rework de brasas del menú), cortinilla dorada con el
  resultado y el sello del rival caído.
- 3,0 s · LEGendaria · 2000 Gambits.
- Variante vendeable: **«Trono Roto»** (misma animación en clave oscura, para cuando
  *pierdes* por mate — gatillo `CheckmateDefeat`).

### 4. «Cosecha de Almas» — gatillo: **CAPTURA**
- El alma de la pieza capturada sube como brasa hacia el marcador de material.
- La "potencia" escala con el valor de la pieza (peón: chispa; dama: espiral completa).
- Evoluciona `CaptureParticles`. · RARA · 650 Gambits.

### 5. «Ascensión» — gatillo: **PROMOCIÓN**
- Pilar de luz sobre la casilla, runa giratoria, la pieza nueva **desciende** del cielo
  con destello y la etiqueta "PROMOCIÓN" en filigrana.
- 1,6 s · ÉPICA · 1100 Gambits.

### 6. «Muralla Viva» — gatillo: **ENROQUE**
- Rey y torre dejan **estela** durante el salto, polvo al aterrizar, mini onda al cerrar
  la formación. Suena a "fortaleza cerrándose".
- 1,0 s · COMÚN · 350 Gambits.

### 7. «Destello Táctico (!!)» — gatillo: **JUGADA BRILLANTE**
- Flash dorado radial + sello **!!** con rebote + arco de lente tenue. Usa la
  clasificación de `MoveEvaluator` (que ya detecta "Brillante"/"Gran Jugada").
- Es la animación de **recompensa emocional** del juego: sin pay-to-win, pura dopamina.
- 1,1 s · ÉPICA · 1300 Gambits.

### 8. «Lanza de Hielo» — gatillo: **CLAVADA (PIN)**
- Cada vez que una pieza queda clavada, un filo de hielo atraviesa la casilla y la pieza
  brilla en azul; se rompe cuando se levanta la clavada.
- 1,4 s · RARA · 750 Gambits (variante «Cadena Ígnea» a 750 también).

### 9. «Racha de Fuego» — gatillo: **N VICTORIAS SEGUIDAS**
- Al entrar a la partida con racha ≥3 (`DynamicDifficultyManager.WinStreak`), el borde
  del tablero se enciende en brasas y el badge de racha entra con stagger.
- 2,0 s (una vez por partida) · LEGendaria · 1600 Gambits.

### 10. «Aliento del Tablero» — gatillo: **SKIN IDLE** *(ya existe, se empaqueta)*
- Los `SkinAnimation` actuales (Fire, Ice, Spectral, Embers, Necrotic, Solar, Abyssal)
  dejan de ser exclusivos de skins y pasan a **módulos reutilizables**: se pueden combinar
  con cualquier pieza (nuevo producto: "Efectos").
- COMÚN–ÉPICA · 300–900 Gambits.

### 11. «Eco de la Jugada» — gatillo: **MOVIMIENTO** (opcional, barato)
- Traza sutil del camino recorrido (línea dorada que se desvanece) + aterrizaje suave.
- COMÚN · 250 Gambits. Bueno como primer producto de precio bajo.

### 12. «Ahogado» — gatillo: **STALEMATE**
- El tablero se llena de neblina gris y las piezas quedan suspendidas (sin brasas, sin
  vida). Cierra la narrativa de cenizas del juego.
- RARA · 600 Gambits.

---

## REGLAS DE DISEÑO
1. **Nunca ocultan información**: toda animación es ≤3 s y no bloquea el input salvo el
   mate (que ya es fin de partida). Botón de "skip" + opción *Reducir movimiento*.
2. **Un gatillo = una ranura equipable** (máx. 1 animación activa por gatillo), igual que
   las skins: persistencia en PlayerPrefs + catálogo con ids estables.
3. **Presupuesto de rendimiento:** ≤ 32 partículas simultáneas + 1 sprite-frame overlay;
   nada de `Resources.Load` en caliente durante la partida (cargar al entrar).
4. **Coherencia de paleta**: oro `#c9a84a`, brasa naranja → rojo, azul noche `#0c152b`
   (la misma del menú y de la tienda Atelier Noir).
5. **Accesibilidad**: alternativa "sutil" para todas las animaciones ≥ RARA.

## BACKLOG SUGERIDO (catálogo inicial de lanzamiento)
| Orden | Animación | Gatillo | Precio |
|---|---|---|---|
| 1 | Sello de Sangre (color) | Check | 350 |
| 2 | Cometa Ígneo | Fork | 700 |
| 3 | Cosecha de Almas | Capture | 650 |
| 4 | Destello Táctico | Brilliant | 1300 |
| 5 | Ascensión | Promotion | 1100 |
| 6 | Corona de Cenizas | Checkmate | 2000 |

El **plan de implementación** (fases, archivos, QA) está en `PLAN-SKINS-Y-ANIMACIONES.md`.
