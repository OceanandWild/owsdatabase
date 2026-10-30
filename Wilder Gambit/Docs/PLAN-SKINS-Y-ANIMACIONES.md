# PLAN 1 — Adición de Skins y Animaciones a la tienda

> **Objetivo:** pasar de "skins con tinte" y `03 ANIMACIONES — Próximamente` a un catálogo
> completo y comprable: skins de piezas (visual + idle) y animaciones de evento (fork,
> jaque, mate…), con preview en la tienda, compra real y persistencia.
> **Alcance:** funcional (sí toca lógica). El diseño *solo visual* de la tienda vive en
> `PLAN-REWORK-TIENDA.md`; los contenidos concretos, en `CONCEPTO-NUEVAS-PIEZAS.md` y
> `CONCEPTO-ANIMACIONES.md`.

## Estado actual (auditoría)
- `Core/PieceSkinConfig.cs`: enum `SkinAnimation` (None, Breathing, Fire, Ice, Spectral,
  Embers, Necrotic, Solar, Abyssal), `SkinRarity`, `PieceSkinLibrary`.
- `Core/PieceSkinManager.cs`: 8 skins en fallback hardcodeado, propiedad y selección en
  `PlayerPrefs` (`Skin_Owned_*`, `Skin_Selected_*`), moneda Gambits, `OceanPayService`
  si existe.
- `UI/YourPiecesModal.cs`: grid de compra/equipar, miniaturas (`GetSkinThumbnail`),
  precios, rarezas.
- `View/BoardView.cs` (~1256): aplica tinte + aura por `SkinAnimation` — **solo color**,
  sin FX reales por skin.
- Tienda: rail `01 TABLEROS / 02 VARIANTES / 03 ANIMACIONES` (los dos últimos
  "Próximamente"), stage con hero preview, `ShopModal.cs` + `ShopBackgroundSelector`
  (10 tableros), bóveda Tides/Gambits.
- FX de evento ya dispersos: `CaptureParticles`, `KnightForkAnimator`, `kingCheckFrames`.

## Arquitectura objetivo

```
Assets/_Project/Scripts/
  Core/
    AnimationTrigger.cs        // enum de gatillos
    FXEventBus.cs              // static event: Raise(trigger, Vector2Int, payload)
    FxPlayer.cs                // resuelve gatillo -> clip equipado (o default) y lo reproduce
    AnimationCatalog.cs        // SO: trigger -> clip (sprites/partículas/sfx/duración)
    PieceSkinCatalog.cs        // SO migrado desde PieceSkinManager.FallbackSkins
  View/Fx/
    FxClipRunner.cs            // overlay de frames + partículas + sfx (un solo runner)
    clips/…                    // implementaciones por gatillo (ForkFx, CheckFx, …)
```

Reglas:
1. **Ids estables** (`anim_fork_cometa`, `skin_knight_forja`) — la persistencia no cambia
   de clave al rehacer catálogos.
2. **Un gatillo = 1 ranura equipable**; si no hay nada equipado → clip gratuito por
   defecto (nunca FX vacío).
3. **Los hooks son opt-out**: si `FxPlayer` no está en escena, no hace nada (no rompe
   partidas existentes ni tests).

---

## Fases

### Fase 0 — Congelar datos y contratos (0,5 día)
- Extraer `FallbackSkins` a `PieceSkinCatalog` (ScriptableObject) con migración automática:
  si no hay SO, se genera en memoria (comportamiento idéntico al de hoy).
- Definir `AnimationTrigger` y `FxClipDefinition` (trigger, displayName, rarity, price,
  durationSec, sprites[], sfx, reducedMotionVariant).
- **Aceptación:** el juego se ve idéntico con el SO presente o ausente.

### Fase 1 — Bus de eventos + hooks (1,5 días)
- `FXEventBus` con `Raise(AnimationTrigger, Vector2Int, FxPayload)`.
- Hooks mínimos (cada uno con `#if`/null-check):
  - `GameManager`: fork (`IsMoveAFork`, ~415–544), mate/stalemate (~632 y fin de
    partida), enroque, promoción.
  - `BoardView`: jaque (junto a `kingCheckFrames`), movimiento (payload from→to).
  - `CaptureParticles`: dispara `Capture` y delega en `FxPlayer` (mantiene el fallback
    actual de polvo/chispa si no hay clip equipado).
  - `MoveEvaluator` → callback hacia `GameManager` cuando clasifica "Brillante".
- **Aceptación:** log de cada gatillo en una partida real (1 jornada de QA manual).

### Fase 2 — Motor de reproducción (1,5 días)
- `FxClipRunner`: overlay en el espacio de la casilla (sigue el patrón de
  `KnightForkAnimator`: escala `tileSize`), partículas del clip, sfx, auto-destrucción.
- Capas de orden: clip < HUD de texto ("JAQUE", "!!") < cortinilla de mate.
- Presupuesto: ≤32 partículas, ≤1 overlay, sin `Resources.Load` en caliente.
- Opción global **Reducir movimiento** (Ajustes ya existente) → variantes sutiles.
- **Aceptación:** 60 fps estables en la build objetivo con todas las animaciones puestas.

### Fase 3 — Skins como producto (1 día)
- Miniaturas reales: generar `thumbnail` por skin (render de la pieza con su tinte/aura)
  y cachearlas al abrir `YourPiecesModal`.
- Preview en stage de la tienda: pieza animada en loop con su `SkinAnimation`.
- **Aceptación:** comprar → "¿Equipar ahora?" → la skin se ve en partida sin reiniciar.

### Fase 4 — Tienda: pestañas vivas (1,5 días)
- `02 VARIANTES` y `03 ANIMACIONES` dejan de ser "Próximamente": pobladas desde los
  catálogos con estados (disponible / propiedad / no conectado).
- Ficha de detalle en stage: nombre, rareza, precio, preview, botón COMPRAR/EQUIPAR.
- Fallback sin sesión: compra local con Gambits (`PlayerPrefs`), igual que hoy.
- **Aceptación:** recorrer el flujo completo de compra de 1 skin + 1 animación en ambas
  ramas (con y sin sesión Surface).

### Fase 5 — Economía y contenido (1 día)
- Tabla de precios alineada con los dos documentos de concepto (común 250–400, rara
  500–750, épica 1100–1500, legendaria 1600–2000 Gambits).
- Backlog de lanzamiento: 6 animaciones (`CONCEPTO-ANIMACIONES.md`) + 4 variantes
  (`CONCEPTO-NUEVAS-PIEZAS.md`) + skins existentes migradas.
- Comprobación de "no-pay-to-win": toda animación es cosmética pura.

### Fase 6 — Persistencia y sincronía (0,5 día)
- Ownership/selección de animaciones con las mismas claves `Anim_Owned_*` / `Anim_Equipped_<Trigger>`.
- `OceanPayService.Sync` incluye animaciones (mismo camino que skins hoy).
- **Aceptación:** borrar/regenerar PlayerPrefs no pierde nada comprado con sesión.

### Fase 7 — QA y lanzamiento (1 día)
- Checklist: equipar en menú → jugar partida → pausa → volver; cambiar skin en pausa;
  mate con animación equipada; captura doble rápida (que no se solapen clips: cola máx. 1
  overlay + 1 HUD); gamepad/teclado sin perder foco; logros de rendimiento.
- Telemetría ligera: gatillo disparado, clip reproducido, fallo de recursos.

## Riesgos
| Riesgo | Mitigación |
|---|---|
| Hooks en `GameManager` rompen partidas | opt-in por presencia de `FxPlayer`; tests de motor intactos |
| Solape de FX en capturas rápidas | cola con prioridad (mate > brilliant > capture > move) |
| Coste de arte | lanzar con 6 clips; reutilizar frames existentes (`KnightFork`, `kingCheck`) |
| USS/UI Toolkit limitado | FX en espacio mundo (SpriteRenderer) para el tablero, no en UI Toolkit |

## Estimación total
**~8,5 días** (0.5 + 1.5 + 1.5 + 1 + 1.5 + 0.5 + 1 + 1 QA) para el MVP de Skins +
Animaciones comprables.

## Orden de ejecución
Fase 0 → 1 → 2 → 4 (con 2 clips piloto: *Cometa Ígnea* y *Corona de Cenizas*) → 3 → 5 →
6 → 7. El Plan 2 (rework visual de la tienda) puede correr **en paralelo** desde la Fase 4.
