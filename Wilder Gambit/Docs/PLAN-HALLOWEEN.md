# PLAN — La Velada de Halloween (evento 2026)

> **Objetivo:** un evento corto y paralelo a la temporada T1 (que sigue viva): una velada
> del **20/10 (21:00) al 2/11** con su propio mini-pase de 30 niveles, misiones diarias, una moneda
> temporal (**Dulces**) y contenido esculpido. Nada del evento toca las claves, los
> contadores ni los cobros de la temporada.
> **Alcance:** funcional + UI (tarjeta del menú, modal del pase) + ajustes de la T1.

## Piezas del sistema

| Archivo | Qué hace |
|---|---|
| `Core/HalloweenEvent.cs` | Calendario de la velada: fase (`NotStarted` / `Active` / `Ended`), cuenta atrás y override de fechas para QA. |
| `Core/HalloweenProgress.cs` | XP del evento: 30 niveles × 60 XP (1.800). Monotónico, por año, y **solo suma dentro de la ventana**; la primera lectura antes del arranque purga el XP viejo. |
| `Core/HalloweenCurrency.cs` | **Dulces** (`🍬`): moneda temporal por año. `Earn` / `Spend`; hoy solo entra (misiones y pases) y solo sale al abrir la Vía Sangre. |
| `Core/HalloweenLanes.cs` | Estado de las vías: la Vía Luna siempre está abierta; la **Vía Sangre** se compra con Dulces y queda abierta toda la edición. Lo comparten el camino de niveles y las misiones premium. |
| `Core/HalloweenMissions.cs` | Motor de misiones: 3 diarias de la Vía Luna (pool de 25) + 10 exclusivas de Sangre por edición (5 libres y 5 premium, de dos pools de 10). Progreso por eventos de juego y cobro a mano con auto-cobro al cerrar el día. |
| `UI/HalloweenPassModal.cs` | Modal de la velada: chips de progreso, resumen de misiones (fichas que abren el tablero), camino de 30 niveles con dos vías (carril horizontal en escritorio, lista vertical en móvil), apertura de la Vía Sangre y overlay de cobro. |
| `UI/HalloweenMissionsModal.cs` | **Tablero de misiones** (modal que se abre por encima del pase): pestaña Vía Luna con las 3 del día y pestaña Vía Sangre con las 10 exclusivas, barra de progreso, cobro y compra de la vía. |
| `Editor/HalloweenDebugMenu.cs` | QA: forzar fase, +XP, +Dulces, completar misiones (diarias y de Sangre), abrir/cerrar Sangre y reset (menú **Wilder Gambit › Halloween**). |

## 1. Ventana y estados

| Fase | Cuándo | Tarjeta del menú | Modal |
|---|---|---|---|
| PRÓXIMAMENTE | antes del 20/10 (21:00) | «PRÓXIMAMENTE» | cuenta atrás; el tablero de misiones enseña lo que viene, sin cobros |
| ACTIVA | 20/10 21:00 → 2/11 23:59 | «¡ACTIVO!» | XP, misiones y cobros en vivo |
| TERMINADA | desde el 3/11 00:00 | «TERMINADO» | resumen de lo cobrado; sin cobros nuevos |

- Claves con sufijo de año (`2026`): cada edición arranca su propio saldo.
- El override de QA (`WG_Halloween_DebugPhase`) se guarda en PlayerPrefs y pisa las fechas reales.

## 2. XP del evento (HalloweenProgress)

| Acción | XP |
|---|---|
| Terminar una partida | +10 |
| Ganarla (además) | +15 |
| Resolver un puzzle | +8 |
| Captura tuya | +1 |
| Desafío diario | +30 |
| Cobrar una misión de la velada | +20 (Luna) · +30 (Sangre libre) · +45 (Sangre premium) |

30 niveles × 60 XP = **1.800 XP**. Fuera de la ventana no entra nada (`AddXp` es no-op);
los cobros automáticos y la QA usan `AddXpForced`.

## 3. Dulces (moneda temporal)

| Fuente | Cantidad |
|---|---|
| Misión diaria de la velada (3/día × 14 días) | 2 cada una (84 máx.) |
| Exclusiva de Sangre **libre** (5 por edición) | 4 cada una (20) |
| Exclusiva de Sangre **premium** (5 por edición) | 6 cada una (30) |
| Vía Luna (30 niveles) | 126 |
| Vía Sangre (30 niveles) | 182 |
| Pase de temporada · vía libre | 29 |
| Pase de temporada · vía real | 37 |
| **Gasto:** abrir la Vía Sangre | 150 |
| **Gasto:** tienda de la velada | niveles del pase, esculturas (55–165) y variantes |

La **tienda de la velada** (`HalloweenShop`) gasta lo que sobre: vende niveles del
mini-pase, las esculturas de la edición y las variantes, todo con Dulces y sin equipar
nada (equipar es cosa del inventario). Sus precios y su catálogo viven en un solo
archivo. La Vía Sangre reparte 182 Dulces en total: 130 en los niveles 1-20 y 52 en los
21-30, pensados para financiar las dos piezas de la Corte que se compran en la tienda.

## 4. Misiones de la velada

El tablero vive en un **modal propio** (`halloween-missions-modal-view`), que se abre
por encima del pase con el botón **MISIONES** del topbar o tocando cualquiera de las
tres fichas de resumen del cuerpo (Luna / Sangre libre / Sangre premium). Se puede
abrir en cualquier fase: antes del 20/10 enseña qué viene, pero los cobros esperan a
que la velada esté activa.

### 4.1 Vía Luna — 3 misiones diarias, pool de 25

- 3 por día, elegidas de forma determinista por fecha (una fácil garantizada) de un
  pool de 25 que mezcla partidas, victorias, dificultad (Caballero / Maestro),
  precisión (80 % y 95 %), partidas sin errores, victorias sin perder piezas o dama,
  mates rápidos, partidas largas, capturas, capturas de dama, puzzles, desafío diario
  y rachas de 3 y 5 victorias.
- Cada una paga **+20 XP de la velada y +2 Dulces**, con cobro manual.
- Al cambiar de día, lo completado y sin cobrar se paga solo (lo ganado no se pierde).

### 4.2 Vía Sangre — 10 exclusivas por edición: 5 libres + 5 premium

- **5 libres**: exigentes pero jugables sin comprar nada (3 victorias, 2 en
  Caballero+, 25 capturas, 2 damas, 4 puzzles, 2 partidas al 80 %, 2 sin perder
  piezas, 2 sin perder la dama, 2 partidas largas, desafío diario). Pagan
  **+30 XP y +4 Dulces**.
- **5 premium**: el techo de la velada (2 victorias en Maestro+, racha de 5, 2 mates
  rápidos, 2 partidas al 95 %, 2 sin errores graves, 5 victorias en Caballero+,
  6 victorias, 3 damas, 40 capturas, 3 partidas largas). Pagan **+45 XP y +6 Dulces**
  y piden la **Vía Sangre abierta** (🍬 150): hasta entonces se ven con el candado.
- La selección de cada edición sale de dos pools de 10 (uno de cada bolsa): la mano
  cambia cada año y se guarda en el estado, así que las 10 son estables durante la
  velada.
- El progreso de las de Sangre usa **contadores del evento** (no se reinician cada
  día) y el cobro es único por misión.

### 4.3 Progreso y contadores

Las mismas señales de juego alimentan las dos familias (`GambitProgress`):
terminar y ganar partidas, dificultad, precisión, errores, piezas perdidas, dama
perdida, velocidad, capturas (con el tipo de pieza), puzzles y desafío diario.
Las diarias llevan su copia del contador (se reinicia con el día) y las de Sangre
la del evento completo.

Fuera de la ventana no entra progreso nuevo: `NoteMatch` y compañía son no-op y los
cobros solo responden con la velada activa.

## 5. Mini-pase (30 niveles, dos vías)

- **Vía Luna (gratis):** Dulces, Gambits, cambios de misión, el **Peón de Brasa**
  (`skin_pawn_halloween`), el **Rey Esqueleto** (`skin_king_halloween`, nivel 17), la
  variante **Peón Calabaza** (`pumpkin_pawn`, nivel 13) y el fondo **Noche de Brujas**
  (`halloween_night`).
- **Vía Sangre (se abre con 150 Dulces):** Dulces en mayor medida, Gambits altos,
  **Torre de Musgo** (`skin_rook_halloween`), **Reina Agrietada** (`skin_queen_halloween`),
  la variante **Caballo Fantasma** (`ghost_knight`, nivel 13), la variante **Reina Vampira**
  (`vampira`, nivel 19), los tableros **Luna Llena** (`halloween_moon`) y **Luna de Sangre**
  (`halloween_blood`).
- **Tramos 21-30 (Parte 2):** la velada crece de 20 a 30 niveles con cinco skins de
  arte propio y lado negro, dos tableros y dos fondos. La Vía Luna reparte Alfil Farol,
  Caballo Espantapájaros, el Cementerio Olvidado y la Noche de la Cosecha;
  la Vía Sangre, el Rey Carmesí, la Cripta de los Cuervos y el Salón del Banquete, y sus
  tramos 21 y 23 pasan a pagar Dulces. Torre Relicario y Reina Maleficio se venden en la
  tienda de la velada (125 y 165 Dulces). La vía Sangre queda en 182 Dulces (130 + 52).
  El **Peón Golosina** queda fuera de circulación: su arte se reserva para la próxima
  invasión de los Gummy Bears y no aparece en tiendas, inventario ni recompensas.
  Detalle y estado del arte en `Docs/PLAN-PASE-VELADA-21-30.md`. Las tarjetas y el cobro
  ya admiten skin, tablero y fondo, así que sustituir una entrada no toca la UI.
- Cobro instantáneo con verificación (si el premio no queda en posesión del jugador, el
  nivel no se consume). Los Gambits usan la fuente nueva `GambitSource.HalloweenPass`
  (sin tope, `bypassCaps`).
- **Layout con dos formas** (igual que el pase de temporada): en escritorio es un carril
  horizontal (columna = carta Luna arriba, medallón sobre la línea al medio, carta Sangre
  abajo, con flechas ← → y scroll lateral) que se escala para caber sin scroll vertical
  (`FitTrack`); en móvil vertical (`.is-portrait`) es una lista vertical con scroll
  (medallón + carta Luna + carta Sangre por fila). El UXML trae las dos y el USS muestra
  la que toca.
- **Sprites compartidos con la temporada** (2026-10-16): los medallones de nivel usan
  `seasonpass_tier.png` (número en el vidrio, offset ≈57% que `FitTrack` escala) y las
  cartas del carril visten `reward_slot_basic` (Luna) y `reward_slot_premium` (Sangre, con
  corona). La carta conserva la proporción 300×276 del marco y su relleno interior sale de
  la ventana del PNG (16/25/24 básico; 56/26/35 premium), escalado con `k`.
- Después del 2/11 no se cobra más: los niveles alcanzados quedan para la próxima edición
  (decisión pendiente si el contenido esculpido rota a la tienda con Gambits).

## 6. Temporada T1: de 75 a 30 niveles

- `SeasonPassModal.TierCount` 75 → **30** (mismo `XpPerTier` = 60: 1.800 XP totales).
- Las dos tablas de recompensas se reescriben a 30 entradas e incluyen **Dulces**
  (vía libre ≈ 29, vía real ≈ 37). La **Torre Fragua** sigue como capstone de la vía real
  (nivel 30): es la única recompensa exclusiva del pase.
- El resto del catálogo movido fuera de la tabla (skins, tableros y fondos extra) sigue
  disponible en las tiendas con Tides/Gambits.

## 7. Contenido nuevo (arte)

Integrado el 2026-10-16 (esculpidos procesados con `Tools/build_halloween_sprites.py`; tableros y variante ya en su medida final; los tableros sumaron su objeto 8×8 v2 en partida el 17/10):

| Objeto | Id | Archivo |
|---|---|---|
| Peón de Brasa | `skin_pawn_halloween` | `Assets/Resources/Skins/skin_pawn_halloween.png` |
| Torre de Musgo | `skin_rook_halloween` | `Assets/Resources/Skins/skin_rook_halloween.png` |
| Reina Agrietada | `skin_queen_halloween` | `Assets/Resources/Skins/skin_queen_halloween.png` |
| Rey Esqueleto | `skin_king_halloween` | `Assets/Resources/Skins/skin_king_halloween.png` |
| Reina Vampira (variante) | `vampira` | `Assets/StreamingAssets/Pieces/White/VampireQueen.png` (+ copia en `Resources/Pieces/White/`) |
| Peón Calabaza (variante) | `pumpkin_pawn` | `Assets/Resources/Pieces/Halloween/hwp_pawn_pumpkin.png` |
| Caballo Fantasma (variante) | `ghost_knight` | `Assets/Resources/Pieces/Halloween/hwp_knight_ghost.png` |
| Tablero Luna Llena | `halloween_moon` | `Assets/StreamingAssets/Board/bg_halloween_moon.jpeg` (ambiente) + `bg_halloween_moon_board.png` (objeto 8×8 en partida) — originales en `_art-source/Halloween/` |
| Tablero Luna de Sangre | `halloween_blood` | `Assets/StreamingAssets/Board/bg_halloween_blood.jpeg` (ambiente) + `bg_halloween_blood_board.png` (objeto 8×8 en partida) — originales en `_art-source/Halloween/` |
| Fondo Noche de Brujas | `halloween_night` | `Assets/StreamingAssets/Backdrop/backdrop_halloween_night.jpg` (original en `_art-source/Halloween/`) |

Pendiente:

| Objeto | Id | Archivo esperado |
|---|---|---|
| Reina Vampira · versión negra | — | `Pieces/Black/VampireQueen.png` (la tarjeta del pase usa la blanca) |

Con el fondo integrado, todas las tarjetas del pase muestran arte propio
(el cobro desbloquea igual los objetos: los ids ya están en los catálogos).

Los dos tableros de la velada son **exclusivos del Pase de Halloween**: la
tienda no los vende (no aparecen en su grilla) y el inventario los agrupa en
la sección «PASE DE HALLOWEEN» hasta reclamar su recompensa. Los **fondos**
del pase sí se suman a la pestaña FONDOS en cuanto se cobran: esa pantalla es
la que los equipa y repinta el menú al momento.

## 8. QA (Editor)

Menú **Wilder Gambit › Halloween**:

- **Fase:** fechas reales / forzar PRÓXIMAMENTE / ACTIVO / TERMINADO.
- **+240 XP** (4 niveles), **+40 Dulces**, **completar las misiones diarias**,
  **completar las exclusivas de Sangre**, **abrir la Vía Sangre gratis**,
  **cerrarla de nuevo** (para probar el candado de las premium), **ver estado en
  consola** y **reset total de la velada** (no toca la temporada).

## 9. Pendientes

1. **Destino post-evento** de los esculpidos: exclusivos hasta Halloween 2027 o rotan a la
   tienda con Gambits (como las piezas de `YourPiecesModal`).
2. **Arte:** todo integrado (skins, tableros —ambiente + objeto 8×8 en partida—, fondos,
   variantes y las cinco esculturas de la Parte 2 con su `_black`); el par del Peón
   Golosina queda archivado para los Gummy Bears. Solo queda la versión
   negra de la **Reina Vampira** para cuando aterrice su equipamiento.
3. **Puente a los Gummy Bears:** la Torre Golosa (`hwp_rook_candy` + su `_black`) y el
   banner de la invasión ya están producidos y reservados; ver `Docs/PLAN-GUMMY-BEARS.md`.
   La torre es la causante del caos en el lore y todavía no tiene entrega definida.
