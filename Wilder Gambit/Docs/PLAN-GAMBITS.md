# PLAN — Economía de Gambits (ganar jugando)

> **Objetivo:** que los Gambits se ganen jugando y que el juego lo anuncie **antes** y lo
> detalle **después**, con más paga cuanto más difícil es el rival y con una barra semanal
> que empuja a volver cada día. Nada de comprar Gambits: las variantes se consiguen con
> tiempo, nunca con dinero.
> **Alcance:** funcional + UI (menú, fin de partida, vista de Progreso).

## Piezas del sistema

| Archivo | Qué hace |
|---|---|
| `Core/GambitSources.cs` | Catálogo de fuentes: id, icono, texto, tope diario de importe y de número de pagos. |
| `Core/GambitEconomyConfig.cs` | ScriptableObject con todos los números de partida, bonus y topes (menú **Wilder Gambit > Crear config de economía de Gambits**). Si el asset no existe, usa los valores por defecto del código. |
| `Core/GambitLedger.cs` | Libro diario en `PlayerPrefs` (`WG_GambitLedger`): total del día por fuente, número de pagos, primera victoria del día y victorias seguidas contra el mismo rival. Se reinicia solo al cambiar de fecha. |
| `Core/GambitEconomy.cs` | **Único** punto por el que entra un Gambit: aplica topes, abona el saldo local al instante y sincroniza con Surface (`EarnGambitsAsync`). Dispara `OnEarned` (toast) y `OnProgressChanged` (UI). |
| `Core/MatchRewards.cs` | Tabla de partida vs IA + `Compute` (sin cobrar) y `Settle` (calcula y cobra). |
| `Core/DailyMissions.cs` | 3 misiones diarias deterministas por fecha, con progreso persistido, 1 cambio de misión al día y cobro a mano. |
| `Core/WeeklyProgress.cs` | **Barra del Atelier**: 7 segmentos (lunes→domingo), recompensa por día perfecto, cofre por semana completa y racha de semanas perfectas. |
| `Core/Achievements.cs` | 16 logros de una sola vez, autopagados al cumplirse. |
| `Core/GambitProgress.cs` | Puente eventos→progreso (`GameEvents`) + contadores para la UI + panel de depuración. |
| `Core/GameEvents.cs` | Bus estático: capturas, fin de partida, puzzles y desafío diario. |
| `UI/ProgressModal.cs` | Vista PROGRESO: barra de 7, cofre, misiones, retos, logros y fuentes. |
| `UI/GambitToast.cs` | Aviso flotante «+60 Gambits · Partidas vs IA» en cada cobro. |

## 1. Partida vs IA (base)

| Modo | Victoria | Tablas | Derrota |
|---|---|---|---|
| Principiante | 20 | 8 | 4 |
| Aprendiz | 35 | 14 | 6 |
| Caballero | 60 | 24 | 10 |
| Maestro | 100 | 40 | 15 |
| Gran Maestro | 160 | 64 | 24 |

Modificadores (se suman sobre la base, y **todo** se detalla en el modal de fin de partida):

| Modificador | Pago |
|---|---|
| Precisión ≥ 85% / ≥ 92% | +25% / +50% |
| Victoria sin perder piezas | +40% |
| Racha de victorias | +10% por victoria encadenada (tope +50%) |
| Primera victoria del día | +50 fijo |
| Mate en ≤ 20 jugadas vs Maestro / Gran Maestro | +60 fijo |
| Partida épica (> 60 jugadas y ganas) | +30 fijo |
| Repetir rival tras ganarle (1ª/2ª/3ª vez) | ×1 / ×0,75 / ×0,5 / ×0,25 |
| Partida de menos de 8 jugadas | no se paga |

## 2. Retos y entrenamiento

- **Entrenamiento táctico** (`PuzzleManager` + `GameManager`): sesión de 5 puzzles sobre el
  tablero real. 20 / 35 / 60 Gambits por puzzle según dificultad, **mitad** si se falla una
  jugada, 0 si se fallan dos; +80 por cada 5 limpios seguidos; +10 de rating por acierto y
  −10 por fallo. El jugador solo mueve la solución: una jugada equivocada no se aplica y
  destella en rojo.
- **Cupo diario del entrenamiento**: solo los **5 primeros puzzles resueltos del día** cobran
  (Gambits, rating y racha). A partir de ahí se puede seguir entrenando todo lo que se quiera,
  pero la sesión es **práctica**: sin Gambits, sin rating y sin romper la racha; la tarjeta
  cambia a **PRACTICAR 5 PUZZLES** y lo dice el toast del final. El cupo se gasta puzzle a
  puzzle (`PaidPuzzlesLeftToday`, claves `PuzzlePaidDay`/`PuzzlePaidPuzzles`, hora local), no
  por sesión: abandonar a medias no lo quema y repetir no lo amplía. Con 30 puzzles y pago por
  puzzle resuelto, repetir sesiones era un farmeo sin fin.
  Como red de seguridad, el cupo nunca se recalcula «de cero»: si el contador se quedara corto
  (PlayerPrefs de una versión anterior o borrado a medias), se deduce de los pagos que el libro
  diario (`GambitLedger.PaymentsToday(Puzzle)`) ya registró hoy, así que no se regalan los 5
  puzzles otra vez. Para subir/bajar el cupo solo hay que tocar `PuzzleManager.DailyPaidPuzzles`.
- **Desafío diario fuera del cupo**: el reto diario es un puzzle aparte (`IsAvailable` lo cierra
  al resolverlo) y no consume los 5 puzzles con premio del entrenamiento.
- **Desafío diario** (1 al día, un puzzle con semilla de la fecha): 50/60/70/80/100 Gambits
  según los días seguidos; saltarse un día reinicia la racha.

## 3. Misiones y barra semanal (pieza central)

- **3 misiones diarias** elegidas de un catálogo de 12 de forma determinista por fecha
  (misma selección para todos ese día); siempre entra una «fácil» y hay **1 cambio al día**.
  Pagan 30–90 Gambits. Ejemplos: *Gana 2 partidas*, *Gana en Caballero+*, *Captura 10
  piezas*, *Resuelve 3 puzzles*, *Gana con el Peón Lancero equipado*, *Logra 3 victorias
  seguidas*, *Completa el desafío diario*.
- **Barra del Atelier**: 7 segmentos, lunes→domingo (hora local). Cada día se rellena en
  tercios (0/3 → 33% → 66% → 100%) con las misiones completadas. Al llegar a 3/3 el día se
  **paga solo**:

  | Día | L | M | X | J | V | S | D |
  |---|---|---|---|---|---|---|---|
  | Gambits | 50 | 60 | 70 | 80 | 90 | 110 | 150 |

- **Cofre del Atelier**: los 7 días perfectos → **1.000 Gambits**, y cada semana perfecta
  **consecutiva** sube el cofre +200 (tope 1.600). El segmento se cobra automáticamente y el
  cofre con un botón; si la semana termina con el cofre sin reclamar, se cobra solo al
  cerrarla (nunca se pierde).
- **3 misiones semanales**: 10 victorias (250), 20 puzzles (250), 15 misiones diarias (350).

## 4. Logros, topes y anti-farmeo

- **Logros** (16): primera victoria, ganar a cada dificultad, 10/50/100 partidas, mate en
  ≤ 20 jugadas, victoria con 100% de precisión, 1200/1400/1600 de rating en puzzles, semana
  perfecta y primera variante. Pagan 50–500 y se cobran solos.
- **Topes diarios** (por fuente y global): partidas 6 pagos/320 G · puzzles 6/380 ·
  desafío 1/120 · misiones diarias 3/400 · semanales 3/900 · días perfectos 1/200 ·
  cofre 1/2.200 · primera del día 1/150. Tope blando global **900 G** (por encima paga el
  25%) y tope duro **1.400 G** (por encima no paga).
  Los 380 G de puzzles son exactamente una sesión perfecta (5 × 60 + 80 de racha), así que
  el cupo de 5 puzzles y el tope de la fuente se agotan a la vez.
- **Anti-farmeo**: repetir rival paga menos, las partidas de menos de 8 jugadas no pagan y
  los pagos por partida/puzzle están limitados por día. `GambitEconomy.Earn` aplica **las dos**
  paredes de cada fuente: el tope de importe (`dailyCap`) y el número de pagos (`maxPayments`,
  comprobado con `GambitLedger.PaymentsToday`). Solo las herramientas de depuración lo saltan
  (`ignorePaymentLimit`), y el tope de importe se respeta siempre.

## 5. Vista PROGRESO

Botón **PROGRESO** del menú principal (con el saldo y un aviso de cobros pendientes) abre:

1. Barra del Atelier con los 7 segmentos, su relleno real, el día actual, los días perdidos
   y la recompensa de cada uno (con ✔ cuando ya se cobró).
2. Cofre con el importe, la racha de semanas perfectas y su botón de cobro.
3. Misiones diarias (con barra de progreso, **COBRAR** y el cambio de misión) y semanales.
4. Retos: desafío diario (premio del día y racha de días · **JUGAR DESAFÍO**) y entrenamiento
   táctico (rating y mejor racha · **ENTRENAR 5 PUZZLES**, que pasa a **PRACTICAR 5 PUZZLES**
   cuando el cupo de premio del día se ha gastado).
5. Logros y catálogo de fuentes con lo ganado hoy y el margen que queda.

**Cofre animado.** Junto al botón de cobro va el cofre en sprite, y al cobrar se abre con las 8
capas de VFX y remata con la carta de premio. Lo llevan `UI/ChestSprites.cs` (carga los 17 PNG
del cofre y las cartas, más las 8 secuencias de frames) y `UI/ChestStage.cs` (el guion de la
apertura: un solo tic de 16 ms mueve todas las capas).

El cofre **no tiene bisagra**: las piezas del generador son dos poses del mismo cofre
(`chest_small` cerrado y `chest_base` abierto), y el cambio se hace **dentro del fogonazo de
`flare`, que va delante del cofre** — un anillo como `shockwave` no lo taparía, porque deja el
centro descubierto y el cofre está justo en el centro. Ver
`Docs/PROMPTS-COFRE-Y-RECOMPENSAS.md` §9 y §10 (incluye por qué `seal_break` se usa con placa
temporal y por qué `dust` va recortado).

**Sonido del cofre.** Las 12 piezas están en `Assets/Resources/SFX/SFX_Chest_*.wav` y las
reproduce `Audio/ChestAudio.cs` con dos fuentes: una para los golpes (que se solapan entre sí) y
otra para el latido en bucle. El sonido sale del **mismo tic de 16 ms** que enciende cada capa,
así que imagen y audio no pueden desincronizarse; el latido, en cambio, va con el estado de la
fila y no con el guion. Los mp3 entregados venían con silencio de relleno hasta el segundo
redondo, tres arranques desplazados (el golpe de `Boom` empezaba en 351 ms) y niveles 15 dB
aparte, así que se midieron y se cortaron uno a uno. El detalle —y la única pieza que **no** se
pudo arreglar, `Crack`, que es un swell y no un chasquido— está en `Docs/PROMPTS-SFX-COFRE.md` §6.

## Cómo probarlo

1. Menú → **PROGRESO**: los chips muestran el saldo y el ritmo del día.
2. **ENTRENAR 5 PUZZLES**: 5 puzzles en el tablero. Juega la solución (se ilumina en verde al
   seleccionar) y prueba una jugada mala (destello rojo, no se aplica). Al acabar vuelves al
   menú con el resumen y los Gambits sumados, y con el HUD de partida recogido: el historial, el
   botón Deshacer y el panel HABILIDADES desaparecen al cerrar la sesión (también si sales a
   medias), como en una partida normal al volver al menú.
3. **Repetir el entrenamiento el mismo día**: al segundo intento (o al sexto puzzle resuelto)
   el botón dice **PRACTICAR 5 PUZZLES** y el subtexto «cupo de hoy gastado». Se juega igual,
   pero el resumen final avisa de que es práctica y el saldo no se mueve; el Console del Editor
   lo confirma con `[PuzzleManager] Entrenamiento en práctica: el cupo de 5 puzzles con premio
   de hoy ya está gastado.` y `[GambitEconomy] … bloqueados: tope de entrenamiento táctico`.
4. **JUGAR DESAFÍO**: mate en 1 (rotación de 12 posiciones). Al resolverlo se paga la racha de
   días, el botón pasa a **✓ HECHO HOY** y la racha sube al día siguiente; si se falla (dos jugadas
   malas) el reto sigue disponible para reintentar. Cualquier mate cuenta, aunque no sea la jugada
   guionada del puzzle.
5. **JUGAR** una partida contra Caballero o superior y comprueba en el modal el desglose
   («Base», «Precisión», «Sin perder piezas», «Primera victoria del día»…).
6. Completa las 3 misiones del día y mira cómo el segmento pasa a 100% y paga su recompensa.
7. **Apertura del cofre.** Tres formas, de más rápida a más completa:
   - **Pulsar el cofre** en **PROGRESO**. Si todavía está cerrado, lo abre como vista previa
     (no cobra nada) — sirve para verla desde el primer arranque, sin rellenar nada.
   - Menú del editor **Wilder Gambit › Probar la apertura del cofre** (sólo en Play): rellena
     los 7 días, abre
     **PROGRESO** y lanza la presentación saltándose la capa de carga.
   - **El cobro de verdad**: rellenar la semana y pulsar **COBRAR COFRE**. El cofre se agrieta,
     estalla, se abre y sale la carta con el importe. El cobro se aplica **antes** de animar, así
     que los Gambits ya están en la cuenta aunque se cierre el modal a mitad; con el cofre ya
     cobrado, pulsarlo repite la presentación sin volver a pagar. De paso se **oye**: la grieta,
     el fogonazo, el anillo, las monedas y el pago. Si no suena nada, casi siempre es que Unity
     todavía no importó los WAV (el importador está en `Editor/ChestAudioImport.cs`).
8. **INVENTARIO** (botón girado del menú, a la derecha de SALIR):
   - **VARIANTES**: las que ya están en juego van en «EN USO» (verde); las tuyas, en «LISTAS
     PARA EQUIPAR» con **EQUIPAR**; y el Peón Lancero sin comprar, en «EN LA TIENDA» con su
     candado. Pulsa la carta o el botón: la pieza cambia y el estado se repinta al momento.
   - **SKINS**: misma idea, con filtro por tipo. Las que no son tuyas se **compran aquí** (con
     Gambits) y, al comprarlas, la carta pasa a **EQUIPAR**: comprar nunca equipa.
   - **TABLEROS**: los 10 tableros con su miniatura; al equipar uno, el fondo del menú se
     refresca al instante.
   - La chapa del botón del menú cuenta las piezas de tu colección.
   - **Regla**: la tienda y «TUS PIEZAS» ya no equipan nada. Allí solo verás el estado
     («EN EL INVENTARIO») y la compra.
9. Para limpiar todo el progreso: `GambitProgress.Debug.ResetEverything()`.

## Notas de diseño

- **Puzzles verificados**: las posiciones del reto diario son mate en 1 y están comprobadas con el
  Stockfish del proyecto (`python Tools/audit_puzzle_solutions.py`, que revisa también las 30 del
  entrenamiento y marca las que no coinciden con el motor). Si se cambia una posición hay que
  volver a pasar el chequeo: con una solución equivocada, el jugador que encuentra el mate ve
  "jugada incorrecta" y puede perder el reto sin haber jugado mal.

  El auditor revisa **toda la línea guionada**, no solo la primera jugada: reproduce el guion ply a
  ply con el motor (`python Tools/audit_puzzle_solutions.py 0` para solo legalidad) y delata las
  jugadas imposibles en la posición alcanzada. Esa clase de error era visible en el tablero: la
  dama negra "respondía" a un fork recorriendo la diagonal atravesando el caballo que la atacaba,
  porque la réplica guionada se aplicaba sin comprobar nada. Ahora `GameManager.ApplyScriptedReply`
  exige que la pieza sea la que tiene el turno y que la jugada esté entre sus legales; si el guion
  no encaja, el puzzle se descarta sin penalizar al jugador (`PuzzleManager.DiscardCurrentPuzzle`)
  y la sesión sigue con el siguiente. Cualquier posición o línea nueva debe pasar el auditor antes
  de entrar en el catálogo.

- **Sin veredicto del motor en entrenamiento**: en los puzzles la jugada ya la valida el guion, así
  que `EvaluateMoveWithStockfish` no analiza ni pone badge. Si analizara, el motor juzgaba la
  propia solución del puzzle (un sacrificio correcto) y le colgaba un "??" encima, que se leía
  como si el puzzle te estuviera diciendo que lo habías hecho mal.

- **El día no puede cerrarse en bucle**: `DailyMissions.Evaluate` lee el estado ya cargado y no pasa
  por `State`. Antes el cambio de día encadenaba `State → EnsureToday → AutoClaimPending →
  Evaluate → State` hasta reventar la pila (StackOverflow, que se lleva el proceso por delante y
  con él todo lo que aún no estuviera en disco: de ahí que se «perdieran» la racha de puzzles y el
  desafío recién completado). Ahora el día avanza *antes* de pagar lo del día anterior y el cobro
  recibe su estado como argumento, así que la recursión no existe. Si se toca este archivo: nada
  que lea `State` desde dentro del cierre del día.

- **Progreso a prueba de cierres**: cada cambio se guarda en el instante (economía, misiones,
  semana, logros, racha de puzzles y reto diario ya llaman a `PlayerPrefs.Save`), terminar o
  abandonar una sesión vuelca todo (`ProgressAutosave.Flush`) y un guardián (`ProgressAutosave`)
  vuelca también al pausar, al perder el foco y al salir. PlayerPrefs vive en memoria hasta el
  `Save`, así que lo que no pase por ahí se pierde si el juego muere de golpe.

- **PROGRESO no enseña el saldo a medias**: el saldo de Gambits es el de la cuenta de Surface
  (Render, que puede tardar en despertar), así que el panel abre su capa de carga
  (`.prog-loading`, animada desde `ProgressModal`) mientras pide el saldo, con tope de 10 s y
  aviso de «sin conexión · progreso local» si no contesta. El saldo se reutiliza 2 min, así que
  reabrir el panel es instantáneo; si la respuesta llega tarde, el panel se repinta solo.

- **Un solo punto de entrada** para el dinero: si algún día hace falta una fuente nueva, se
  añade a `GambitSources` y se llama a `GambitEconomy.Earn(...)`; topes, toast y sync con
  Surface vienen incluidos.
- **El saldo sigue siendo local** (`PlayerPrefs`): es una economía «de confianza». Si se
  quiere cerrar, el saldo debería vivir en Surface y el cliente pedir `earn` con motivo
  firmado.
- Los motivos enviados a Surface siguen el patrón `fuente_meta` (por ejemplo
  `match_victory_grandmaster`, `mission_win_hard`, `weekly_chest_2026-09-21`).
