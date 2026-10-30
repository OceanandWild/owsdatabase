# PLAN — Lote 3 de variantes de piezas (lote nuevo, V1–V6 descartados)

> La Fase 1/2 anterior (Alfil Espejo, Torre Baluarte, Caballo Tangente, Peón
> Fantasma) queda **descartada a petición del jugador**. Este documento la
> sustituye: 4 variantes **nuevas**, con mecánicas finales, orden, precios y el
> checklist de los 10 puntos de toque (patrón Lancer, sin cambios: ver §4).
>
> Cantera original (histórica): `Docs/CONCEPTO-NUEVAS-PIEZAS.md`.
> Alcance: funcional + UI (tienda, inventario, enciclopedia, panel de
> habilidades). Sin cambios al motor de reglas base ni a Surface.

## 1. Lote recomendado

| Fase | Variante | Base | Rareza | Precio | Esfuerzo |
|---|---|---|---|---|---|
| 3A | **Peón Mensajero** · pasiva «Correo» | Peón | RARA | 600 G | ~0,5–1 día |
| 3B | **Torre Codo** · pasiva «Recodo» | Torre | RARA | 700 G | ~1 día |
| 3C | **Alfil Travesía** · pasiva «Travesía» | Alfil | ÉPICA | 900 G | ~1–1,5 días |
| 3D | **Dama Jinete** · pasiva «Cabalgada» | Dama | LEGENDARIA | 1500 Tides | ~1 día |

Total del lote: 2200 G + 1500 T (la Jinete es la primera variante premium en
Tides, al nivel de los tableros premium; el resto se gana jugando).

## 2. Mecánicas finales

### 3A. Peón Mensajero — «Correo»

**Avance doble desde cualquier fila** (no solo la inicial), si las dos
casillas están libres. Resto idéntico: avance simple, capturas diagonales,
promoción y al paso sin cambios.

- Implementación: `MessengerPawn : Pawn` quitando la condición de fila inicial
  en la rama del avance doble. La más trivial del lote.
- Regla fina (fijada aquí): el **al paso solo existe contra dobles desde la
  fila inicial** (regla clásica intacta; los dobles de mensajero no se pueden
  tomar al paso). Evita reescribir `Pawn.cs` de capturas.
- Mapa de ataques sin cambios (ataca en diagonal como siempre): **sin tocar
  `Board.IsSquareAttacked`**.
- Contrajuego: el doble huido deja el peón vendido si no hay respaldo; premia
  rupturas, castiga el abuso. Riesgo bajo. Icono fallback: ✉.

### 3B. Torre Codo — «Recodo»

Además de sus rectas, **salta 2 casillas en diagonal** (aterriza en destino
libre o capturable; la pieza intermedia se ignora, no se captura).

- Implementación: `ElbowRook : Rook` + 4 destinos fijos en `GetValidMoves`.
  Sin raycast nuevo, sin flags: esfuerzo bajo.
- Mapa de ataques: los 4 aterrizajes cuentan como atacados (salta, así que el
  intermedio da igual). Rama pequeña en `Board.IsSquareAttacked` (mismo sitio
  que el frontal del Lancero).
- Contrajuego: destinos fijos y visibles; no abre líneas, solo pica. Riesgo
  bajo. Icono fallback: 📐.

### 3C. Alfil Travesía — «Travesía»

Su diagonal **atraviesa 1 pieza** (aliada o enemiga, sin capturarla en el
salto); a partir de ahí, reglas normales (la segunda pieza sí bloquea; más
allá mueve y captura como siempre).

- Implementación: `PassageBishop : Bishop` con raycast propio: al primer
  bloqueador se lo salta (sin añadirlo como captura), el segundo bloquea.
  Contenido en el bucle del rayo: esfuerzo medio, cero estados.
- Checkpoint en implementación: el mapa de ataques de alfiles en
  `Board.IsSquareAttacked` (sección 3, «Demás piezas»): si usa `GetValidMoves`,
  la Travesía entra gratis; si hay raycast duplicado, replicar el salto.
  **No asumir: leer antes de codificar.**
- Contrajuego: sigue atado al color; atravesar delata la intención un turno
  antes. Riesgo bajo-medio. Icono fallback: ⛰.

### 3D. Dama Jinete — «Cabalgada» (legendaria del lote)

Además de todo su repertorio, **una vez por partida** puede dar un **salto de
caballo** (los 8 destinos, con captura). La UI marca «Cabalgada usada».

- Implementación: `RiderQueen : Queen` con flag de instancia
  `RideAvailable = true` + 8 offsets cuando está disponible. Las piezas se
  spawnean cada partida, así que el flag **se resetea solo**: sin persistencia
  (igual que el Quebro descartado).
- Mapa de ataques: los 8 saltos cuentan **solo si `RideAvailable`**
  (`p is RiderQueen && p.RideAvailable`). Filtro de clavada/rey existente
  (`IsMoveLeavesKingInCheck`) se aplica igual a los 8 destinos.
- Estado visible: tarjeta en `VariantAbilityPanel` con «Cabalgada
  disponible/usada».
**Estado: IMPLEMENTADO (código).** QA visual pendiente en el editor Unity.
Clases: `Pieces/RiderQueen.cs` (flag `RideAvailable`, `IsRideDestination`,
`ConsumeRide`), loadout de dama en `PieceLoadoutManager` (precio
`RIDER_PRICE_TIDES = 1500`), consumo en `Board.MovePiece` (las simulaciones no
pasan por ahí), sprites/spawn/resolve en `BoardView` (pivot del cuerpo 0.34),
ítem con `priceTides` en `ShopVariantSelector` (primera variante premium),
filas en `InventoryModal`, sección DAMA en `YourPiecesModal` (UXML + C# +
entrada de enciclopedia), tarjeta en `VariantAbilityPanel`, `riderData` en el
Undo de `GameManager`, +1 en `GambitProgress.OwnedVariants`.
Arte: `Resources/Pieces/White/RiderQueen.png` (1065×810, dama de hielo + puño
+ espada); la negra aún no existe y cae a la Dama clásica negra (generarla con
el mismo prompt + ref Black). Promociones coronan Dama clásica (decidido).
Misiones: sin misión de Jinete todavía (seguimiento).

## 3. Decisiones de diseño (heredadas del lote anterior, siguen valiendo)

1. **Equipar = todas las piezas de ese tipo** (precedente Lancero).
2. **La IA juega clásico** (auditorías de puzzles + claridad rival). Checkpoint:
   forzar loadout clásico en el bando IA al implementar.
3. **`Type` base siempre** (FEN, promoción, al paso, notación y Stockfish intactos).
4. **Arte opcional el día 1** (fallback al sprite base + icono; los PNG
   `Resources/Pieces/White|Black/<Variante>.png` entran en lote de arte aparte:
   8 sprites, prompts estilo packs).

## 4. Checklist por variante (patrón Lancer, 10 puntos — sin cambios)

1. `Scripts/Pieces/<Variante>.cs` — subclase + override de `GetValidMoves`.
2. `Core/Board.cs` (`IsSquareAttacked`) — 3A no, 3B sí, 3C según checkpoint,
   3D condicional al flag.
3. `Core/PieceLoadoutManager.cs` — const de precio + `KEY_OWNED` + estado de
   loadout (int) + `UsesX(team)` con gateo de propiedad. (Sin rework de
   loadouts: cada variante es de un tipo distinto, todas con 2 estados.)
4. `View/BoardView.cs` — sprites W/B + `GetXSprite` con fallback + ramas de
   spawn por bando + resolución de sprite + `GetPieceType` si aplica.
5. `UI/ShopVariantSelector.cs` — entrada en `Items` (+ contador del tab en
   `MainMenu.uxml`; el paginador ya pagina solo).
6. `UI/InventoryModal.cs` — carta de variante (comprar→equipar vive aquí).
7. `UI/YourPiecesModal.cs` — ficha de enciclopedia (lore + tip).
8. `UI/VariantAbilityPanel.cs` — tarjeta en partida (3D: estado de Cabalgada).
9. `Core/GameManager.cs` — ganchos de restauración/turno (revisar los del
   Lancero antes de replicar).
10. `Core/GambitProgress.cs` — `SyncVariantsOwned` (logro de coleccionista).

## 5. Fases y QA

| Fase | Contenido | Esfuerzo |
|---|---|---|
| 3A | Peón Mensajero (mecánica + 10 puntos + QA) | ~0,5–1 día |
| 3B | Torre Codo (mecánica + mapa de ataques + 10 puntos + QA) | ~1 día |
| 3C | Alfil Travesía (raycast con salto + checkpoint + 10 puntos + QA) | ~1–1,5 días |
| 3D | Dama Jinete (flag 1×/partida + tarjeta de estado + 10 puntos + QA) | ~1 día |

**QA por variante** (checklist para el editor): comprar con y sin saldo (chips
con flash), equipar desde inventario (todas las del tipo cambian en tablero),
pasiva en partida vs IA (la IA sigue clásica), jaque/clavada con la pasiva,
deshacer/restaurar (GameManager), puzzles con variante equipada (¿forzar
clásico?), contador del tab y paginación, tarjeta del panel de habilidades,
logro de coleccionista. Casos propios: 3A al paso solo vs dobles iniciales,
3B salto con intermedio ocupado, 3C segundo bloqueador sí bloquea, 3D
Cabalgada gastada desaparece del mapa de ataques.
