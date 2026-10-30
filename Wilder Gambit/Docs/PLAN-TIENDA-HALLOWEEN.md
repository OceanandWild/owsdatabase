# PLAN — Tienda de la Velada (tienda de Dulces)

> **Objetivo:** que los **Dulces** sobrantes de la velada de Halloween tengan destino:
> un modal propio —**Tienda de la Velada**— donde se cambian por Gambits, niveles del
> mini-pase, las **skins esculpidas** (`hwp_*`) y las **variantes** de la edición.
> Nada de la tienda toca las claves de la temporada T1: todo vive en el evento.
> **Alcance:** funcional (catálogo + compras) + UI (modal nuevo) + integración con
> skins (arte propio en partida), variantes (arte + equipamiento) y el pase (botón TIENDA).

## Piezas del sistema

| Archivo | Qué hace |
|---|---|
| `Core/HalloweenShop.cs` | Catálogo y compras de la tienda: packs de Gambits, niveles del pase, skins esculpidas y variantes. Todo se paga con `HalloweenCurrency.Spend`. |
| `UI/HalloweenShopModal.cs` | Modal de la tienda (4 pestañas: GAMBITS · NIVELES · SKINS · VARIANTES), fichas con arte del catálogo y CTA de estado. Espejo del modal de misiones. |
| `Core/HalloweenArt.cs` | Arte de la velada (`Resources/Pieces/Halloween/hwp_*`): nombres, carga por disco/Resources y caché. Lo comparten tablero, tienda e inventario. |
| `Core/PieceSkinManager.cs` | Cuatro skins nuevas (`skin_pawn_spider`, `skin_knight_bat`, `skin_rook_crypt`, `skin_rook_grave`) con **arte propio** (no solo tinte): la skin reemplaza el sprite de la pieza en partida. |
| `Core/PieceLoadoutManager.cs` | Propiedad y equipamiento de las dos variantes: Peón Calabaza y Caballo Fantasma. |
| `Pieces/PumpkinPawn.cs` | Peón Calabaza: pasiva «Explosión de Calabaza» (el primer peón capturado del bando aturde 2 turnos al capturador). Mismo movimiento que el peón clásico y `Type` fijo. |
| `Pieces/GhostKnight.cs` | Caballo Fantasma: pasiva «Salto de Niebla» (tras capturar, reaparece a un salto) + activa «Posesión» (cambia casilla con un peón aliado). `Type` fijo. |
| `UI/HalloweenPassModal.cs` | Enciende el botón **TIENDA** del topbar (antes deshabilitado) y lo conecta con el modal de la tienda. |

## 1. Entrada y fases

- El botón **TIENDA** del topbar del pase de Halloween abre el modal por encima
  (`OpenHalloweenShopModal`), igual que MISIONES abre el tablero. En móvil vertical
  el botón vive en la fila de acciones, junto a MISIONES (antes se ocultaba).
- La tienda **se abre en cualquier fase** (antes, durante y después de la velada):
  los Dulces y lo comprado no se pierden con el cierre.
- Lo único con compuerta de fechas son los **niveles del pase**: solo se compran con
  la velada activa (`HalloweenEvent.IsActiveNow`). Fuera de la ventana el CTA queda
  apagado («SE ABRE CON LA VELADA» / «LA VELADA TERMINÓ»).
- Regla de la casa: **la tienda vende, el inventario equipa**. Las fichas de skins y
  variantes compradas muestran «EN TU INVENTARIO» y el equipamiento se hace en
  Tus Piezas / Inventario.

## 2. Catálogo

### 2.1 Gambits (pestaña GAMBITS — repetible, sin topes)

| Pack | Gambits | Precio (🍬) |
|---|---|---|
| Puñado de Gambits | 500 | 10 |
| Bolsa de Gambits | 1.500 | 26 |
| Cofre de Gambits | 4.000 | 60 |
| Alijo de Gambits | 10.000 | 130 |

- Cobro por `GambitEconomy.Earn(..., GambitSource.HalloweenShop, bypassCaps: true)`:
  es una compra, no farming, así que no toca los topes diarios del libro.
- El pago se verifica antes de gastar: si la economía lo recorta, no se descuentan Dulces.

### 2.2 Niveles del pase (pestaña NIVELES — solo con la velada activa)

| Opción | Efecto | Precio (🍬) |
|---|---|---|
| Nivel suelto | +60 XP (1 nivel) | 14 |
| Tramo de 5 | +300 XP (5 niveles) | 65 (13/nivel) |
| Decena | +600 XP (10 niveles) | 120 (12/nivel) |
| **Completar todo el pase** | XP hasta el tope (1.800) | 26 por nivel faltante |

- El XP entra por `HalloweenProgress.AddXpForced` (sin compuerta de fechas: la
  compuerta la pone el CTA) y se clampea al tope.
- **Completar todo el pase es carísimo a propósito**: desde cero cuesta 780 Dulces
  (30 niveles × 26), más que todo lo que reparte la edición. Es la salida de
  emergencia para quien llegó tarde, no un atajo barato.
- El precio de completar se calcula con los niveles faltantes al momento de la compra.

### 2.3 Skins esculpidas (pestaña SKINS)

| Piel | Pieza | Rareza | Precio (🍬) |
|---|---|---|---|
| Peón Araña (`skin_pawn_spider`) | Peón | Poco común | 55 |
| Torre Cripta (`skin_rook_crypt`) | Torre | Rara | 70 |
| Caballo Murciélago (`skin_knight_bat`) | Caballo | Rara | 75 |
| Torre Tumba (`skin_rook_grave`) | Torre | Rara | 85 |

- **Arte propio**: a diferencia de las skins de tinte, estas reemplazan el sprite de
  la pieza en partida (`BoardView.ApplyEquippedSkin`). El lado negro usa la versión
  `hwp_*_black.png` cuando exista; mientras no esté, cae al arte base con tinte
  neutro oscuro para que los bandos se distingan.
- Las cuatro skins del pase (`skin_pawn_halloween` y compañía) siguen siendo
  exclusivas del pase: la tienda no las vende.

### 2.4 Variantes (pestaña VARIANTES)

| Variante | Pieza | Precio (🍬) |
|---|---|---|
| Peón Calabaza (`pumpkin_pawn`) | Peón | 110 |
| Caballo Fantasma (`ghost_knight`) | Caballo | 125 |

- **Peón Calabaza** (pasiva «Explosión de Calabaza») y **Caballo Fantasma** (pasiva
  «Salto de Niebla» + activa «Posesión») ya traen su mecánica.
- El equipamiento convive con las variantes ya existentes: Alfil = clásico /
  Nigromante y Peón = clásico / Lancero / Calabaza (un loadout por bando).
- Las versiones negras del arte quedan pendientes: la pieza negra usa
  `Pieces/Halloween/hwp_*_black.png` en cuanto exista.
- El resto del lote (`hwp_knight_skeleton`, `hwp_bishop_vampire`, `hwp_king_vampire`,
  `hwp_queen_witch`) queda **fuera de la tienda** hasta que se decida su destino.

## 3. Economía de la edición (referencia)

| Ingresos por edición | Dulces |
|---|---|
| 3 misiones diarias × 14 días × 2 | 84 |
| 5 exclusivas de Sangre libres × 4 | 20 |
| 5 exclusivas de Sangre premium × 6 | 30 |
| Vía Luna (30 niveles) | 126 |
| Vía Sangre (30 niveles) | 130 |
| Pase de temporada (vía libre 29 + real 37) | 66 |
| **Total** | **456** |

| Gastos | Dulces |
|---|---|
| Abrir la Vía Sangre | 150 |
| **Queda para la tienda** | **306** |

Con 306 Dulces alcanza para una variante + una skin, o para dos skins y un puñado
de Gambits. Los precios viven todos en `HalloweenShop`: cualquier ajuste es una línea.

## 4. QA (Editor)

Menú **Wilder Gambit › Halloween**: `+40 Dulces` para probar compras, `+240 XP`
para los niveles, y el reset de la velada. Con la fase forzada a ACTIVO se prueban
las compras de nivel; con PRÓXIMAMENTE/TERMINADO se comprueba el candado.

## 5. Pendientes

1. **Arte negro** de las dos variantes y de las cuatro skins esculpidas
   (`hwp_*_black.png`): se resuelve soltando los PNG en `Resources/Pieces/Halloween`.
2. **Destino post-velada** de las skins esculpidas (¿rotan a la tienda con Gambits/Tides
   o se retiran hasta Halloween 2027?).
