# CONCEPTO — Nuevas piezas y variantes para Wilder Gambit

> Documento de **concepto** (no de implementación). Sirve como cantera de ideas para la
> pestaña **02 VARIANTES** de la tienda y para futuros modos de juego.

## Punto de partida (lo que ya existe en el código)

- Piezas estándar: `Assets/_Project/Scripts/Pieces/{King,Queen,Rook,Bishop,Knight,Pawn}.cs`
- Piezas especiales ya jugables: `SpectralPawn` (Peón Espectral) y `NecromancerBishop`
  (llamado desde `GameManager` cuando cae una pieza aliada).
- Transformación en partida: el **Caballo Blanco** pasa a estado *Fork*
  (`BoardView.TriggerKnightForkTransformation`, `KnightForkAnimator`).
- Fichas de piezas en la UI: formato ya establecido en `YourPiecesModal.cs` (~línea 414)
  con `name / type / rarity / passive / active / lore / tip`.
- Tienda: rail con `02 VARIANTES — Próximamente` (`MainMenu.uxml`, `shop2-nav`).

Conclusión: el motor ya tolera reglas no clásicas. Los conceptos de abajo siguen ese
precedente y están pensados para **venderse como Variantes** (pieza cosmética + regla
propia) sin romper el equilibrio base.

---

## A. VARIANTES DE PIEZAS EXISTENTES

### V1 — Alfil Espejo *(variante de Alfil)*
- **Pasiva «Reflejo»:** una vez por turno y **sin moverse**, puede cambiar de color de
  casilla (blanco ↔ negro). Gasta el turno.
- **Contrajuego:** pierde un tempo; contra torres y damas en columnas abiertas es castigo
  real.
- **Perfil:** RARA · ~500 Gambits · icono ◐.
- **Implementación:** `Bishop.cs` + flag `IsLightSquare`; el "cambio" es un estado, no un
  movimiento (no hay que tocar la lógica de legalidad del board, solo validar que no se
  combine con movimiento en el mismo turno).

### V2 — Torre Baluarte *(variante de Torre)*
- **Pasiva «Quebro»:** una vez por partida puede mover **1 casilla en diagonal** (como el
  Rey). Ideal para finales torre+rey.
- **Contrajuego:** uso único y visible (la UI marca "Quebro usado"); no escala.
- **Perfil:** RARA · ~650 Gambits · icono ⛨.
- **Implementación:** en `Rook.GetLegalMoves`, añadir 4 casillas adyacentes solo si
  `quebroDisponible == true`.

### V3 — Caballo Tangente *(variante de Caballo)*
- **Pasiva «Tangente»:** además del salto en L, puede dar **1 paso en diagonal** (Ferz).
- **Contrajuego:** es estrictamente mejor que un caballo, por eso su precio y su
  rareza; el rival puede juzgar mal el radio de ataque (ese es el gancho táctico).
- **Perfil:** ÉPICA · ~1200 Gambits · icono ◇.
- **Implementación:** `Knight.cs` añade 4 offsets diagonal de 1 casilla, con el mismo
  filtro de clavada (`IsMoveLeavesKingInCheck` ya existe).

### V4 — Peón Lancero *(variante de Peón)* ✅ IMPLEMENTADO
- **Pasiva «Lanza»:** puede **capturar hacia adelante** (además de la captura diagonal);
  mantiene avance simple, doble y al paso.
- **Contrajuego:** los peones lanceros no pueden ser "empujados" en masa sin abrir
  líneas; premia la captura activa, castiga la pasividad.
- **Perfil:** COMÚN → RARA · ~400 Gambits · icono ⚑.
- **Implementación:** `Pawn.cs`, rama extra en la captura; promoción igual que hoy.

### V5 — Rey Centinela *(variante de Rey)*
- **Pasiva «Escudo del Trono»:** **una vez por partida**, al entrar en jaque, el jaque se
  anula durante 1 réplica (el Rey ignora la amenaza ese turno).
- **Contrajuego:** no puede moverse durante la réplica protegido, y el rival lo ve (aviso
  en la UI). Si le dan mate *dentro* de esa réplica, es mate igual.
- **Perfil:** Legendaria · ~2000 Gambits · icono ♛.
- **Implementación:** flag en `Board.IsKingInCheck`-equivalente + evento en `GameManager`.
  Es la pieza con más riesgo de reglas: **prototipar primero en una partida de prueba**.

### V6 — Dama Ascética *(variante de Dama)*
- **Pasiva «Libre»:** alcance máximo de **3 casillas**, pero **ignora clavadas** (puede
  moverse aunque deje en jaque a su propio rey… no: ignorar la clavada significa que la
  regla de "no dejar tu propio rey en jaque" se relaja *solo* para ella en turnos
  impares — definir al prototipar).
- **Ajuste recomendado (versión segura):** alcance 3 + inmunidad a clavada, sin tocar la
  legalidad del jaque.
- **Perfil:** ÉPICA · ~1500 Gambits · icono ♢.
- **Implementación:** dos behaviors ya presentes en el código (limitar raycast + estado
  `isPinned` de la pieza).

---

## B. PIEZAS NUEVAS (categoría propia en la tienda)

### P1 — Halcón Errante *(promoción alternativa)*
- **Movimiento:** híbrido **Alfil + Caballo** (diagonal ∞ + saltos en L). Valor ≈ 5,5.
- **Rol:** la promoción "táctica" frente a la Dama "bruta".
- **Contrajuego:** no puede enrocar, es una pieza alta (blanca) visible desde lejos.
- **Perfil:** ÉPICA · ~1400 Gambits.
- **Implementación:** clase `Falcon.cs` que compone los dos patrones de búsqueda ya
  escritos (`Bishop` raycast + `Knight` offsets). Promoción: añadir opción en el diálogo
  de promoción.

### P2 — Nigromante Anciano *(evolución del NecromancerBishop)*
- **Pasiva «Resurrección»:** la primera vez que una pieza aliada es capturada en su
  radio (2 casillas), esa pieza vuelve como **Peón** en la casilla original vacía.
- **Contrajuego:** una sola vez por partida; el Nigromante queda "sin mana" (pierde su
  aura necrótica visible).
- **Perfil:** LEGendaria · ~1800 Gambits.
- **Implementación:** ya existe el gancho (`NecromancerBishop` recibe el aviso desde
  `GameManager`); hay que añadir el respawn del peón + la marca de "usado".

### P3 — Estandarte *(pieza de apoyo, nueva)*
- **Movimiento:** 1 casilla en cualquier dirección, **no captura**.
- **Pasiva «Estandarte»:** cualquier pieza aliada a 1 casilla de él tiene +1 de alcance
  (torre 8→9, alfil ∞→∞ pero gana el salto corto de 1, caballo gana Ferz… definir casos).
- **Contrajuego:** es una pieza sin ataque: capturarla es fácil y deja al portador sin
  bonificación. Solo disponible en modos con promoción especial.
- **Perfil:** RARA · pack "Piezas de Apoyo".
- **Implementación:** mayor esfuerzo (modifica alcances de terceros). **Solo si** los
  conceptos V1–P2 funcionan bien.

### P4 — Peón Espectral II — «Fantasma» *(iteración del SpectralPawn existente)*
- **Pasiva «Fase»:** puede cruzar **1 pieza** (aliada o enemiga) por casilla, una vez
  por turno, sin capturar.
- **Contrajuego:** no puede capturar en el turno en que atraviesa.
- **Perfil:** RARA · ~600 Gambits.
- **Implementación:** ya existe `SpectralPawn`; añadir el "phase-through" es un caso de
  pathfinding acotado.

---

## C. CUADRO COMPARATIVO

| # | Pieza | Tipo | Rareza | Precio (Gambits) | Esfuerzo | Riesgo de balance |
|---|-------|------|--------|------------------|----------|-------------------|
| V1 | Alfil Espejo | Variante | Rara | 500 | Bajo | Bajo |
| V2 | Torre Baluarte | Variante | Rara | 650 | Bajo | Bajo |
| V3 | Caballo Tangente | Variante | Épica | 1200 | Bajo | Medio |
| V4 | Peón Lancero | Variante | Común/Rara | 400 | Bajo | Bajo |
| V5 | Rey Centinela | Variante | Legendaria | 2000 | Alto | **Alto** |
| V6 | Dama Ascética | Variante | Épica | 1500 | Medio | Medio |
| P1 | Halcón Errante | Nueva | Épica | 1400 | Medio | Medio |
| P2 | Nigromante Anciano | Evolución | Legendaria | 1800 | Bajo-Medio | Medio |
| P3 | Estandarte | Nueva | Rara | 700 | **Alto** | Alto |
| P4 | Peón Fantasma | Variante | Rara | 600 | Bajo | Bajo |

**Orden de producción recomendado:** V4 → V1 → V2 → P4 → V3 → P1 → P2 → V6 → V5 → P3.

## D. REQUISITOS COMUNES A TODAS LAS VARIANTES
1. Ficha en `YourPiecesModal` con el formato existente (lore + tip incluidos).
2. Icono/sprite propio en `Assets/Resources/Pieces/<Color>/<Pieza>.png`.
3. Entrada en la pestaña `02 VARIANTES` de la tienda con preview en stage.
4. Nombre de id estable (`variant_bishop_mirror`) para persistencia de propiedad
   (mismo sistema que `PieceSkinManager`: PlayerPrefs + OceanPay).
5. Modo de uso: o bien (a) skin que **cambia las reglas de esa pieza en todas las
   partidas**, o bien (b) equipada por ranura como hoy — **decidir en el Plan de Skins**
   para no mezlear reglas con cosmética.
