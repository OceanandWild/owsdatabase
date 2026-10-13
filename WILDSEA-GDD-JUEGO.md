# WILDSEA REALMS — GDD del Juego (Espacio)

> Documento de diseño de **Fase 2**. El GDD de v1 (`WILDSEA-REALMS.md`) cubre menús y Hub;
> este cubre las reglas. Motor: Unity 6000 URP, UI Toolkit.
> Alcance de esta fase: **Espacio**, sus 2 modos, contra IA y contra hotseat local.
>
> Decisiones ya tomadas (no se reabren sin acordar):
> 1. **Un solo pool de cartas** para los 2 modos. Cambia la meta, no las cartas.
> 2. **IA y hotseat desde el primer día.** Obliga a un modelo de turnos asíncrono.
> 3. Este documento va antes del código.

---

## 0. Ficha rápida

- **Universo:** Espacio
- **Modos:** Estrella y Galaxia
- **Jugadores:** 2 (IA o humano local, intercambiable en caliente)
- **Partida Estrella:** ~6 turnos. **Galaxia:** ~16 turnos.
- **Pool:** 30 diseños de carta. **Mazo inicial:** 20 cartas, idéntico para ambos jugadores.
- **Métrica:** Cosmos. Todo es Cosmos: energía y puntos.

## 1. Pilares

1. **El tablero es el conflicto.** No se juega mano contra mano: se compite por un
   tablero compartido de Estrellas. Robarlecosmos al rival es la jugada fuerte.
2. **Las cartas no cambian entre modos.** Se aprenden una vez. La habilidad está
   en cuándo, no en memorizar dos mazos.
3. **Cada turno es una decisión legible.** Pocas cartas, efectos claros, nada oculto.
4. **Sin azar en el turno.** Solo hay azar en el robo. Nada de dados ni daño aleatorio.

## 2. Vocabulario

| Término | Significado |
|---|---|
| **Cosmos** | Recurso único. Se gana por turno y se gasta al jugar cartas. También es la unidad de puntuación. |
| **Estrella** | Casilla del tablero compartido. Se completa al llegar a **5 de cosmos**. |
| **Galaxia** | **4 Estrellas** completadas por el mismo jugador. |
| **Nexo** | El tablero compartido. |
| **Pila** | Mazo del jugador. Roba 2 al empezar cada turno. |
| **Nexo→Mazo** | Al robar, si la Pila está vacía, baraja el descarte y se lo queda. |

## 3. El tablero

**5 casillas de Estrella**, comunes a los dos jugadores, en fila.

```
   [ S1 ] [ S2 ] [ S3 ] [ S4 ] [ S5 ]
     0     2     5     0     3        <- cosmos actual,cosmos puesto por cada quien
```

Reglas:

1. Cualquiera de los dos puede aportar cosmos a **cualquier** Estrella que no esté completa.
2. Al llegar a 5, la Estrella se completa y **la reclama quien más cosmos aporta en ella**.
3. Empate: gana el turno el **jugador activo**. Es un sesgo deliberado a favor de la iniciativa.
4. Una Estrella completa ya no admite cosmos.

Esto genera la tensión central: aportar a una Estrella donde el rival va ganando es
"invertir en algo que te van a quitar". Aportar a una vacía o a una propia es seguro pero lento.

## 4. El turno

```
1. ROBAR      hasta tener 5 cartas en la mano (tope de mano: 7)
2. COBRAR     3 cosmos  +  1 por cada Estrella propia
3. JUGAR      cartas hasta quedarse sin cosmos o sin jugables
4. RESOLVER   efectos de las cartas jugadas, en el orden jugadas
5. FIN        el cosmos no gastado se pierde (salvo Ley de Conservación)
```

El orden de los pasos 1 y 2 importa: robar **antes** de cobrar cosmos es lo que hace que
las cartas de robo (Sondeo, Cartografía) valgan la pena.

## 5. Los dos modos

Mismo pool, misma economía por turno. Difieren en **tres cosas**:

| | **Modo Estrella** | **Modo Galaxia** |
|---|---|---|
| **Victoria** | Completar **1** Estrella | Completar **4** Estrellas |
| **Completar una Estrella** | Termina la partida | Robás 1 carta + ganás **+1 cosmos permanente** por cada Estrella propia |
| **Casillas en el Nexo** | **4** (tablero chico, mucha contensión) | **6** (más espacio, 4 son necesarias) |

La diferencia de fondo: en Estrella es una carrera pura, se gana rápido y se pierde rápido.
En Galaxia no podés ganar antes del turno ~12, así que la primera mitad se juega para
**tomar ventaja**, no para cerrar. Y como cada Estrella propia da +1 cosmos permanente, ganar
tarde genera efecto bola de nieve: la ventaja se acumula sola.

> **Nota de balance:** el objetivo de Estrella (5 cosmos netos) es un cuarto del de Galaxia
> (20). Con la misma economía por turno, las duraciones salen solas sin tocar cartas.

## 6. Anatomía de la carta

```
CardDef
  id           string      "colonizador"
  name         string      "Colonizador"
  cost         int         cosmos que cuesta jugarla
  cosmos       int         valor que aporta al tablero
  tag          enum        Cosmos | Star | Event | Tech
  iconGlyph    string      "🚀"  (sprite en v2 del juego)
  effects      list        reglas que dispara al resolverse
```

Cuatro tags, cuatro comportamientos de resolución distintos:

| Tag | Cuándo resuelve | Ejemplo |
|---|---|---|
| **Cosmos** | Inmediato, al jugar | Colonizador: +2 a una Estrella |
| **Star** | Al **completarse** la Estrella a la que aporta | Sirio: al completarse, robás 1 carta |
| **Event** | Inmediato, una vez por partida | Supernova: vacía una Estrella incompleta |
| **Tech** | Permanente, desde que se juega | Red de Sensores: +1 cosmos al completar |

Las **Star** son las únicas cartas cuyo valor no escosmos: dependen de que la Estrella
se complete. Eso las hace lugar-dependent y es la principal decisión táctica del juego.

## 7. El pool (30 diseños)

### 7.1 Cosmos (14)

| Nombre | Coste | Cosmos | Notas |
|---|---|---|---|
| Chispa | 0 | 1 | Relleno. Nunca la descarten. |
| Explorador | 1 | 1 | El cuerpo del mazo. |
| Resonancia | 1 | 2 | Mejor ratio que Explorador. La primera carta que se quiere. |
| Colonizador | 2 | 2 | |
| Corriente | 2 | 3 | Ratio 1.5. |
| Navegante | 3 | 3 | |
| Impulso | 3 | 4 | Ratio 1.33. Cara de comprar pero muy eficiente. |
| Catalizador | 4 | 6 | La única que mueve el juego de golpe. |

Repeticiones: Chispa x3 · Explorador x3 · Resonancia x2 · Colonizador x2 · Corriente x2 · Navegante x1 · Impulso x1 · Catalizador x1 = **15 cartas**, 15 turnos de fuera.

### 7.2 Star (6) — con nombre, dependen de completar

| Nombre | Coste | Efecto al completarse su Estrella |
|---|---|---|
| Procyon | 1 | Ganás 2 cosmos extra este turno |
| Sirio | 2 | Robás 1 carta |
| Altair | 2 | +1 cosmos a cada Estrella propia |
| Betelgeuse | 3 | +2cosmos a una Estrella y +1 permanente |
| Vega | 3 | Tu próxima carta de esta partida cuesta 1 menos |
| Rigel | 4 | +2 cosmos a una Estrella y +1 a todas |

### 7.3 Event (4) — una vez por partida

| Nombre | Coste | Efecto |
|---|---|---|
| Sondeo | 0 | Robás 1 carta |
| Cartografía | 1 | Robás 1 carta, +1 cosmos |
| Supernova | 5 | Vacía una Estrella incompleta (vuelve a 0) |
| Colapso | 4 | Vacía la Estrella donde el rival tiene más cosmos |

### 7.4 Tech (2) — permanentes

| Nombre | Coste | Efecto |
|---|---|---|
| Red de Sensores | 2 | Cada vez que completás una Estrella, ganás 1 cosmos extra |
| Ley de Conservación | 3 | El cosmos no gastado **no se pierde** al final del turno |

### 7.5 Robo (4)

| Nombre | Coste | Cosmos | Efecto |
|---|---|---|---|
| Reciclaje | 0 | 0 | Descartás 1 carta de la mano, ganás 2 cosmos |
| Sondeo de Profundidad | 1 | 1 | Robás 1 carta |
| Archivo | 2 | 2 | Robás 2 cartas |
| Búsqueda | 2 | 3 | Robás 1 carta |

> **Total: 31.** Hay una carta de más respecto a los 30 del objetivo. Se ajusta al cerrar
> el mazo; dejada a propósito para que la aritmética se vea al/designar el mazo y no después.

## 8. Mazo inicial (20 cartas, idéntico para ambos)

| Cantidad | Carta | Tag | Por qué está |
|---|---|---|---|
| x3 | Chispa | Cosmos | Nunca se muere la mano |
| x2 | Explorador | Cosmos | Cuerpo |
| x2 | Resonancia | Cosmos | Ratio, primera compra |
| x2 | Colonizador | Cosmos | Cuerpo |
| x1 | Corriente | Cosmos | Valor |
| x1 | Impulso | Cosmos | Golpe grande |
| x1 | Catalizador | Cosmos | Acelera la partida |
| x2 | Procyon | Star | Barato, cumple al completar |
| x1 | Sirio | Star | Robo, genera boards distintos |
| x1 | Altair | Star | Escala con tus Estrellas |
| x1 | Búsqueda | Robo | Motor de robo |
| x1 | Sondeo de Profundidad | Robo | Motor de robo |
| x1 | Reciclaje | Robo | Filtra cartas flojas de la mano |
| x1 | Supernova | Event | Negación de tablero |
| x1 | Red de Sensores | Tech | Premia completar |
| | | **= 20** | |

**Descarte:** se baraja de nuevo cuando la Pila se agota. Sin límite.

## 9. Victoria, derrota y fin

- **Estrella:** al completarse una Estrella y ser reclamada, gana quien la reclamó.
- **Galaxia:** al llegar a 4 Estrellas propias, gana quien las tenga.
- **Empate técnico:** si un jugador no puede jugar y no tiene cartas jugables, **pierde**
  (el rival gana por abandono). Nunca hay empate.
- **Fin de partida:** inmediata. No hay turnos extra ni prolongation.

## 10. Los dos rivalizadores

Esto es lo que "IA y hotseat desde el start" cuesta. Un jugador es una **interfaz**, no
una cosa dentro del motor:

```csharp
public interface IPlayerController
{
    // Presenta el estado al jugador (IA: log; humano: dibuja la UI)
    IEnumerator BeginTurn(ViewFor player);
    // Devuelve las cartas que quiere jugar. IA: inmediato. Humano: espera input.
    IEnumerator RequestPlays(ref MatchState s, ViewFor player);
}
```

El `MatchRunner` (MonoBehaviour, corrutina) alterna entre los dos sin saber cuál es cuál.
Cambiar de IA a humano en caliente es cambiar una referencia.

### 10.1 IA — heurística voraz (v1)

Sin búsqueda. En cada turno, hasta que no pueda jugar:

1. Lista las cartas de la mano con `cost <= cosmos`.
2. Puntúa cada una:
   - `+100` si completa una Estrella
   - `+40` si la aporta a una Estrella donde ya va ganando
   - `+25` si es una Star que ya está cerca de completarse
   - `+10 × (cosmos / coste)` como base
3. Juega la de mayor puntaje. Repite.
4. Si no hay jugables: descarta su peor carta (Reciclaje) y juega eso.

Objetivo declarado: **que sea mediocre a propósito.** Debe poder perder y debe dejar
que una persona normal gane con jugar razonable. Sirve para testear balance, no para
competir.

### 10.2 Hotseat

El turno humano se cierra con un **telón**: pantalla negra con "Pasale el control a
<nombre>", que espera un toque. Se implementa como una stage más de la corrutina del
`MatchRunner`, no como un caso especial de la UI.

## 11. Balance — números para arrancar

Estos son los valores a testear, no truths. Si el playtest los rompe, se cambian acá.

| Parámetro | Valor | Rango sano |
|---|---|---|
| Cosmos por turno | 3 | 3-4 |
| Cosmos para completar Estrella | 5 | 4-6 |
| Cosmos inicial | 0 | 0 |
| Mano inicial | 5 | 5-6 |
| Robo por turno | 2 | 1-2 |
| Tope de mano | 7 | 7-8 |
| Estrellas (Nexo) | 5 (4 / 6 por modo) | 4-6 |
| Meta Galaxia | 4 Estrellas | 3-5 |
| Duración Estrella | ~6 turnos | 5-8 |
| Duración Galaxia | ~16 turnos | 12-20 |

**Smoke test:** si una partida de Estrella no termina en menos de 8 turnos, o una de
Galaxia no termina en más de 20, el ritmo está roto antes que las cartas.

## 12. Qué NO entra en esta fase

- Online / relay. El modelo de `IPlayerController` lo permite después; el de red no.
- Más Universos. Espacio define las reglas de aislamiento.
- Arte de cartas. En v1: `iconGlyph` unicode, como las cards del Hub.
- Animaciones. Las cartas se colocan de golpe; el efecto visual viene después.

## 13. Decisiones abiertas

Ninguna de estas bloquea el arranque. Se resuelven cuando toque:

1. **Cosmos se puede gastar en cartas Star que no vas a completar.** ¿Se permite?
   Hoy sí, y es una decisión real (invertís en una Estrella que te van a robar).
2. **Estrellas vacías al final de partida.** No hacen nada. ¿Se barren o quedan?
3. **El jugador activo saca primero.** Hoy no hay ventaja de ser el que empieza más
   allá del desempate a su favor.
4. **Tech de 3 cosmos es fuerte.** Ley de Conservación probablemente rompe el ritmo si se
   juega temprano. Hay que ver si necesita un limitador.

## 14. Lo que hay que revisar de este documento

Cuatro cosas que se eligieron sin poder testear y conviene mirar con lupa:

1. **El Nexo compartido** (sección 3). Es la decisión de diseño más grande: hace que
   el juego sea de contendsión y no de solitario. Si no convence, todo lo demás se
   recalcula.
2. **La diferencia de 5 vs 6 casillas** entre modos. Elegida por coherencia con la meta,
   no por playtest.
3. **Que 31 cartas no 30** — la aritmética del pool está sin cerrar a propósito.
4. **La Tope de mano en 7 con robo de 2.** Con 4 cartas Robo en el mazo, la mano se
   inunda rápido. Puede que el robo tenga que ser 1.
