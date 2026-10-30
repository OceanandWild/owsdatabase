# DOÑA PATADA — Documento de Diseño (borrador v0.1)

> Título provisional. Género: side-scroller 2D de pateo callejero.
> Tono: absurdo, cómico, sin violencia gráfica.
> Plataforma objetivo: PC (Unity 2D), con posibilidad de móvil más adelante.

---

## 1. High concept

Una anciana con muy poca paciencia recorre el barrio pateando abuelos que se le cruzan.
Es un Mario Bros lateral donde el salto es opcional y la patada de cadera es obligatoria:
avanzás, encadenás combos, mandás abuelos a volar y sumás puntos por hacerlo con estilo.

**Frase de ascensor:** *"Es Streets of Rage, pero con jubilados y una chancla con score."*

---

## 2. Pilares de diseño

1. **La patada siempre se siente bien.** Impacto exagerado, slow-mo breve, sonido de chancla, abuelos volando en arco.
2. **Fácil de agarrar, difícil de dominar.** Dos botones para pegar, pero el score premia variedad y encadenamiento.
3. **El humor nace del contraste.** Anciana frágil + violencia de dibujito + situaciones cotidianas del barrio.
4. **Partidas cortas, reinicio instantáneo.** Niveles de 3 a 6 minutos, muerte sin castigo largo.

---

## 3. Loop central

```
Entrar al nivel
   ↓
Avanzar pateando abuelos y esquivando obstáculos
   ↓
Encadenar combos para subir el multiplicador
   ↓
Llegar al objetivo del nivel (la fila, el bingo, la farmacia)
   ↓
Pantalla de resultados: puntos, rango, récord
   ↓
Desbloquear chancla / nivel / cosmético
   ↓
Siguiente nivel
```

Loop de sesión: 3-4 niveles por partida, con continue si se pierde.

---

## 4. Protagonista

**Doña Patada** (nombre real: Doña Remedios, 78 años).

- Jubilada, ex campeona de bochas, camina con una cadera que "ya no está para joda".
- Motivo del recorrido: alguien le robó su lugar en la fila del bingo y quiere recuperarlo.
- Personalidad: pocas palabras, mucha chancla. Nunca corre: avanza con determinación.
- Silueta reconocible: pelo blanco recogido, bata floreada, cartera colgada, chancla en la mano.

### Movimiento y estados

| Acción | Descripción |
|---|---|
| Caminar | Velocidad base, sin prisa |
| Apurar el paso | Dash corto con doble toque (no hay sprint sostenido) |
| Saltar | Salto corto, con patada aérea disponible |
| Agacharse | Esquiva ataques altos, permite barrida |

La protagonista **solo mira a izquierda o derecha**. No hay apuntado vertical ni movimiento en profundidad.

---

## 5. Combate

### 5.1 Ataques base

| Ataque | Input | Función |
|---|---|---|
| Patada rápida | Kick | Golpe básico, rápido, poco daño |
| Patada cargada | Mantener Kick y soltar | Lanza al enemigo lejos; rompe guardia |
| Barrida | Agachada + Kick | Derriba andadores y sillas de ruedas |
| Patada aérea | Kick en el aire | Remate, rebote contra el piso |
| Agarre | Cerca + Grab | Sostener al abuelo un instante |
| Lanzamiento | Grab + dirección | Tirar al abuelo contra otros enemigos u obstáculos |
| Chancla | Throw | Proyectil con rebote, se recupera del piso |

### 5.2 Defensa

- **Cartera**: bloqueo frontal con la cartera. Reduce daño, no lo elimina.
- **Parry de bolso**: bloquear en el momento exacto del golpe aturde al enemigo y abre combo gratis.
- **Grito de abuela**: recurso defensivo de área, empuja a todos los enemigos cercanos.

### 5.3 Combos

El multiplicador sube con cada golpe conectado sin recibir daño:

| Golpes seguidos | Multiplicador |
|---|---|
| 0-2 | x1 |
| 3-5 | x2 |
| 6-9 | x3 |
| 10-14 | x4 |
| 15+ | x5 (máximo) |

El multiplicador se pierde **solo** al recibir daño. Si pasan 4 segundos sin golpear, baja un nivel (no se reinicia).

### 5.4 Estilo

El score premia no repetir el mismo ataque:

- Variar entre patada, barrida, agarre y chancla da **bonus de estilo** (+25% al final del combo).
- Matar con el entorno (carrito, bache, vidriera) da **bonus de escenario** (+150).
- Mantener al abuelo en el aire con patadas aéreas da **bonus de malabarismo** (+50 por golpe).

---

## 6. Medidores

### Paciencia (vida)

- 3 golpes y se le acaba la paciencia.
- Se recupera con **pastillas** (pickup común) y **té de tilo** (pickup raro, restaura todo).
- Al llegar a cero: Doña Patada resopla, se agarra la cadera y se retira del nivel. Una vida menos.

### Mala leche (especial)

- Se llena pateando y encadenando combos.
- Al activarse: **Modo Chancla** durante 8 segundos.
  - Daño x2, velocidad +20%, patadas dejan estela cómica.
  - La música cambia a cumbia con órgano de iglesia.
- Alternativa táctica: gastar el medidor en **Grito de Abuela** para limpiar la pantalla.

---

## 7. Enemigos

| Enemigo | Comportamiento | Debilidad |
|---|---|---|
| Abuelo de bastón | Camina lento, golpea con bastón | Cualquier patada |
| Abuelo con andador | Bloquea de frente, avanza en línea | Barrida o patada cargada |
| Abuelo del banco | Tira migas de pan y palomas | Agarre y lanzamiento |
| Abuelo en silla de ruedas | Embestida en línea recta | Esquivar y redirigir contra pared |
| Abuelo de las compras | Tanque, aguanta tres golpes | Patada cargada al costado |
| Abuela rival de bingo | Esquiva y contraataca | Parry y castigo |
| Guardia de la farmacia | Bloquea con portapapeles | Chancla a la cabeza o entorno |

**Regla de tono:** los abuelos nunca sangran ni gritan de dolor. Reaccionan con quejas cómicas ("¡en mis tiempos esto no pasaba!"), se marean y desaparecen entre estrellitas.

---

## 8. Niveles

1. **El Parque** — tutorial. Bancos, palomas, primera chancla.
2. **La Fila del Banco** — embudo de gente, empujones, primer mini-jefe.
3. **El Supermercado** — carritos como obstáculo, pasillo de ofertas, vidrieras.
4. **El Bingo** — nivel de jefe. Butacas, bolillas, alfombra que resbala.
5. **La Farmacia** — pastillas como cura y como trampa; el guardia bloquea.
6. **La Residencia** — plataformas, pasillos, abuelos en masa.
7. **El Club del Dominó** — mesa por mesa, rivales que hacen trampa.
8. **La Plaza Mayor** — jefe final: el Abuelo Supremo del Bingo.

Cada nivel tiene:
- Un objetivo claro (llegar al final, romper la fila, recuperar el cartón).
- Una sección secreta opcional con puntos extra.
- Un rango final: C, B, A o **S (Abuela Suprema)**.

---

## 9. Score

### Puntos base

| Fuente | Puntos |
|---|---|
| Abuelo común | 100 |
| Abuelo con andador | 150 |
| Abuelo tanque | 250 |
| Abuela rival | 300 |
| Jefe | 1.000 |
| Pastillas | 25 |
| Chancla recuperada en el aire | 50 |

### Multiplicadores y bonus

- Multiplicador de combo: x1 a x5 (ver 5.3).
- Bonus de estilo: +25% si usaste 3 ataques distintos en el combo.
- Bonus de escenario: +150 por KO ambiental.
- Bonus de malabarismo: +50 por golpe aéreo encadenado.
- Bonus de perfección: +500 si terminás el nivel sin recibir daño.
- Bonus de tiempo: hasta +300 según el reloj.

### Rangos por nivel

| Rango | Requisito |
|---|---|
| C | Terminar el nivel |
| B | 60% del score máximo estimado |
| A | 80% del score máximo estimado |
| S | 95% + sin recibir daño |

---

## 10. Progresión y desbloqueables

- **Chanclas**: distintas stats y efecto visual (chancla de goma, de cuero, con brillitos, edición bingo).
- **Batas**: cosméticos que no cambian stats.
- **Movimientos**: patada cargada desde el nivel 2, agarre desde el nivel 3, parry desde el nivel 4.
- **Cartones de bingo**: moneda de progreso; se gastan en la tienda del club.
- **Récords**: score por nivel y score total, guardados localmente.

Sin árbol de habilidades complejo: desbloqueos lineales y claros.

---

## 11. Estética y audio

- **Arte**: pixel art de alta resolución o cartoon vectorial simple. Paleta cálida de barrio: verdes apagados, ocres, flores de bata.
- **Animación**: exagerada, con anticipación y squash/stretch. El impacto de la patada congela un frame y sacude la cámara.
- **Cámara**: lateral fija con scroll horizontal, pequeños zooms en los remates.
- **Música**: base de cumbia/chiptune; en Modo Chancla cambia a órgano dramático.
- **Sonido**: chancla seca, queja de abuelo, bolillas de bingo, palomas.

---

## 12. Referencias

- *Streets of Rage 4* — legibilidad de combos y feedback de impacto.
- *Shovel Knight* — niveles cortos con secreto opcional.
- *Untitled Goose Game* — humor cotidiano y tono absurdo sin crueldad.
- *Mario Bros* — estructura de avance lateral y ritmo de niveles.

---

## 13. Alcance del MVP

Para validar la idea antes de producir arte final:

- 1 nivel jugable (El Parque).
- 3 tipos de enemigo: bastón, andador, silla de ruedas.
- 3 ataques: patada rápida, patada cargada y chancla.
- Score con multiplicador y rango final.
- 1 pickup: pastillas.
- Sin tienda, sin jefes, sin progresión.

**Métrica de éxito del prototipo:** que patear se sienta tan bien que den ganas de repetir el nivel para subir el rango.

---

## 14. Riesgos y decisiones abiertas

- **Tono**: el humor con abuelos puede leerse mal si se cruza la línea. Regla: nadie sufre, todo es dibujito.
- **Nombre**: "Doña Patada" es provisional; ver alternativas en el anexo.
- **Movimiento**: decidir si hay scroll automático en alguna sección o todo es avance libre.
- **Multijugador**: cooperativo local de dos abuelas queda para una segunda etapa.

---

## Anexo A — Lluvia de ideas abierta

### Nombres alternativos
- Doña Patada
- Abuela K.O.
- Chancla Fury
- La Pateadora
- Bingo Brawl
- Geriátrico Rumble

### Gags reutilizables
- Slow-mo con zoom al impacto y una paloma que cruza en cámara lenta.
- El abuelo vuela y se queda colgado de un árbol como adorno.
- Cartel de "Cuidado con la abuela" en cada nivel.
- La chancla vuelve sola como boomerang si la tirás con mala leche llena.
- Récord celebrado con fuegos artificiales de bolillas de bingo.

### Ideas para jefes
- **El Abuelo Supremo del Bingo**: pega con el micrófono y convoca bolillas.
- **La Presidenta del Club**: pelea con reglamento en mano, invoca socios.
- **El Guardia de la Farmacia**: usa el portapapeles como escudo y llama refuerzos.
- **El Rey del Dominó**: mesa giratoria, fichas como proyectiles.

### Posibles power-ups
- **Té de tilo**: restaura toda la paciencia.
- **Chancla con brillitos**: el próximo golpe es crítico.
- **Silla de ruedas**: montable temporal, embiste en línea recta.
- **Cartón de bingo**: imán de puntos durante 10 segundos.
