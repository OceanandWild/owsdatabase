# ⚔️ WILDWEAPON MAYHEM — Documento de Diseño (v1: Duelos de Armas PVP)

> Reboot del proyecto para Unity 2D. La versión Electron fue retirada del workspace (ver sección 12: migración).
> Este documento define el nuevo juego desde cero: **duelos de armas 1v1 con carga de 2 armas** (portador simple + habilidades por arma), **economía nueva sin gacha**, y un plan de reuso del arsenal ya producido.
> Motor: **Unity 6000 URP 2D + UI Toolkit** (estándar actual del estudio).
> Slug: `wildweapon-mayhem` · Carpeta: `WildWeapon Mayhem/` · Repo de releases: `OceanandWild/wildweapon-mayhem`
> Estado: **propuesta v1 para aprobación** · 2026-10-17

---

## 0. Ficha rápida

- **Título:** WILDWEAPON MAYHEM
- **Tagline:** *Un arma. Un rival. Sin excusas.*
- **Género:** Duelos de armas 1v1 (arena de acción top-down con **carga de armas**: 2 slots en v1)
- **Vista:** 2D cenital · canvas de diseño 1920×1080
- **Plataformas v1:** Windows (principal) · WebGL testeable · Android fase 1B (táctil)
- **Sesión:** duelo best-of-3 ≈ 2–4 min · sesión diaria online ≈ 5–15 min
- **Modos v1:** Online 1v1 (sala con código) · Local 1v1 · Entrenamiento (tutorial + bots)
- **Carga de duelo:** 2 armas equipadas por portador (3 con el **Mayhem Game Pass**, futuro)
- **Pilares:**
  1. **Tu carga, tu kit.** Cada arma trae sus propias habilidades; combinás 2 (y pronto 3 con el Game Pass) y el **cambio en combate** es la curva de skill.
  2. **Duelo corto y reñido.** Rounds de ~60–75 s, sin downtime, best-of-3 siempre al filo.
  3. **Espectáculo contundente.** VFX/SFX del arsenal existente (ya producidos) como identidad de golpe.
  4. **Justo por diseño.** Cero pay-to-win: todo se desbloquea jugando; el pago es decorativo.
- **Lo que NO es v1:** sin ranked con temporadas, sin 2v2, sin gacha, sin poderes/elementos, sin 3er slot (llega con el Game Pass), sin modo historia, sin móvil final, sin espectador/replays. Todo eso queda en el roadmap (sección 11) con los enchufes listos.

---

## 1. Concepto

El **Mayhem** es el torneo de portadores: las armas son reliquias nacidas del Rift y las arenas son fragmentos de mundos colapsados. No hay ejércitos ni hordas: hay dos portadores, un fragmento de arena, y una **carga de armas** que define quién sos dentro del ring.

El juego es un **duelo de armas 1v1 en vista cenital**: te movés libremente por una arena cerrada y apuntás con el mouse. Tu **portador** es mínimo (un sprite simple al inicio; las animaciones llegan después) — lo que define tu estilo de pelea es la **carga de armas**: antes del duelo equipás **2 armas** (la tercera llega con el **Mayhem Game Pass**) y en combate las intercambiás sobre la marcha. El arma activa te da ataque básico (M1) + habilidades (Q/E) + definitiva (R), y cada arma mantiene sus propios cooldowns: el dominio real es saber **cuándo cambiar y encadenar kits**. Próximamente también entran **poderes y elementos** que otorgan habilidades extra (ver sección 3.4).

**Loop de sesión:**
```
Login (Ocean Pay) → Misiones → Duelo 1v1 (best-of-3) → Recompensas (MC + maestría)
     ↑                                                        │
     └──────────────  desbloquear arma / cosmético  ←─────────┘
```

**Framing de contenido continuista:** se conservan los nombres y el lore de la era anterior — Distrito Nebula, Fosa Leviatán, Aegis Constructor, Prime Riftlord, el Lucky Boss — ahora como arenas, bots y cosméticos en vez de hordas.

---

## 2. Reglas de duelo (núcleo)

### 2.1 Estructura
| Regla | Valor |
|---|---|
| HP por ronda | 100 (sin respawn: caés y terminó la ronda) |
| Formato | Best-of-3 (primero en ganar 2 rondas) |
| Duración de ronda | Objetivo 45–75 s · timer duro 75 s |
| Fin de round | HP rival a 0 |
| Empate | No existe: al llegar el timer arranca **Overdrive** (ver 2.2) y sigue hasta que alguien caiga |
| Reset de ronda | HP 100, cooldowns completos, adrenalina 0, posiciones espejadas |

### 2.2 Overdrive (anti-turtle)
A los 75 s, la ronda entra en **Overdrive** de forma permanente:
- Daño de todos los ataques **×1.5**.
- Se activa el **hazard de la arena** (sección 4).
- HUD cambia a paleta roja + música acelera (feedback inequívoco).

### 2.3 Movimiento y feel (números línea base — a iterar en F0/F1)
| Parámetro | Valor | Nota |
|---|---|---|
| Tick de simulación | 60 Hz fijo | fixed-step, amigable con predicción |
| Velocidad | 320 px/s | aéreo no aplica (sin plataformas) |
| Colisión de personaje | círculo r=18 px | empuje suave entre jugadores |
| Dash (Shift/mantener) | 520 px/s por 0.18 s | i-frames 0.15 s · 1 carga · cd 5 s |
| Hitstop | 60 ms por impacto | el "punch" viene de acá |
| Knockback | 120 px/s cosmético | el KO es por HP, no por knockback (ver decisión abierta #2) |
| Fricción de frenado | decae a 0 en 0.15 s | control quirúrgico |

### 2.4 Ataques y cambio de arma
- **M1 (básico):** del **arma activa**. Melee 90 px de arco 120° → 12 dmg, cadencia 0.35 s. Armas a distancia: proyectil 14 dmg, cadencia 0.5 s.
- **Q / E (habilidades del arma activa):** Q cd 6 s · E cd 9 s · animación ~0.5 / 0.7 s (windup → active → recovery).
- **Cambio de arma (swap):** tecla **X** (o rueda del mouse) · 0.5 s de cambio · cada arma conserva **cooldowns independientes** (podés castear con una, cambiar, y seguir con la otra).
- **R (definitiva del arma activa):** consume el **medidor de Adrenalina** 0–100 (compartido por el portador). Se carga +8 por golpe dado, +5 por daño recibido, +25 por orbe de la Bóveda Dorada. Se resetea entre rondas.
- **Castigo de canalización:** si te golpean durante el windup de Q/E/R, el daño recibido es ×1.25. Las habilidades se castigan: usarlas mal duele.
- **Root parcial:** durante Q/E/R podés moverte al 40% (el juego mantiene ritmo; el castigo es de timing, no de inmovilidad total).
- **Cadenas de swap (la salsa):** ej. Chain Scythe E tira al rival → swap → Zeus Axe Q en el punto de caída. El diseño premia preparar el golpe con un arma y cobrarlo con la otra.

---

## 3. Arsenal — armas equipables (2 slots · 3 con Game Pass)

**Cómo funciona la carga:** antes del duelo armás tu loadout con **2 armas** (v1). Con el **Mayhem Game Pass** (futuro) se habilita el **3er slot**. Las armas de la carga están disponibles en combate con cooldowns independientes (swap con X): no hay arma "de reserva muerta" — la segunda siempre suma.

**Roster de lanzamiento (6 armas).** Cinco tienen arte y SFX ya producidos (en `_art-source/`); la Katana se produce mínima como arma inicial.

| # | Arma | Rol | Q | E | R (definitiva) | Arte |
|---|---|---|---|---|---|---|
| 1 | **Katana** | Duelista (starter, gratis) | Slash circular con stun 0.4 s | Dash-tajo con i-frames | Corte en 8 direcciones | A producir (mínimo) |
| 2 | **Tiger Gloves** | Rushdown | Zarpazo con salto-adelante | Ráfaga de 6 golpes | Rugido: stun + empuje en área | ✅ Listo |
| 3 | **Storm Guitar** | Zona / control | Acorde de Tormenta (onda + stun breve) | Solo eléctrico rebotante | Cataclismo multionda | ✅ Listo |
| 4 | **Solar Halberd** | Alcance / poke | Estocada solar (atraviesa) | Giro con escudo solar (corta proyectiles) | Pilar solar (zona de daño) | ✅ Listo |
| 5 | **Chain Scythe** | Trampero | Tajo espiral (atrae + ralentiza) | Lanzar cadena (marca zona, regresa) | Guadañas orbitales en ráfaga | ✅ Listo |
| 6 | **Zeus Axe** | Burst / ejecutor | Hachazo trueno (mini-stun) | Cadena voltaica rebotante | Tormenta: rayos en área | ✅ Listo |

**Daño referencial de habilidades:** Q 18–25 · E 22–30 · R 40–55. Exactos por arma en `WeaponDef` (ScriptableObject), ajustables sin tocar código.

**Temporada 1+ (roster completo a 13, ya definido):** Ion Pistols (poke a distancia), Mantis Blades (dps cuerpo a cuerpo), Volt Daggers (burst móvil), Mirage Rifle (zona con ecos holográficos), Nebula Glaive (control de espacio), Vortex Cannon (gravedad), Aether Pike (duelista híbrido).

**Regla de diseño (no se rompe):** ninguna arma tiene ventaja de stats; las diferencias son alcance, movilidad, control y timing. Todas desbloqueables jugando — ninguna exclusiva de pago.

**Cargas legales en v1:** cualquier par de armas distintas es válido. Los pares rotos se vigilan con telemetría y se ajustan por números antes que por prohibiciones.

### 3.4 Poderes y elementos (próximamente)

Después de v1, el portador suma una capa más: **Poderes** (1 slot) y **Elementos** (Fuego, Hielo, Tormenta, Rift).

- Un **Poder** otorga 1 habilidad activa extra (tecla F) y/o pasivas que modifican el comportamiento de tus armas.
- Un **Elemento** tiñe tus habilidades de arma (variantes de VFX + efectos: quemadura, ralentización, voltaje, empuje) — sin multiplicar el esfuerzo de arte: recolor + parámetros.
- Regla de balance: Poder/Elemento agrega **opciones**, no stats crudos; el daño total esperado por ronda no sube con la capa nueva.

---

## 4. Arenas v1 (3)

| Arena | Tema (lore viejo) | Layout | Hazard (solo en Overdrive) |
|---|---|---|---|
| **Chatarra Nebula** | Distrito Nebula | 4 coberturas giratorias + pilar central | Lluvia de escombros telegrafiada por sombras |
| **Fosa Leviatán** | Corazón Leviatán / Abyss | Anillo central elevado + fosa perimetral | Pulso abisal que electrifica el borde 1 s (telegrafiado) |
| **Bóveda Dorada** | Luck del Lucky Boss | Arena limpia + 4 pedestales | Lluvia de MayhemCoins: agarrar una da +25 adrenalina |

```
┌──────────────────────────────────────────────────┐
│   Arena jugable 1500×850 centrada en 1920×1080   │
│                                                  │
│    ▓▓▓▓          ╔══════╗           ▓▓▓▓         │
│    ▓▓▓▓    ····  ║ pilar║   ····    ▓▓▓▓         │
│            ····  ╚══════╝   ····                 │
│         ⌁⌁⌁⌁⌁⌁  [ zona hazard ]  ⌁⌁⌁⌁⌁⌁⌁          │
│  ═══════════════ muros sólidos ════════════════  │
└──────────────────────────────────────────────────┘
   ▓ cobertura  · espacio abierto  ⌁ zona de hazard
```

- **Sin hazards en la ronda 1** por defecto (aprendizaje); en custom se puede forzar.
- Las coberturas bloquean proyectiles y línea de visión: el duelo tiene esquinas y respiración.

---

## 5. Modos

### 5.1 Online 1v1 (v1, casual)
- Sala con **código de 5 caracteres** (mismo patrón que WildMind).
- Flujo: armar carga (2 armas) → arena (o aleatoria) → best-of-3 → resultado → **rematch 1-tap**.
- Sin matchmaking automático en v1 (cola simple en Fase 3 si la demanda aparece).

### 5.2 Local 1v1 (couch)
- **P1:** teclado + mouse. **P2:** gamepad twin-stick (modo recomendado).
- P2 por teclado (sin mouse): apuntado por dirección de movimiento (asistido) — ver decisión abierta #4.
- Pausa/selección con UI compartida (UI Toolkit).

### 5.3 Entrenamiento
- **Tutorial:** mover → dash → M1 → **swap de arma** → Q/E/R → cargar adrenalina → ganar una ronda contra bot Fácil.
- **Dummy:** HP infinito, muestra DPS del kit en tiempo real.
- **Bots (Fácil / Normal / Difícil):** 3 arquetipos simples (perseguidor, zoner, trapper). Los difíciles llevan skins de personajes de la era anterior (Aegis Constructor, Prime Riftlord) como guiño.

### 5.4 Controles
| Acción | P1 (teclado) | P2 (gamepad) | Táctil (1B) |
|---|---|---|---|
| Mover | WASD | stick izq | joystick |
| Apuntar | mouse | stick der | drag-to-aim |
| Ataque básico | Click izq (o mantener) | RT | botón A |
| Q / E | Q / E | LB / RB | botones B / C |
| Cambiar arma | X (o rueda) | Click LS / LT | botón dedicado |
| Dash | Shift o Espacio | B | botón D |
| Definitiva (R) | R | Y | botón E (aparece con adrenalina llena) |

---

## 6. Netcode (host-autoritativo, patrón Rumble/WildMind)

- **Simulación:** host a 60 Hz fixed-step. Los clientes mandan **inputs** (~30 Hz, incluyen el `swap` de arma); el host integra y difunde **snapshots** (20 Hz, arrays compactos `[id,x,y,angle,hp,state]`).
- **Interpolación:** clientes renderizan a `ahora − 100 ms`; el jugador propio además usa **predicción local** con reconciliación suave (15% por frame).
- **Eventos discretos** (hit, ult, KO, hazard) viajan inmediatos: los momentos importantes se sienten punchy aunque la posición interpole.
- **Relay:** `server.js` con prefijo `wildweapon:*` y guardia estricta: solo el host emite snapshots y resultados; los clientes solo emiten inputs. Mismo bloque passthrough que `wildmind:brawl-*`.
- **Ping visible** en HUD; si el ping supera ~300 ms sostenidos, la sala avisa y ofrece pausa.

| Caso borde | Comportamiento |
|---|---|
| El host se va | La sala se cierra con aviso; el ganador provisional se registra |
| Desconexión de un cliente | 15 s de gracia; luego pierde la ronda en curso |
| Lag spike severo | Pausa de 5 s + aviso a ambos |
| Trampa/desync de input | El host ignora inputs inválidos y mantiene su sim (cliente recalcula) |

> Fuera de v1: servidor dedicado autoritativo. La arquitectura deja los dos puntos de enchufe (input stream + snapshot stream) para migrar sin tocar gameplay.

---

## 7. Progresión y economía (NUEVA — sin gacha)

**Principios:**
1. Nada de poder comprable: el 100% del poder se juega, no se paga.
2. Una sola fuente de verdad cosmética, transferible solo por cuenta.
3. Todo el contenido se desbloquea jugando; el pago compra tiempo decorativo, no acceso.

### 7.1 Monedas
| Moneda | Origen | Usos |
|---|---|---|
| **MayhemCoins (MC)** — blanda | Victorias (60) · derrotas (25) · rachas · misiones · maestría | Armas T2/T3 (1.500 / 2.500 MC) · skins comunes (800) · emotes (300–600) |
| **Tides** — premium (vía Ocean Pay) | Compra directa | Mayhem Game Pass · skins épicas/míticas · packs de fundador |

### 7.2 Maestría de arma (1–20)
XP por ronda jugada con el arma (bonus por victoria). Recompensas **solo cosméticas**:

| Nivel | Recompensa |
|---|---|
| 3 | Emote del arma |
| 5 | Color alternativo A |
| 8 | Traza de proyectil/dash VFX |
| 12 | Color épico B |
| 16 | **Firma**: efecto de kill exclusivo del arma |
| 20 | Título de portador |

### 7.3 Temporadas (10 semanas) y Mayhem Game Pass
- **Serie de Duelos:** 5 placements → división: Bronce · Plata · Oro · Rift · **Mayhem**.
- Progresión por divisiones con recompensas por temporada (MC + banner + skin temática).
- **Mayhem Game Pass** (futuro, post-v1): habilita el **3er slot de arma** + track de cosméticos (track gratis + track Tides de 499). El cosmético es decorativo; el 3er slot es la promesa de valor principal del pase.
  > ⚠️ Balance: el 3er slot es una ventaja de opciones. Ver mitigación recomendada en decisión abierta #4 (también desbloqueable por mérito; el Game Pass lo entrega al instante).

### 7.4 Misiones
- 3 diarias (30–60 MC c/u): "ganá 2 duelos", "usá 5 definitivas", "ganá sin perder una ronda".
- 3 semanales (150 MC c/u): "probá 3 armas distintas", "ganá 10 duelos", "maestría +5 con un arma".

### 7.5 Legacy Founders (migración de la era Electron) — decisión abierta #6
Propuesta: los dueños históricos de los packs **Zeus Axe Founder** y **Tiger Gloves Premium** reciben: skin "Legacy" exclusiva de su arma + 2.000 MC + emote de fundador. No se pierde ningún privilegio percibido; se convierte en cosmético (el arma en sí será desbloqueable por todos, por la regla "sin exclusividad de poder").

### 7.6 Backend / Ocean Pay (Fase 3)
- Login unificado vía **Ocean Pay** (identidad central del ecosistema).
- Schema nuevo del juego (nombres tentativos): `ww_profiles`, `ww_inventory`, `ww_mastery`, `ww_matches`, `ww_season`. Los define servidor en Fase 3.
- **Los endpoints viejos de servidor** (`mayhemcoins` sync/change y la tienda de packs WildWeapon con Tides) quedan **deprecados** al salir v1: no se borran hasta que no queden instalaciones Electron activas (periodo de gracia) — ver sección 10.

---

## 8. Arte y audio

**Ya disponible (preservado en `WildWeapon Mayhem/_art-source/`):**
| Asset | Contenido | Uso en el nuevo juego |
|---|---|---|
| 5 armas completas | Spritesheets + frames de swing/slash/tajo + partículas (impact, glow, shockring, estelas) | Direccional de VFX en gameplay |
| SFX por arma | 4 variantes de ataque por arma (slash, woosh, blast, voltage…) | Sonido de golpes por arma |
| Presentation renders | 1 render por arma (calidad de ficha) | Selección de arma / tienda / rosters |
| Icono (`wildweaponmayhem.ico/png`) | Marca | App, OWS Store (ya referenciado) |

**A producir (Fase 0–1):**
| Asset | Spec | Nota |
|---|---|---|
| **Portador** (1 personaje base) | **v0: sprite simple (1–2 frames) para el prototipo** — las animaciones se producen después (F1+): 4 direcciones + flip · frame 256 px · 8 anims (idle, run, dash, M1, Q, E, R, hit/death) | Un solo personaje; skins por recolor + accesorios. Nada de esto bloquea F0 |
| 3 arenas | Tilesets 1920×1080 + props (coberturas, pilares) | Temas: Nebula / Abyss / Dorada |
| VFX genéricos | Impacto neutro, escudo, marcador de zona, indicador de hazard | Se combinan con los VFX de arma existentes |
| UI Toolkit | Menú, Arsenal (usa renders), HUD (HP, adrenalina, cooldowns **por arma**, indicador de arma activa), Resultados, Rank | Estándar del estudio |
| SFX UI/ambiente | Click, navegación, KO, ambiente por arena | Algunos reusables del ecosistema |

**Intensidad de VFX por rareza:** las armas comunes (Katana) usan VFX grisáceo sin glow; los acentos de color (cyan/magenta) se reservan a tiers superiores y el efecto firma a las épicas. El gameplay no cambia: solo el espectáculo visual acompaña la rareza.

**Regla técnica house (obligatoria):** los spritesheets se normalizan con el pipeline ImageMagick antes de importar a Unity (extent → crop por grilla → trim/extent centrado). No recortar frame a frame.

---

## 9. Tecnología y pipeline

- **Unity 6000 URP 2D.** UI 100% con **UI Toolkit**. Gameplay con sprites + física propia (sin Rigidbody en el duelo: el tick fixed-step manda).
- **Data-driven (ScriptableObjects):** `WeaponDef`, `AbilityDef`, `LoadoutDef` (2–3 slots), `ArenaDef`, `SeasonDef`, `CosmeticDef`, `BotDef`, `PowerDef`/`ElementDef` (ganchos futuros).
  → Agregar un arma nueva = crear 1 asset + meter VFX/SFX. Cero código de UI (patrón ya validado en WildSea: "añadir un Universo = 1 asset").
- **Escenas:** `Boot → MainMenu → Arsenal → Lobby → Arena → Results`.
- **Input System:** teclado/mouse, gamepad, táctil (fase 1B).
- **Determinismo amable:** sim 60 Hz fixed-step; nada de floats dependientes de framerate (preparado para predicción y, eventualmente, rollback).
- **Estructura del proyecto Unity (a bootstrapear en la carpeta existente):**
```
WildWeapon Mayhem/
├─ Assets/_WildWeapon/
│  ├─ Scenes/            (Boot, MainMenu, Arsenal, Lobby, Arena, Results)
│  ├─ Scripts/Core/      (sim, kits, rondas, Overdrive)
│  ├─ Scripts/Net/       (input stream, snapshots, predicción)
│  ├─ Scripts/UI/        (Toolkit controllers)
│  ├─ Data/              (WeaponDef, ArenaDef, …)
│  ├─ Art/  Audio/  UI/
├─ _art-source/          (arte crudo existente — fuera de Assets)
├─ build/                (iconos de release: wildweaponmayhem.ico)
└─ ICON_PROMPT.md · wildweaponmayhem.png
```
- **Build/release (Fase 4):** el flujo `scripts/release.ps1` actual asume Electron; para Unity se define en Fase 4 (referencia: `Wilder Gambit/build-windows.ps1`). Versionado estándar `YYYY.M.D-tHHMM`.

---

## 10. Integración con el ecosistema OWS

| Punto | Estado | Acción |
|---|---|---|
| Ficha OWS Store (`wildweapon-mayhem`) | Existe, estado `launched`, desc vieja | Al lanzar: bump de versión + descripción nueva + changelog por flujo de 2 pasos + noticia |
| Iconos de Store (`OWS Store/build/wildweaponmayhem.ico`, raw `.png` del proyecto) | Referenciados y preservados | Sin cambios |
| Repo de releases (`OceanandWild/wildweapon-mayhem`) | Contiene releases Electron históricos | Se reutiliza para el nuevo juego; los releases viejos quedan como histórico |
| `server.js` — economía vieja (mayhemcoins, packs Tides) | Activa | Fase 3: endpoints nuevos; Fase 4: deprecación con periodo de gracia |
| Backup (`scripts/backup-to-github.ps1`) | Operativo | Correr en WIP/release como siempre |
| Ficha "coming_soon" + noticia de rework | Antecedente ya publicado en su momento | Opcional ahora (decisión abierta #7) |

---

## 11. Roadmap por fases

| Fase | Contenido | Criterio de salida |
|---|---|---|
| **F0 — Prototipo local** (1–2 sem) | Arena gris, movimiento + dash, portador sprite simple, **swap de 2 armas** (Katana + arma gris), HP/rondas/Overdrive, local 2P | *"El duelo ya es divertido en gris"* |
| **F1 — Vertical slice** (4–6 sem) | 3 armas reales (Katana, Zeus Axe, Chain Scythe) con VFX/SFX existentes, 1 arena themed, bots, HUD + resultados | *"Se ve y suena a WildWeapon"* |
| **F2 — Online + contenido** (6–8 sem) | Relay `wildweapon:*`, salas con código, 6 armas, 3 arenas, balance pass v1 | *"10 duelos online sin bugs críticos"* |
| **F3 — Meta y economía** (4–6 sem) | Ocean Pay, MC/Tides, maestrías, misiones, temporada, tienda, Legacy Founders | *"Loop de sesión diaria completo"* |
| **F4 — Release** (2 sem) | Build Windows (+ Android eval), trailer, OWS Store bump + changelog, backup release | *"Publicado y detectado por la Store"* |

*(Estimaciones orientativas, no compromiso. Los gates son los criterios, no las fechas.)*

**Post-v1 (Temporada 1+):** poderes y elementos, 3er slot vía Mayhem Game Pass, ranked completo, 2v2 y espectador — los ganchos quedan en `LoadoutDef`/`PowerDef` desde F0.

---

## 12. Migración de la era Electron

La versión Electron fue **retirada del workspace** (2026-10-17) por decisión de producto: el nuevo juego la reemplaza por completo.

- **Eliminado:** `index.html` (juego completo), `main.js`, `preload.js`, `package.json*`, `scripts/stamp-version.js`, `build/installer.nsh`, `ai_trainer/`, `.netlify/`, `deploy.ps1`, `fix-taskbar-icon.ps1`, `.eslintrc.json`, `license_agreement.rtf`.
- **Preservado:** todo el arte y SFX (movido a `_art-source/`), `wildweaponmayhem.ico`, `wildweaponmayhem.png` (referenciado por OWS Store vía raw), `ICON_PROMPT.md`.
- **Recuperación:** el código eliminado vive en el historial de `owsdatabase` y en el repo `OceanandWild/wildweapon-mayhem`. Nada se perdió de forma irreversible.
- **Pendiente:** decidir qué hacer con los instaladores/releases Electron en GitHub (dejarlos como histórico es la recomendación) y con las instalaciones activas (periodo de gracia de la economía vieja).

---

## 13. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Netcode host-autoritativo percibido como injusto | v1 casual + ping visible; inputs/snapshots aislados para migrar a servidor dedicado sin tocar gameplay |
| Costo de arte del portador (anims × direcciones) | 1 personaje base + skins recolor; los VFX de armas son el 80% del impacto visual |
| Balance de kits | Datos 100% en ScriptableObjects + telemetría local (F1) + iteración sin builds de UI |
| Scope creep (2v2/ranked antes de tiempo) | Gates por fase firmes; F2 no abre nuevas features hasta pasar su criterio |
| Migración de economía (saldos/packs viejos) | Legacy Founders + periodo de gracia + endpoints viejos vivos hasta F4 |
| Dependencia de `server.js` (relay) | Patrón ya en producción (WildMind); fallback: partidas locales siempre jugables |

---

## 14. Decisiones abiertas

1. **Vista:** cenital (recomendada — reusa el 100% del arte existente y simplifica netcode) vs lateral de plataformas (estilo Rumble/Brawlhalla — cambiaría arte y netcode).
2. **Condición de muerte:** HP clásico (recomendado) vs barra porcentual con knockback tipo Smash.
3. **Esquema de la carga:** swap de arma activa (recomendado — un kit a la vez, cooldowns independientes, cadenas de swap) vs los dos kits vivos a la vez en teclas separadas (más opciones, más carga mental y más HUD).
4. **3er slot (Mayhem Game Pass):** dar por mérito además del pase (recomendado por balance) vs exclusivo del Game Pass.
5. **Pares de armas:** permitir cualquier combinación (recomendado) vs vetos puntuales si la telemetría detecta un par roto.
6. **Local 2P por teclado:** apuntado asistido para P2 (recomendado) vs teclado obliga a gamepad.
7. **Gacha:** fuera de v1 (recomendado); reevaluar como "Rituales" en v2 solo si la economía lo pide.
8. **Legacy:** aceptar propuesta de Legacy Founders (sección 7.5) vs otra compensación.
9. **OWS Store:** ¿marcar la ficha como `coming_soon` ahora con noticia de rework, o recién en F4?
10. **Ranked:** v2 (recomendado) vs adelantar la Serie de Duelos a v1.

---

*Este documento es la fuente de verdad de diseño del nuevo WildWeapon Mayhem. Todos los números son línea base: se validan en el prototipo F0 y se ajustan con telemetría en F1/F2 sin reescribir el diseño.*
