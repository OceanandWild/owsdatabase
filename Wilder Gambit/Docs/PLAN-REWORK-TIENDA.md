# PLAN 2 — Rework visual de la tienda (SOLO VISUAL) · v2

> **Estado: IMPLEMENTADO (V1–V6 código).** Pendiente solo QA visual en el editor Unity
> (capturas antes/después en 1280×720 y 1920×1080) — no hay Unity disponible en esta máquina.
> Notas de implementación al final del documento.

> **Layout nuevo (v2, sustituye al split rail + stage):**
> **barra superior con tabs scrolleables** de todas las categorías + **grid de cards a la
> izquierda** + **panel de detalle a la derecha que solo existe cuando hay selección**.
>
> **Restricción dura:** **cero cambios de lógica de negocio**. No se tocan precios,
> propiedad, Surface ni flujos de compra. Los únicos cambios de código permitidos son
> *bindings* de clases/estados (`AddToClassList`/`RemoveFromClassList` y callbacks de
> selección) en `ShopModal.cs`.

Archivos: `Assets/_Project/UI/MainMenu.uxml` (`shop-modal-view`), `Assets/_Project/UI/MainMenu.uss`
(bloque `shop2-*`), bindings mínimos en `Scripts/UI/ShopModal.cs`, y un sprite nuevo:
`Wilder Gambit - Lock.png` → `Assets/_Project/Textures/UI/shop_lock.png` (copia desde
`C:\Users\Equipo\Downloads\Wilder Gambit - Lock.png`; es un candado dorado con grabados
de ajedrez, transparente — identidad Atelier).

---

## 1. Layout objetivo

```
┌────────────────────────────────────────────────────────────────────┐
│ ← VOLVER   ATELIER · COLECCIÓN                [◈ 61,18K][♔ 0]  👤 │  ← topbar fija
├────────────────────────────────────────────────────────────────────┤
│ TABLEROS │ ANIMACIONES🔒 │ FONDOS🔒 │ VARIANTES🔒 │ PIEZAS🔒 │ ... │  ← tabs scrolleables
├────────────────────────────────────────────────────────────────────┤
│ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐            │
│ │      │ │      │ │      │ │      │ │      │ │      │            │
│ │ img  │ │ img  │ │ img  │ │ img  │ │ img  │ │ img  │            │
│ │      │ │      │ │      │ │      │ │      │ │      │            │
│ ├──────┤ ├──────┤ ├──────┤ ├──────┤ ├──────┤ ├──────┤            │
│ │Nombre│ │Nombre│ │Nombre│ │Nombre│ │Nombre│ │Nombre│            │
│ │ 500G │ │ 650G │ │ ...  │ │ ...  │ │ ...  │ │ ...  │            │
│ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘            │
│   GRID A ANCHO COMPLETO (sin panel → sin espacio muerto)          │
└────────────────────────────────────────────────────────────────────┘

Al hacer clic en una card:

│ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐  │ ▓▓ VISTA PREVIA GRANDE ▓▓ │
│ │ ...  │ │ ...  │ │ ...  │ │ ...  │  │ Fuego Volcánico           │
│ └──────┘ └──────┘ └──────┘ └──────┘  │ RARA · Tablero             │
│ ┌──────┐ ┌──────┐                    │ Haz clic en EQUIPAR…       │
│ │ ...  │ │ ...  │   ← grid ~62%      │ [precio]   [EQUIPAR]       │
│ └──────┘ └──────┘                    │ ◈ lore / detalles extra    │
                                       │  PANEL DERECHO ~38%        │
```

- **Cards**: rectangulares verticales (formato ~4:5, p. ej. 168×208 px): imagen arriba,
  nombre y precio abajo, en dos líneas fijas. Hover: elevación + barrido de brillo.
- **Panel detalle**: **no se instancia en el layout hasta que se seleccione una card**
  (grid a ancho completo mientras tanto). Contenido: preview grande, nombre, rareza con
  línea de color, descripción/flavor, precio y CTA (EQUIPAR/COMPRAR), + info extra de la
  card seleccionada.
- **Topbar**: back, marca (`ATELIER · COLECCIÓN`), bóveda (Gambits destacado) y usuario.
  Los chips `shop-tides-label` / `shop-gambits-label` mantienen sus `name` actuales.

## 2. Tabs superiores

| # | Tab | Estado |
|---|-----|--------|
| 01 | **TABLEROS** | ✅ activo, con contenido (10 tableros de `ShopBackgroundSelector`) |
| 02 | **ANIMACIONES** | 🔒 gris + candado (sin contenido aún) |
| 03 | **FONDOS** | 🔒 gris + candado |
| 04 | **VARIANTES DE PIEZAS** | 🔒 gris + candado |
| 05 | **PIEZAS** | 🔒 gris + candado |
| 06 | **PAQUETES** | ✅ activo desde la ronda de paquetes (10 ofertas de Gambits por Tides, ver §11) |

- Contenedor con `ScrollView mode="Horizontal"` → **scrolleable** si no caben (scroll
  suave con rueda/gamepad, scrollbar oculto o fino).
- Tab activo: fondo oro tenue + subrayado de 2px + contador de ítems.
- Tab bloqueado: **gris** (texto `#6b7488`, fondo plano, sin hover), **candado**
  (`shop_lock.png`, ~14px, tinte gris) junto al nombre, **no responde al clic** (solo
  muestra un tooltip/estado "Próximamente" opcional).
- Cuando una categoría reciba contenido (Plan 1), pasar a activa = quitar candado y
  contador real: es 1 clase CSS + 1 línea de contador.

## 3. Animación del panel derecho (sutil)

- **Abrir** (seleccionar card): el panel entra con `opacity 0→1` +
  `translate: 16px→0` en **0.25 s ease-out**; el contenido interior escalona
  (preview → título → info → CTA, 40 ms de diferencia, reutilizando el patrón
  `PlayStagger` del menú).
- **Colapsar** (deseleccionar / clic en otra zona): `opacity 1→0` + `translate 0→12px`
  en **0.18 s** y **solo entonces** se retira del layout (`schedule.Execute` al terminar,
  mismo patrón que `HideModalWithFade`) → el grid recupera el ancho.
- **Reflow del grid**: cambio de `flex-grow` (62/38 ↔ 100/0). **Sin transición de
  `width`** (UI Toolkit no la soporta de forma fiable): el reflow es instantáneo y lo
  disimula la entrada/salida del panel; si se ve brusco, alternativa = panel
  *posicionado absoluto* encima del borde derecho con sombra simulada (decisión en V3).
- Cambiar de card seleccionada: el panel **no** se colapsa; solo hace cross-fade de su
  contenido (0.15 s) para no parpadear.

## 4. Estados y ambiente

- **Skeleton** (cargando sesión): grid con 6 cards fantasma shimmer + topbar ya visible
  (sustituye a la card suelta "Verificando sesión guardada…" de la captura actual).
- **Vacío / error / offline**: se mantiene la lógica actual pero con la estructura nueva
  (ilustración tipográfica + copy centrado en la zona del grid).
- **Login**: la card de login pasa al centro del área del grid.
- **Ambiente**: brasas sutiles (~40 % de densidad del menú, mismo sistema reworkeado)
  detrás del grid + vignette tenue; hereda la identidad fuego/brasa del juego.
- **Movimiento**: apertura de la ventana `opacity + scale 0.98→1` (0.25 s), stagger de
  cards al cambiar de tab, hover 0.18 s. Todo pausable con *Reducir movimiento*.

## 5. Accesibilidad / consistencia
- Tabs y cards navegables con gamepad/teclado: foco = anillo dorado (ya patrón en el menú).
- Contraste AA (`#6b7488` solo sobre fondos claros; sobre `#0c152b` subir a `#8a9bb5`).
- Precios siempre en la misma píldora dorada; rareza siempre con su línea de color.
- Una sola familia tipográfica, tamaños ya usados (10/11/12/13/30).

## 6. Fases

| Fase | Contenido | Esfuerzo |
|---|---|---|
| V1 | Importar `shop_lock.png`, tokens, **reestructurar UXML**: rail → topbar + tabs scrolleables (manteniendo todos los `name` que consulta `ShopModal`) | 1 día |
| V2 | Grid de cards (formato 4:5, estados: hover/selected/owned/equipado) + skeleton | 1 día |
| V3 | Panel detalle + animación abrir/collapsar + reflow del grid + cross-fade al cambiar de card | 1 día |
| V4 | Tabs bloqueados grises con candado + lógica de "no clickeable" (solo clase) | 0,5 día |
| V5 | Ambiente: brasas sutiles, vignette, apertura, stagger de tabs/cards | 0,5 día |
| V6 | QA visual: capturas antes/después, 1280×720 y 1920×1080, gamepad, *Reducir movimiento* | 0,5 día |

**Total: ~4,5 días.**

## 7. Criterios de aceptación
1. Sin selección: **cero espacio reservado** para el panel (grid a ancho completo).
2. Con selección: panel entra con la animación sutil y ofrece preview + info + CTA.
3. Tabs vacíos: grises con candado dorado y no clickeables.
4. El scroll de tabs funciona con ratón y gamepad sin scrollbar feo.
5. Diff de `ShopModal.cs` limitado a clases/estados y callbacks de selección (nada de
   precios/propiedad/Surface).
6. 60 fps al recorrer el grid; transiciones solo sobre `opacity`/`translate`/`scale`/
   `background-color`/`border-color`.

## 8. Riesgos
- **`ShopModal.cs` consulta muchos `name`/clases del layout viejo** → inventario de
  nombres antes de tocar el UXML (fase V1) para no romper la lógica existente.
- UI Toolkit sin `box-shadow` → profundidad con doble borde + degradados.
- Reflow sin transición de ancho → alternativa absoluta descrita en §3.
- Conflicto con Plan 1 (mismos archivos) → este plan va primero; Plan 1 se adapta al
  nuevo layout en su Fase 4.

## 9. Notas de implementación (hecho)
- **UXML**: rail → `shop2-topbar` + `shop2-tabs-bar` (ScrollView horizontal con 6 tabs:
  TABLEROS activo; ANIMACIONES/FONDOS/VARIANTES/PIEZAS/PAQUETES con `shop2-tab-locked` +
  `picking-mode="Ignore"` y candado `shop_lock.png`) + `shop2-body` (`shop2-catalog` +
  `shop2-detail`). El hero (`bg-preview-panel`) se movió al panel de detalle; todos los
  `name` consultados por `ShopModal`/`ShopBackgroundSelector` se conservaron.
- **USS**: `.shop2-window` a columna; bloques nuevos de topbar/tabs/body/detail/skeleton;
  cards 176×210 con precio en píldora y estado `bg-card-selected`; CTA de las cards movido
  al panel; responsive ≤900px reescrito (detail pasa debajo del grid).
- **C#** (solo bindings/estados): `ShopBackgroundSelector` — clic en card →
  `SelectCard` (abre panel), clic repetido → `CloseDetail` (colapsa), page-change/tab
  refrescan cierran el panel; `UpdateDetail` rellena precio/estado/lore/CTA;
  `ShopModal.OnShopOpened/Closed` inicia/para `ShopEmberField`.
- **Nuevo**: `Scripts/UI/ShopEmberField.cs` — brasas sutiles (18 partículas, ~40% de la
  densidad del menú) animadas con el scheduler del panel.
- **Candado**: `C:\Users\Equipo\Downloads\Wilder Gambit - Lock.png` copiado y reducido a
  160px en `Assets/_Project/Textures/UI/shop_lock.png` (el .meta lo genera Unity al abrir).
- **QA pendiente en editor**: apertura de tienda, clic en card (anima panel), clic
  repetido (colapsa), cambio de página (colapsa), tabs bloqueados no clickeables,
  skeleton durante “Verificando sesión…”, login/loading acotados al catálogo, brasas.
- **Corrección post-QA (r2)**: `shop2-detail` estaba fuera de `shop2-body` (se apilaba en
  la ventana vertical, colapsaba el catálogo y dejaba las flechas del scrollbar flotando
  junto a un hueco) → movido dentro de `shop2-body` como segundo hijo. Compactación:
  `.shop2-connected { justify-content: center }` + `.shop2-grid-scroll { flex-grow: 0;
  flex-shrink: 1; min-height: 0 }` (poco contenido = bloque centrado y compacto; mucho =
  rellena y scroll interno igual que antes), scrollbar vertical atenuado (flechas al 30%),
  y panel de detalle compactado (hero 196px, padding 14px, contenido apilado arriba sin
  hueco muerto debajo).

## 10. La tienda ya NO equipa (equipar vive en el INVENTARIO)

Regla del juego a partir de esta ronda: **la tienda vende, el inventario equipa**. La tienda
conserva el catálogo, la vista previa y la compra; poner algo en juego solo se hace desde
`InventoryModal` (botón girado INVENTARIO del menú).

- **`ShopBackgroundSelector`**: `OnDetailAction` solo compra (`if (IsThemeUnlocked(index)) return;`),
  `OnBuyAndEquip` ya no equipa (desbloquea y refresca catálogo/detalle) y se retiró el viejo
  `OnEquip`. El CTA queda: `✓ EN USO` (activo, apagado) · `✔ EN TU INVENTARIO` (comprado,
  apagado) · `🔓 COMPRAR — N GAMBITS` · `NECESITAS N GAMBITS`. El texto de la ficha dice dónde se
  equipa y el hero de la vista previa también.
- **`ShopVariantSelector`**: la carta comprada ya no lleva botón EQUIPAR sino el rótulo
  `✔ EN EL INVENTARIO`; `OnAction` solo compra, y `FillDetail` informa de que se equipa desde
  el inventario. El campo `equip` de `VariantItem` se eliminó (nadie lo llamaba).
- **Propiedad de tableros**: `ThemePrices`, `IsUnlocked`, `Unlock` y `UnlockedCount` se movieron
  a `BoardBackgroundManager` (una sola fuente); `ShopBackgroundSelector` los reutiliza, así que
  los precios ya no están duplicados.
- **Fondos y tableros cosméticos**: los dos catálogos se cobran en Gambits, con precios bajos
  (100–400) y sin rareza. La rareza del Atelier queda solo para skins, variantes y animaciones.
- **Enciclopedia y skins**: `YourPiecesModal` conserva el catálogo y la enciclopedia, pero sus
  botones de variante quedan desactivados y **rotulados con el estado** (`✅ EN USO` /
  `✔ EN EL INVENTARIO` / `🔒 400 G EN TIENDA`); nunca equipan. Comprar una skin tampoco la pone
  (antes se equipaba sola) y el saldo se refresca en `GambitProgress.NotifyChanged()`.
- **Lo que comprueba QA**: al comprar un tablero o una variante, el estado pasa a «EN EL
  INVENTARIO» sin cambiar nada en juego; el fondo del menú solo cambia al equiparlo desde el
  inventario (`ApplyMainMenuBackground` se refresca por callback).

## 11. Pestaña PAQUETES — Gambits por Tides (nuevo)

Activa desde esta ronda: vende **Gambits a cambio de Tides** en 10 tramos con
bonus escalonado (Puñado 100 G/60 T → Fortuna 15000 G/5200 T; la tasa mejora en
cada tramo). Detalle del catálogo y de la compra en `Docs/PROMPTS-PAQUETES-GAMBITS.md`
(precios, tasa y sprites `gambit_pack_01..10`).

- **Código (solo bindings/estados + catálogo nuevo, sin tocar precios ni Surface
  existentes)**: `Scripts/UI/ShopPackSelector.cs` (espejo de `ShopVariantSelector`:
  mismo `ShopGridPager`, mismas cards `.bg-card`, mismo panel `shop2-detail`
  marcado con `detail-showing-pack`); `ShopModal.cs` lo cablea como tercera
  pestaña (crea el selector en `OnShopOpened`, lo atiende en `SelectTab` y
  `RefreshActiveCatalog`, y refresca ambos chips de la bóveda con
  `RefreshVaultChips`); `tab-packs` en `MainMenu.uxml` pasa a activo con contador 10.
- **Compra**: cobra Tides (`CurrentUser.tides` + `PlayerPrefs["PlayerTides"]`) y
  abona Gambits al instante (`PieceSkinManager.AddLocalGambits` + `GambitProgress`).
- **QA en editor**: abrir PAQUETES (10 cards, paginación si no caben), clic en card
  (abre detalle con «TIDES → GAMBITS»), comprar (bajan Tides, suben Gambits, chips
  con flash), sin saldo (CTA apagado «NECESITAS N TIDES»), cambiar de pestaña
  (el detalle no cruza marcas: `ClearSharedDetailMarkers`).

## 12. Carrito del Atelier (compra múltiple en un solo checkout)

La tienda suma un carrito para juntar varios artículos y pagarlos en una sola
operación de Surface. El flujo directo de cada ficha sigue vivo: el carrito es una
segunda vía, no un reemplazo.

- **Modelo** (`Scripts/UI/ShopCart.cs`): `ShopCart` guarda líneas en memoria con
  producto, nombre, precio, divisa, arte, comprobación de propiedad y acción de
  entrega. Valida duplicados y **una sola divisa por checkout** (Surface cobra una
  moneda por request), calcula el total y arma el nombre/descripción que recibe
  Surface. `PruneOwned()` quita lo que ya entró al inventario por otra vía.
- **UI** (`Scripts/UI/ShopCartUI.cs` + UXML/USS): botón CARRITO con contador en el
  topbar, CTA secundario `+ AÑADIR AL CARRITO` en el panel de detalle compartido y
  overlay con miniatura, nombre, tipo, precio y botón de quitar por línea. El pago
  abre un único checkout de Surface con un producto sintético
  (`wilder-gambit-cart-<ticks>`); el botón se apaga sin sesión y se reactiva al
  iniciar sesión.
- **Entrega**: al confirmarse el cobro se entrega todo (`grant` de cada línea) y se
  descuenta el total en la divisa del carrito. Los tableros y variantes entran al
  inventario, los fondos se desbloquean y aplican al menú, y skins/animaciones
  quedan en propiedad. Un fallo o cancelación deja el carrito intacto.
- **Persistencia y limpieza**: el carrito vive con `ShopModal`, así que sobrevive a
  cerrar/reabrir la tienda. Se depura al abrir el overlay, antes de pagar y cuando
  una compra directa desbloquea el mismo artículo (`BalanceChanged` →
  `OnStoreBalanceChanged`), evitando el doble cobro.
- **Ruteo por pestaña**: `ShopBackgroundSelector`, `ShopBackdropSelector`,
  `ShopVariantSelector`, `ShopSkinSelector` y `ShopAnimationSelector` implementan
  `IShopCartSource`; `ShopModal` fija la fuente activa en `SelectTab` y rutea
  `btn-detail-cart`. Cada selector calcula su precio final (incluida la oferta de
  Halloween de las variantes) al agregar.
- **QA en editor (verificado)**: agregar dos artículos con el botón real del detalle
  (badge 1→2, toast con el nombre, CTA pasa a «✓ EN EL CARRITO»), carrito con
  miniatura/nombre/tipo/precio por línea, total correcto, quitar con el botón ✕,
  mezcla de divisas rechazada con aviso («El carrito está en Gambits…»), carrito
  intacto al cerrar/reabrir la tienda, y checkout de Surface abierto con el producto
  sintético (`wilder-gambit-cart-…`, total y divisa correctos, etapa Review con saldo
  y topes OK) y cancelación sin tocar el carrito. Sin errores de compilación, UXML ni
  USS (solo avisos previos de `PauseMenu` y `SurfacePreviewCapture`).
- **Corrección post-QA (r1)**: el CTA del carrito se calculaba con
  `shop2-detail-open`, clase que el panel aplica un frame después de mostrarse; en la
  primera selección de cada pestaña el botón quedaba oculto. Ahora la condición es
  «panel no oculto + marca de la pestaña», tanto para pintar el botón como para
  aceptar el artículo. Además, la descripción que viaja a Surface se acota a 240
  caracteres (el mismo límite del servidor) para no cortar a mitad de palabra.
