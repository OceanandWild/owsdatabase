# -*- coding: utf-8 -*-
"""
build_halloween_missions_tanda2.py — Tanda 2 del modal de MISIONES DE LA VELADA
-------------------------------------------------------------------------------
Procesa los JPG de la "Tanda 2" (bandas, pestañas, chips, chips de estado,
divisores y tira de ayuda) y los deja como PNG con alfa en
Assets/Resources/UI/Halloween/Missions/.

Pipeline (mismo corte de fondo que la Tanda 1, mas dos pasos nuevos):
  1. cut(): quita el fondo por bandas de luminancia/croma conectado al borde.
  2. Cuerpo del marco: se mide la fila donde el arte ocupa todo el ancho
     (el filete exterior). Todo lo que sobresale del filete *dentro de la
     zona central* (cresta del rail, gotas, púas, bultos) se recorta: en
     9-slice esa zona se estira en horizontal y un adorno con borde duro se
     convertiría en una mancha.
  3. Aplanado del filete (solo píldoras): en la zona central las filas del
     filete se copian de una franja limpia, así el filete queda continuo y
     el estirado no deja rastros.
  4. Inpaint (solo el pie): la luna tallada cuelga del filete hacia el
     interior; se rellena con el color del filete/interior vecino.
  5. Recorte al alfa, salida PNG en el proyecto + preview de inspección.

Uso:  python build_halloween_missions_tanda2.py
"""
import os
import shutil
import numpy as np
from PIL import Image, ImageDraw
from scipy import ndimage

from build_halloween_missions import cut  # mismo criterio de fondo que la Tanda 1

SRC = r"C:\Users\Equipo\Downloads\Tanda 2"
ARCHIVE = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\_art-source\Halloween\Missions"
OUT_DIR = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\Assets\Resources\UI\Halloween\Missions"
PREVIEW = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\Temp\t2_processed.png"

# slot -> parámetros.  L/R: ancho de las esquinas fijas (px del arte, adorno
# de punta incluido).  tol: margen de recorte sobre el filete.  flatten: el
# filete de la zona central se aplana.  inpaint: rectángulos a rellenar.
SLOTS = [
    dict(slot="hwm_topbar",      file="Fantasy_game_UI_band_frame_20261017140136_2.jpg", bands=[(0, 26, 10)], steps=6, erode=1, L=230, R=230, tol=3, flatten=False,
         top_ov=59, bot_ov=362),  # el plato oscuro de la cresta tapa el alfa del filete: se fija a mano
    dict(slot="hwm_hero",        file="Fantasy_game_UI_band_frame_20261017140136.jpg",   bands=[(0, 34, 18)], steps=6, erode=1, L=300, R=300, tol=3, flatten=False),
    dict(slot="hwm_footer",      file="Gothic_fantasy_UI_frame_banner_20261017140136.jpg", bands=[(0, 40, 20)], steps=6, erode=1, L=200, R=200, tol=3, flatten=False,
         inpaint=[dict(x_from="center", half=110, y_from="body", y_to=46, lum=110, dx=-160)]),
    dict(slot="hwm_hint_strip",  file="Fantasy_game_UI_frame_strip_20261017140136.jpg",  bands=[(0, 30, 12)], steps=6, erode=1, L=190, R=170, tol=3, flatten=False),
    dict(slot="hwm_tab_luna",    file="Fantasy_game_UI_button_plate_20261017140136_2.jpg", bands=[(0, 44, 14)], steps=6, erode=1, L=210, R=210, tol=3, flatten=True),
    dict(slot="hwm_tab_luna_on", file="Glowing_fantasy_game_UI_button_20261017140136.jpg", bands=[(0, 40, 20)], steps=6, erode=1, L=210, R=210, tol=3, flatten=True),
    dict(slot="hwm_tab_sangre",  file="Gothic_fantasy_game_UI_button_20261017140136.jpg", bands=[(0, 30, 12)], steps=6, erode=1, L=240, R=240, tol=3, flatten=True),
    dict(slot="hwm_tab_sangre_on", file="Fantasy_game_UI_button_plate_20261017140136.jpg", bands=[(0, 30, 12)], steps=6, erode=1, L=230, R=230, tol=3, flatten=True),
    dict(slot="hwm_chip_xp",     file="Fantasy_game_UI_stat_chip_20261017140136.jpg",    bands=[(0, 30, 12)], steps=6, erode=1, L=190, R=190, tol=3, flatten=True),
    dict(slot="hwm_chip_dulces", file="Fantasy_game_UI_stat_frame_20261017140136.jpg",   bands=[(0, 26, 12)], steps=6, erode=1, L=230, R=230, tol=3, flatten=True),
    dict(slot="hwm_state_chip",  file="Fantasy_game_UI_badge_frame_20261017140136.jpg",  bands=[(0, 30, 12)], steps=6, erode=1, L=230, R=190, tol=3, flatten=True),
    dict(slot="hwm_rule_luna",   file="Gothic_Halloween_ornamental_divider_20261017140136.jpg", bands=[(0, 26, 10)], steps=4, erode=1, L=180, R=190, tol=2, flatten=False),
    dict(slot="hwm_rule_sangre", file="Gothic_ornamental_divider_line_20261017140136.jpg", bands=[(0, 26, 10)], steps=4, erode=1, L=190, R=200, tol=2, flatten=False),
]


def rim_curves(mask, x0, x1, mid_deg=1, semi_deg=2, rej_mid=5.0, rej_semi=3.0):
    """Curvas del filete (borde superior e inferior) en la zona central.

    Se ajustan con rechazo la línea media del cuerpo (los adornos la mueven
    poco) y la semialtura.  Los adornos solo *agregan* alto, así que en la
    semialtura se rechaza únicamente hacia arriba: la cresta ancha del riel no
    arrastra la curva, pero la panza de las píldoras elípticas (que es casi
    cuadrática) sí se sigue."""
    h = mask.shape[0]
    xs = np.arange(x0, x1)
    any_col = mask[:, x0:x1].any(axis=0)
    top = np.where(any_col, np.argmax(mask[:, x0:x1], axis=0), h).astype(float)
    bot = np.where(any_col, h - 1 - np.argmax(mask[::-1, x0:x1], axis=0), 0).astype(float)

    mid = 0.5 * (top + bot)
    semi = 0.5 * (bot - top)

    # Ancla de la línea media: los adornos sobresalen hacia un lado, así que el
    # borde real está en el top más profundo y el bot más alto de la zona.
    mid0 = 0.5 * (float(top.max()) + float(bot.min()))
    semi0 = 0.5 * (float(bot.min()) - float(top.max()))

    # x centrada y escalada a [-1, 1]: con los valores crudos el ajuste queda
    # mal condicionado.
    c = 0.5 * (xs.min() + xs.max())
    s = max(1.0, 0.5 * (xs.max() - xs.min()))
    xn = (xs - c) / s

    coef_mid = np.polyfit(xn, mid, mid_deg)
    for r in (15.0, 10.0, 7.0, 5.0):
        keep = np.abs(mid - mid0) < r
        if keep.sum() < 32:
            break
        coef_mid = np.polyfit(xn[keep], mid[keep], mid_deg)

    # La semialtura sí varía con la panza de las píldoras (casi cuadrática), así
    # que se rechaza por residuo: los adornos solo agregan alto.
    coef_semi = np.polyfit(xn, semi, semi_deg)
    for r in (6.0, 3.0, 2.0):
        res = semi - np.polyval(coef_semi, xn)
        keep = res < r
        if keep.sum() < 64:
            break
        coef_semi = np.polyfit(xn[keep], semi[keep], semi_deg)

    mid_fit = np.polyval(coef_mid, xn)
    semi_fit = np.polyval(coef_semi, xn) + 0.02 * semi0 + 1.0
    return xs, mid_fit - semi_fit, mid_fit + semi_fit


def rim_inner(plate, ref_x, top, bot):
    """Borde interior del filete, medido en la columna ref_x (el filete es
    brillante y el interior es oscuro)."""
    a = np.asarray(plate)[:, :, :3].astype(int)
    h = a.shape[0]
    top = max(0, min(h - 1, top))
    bot = max(top + 1, min(h, bot))
    lum = a[:, ref_x, :].max(axis=1)
    thr = 0.45 * lum[top:bot].max()
    inner_top = top
    while inner_top < bot and lum[inner_top] >= thr:
        inner_top += 1
    inner_bot = bot - 1
    while inner_bot > top and lum[inner_bot] >= thr:
        inner_bot -= 1
    return inner_top, inner_bot + 1


def clip_zone(plate, xs, top, bot, tol):
    """Recorta el alfa fuera de la curva del filete, solo en la zona central
    (la que el 9-slice estira o comprime): un adorno con borde duro se
    convertiría en una mancha."""
    a = np.asarray(plate).copy()
    h = a.shape[0]
    for i, x in enumerate(xs):
        y0 = max(0, int(round(top[i])) - tol)
        y1 = min(h, int(round(bot[i])) + tol + 1)
        a[:y0, x, 3] = 0
        a[y1:, x, 3] = 0
    return Image.fromarray(a)


def flatten_rim(plate, xs, top, bot, frac=0.30):
    """Aplana el filete de la zona central siguiendo su curva: se calcula un
    perfil mediano (la mediana por fila relativa sobre todas las columnas de la
    zona, así los adornos puntuales se diluyen) y se copia en cada columna.  En
    9-slice la zona central se comprime mucho y el patrón del filete se
    ensuciaría.  La banda cubre una fracción fija del alto: ese mismo valor va
    como slice vertical en el C#, así lo que se comprime es la franja aplanada."""
    a = np.asarray(plate).copy()
    h = a.shape[0]
    thick_t = max(1, int(round(frac * float(np.median(bot - top)))))

    tops, bots = [], []
    for i, x in enumerate(xs):
        yt = int(round(top[i]))
        yb = int(round(bot[i]))
        if 0 <= yt and yt + thick_t <= h:
            tops.append(a[yt:yt + thick_t, x, :])
        if 0 <= yb - thick_t and yb <= h:
            bots.append(a[yb - thick_t:yb, x, :])
    prof_t = np.median(np.stack(tops), axis=0) if tops else None
    prof_b = np.median(np.stack(bots), axis=0) if bots else None

    for i, x in enumerate(xs):
        yt = int(round(top[i]))
        yb = int(round(bot[i]))
        if prof_t is not None:
            ya, yb2 = max(0, yt), min(h, yt + thick_t)
            if yb2 > ya:
                sa = ya - yt
                a[ya:yb2, x, :] = prof_t[sa:sa + (yb2 - ya), :]
        if prof_b is not None:
            ya, yb2 = max(0, yb - thick_t), min(h, yb)
            if yb2 > ya:
                sa = ya - (yb - thick_t)
                a[ya:yb2, x, :] = prof_b[sa:sa + (yb2 - ya), :]
    return Image.fromarray(a)


def inpaint_bright(plate, half, y_from, y_to, lum_thr, dx):
    """Rellena un adorno brillante que cuelga del filete hacia el interior
    (la luna del pie), copiando color desde la izquierda del rectángulo."""
    a = np.asarray(plate).copy()
    h, w = a.shape[:2]
    cx = w // 2
    x0, x1 = max(0, cx - half), min(w, cx + half)
    y0, y1 = max(0, y_from), min(h, y_to)
    sub = a[y0:y1, x0:x1, :3].astype(int)
    m = sub.max(axis=2) > lum_thr
    if not m.any():
        return plate
    m = ndimage.binary_dilation(m, iterations=3)
    xs = np.arange(x0, x1)
    for i, y in enumerate(range(y0, y1)):
        row = m[i]
        if not row.any():
            continue
        src = np.clip(xs[row] + dx, 0, w - 1)
        a[y, xs[row]] = a[y, src]
    return Image.fromarray(a)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ARCHIVE, exist_ok=True)
    tiles = []

    for cfg in SLOTS:
        slot = cfg["slot"]
        path = os.path.join(SRC, cfg["file"])
        plate, bbox = cut(path, cfg["bands"], cfg["steps"], cfg["erode"])

        m = np.asarray(plate)[:, :, 3] > 16
        x0, x1 = cfg["L"], plate.width - cfg["R"]
        xs, top, bot = rim_curves(m, x0, x1)
        if "top_ov" in cfg:
            top = np.full(len(xs), float(cfg["top_ov"]))
        if "bot_ov" in cfg:
            bot = np.full(len(xs), float(cfg["bot_ov"]))
        print("%-18s %-52s cortado %4dx%-4d  filete zona %4d..%4d  curva y %5.1f..%5.1f / %5.1f..%5.1f"
              % (slot, cfg["file"][:52], plate.width, plate.height, x0, x1,
                 top.min(), top.max(), bot.min(), bot.max()))

        plate = clip_zone(plate, xs, top, bot, cfg["tol"])
        if cfg["flatten"]:
            plate = flatten_rim(plate, xs, top, bot)
        for ip in cfg.get("inpaint", []):
            plate = inpaint_bright(plate, ip["half"], int(top.min()), ip["y_to"], ip["lum"], ip["dx"])

        # recorte final al alfa
        mask = plate.getchannel("A").point(lambda v: 255 if v > 16 else 0)
        box = mask.getbbox()
        plate = plate.crop(box)

        out = os.path.join(OUT_DIR, slot + ".png")
        plate.save(out)
        shutil.copy2(path, os.path.join(ARCHIVE, cfg["file"]))
        print("      -> %-4dx%-4d  %s" % (plate.width, plate.height, out))

        img = Image.new("RGBA", plate.size, (18, 8, 36, 255))
        img.alpha_composite(plate)
        img = img.convert("RGB")
        sc = min(1.0, 960.0 / img.width, 260.0 / img.height)
        img = img.resize((max(1, int(img.width * sc)), max(1, int(img.height * sc))), Image.LANCZOS)
        tile = Image.new("RGB", (980, 300), (8, 8, 12))
        tile.paste(img, ((980 - img.width) // 2, 34))
        d = ImageDraw.Draw(tile)
        d.text((8, 8), "%s  %dx%d   L/R %d/%d" % (slot, plate.width, plate.height, cfg["L"], cfg["R"]),
               fill=(255, 255, 0))
        tiles.append(tile)

    cols = 2
    rows = (len(tiles) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * 980, rows * 300), (8, 8, 12))
    for i, t in enumerate(tiles):
        sheet.paste(t, ((i % cols) * 980, (i // cols) * 300))
    sheet.save(PREVIEW)
    print(PREVIEW, sheet.size)


if __name__ == "__main__":
    main()
