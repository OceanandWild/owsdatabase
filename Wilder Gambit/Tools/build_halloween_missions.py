# -*- coding: utf-8 -*-
"""
build_halloween_missions.py — Tanda 1 del modal de MISIONES DE LA VELADA
-----------------------------------------------------------------------
Procesa los JPG generados por IA (fondo negro o gris oscuro) de la
"Tanda 1 - Modales" y los deja como PNG con alfa listos para Unity, en
Assets/Resources/UI/Halloween/Missions/.

Pipeline (mismo criterio que build_halloween_chips.py):
  1. Flood-fill del fondo desde los bordes, con umbral de semilla y de
     crecimiento POR IMAGEN (varias generaciones salieron con fondo gris
     #1f2024..#383838 en lugar de negro puro).
  2. Defringe: erosion de 1 px del alfa + desenfoque leve (0.6 px).
  3. Recorte al contenido (bbox del alfa).
  4. Normalizacion al canvas de destino (alto fijo, ancho segun aspect
     natural para no deformar el ornato) con LANCZOS.
  5. Salida: PNG en el proyecto + previews de inspeccion.

Uso:  python build_halloween_missions.py
"""
import os
import shutil
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
from scipy import ndimage

SRC = r"C:\Users\Equipo\Downloads\Tanda 1 - Modales"
ARCHIVE = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\_art-source\Halloween\Missions"
OUT_DIR = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\Assets\Resources\UI\Halloween\Missions"

# slot -> (prefijo, excluir _2, alto de canvas, bandas de fondo, pasos, erode)
# El fondo de cada generacion se midio sobre el anillo exterior y sobre el
# centro del marco: no hay un umbral unico (negro puro, negro con vineteado,
# gris #1f2024..#383838, violeta oscuro y sombra propia debajo del marco).
# Cada banda es (lum_min, lum_max, chroma_max): el fondo es la union.
SLOTS = [
    ("hwm_window",       "Fantasy_game_UI_window_frame",     False, 1230, [(0, 46, 13)],            4, 1),
    ("hwm_card_luna",    "Fantasy_game_UI_frame_border",     False,  172, [(0, 34, 11)],            4, 1),
    ("hwm_card_sangre",  "Gothic_halloween_game_UI_frame",   False,  172, [(0, 16, 11)],            3, 1),
    ("hwm_card_premium", "Fantasy_game_UI_row_frame",        False,  172, [(44, 255, 10), (0, 42, 16)], 2, 2),
    ("hwm_card_ready",   "Fantasy_game_UI_frame_glowing",    False,  172, [(0, 30, 12)],            0, 1),
    ("hwm_card_claimed", "Fantasy_game_UI_frame_design",     False,  172, [(45, 255, 16), (0, 26, 12)], 0, 2),
    ("hwm_card_locked",  "Locked_fantasy_game_UI_card",      False,  172, [(0, 30, 16)],            1, 1),
    ("hwm_banner",       "Fantasy_game_UI_banner_plate",     True,   128, [(0, 40, 16)],            3, 1),
    ("hwm_banner_open",  "Fantasy_game_UI_banner_plate",     False,  128, [(0, 40, 16)],            3, 1),
    ("hwm_claim",        "Fantasy_game_UI_button_plate",     False,   64, [(0, 80, 14)],            0, 2),
    ("hwm_empty_moon",   "Halloween_chessboard_and_candles", False,  768, [(0, 14, 8)],             4, 1),
    ("hwm_crest",        "Chess_tower_and_crescent_moon",    False,  320, [(0, 46, 34)],            2, 1),
]

# ancho forzado (si el aspect natural no se quiere): None = aspect natural
FORCE_W = {
    # los cuatro marcos de tarjeta comparten ancho para que el 9-slice
    # del codigo use las mismas fracciones
    "hwm_card_luna": 2048,
    "hwm_card_sangre": 2048,
    "hwm_card_premium": 2048,
    "hwm_card_ready": 2048,
    "hwm_card_claimed": 2048,
    "hwm_card_locked": 2048,
    "hwm_banner": 2048,
    "hwm_banner_open": 2048,
}


def find_file(prefix, second):
    hits = []
    for name in os.listdir(SRC):
        if not name.lower().endswith((".jpg", ".png", ".jpeg")):
            continue
        if not name.startswith(prefix):
            continue
        is_second = os.path.splitext(name)[0].endswith("_2")
        if is_second != second:
            continue
        hits.append(name)
    if len(hits) != 1:
        raise RuntimeError("origen ambiguo para %s: %s" % (prefix, hits))
    return os.path.join(SRC, hits[0])


def cut(path, bands, steps, erode):
    """Recorta el fondo: region DEL RANGO DE FONDO conectada al borde.

    El fondo se define por bandas de luminancia + croma bajo (el arte de esta
    tanda es violeta/carmesi/ambar saturado y brillante), y solo se quita si
    la region toca el borde de la imagen: los interiores de los marcos quedan
    encerrados por el filete y sobreviven aunque sean oscuros.
    """
    img = Image.open(path).convert("RGB")
    arr = np.asarray(img).astype(np.int16)
    lum = arr.max(axis=2)
    chroma = lum - arr.min(axis=2)

    def bands_mask(bs):
        m = np.zeros(lum.shape, bool)
        for lo, hi, ct in bs:
            m |= (lum >= lo) & (lum <= hi) & (chroma < ct)
        return m

    seed = bands_mask(bands)
    loose = bands_mask([(max(0, lo - 8), min(255, hi + 8), ct + 4) for lo, hi, ct in bands])
    grow = seed.copy()
    for _ in range(steps):
        grow = ndimage.binary_dilation(grow, iterations=1) & loose

    # region de fondo = lo que toca el borde
    free = grow.copy()
    free[0, :] = free[-1, :] = free[:, 0] = free[:, -1] = True
    labels, _ = ndimage.label(free, structure=np.ones((3, 3)))   # 8-vecindad: mas laxo
    edge = np.concatenate([labels[0, :], labels[-1, :], labels[:, 0], labels[:, -1]])
    bg = np.isin(labels, np.unique(edge))

    # El fondo gris del generador coincide en color con el riel de algunas
    # tarjetas: el flood entra por el borde y come el ornato. Se sella con un
    # cierre morfologico (tapa las fugas de 1-2 px) y se rellenan los huecos
    # que quedaron encerrados por el arte.
    art = ~bg
    art = ndimage.binary_closing(art, structure=np.ones((5, 5)))
    art = ndimage.binary_fill_holes(art)

    alpha = np.where(art, 255, 0).astype(np.uint8)
    alpha_img = Image.fromarray(alpha, "L")
    for _ in range(erode):
        alpha_img = alpha_img.filter(ImageFilter.MinFilter(3))  # defringe
    alpha_img = alpha_img.filter(ImageFilter.GaussianBlur(0.6))

    mask = alpha_img.point(lambda v: 255 if v > 16 else 0)
    bbox = mask.getbbox()
    if bbox is None:
        raise RuntimeError("sin contenido tras el recorte de fondo: %s" % path)

    plate = img.crop(bbox)
    plate.putalpha(alpha_img.crop(bbox))
    return plate, bbox


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ARCHIVE, exist_ok=True)

    plates = []
    for slot, prefix, second, canvas_h, bands, steps, erode in SLOTS:
        path = find_file(prefix, second)
        plate, bbox = cut(path, bands, steps, erode)
        w, h = plate.size
        asp = w / h
        force_w = FORCE_W.get(slot)
        canvas_w = force_w if force_w else int(round(asp * canvas_h))
        if canvas_w % 2:
            canvas_w += 1
        final = plate.resize((canvas_w, canvas_h), Image.LANCZOS)
        out = os.path.join(OUT_DIR, slot + ".png")
        final.save(out)
        plates.append((slot, final, bbox, asp))
        print("%-18s bbox=%-24s %4dx%-4d asp=%5.3f -> canvas %4dx%-4d  %s"
              % (slot, str(bbox), w, h, asp, canvas_w, canvas_h, os.path.basename(path)))

    # archivo de originales (sin tocar)
    for name in os.listdir(SRC):
        if name.lower().endswith((".jpg", ".jpeg", ".png")) and not name.startswith("_"):
            shutil.copy2(os.path.join(SRC, name), os.path.join(ARCHIVE, name))

    # previews: sobre el color de la ventana del modal y sobre magenta
    for tag, bg in (("modal", (10, 5, 24, 255)), ("magenta", (255, 0, 255, 255))):
        sheet = Image.new("RGBA", (1500, 1520), bg)
        y = 8
        for slot, im, _, _ in plates:
            if slot.startswith("hwm_card"):
                disp = im.resize((1300, int(im.height * 1300 / im.width)), Image.LANCZOS)
            elif slot.startswith("hwm_banner"):
                disp = im.resize((1300, int(im.height * 1300 / im.width)), Image.LANCZOS)
            elif slot == "hwm_window":
                disp = im.resize((760, int(im.height * 760 / im.width)), Image.LANCZOS)
            elif slot == "hwm_empty_moon":
                disp = im.resize((560, 560), Image.LANCZOS)
            elif slot == "hwm_crest":
                disp = im.resize((240, 240), Image.LANCZOS)
            else:
                disp = im.resize((400, int(im.height * 400 / im.width)), Image.LANCZOS)
            if y + disp.height + 20 > sheet.height:
                break
            sheet.alpha_composite(disp, (10, y))
            y += disp.height + 12
        out = os.path.join(SRC, "_preview_missions_%s.png" % tag)
        sheet.save(out)
        print("preview   %s  (%dx%d)" % (out, sheet.width, sheet.height))


if __name__ == "__main__":
    main()
