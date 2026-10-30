# -*- coding: utf-8 -*-
"""
build_halloween_chips.py — Paneles del topbar del Pase de Halloween
-------------------------------------------------------------------
Procesa los 3 JPG generados por IA (fondo negro) y los deja como PNG con
alfa listos para Unity, normalizados a un canvas uniforme (misma proporcion
para las tres placas).

Pipeline (mismo criterio que el arte de Progreso):
  1. Flood-fill del fondo negro desde los bordes (semilla estricta < 26 y
     crecimiento acotado sobre el halo del JPEG, < 58, hasta 4 px).
  2. Defringe: erosion de 1 px del alfa + desenfoque leve (0.6 px).
  3. Recorte al contenido (bbox del alfa).
  4. Resize LANCZOS al canvas uniforme (2x del tamano de display).
  5. Salida: Assets/Resources/UI/Halloween/chip_{nivel,xp,dulces}.png
     + preview de topbar para inspeccion visual.

Uso:  python build_halloween_chips.py
"""
import os
import shutil
from PIL import Image, ImageChops, ImageDraw, ImageFilter

SRC = r"C:\Users\Equipo\Downloads\Chips - Halloween"
OUT_DIR = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\Assets\Resources\UI\Halloween"
PREVIEW = r"C:\Users\Equipo\Downloads\Chips - Halloween\_preview_topbar.png"

# archivo de origen -> slot (segun revision visual de las generaciones)
FILES = {
    "chip_nivel":  "Gothic_fantasy_UI_stat_panel_20261016014111.jpg",
    "chip_xp":     "Fantasy_game_stat_panel_frame_20261016014111.jpg",
    "chip_dulces": "Fantasy_game_stat_panel_frame_20261016014111_2.jpg",
}

CANVAS_H = 180          # 2x del alto de display (90 px)
SEED_T = 26             # semilla estricta de "negro puro"
GROW_T = 58             # tope del halo JPEG que absorbe el crecimiento
GROW_STEPS = 4          # px maximos de crecimiento (1 por paso)


def cut_plate(path):
    """Devuelve (RGBA recortado al marco, ancho, alto del recorte)."""
    img = Image.open(path).convert("RGB")
    r, g, b = img.split()
    mx = ImageChops.lighter(ImageChops.lighter(r, g), b)

    strict = mx.point(lambda v: 255 if v < SEED_T else 0)
    seed = strict.copy()
    # el fondo exterior es una unica region conectada: (0,0) siempre es fondo
    ImageDraw.floodfill(seed, (0, 0), 128, thresh=0)
    grow = seed.point(lambda v: 255 if v == 128 else 0)

    cand = mx.point(lambda v: 255 if v < GROW_T else 0)
    for _ in range(GROW_STEPS):
        grown = ImageChops.darker(grow.filter(ImageFilter.MaxFilter(3)), cand)
        grow = ImageChops.lighter(grow, grown)

    alpha = ImageChops.invert(grow)                 # 255 = dentro del marco
    alpha = alpha.filter(ImageFilter.MinFilter(3))  # defringe de 1 px
    alpha = alpha.filter(ImageFilter.GaussianBlur(0.6))

    mask = alpha.point(lambda v: 255 if v > 16 else 0)
    bbox = mask.getbbox()
    if bbox is None:
        raise RuntimeError("sin contenido tras el flood-fill: %s" % path)

    plate = img.crop(bbox)
    plate.putalpha(alpha.crop(bbox))
    return plate, bbox


def main():
    plates = {}
    aspects = []
    for slot, name in FILES.items():
        plate, bbox = cut_plate(os.path.join(SRC, name))
        w, h = plate.size
        asp = w / h
        aspects.append(asp)
        plates[slot] = plate
        print("%-12s bbox=%s  %dx%d  aspect=%.3f" % (slot, bbox, w, h, asp))

    avg = sum(aspects) / len(aspects)
    canvas_w = int(round(avg * CANVAS_H))
    if canvas_w % 2:
        canvas_w += 1
    print("\naspect promedio=%.3f  ->  canvas %dx%d  (display %dx%d)"
          % (avg, canvas_w, CANVAS_H, canvas_w // 2, CANVAS_H // 2))

    os.makedirs(OUT_DIR, exist_ok=True)
    disp_w, disp_h = canvas_w // 2, CANVAS_H // 2
    strip = Image.new("RGBA", (disp_w * 3 + 4 * 14, disp_h + 28), (12, 21, 43, 255))
    for i, slot in enumerate(("chip_nivel", "chip_xp", "chip_dulces")):
        final = plates[slot].resize((canvas_w, CANVAS_H), Image.LANCZOS)
        out = os.path.join(OUT_DIR, slot + ".png")
        final.save(out)
        print("escrito %s  (%dx%d)" % (out, canvas_w, CANVAS_H))

        # preview a tamano real de display sobre el color del topbar
        strip.alpha_composite(final.resize((disp_w, disp_h), Image.LANCZOS),
                              (14 + i * (disp_w + 14), 14))

    strip.save(PREVIEW)
    print("preview   %s  (%dx%d)" % (PREVIEW, strip.width, strip.height))

    # copia de inspeccion en Downloads (por si se quiere volver a mirar)
    for slot in FILES:
        shutil.copy2(os.path.join(OUT_DIR, slot + ".png"),
                     os.path.join(SRC, slot + ".png"))


if __name__ == "__main__":
    main()
