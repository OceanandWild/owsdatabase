# -*- coding: utf-8 -*-
"""
check_skin_pair.py — QA de un par blanco/negro del Pase de la Velada
-------------------------------------------------------------------
Comprueba, para cada skin, que la version negra conserva la silueta de la
blanca y que ambas se distinguen a tamano de casilla.

Metricas:
  - IoU de alfa (tras escalar la negra al alto de la blanca y centrar por bbox).
  - Diferencia de luminancia media de los pixeles opacos a 78 px.
  - Relacion alto/ancho de cada pieza.

Salidas en %TEMP%\\ows-flow\\proc\\pairs:
  overlay_<skin>.png   blanca en rojo, negra en cian, interseccion en gris.
  casilla_<skin>.png   las dos a 78 px sobre fondo claro y oscuro.

Uso:
  python Tools/check_skin_pair.py hwp_bishop_lantern
  python Tools/check_skin_pair.py --all
"""
import os
import sys

from PIL import Image, ImageChops

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART = os.path.join(ROOT, "Assets", "Resources", "Pieces", "Halloween")
PREVIEW = os.path.join(os.environ.get("TEMP", ""), "ows-flow", "proc", "pairs")

PAIRS = [
    "hwp_bishop_lantern",
    "hwp_knight_scarecrow",
    "hwp_king_crimson",
    "hwp_pawn_candy",
    "hwp_rook_candy",
    "hwp_rook_reliquary",
    "hwp_queen_hex",
]

TILE_H = 78


def load(name, black=False):
    path = os.path.join(ART, name + ("_black" if black else "") + ".png")
    if not os.path.exists(path):
        return None
    return Image.open(path).convert("RGBA")


def mask_of(img, t=24):
    return img.getchannel("A").point(lambda v: 255 if v > t else 0)


def fit_to_height(img, h):
    w = max(1, int(round(img.width * h / img.height)))
    return img.resize((w, h), Image.LANCZOS)


def alpha_iou(white, black):
    w_m = mask_of(white)
    wb = w_m.getbbox()
    white = white.crop(wb)
    black = fit_to_height(black, white.height)
    b_m = mask_of(black)
    bb = b_m.getbbox()
    black = black.crop(bb)
    white = fit_to_height(white, max(white.height, black.height))
    black = fit_to_height(black, white.height)

    w, h = max(white.width, black.width), white.height
    a = Image.new("L", (w, h), 0)
    b = Image.new("L", (w, h), 0)
    a.paste(mask_of(white), ((w - white.width) // 2, 0))
    b.paste(mask_of(black), ((w - black.width) // 2, 0))
    inter = ImageChops.darker(a, b)
    union = ImageChops.lighter(a, b)
    ia = sum(inter.histogram()[255:])
    ua = sum(union.histogram()[255:])
    return (ia / ua if ua else 0.0), (a, b, w, h)


def mean_lum(img):
    rgb = img.convert("RGB")
    px = list(rgb.getdata())
    al = list(img.getchannel("A").getdata())
    vals = [(0.2126 * r + 0.7152 * g + 0.0722 * b) for (r, g, b), a in zip(px, al) if a > 200]
    return sum(vals) / len(vals) if vals else 0.0


def strip(white, black, name):
    small_w = fit_to_height(white, TILE_H)
    small_b = fit_to_height(black, TILE_H)
    cell = max(small_w.width, small_b.width) + 16
    canvas = Image.new("RGBA", (cell * 2 + 24, TILE_H * 2 + 48), (0, 0, 0, 0))

    dark = (32, 28, 40, 255)
    light = (238, 234, 240, 255)
    canvas.alpha_composite(Image.new("RGBA", (cell, TILE_H + 8), dark), (0, 8))
    canvas.alpha_composite(Image.new("RGBA", (cell * 2 + 24, TILE_H + 8), dark), (0, 8))
    canvas.alpha_composite(Image.new("RGBA", (cell, TILE_H + 8), dark), (cell + 8, 8))
    canvas.alpha_composite(Image.new("RGBA", (cell * 2 + 24, TILE_H + 8), dark), (cell + 8, 8))
    canvas.alpha_composite(Image.new("RGBA", (cell * 2 + 24, TILE_H + 8), light), (0, TILE_H + 32))
    canvas.alpha_composite(small_w, ((cell - small_w.width) // 2, 8 + (TILE_H - small_w.height) // 2))
    canvas.alpha_composite(small_b, (cell + 8 + (cell - small_b.width) // 2, 8 + (TILE_H - small_b.height) // 2))
    canvas.alpha_composite(small_w, ((cell - small_w.width) // 2, TILE_H + 32 + (TILE_H - small_w.height) // 2))
    canvas.alpha_composite(small_b, (cell + 8 + (cell - small_b.width) // 2, TILE_H + 32 + (TILE_H - small_b.height) // 2))
    os.makedirs(PREVIEW, exist_ok=True)
    canvas.save(os.path.join(PREVIEW, "casilla_" + name + ".png"))


def overlay(white, black, name):
    iou, (a, b, w, h) = alpha_iou(white, black)
    rgb = Image.merge("RGB", (a, b, b))
    os.makedirs(PREVIEW, exist_ok=True)
    rgb.save(os.path.join(PREVIEW, "overlay_" + name + ".png"))
    return iou


def check(name):
    white = load(name)
    black = load(name, black=True)
    if white is None or black is None:
        print("falta el par: %s" % name)
        return
    iou = overlay(white, black, name)
    strip(white, black, name)
    lw = mean_lum(fit_to_height(white, TILE_H))
    lb = mean_lum(fit_to_height(black, TILE_H))
    print(
        "%s  blanco %dx%d  negro %dx%d  IoU=%.3f  lum78=%.1f/%.1f  delta=%.1f"
        % (name, white.width, white.height, black.width, black.height, iou, lw, lb, lw - lb)
    )


def main():
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    names = PAIRS if (not only or "--all" in sys.argv) else only
    for n in names:
        check(n)
    if os.path.isdir(PREVIEW):
        print("previews:", PREVIEW)


if __name__ == "__main__":
    main()
