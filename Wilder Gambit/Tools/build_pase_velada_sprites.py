# -*- coding: utf-8 -*-
"""
build_pase_velada_sprites.py — Lote 21-30 del Pase de la Velada
----------------------------------------------------------------
Toma los JPG crudos de Flow (fondo blanco) y los deja como PNG con alfa
en Resources/Pieces/Halloween, normalizados a la familia hwp_*:
  - recorte al contenido (bbox del alfa),
  - alto final 900 px conservando proporcion (igual que hwp_knight_skeleton),
  - preview sobre mitad oscura / mitad clara, a tamano de casilla.

Uso:
  python Tools/build_pase_velada_sprites.py
  python Tools/build_pase_velada_sprites.py --only bishop
"""
import os
import sys
from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(os.environ.get("TEMP", ""), "ows-flow", "raw")
OUT = os.path.join(ROOT, "Assets", "Resources", "Pieces", "Halloween")
PREVIEW = os.path.join(os.environ.get("TEMP", ""), "ows-flow", "proc", "previews")

TARGET_H = 900
SEED_T = 24
GROW_T = 56
GROW_STEPS = 4

# (crudo, nombre final sin extension)
JOBS = [
    ("bishop_lantern_w4_raw.jpg", "hwp_bishop_lantern"),
    ("bishop_lantern_black_raw.jpg", "hwp_bishop_lantern_black"),
    ("knight_scarecrow_w_raw.jpg", "hwp_knight_scarecrow"),
    ("knight_scarecrow_black_raw.jpg", "hwp_knight_scarecrow_black"),
    ("king_crimson_w_raw.jpg", "hwp_king_crimson"),
    ("king_crimson_black_raw.jpg", "hwp_king_crimson_black"),
    ("rook_reliquary_w_raw.jpg", "hwp_rook_reliquary"),
    ("rook_reliquary_black_raw.jpg", "hwp_rook_reliquary_black"),
    ("queen_hex_w_raw.jpg", "hwp_queen_hex"),
    ("queen_hex_black_raw.jpg", "hwp_queen_hex_black"),
    ("pawn_candy_w_raw.jpg", "hwp_pawn_candy"),
    ("pawn_candy_black_raw.jpg", "hwp_pawn_candy_black"),
]


def flatten_background(img):
    """Lleva el fondo del borde a blanco puro (Flow a veces lo entrega gris).

    Mide la mediana del marco exterior y aplica una ganancia por canal para
    que ese color llegue a 255. La pieza es oscura, asi que la ganancia apenas
    la toca; el recorte posterior ya puede sembrar en blanco.
    """
    px = img.load()
    w, h = img.size
    ring = []
    for x in range(w):
        ring.append(px[x, 0]); ring.append(px[x, h - 1])
    for y in range(h):
        ring.append(px[0, y]); ring.append(px[w - 1, y])
    ring.sort(key=lambda c: c[0] + c[1] + c[2])
    mid = ring[len(ring) // 2]
    if min(mid) >= 250:
        return img, mid
    gain = [255.0 / max(1, v) for v in mid]
    lut = [[min(255, int(v * gain[c])) for v in range(256)] for c in range(3)]
    out = img.copy()
    r, g, b = out.split()
    out = Image.merge("RGB", (r.point(lut[0]), g.point(lut[1]), b.point(lut[2])))
    return out, mid


def grow_from_border(strict):
    """Crece el fondo desde TODOS los pixeles blancos del borde.

    El flood-fill de un solo punto se corta si el JPEG deja una costura
    (una linea de pixeles algo mas grises) y entonces el fondo se queda
    opaco. Sembrar en todo el marco y dilatar sobre la mascara estricta
    evita ese fallo.
    """
    w, h = strict.size
    sp = strict.load()
    seeds = Image.new("L", (w, h), 0)
    dp = seeds.load()
    for x in range(w):
        if sp[x, 0]:
            dp[x, 0] = 255
        if sp[x, h - 1]:
            dp[x, h - 1] = 255
    for y in range(h):
        if sp[0, y]:
            dp[0, y] = 255
        if sp[w - 1, y]:
            dp[w - 1, y] = 255
    if seeds.getbbox() is None:
        return seeds
    for _ in range(4000):
        grown = ImageChops.darker(seeds.filter(ImageFilter.MaxFilter(3)), strict)
        merged = ImageChops.lighter(seeds, grown)
        if ImageChops.difference(merged, seeds).getbbox() is None:
            return merged
        seeds = merged
    return seeds


def cut_white_background(path):
    img = Image.open(path).convert("RGB")
    img, border = flatten_background(img)
    print("  fondo borde=%s" % (border,))
    r, g, b = img.split()
    mn = ImageChops.darker(ImageChops.darker(r, g), b)

    strict = mn.point(lambda v: 255 if v >= 255 - SEED_T else 0)
    grow = grow_from_border(strict)
    if grow.getbbox() is None:
        raise RuntimeError("sin fondo blanco en el borde: %s (esquina=%s)" % (path, img.getpixel((0, 0))))

    cand = mn.point(lambda v: 255 if v >= 255 - GROW_T else 0)
    for _ in range(GROW_STEPS):
        grown = ImageChops.darker(grow.filter(ImageFilter.MaxFilter(3)), cand)
        grow = ImageChops.lighter(grow, grown)

    alpha = ImageChops.invert(grow)
    alpha = alpha.filter(ImageFilter.MinFilter(3))
    alpha = alpha.filter(ImageFilter.GaussianBlur(0.6))

    mask = alpha.point(lambda v: 255 if v > 64 else 0)
    bbox = mask.getbbox()
    if bbox is None:
        raise RuntimeError("sin contenido tras el flood-fill: %s" % path)
    # 2 px de aire para no cortar el antialias del contorno.
    bbox = (max(0, bbox[0] - 2), max(0, bbox[1] - 2),
            min(img.width, bbox[2] + 2), min(img.height, bbox[3] + 2))

    plate = img.crop(bbox)
    plate.putalpha(alpha.crop(bbox))
    return unmix_white(plate), bbox


def unmix_white(rgba):
    try:
        import numpy as np
    except ImportError:
        print("  (numpy no disponible: sin desmezcla de halo)")
        return rgba
    a = np.asarray(rgba).astype(np.float32)
    al = a[..., 3:4] / 255.0
    safe = np.maximum(al, 1e-3)
    c = (a[..., :3] - (1.0 - al) * 255.0) / safe
    c = np.clip(c, 0, 255)
    out = a.copy()
    out[..., :3] = np.where(al >= 0.16, c, a[..., :3])
    return Image.fromarray(out.astype(np.uint8), "RGBA")


def normalize(cut, target_h=TARGET_H):
    w = max(1, int(round(cut.width * target_h / cut.height)))
    return cut.resize((w, target_h), Image.LANCZOS)


def preview(canvas, name):
    os.makedirs(PREVIEW, exist_ok=True)
    # Franja de casilla: 78 px de alto, dos fondos.
    small = canvas.resize((max(1, round(canvas.width * 78 / canvas.height)), 78), Image.LANCZOS)
    strip = Image.new("RGBA", (small.width * 2 + 24, 110), (0, 0, 0, 0))
    strip.alpha_composite(Image.new("RGBA", (small.width + 24, 110), (30, 26, 38, 255)), (0, 0))
    strip.alpha_composite(Image.new("RGBA", (small.width + 24, 110), (238, 234, 240, 255)), (small.width + 24, 0))
    strip.alpha_composite(small, (12, 16))
    strip.alpha_composite(small, (small.width + 36, 16))
    strip.save(os.path.join(PREVIEW, "casilla_" + name + ".png"))

    # Vista grande sobre fondo oscuro.
    big = Image.new("RGBA", (canvas.width + 40, canvas.height + 40), (24, 22, 30, 255))
    big.alpha_composite(canvas, (20, 20))
    big.save(os.path.join(PREVIEW, "grande_" + name + ".png"))


def main():
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].lower()

    for raw_name, art in JOBS:
        if only and only not in art and only not in raw_name:
            continue
        src = os.path.join(RAW, raw_name)
        if not os.path.exists(src):
            print("falta crudo: %s" % src)
            continue
        cut, bbox = cut_white_background(src)
        canvas = normalize(cut)
        dst = os.path.join(OUT, art + ".png")
        canvas.save(dst)
        preview(canvas, art)
        print("%s  bbox=%s  %dx%d -> %dx%d  (%.1f KB)"
              % (art, bbox, cut.width, cut.height, canvas.width, canvas.height,
                 os.path.getsize(dst) / 1024.0))


if __name__ == "__main__":
    main()
