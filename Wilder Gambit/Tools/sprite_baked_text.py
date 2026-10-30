"""Detecta y borra el TEXTO FALSO que las imágenes generadas suelen traer horneado
dentro de los contenedores (píldoras, chips, botones).

Idea: el relleno de un contenedor es un tono oscuro suave y el marco mide ~10-13 px.
Cualquier píxel que esté a 14 px o más del borde y destaque sobre el relleno oscuro de
su propia fila es una marca horneada (letras, filetes), y sobra: las etiquetas ya las
pinta la UI (ver Docs/PROMPTS-SPRITES-UI.md). Se mide así, fila a fila, para no confundir
un relleno claro legítimo (un chip lleno, una barra de progreso) con texto.

Uso:
    python Tools/sprite_baked_text.py check Assets/Resources/UI/Progress
    python Tools/sprite_baked_text.py clean Assets/Resources/UI/Progress/btn_claim_ready.png
"""
import glob
import os
import sys

import numpy as np
from PIL import Image, ImageFilter
from scipy import ndimage

DEPTH = 10         # px desde la silueta: por debajo de esto es marco, no se toca
CHECK = 14         # px desde la silueta para considerar una marca "horneada"
DARK = 0.15        # fracción más oscura de la fila = relleno de referencia
MARK = 30          # cuánto destaca una marca sobre el relleno
FEATHER = 2
SMOOTH = 3
MIN_ROW = 8        # píxeles repintables mínimos por fila
ALERT = 0.01       # fracción del interior con marcas que merece revisión


def lum(c):
    return 0.3 * c[0] + 0.6 * c[1] + 0.1 * c[2]


def deep_mask(im, depth):
    w, h = im.size
    px = im.load()
    mask = Image.new("L", (w, h), 0)
    mp = mask.load()
    for y in range(h):
        for x in range(w):
            mp[x, y] = 255 if px[x, y][3] > 110 else 0
    pad = Image.new("L", (w + depth * 2, h + depth * 2), 0)
    pad.paste(mask, (depth, depth))
    return pad.filter(ImageFilter.MinFilter(depth * 2 + 1)).crop((depth, depth, depth + w, depth + h))


def rows_with_fill(im, deep):
    """Filas repintables: (y, x0, x1, color de relleno, píxeles)."""
    w, h = im.size
    px = im.load()
    rows = []
    for y in range(h):
        pts = [x for x in range(w) if deep[x, y]]
        if len(pts) < MIN_ROW:
            continue
        order = sorted(pts, key=lambda x: lum(px[x, y][:3]))
        dark = order[: max(1, int(len(order) * DARK))]
        color = tuple(sum(px[x, y][c] for x in dark) / len(dark) for c in range(3))
        rows.append([y, pts[0], pts[-1], color, pts])
    return rows


def marks(path):
    """Marcas horneadas con forma de LETRA (finas y pequeñas) y total repintable.

    Se descartan las manchas grandes: un relleno claro de verdad (un chip lleno) o un
    filete largo del propio adorno no son texto horneado.
    """
    im = Image.open(path).convert("RGBA")
    deep = deep_mask(im, CHECK).load()
    px = im.load()
    w, h = im.size

    flag = Image.new("L", (w, h), 0)
    fp = flag.load()
    total = 0
    for y, x0, x1, color, _ in rows_with_fill(im, deep):
        base = lum(color)
        for x in range(x0, x1 + 1):
            total += 1
            if lum(px[x, y][:3]) - base > MARK:
                fp[x, y] = 1

    arr, hits = np.array(flag), 0
    labels, count = ndimage.label(arr)
    for sl in ndimage.find_objects(labels):
        if sl is None:
            continue
        hgt = sl[0].stop - sl[0].start
        wid = sl[1].stop - sl[1].start
        area = int((labels[sl] == labels[sl][0, 0]).sum())
        if hgt <= 24 and wid <= 40 and area >= 6:
            hits += area
    return hits, total


def clean(path):
    im = Image.open(path).convert("RGBA")
    w, h = im.size
    px = im.load()
    deep = deep_mask(im, DEPTH).load()

    rows = rows_with_fill(im, deep)
    smooth = []
    for i, row in enumerate(rows):
        win = rows[max(0, i - SMOOTH): i + SMOOTH + 1]
        smooth.append(tuple(sum(r[3][c] for r in win) / len(win) for c in range(3)))

    changed = 0
    for (y, lo, hi, _, pts), color in zip(rows, smooth):
        base = lum(color)
        for x in pts:
            if lum(px[x, y][:3]) - base <= MARK:
                continue
            k = 1.0
            d = x - lo
            if d < FEATHER:
                k = (d + 1) / (FEATHER + 1)
            d = hi - x
            if d < FEATHER:
                k = min(k, (d + 1) / (FEATHER + 1))
            rgb = tuple(px[x, y][c] * (1 - k) + color[c] * k for c in range(3))
            px[x, y] = (int(rgb[0]), int(rgb[1]), int(rgb[2]), px[x, y][3])
            changed += 1

    im.save(path)
    print(f"limpiado {os.path.basename(path)}: {changed} px de marca borrados")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    mode, target = sys.argv[1], sys.argv[2]
    paths = [target] if os.path.isfile(target) else sorted(glob.glob(os.path.join(target, "*.png")))

    if mode == "check":
        flagged = 0
        print("sprite                      marcas   % del relleno")
        for p in paths:
            hits, total = marks(p)
            pct = 100.0 * hits / max(1, total)
            if hits:
                note = "   <-- revisar (puede ser adorno propio)" if pct >= ALERT * 100 else ""
                print(f"  {os.path.basename(p):24s} {hits:6d}   {pct:5.1f}%{note}")
            if pct >= ALERT * 100:
                flagged += 1
        print(f"revisados {len(paths)} sprites · a revisar a ojo {flagged}")
        return 0

    if mode == "clean":
        for p in paths:
            hits, _ = marks(p)
            if hits:
                clean(p)
        return 0

    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
