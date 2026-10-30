# -*- coding: utf-8 -*-
"""
build_halloween_boards.py — Tableros-objeto 8x8 de Halloween (v3)
------------------------------------------------------------------
Procesa los JPG generados por IA (fondo negro) con la grilla 8x8 pintada:

  1. Flood-fill del negro desde los bordes (semilla estricta + crecimiento
     acotado sobre el halo del JPEG). Mismo criterio que build_halloween_chips.
  2. Defringe + recorte al contenido (bbox del alfa).
  3. Deteccion de la grilla 8x8 por contraste de paridad y ajuste fino de las 7
     juntas interiores al perfil de bordes: devuelve el rectangulo exacto, sin
     depender de que el borde sea fino ni de que el tablero este centrado.
  4. Recomposicion a canvas cuadrado de OUT px con la grilla ocupando
     INNER_FRACTION (0.83, la constante de BoardBackgroundManager): se escala
     cada eje por separado para que la grilla quede EXACTAMENTE cuadrada y
     centrada. Si el marco no entra, se recorta; SQUEEZE comprime solo el borde.
  5. Overlays de verificacion (grilla roja sobre el original, grilla verde
     0.83 sobre el final) + preview.

Uso:
    python build_halloween_boards.py                 # slots nuevos (graveyard, crypt)
    python build_halloween_boards.py --only graveyard,crypt
"""
import argparse
import os
import shutil

import numpy as np
from PIL import Image, ImageChops, ImageDraw, ImageFilter

SRC = os.path.join(os.environ.get("TEMP", ""), "ows-flow", "raw")
FILES = {
    "graveyard": "graveyard_board_raw.jpg",
    "crypt": "crypt_board_raw.jpg",
    # Historial (ya publicados a su tamano nativo; no se recomponen por defecto).
    "moon": "Stone_chessboard_top-down_view_20261016234548.jpg",
    "blood": "Stone_chessboard_under_blood_moon_20261016234548.jpg",
}
LEGACY = {"moon", "blood"}

OUT = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\_art-source\Halloween\procesados"
ARCHIVE = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit\_art-source\Halloween"

SEED_T = 26        # semilla estricta de "negro puro"
GROW_T = 58        # tope del halo JPEG que absorbe el crecimiento
GROW_STEPS = 4     # px maximos de crecimiento (1 por paso)

INNER_FRACTION = 0.83   # BoardBackgroundManager.BoardArtInnerFraction
OUT_SIZE = 1024

# Slots cuyo borde ornamental no cabe en el margen del 0.83: se comprime SOLO
# el marco (grilla intacta) para que entre completo. El resto va a escala uniforme.
SQUEEZE = set()

# Overrides manuales de la grilla (x0, y0, cell_x, cell_y) en coordenadas del
# recorte, solo si la deteccion automatica falla. Verificar con ov_<slot>.
OVERRIDE = {}


def cut_board(path):
    """Recorta el tablero quitando el negro exterior (devuelve RGBA + bbox)."""
    img = Image.open(path).convert("RGB")
    r, g, b = img.split()
    mx = ImageChops.lighter(ImageChops.lighter(r, g), b)

    strict = mx.point(lambda v: 255 if v < SEED_T else 0)
    seed = strict.copy()
    ImageDraw.floodfill(seed, (0, 0), 128, thresh=0)
    grow = seed.point(lambda v: 255 if v == 128 else 0)

    cand = mx.point(lambda v: 255 if v < GROW_T else 0)
    for _ in range(GROW_STEPS):
        grown = ImageChops.darker(grow.filter(ImageFilter.MaxFilter(3)), cand)
        grow = ImageChops.lighter(grow, grown)

    alpha = ImageChops.invert(grow)
    alpha = alpha.filter(ImageFilter.MinFilter(3))   # defringe de 1 px
    alpha = alpha.filter(ImageFilter.GaussianBlur(0.6))

    mask = alpha.point(lambda v: 255 if v > 16 else 0)
    bbox = mask.getbbox()
    if bbox is None:
        raise RuntimeError("sin contenido tras el flood-fill: %s" % path)

    board = img.crop(bbox)
    board.putalpha(alpha.crop(bbox))
    return board, bbox


def _cell_means(ii, x0, y0, cx, cy):
    xs = np.clip(np.rint(x0 + cx * np.arange(9)).astype(int), 0, ii.shape[1] - 1)
    ys = np.clip(np.rint(y0 + cy * np.arange(9)).astype(int), 0, ii.shape[0] - 1)
    s = ii[np.ix_(ys, xs)]
    m = s[1:, 1:] - s[:-1, 1:] - s[1:, :-1] + s[:-1, :-1]
    return m / ((ys[1:] - ys[:-1])[:, None] * (xs[1:] - xs[:-1])[None, :])


def _parity(ii, x0, y0, cx, cy):
    m = _cell_means(ii, x0, y0, cx, cy)
    even = (m[0::2, 0::2].mean() + m[1::2, 1::2].mean()) / 2.0
    odd = (m[0::2, 1::2].mean() + m[1::2, 0::2].mean()) / 2.0
    return abs(even - odd) / (m.std() + 1e-6)


def _peak(prof, guess, win=12):
    lo = max(2, int(round(guess)) - win)
    hi = min(len(prof) - 3, int(round(guess)) + win)
    i = lo + int(np.argmax(prof[lo:hi]))
    a, b, c = prof[i - 1], prof[i], prof[i + 1]
    den = a - 2 * b + c
    d = (a - c) / (2.0 * den) if den else 0.0
    return i + 0.5 + d, prof[i]


def refine_grid(gray, x0, y0, cx, cy):
    """Engancha las 7 lineas interiores al pico real del perfil de bordes.

    El ajuste por paridad da el orden de magnitud; este paso corrige el ~1%
    que deja las lineas centrales fuera de la junta (se nota en el overlay).
    """
    band = gray[int(round(y0 + cy)):int(round(y0 + 7 * cy)), :]
    prof = np.convolve(np.abs(np.diff(band, axis=1)).mean(axis=0), np.ones(3) / 3.0, mode="same")
    ks, ps, ws = [], [], []
    for k in range(1, 8):
        pos, w = _peak(prof, x0 + k * cx)
        ks.append(k); ps.append(pos); ws.append(w)
    b, a = np.polyfit(np.array(ks), np.array(ps), 1, w=np.array(ws))
    nx0, ncx = a, b

    band = gray[:, int(round(x0 + cx)):int(round(x0 + 7 * cx))]
    prof = np.convolve(np.abs(np.diff(band, axis=0)).mean(axis=1), np.ones(3) / 3.0, mode="same")
    ks, ps, ws = [], [], []
    for k in range(1, 8):
        pos, w = _peak(prof, y0 + k * cy)
        ks.append(k); ps.append(pos); ws.append(w)
    b, a = np.polyfit(np.array(ks), np.array(ps), 1, w=np.array(ws))
    ny0, ncy = a, b
    return nx0, ny0, ncx, ncy


def detect_grid(board):
    """Grilla 8x8 por contraste de paridad + ajuste fino a las juntas."""
    gray = np.asarray(board.convert("L"), dtype=np.float32)
    h, w = gray.shape
    ii = np.pad(gray.cumsum(0).cumsum(1), ((1, 0), (1, 0)))
    cx0, cy0 = w / 2.0, h / 2.0

    best = (-1.0, cx0 - 4 * (w * 0.08), cy0 - 4 * (h * 0.08), w * 0.08, h * 0.08)
    for cx in np.arange(w * 0.055, w * 0.115, 0.5):
        x0 = cx0 - 4 * cx
        for cy in np.arange(h * 0.055, h * 0.115, 0.5):
            y0 = cy0 - 4 * cy
            s = _parity(ii, x0, y0, cx, cy)
            if s > best[0]:
                best = (s, x0, y0, cx, cy)
    s, x0, y0, cx, cy = best

    for ox in np.arange(-20, 20.1, 1.0):
        for oy in np.arange(-20, 20.1, 1.0):
            s2 = _parity(ii, x0 + ox, y0 + oy, cx, cy)
            if s2 > s:
                s, x0, y0 = s2, x0 + ox, y0 + oy
    for dcx in np.arange(-1.2, 1.21, 0.1):
        for dcy in np.arange(-1.2, 1.21, 0.1):
            s2 = _parity(ii, x0, y0, cx + dcx, cy + dcy)
            if s2 > s:
                s, cx, cy = s2, cx + dcx, cy + dcy
    nx0, ny0, ncx, ncy = refine_grid(gray, x0, y0, cx, cy)
    return nx0, ny0, ncx, ncy, s


def draw_grid(img, x0, y0, cx, cy, color, width=2):
    ov = img.copy()
    d = ImageDraw.Draw(ov)
    for k in range(9):
        x = x0 + cx * k
        y = y0 + cy * k
        d.line([(x, y0), (x, y0 + cy * 8)], fill=color, width=width)
        d.line([(x0, y), (x0 + cx * 8, y)], fill=color, width=width)
    return ov


def compose(board, grid, size=OUT_SIZE, inner=INNER_FRACTION):
    """Escala por eje para que la grilla mida inner*size y la centra."""
    x0, y0, cx, cy = grid
    target = inner * size
    sx, sy = target / (8.0 * cx), target / (8.0 * cy)
    resized = board.resize((int(round(board.width * sx)), int(round(board.height * sy))),
                           Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gcx = (x0 + 4 * cx) * sx
    gcy = (y0 + 4 * cy) * sy
    canvas.alpha_composite(resized, (int(round(size / 2 - gcx)), int(round(size / 2 - gcy))))
    return canvas, sx, sy


def compose_squeeze(board, grid, size=OUT_SIZE, inner=INNER_FRACTION):
    """Grilla intacta y marco comprimido para que entre completo en el lienzo.

    Divide el tablero en 3x3 (marco izquierdo / grilla / marco derecho, idem
    vertical) y lleva cada pieza a su hueco: la grilla a inner*size exacto y
    los ocho tramos de marco al margen restante. Solo se deforma el borde.
    """
    x0, y0, cx, cy = grid
    gx1, gy1 = x0 + 8 * cx, y0 + 8 * cy
    m = int(round((1.0 - inner) * size / 2.0))
    t = size - 2 * m
    cols = [(0.0, x0, 0), (x0, gx1, m), (gx1, float(board.width), m + t)]
    rows = [(0.0, y0, 0), (y0, gy1, m), (gy1, float(board.height), m + t)]
    widths = [m, t, m]
    heights = [m, t, m]
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    for j, (sy0, sy1, oy) in enumerate(rows):
        for i, (sx0, sx1, ox) in enumerate(cols):
            box = (int(round(sx0)), int(round(sy0)), int(round(sx1)), int(round(sy1)))
            tile = board.crop(box)
            if tile.width < 1 or tile.height < 1:
                continue
            tile = tile.resize((max(1, widths[i]), max(1, heights[j])), Image.LANCZOS)
            canvas.alpha_composite(tile, (ox, oy))
    return canvas, t / (8.0 * cx), t / (8.0 * cy)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="slots separados por coma")
    args = ap.parse_args()
    only = [s.strip() for s in args.only.split(",") if s.strip()] or \
           [s for s in FILES if s not in LEGACY]

    os.makedirs(OUT, exist_ok=True)
    print("== Fase 1: recorte, deteccion y composicion ==")
    finals = {}
    for slot in only:
        name = FILES[slot]
        src = os.path.join(SRC, name)
        board, bbox = cut_board(src)
        grid = OVERRIDE.get(slot)
        if grid:
            gx0, gy0, gcx, gcy = grid
            score = float("nan")
        else:
            gx0, gy0, gcx, gcy, score = detect_grid(board)
        grid = (gx0, gy0, gcx, gcy)
        print("%-9s bbox=%s  tablero=%dx%d  grilla=(%.1f,%.1f) celda=%.2fx%.2f "
              "%.0f%%  score=%.2f"
              % (slot, bbox, board.width, board.height, gx0, gy0, gcx, gcy,
                 100.0 * (8 * gcx) / board.width, score))

        draw_grid(board, *grid, (255, 40, 40, 255)).save(
            os.path.join(SRC, "ov_%s_grilla.png" % slot))

        canvas, sx, sy = (compose_squeeze if slot in SQUEEZE else compose)(board, grid)
        finals[slot] = canvas

        out_png = os.path.join(OUT, "halloween_%s_board_v3.png" % slot)
        canvas.save(out_png)
        print("          -> %dx%d  escala=%.3fx%.3f  %s"
              % (canvas.width, canvas.height, sx, sy, out_png))

        # Overlay final: grilla 0.83 que usa el juego.
        ov = canvas.copy()
        d = ImageDraw.Draw(ov)
        g0 = int(round((OUT_SIZE - INNER_FRACTION * OUT_SIZE) / 2.0))
        g1 = int(round((OUT_SIZE + INNER_FRACTION * OUT_SIZE) / 2.0))
        d.rectangle([g0, g0, g1 - 1, g1 - 1], outline=(80, 255, 120, 255), width=2)
        step = (g1 - g0) / 8.0
        for i in range(1, 8):
            p = int(round(g0 + step * i))
            d.line([(p, g0), (p, g1)], fill=(80, 255, 120, 110), width=1)
            d.line([(g0, p), (g1, p)], fill=(80, 255, 120, 110), width=1)
        ov.save(os.path.join(SRC, "verificacion_%s.png" % slot))

        raw_copy = os.path.join(ARCHIVE, "halloween_%s_board_v3_original.jpg" % slot)
        if not os.path.exists(raw_copy):
            shutil.copy2(src, raw_copy)

    # Preview sobre fondo oscuro.
    if finals:
        h = 420
        keys = list(finals)
        scaled = [finals[k].resize((int(h * finals[k].width / finals[k].height), h), Image.LANCZOS)
                  for k in keys]
        prev = Image.new("RGBA", (sum(s.width for s in scaled) + 16 * (len(keys) + 1), h + 32),
                         (18, 22, 40, 255))
        x = 16
        for s in scaled:
            prev.alpha_composite(s, (x, 16))
            x += s.width + 16
        p = os.path.join(SRC, "preview_tableros_v3.png")
        prev.save(p)
        print("preview   %s" % p)


if __name__ == "__main__":
    main()
