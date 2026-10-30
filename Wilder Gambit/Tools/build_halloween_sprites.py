# -*- coding: utf-8 -*-
"""
build_halloween_sprites.py — Skins y variante de la Velada de Halloween
-----------------------------------------------------------------------
Procesa los 5 JPG generados por IA (fondo blanco) de la carpeta
«Variantes y Skins - Halloween» y los deja como PNG con alfa listos para
Unity, normalizados al encuadre de la familia de skins (misma fracción de
alto y mismo centro que la skin de referencia de cada tipo de pieza).

Pipeline (mismo criterio que build_halloween_chips.py, fondo blanco):
  1. Flood-fill del fondo blanco desde los bordes (semilla estricta y
     crecimiento acotado sobre el halo del JPEG).
  2. Defringe: erosión de 1 px del alfa + desenfoque leve (0.6 px).
  3. Desmezcla del halo blanco en píxeles semitransparentes (numpy).
  4. Recorte al contenido (bbox del alfa).
  5. Normalización al canvas de su familia (917x512; la Reina Vampira al
     canvas de variante de la Dama Jinete) con el mismo encuadre.
  6. Salidas:
       - Assets/Resources/Skins/skin_pawn_halloween.png
       - Assets/Resources/Skins/skin_rook_halloween.png
       - Assets/Resources/Skins/skin_queen_halloween.png
       - Assets/Resources/Skins/skin_king_halloween.png
       - Assets/StreamingAssets/Pieces/White/VampireQueen.png
       - Assets/Resources/Pieces/White/VampireQueen.png
     + previews (mitad oscura / mitad clara) en la carpeta de origen.

Uso:  python build_halloween_sprites.py
"""
import os
from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit"
SRC = r"C:\Users\Equipo\Downloads\Variantes y Skins - Halloween"
SKIN_OUT = os.path.join(ROOT, "Assets", "Resources", "Skins")
STREAM_OUT = os.path.join(ROOT, "Assets", "StreamingAssets", "Pieces", "White")
RES_OUT = os.path.join(ROOT, "Assets", "Resources", "Pieces", "White")
PREVIEW_DIR = os.path.join(SRC, "_procesados")

# JPG de origen -> id de skin -> skin de referencia (mismo tipo de pieza)
SKIN_JOBS = [
    ("Reskin_pawn_with_ember_material_20261016193124.jpg",   "skin_pawn_halloween",  "skin_pawn_golden"),
    ("Reskin_rook_tower_moss_20261016193124.jpg",            "skin_rook_halloween",  "skin_rook_crimson"),
    ("Reskin_queen_statue_stone_cracks_20261016193124.jpg",  "skin_queen_halloween", "skin_queen_roses"),
    ("Reskinking_king_image_as_skeleton_20261016193124.jpg", "skin_king_halloween",  "skin_king_solar"),
]

VAMPIRE_SRC = "Reskinning_queen_image_as_vampire_20261016193124.jpg"
RIDER_REF = os.path.join(ROOT, "Assets", "StreamingAssets", "Pieces", "White", "RiderQueen.png")

SEED_T = 24          # semilla estricta de "blanco puro"
GROW_T = 56          # tope del halo JPEG que absorbe el crecimiento
GROW_STEPS = 4       # px máximos de crecimiento (1 por paso)


def cut_white_background(path):
    """Recorta el fondo blanco conectado a los bordes y devuelve el RGBA."""
    img = Image.open(path).convert("RGB")
    r, g, b = img.split()
    mn = ImageChops.darker(ImageChops.darker(r, g), b)  # canal más bajo

    strict = mn.point(lambda v: 255 if v >= 255 - SEED_T else 0)
    seed = strict.copy()

    # Semilla: primer píxel del borde que sea blanco puro (normalmente (0,0)).
    seed_px = None
    for x in range(0, img.width, 4):
        if seed.getpixel((x, 0)):
            seed_px = (x, 0)
            break
    if seed_px is None:
        for x in range(0, img.width, 4):
            if seed.getpixel((x, img.height - 1)):
                seed_px = (x, img.height - 1)
                break
    if seed_px is None:
        for y in range(0, img.height, 4):
            if seed.getpixel((0, y)):
                seed_px = (0, y)
                break
    if seed_px is None:
        for y in range(0, img.height, 4):
            if seed.getpixel((img.width - 1, y)):
                seed_px = (img.width - 1, y)
                break
    if seed_px is None:
        corner = img.getpixel((0, 0))
        raise RuntimeError("no encontré fondo blanco en los bordes: %s (esquina=%s)" % (path, corner))

    ImageDraw.floodfill(seed, seed_px, 128, thresh=0)
    grow = seed.point(lambda v: 255 if v == 128 else 0)

    cand = mn.point(lambda v: 255 if v >= 255 - GROW_T else 0)
    for _ in range(GROW_STEPS):
        grown = ImageChops.darker(grow.filter(ImageFilter.MaxFilter(3)), cand)
        grow = ImageChops.lighter(grow, grown)

    alpha = ImageChops.invert(grow)                 # 255 = dentro de la pieza
    alpha = alpha.filter(ImageFilter.MinFilter(3))  # defringe de 1 px
    alpha = alpha.filter(ImageFilter.GaussianBlur(0.6))

    mask = alpha.point(lambda v: 255 if v > 16 else 0)
    bbox = mask.getbbox()
    if bbox is None:
        raise RuntimeError("sin contenido tras el flood-fill: %s" % path)

    plate = img.crop(bbox)
    plate.putalpha(alpha.crop(bbox))
    return unmix_white(plate), bbox


def unmix_white(rgba):
    """En píxeles semitransparentes, desmezcla el blanco del borde
    (c' = (c - (1-a)·bg) / a) para que no quede halo claro al pegar."""
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


def ref_frame(path):
    """Marco de referencia: tamaño de canvas + fracción de alto + centro del
    contenido (todo en fracciones 0..1)."""
    im = Image.open(path).convert("RGBA")
    w, h = im.size
    mask = im.split()[3].point(lambda v: 255 if v > 16 else 0)
    bb = mask.getbbox()
    if bb is None:
        raise RuntimeError("referencia sin alfa: %s" % path)
    x0, y0, x1, y1 = bb
    return {
        "size": (w, h),
        "fh": (y1 - y0) / h,
        "cx": ((x0 + x1) / 2.0) / w,
        "cy": ((y0 + y1) / 2.0) / h,
    }


def normalize_to_frame(cut, frame, height_scale=1.0):
    """Escala el recorte a la fracción de alto del marco y lo centra igual."""
    w, h = frame["size"]
    target_h = max(1, int(round(frame["fh"] * height_scale * h)))
    scale = target_h / cut.height
    target_w = max(1, int(round(cut.width * scale)))
    resized = cut.resize((target_w, target_h), Image.LANCZOS)

    cx = int(round(frame["cx"] * w))
    cy = int(round(frame["cy"] * h))
    canvas = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    canvas.alpha_composite(resized, (cx - target_w // 2, cy - target_h // 2))
    return canvas


def save_preview(canvas, name):
    """Preview mitad oscura / mitad clara para inspección visual."""
    w, h = canvas.size
    half = w // 2
    bg = Image.new("RGBA", (w, h))
    bg.paste(Image.new("RGBA", (half, h), (30, 26, 38, 255)), (0, 0))
    bg.paste(Image.new("RGBA", (w - half, h), (238, 234, 240, 255)), (half, 0))
    bg.alpha_composite(canvas)
    out = os.path.join(PREVIEW_DIR, "preview_" + name + ".png")
    bg.convert("RGB").save(out)
    print("  preview   %s" % out)


def save_png(canvas, path, name):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    canvas.save(path)
    kb = os.path.getsize(path) / 1024.0
    print("  escrito   %s  (%.1f KB)" % (path, kb))


def main():
    os.makedirs(PREVIEW_DIR, exist_ok=True)

    print("── Skins (4) ─────────────────────────────────────────────")
    for src_name, skin_id, ref_skin in SKIN_JOBS:
        src = os.path.join(SRC, src_name)
        ref = os.path.join(SKIN_OUT, ref_skin + ".png")
        frame = ref_frame(ref)
        cut, bbox = cut_white_background(src)
        canvas = normalize_to_frame(cut, frame)
        print("%s" % skin_id)
        print("  bbox=%s  recorte=%dx%d  canvas=%dx%d  fh=%.3f cx=%.3f cy=%.3f (ref %s)"
              % (bbox, cut.width, cut.height, canvas.width, canvas.height,
                 frame["fh"], frame["cx"], frame["cy"], ref_skin))
        save_png(canvas, os.path.join(SKIN_OUT, skin_id + ".png"), skin_id)
        save_preview(canvas, skin_id)

    print("── Variante: Reina Vampira ───────────────────────────────")
    frame = ref_frame(RIDER_REF)
    cut, bbox = cut_white_background(os.path.join(SRC, VAMPIRE_SRC))
    canvas = normalize_to_frame(cut, frame, height_scale=0.95)
    print("  bbox=%s  recorte=%dx%d  canvas=%dx%d  (ref RiderQueen fh=%.3f cx=%.3f cy=%.3f)"
          % (bbox, cut.width, cut.height, canvas.width, canvas.height,
             frame["fh"], frame["cx"], frame["cy"]))
    save_png(canvas, os.path.join(STREAM_OUT, "VampireQueen.png"), "vampire_stream")
    save_png(canvas, os.path.join(RES_OUT, "VampireQueen.png"), "vampire_resources")
    save_preview(canvas, "VampireQueen")

    print("\nListo: 4 skins + 1 variante con alfa, encuadre familiar y previews.")


if __name__ == "__main__":
    main()
