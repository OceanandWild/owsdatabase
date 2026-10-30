# -*- coding: utf-8 -*-
"""
build_halloween_scenery.py — Ambientes 16:9 y fondos de la Velada
-----------------------------------------------------------------
Toma los JPG crudos de Flow y los deja en el formato que carga el juego:

  * Ambiente de tablero -> Assets/StreamingAssets/Board/bg_halloween_<slot>.jpeg
    1376x768, calidad 92 (lo pinta BoardBackgroundManager detrás del objeto 8x8).
  * Fondo de menu       -> Assets/StreamingAssets/Backdrop/backdrop_halloween_<name>.jpg
    2752x1536, calidad 90 (BackdropManager).

El recorte es "cover": escala a cubrir y centra, sin deformar.

Uso: python build_halloween_scenery.py [--only slot,slot]
"""
import argparse
import os
import shutil

from PIL import Image

RAW = os.path.join(os.environ.get("TEMP", ""), "ows-flow", "raw")
ROOT = r"C:\Users\Equipo\Desktop\OWS Unity\Wilder Gambit"
BOARD = os.path.join(ROOT, "Assets", "StreamingAssets", "Board")
BACKDROP = os.path.join(ROOT, "Assets", "StreamingAssets", "Backdrop")
ARCHIVE = os.path.join(ROOT, "_art-source", "Halloween")

# slot: (crudo, destino, tamano, calidad)
JOBS = {
    "graveyard_env": ("graveyard_env_raw.jpg", os.path.join(BOARD, "bg_halloween_graveyard.jpeg"),
                      (1376, 768), 92),
    "crypt_env": ("crypt_env_raw.jpg", os.path.join(BOARD, "bg_halloween_crypt.jpeg"),
                  (1376, 768), 92),
    "harvest": ("harvest_backdrop_raw.jpg", os.path.join(BACKDROP, "backdrop_halloween_harvest.jpg"),
                (2752, 1536), 90),
    "banquet": ("banquet_backdrop_raw.jpg", os.path.join(BACKDROP, "backdrop_halloween_banquet.jpg"),
                (2752, 1536), 90),
}


def cover(img, size):
    w, h = size
    s = max(w / img.width, h / img.height)
    resized = img.resize((int(round(img.width * s)), int(round(img.height * s))), Image.LANCZOS)
    left = (resized.width - w) // 2
    top = (resized.height - h) // 2
    return resized.crop((left, top, left + w, top + h))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    only = [s.strip() for s in args.only.split(",") if s.strip()] or list(JOBS)

    os.makedirs(ARCHIVE, exist_ok=True)
    for slot in only:
        raw_name, dest, size, quality = JOBS[slot]
        src = os.path.join(RAW, raw_name)
        img = Image.open(src).convert("RGB")
        exact = img.size == size
        out = cover(img, size)
        out.save(dest, "JPEG", quality=quality, optimize=True, progressive=True)
        raw_copy = os.path.join(ARCHIVE, "halloween_%s_raw.jpg" % slot)
        if not os.path.exists(raw_copy):
            shutil.copy2(src, raw_copy)
        print("%-14s %sx%s -> %sx%s %s  %5.0f KB  %s"
              % (slot, img.width, img.height, out.width, out.height,
                 "exacto" if exact else "cover", os.path.getsize(dest) / 1024.0,
                 os.path.basename(dest)))


if __name__ == "__main__":
    main()
