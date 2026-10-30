"""Simula el 9-slice que aplica ProgressSprites.cs y lo imprime en ASCII.

Útil para comprobar a ojo (sin abrir Unity) que el marco no se deforma y cuánto sitio
real queda para la etiqueta en el centro.

Uso: python Tools/slice_preview.py Assets/Resources/UI/Progress/btn_claim_ready.png 118 34 0.22 0.50
"""
import sys
from PIL import Image

FOOTER = 24  # padding horizontal de .prog-claim en MainMenu.uss


def lum(c):
    return 0.3 * c[0] + 0.6 * c[1] + 0.1 * c[2]


def nine_slice(path, css_w, css_h, frac_x, frac_y):
    src = Image.open(path).convert("RGBA")
    w, h = src.size
    sl, st = round(w * frac_x), round(h * frac_y)
    scale = min(css_w / w, css_h / h)
    el, et = max(1, round(sl * scale)), max(1, round(st * scale))

    out = Image.new("RGBA", (css_w, css_h), (0, 0, 0, 0))
    mid_w, mid_h = css_w - 2 * el, css_h - 2 * et

    def piece(box, size):
        return src.crop(box).resize(size, Image.BILINEAR)

    out.paste(piece((0, 0, sl, st), (el, et)), (0, 0))
    out.paste(piece((w - sl, 0, w, st), (el, et)), (css_w - el, 0))
    out.paste(piece((0, h - st, sl, h), (el, et)), (0, css_h - et))
    out.paste(piece((w - sl, h - st, w, h), (el, et)), (css_w - el, css_h - et))
    if mid_w > 0:
        out.paste(piece((sl, 0, w - sl, st), (mid_w, et)), (el, 0))
        out.paste(piece((sl, h - st, w - sl, h), (mid_w, et)), (el, css_h - et))
    if mid_h > 0:
        out.paste(piece((0, st, sl, h - st), (el, mid_h)), (0, et))
        out.paste(piece((w - sl, st, w, h - st), (el, mid_h)), (css_w - el, et))
    if mid_w > 0 and mid_h > 0:
        out.paste(piece((sl, st, w - sl, h - st), (mid_w, mid_h)), (el, et))
    return out, scale, (el, et)


def main():
    path = sys.argv[1]
    css_w, css_h = int(sys.argv[2]), int(sys.argv[3])
    frac_x, frac_y = float(sys.argv[4]), float(sys.argv[5])

    img, scale, (el, et) = nine_slice(path, css_w, css_h, frac_x, frac_y)
    px = img.load()
    print(f"{path} -> {css_w}x{css_h}  escala {scale:.2f}  corte {el}x{et}px por esquina")
    print(f"   etiqueta centrada: caja x=[{FOOTER}, {css_w - FOOTER}]  (hueco libre x=[{el}, {css_w - el}])")

    for y in range(0, css_h, 2):
        line = []
        for x in range(css_w):
            r, g, b, a = px[x, y]
            if a < 60:
                line.append(".")
            elif lum((r, g, b)) > 120:
                line.append("#")
            elif lum((r, g, b)) > 60:
                line.append("+")
            else:
                line.append(" ")
        print("|" + "".join(line) + "|")


if __name__ == "__main__":
    main()
