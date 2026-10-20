"""Analiza los SFX de UI de WildWeapon Mayhem: envolvente temporal y espectro.

Uso: python tools/analyze-ui-audio.py
"""
import wave
import sys
import pathlib

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
UI_DIR = ROOT / "Assets" / "_WildWeapon" / "Resources" / "WW" / "Audio" / "UI"


def load(path):
    with wave.open(str(path), "rb") as w:
        assert w.getsampwidth() == 2 and w.getnchannels() == 1
        rate = w.getframerate()
        data = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16)
    return rate, data.astype(np.float64) / 32768.0


def envelope(x, rate, win_ms=5.0):
    w = int(rate * win_ms / 1000)
    n = len(x) // w
    env = np.array([np.sqrt(np.mean(x[i * w:(i + 1) * w] ** 2)) for i in range(n)])
    return env, win_ms


def spectrum(x, rate, label):
    # FFT sobre la senal completa (el sonido es corto)
    n = len(x)
    win = np.hanning(n)
    spec = np.abs(np.fft.rfft(x * win))
    freqs = np.fft.rfftfreq(n, 1.0 / rate)
    mag = spec / (n / 2)

    # picos pronunciados del espectro (parciales)
    order = np.argsort(mag)[::-1]
    peaks = []
    for idx in order:
        f = freqs[idx]
        if f < 60 or f > 12000:
            continue
        if all(abs(f - pf) > 120 for pf, _ in peaks):
            peaks.append((f, mag[idx]))
        if len(peaks) >= 9:
            break
    print(f"  picos del espectro ({label}):")
    for f, m in peaks:
        db = 20 * np.log10(m + 1e-12)
        print(f"    {f:8.0f} Hz  {db:6.1f} dB")

    # banda de energia
    total = np.sum(mag ** 2)
    for name, lo, hi in (("sub 40-200", 40, 200), ("cuerpo 200-1500", 200, 1500),
                         ("presencia 1500-5000", 1500, 5000), ("brillo 5000-12000", 5000, 12000)):
        band = mag[(freqs >= lo) & (freqs < hi)]
        share = 100 * np.sum(band ** 2) / total if total > 0 else 0
        print(f"    {name:22s} {share:5.1f} % de la energia")


for name in ("ww_sfx_click", "ww_sfx_hover"):
    path = UI_DIR / f"{name}.wav"
    if not path.exists():
        print(f"falta {path}")
        sys.exit(1)
    rate, x = load(path)
    env, win_ms = envelope(x, rate)
    print(f"\n=== {name}  ({len(x)/rate:.3f}s, {rate} Hz) ===")
    print("  envolvente (rms cada %.0f ms):" % win_ms)
    line = "   "
    for i, v in enumerate(env):
        bar = "#" * int(v * 60)
        line += f"{v:.2f}|"
        if i % 12 == 11:
            print(line)
            line = "   "
    if line.strip():
        print(line)
    spectrum(x, rate, name)
