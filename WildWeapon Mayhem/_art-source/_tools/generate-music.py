#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WildWeapon Mayhem - Generador de musica con Lyria (Gemini API / Interactions API).

Uso:
  python generate-music.py            -> genera todas las pistas configuradas
  python generate-music.py menu       -> solo la de menu
  python generate-music.py arena      -> solo la de arena

La API key se lee, en orden:
  1) <OWS Unity>/secrets/gemini-music-key   (key dedicada, si existe)
  2) <OWS Unity>/secrets/owsdatabase.env    (fallback: variable GEMINI_API_KEY)

Salida:
  <OWS Unity>/WildWeapon Mayhem/_art-source/Music/<id>.mp3  (+ .json con trazabilidad)

Costos (tier pagado, sin nivel gratuito):
  lyria-3-clip-preview : $0.04 por clip de 30 s
  lyria-3.5            : $0.08 por cancion completa
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ART_SOURCE = os.path.abspath(os.path.join(HERE, ".."))
PROJECT = os.path.abspath(os.path.join(ART_SOURCE, ".."))
OWS_ROOT = os.path.abspath(os.path.join(PROJECT, ".."))
SECRETS = os.path.join(OWS_ROOT, "secrets")
OUT_DIR = os.path.join(ART_SOURCE, "Music")

ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/interactions"

# ---------------------------------------------------------------------------
# Configuracion de pistas
# ---------------------------------------------------------------------------
TRACKS = {
    "menu": {
        "model": "lyria-3-clip-preview",
        "out": "ww_music_menu_v1.mp3",
        "prompt": (
            "An instrumental fantasy tournament game menu theme, about 30 seconds, "
            "designed as a seamless loop. Calm, mysterious, quiet anticipation. "
            "Sparse piano notes over a warm sustained string pad, soft airy choir texture, "
            "a slow deep heartbeat-like drum pulse, distant French horn melody. "
            "68 BPM, key of A minor. No vocals, no lyrics, purely instrumental. "
            "Cinematic and epic but restrained, neutral tone, not menacing. "
            "Steady dynamics, no big climax, gentle seamless loop."
        ),
    },
    "arena": {
        "model": "lyria-3.5",
        "out": "ww_music_arena_v1.mp3",
        "prompt": (
            "Instrumental high-energy arena combat music for a fast cartoon dueling game, "
            "about 100 seconds long. Driving tribal war drums and taiko hits, punchy staccato "
            "low-string ostinato, distorted electric guitar power chords, brass stabs and fast "
            "snare fills. Around 132 BPM in D minor. Aggressive, playful, high-stakes tournament "
            "energy. No vocals, no lyrics, purely instrumental. Structure: short tense intro, "
            "energetic main combat section with variations, brief half-time bridge, intense "
            "final push, then resolve back to the main motif so the track can loop seamlessly."
        ),
    },
}


def read_api_key():
    dedicated = os.path.join(SECRETS, "gemini-music-key")
    if os.path.exists(dedicated):
        key = open(dedicated, encoding="utf-8-sig").read().strip()
        if key:
            print(f"[key] usando key dedicada: {dedicated}")
            return key

    env_path = os.path.join(SECRETS, "owsdatabase.env")
    if os.path.exists(env_path):
        for line in open(env_path, encoding="utf-8-sig", errors="ignore"):
            line = line.strip()
            if line.startswith("GEMINI_API_KEY"):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
                if key:
                    print(f"[key] usando GEMINI_API_KEY de: {env_path}")
                    return key

    sys.exit("[key] ERROR: no encontre API key. Crea secrets/gemini-music-key o GEMINI_API_KEY en owsdatabase.env")


def call_lyria(api_key, model, prompt, timeout=540):
    body = {
        "model": model,
        "input": prompt,
        "store": False,
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        ENDPOINT,
        data=data,
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def extract_audio_b64(payload):
    """Intenta sacar el audio base64 de la respuesta (convenience o steps)."""
    # 1) convenience en raiz o dentro de interaction
    for node in (payload, payload.get("interaction") or {}):
        oa = node.get("output_audio") or node.get("outputAudio")
        if isinstance(oa, dict) and oa.get("data"):
            return oa["data"]

    # 2) recorrer steps -> content blocks
    def iter_steps(node):
        steps = node.get("steps") or []
        for step in steps:
            for block in (step.get("content") or []):
                if isinstance(block, dict):
                    yield block

    for node in (payload, payload.get("interaction") or {}):
        for block in iter_steps(node):
            btype = (block.get("type") or "").lower()
            if "audio" in btype and block.get("data"):
                return block["data"]
    return None


def generate_track(api_key, track_id, cfg):
    model = cfg["model"]
    out_path = os.path.join(OUT_DIR, cfg["out"])
    print(f"[gen] {track_id}: modelo={model}")
    print(f"[gen] prompt: {cfg['prompt'][:110]}...")
    t0 = time.time()
    try:
        payload = call_lyria(api_key, model, cfg["prompt"])
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        print(f"[gen] ERROR HTTP {e.code}")
        print(body[:900])
        return False
    except Exception as e:  # noqa: BLE001
        print(f"[gen] ERROR: {type(e).__name__}: {e}")
        return False

    audio_b64 = extract_audio_b64(payload)
    if not audio_b64:
        print("[gen] ERROR: la respuesta no trae audio. Claves raiz:")
        print(json.dumps({k: type(v).__name__ for k, v in payload.items()}, indent=1)[:800])
        print(json.dumps(payload, indent=1)[:1500])
        return False

    raw = base64.b64decode(audio_b64)
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(raw)

    sidecar = {
        "id": track_id,
        "model": model,
        "prompt": cfg["prompt"],
        "file": cfg["out"],
        "bytes": len(raw),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api": "gemini-interactions v1beta",
        "watermark": "SynthID",
    }
    with open(out_path + ".json", "w", encoding="utf-8") as f:
        json.dump(sidecar, f, indent=2, ensure_ascii=False)

    dt = time.time() - t0
    print(f"[gen] OK {track_id}: {out_path}")
    print(f"[gen]     {len(raw)/1024:.0f} KB en {dt:.0f}s")
    return True


def main():
    wanted = [a.lower() for a in sys.argv[1:]]
    if wanted:
        for w in wanted:
            if w not in TRACKS:
                sys.exit(f"Pista desconocida: {w}. Opciones: {', '.join(TRACKS)}")
    else:
        wanted = list(TRACKS)

    api_key = read_api_key()
    ok = 0
    for track_id in wanted:
        if generate_track(api_key, track_id, TRACKS[track_id]):
            ok += 1
    print(f"[done] {ok}/{len(wanted)} pistas generadas en {OUT_DIR}")
    if ok != len(wanted):
        sys.exit(1)


if __name__ == "__main__":
    main()
