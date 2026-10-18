# Música de WildWeapon Mayhem — vía Flow Music (Lyria)

Generás las 2 pistas en tu Flow Music con los prompts de abajo y las guardás en
esta carpeta (`_art-source/Music/`). Después el agente las importa al juego,
corre el builder y queda andando (menú ↔ arena con crossfade).

## Archivos a generar (nombres exactos)

| Archivo | Uso | Duración ideal |
|---|---|---|
| `ww_music_menu_v1.*`  | Tema del menú  | 30–120 s, puede loopear |
| `ww_music_arena_v1.*` | Tema de combate | 90–120 s, puede loopear |

Formato: WAV o MP3 (cualquiera sirve). Si querés iterar, guardá `..._v2`, `..._v3`
(elegimos la mejor al importar; el builder toma la primera `v1` por orden alfabético,
avisen cuál usar).

## Reglas rápidas

- **Instrumental, sin voces ni letras.** Si Flow agrega voz, regenerar (probá agregar
  "instrumental only, no vocals" o usar el modo instrumental si aparece).
- El menú: calmo/épico contenido, **neutral** (nada de samurái/dojo).
- La arena: energía alta, tribal/guitarra, sensación de torneo.
- Cada generación de Flow Music lleva **watermark SynthID** (imperceptible).
- Uso comercial: los planes pagos de Flow Music incluyen derechos comerciales.

---

## Prompt — MENÚ (pegar en Flow Music)

```
Elegant instrumental fantasy arena menu theme. Calm and mysterious with quiet
anticipation: soft piano notes over warm sustained strings, airy choir pad, slow
heartbeat-like low drum pulse, distant horn melody. Around 70 BPM, minor key.
Cinematic and epic but restrained, neutral mood, steady dynamics, no big climax,
designed to loop seamlessly. Purely instrumental, no vocals, no lyrics.
```

## Prompt — ARENA (pegar en Flow Music)

```
Instrumental high-energy arena combat theme for a fast cartoon dueling game.
Driving tribal war drums and taiko hits, punchy staccato low-string ostinato,
distorted electric guitar power chords, brass stabs and fast snare fills.
Around 130 BPM in D minor. Aggressive, playful, high-stakes tournament energy.
Short tense intro, energetic main combat section with variations, brief
half-time bridge, intense final push, then resolve back to the main motif so
the track can loop seamlessly. Purely instrumental, no vocals, no lyrics.
```

---

## Qué pasa después (lo hace el agente)

1. Import a `Assets/_WildWeapon/Audio/Music/` (con settings de importador correctos).
2. Build completo (`WildWeapon/Construir juego completo`) → cablea `MusicPlayer`
   en MainMenu y Arena (el menú además recibe su `AudioListener`).
3. Verificación en Play + consola.

> Nota: el script `_art-source/_tools/generate-music.py` queda como camino alternativo
> si algún día habilitás billing en la Gemini API (Lyria 3.5: $0.08/canción,
> clip 30 s: $0.04). Mismos nombres de archivo, misma integración.
