# =============================================================================
# WILDSEA REALMS - Generador de SFX de UI
#
# Sintetiza los sonidos de interfaz como WAV 16-bit mono 44.1 kHz. No dependen
# de assets externos ni de samples de otros proyectos OWS (los que hay en el
# workspace son SFX de armas y musica de otros juegos: no encajan en un menu).
#
# Correr:  powershell -File tools\Generate-UI-Audio.ps1
# Salida:  Assets\Resources\WS\Audio\UI\*.wav
#
# Regenerar es barato y deterministico (semilla fija), asi que si un sonido
# molesta se ajusta el codigo de abajo y se vuelve a correr.
# =============================================================================

param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\Assets\Resources\WS\Audio\UI')
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- sintetizador
$csharp = @'
using System;
using System.IO;
using System.Text;

public static class Sfx
{
    const int RATE = 44100;

    public static void Write(string path, float[] s)
    {
        using (var fs = new FileStream(path, FileMode.Create))
        using (var w = new BinaryWriter(fs))
        {
            int n = s.Length;
            w.Write(Encoding.ASCII.GetBytes("RIFF"));
            w.Write(36 + n * 2);
            w.Write(Encoding.ASCII.GetBytes("WAVE"));
            w.Write(Encoding.ASCII.GetBytes("fmt "));
            w.Write(16);
            w.Write((short)1);          // PCM
            w.Write((short)1);          // mono
            w.Write(RATE);
            w.Write(RATE * 2);
            w.Write((short)2);          // block align
            w.Write((short)16);         // bits
            w.Write(Encoding.ASCII.GetBytes("data"));
            w.Write(n * 2);
            for (int i = 0; i < n; i++)
            {
                float v = s[i];
                if (v > 1f) v = 1f;
                if (v < -1f) v = -1f;
                w.Write((short)(v * 32767));
            }
        }
    }

    // Ataque lineal + caida exponencial. atk/dec en fraccion de duracion.
    static float Env(int i, int n, float atk, float dec)
    {
        float t = (float)i / n;
        if (t < atk) return t / atk;
        return (float)Math.Exp(-(t - atk) / dec);
    }

    // --- click: barrido corto y seco, el "tac" de un boton ---------------
    public static float[] Click()
    {
        int n = (int)(RATE * 0.07f);
        var s = new float[n];
        for (int i = 0; i < n; i++)
        {
            float t = (float)i / RATE;
            float f = 1500f - 720f * ((float)i / n);
            s[i] = (float)Math.Sin(2 * Math.PI * f * t) * Env(i, n, 0.004f, 0.16f) * 0.45f;
        }
        return s;
    }

    // --- hover: mas agudo y mas corto, casi subliminal -------------------
    public static float[] Hover()
    {
        int n = (int)(RATE * 0.045f);
        var s = new float[n];
        for (int i = 0; i < n; i++)
        {
            float t = (float)i / RATE;
            s[i] = (float)Math.Sin(2 * Math.PI * 1950f * t) * Env(i, n, 0.003f, 0.09f) * 0.20f;
        }
        return s;
    }

    // --- confirm / back: dos tonos, segunda nota arriba / abajo ------------
    public static float[] Confirm()
    {
        int n = (int)(RATE * 0.22f);
        var s = new float[n];
        int half = n / 2;
        for (int i = 0; i < n; i++)
        {
            float f = (i < half) ? 620f : 930f;
            float t = (float)i / RATE;
            s[i] = (float)Math.Sin(2 * Math.PI * f * t) * Env(i, n, 0.005f, 0.42f) * 0.30f;
        }
        return s;
    }

    public static float[] Back()
    {
        int n = (int)(RATE * 0.22f);
        var s = new float[n];
        int half = n / 2;
        for (int i = 0; i < n; i++)
        {
            float f = (i < half) ? 930f : 620f;
            float t = (float)i / RATE;
            s[i] = (float)Math.Sin(2 * Math.PI * f * t) * Env(i, n, 0.005f, 0.42f) * 0.28f;
        }
        return s;
    }

    // --- denied: grave y desafinado, el "no" sin ser grind -----------------
    public static float[] Denied()
    {
        int n = (int)(RATE * 0.28f);
        var s = new float[n];
        for (int i = 0; i < n; i++)
        {
            float t = (float)i / RATE;
            float f = 150f + 22f * (float)Math.Sin(2 * Math.PI * 11f * t);
            double v = Math.Sin(2 * Math.PI * f * t) + 0.35 * Math.Sin(2 * Math.PI * f * 2 * t);
            s[i] = (float)(v / 1.35) * Env(i, n, 0.010f, 0.30f) * 0.34f;
        }
        return s;
    }

    // --- ambient: mar en loop sin costura ---------------------------------
    // Dos bandas de ruido filtrado (rumor + siseo) moduladas por un LFO cuyo
    // periodo divide exacto la duracion, y crossfade cola->cabeza para que el
    // loop no tengaclic. El bucle es lo que hace que funcione AudioSource.loop.
    public static float[] Ambient(int seconds)
    {
        int n = RATE * seconds;
        var s = new float[n];
        var rnd = new Random(1234);              // semilla fija: salida reproducible
        float rumble = 0f, hiss = 0f;
        for (int i = 0; i < n; i++)
        {
            float w = (float)(rnd.NextDouble() * 2 - 1);
            rumble += (w - rumble) * 0.004f;
            hiss   += (w - hiss)   * 0.060f;
            s[i] = rumble * 3.0f + hiss * 0.55f;
        }
        for (int i = 0; i < n; i++)
        {
            float t = (float)i / RATE;
            float lfo = 0.55f
                + 0.22f * (float)Math.Sin(2 * Math.PI * t / seconds)
                + 0.12f * (float)Math.Sin(2 * Math.PI * 2 * t / seconds)
                + 0.07f * (float)Math.Sin(2 * Math.PI * 3 * t / seconds);
            s[i] *= lfo;
        }

        int fade = RATE;                          // 1 s de crossfade
        int len = n - fade;
        var o = new float[len];
        for (int i = 0; i < fade; i++)
        {
            float k = (float)i / fade;
            o[i] = s[i] * k + s[len + i] * (1f - k);
        }
        Array.Copy(s, fade, o, fade, len - fade);

        float mx = 0f;
        for (int i = 0; i < len; i++) mx = Math.Max(mx, Math.Abs(o[i]));
        if (mx > 0f) for (int i = 0; i < len; i++) o[i] = o[i] / mx * 0.5f;
        return o;
    }
}
'@

Add-Type -TypeDefinition $csharp -Language CSharp

# ---------------------------------------------------------------- generacion
$dir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$clips = @{
    'WS_sfx_click'   = { [Sfx]::Click() }
    'WS_sfx_hover'   = { [Sfx]::Hover() }
    'WS_sfx_confirm' = { [Sfx]::Confirm() }
    'WS_sfx_back'    = { [Sfx]::Back() }
    'WS_sfx_denied'  = { [Sfx]::Denied() }
    'WS_amb_sea'     = { [Sfx]::Ambient(12) }
}

foreach ($name in ($clips.Keys | Sort-Object)) {
    $path = Join-Path $dir "$name.wav"
    $data = & $clips[$name]
    [Sfx]::Write($path, $data)
    $kb = (Get-Item $path).Length / 1KB
    $sec = $data.Length / 44100.0
    "{0,-16} {1,7:N0} KB  {2,5:N2}s" -f $name, $kb, $sec
}
