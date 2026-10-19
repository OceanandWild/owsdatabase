# =============================================================================
# WILDWEAPON MAYHEM - Generador de SFX de UI
#
# Sintetiza los sonidos de interfaz como WAV 16-bit mono 44.1 kHz. No dependen
# de assets externos: el "clack" del click y el "tick" del hover se arman con un
# golpe de ruido filtrado mas un par de parciales metalicos, con la silueta de
# un arma de arena (golpe seco + cola brillante).
#
# Correr:  powershell -File tools\Generate-UI-Audio.ps1
# Salida:  Assets\_WildWeapon\Resources\WW\Audio\UI\*.wav
#
# Regenerar es barato y deterministico (semilla fija), asi que si un sonido
# molesta se ajusta el codigo de abajo y se vuelve a correr.
# =============================================================================

param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\Assets\_WildWeapon\Resources\WW\Audio\UI')
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

    // Normaliza al pico pedido: deja la forma intacta y fija el nivel.
    static float[] Peak(float[] s, float target)
    {
        float mx = 0f;
        for (int i = 0; i < s.Length; i++) mx = Math.Max(mx, Math.Abs(s[i]));
        if (mx > 0f)
            for (int i = 0; i < s.Length; i++) s[i] = s[i] / mx * target;
        return s;
    }

    // --- click: "clack" metalico -------------------------------------------
    // Transitorio de ruido (el golpe) + dos parciales de placa (la cola) +
    // un cuerpo grave que le da peso al boton.
    public static float[] Click()
    {
        int n = (int)(RATE * 0.10f);
        var s = new float[n];
        var rnd = new Random(2024);          // semilla fija: salida reproducible
        float lp = 0f, hp = 0f;
        for (int i = 0; i < n; i++)
        {
            float t = (float)i / RATE;

            // Ruido en banda: pasa-bajo y pasa-alto encadenados.
            float w = (float)(rnd.NextDouble() * 2 - 1);
            lp += (w - lp) * 0.55f;
            hp += (lp - hp) * 0.35f;
            float noise = (lp - hp) * 2.2f;

            // Parciales metalicos: dos modos que suenan a placa golpeada.
            float f1 = 1240f, f2 = 1870f;
            float metal = (float)(Math.Sin(2 * Math.PI * f1 * t) + 0.6 * Math.Sin(2 * Math.PI * f2 * t)) / 1.6f;

            // Cuerpo: el "golpe" grave que asienta el boton.
            float body = (float)Math.Sin(2 * Math.PI * 165f * t);

            float v = noise * 0.5f + metal * 0.6f + body * 0.35f;
            s[i] = v * Env(i, n, 0.002f, 0.16f);
        }
        return Peak(s, 0.85f);
    }

    // --- hover: "tick" suave, mas agudo y mas corto que el click ------------
    public static float[] Hover()
    {
        int n = (int)(RATE * 0.07f);
        var s = new float[n];
        for (int i = 0; i < n; i++)
        {
            float t = (float)i / RATE;
            float f = 2050f;
            float v = (float)(Math.Sin(2 * Math.PI * f * t) + 0.35 * Math.Sin(2 * Math.PI * f * 2.01f * t)) / 1.35f;
            s[i] = v * Env(i, n, 0.004f, 0.22f);
        }
        return Peak(s, 0.5f);
    }
}
'@

Add-Type -TypeDefinition $csharp -Language CSharp

# ---------------------------------------------------------------- generacion
$dir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$clips = @{
    'ww_sfx_click' = { [Sfx]::Click() }
    'ww_sfx_hover' = { [Sfx]::Hover() }
}

foreach ($name in ($clips.Keys | Sort-Object)) {
    $path = Join-Path $dir "$name.wav"
    $data = & $clips[$name]
    [Sfx]::Write($path, $data)
    $kb = (Get-Item $path).Length / 1KB
    $sec = $data.Length / 44100.0
    "{0,-16} {1,7:N0} KB  {2,5:N2}s" -f $name, $kb, $sec
}
